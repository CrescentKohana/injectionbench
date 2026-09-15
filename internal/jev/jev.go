// Package jev is a client for TypeSafe AI's System One ("Jev") model, which answers typed
// questions (noul, choice, score) about an arbitrary JSON state.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Config configures a Client.
type Config struct {
	BaseURL     string
	APIKey      string
	Model       string
	Timeout     time.Duration
	MaxRetries  int
	BaseBackoff time.Duration
}

const (
	defaultModel       = "jev-latest"
	defaultTimeout     = 5 * time.Second
	defaultMaxRetries  = 3
	defaultBaseBackoff = 200 * time.Millisecond
	backoffCap         = 10 * time.Second
	maxResponseBytes   = 1 << 20
	apiErrorBodyBytes  = 512
)

// Client calls the System One API.
type Client struct {
	cfg    Config
	client *http.Client
}

// NewClient returns a Client. It errors if APIKey or BaseURL is empty.
func NewClient(cfg Config, httpClient *http.Client) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("jev: config: APIKey is empty")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("jev: config: BaseURL is empty")
	}
	if cfg.Model == "" {
		cfg.Model = defaultModel
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{cfg: cfg, client: httpClient}, nil
}

// Question is one typed question asked about a Request's State.
type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Noul asks a free-valued [0,1] question.
func Noul(instructions string) Question {
	return Question{Type: "noul", Instructions: instructions}
}

// Choice asks a multiple-choice question; options maps each choice to its description.
func Choice(instructions string, options map[string]string) Question {
	return Question{Type: "choice", Instructions: instructions, Criteria: options}
}

// Score asks a leveled question; levels names each level from lowest to highest.
func Score(instructions string, levels []string) Question {
	return Question{Type: "score", Instructions: instructions, Criteria: levels}
}

// Request is one System One call.
type Request struct {
	State     any                 `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

// Answer is System One's answer to one Question.
type Answer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Legend        map[string]string  `json:"legend,omitempty"`
}

// Usage reports token consumption for one call.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response is System One's reply to a Request.
type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   Usage             `json:"usage"`
}

// APIError is a non-2xx response from System One.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("jev: api error: status %d: %s", e.StatusCode, e.Body)
}

// ErrInvalidResponse is wrapped by errors from a successful but semantically invalid response.
var ErrInvalidResponse = errors.New("jev: invalid response")

// SystemOne asks req's questions about req.State, filling Model from the Client's configuration
// when req.Model is empty. It retries 429, 529, other 5xx and network errors up to
// cfg.MaxRetries times; any other 4xx is returned immediately as *APIError.
func (c *Client) SystemOne(ctx context.Context, req Request) (Response, error) {
	if req.Model == "" {
		req.Model = c.cfg.Model
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("jev: encode request: %w", err)
	}

	data, err := c.doWithRetry(ctx, payload)
	if err != nil {
		return Response{}, err
	}

	var resp Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return Response{}, fmt.Errorf("jev: decode response: %w", err)
	}
	if err := validateResponse(req, resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func validateResponse(req Request, resp Response) error {
	for key, q := range req.Questions {
		ans, ok := resp.Answers[key]
		if !ok || ans.Type != q.Type {
			return fmt.Errorf("%w: missing or mismatched-type answer for question %q", ErrInvalidResponse, key)
		}
		switch q.Type {
		case "noul":
			if ans.Noul == nil || *ans.Noul < 0 || *ans.Noul > 1 {
				return fmt.Errorf("%w: noul answer for %q is missing or out of [0,1]", ErrInvalidResponse, key)
			}
		case "score":
			if ans.Score == nil || *ans.Score < 0 || *ans.Score > 1 {
				return fmt.Errorf("%w: score answer for %q is missing or out of [0,1]", ErrInvalidResponse, key)
			}
		case "choice":
			options, ok := criteriaOptions(q.Criteria)
			if !ok {
				return fmt.Errorf("%w: choice question %q has no options to validate against", ErrInvalidResponse, key)
			}
			if !options[ans.Choice] {
				return fmt.Errorf("%w: choice %q for %q names no known option", ErrInvalidResponse, ans.Choice, key)
			}
		}
	}
	return nil
}

// criteriaOptions extracts the option names from a Choice Question's Criteria, accepting the
// map[string]string jev.Choice builds directly and the map[string]any a JSON round trip produces.
func criteriaOptions(criteria any) (map[string]bool, bool) {
	options := map[string]bool{}
	switch c := criteria.(type) {
	case map[string]string:
		for k := range c {
			options[k] = true
		}
	case map[string]any:
		for k := range c {
			options[k] = true
		}
	default:
		return nil, false
	}
	return options, true
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == 529 || status >= 500
}

func (c *Client) doWithRetry(ctx context.Context, payload []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		data, status, retryAfter, hasRetryAfter, err := c.doOnce(ctx, payload)
		switch {
		case err == nil && status >= 200 && status < 300:
			return data, nil
		case err == nil && !retryableStatus(status):
			return nil, &APIError{StatusCode: status, Body: truncateBody(data)}
		case err == nil:
			lastErr = &APIError{StatusCode: status, Body: truncateBody(data)}
		default:
			lastErr = fmt.Errorf("jev: request: %w", err)
		}

		if attempt == c.cfg.MaxRetries {
			break
		}
		delay := backoffDelay(c.cfg.BaseBackoff, attempt, retryAfter, hasRetryAfter)
		if sleepErr := sleepContext(ctx, delay); sleepErr != nil {
			return nil, sleepErr
		}
	}
	return nil, lastErr
}

func (c *Client) doOnce(ctx context.Context, payload []byte) (data []byte, status int, retryAfter time.Duration, hasRetryAfter bool, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.cfg.BaseURL+"/v1/systemone", bytes.NewReader(payload))
	if err != nil {
		return nil, 0, 0, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, 0, 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err = io.ReadAll(limited)
	if err != nil {
		return nil, resp.StatusCode, 0, false, err
	}
	if len(data) > maxResponseBytes {
		return nil, resp.StatusCode, 0, false, fmt.Errorf("jev: response exceeds %d bytes", maxResponseBytes)
	}

	retryAfter, hasRetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	return data, resp.StatusCode, retryAfter, hasRetryAfter, nil
}

// parseRetryAfter reads a Retry-After header, falling back to the caller's own backoff (ok=false)
// for a negative, zero, unparsable, or already-past value.
func parseRetryAfter(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs <= 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(header); err == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, false
	}
	return 0, false
}

func backoffDelay(base time.Duration, attempt int, retryAfter time.Duration, hasRetryAfter bool) time.Duration {
	if hasRetryAfter {
		if retryAfter > backoffCap {
			return backoffCap
		}
		return retryAfter
	}
	maxDelay := base * time.Duration(uint64(1)<<uint(attempt)) //nolint:gosec // G115: attempt is a small, bounded retry counter
	if maxDelay <= 0 || maxDelay > backoffCap {
		maxDelay = backoffCap
	}
	return time.Duration(rand.Int64N(int64(maxDelay) + 1)) //nolint:gosec // G404: retry jitter has no security relevance
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func truncateBody(data []byte) string {
	if len(data) > apiErrorBodyBytes {
		return string(data[:apiErrorBodyBytes])
	}
	return string(data)
}
