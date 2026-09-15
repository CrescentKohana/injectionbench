package llm

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

// OpenAIConfig configures the OpenAI-compatible chat-completions client.
type OpenAIConfig struct {
	BaseURL     string
	APIKey      string
	Model       string
	Timeout     time.Duration
	MaxRetries  int
	BaseBackoff time.Duration
}

const (
	defaultOpenAITimeout    = 30 * time.Second // completions are slow; 5s would false-positive on normal latency
	defaultOpenAIMaxRetries = 3
	defaultOpenAIBackoff    = 500 * time.Millisecond
	backoffCap              = 10 * time.Second
	maxOpenAIResponseBytes  = 1 << 20
	errorBodyTruncateBytes  = 512
)

type openAIModel struct {
	cfg    OpenAIConfig
	client *http.Client
}

// NewOpenAI returns a Model backed by an OpenAI-compatible chat-completions endpoint at
// cfg.BaseURL + "/chat/completions". It errors if BaseURL or Model is empty.
func NewOpenAI(cfg OpenAIConfig, httpClient *http.Client) (Model, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("llm: openai config: BaseURL is empty")
	}
	if cfg.Model == "" {
		return nil, errors.New("llm: openai config: Model is empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultOpenAITimeout
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultOpenAIMaxRetries
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = defaultOpenAIBackoff
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &openAIModel{cfg: cfg, client: httpClient}, nil
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIToolProperty struct {
	Type string `json:"type"`
}

type openAIToolParameters struct {
	Type       string                        `json:"type"`
	Properties map[string]openAIToolProperty `json:"properties"`
	Required   []string                      `json:"required"`
}

type openAIToolFunction struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Parameters  openAIToolParameters `json:"parameters"`
}

type openAITool struct {
	Type     string             `json:"type"`
	Function openAIToolFunction `json:"function"`
}

type openAIChatRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
	Tools    []openAITool    `json:"tools,omitempty"`
}

type openAIFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openAIResponseToolCall struct {
	Function openAIFunctionCall `json:"function"`
}

type openAIResponseMessage struct {
	Content   *string                  `json:"content"`
	ToolCalls []openAIResponseToolCall `json:"tool_calls"`
}

type openAIChoice struct {
	Message openAIResponseMessage `json:"message"`
}

type openAIChatResponse struct {
	Choices []openAIChoice `json:"choices"`
}

// Complete implements Model.
func (m *openAIModel) Complete(ctx context.Context, req Request) (Completion, error) {
	body := openAIChatRequest{Model: m.cfg.Model, Messages: convertMessagesToOpenAI(req.Messages)}
	if len(req.Tools) > 0 {
		body.Tools = convertToolsToOpenAI(req.Tools)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return Completion{}, fmt.Errorf("llm: encode openai request: %w", err)
	}

	data, err := m.doWithRetry(ctx, payload)
	if err != nil {
		return Completion{}, err
	}

	var parsed openAIChatResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Completion{}, fmt.Errorf("llm: decode openai response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return Completion{}, errors.New("llm: openai response has no choices")
	}

	msg := parsed.Choices[0].Message
	content := ""
	if msg.Content != nil {
		content = *msg.Content
	}

	toolCalls := make([]ToolCall, 0, len(msg.ToolCalls))
	for _, tc := range msg.ToolCalls {
		args, err := decodeOpenAIArguments(tc.Function.Arguments)
		if err != nil {
			return Completion{}, fmt.Errorf("llm: decode tool call arguments: %w", err)
		}
		toolCalls = append(toolCalls, ToolCall{Name: tc.Function.Name, Arguments: args})
	}
	return Completion{Content: content, ToolCalls: toolCalls}, nil
}

func convertMessagesToOpenAI(msgs []Message) []openAIMessage {
	out := make([]openAIMessage, len(msgs))
	for i, m := range msgs {
		out[i] = openAIMessage{Role: string(m.Role), Content: m.Content}
	}
	return out
}

func convertToolsToOpenAI(tools []Tool) []openAITool {
	out := make([]openAITool, len(tools))
	for i, t := range tools {
		props := make(map[string]openAIToolProperty, len(t.Parameters))
		for _, p := range t.Parameters {
			props[p] = openAIToolProperty{Type: "string"}
		}
		out[i] = openAITool{
			Type: "function",
			Function: openAIToolFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters: openAIToolParameters{
					Type:       "object",
					Properties: props,
					Required:   append([]string(nil), t.Parameters...),
				},
			},
		}
	}
	return out
}

// decodeOpenAIArguments parses a tool call's JSON-encoded arguments string into a flat
// string map; non-string JSON values are kept as their original JSON text.
func decodeOpenAIArguments(raw string) (map[string]string, error) {
	if raw == "" {
		return map[string]string{}, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			out[k] = s
			continue
		}
		out[k] = string(v)
	}
	return out, nil
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// doWithRetry sends payload, retrying retryable failures up to cfg.MaxRetries times with
// exponential backoff and full jitter, honouring a Retry-After header when present.
func (m *openAIModel) doWithRetry(ctx context.Context, payload []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= m.cfg.MaxRetries; attempt++ {
		data, status, retryAfter, hasRetryAfter, err := m.doOnce(ctx, payload)
		switch {
		case err == nil && status >= 200 && status < 300:
			return data, nil
		case err == nil && !retryableStatus(status):
			return nil, fmt.Errorf("llm: openai request failed: status %d: %s", status, truncateBody(data))
		case err == nil:
			lastErr = fmt.Errorf("llm: openai request failed: status %d: %s", status, truncateBody(data))
		default:
			lastErr = fmt.Errorf("llm: openai request: %w", err)
		}

		if attempt == m.cfg.MaxRetries {
			break
		}
		delay := backoffDelay(m.cfg.BaseBackoff, attempt, retryAfter, hasRetryAfter)
		if sleepErr := sleepContext(ctx, delay); sleepErr != nil {
			return nil, sleepErr
		}
	}
	return nil, lastErr
}

func (m *openAIModel) doOnce(ctx context.Context, payload []byte) (data []byte, status int, retryAfter time.Duration, hasRetryAfter bool, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, m.cfg.BaseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return nil, 0, 0, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+m.cfg.APIKey)

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return nil, 0, 0, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, maxOpenAIResponseBytes+1)
	data, err = io.ReadAll(limited)
	if err != nil {
		return nil, resp.StatusCode, 0, false, err
	}
	if len(data) > maxOpenAIResponseBytes {
		return nil, resp.StatusCode, 0, false, fmt.Errorf("llm: openai response exceeds %d bytes", maxOpenAIResponseBytes)
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

// backoffDelay prefers an honoured Retry-After, capped at backoffCap; otherwise it computes
// exponential backoff from base with full jitter (a uniform draw in [0, min(cap, base*2^attempt)]).
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
	if len(data) > errorBodyTruncateBytes {
		return string(data[:errorBodyTruncateBytes])
	}
	return string(data)
}
