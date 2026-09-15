// Package target defines the HTTP contract InjectionBench uses to attack an LLM application,
// and an HTTP client implementing it.
package target

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Message is one turn of the conversation sent to a target.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Document is a retrieved (RAG) document; attacker-controllable in an indirect injection attack.
type Document struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// Request is the full state a stateless target needs to answer one turn.
type Request struct {
	Messages    []Message         `json:"messages"`
	Documents   []Document        `json:"documents,omitempty"`
	ToolOutputs map[string]string `json:"tool_outputs,omitempty"`
	Canary      string            `json:"canary"`
}

// ToolCall is a tool invocation the target executed while producing a Response.
type ToolCall struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments"`
}

// Response is what the target returns for one turn.
type Response struct {
	Reply     string     `json:"reply"`
	ToolCalls []ToolCall `json:"tool_calls"`
}

// Target is a system under test.
type Target interface {
	Send(ctx context.Context, req Request) (Response, error)
}

const maxResponseBytes = 1 << 20 // 1 MiB

type httpTarget struct {
	url    string
	client *http.Client
}

// NewHTTP returns a Target that POSTs req as JSON to url and decodes the JSON Response.
func NewHTTP(url string, timeout time.Duration) Target {
	return &httpTarget{
		url:    url,
		client: &http.Client{Timeout: timeout},
	}
}

func (t *httpTarget) Send(ctx context.Context, req Request) (Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("target: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("target: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("target: send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("target: unexpected status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Response{}, fmt.Errorf("target: read response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return Response{}, fmt.Errorf("target: response exceeds %d bytes", maxResponseBytes)
	}

	var out Response
	if err := json.Unmarshal(data, &out); err != nil {
		return Response{}, fmt.Errorf("target: decode response: %w", err)
	}
	return out, nil
}
