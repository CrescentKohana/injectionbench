package llm_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/llm"
)

func newOpenAIModel(t *testing.T, srv *httptest.Server, cfg llm.OpenAIConfig) llm.Model {
	t.Helper()
	cfg.BaseURL = srv.URL
	if cfg.Model == "" {
		cfg.Model = "gpt-test"
	}
	model, err := llm.NewOpenAI(cfg, srv.Client())
	if err != nil {
		t.Fatalf("NewOpenAI returned error: %v", err)
	}
	return model
}

func jsonResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestOpenAIConstructorErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  llm.OpenAIConfig
	}{
		{"empty BaseURL", llm.OpenAIConfig{BaseURL: "", Model: "gpt-test"}},
		{"empty Model", llm.OpenAIConfig{BaseURL: "https://api.openai.com/v1", Model: ""}},
		{"both empty", llm.OpenAIConfig{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := llm.NewOpenAI(tt.cfg, http.DefaultClient); err == nil {
				t.Fatalf("NewOpenAI(%+v, ...) returned nil error, want one", tt.cfg)
			}
		})
	}
}

func TestOpenAIRequestShape(t *testing.T) {
	var capturedPath, capturedAuth string
	var capturedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatalf("decoding request body failed: %v", err)
		}
		jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "sk-test-key", Model: "gpt-test"})
	req := llm.Request{
		Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}},
		Tools: []llm.Tool{
			{Name: "search_docs", Description: "search documents", Parameters: []string{"query"}},
		},
	}
	if _, err := model.Complete(ctx(), req); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}

	if capturedPath != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", capturedPath)
	}
	if capturedAuth != "Bearer sk-test-key" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer sk-test-key")
	}
	if capturedBody["model"] != "gpt-test" {
		t.Errorf("model = %v, want gpt-test", capturedBody["model"])
	}

	tools, ok := capturedBody["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("tools = %v, want a one-element array", capturedBody["tools"])
	}
	tool, ok := tools[0].(map[string]any)
	if !ok || tool["type"] != "function" {
		t.Fatalf("tool = %v, want type=function", tool)
	}
	fn, ok := tool["function"].(map[string]any)
	if !ok {
		t.Fatalf("tool.function = %v, want an object", tool["function"])
	}
	if fn["name"] != "search_docs" || fn["description"] != "search documents" {
		t.Errorf("function = %v, want name=search_docs description=\"search documents\"", fn)
	}
	params, ok := fn["parameters"].(map[string]any)
	if !ok || params["type"] != "object" {
		t.Fatalf("parameters = %v, want type=object", fn["parameters"])
	}
	props, ok := params["properties"].(map[string]any)
	if !ok {
		t.Fatalf("parameters.properties = %v, want an object", params["properties"])
	}
	queryProp, ok := props["query"].(map[string]any)
	if !ok || queryProp["type"] != "string" {
		t.Errorf("properties.query = %v, want type=string", props["query"])
	}
	required, ok := params["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "query" {
		t.Errorf("required = %v, want [query]", params["required"])
	}
}

func TestOpenAICompletionParsing(t *testing.T) {
	body := `{"choices":[{"message":{"content":"the answer",` +
		`"tool_calls":[{"function":{"name":"send_email",` +
		`"arguments":"{\"to\":\"a@b.com\",\"count\":3,\"urgent\":true}"}}]}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, body)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k"})
	c, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if c.Content != "the answer" {
		t.Errorf("Content = %q, want %q", c.Content, "the answer")
	}
	if len(c.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %+v, want exactly one", c.ToolCalls)
	}
	call := c.ToolCalls[0]
	if call.Name != "send_email" {
		t.Errorf("Name = %q, want send_email", call.Name)
	}
	if call.Arguments["to"] != "a@b.com" {
		t.Errorf("to = %q, want a@b.com", call.Arguments["to"])
	}
	if call.Arguments["count"] != "3" {
		t.Errorf("count = %q, want stringified \"3\"", call.Arguments["count"])
	}
	if call.Arguments["urgent"] != "true" {
		t.Errorf("urgent = %q, want stringified \"true\"", call.Arguments["urgent"])
	}
}

func TestOpenAINullContentBecomesEmptyString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":null}}]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k"})
	c, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if c.Content != "" {
		t.Errorf("Content = %q, want empty string for null content", c.Content)
	}
}

func TestOpenAIEmptyChoicesIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, `{"choices":[]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k"})
	if _, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}}); err == nil {
		t.Fatal("Complete returned nil error for empty choices, want one")
	}
}

func TestOpenAIRetriesOn429ThenSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"rate limited"}`)
			return
		}
		jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":"ok after retry"}}]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k", MaxRetries: 2, BaseBackoff: time.Millisecond})
	c, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}})
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if c.Content != "ok after retry" {
		t.Errorf("Content = %q, want %q", c.Content, "ok after retry")
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts = %d, want 3 (1 initial + 2 retries)", got)
	}
}

func TestOpenAIRetriesOn5xxThenSucceeds(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			jsonResponse(w, http.StatusBadGateway, `{"error":"bad gateway"}`)
			return
		}
		jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k", MaxRetries: 1, BaseBackoff: time.Millisecond})
	if _, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}}); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2 (1 initial + 1 retry)", got)
	}
}

func TestOpenAIRetryAfterHonoured(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			jsonResponse(w, http.StatusTooManyRequests, `{"error":"rate limited"}`)
			return
		}
		jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k", MaxRetries: 1, BaseBackoff: time.Millisecond})
	start := time.Now()
	if _, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}}); err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond || elapsed > 5*time.Second {
		t.Errorf("elapsed = %v, want about 1s: the jittered fallback is at most 1ms, so only an honoured Retry-After: 1 waits this long", elapsed)
	}
}

// TestOpenAIRetryAfterEdgeCasesStillRetrySuccessfully covers the round-3 clarification that a
// negative, zero or unparsable Retry-After must not break retrying: the client falls back to its
// own backoff and still succeeds. BaseBackoff is tiny so this test stays fast either way.
func TestOpenAIRetryAfterEdgeCasesStillRetrySuccessfully(t *testing.T) {
	for _, headerValue := range []string{"-5", "0", "abc"} {
		t.Run(headerValue, func(t *testing.T) {
			var attempts int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&attempts, 1) == 1 {
					w.Header().Set("Retry-After", headerValue)
					jsonResponse(w, http.StatusTooManyRequests, `{"error":"rate limited"}`)
					return
				}
				jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
			}))
			defer srv.Close()

			model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k", MaxRetries: 1, BaseBackoff: time.Millisecond})
			start := time.Now()
			c, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}})
			if err != nil {
				t.Fatalf("Complete returned error for Retry-After: %q, want it to retry and succeed: %v", headerValue, err)
			}
			if c.Content != "ok" {
				t.Errorf("Content = %q, want %q", c.Content, "ok")
			}
			if elapsed := time.Since(start); elapsed < 0 {
				t.Errorf("observed delay between attempts = %v, want non-negative", elapsed)
			} else if elapsed > 2*time.Second {
				t.Errorf("observed delay between attempts = %v, want well under 2s given a 1ms BaseBackoff", elapsed)
			}
			if got := atomic.LoadInt32(&attempts); got != 2 {
				t.Errorf("attempts = %d, want 2 (1 initial + 1 retry) for Retry-After: %q", got, headerValue)
			}
		})
	}
}

func TestOpenAINonRetryable400(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		jsonResponse(w, http.StatusBadRequest, `{"error":"bad request"}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k", MaxRetries: 3, BaseBackoff: time.Millisecond})
	if _, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}}); err == nil {
		t.Fatal("Complete returned nil error for a 400 response, want one")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts = %d, want 1 (400 must not be retried)", got)
	}
}

func TestOpenAIExhaustedRetriesReturnsError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		jsonResponse(w, http.StatusTooManyRequests, `{"error":"rate limited"}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k", MaxRetries: 1, BaseBackoff: time.Millisecond})
	if _, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}}); err == nil {
		t.Fatal("Complete returned nil error after exhausting retries, want one")
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2 (1 initial + 1 retry)", got)
	}
}

func TestOpenAITimeoutRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		jsonResponse(w, http.StatusOK, `{"choices":[{"message":{"content":"too slow"}}]}`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{
		APIKey: "k", Timeout: 30 * time.Millisecond, MaxRetries: 1, BaseBackoff: time.Millisecond,
	})
	start := time.Now()
	_, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Complete returned nil error for a request exceeding its timeout, want one")
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed = %v, want well under the server's 500ms sleep since the client should time out per attempt", elapsed)
	}
}

func TestOpenAIUndecodableJSONIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, `{not valid json`)
	}))
	defer srv.Close()

	model := newOpenAIModel(t, srv, llm.OpenAIConfig{APIKey: "k"})
	if _, err := model.Complete(ctx(), llm.Request{Messages: []llm.Message{{Role: llm.RoleUser, Content: "hi"}}}); err == nil {
		t.Fatal("Complete returned nil error for undecodable JSON, want one")
	}
}
