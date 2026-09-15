package target_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

func TestNewHTTPAgainstDemoHandler(t *testing.T) {
	model := &scriptedModel{completion: llm.Completion{Content: "hello from the demo"}}
	app := demo.New(demo.ModeVulnerable, model)
	srv := httptest.NewServer(app.Handler(testLogger(t)))
	defer srv.Close()

	tgt := target.NewHTTP(srv.URL+"/chat", 5*time.Second)
	resp, err := tgt.Send(context.Background(), target.Request{
		Messages: []target.Message{{Role: "user", Content: "hi"}},
		Canary:   "IB-0000000000000000",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if resp.Reply != "hello from the demo" {
		t.Errorf("Reply = %q, want %q", resp.Reply, "hello from the demo")
	}
}

func TestNewHTTPNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	tgt := target.NewHTTP(srv.URL, 5*time.Second)
	_, err := tgt.Send(context.Background(), target.Request{Canary: "x"})
	if err == nil {
		t.Fatal("Send returned nil error for a 500 response, want an error")
	}
}

func TestNewHTTPOversizedResponse(t *testing.T) {
	huge := strings.Repeat("a", 2<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := target.Response{Reply: huge}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tgt := target.NewHTTP(srv.URL, 5*time.Second)
	_, err := tgt.Send(context.Background(), target.Request{Canary: "x"})
	if err == nil {
		t.Fatal("Send returned nil error for a response over 1 MiB, want an error")
	}
}

func TestNewHTTPNullToolCallsDecodesEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"reply":"ok","tool_calls":null}`)
	}))
	defer srv.Close()

	tgt := target.NewHTTP(srv.URL, 5*time.Second)
	resp, err := tgt.Send(context.Background(), target.Request{Canary: "x"})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if len(resp.ToolCalls) != 0 {
		t.Errorf("ToolCalls = %v, want empty", resp.ToolCalls)
	}
}

func TestNewHTTPSendsJSONRequestBody(t *testing.T) {
	var captured target.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body failed: %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decoding request body failed: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(target.Response{Reply: "ack"})
	}))
	defer srv.Close()

	tgt := target.NewHTTP(srv.URL, 5*time.Second)
	req := target.Request{
		Messages: []target.Message{{Role: "user", Content: "hi"}},
		Canary:   "IB-ABCDEF0123456789",
	}
	if _, err := tgt.Send(context.Background(), req); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if captured.Canary != req.Canary {
		t.Errorf("captured Canary = %q, want %q", captured.Canary, req.Canary)
	}
	if len(captured.Messages) != 1 || captured.Messages[0].Content != "hi" {
		t.Errorf("captured Messages = %+v, want one message with content %q", captured.Messages, "hi")
	}
}

func TestNewHTTPNetworkErrorToUnreachableHost(t *testing.T) {
	tgt := target.NewHTTP("http://127.0.0.1:1", 200*time.Millisecond)
	_, err := tgt.Send(context.Background(), target.Request{Canary: "x"})
	if err == nil {
		t.Fatal("Send returned nil error for an unreachable host, want an error")
	}
}

type scriptedModel struct {
	completion llm.Completion
}

func (m *scriptedModel) Complete(ctx context.Context, req llm.Request) (llm.Completion, error) {
	return m.completion, nil
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
