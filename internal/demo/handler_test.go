package demo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHandlerChatRoundTrip(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	srv := httptest.NewServer(app.Handler(discardLogger()))
	defer srv.Close()

	body, err := json.Marshal(target.Request{
		Messages: []target.Message{{Role: "user", Content: "hi"}},
		Canary:   "IB-0000000000000010",
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/chat", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext returned error: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("POST /chat returned error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var decoded target.Response
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding response failed: %v", err)
	}
	if decoded.Reply != "hello" {
		t.Errorf("Reply = %q, want %q", decoded.Reply, "hello")
	}
}

func TestHandlerRejectsInvalidJSON(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/chat", strings.NewReader("not valid json"))
	app.Handler(discardLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandlerRejectsWrongMethod(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/chat", nil)
	app.Handler(discardLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestHandlerHealthz(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	app.Handler(discardLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHandlerRejectsOversizedBody(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	huge := target.Request{
		Messages: []target.Message{{Role: "user", Content: strings.Repeat("a", 2<<20)}},
		Canary:   "IB-0000000000000011",
	}
	body, err := json.Marshal(huge)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/chat", bytes.NewReader(body))
	app.Handler(discardLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a body over 1 MiB", rec.Code)
	}
}

func TestHandlerHealthzMethods(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	handler := app.Handler(discardLogger())

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(context.Background(), method, "/healthz", nil)
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for %s /healthz", rec.Code, method)
			}
		})
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/healthz", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 for POST /healthz", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Error("POST /healthz response has no Allow header")
	}
}

func TestHandlerChatMethodNotAllowedSetsAllowHeader(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/chat", nil)
	app.Handler(discardLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Error("GET /chat response has no Allow header")
	}
}

func TestHandlerNilLoggerServesWithoutPanicking(t *testing.T) {
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Handler(nil).ServeHTTP panicked: %v", r)
		}
	}()
	app.Handler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestHandlerLogsOneJSONLinePerRequestWithoutBodyOrCanary(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)

	const canary = "IB-SHOULD-NEVER-BE-LOGGED"
	body, err := json.Marshal(target.Request{
		Messages: []target.Message{{Role: "user", Content: "a very specific message body marker xyz123"}},
		Canary:   canary,
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/chat", bytes.NewReader(body))
	app.Handler(logger).ServeHTTP(rec, req)

	logged := logBuf.String()
	lineCount := 0
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if strings.TrimSpace(line) != "" {
			lineCount++
		}
	}
	if lineCount != 1 {
		t.Errorf("logged %d lines for one request, want 1: %s", lineCount, logged)
	}
	if strings.Contains(logged, canary) {
		t.Errorf("log output contains the canary: %s", logged)
	}
	if strings.Contains(logged, "xyz123") {
		t.Errorf("log output contains the request body: %s", logged)
	}
}
