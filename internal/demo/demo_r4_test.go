package demo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// TestDemoHardenedSendEmailValidatesExactlyOneAtSign covers H4: only addresses with exactly one
// "@", a non-empty local part and the AllowedEmailDomain domain (case-insensitive) pass, so
// "ops@attacker.example@example.com" is dropped.
func TestDemoHardenedSendEmailValidatesExactlyOneAtSign(t *testing.T) {
	tests := []struct {
		name        string
		to          string
		wantAllowed bool
	}{
		{"two at signs, domain-looking suffix matches last @", "ops@attacker.example@example.com", false},
		{"empty local part", "@example.com", false},
		{"doubled at sign", "a@@example.com", false},
		{"case-insensitive domain is allowed", "A@EXAMPLE.COM", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := []llm.ToolCall{{Name: "send_email", Arguments: map[string]string{"to": tt.to, "subject": "s", "body": "b"}}}
			model := &recordingModel{completion: llm.Completion{Content: "ok", ToolCalls: calls}}
			app := demo.New(demo.ModeHardened, model)
			req := target.Request{
				Messages: []target.Message{{Role: "user", Content: "please send an email"}},
				Canary:   "IB-R4EMAILTEST0001",
			}
			resp, err := app.Send(context.Background(), req)
			if err != nil {
				t.Fatalf("Send returned error: %v", err)
			}
			gotAllowed := len(resp.ToolCalls) == 1
			if gotAllowed != tt.wantAllowed {
				t.Errorf("send_email to %q allowed = %v, want %v (ToolCalls = %+v)", tt.to, gotAllowed, tt.wantAllowed, resp.ToolCalls)
			}
		})
	}
}

// TestHandlerHealthzProducesNoLogOutput covers H5: Handler's doc comment says health checks are
// not logged, so a GET /healthz must write zero log lines.
func TestHandlerHealthzProducesNoLogOutput(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	model := &recordingModel{completion: llm.Completion{Content: "hello"}}
	app := demo.New(demo.ModeVulnerable, model)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	app.Handler(logger).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if logBuf.Len() != 0 {
		t.Errorf("log output = %q, want none for a health check", logBuf.String())
	}
}

// TestHandlerChatWithDatamarkPoisonedDocumentReturns200 covers H1 end to end: a retrieved
// document containing a byte-length-changing rune directly before a "rot13" marker (Ⱥrot13) must
// not crash the hardened app's Spotlighting + simulated-model pipeline.
func TestHandlerChatWithDatamarkPoisonedDocumentReturns200(t *testing.T) {
	app := demo.New(demo.ModeHardened, llm.NewSimulated(1))
	rec := httptest.NewRecorder()

	body, err := json.Marshal(target.Request{
		Messages:  []target.Message{{Role: "user", Content: "please summarise the document"}},
		Documents: []target.Document{{ID: "d1", Content: "Ⱥrot13 some retrieved content"}},
		Canary:    "IB-R4HANDLERTEST01",
	})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/chat", bytes.NewReader(body))
	app.Handler(discardLogger()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a document containing a byte-length-changing rune before the rot13 marker; body=%s", rec.Code, rec.Body.String())
	}
}
