package demo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

func postChat(t *testing.T, app *demo.App, req target.Request) int {
	t.Helper()
	srv := httptest.NewServer(app.Handler(discardLogger()))
	defer srv.Close()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/chat", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestHandlerChatModelFailureIsServerError(t *testing.T) {
	app := demo.New(demo.ModeHardened, &recordingModel{err: errors.New("model unavailable")})
	req := target.Request{Messages: []target.Message{{Role: "user", Content: "hi"}}, Canary: "IB-0000000000000000"}
	if status := postChat(t, app, req); status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when the model fails", status)
	}
}

func TestHandlerChatWithoutMessagesIsBadRequest(t *testing.T) {
	for _, mode := range []demo.Mode{demo.ModeVulnerable, demo.ModeHardened} {
		t.Run(string(mode), func(t *testing.T) {
			app := demo.New(mode, &recordingModel{completion: llm.Completion{Content: "ok"}})
			srv := httptest.NewServer(app.Handler(discardLogger()))
			defer srv.Close()

			body, err := json.Marshal(target.Request{Messages: []target.Message{}, Canary: "IB-0000000000000000"})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/chat", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for a request without messages", resp.StatusCode)
			}
		})
	}
}
