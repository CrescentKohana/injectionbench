package demo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/CrescentKohana/injectionbench/internal/target"
)

const maxRequestBodyBytes = 1 << 20

// Handler serves POST /chat (the target contract) and GET/HEAD /healthz. Each /chat request logs
// one JSON line with a request ID, never the request body or the canary; health checks are not
// logged.
func (a *App) Handler(logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/chat", a.chatHandler(logger))
	return mux
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (a *App) chatHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()

		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			logger.Info("chat request", "request_id", reqID, "status", http.StatusMethodNotAllowed, "method", r.Method)
			return
		}

		var req target.Request
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			logger.Info("chat request", "request_id", reqID, "status", http.StatusBadRequest)
			return
		}

		resp, err := a.Send(r.Context(), req)
		if errors.Is(err, errNoMessages) {
			w.WriteHeader(http.StatusBadRequest)
			logger.Info("chat request", "request_id", reqID, "status", http.StatusBadRequest)
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			logger.Info("chat request", "request_id", reqID, "status", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error("chat response encoding failed", "request_id", reqID)
			return
		}
		logger.Info("chat request", "request_id", reqID, "status", http.StatusOK)
	}
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
