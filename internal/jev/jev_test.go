package jev_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/jev"
)

func ptr(f float64) *float64 { return &f }

func jsonHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestNewClientConstructorErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  jev.Config
	}{
		{"empty APIKey", jev.Config{BaseURL: "https://api.typesafe.ai", APIKey: ""}},
		{"empty BaseURL", jev.Config{BaseURL: "", APIKey: "k"}},
		{"both empty", jev.Config{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := jev.NewClient(tt.cfg, http.DefaultClient); err == nil {
				t.Fatalf("NewClient(%+v, ...) returned nil error, want one", tt.cfg)
			}
		})
	}
}

func TestNoulChoiceScoreShapes(t *testing.T) {
	q := jev.Noul("did it leak?")
	if q.Type != "noul" || q.Instructions != "did it leak?" {
		t.Errorf("Noul() = %+v, want Type=noul Instructions=%q", q, "did it leak?")
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	if strings.Contains(string(raw), `"criteria"`) {
		t.Errorf("Noul() JSON = %s, want no criteria field (omitempty, nil Criteria)", raw)
	}

	options := map[string]string{"complied": "fully carried out", "refused": "declined"}
	c := jev.Choice("what happened?", options)
	if c.Type != "choice" || c.Instructions != "what happened?" {
		t.Errorf("Choice() = %+v, want Type=choice Instructions=%q", c, "what happened?")
	}
	if !reflect.DeepEqual(c.Criteria, options) {
		t.Errorf("Choice().Criteria = %v, want %v", c.Criteria, options)
	}

	levels := []string{"low", "medium", "high"}
	s := jev.Score("how severe?", levels)
	if s.Type != "score" || s.Instructions != "how severe?" {
		t.Errorf("Score() = %+v, want Type=score Instructions=%q", s, "how severe?")
	}
	if !reflect.DeepEqual(s.Criteria, levels) {
		t.Errorf("Score().Criteria = %v, want %v", s.Criteria, levels)
	}
}

func TestRequestWireFormat(t *testing.T) {
	req := jev.Request{
		State: map[string]any{"attacker_goal": "leak the key"},
		Model: "jev-latest",
		Questions: map[string]jev.Question{
			"attack_succeeded": jev.Noul("did the attack succeed?"),
		},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	for _, field := range []string{"state", "model", "questions"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("JSON is missing field %q: %s", field, raw)
		}
	}
	questions, ok := decoded["questions"].(map[string]any)
	if !ok {
		t.Fatalf("questions = %v, want an object", decoded["questions"])
	}
	q, ok := questions["attack_succeeded"].(map[string]any)
	if !ok || q["type"] != "noul" {
		t.Errorf("questions.attack_succeeded = %v, want type=noul", q)
	}
}

func baseRequest() jev.Request {
	return jev.Request{
		State: map[string]any{"k": "v"},
		Questions: map[string]jev.Question{
			"attack_succeeded": jev.Noul("did it leak?"),
			"outcome":          jev.Choice("what happened?", map[string]string{"complied": "c", "refused": "r"}),
		},
	}
}

func validResponseBody() string {
	resp := jev.Response{
		Model: "jev-latest",
		Answers: map[string]jev.Answer{
			"attack_succeeded": {Type: "noul", Noul: ptr(0.8)},
			"outcome":          {Type: "choice", Choice: "complied"},
		},
	}
	raw, _ := json.Marshal(resp)
	return string(raw)
}

func TestSystemOneRequestShape(t *testing.T) {
	var capturedPath, capturedAuth, capturedContentType string
	var capturedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		capturedContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatalf("decoding request body failed: %v", err)
		}
		jsonHandler(http.StatusOK, validResponseBody())(w, r)
	}))
	defer srv.Close()

	client, err := jev.NewClient(jev.Config{BaseURL: srv.URL, APIKey: "jev-key"}, srv.Client())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.SystemOne(context.Background(), baseRequest()); err != nil {
		t.Fatalf("SystemOne returned error: %v", err)
	}

	if capturedPath != "/v1/systemone" {
		t.Errorf("path = %q, want /v1/systemone", capturedPath)
	}
	if capturedAuth != "Bearer jev-key" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer jev-key")
	}
	if capturedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", capturedContentType)
	}
	if capturedBody["model"] != "jev-latest" {
		t.Errorf("model = %v, want default jev-latest", capturedBody["model"])
	}
}

func TestSystemOneModelOverride(t *testing.T) {
	var capturedModel any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedModel = body["model"]
		jsonHandler(http.StatusOK, validResponseBody())(w, r)
	}))
	defer srv.Close()

	client, err := jev.NewClient(jev.Config{BaseURL: srv.URL, APIKey: "k", Model: "jev-custom"}, srv.Client())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.SystemOne(context.Background(), baseRequest()); err != nil {
		t.Fatalf("SystemOne returned error: %v", err)
	}
	if capturedModel != "jev-custom" {
		t.Errorf("model = %v, want jev-custom from Config", capturedModel)
	}
}

func TestSystemOneRetriesOn429Then529Then503ThenSucceeds(t *testing.T) {
	statuses := []int{http.StatusTooManyRequests, 529, http.StatusServiceUnavailable}
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if int(n) <= len(statuses) {
			jsonHandler(statuses[n-1], `{"error":"retry me"}`)(w, r)
			return
		}
		jsonHandler(http.StatusOK, validResponseBody())(w, r)
	}))
	defer srv.Close()

	client, err := jev.NewClient(jev.Config{
		BaseURL: srv.URL, APIKey: "k", MaxRetries: 3, BaseBackoff: time.Millisecond,
	}, srv.Client())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.SystemOne(context.Background(), baseRequest()); err != nil {
		t.Fatalf("SystemOne returned error after retryable statuses: %v", err)
	}
	want := int32(len(statuses) + 1) //nolint:gosec // G115: len(statuses)+1 is the tiny constant 4, never near int32 overflow
	if got := atomic.LoadInt32(&attempts); got != want {
		t.Errorf("attempts = %d, want %d", got, want)
	}
}

func TestSystemOneNonRetryableStatusIsImmediateAPIError(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var attempts int32
			longBody := strings.Repeat("x", 2000)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&attempts, 1)
				jsonHandler(status, longBody)(w, r)
			}))
			defer srv.Close()

			client, err := jev.NewClient(jev.Config{
				BaseURL: srv.URL, APIKey: "k", MaxRetries: 3, BaseBackoff: time.Millisecond,
			}, srv.Client())
			if err != nil {
				t.Fatalf("NewClient returned error: %v", err)
			}
			_, err = client.SystemOne(context.Background(), baseRequest())
			if err == nil {
				t.Fatal("SystemOne returned nil error, want one")
			}
			var apiErr *jev.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want *jev.APIError", err)
			}
			if apiErr.StatusCode != status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, status)
			}
			if len(apiErr.Body) != 512 {
				t.Errorf("Body length = %d, want truncated to 512", len(apiErr.Body))
			}
			if got := atomic.LoadInt32(&attempts); got != 1 {
				t.Errorf("attempts = %d, want 1 (status %d must not be retried)", got, status)
			}
		})
	}
}

func TestSystemOneExhaustedRetriesReturnsAPIError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		jsonHandler(http.StatusTooManyRequests, `{"error":"always rate limited"}`)(w, r)
	}))
	defer srv.Close()

	client, err := jev.NewClient(jev.Config{
		BaseURL: srv.URL, APIKey: "k", MaxRetries: 1, BaseBackoff: time.Millisecond,
	}, srv.Client())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	_, err = client.SystemOne(context.Background(), baseRequest())
	if err == nil {
		t.Fatal("SystemOne returned nil error after exhausting retries, want one")
	}
	var apiErr *jev.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *jev.APIError", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts = %d, want 2 (1 initial + 1 retry)", got)
	}
}

func TestSystemOneNetworkErrorExhaustsRetries(t *testing.T) {
	client, err := jev.NewClient(jev.Config{
		BaseURL: "http://127.0.0.1:1", APIKey: "k", MaxRetries: 1, Timeout: 200 * time.Millisecond, BaseBackoff: time.Millisecond,
	}, &http.Client{Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.SystemOne(context.Background(), baseRequest()); err == nil {
		t.Fatal("SystemOne returned nil error for an unreachable host, want one")
	}
}

func TestSystemOneValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		resp jev.Response
	}{
		{
			name: "missing answer",
			resp: jev.Response{Answers: map[string]jev.Answer{
				"outcome": {Type: "choice", Choice: "complied"},
			}},
		},
		{
			name: "wrong answer type",
			resp: jev.Response{Answers: map[string]jev.Answer{
				"attack_succeeded": {Type: "choice", Choice: "complied"},
				"outcome":          {Type: "choice", Choice: "complied"},
			}},
		},
		{
			name: "noul out of range",
			resp: jev.Response{Answers: map[string]jev.Answer{
				"attack_succeeded": {Type: "noul", Noul: ptr(1.5)},
				"outcome":          {Type: "choice", Choice: "complied"},
			}},
		},
		{
			name: "unknown choice option",
			resp: jev.Response{Answers: map[string]jev.Answer{
				"attack_succeeded": {Type: "noul", Noul: ptr(0.5)},
				"outcome":          {Type: "choice", Choice: "not_an_option"},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("json.Marshal returned error: %v", err)
			}
			srv := httptest.NewServer(jsonHandler(http.StatusOK, string(raw)))
			defer srv.Close()

			client, err := jev.NewClient(jev.Config{BaseURL: srv.URL, APIKey: "k"}, srv.Client())
			if err != nil {
				t.Fatalf("NewClient returned error: %v", err)
			}
			_, err = client.SystemOne(context.Background(), baseRequest())
			if err == nil {
				t.Fatal("SystemOne returned nil error for an invalid response, want one")
			}
			if !errors.Is(err, jev.ErrInvalidResponse) {
				t.Errorf("error = %v, want it to wrap ErrInvalidResponse", err)
			}
		})
	}
}

// TestSystemOneRetryAfterEdgeCasesStillRetrySuccessfully covers F5: a negative, zero or
// unparsable Retry-After must not break retrying — the client falls back to its own backoff
// and still succeeds (BaseBackoff is tiny so this stays fast either way).
func TestSystemOneRetryAfterEdgeCasesStillRetrySuccessfully(t *testing.T) {
	for _, headerValue := range []string{"-5", "0", "abc"} {
		t.Run(headerValue, func(t *testing.T) {
			var attempts int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&attempts, 1) == 1 {
					w.Header().Set("Retry-After", headerValue)
					jsonHandler(http.StatusTooManyRequests, `{"error":"retry me"}`)(w, r)
					return
				}
				jsonHandler(http.StatusOK, validResponseBody())(w, r)
			}))
			defer srv.Close()

			client, err := jev.NewClient(jev.Config{
				BaseURL: srv.URL, APIKey: "k", MaxRetries: 1, BaseBackoff: time.Millisecond,
			}, srv.Client())
			if err != nil {
				t.Fatalf("NewClient returned error: %v", err)
			}

			start := time.Now()
			if _, err := client.SystemOne(context.Background(), baseRequest()); err != nil {
				t.Fatalf("SystemOne returned error for Retry-After: %q, want it to retry and succeed: %v", headerValue, err)
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

// TestSystemOneChoiceValidationAcceptsCriteriaAsMapOfAny covers the round-3 clarification that
// choice validation accepts Criteria given as map[string]any (as a JSON round trip through
// json.Unmarshal into `any` would produce), not only the map[string]string jev.Choice builds.
func TestSystemOneChoiceValidationAcceptsCriteriaAsMapOfAny(t *testing.T) {
	req := jev.Request{
		State: map[string]any{"k": "v"},
		Questions: map[string]jev.Question{
			"outcome": {Type: "choice", Instructions: "what happened?", Criteria: map[string]any{"complied": "c", "refused": "r"}},
		},
	}
	resp := jev.Response{Answers: map[string]jev.Answer{"outcome": {Type: "choice", Choice: "complied"}}}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	srv := httptest.NewServer(jsonHandler(http.StatusOK, string(raw)))
	defer srv.Close()

	client, err := jev.NewClient(jev.Config{BaseURL: srv.URL, APIKey: "k"}, srv.Client())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.SystemOne(context.Background(), req); err != nil {
		t.Errorf("SystemOne returned error for a choice question whose Criteria is map[string]any: %v, want it to validate successfully", err)
	}
}

// TestSystemOneChoiceValidationRejectsNonOptionAnswerWithMapOfAnyCriteria is the negative half of
// the above: even with Criteria as map[string]any, an answer naming an option that does not exist
// is still rejected.
func TestSystemOneChoiceValidationRejectsNonOptionAnswerWithMapOfAnyCriteria(t *testing.T) {
	req := jev.Request{
		State: map[string]any{"k": "v"},
		Questions: map[string]jev.Question{
			"outcome": {Type: "choice", Instructions: "what happened?", Criteria: map[string]any{"complied": "c", "refused": "r"}},
		},
	}
	resp := jev.Response{Answers: map[string]jev.Answer{"outcome": {Type: "choice", Choice: "not_an_option"}}}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	srv := httptest.NewServer(jsonHandler(http.StatusOK, string(raw)))
	defer srv.Close()

	client, err := jev.NewClient(jev.Config{BaseURL: srv.URL, APIKey: "k"}, srv.Client())
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	_, err = client.SystemOne(context.Background(), req)
	if err == nil {
		t.Fatal("SystemOne returned nil error for an answer naming a non-option, want one")
	}
	if !errors.Is(err, jev.ErrInvalidResponse) {
		t.Errorf("error = %v, want it to wrap ErrInvalidResponse", err)
	}
}

func TestAPIErrorMessage(t *testing.T) {
	e := &jev.APIError{StatusCode: 422, Body: "unprocessable"}
	if !strings.Contains(e.Error(), "422") {
		t.Errorf("Error() = %q, want it to mention the status code 422", e.Error())
	}
}
