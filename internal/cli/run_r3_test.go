package cli_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const oneDirectAttackJSON = `[{"id":"DI-900","name":"n","category":"direct","owasp":["LLM01:2025"],` +
	`"atlas":["AML.T0051.000"],"turns":["go"],"goal":"g","success":{"canary_leak":true}}]`

func writeOneAttackDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(oneDirectAttackJSON), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return dir
}

func TestCLIRunAllTrialsErroredExitsTwo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	code, stdout, stderr := runCLI(t, "run", "--target", srv.URL+"/chat", "--trials", "3", "--seed", "1", "--judge", "canary")
	if code != 2 {
		t.Errorf("exit code = %d, want 2 when every trial errors; stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("stderr is empty, want a message explaining that every trial errored")
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty: a run that measured nothing must not write a report", stdout)
	}
}

func TestCLIRunPartialErrorsWarnOnStderrWithoutChangingExitCode(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":"ok","tool_calls":null}`))
	}))
	defer srv.Close()

	dir := writeOneAttackDir(t)
	code, _, stderr := runCLI(t, "run",
		"--target", srv.URL+"/chat", "--attacks", dir,
		"--trials", "5", "--seed", "1", "--judge", "canary", "--concurrency", "1")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (partial errors must not change the exit code on their own); stderr=%s", code, stderr)
	}
	want := "warning: 1 trials failed and were excluded from every rate"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
}

func TestCLIRunMaxASRNotGivenNeverExitsOne(t *testing.T) {
	code, _, stderr := runCLI(t, "run", "--target", "builtin:vulnerable", "--llm", "sim", "--judge", "canary", "--trials", "20", "--seed", "1")
	if code == 1 {
		t.Errorf("exit code = 1 without --max-asr given, want the threshold to never apply; stderr=%s", stderr)
	}
}

func TestCLIRunMaxASROutOfRangeExitsTwo(t *testing.T) {
	for _, value := range []string{"-0.5", "1.5"} {
		t.Run(value, func(t *testing.T) {
			code, _, stderr := runCLI(t, "run",
				"--target", "builtin:vulnerable", "--llm", "sim", "--judge", "canary", "--trials", "1", "--max-asr", value)
			if code != 2 {
				t.Errorf("exit code = %d, want 2 for --max-asr %s (outside [0,1]); stderr=%s", code, value, stderr)
			}
		})
	}
}
