package cli_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/cli"
	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/llm"
)

// TestCLIRunExplicitLLMWithHTTPTargetIsUsageError covers H3: an http(s):// target owns its own
// model, so an explicit --llm (valid or not) is a usage error, not merely ignored. The target
// here is a real, working server, so without the validation the run would otherwise succeed.
func TestCLIRunExplicitLLMWithHTTPTargetIsUsageError(t *testing.T) {
	app := demo.New(demo.ModeVulnerable, llm.NewSimulated(1))
	srv := httptest.NewServer(app.Handler(slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer srv.Close()

	for _, llmValue := range []string{"openai", "opnai"} {
		t.Run(llmValue, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, "run",
				"--target", srv.URL+"/chat", "--llm", llmValue, "--trials", "1", "--judge", "canary")
			if code != 2 {
				t.Errorf("exit code = %d, want 2 for an explicit --llm %q against an http(s) target "+
					"(the remote app owns its own model); stdout=%q stderr=%q", code, llmValue, stdout, stderr)
			}
		})
	}
}

// TestCLIRunUnknownLLMWithBuiltinTargetIsUsageError covers H3: --llm is validated for every
// target, including a builtin one.
func TestCLIRunUnknownLLMWithBuiltinTargetIsUsageError(t *testing.T) {
	code, _, stderr := runCLI(t, "run", "--target", "builtin:vulnerable", "--llm", "bogus", "--trials", "1")
	if code != 2 {
		t.Errorf("exit code = %d, want 2 for --llm bogus; stderr=%s", code, stderr)
	}
}

// syncBuffer is a concurrency-safe io.Writer that signals on ch whenever new bytes are written,
// so a reader can block on the channel instead of polling on a fixed sleep.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ch  chan struct{}
}

func newSyncBuffer() *syncBuffer { return &syncBuffer{ch: make(chan struct{}, 1)} }

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.buf.Write(p)
	s.mu.Unlock()
	select {
	case s.ch <- struct{}{}:
	default:
	}
	return n, err
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

var listeningAddrRe = regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)

// waitForListeningAddress blocks on syncBuffer's write signal, never a fixed sleep, until the
// "listening on 127.0.0.1:<port>" line appears or the deadline elapses.
func waitForListeningAddress(t *testing.T, buf *syncBuffer) string {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if m := listeningAddrRe.FindStringSubmatch(buf.String()); m != nil {
			return m[1]
		}
		select {
		case <-buf.ch:
		case <-deadline:
			t.Fatalf("stderr never printed a \"listening on 127.0.0.1:<port>\" line within 3s; got %q", buf.String())
		}
	}
}

// TestCLIServePrintsListeningAddressAndAnswersHealthz covers H3: serve prints the actual bound
// address to stderr once listening, and that address answers GET /healthz with 200.
func TestCLIServePrintsListeningAddressAndAnswersHealthz(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stderr := newSyncBuffer()
	var stdout bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, []string{"serve", "--mode", "vulnerable", "--addr", "127.0.0.1:0"}, &stdout, stderr)
	}()

	addr := waitForListeningAddress(t, stderr)

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/healthz", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext returned error: %v", err)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("GET %s/healthz failed: %v", addr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, want 0 after a cancelled context triggers graceful shutdown; stdout=%q stderr=%q",
				code, stdout.String(), stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not shut down within 3s of context cancellation")
	}
}
