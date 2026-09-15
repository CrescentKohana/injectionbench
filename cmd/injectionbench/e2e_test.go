package main_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/report"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary build under -short: requires invoking the go toolchain")
	}
	bin := filepath.Join(t.TempDir(), "injectionbench")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".") //nolint:gosec // G204: fixed "go build" invocation; bin is this test's own t.TempDir() path
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func runBinary(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...) //nolint:gosec // G204: bin is the binary this test just built, not external input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("running binary failed: %v", err)
		}
	}
	return code, stdout.String(), stderr.String()
}

func TestBinaryRunMaxASRExitCode(t *testing.T) {
	bin := buildBinary(t)
	code, _, stderr := runBinary(t, bin, "run", "--target", "builtin:vulnerable", "--llm", "sim", "--judge", "canary", "--trials", "10", "--seed", "1", "--max-asr", "0")
	if code != 1 {
		t.Errorf("exit code = %d, want 1; stderr=%s", code, stderr)
	}
}

func TestBinaryCompareExitCodes(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	writeReport := func(name string, successes, trials int) string {
		path := filepath.Join(dir, name)
		f, err := os.Create(path) //nolint:gosec // G304: path is built from this test's own t.TempDir(), not external input
		if err != nil {
			t.Fatalf("Create returned error: %v", err)
		}
		defer func() { _ = f.Close() }()
		r := report.Report{
			Tool: "injectionbench", Version: "test", Target: "t", Judge: "canary",
			TrialsPerAttack: trials, Seed: 1, Confidence: 0.95,
			Overall: report.Rate{Successes: successes, Trials: trials, ASR: float64(successes) / float64(trials)},
		}
		if err := report.WriteJSON(f, r); err != nil {
			t.Fatalf("WriteJSON returned error: %v", err)
		}
		return path
	}

	noRegressionBaseline := writeReport("stable-baseline.json", 10, 100)
	noRegressionCurrent := writeReport("stable-current.json", 10, 100)
	code, _, stderr := runBinary(t, bin, "compare", "--baseline", noRegressionBaseline, "--current", noRegressionCurrent)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 for no regression; stderr=%s", code, stderr)
	}

	regressionBaseline := writeReport("regressed-baseline.json", 5, 100)
	regressionCurrent := writeReport("regressed-current.json", 50, 100)
	code, _, stderr = runBinary(t, bin, "compare", "--baseline", regressionBaseline, "--current", regressionCurrent)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 for a significant regression; stderr=%s", code, stderr)
	}
}
