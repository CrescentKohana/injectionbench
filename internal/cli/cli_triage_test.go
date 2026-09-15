package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/report"
)

func TestCLIRunTrialsOutOfRangeIsUsageError(t *testing.T) {
	for _, trials := range []string{"0", "-1", "100001", "2147483647"} {
		t.Run(trials, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, "run", "--target", "builtin:vulnerable", "--trials", trials)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "--trials") {
				t.Errorf("code=%d stdout=%q stderr=%q, want exit 2, no report, and a --trials message", code, stdout, stderr)
			}
		})
	}
}

func TestCLIExplicitlyEmptyLLMIsUsageError(t *testing.T) {
	code, _, stderr := runCLI(t, "run", "--target", "builtin:vulnerable", "--llm=", "--trials", "1")
	if code != 2 || !strings.Contains(stderr, "--llm") {
		t.Errorf("code=%d stderr=%q, want exit 2 naming --llm", code, stderr)
	}
}

func TestCLIRunConcurrencyAboveLimitIsUsageError(t *testing.T) {
	code, stdout, stderr := runCLI(t, "run", "--target", "builtin:hardened", "--trials", "1", "--concurrency", "1025")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "--concurrency") {
		t.Errorf("code=%d stdout=%q stderr=%q, want exit 2 and a --concurrency message", code, stdout, stderr)
	}
}

func TestCLIRunMaxConcurrencyAboveJobCountEndToEnd(t *testing.T) {
	code, stdout, stderr := runCLI(t, "run", "--target", "builtin:hardened", "--category", "direct", "--trials", "1", "--concurrency", "1024")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q, want exit 0", code, stderr)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil || rep.Overall.Trials == 0 {
		t.Fatalf("stdout is not a report with measured trials: err=%v\n%s", err, stdout)
	}
}
