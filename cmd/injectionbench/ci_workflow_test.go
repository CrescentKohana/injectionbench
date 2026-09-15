package main_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/report"
)

const ciWorkflowPath = "../../.github/workflows/ci.yml"

var (
	stepStartRe         = regexp.MustCompile(`^(\s*)-\s+\S`)
	runLineRe           = regexp.MustCompile(`(?m)^(\s*)run:(.*)$`)
	shellValueRe        = regexp.MustCompile(`(?m)^\s*shell:\s*(.+?)\s*$`)
	usesLineRe          = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	pinnedUsesRe        = regexp.MustCompile(`^([^\s@]+)@([0-9A-Fa-f]{40})\s*#\s*(v\S+)\s*$`)
	exitCodeEqualsOneRe = regexp.MustCompile(`-eq\s*1\b|-ne\s*1\b|==\s*1\b|!=\s*1\b`)
)

var gatingKeywords = []string{"injectionbench compare", "--max-asr", "validate-judges"}

func readCIWorkflowLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(ciWorkflowPath)
	if err != nil {
		t.Fatalf("reading %s failed: %v", ciWorkflowPath, err)
	}
	return strings.Split(string(data), "\n")
}

// splitSteps groups ci.yml's lines into one block per step ("- " list item): the indentation of
// the first such line found sets the column every step boundary must match, and a dedent below
// that column (leaving the enclosing steps: list) resets the parser for the next job.
func splitSteps(lines []string) []string {
	indent := -1
	var steps []string
	var current []string
	for _, line := range lines {
		if m := stepStartRe.FindStringSubmatch(line); m != nil {
			col := len(m[1])
			if indent == -1 || col == indent {
				indent = col
				if len(current) > 0 {
					steps = append(steps, strings.Join(current, "\n"))
				}
				current = []string{line}
				continue
			}
		}
		if indent == -1 {
			continue
		}
		leading := len(line) - len(strings.TrimLeft(line, " "))
		if strings.TrimSpace(line) != "" && leading < indent {
			steps = append(steps, strings.Join(current, "\n"))
			current = nil
			indent = -1
			continue
		}
		current = append(current, line)
	}
	if len(current) > 0 {
		steps = append(steps, strings.Join(current, "\n"))
	}
	return steps
}

// runBlockOf extracts the shell script under a step's run: key, excluding the surrounding YAML
// (name:, uses:, shell:, the run: key itself), so gating-command detection and the pipefail-guard
// ordering check operate on the script instead of matching YAML metadata by coincidence.
func runBlockOf(step string) string {
	lines := strings.Split(step, "\n")
	for i, line := range lines {
		m := runLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if rest := strings.TrimSpace(m[2]); rest != "" && rest != "|" && rest != ">" {
			return rest
		}
		runIndent := len(m[1])
		var block []string
		for _, l := range lines[i+1:] {
			if strings.TrimSpace(l) == "" {
				block = append(block, l)
				continue
			}
			if len(l)-len(strings.TrimLeft(l, " ")) <= runIndent {
				break
			}
			block = append(block, l)
		}
		return strings.Join(block, "\n")
	}
	return ""
}

func containsGatingCommand(runBlock string) bool {
	for _, kw := range gatingKeywords {
		if strings.Contains(runBlock, kw) {
			return true
		}
	}
	return false
}

// hasPipefailGuard reports whether runBlock protects a pipe from swallowing a failing exit code:
// either the step's shell: value itself enables pipefail, or "set -o pipefail" appears in the
// script before the first "|".
func hasPipefailGuard(step, runBlock string) bool {
	if m := shellValueRe.FindStringSubmatch(step); m != nil && strings.Contains(m[1], "-o pipefail") {
		return true
	}
	pipeIdx := strings.Index(runBlock, "|")
	if pipeIdx < 0 {
		return true
	}
	guardIdx := strings.Index(runBlock, "set -o pipefail")
	return guardIdx >= 0 && guardIdx < pipeIdx
}

// TestCIGatedStepsArePipefailSafe checks that a step whose run: script pipes the output of a
// gating command (compare, --max-asr, validate-judges) into anything else does not let the pipe
// swallow a non-zero exit code.
func TestCIGatedStepsArePipefailSafe(t *testing.T) {
	steps := splitSteps(readCIWorkflowLines(t))
	if len(steps) == 0 {
		t.Fatal("no steps found in ci.yml; the parser likely needs updating for a new file layout")
	}

	found := false
	for _, step := range steps {
		runBlock := runBlockOf(step)
		if !containsGatingCommand(runBlock) {
			continue
		}
		found = true
		if !strings.Contains(runBlock, "|") {
			continue
		}
		if !hasPipefailGuard(step, runBlock) {
			t.Errorf("gated step pipes its output but does not guard against the pipe swallowing a failing exit code "+
				"(need `shell: bash` with `set -o pipefail`, or `set -o pipefail` before the first `|` in its run: script):\n%s", step)
		}
	}
	if !found {
		t.Fatal("no step in ci.yml invokes compare, --max-asr or validate-judges; this test's assumptions about the workflow no longer hold")
	}
}

// TestCIReverseDirectionGateUsesAlphaFormatJSONAndJQOnOverallRegressed checks F3: the reverse
// gate runs compare with --alpha 0.01 --format json, requires exit code exactly 1, and uses jq
// against the overall row's regressed field.
func TestCIReverseDirectionGateUsesAlphaFormatJSONAndJQOnOverallRegressed(t *testing.T) {
	steps := splitSteps(readCIWorkflowLines(t))
	var reverseStep string
	for _, step := range steps {
		runBlock := runBlockOf(step)
		if strings.Contains(runBlock, "--baseline hardened.json") && strings.Contains(runBlock, "--current vulnerable.json") {
			reverseStep = runBlock
			break
		}
	}
	if reverseStep == "" {
		t.Fatal("no step runs `compare --baseline hardened.json --current vulnerable.json`; " +
			"this test's assumptions about ci.yml no longer hold")
	}

	if !strings.Contains(reverseStep, "--alpha 0.01") {
		t.Error("reverse-direction gate does not pass --alpha 0.01")
	}
	if !strings.Contains(reverseStep, "--format json") {
		t.Error("reverse-direction gate does not pass --format json")
	}
	if !strings.Contains(reverseStep, "$?") {
		t.Error("reverse-direction gate does not capture the command's exit status ($?)")
	}
	if !exitCodeEqualsOneRe.MatchString(reverseStep) {
		t.Errorf("reverse-direction gate does not check the captured exit code equals exactly 1 "+
			"(want a `-eq 1`, `-ne 1`, `== 1` or `!= 1` style comparison):\n%s", reverseStep)
	}
	if !strings.Contains(reverseStep, "jq") {
		t.Error("reverse-direction gate does not use jq to parse the JSON comparison output")
	}
	if !strings.Contains(reverseStep, "overall") || !strings.Contains(reverseStep, "regressed") {
		t.Error(`reverse-direction gate's jq check does not reference the "overall" row's "regressed" field`)
	}
}

// TestCIActionsArePinnedToFullCommitSHA checks the supply-chain pinning convention: every
// non-local `uses:` reference names a full 40-hex commit SHA with a trailing version comment.
func TestCIActionsArePinnedToFullCommitSHA(t *testing.T) {
	lines := readCIWorkflowLines(t)
	found := false
	for i, line := range lines {
		m := usesLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ref := m[1]
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		found = true
		parts := strings.SplitN(line, "uses:", 2)
		if len(parts) != 2 {
			t.Fatalf("line %d: %q contains uses: but could not be split on it", i+1, line)
		}
		rest := strings.TrimSpace(parts[1])
		if !pinnedUsesRe.MatchString(rest) {
			t.Errorf("line %d: uses %q is not pinned to a 40-hex commit SHA with a trailing version comment", i+1, rest)
		}
	}
	if !found {
		t.Fatal("no uses: lines found in ci.yml")
	}
}

func writeCIReportFile(t *testing.T, path string, successes, trials int) {
	t.Helper()
	f, err := os.Create(path) //nolint:gosec // G304: path is built from this test's own t.TempDir()
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
}

// fencedBlockRe captures the body of a fenced Markdown code block, for checking that CI's reverse-
// direction JSON is wrapped (H5) rather than pasted raw into the step summary.
var fencedBlockRe = regexp.MustCompile("(?s)```[a-zA-Z]*\\s*\\n(.*?)```")

// TestCIReverseDirectionGateScriptActuallyGates covers F3 and H5: it executes the reverse-direction
// gate's run: script with bash -eo pipefail against real reports, and checks that what it appends
// to $GITHUB_STEP_SUMMARY on success is fenced.
func TestCIReverseDirectionGateScriptActuallyGates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping under -short: builds the real binary and shells out to bash/jq")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is not installed; the gate script itself requires it")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}

	steps := splitSteps(readCIWorkflowLines(t))
	var script string
	for _, step := range steps {
		runBlock := runBlockOf(step)
		if strings.Contains(runBlock, "--baseline hardened.json") && strings.Contains(runBlock, "--current vulnerable.json") {
			script = runBlock
			break
		}
	}
	if script == "" {
		t.Fatal("no step runs `compare --baseline hardened.json --current vulnerable.json`; " +
			"this test's assumptions about ci.yml no longer hold")
	}

	bin := buildBinary(t)
	binBytes, err := os.ReadFile(bin) //nolint:gosec // G304: bin is the binary this test just built via buildBinary(t), not external input
	if err != nil {
		t.Fatalf("reading built binary failed: %v", err)
	}

	run := func(t *testing.T, hardenedSuccesses, hardenedTrials, vulnSuccesses, vulnTrials int, missingVulnerable bool) (code int, out, summary string) {
		t.Helper()
		dir := t.TempDir()
		binPath := filepath.Join(dir, "injectionbench")
		if err := os.WriteFile(binPath, binBytes, 0o755); err != nil { //nolint:gosec // G306: test fixture needs +x to run as ./injectionbench
			t.Fatalf("writing test binary failed: %v", err)
		}
		writeCIReportFile(t, filepath.Join(dir, "hardened.json"), hardenedSuccesses, hardenedTrials)
		if !missingVulnerable {
			writeCIReportFile(t, filepath.Join(dir, "vulnerable.json"), vulnSuccesses, vulnTrials)
		}
		summaryPath := filepath.Join(dir, "summary.md")
		if err := os.WriteFile(summaryPath, nil, 0o600); err != nil {
			t.Fatalf("creating summary file failed: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-eo", "pipefail", "-c", script) //nolint:gosec // G204: script text comes from this repo's own ci.yml, not external input
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GITHUB_STEP_SUMMARY="+summaryPath)
		var outBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf
		runErr := cmd.Run()
		code = 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				t.Fatalf("running the extracted gate script failed: %v\n%s", runErr, outBuf.String())
			}
		}
		summaryBytes, err := os.ReadFile(summaryPath) //nolint:gosec // G304: path is this test's own t.TempDir() file
		if err != nil {
			t.Fatalf("reading summary file failed: %v", err)
		}
		return code, outBuf.String(), string(summaryBytes)
	}

	t.Run("hardened clearly better exits zero and fences the summary", func(t *testing.T) {
		code, out, summary := run(t, 1, 100, 60, 100, false)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 when hardened is clearly, significantly better than vulnerable; output:\n%s", code, out)
		}
		m := fencedBlockRe.FindStringSubmatch(summary)
		if m == nil {
			t.Fatalf("summary does not contain a fenced code block (H5: the reverse-direction JSON must be fenced):\n%s", summary)
		}
		if !strings.Contains(m[1], `"regressed"`) {
			t.Errorf("fenced block does not contain the reverse-direction comparison JSON:\n%s", m[1])
		}
	})

	t.Run("equal reports exit non-zero", func(t *testing.T) {
		code, out, _ := run(t, 10, 100, 10, 100, false)
		if code == 0 {
			t.Fatalf("exit code = 0, want non-zero when hardened is not significantly better than vulnerable; output:\n%s", out)
		}
	})

	t.Run("missing input file exits non-zero", func(t *testing.T) {
		code, out, _ := run(t, 10, 100, 0, 0, true)
		if code == 0 {
			t.Fatalf("exit code = 0, want non-zero when an input report file is missing; output:\n%s", out)
		}
	})
}
