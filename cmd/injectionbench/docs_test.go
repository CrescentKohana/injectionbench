// Package main_test holds contract tests that check the repository's documentation and config
// files against the behaviour they describe, so the two cannot silently drift apart.
package main_test

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/judge"
)

const (
	readmePath        = "../../README.md"
	shippedLabelsPath = "../../datasets/judge-labels.jsonl"
	gitignorePath     = "../../.gitignore"
)

var readmeConfusionMatrixRe = regexp.MustCompile(
	`(?s)\|\s*TP\s*\|\s*FP\s*\|\s*TN\s*\|\s*FN\s*\|[^\n]*\n\|[-\s|]+\|\n\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|`,
)

func openShippedLabels(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open(shippedLabelsPath)
	if err != nil {
		t.Fatalf("opening %s failed: %v (acceptance criterion 6 requires this shipped dataset)", shippedLabelsPath, err)
	}
	return f
}

// TestCanaryJudgeConfusionMatrixMatchesPublishedREADME reads README.md's published TP/FP/TN/FN
// table and asserts it still matches the canary judge's actual confusion matrix on the shipped
// labels, so the two cannot silently drift apart.
func TestCanaryJudgeConfusionMatrixMatchesPublishedREADME(t *testing.T) {
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s failed: %v", readmePath, err)
	}
	m := readmeConfusionMatrixRe.FindStringSubmatch(string(data))
	if m == nil {
		t.Fatalf("%s has no TP/FP/TN/FN table in the expected Markdown format; update this test's regex if the layout changed", readmePath)
	}
	want := make([]int, 4)
	for i, s := range m[1:5] {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("parsing %q as an int failed: %v", s, err)
		}
		want[i] = n
	}

	f := openShippedLabels(t)
	defer func() { _ = f.Close() }()
	labels, err := judge.LoadLabels(bufio.NewReader(f))
	if err != nil {
		t.Fatalf("LoadLabels(%s) returned error: %v", shippedLabelsPath, err)
	}

	metrics, err := judge.Validate(context.Background(), judge.NewCanary(), labels)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	got := []int{metrics.TP, metrics.FP, metrics.TN, metrics.FN}
	names := []string{"TP", "FP", "TN", "FN"}
	for i, name := range names {
		if got[i] != want[i] {
			t.Errorf("%s = %d, want %d (README.md's published confusion matrix for the canary judge on the shipped labels)", name, got[i], want[i])
		}
	}
}

// TestGitignoreIgnoresREADMEQuickStartOutputs covers F7: the README's quick-start commands write
// vulnerable.json and hardened.json at the repository root, and .gitignore must exclude exactly
// those root-level paths so a reader following the quick start doesn't accidentally commit them.
func TestGitignoreIgnoresREADMEQuickStartOutputs(t *testing.T) {
	f, err := os.Open(gitignorePath)
	if err != nil {
		t.Fatalf("opening %s failed: %v", gitignorePath, err)
	}
	defer func() { _ = f.Close() }()

	lines := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines[strings.TrimSpace(scanner.Text())] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s failed: %v", gitignorePath, err)
	}

	for _, want := range []string{"/vulnerable.json", "/hardened.json"} {
		if !lines[want] {
			t.Errorf("%s does not contain the line %q", gitignorePath, want)
		}
	}
}
