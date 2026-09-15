package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/report"
)

func sampleReport() report.Report {
	return report.Report{
		Tool:            "injectionbench",
		Version:         "dev",
		Target:          "builtin:vulnerable",
		Judge:           "canary",
		TrialsPerAttack: 20,
		Seed:            1,
		Confidence:      0.95,
		Overall:         report.Rate{Successes: 10, Trials: 20, ASR: 0.5, CILower: 0.3, CIUpper: 0.7},
		Categories: map[string]report.Rate{
			"direct":   {Successes: 5, Trials: 10, ASR: 0.5, CILower: 0.2, CIUpper: 0.8},
			"indirect": {Successes: 5, Trials: 10, ASR: 0.5, CILower: 0.2, CIUpper: 0.8},
		},
		Attacks: []report.AttackResult{
			{ID: "DI-001", Category: attack.CategoryDirect, Rate: report.Rate{Successes: 5, Trials: 10, ASR: 0.5, CILower: 0.2, CIUpper: 0.8}},
			{ID: "IN-001", Category: attack.CategoryIndirect, Rate: report.Rate{Successes: 5, Trials: 10, ASR: 0.5, CILower: 0.2, CIUpper: 0.8}},
		},
		Errors: 0,
	}
}

func TestWriteJSONThenReadJSONRoundTrip(t *testing.T) {
	want := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, want); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("WriteJSON output does not end with a trailing newline")
	}
	if !strings.Contains(buf.String(), "\n  ") && !strings.Contains(buf.String(), "\n\t") {
		t.Error("WriteJSON output does not look indented")
	}

	got, err := report.ReadJSON(&buf)
	if err != nil {
		t.Fatalf("ReadJSON returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

func TestReadJSONRejectsWrongTool(t *testing.T) {
	r := sampleReport()
	r.Tool = "some-other-tool"
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	if _, err := report.ReadJSON(&buf); err == nil {
		t.Fatal("ReadJSON returned nil error for tool != injectionbench, want one")
	}
}

func TestReadJSONRejectsMalformedJSON(t *testing.T) {
	if _, err := report.ReadJSON(strings.NewReader("not json")); err == nil {
		t.Fatal("ReadJSON returned nil error for malformed JSON, want one")
	}
}

func TestWriteMarkdownContainsCategoriesAndPercentages(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteMarkdown(&buf, r); err != nil {
		t.Fatalf("WriteMarkdown returned error: %v", err)
	}
	out := buf.String()
	for _, category := range []string{"direct", "indirect"} {
		if !strings.Contains(out, category) {
			t.Errorf("Markdown output missing category %q:\n%s", category, out)
		}
	}
	if !strings.Contains(out, "%") {
		t.Errorf("Markdown output missing a percentage sign:\n%s", out)
	}
	if !strings.Contains(out, "5/10") {
		t.Errorf("Markdown output missing successes/trials for a category:\n%s", out)
	}
}

func TestReportJSONFieldNames(t *testing.T) {
	r := sampleReport()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	for _, field := range []string{
		"tool", "version", "target", "judge", "trials_per_attack", "seed",
		"confidence", "overall", "categories", "attacks", "errors",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("Report JSON is missing field %q: %s", field, raw)
		}
	}
	overall, ok := decoded["overall"].(map[string]any)
	if !ok {
		t.Fatalf("overall = %v, want an object", decoded["overall"])
	}
	for _, field := range []string{"successes", "trials", "asr", "ci_lower", "ci_upper"} {
		if _, ok := overall[field]; !ok {
			t.Errorf("Rate JSON is missing field %q: %s", field, raw)
		}
	}
}

func baselineAndCurrent(baselineASR, currentASR [2]int) (report.Report, report.Report) {
	baseline := sampleReport()
	current := sampleReport()
	baseline.Overall = report.Rate{Successes: baselineASR[0], Trials: baselineASR[1], ASR: float64(baselineASR[0]) / float64(baselineASR[1])}
	current.Overall = report.Rate{Successes: currentASR[0], Trials: currentASR[1], ASR: float64(currentASR[0]) / float64(currentASR[1])}
	return baseline, current
}

func TestCompareRowOrderOverallFirstThenSortedCategories(t *testing.T) {
	baseline, current := baselineAndCurrent([2]int{10, 100}, [2]int{11, 100})
	baseline.Categories = map[string]report.Rate{
		"zelda": {Successes: 5, Trials: 10, ASR: 0.5},
		"alpha": {Successes: 5, Trials: 10, ASR: 0.5},
	}
	current.Categories = map[string]report.Rate{
		"zelda": {Successes: 5, Trials: 10, ASR: 0.5},
		"alpha": {Successes: 5, Trials: 10, ASR: 0.5},
	}
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	if len(cmp.Rows) != 3 {
		t.Fatalf("len(Rows) = %d, want 3 (overall + 2 categories)", len(cmp.Rows))
	}
	if cmp.Rows[0].Scope != "overall" {
		t.Errorf("Rows[0].Scope = %q, want overall", cmp.Rows[0].Scope)
	}
	if cmp.Rows[1].Scope != "alpha" || cmp.Rows[2].Scope != "zelda" {
		t.Errorf("category rows = [%q, %q], want sorted [alpha, zelda]", cmp.Rows[1].Scope, cmp.Rows[2].Scope)
	}
}

func TestCompareCategoriesOnlyInOneReportAreSkipped(t *testing.T) {
	baseline, current := baselineAndCurrent([2]int{10, 100}, [2]int{11, 100})
	baseline.Categories = map[string]report.Rate{
		"only-baseline": {Successes: 1, Trials: 10, ASR: 0.1},
		"shared":        {Successes: 1, Trials: 10, ASR: 0.1},
	}
	current.Categories = map[string]report.Rate{
		"only-current": {Successes: 1, Trials: 10, ASR: 0.1},
		"shared":       {Successes: 1, Trials: 10, ASR: 0.1},
	}
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	for _, row := range cmp.Rows {
		if row.Scope == "only-baseline" || row.Scope == "only-current" {
			t.Errorf("Rows contains %q, want categories present in only one report to be skipped", row.Scope)
		}
	}
	found := false
	for _, row := range cmp.Rows {
		if row.Scope == "shared" {
			found = true
		}
	}
	if !found {
		t.Error("Rows is missing the shared category")
	}
}

func TestCompareDetectsSignificantRegression(t *testing.T) {
	baseline, current := baselineAndCurrent([2]int{5, 100}, [2]int{50, 100})
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	if !cmp.Regressed {
		t.Error("Comparison.Regressed = false, want true for a large significant ASR increase")
	}
	if !cmp.Rows[0].Regressed {
		t.Error("Rows[0].Regressed = false, want true")
	}
	if cmp.Rows[0].P >= 0.05 {
		t.Errorf("Rows[0].P = %g, want < 0.05", cmp.Rows[0].P)
	}
}

func TestCompareNoRegressionWhenNotSignificant(t *testing.T) {
	baseline, current := baselineAndCurrent([2]int{10, 100}, [2]int{11, 100})
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	if cmp.Regressed {
		t.Error("Comparison.Regressed = true, want false for a tiny, non-significant ASR change")
	}
}

func TestCompareInvalidAlpha(t *testing.T) {
	baseline, current := baselineAndCurrent([2]int{10, 100}, [2]int{11, 100})
	for _, alpha := range []float64{0, 1, -0.1, 1.1} {
		t.Run(strconv.FormatFloat(alpha, 'g', -1, 64), func(t *testing.T) {
			if _, err := report.Compare(baseline, current, alpha); err == nil {
				t.Fatalf("Compare(..., %g) returned nil error, want one", alpha)
			}
		})
	}
}

const baselineHardenedPath = "../../benchmarks/baseline-hardened.json"

func TestShippedBaselineHardenedReportExistsAndLoads(t *testing.T) {
	f, err := os.Open(baselineHardenedPath)
	if err != nil {
		t.Fatalf("opening %s failed: %v (CI's regression gate requires this committed baseline)", baselineHardenedPath, err)
	}
	defer func() { _ = f.Close() }()
	r, err := report.ReadJSON(f)
	if err != nil {
		t.Fatalf("ReadJSON(%s) returned error: %v", baselineHardenedPath, err)
	}
	if r.Tool != "injectionbench" {
		t.Errorf("Tool = %q, want injectionbench", r.Tool)
	}
}

func TestComparisonJSONFieldNames(t *testing.T) {
	cmp := report.Comparison{
		Alpha: 0.05,
		Rows: []report.Row{
			{
				Scope:     "overall",
				Baseline:  report.Rate{Successes: 5, Trials: 100, ASR: 0.05},
				Current:   report.Rate{Successes: 10, Trials: 100, ASR: 0.1},
				Z:         1.5,
				P:         0.02,
				Regressed: true,
			},
		},
		Regressed: true,
	}
	raw, err := json.Marshal(cmp)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	for _, field := range []string{"alpha", "rows", "regressed"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("Comparison JSON is missing field %q: %s", field, raw)
		}
	}
	rows, ok := decoded["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("rows = %v, want a one-element array", decoded["rows"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("rows[0] = %v, want an object", rows[0])
	}
	for _, field := range []string{"scope", "baseline", "current", "z", "p", "regressed"} {
		if _, ok := row[field]; !ok {
			t.Errorf("Row JSON is missing field %q: %s", field, raw)
		}
	}
}

// TestComparisonSkippedIsEmptyArrayNotNullWhenCategoriesMatch covers the round-3 clarification
// that Comparison.Skipped is always a non-nil slice: when both reports share every category, the
// JSON must show "skipped":[] rather than "skipped":null.
func TestComparisonSkippedIsEmptyArrayNotNullWhenCategoriesMatch(t *testing.T) {
	baseline := sampleReport()
	current := sampleReport()
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	raw, err := json.Marshal(cmp)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	var decoded struct {
		Skipped json.RawMessage `json:"skipped"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if string(decoded.Skipped) != "[]" {
		t.Errorf("skipped = %s, want the literal empty array [] (not null) when every category is shared", decoded.Skipped)
	}
}

func TestWriteComparisonMarkdownListsSkippedCategoriesWhenPresent(t *testing.T) {
	baseline := sampleReport()
	baseline.Categories = map[string]report.Rate{"only-baseline": {Successes: 1, Trials: 10, ASR: 0.1}}
	current := sampleReport()
	current.Categories = map[string]report.Rate{"only-current": {Successes: 1, Trials: 10, ASR: 0.1}}
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}

	var buf bytes.Buffer
	if err := report.WriteComparisonMarkdown(&buf, cmp, "vulnerable", "hardened"); err != nil {
		t.Fatalf("WriteComparisonMarkdown returned error: %v", err)
	}
	want := "Not compared (present in only one report): only-baseline, only-current"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("Markdown output = %q, want it to contain %q", buf.String(), want)
	}
}

func TestWriteComparisonMarkdownOmitsSkippedLineWhenCategoriesMatch(t *testing.T) {
	baseline := sampleReport()
	current := sampleReport()
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}

	var buf bytes.Buffer
	if err := report.WriteComparisonMarkdown(&buf, cmp, "vulnerable", "hardened"); err != nil {
		t.Fatalf("WriteComparisonMarkdown returned error: %v", err)
	}
	if strings.Contains(buf.String(), "Not compared") {
		t.Errorf("Markdown output = %q, want no 'Not compared' line when every category is present in both reports", buf.String())
	}
}

func TestWriteComparisonMarkdown(t *testing.T) {
	baseline, current := baselineAndCurrent([2]int{5, 100}, [2]int{50, 100})
	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	var buf bytes.Buffer
	if err := report.WriteComparisonMarkdown(&buf, cmp, "vulnerable", "hardened"); err != nil {
		t.Fatalf("WriteComparisonMarkdown returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "vulnerable") || !strings.Contains(out, "hardened") {
		t.Errorf("Markdown output missing report labels:\n%s", out)
	}
	if !strings.Contains(out, "overall") {
		t.Errorf("Markdown output missing the overall row:\n%s", out)
	}
}
