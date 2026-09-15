package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/CrescentKohana/injectionbench/internal/stats"
)

// Row compares one scope ("overall" or a category name) between a baseline and current Report.
type Row struct {
	Scope     string  `json:"scope"`
	Baseline  Rate    `json:"baseline"`
	Current   Rate    `json:"current"`
	Z         float64 `json:"z"`
	P         float64 `json:"p"`
	Regressed bool    `json:"regressed"`
}

// Comparison is the result of comparing a baseline and current Report.
type Comparison struct {
	Alpha     float64  `json:"alpha"`
	Rows      []Row    `json:"rows"`
	Regressed bool     `json:"regressed"`
	Skipped   []string `json:"skipped"` // categories present in only one report, sorted; not compared
}

// Compare tests, for "overall" and for every category present in both reports, whether current's
// ASR is significantly higher than baseline's at significance level alpha (one-sided
// two-proportion z-test: H1 current > baseline).
func Compare(baseline, current Report, alpha float64) (Comparison, error) {
	if alpha <= 0 || alpha >= 1 {
		return Comparison{}, fmt.Errorf("report: alpha must be in (0,1), got %v", alpha)
	}

	cmp := Comparison{Alpha: alpha}

	overallRow, err := compareRate("overall", normalizedRate(baseline.Overall, baseline.Confidence), normalizedRate(current.Overall, current.Confidence), alpha)
	if err != nil {
		return Comparison{}, fmt.Errorf("report: compare overall: %w", err)
	}
	cmp.Rows = append(cmp.Rows, overallRow)

	for _, name := range sharedSortedCategoryNames(baseline.Categories, current.Categories) {
		row, err := compareRate(name, normalizedRate(baseline.Categories[name], baseline.Confidence), normalizedRate(current.Categories[name], current.Confidence), alpha)
		if err != nil {
			return Comparison{}, fmt.Errorf("report: compare category %s: %w", name, err)
		}
		cmp.Rows = append(cmp.Rows, row)
	}

	cmp.Skipped = onlyInOneCategoryNames(baseline.Categories, current.Categories)

	for _, row := range cmp.Rows {
		if row.Regressed {
			cmp.Regressed = true
			break
		}
	}
	return cmp, nil
}

// normalizedRate rebuilds r's ASR and confidence interval from its counts, so a comparison row
// never shows stored values that disagree with the counts the verdict is based on.
func normalizedRate(r Rate, confidence float64) Rate {
	r.ASR = rateASR(r)
	r.CILower, r.CIUpper = 0, 0
	if ci, err := stats.Wilson(r.Successes, r.Trials, confidence); err == nil {
		r.CILower, r.CIUpper = ci.Lower, ci.Upper
	}
	return r
}

func compareRate(scope string, baseline, current Rate, alpha float64) (Row, error) {
	z, p, err := stats.TwoProportionZTest(baseline.Successes, baseline.Trials, current.Successes, current.Trials)
	if err != nil {
		return Row{}, err
	}
	return Row{
		Scope:     scope,
		Baseline:  baseline,
		Current:   current,
		Z:         z,
		P:         p,
		Regressed: current.ASR > baseline.ASR && p < alpha,
	}, nil
}

func sharedSortedCategoryNames(a, b map[string]Rate) []string {
	var names []string
	for name := range a {
		if _, ok := b[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func onlyInOneCategoryNames(a, b map[string]Rate) []string {
	names := []string{}
	for name := range a {
		if _, ok := b[name]; !ok {
			names = append(names, name)
		}
	}
	for name := range b {
		if _, ok := a[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// WriteComparisonMarkdown writes a before/after Markdown table for c, labelling the two reports
// with baselineLabel and currentLabel.
func WriteComparisonMarkdown(w io.Writer, c Comparison, baselineLabel, currentLabel string) error {
	var err error
	write := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	write("# InjectionBench comparison: %s -> %s\n\n", baselineLabel, currentLabel)
	write("Significance level (alpha): %.4f\n\n", c.Alpha)
	write("| Scope | %s ASR | %s ASR | z | p | Regressed |\n", baselineLabel, currentLabel)
	write("|---|---|---|---|---|---|\n")
	for _, row := range c.Rows {
		write("| %s | %.2f%% (%d/%d) | %.2f%% (%d/%d) | %.3f | %.4f | %v |\n",
			row.Scope,
			row.Baseline.ASR*100, row.Baseline.Successes, row.Baseline.Trials,
			row.Current.ASR*100, row.Current.Successes, row.Current.Trials,
			row.Z, row.P, row.Regressed,
		)
	}
	if len(c.Skipped) > 0 {
		write("\nNot compared (present in only one report): %s\n", strings.Join(c.Skipped, ", "))
	}
	return err
}
