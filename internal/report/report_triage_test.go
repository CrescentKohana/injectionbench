package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/report"
)

func TestCompareRowsCarryASRDerivedFromCounts(t *testing.T) {
	baseline := sampleReport()
	current := sampleReport()
	baseline.Overall = report.Rate{Successes: 5, Trials: 100, ASR: 0.99}
	current.Overall = report.Rate{Successes: 50, Trials: 100, ASR: 0.01}

	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	row := cmp.Rows[0]
	if row.Baseline.ASR != 0.05 || row.Current.ASR != 0.5 {
		t.Errorf("row ASRs = %v -> %v, want 0.05 -> 0.5 derived from the counts", row.Baseline.ASR, row.Current.ASR)
	}

	var md bytes.Buffer
	if err := report.WriteComparisonMarkdown(&md, cmp, "base", "cur"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "5.00% (5/100)") || !strings.Contains(md.String(), "50.00% (50/100)") {
		t.Errorf("markdown does not render count-derived percentages:\n%s", md.String())
	}
}
