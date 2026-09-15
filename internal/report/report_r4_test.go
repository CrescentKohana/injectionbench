package report_test

import (
	"bytes"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/report"
)

// TestCompareDerivesRegressionFromCountsNotStoredASRField covers H2: the counts (5/100 -> 50/100)
// are a significant increase while the stored ASR fields claim the opposite (0.99 -> 0.01), so
// only a verdict derived from Successes/Trials reports the regression.
func TestCompareDerivesRegressionFromCountsNotStoredASRField(t *testing.T) {
	baseline := sampleReport()
	baseline.Overall = report.Rate{Successes: 5, Trials: 100, ASR: 0.99}
	current := sampleReport()
	current.Overall = report.Rate{Successes: 50, Trials: 100, ASR: 0.01}

	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	if !cmp.Rows[0].Regressed {
		t.Errorf("Rows[0].Regressed = false, want true: the true counts are a large, significant "+
			"increase that a deliberately inconsistent stored ASR field must not be able to hide (p=%v)",
			cmp.Rows[0].P)
	}
	if !cmp.Regressed {
		t.Error("Comparison.Regressed = false, want true")
	}
}

// TestCompareIgnoresStoredASRWhenCountsAreIdentical is the companion case: identical
// Successes/Trials must never regress, regardless of a mismatched stored ASR field, catching an
// implementation that treats a stored-ASR difference alone as sufficient for a regression.
func TestCompareIgnoresStoredASRWhenCountsAreIdentical(t *testing.T) {
	baseline := sampleReport()
	baseline.Overall = report.Rate{Successes: 10, Trials: 100, ASR: 0.01}
	current := sampleReport()
	current.Overall = report.Rate{Successes: 10, Trials: 100, ASR: 0.99}

	cmp, err := report.Compare(baseline, current, 0.05)
	if err != nil {
		t.Fatalf("Compare returned error: %v", err)
	}
	if cmp.Rows[0].Regressed || cmp.Regressed {
		t.Error("identical Successes/Trials must never regress, regardless of a mismatched stored ASR field")
	}
}

func reportWithOverallRate(r report.Rate) report.Report {
	rep := sampleReport()
	rep.Overall = r
	return rep
}

func reportWithCategoryRate(name string, r report.Rate) report.Report {
	rep := sampleReport()
	rep.Categories = map[string]report.Rate{name: r}
	return rep
}

func reportWithAttackRate(r report.Rate) report.Report {
	rep := sampleReport()
	rep.Attacks = []report.AttackResult{{ID: "DI-001", Category: attack.CategoryDirect, Rate: r}}
	return rep
}

// TestReadJSONRejectsInvalidRateVariants covers H2: ReadJSON rejects a report whose any Rate has
// negative trials, negative successes, successes exceeding trials, or an asr that mismatches
// successes/trials beyond tolerance — wherever that Rate appears (overall, category, or attack).
func TestReadJSONRejectsInvalidRateVariants(t *testing.T) {
	invalid := []struct {
		name string
		rate report.Rate
	}{
		{"negative trials", report.Rate{Successes: 1, Trials: -1, ASR: 1}},
		{"negative successes", report.Rate{Successes: -1, Trials: 10, ASR: 0}},
		{"successes greater than trials", report.Rate{Successes: 11, Trials: 10, ASR: 1.1}},
		{"asr mismatches successes over trials beyond tolerance", report.Rate{Successes: 5, Trials: 10, ASR: 0.9}},
	}
	placements := []struct {
		name string
		wrap func(report.Rate) report.Report
	}{
		{"overall", reportWithOverallRate},
		{"category", func(r report.Rate) report.Report { return reportWithCategoryRate("direct", r) }},
		{"attack", reportWithAttackRate},
	}
	for _, inv := range invalid {
		for _, pl := range placements {
			t.Run(inv.name+"/"+pl.name, func(t *testing.T) {
				var buf bytes.Buffer
				if err := report.WriteJSON(&buf, pl.wrap(inv.rate)); err != nil {
					t.Fatalf("WriteJSON returned error: %v", err)
				}
				if _, err := report.ReadJSON(&buf); err == nil {
					t.Fatalf("ReadJSON returned nil error for a %s Rate placed in %s, want one", inv.name, pl.name)
				}
			})
		}
	}
}

// TestReadJSONAcceptsZeroTrialsWithZeroASR covers H2's explicit carve-out: a Rate with no trials
// at all (asr conventionally 0) is internally consistent and must round-trip unchanged.
func TestReadJSONAcceptsZeroTrialsWithZeroASR(t *testing.T) {
	var buf bytes.Buffer
	rep := reportWithOverallRate(report.Rate{Successes: 0, Trials: 0, ASR: 0, CILower: 0, CIUpper: 0})
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	got, err := report.ReadJSON(&buf)
	if err != nil {
		t.Fatalf("ReadJSON returned error for a zero-trials zero-asr Rate, want it accepted: %v", err)
	}
	if got.Overall.Trials != 0 || got.Overall.ASR != 0 {
		t.Errorf("Overall = %+v, want Trials=0 ASR=0 round-tripped unchanged", got.Overall)
	}
}

// TestReadJSONAcceptsASRWithinTolerance covers the 1e-9 tolerance boundary from the other side: a
// tiny, floating-point-scale mismatch well inside tolerance must not be rejected.
func TestReadJSONAcceptsASRWithinTolerance(t *testing.T) {
	var buf bytes.Buffer
	rep := reportWithOverallRate(report.Rate{Successes: 5, Trials: 10, ASR: 0.5 + 5e-10})
	if err := report.WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	if _, err := report.ReadJSON(&buf); err != nil {
		t.Errorf("ReadJSON returned error for an asr within the 1e-9 tolerance: %v", err)
	}
}
