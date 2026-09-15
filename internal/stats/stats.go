// Package stats provides the confidence intervals, significance test and classifier metrics
// InjectionBench uses to turn noisy, repeated attack trials into defensible numbers.
package stats

import (
	"fmt"
	"math"
)

// Interval is a closed confidence interval over a proportion.
type Interval struct {
	Lower, Upper float64
}

// Wilson returns the Wilson score interval for successes out of trials at the given confidence
// level (e.g. 0.95 for 95%).
func Wilson(successes, trials int, confidence float64) (Interval, error) {
	if trials <= 0 {
		return Interval{}, fmt.Errorf("stats: trials must be positive, got %d", trials)
	}
	if successes < 0 {
		return Interval{}, fmt.Errorf("stats: successes must not be negative, got %d", successes)
	}
	if successes > trials {
		return Interval{}, fmt.Errorf("stats: successes %d exceeds trials %d", successes, trials)
	}
	if confidence <= 0 || confidence >= 1 {
		return Interval{}, fmt.Errorf("stats: confidence must be in (0,1), got %v", confidence)
	}

	n := float64(trials)
	phat := float64(successes) / n
	z := math.Sqrt2 * math.Erfinv(confidence)
	z2 := z * z

	denom := 1 + z2/n
	center := phat + z2/(2*n)
	margin := z * math.Sqrt(phat*(1-phat)/n+z2/(4*n*n))

	lower := clamp01((center - margin) / denom)
	upper := clamp01((center + margin) / denom)
	if successes == 0 {
		lower = 0
	}
	if successes == trials {
		upper = 1
	}
	return Interval{Lower: lower, Upper: upper}, nil
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// TwoProportionZTest tests H1: p2 > p1 (the proportion behind s2/n2 exceeds the one behind s1/n1)
// using the pooled standard error, returning the z statistic and its one-sided p-value. When the
// pooled variance is zero, z is 0 and p is 1.
func TwoProportionZTest(s1, n1, s2, n2 int) (z, p float64, err error) {
	if n1 <= 0 || n2 <= 0 {
		return 0, 0, fmt.Errorf("stats: sample sizes must be positive, got n1=%d n2=%d", n1, n2)
	}
	if s1 < 0 || s1 > n1 {
		return 0, 0, fmt.Errorf("stats: s1=%d out of range for n1=%d", s1, n1)
	}
	if s2 < 0 || s2 > n2 {
		return 0, 0, fmt.Errorf("stats: s2=%d out of range for n2=%d", s2, n2)
	}

	f1, f2 := float64(n1), float64(n2)
	p1, p2 := float64(s1)/f1, float64(s2)/f2
	pooled := float64(s1+s2) / (f1 + f2)
	variance := pooled * (1 - pooled) * (1/f1 + 1/f2)
	if variance <= 0 {
		return 0, 1, nil
	}

	z = (p2 - p1) / math.Sqrt(variance)
	p = 1 - normalCDF(z)
	return z, p, nil
}

func normalCDF(z float64) float64 {
	return 0.5 * (1 + math.Erf(z/math.Sqrt2))
}

// BinaryMetrics summarises a binary classifier's performance against ground truth.
type BinaryMetrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Accuracy  float64 `json:"accuracy"`
}

// Binary compares predicted labels against actual (ground truth) labels of equal, non-zero
// length and computes TP/FP/TN/FN, precision, recall, F1 and accuracy.
func Binary(predicted, actual []bool) (BinaryMetrics, error) {
	if len(predicted) == 0 {
		return BinaryMetrics{}, fmt.Errorf("stats: empty input")
	}
	if len(predicted) != len(actual) {
		return BinaryMetrics{}, fmt.Errorf("stats: length mismatch: predicted=%d actual=%d", len(predicted), len(actual))
	}

	var m BinaryMetrics
	for i, pred := range predicted {
		switch {
		case pred && actual[i]:
			m.TP++
		case pred && !actual[i]:
			m.FP++
		case !pred && actual[i]:
			m.FN++
		default:
			m.TN++
		}
	}

	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	m.Accuracy = float64(m.TP+m.TN) / float64(len(predicted))
	return m, nil
}
