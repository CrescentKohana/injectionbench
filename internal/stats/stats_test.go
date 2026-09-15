package stats_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/stats"
)

const wilsonTolerance = 1e-3

func TestWilsonReferenceValues(t *testing.T) {
	tests := []struct {
		name       string
		successes  int
		trials     int
		confidence float64
		lower      float64
		upper      float64
	}{
		{"5 of 10 at 95%", 5, 10, 0.95, 0.2366, 0.7634},
		{"0 of 10 at 95%", 0, 10, 0.95, 0, 0.2775},
		{"10 of 10 at 95%", 10, 10, 0.95, 0.7225, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := stats.Wilson(tt.successes, tt.trials, tt.confidence)
			if err != nil {
				t.Fatalf("Wilson(%d, %d, %g) returned error: %v", tt.successes, tt.trials, tt.confidence, err)
			}
			if math.Abs(got.Lower-tt.lower) > wilsonTolerance {
				t.Errorf("Lower = %g, want %g ± %g", got.Lower, tt.lower, wilsonTolerance)
			}
			if math.Abs(got.Upper-tt.upper) > wilsonTolerance {
				t.Errorf("Upper = %g, want %g ± %g", got.Upper, tt.upper, wilsonTolerance)
			}
			if got.Lower < 0 || got.Lower > 1 || got.Upper < 0 || got.Upper > 1 {
				t.Errorf("bounds out of [0,1]: %+v", got)
			}
			if got.Lower > got.Upper {
				t.Errorf("Lower %g > Upper %g", got.Lower, got.Upper)
			}
		})
	}
}

func TestWilsonBoundsClampedAcrossRange(t *testing.T) {
	for trials := 1; trials <= 50; trials++ {
		for successes := 0; successes <= trials; successes++ {
			got, err := stats.Wilson(successes, trials, 0.95)
			if err != nil {
				t.Fatalf("Wilson(%d, %d, 0.95) returned error: %v", successes, trials, err)
			}
			if got.Lower < 0 || got.Upper > 1 {
				t.Fatalf("Wilson(%d, %d, 0.95) = %+v escapes [0,1]", successes, trials, got)
			}
		}
	}
}

func TestWilsonZeroSuccessesLowerIsExactlyZero(t *testing.T) {
	for _, trials := range []int{1, 2, 3, 5, 10, 20, 50, 100, 1000} {
		for _, confidence := range []float64{0.5, 0.9, 0.95, 0.99} {
			got, err := stats.Wilson(0, trials, confidence)
			if err != nil {
				t.Fatalf("Wilson(0, %d, %g) returned error: %v", trials, confidence, err)
			}
			if got.Lower != 0 {
				t.Errorf("Wilson(0, %d, %g).Lower = %v, want exactly 0", trials, confidence, got.Lower)
			}
		}
	}
}

func TestWilsonAllSuccessesUpperIsExactlyOne(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 10, 20, 50, 100, 1000} {
		for _, confidence := range []float64{0.5, 0.9, 0.95, 0.99} {
			got, err := stats.Wilson(n, n, confidence)
			if err != nil {
				t.Fatalf("Wilson(%d, %d, %g) returned error: %v", n, n, confidence, err)
			}
			if got.Upper != 1 {
				t.Errorf("Wilson(%d, %d, %g).Upper = %v, want exactly 1", n, n, confidence, got.Upper)
			}
		}
	}
}

func TestWilsonWiderConfidenceIsWiderInterval(t *testing.T) {
	ci95, err := stats.Wilson(5, 10, 0.95)
	if err != nil {
		t.Fatalf("Wilson at 0.95 returned error: %v", err)
	}
	ci99, err := stats.Wilson(5, 10, 0.99)
	if err != nil {
		t.Fatalf("Wilson at 0.99 returned error: %v", err)
	}
	if ci99.Lower >= ci95.Lower {
		t.Errorf("99%% Lower %g should be below 95%% Lower %g", ci99.Lower, ci95.Lower)
	}
	if ci99.Upper <= ci95.Upper {
		t.Errorf("99%% Upper %g should be above 95%% Upper %g", ci99.Upper, ci95.Upper)
	}
}

func TestWilsonErrors(t *testing.T) {
	tests := []struct {
		name       string
		successes  int
		trials     int
		confidence float64
	}{
		{"zero trials", 0, 0, 0.95},
		{"negative trials", 0, -1, 0.95},
		{"negative successes", -1, 10, 0.95},
		{"successes exceeds trials", 11, 10, 0.95},
		{"confidence zero", 5, 10, 0},
		{"confidence one", 5, 10, 1},
		{"confidence negative", 5, 10, -0.1},
		{"confidence above one", 5, 10, 1.1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := stats.Wilson(tt.successes, tt.trials, tt.confidence); err == nil {
				t.Fatalf("Wilson(%d, %d, %g) returned nil error, want one", tt.successes, tt.trials, tt.confidence)
			}
		})
	}
}

// normalCDF and twoProportionZTestReference reimplement the spec's formula
// independently of the package under test, to serve as an oracle.
func normalCDF(x float64) float64 {
	return 0.5 * (1 + math.Erf(x/math.Sqrt2))
}

func twoProportionZTestReference(s1, n1, s2, n2 int) (float64, float64) {
	p1 := float64(s1) / float64(n1)
	p2 := float64(s2) / float64(n2)
	pooled := float64(s1+s2) / float64(n1+n2)
	se := math.Sqrt(pooled * (1 - pooled) * (1/float64(n1) + 1/float64(n2)))
	if se == 0 {
		return 0, 1
	}
	z := (p2 - p1) / se
	return z, 1 - normalCDF(z)
}

func TestTwoProportionZTestAgainstReferenceFormula(t *testing.T) {
	tests := []struct {
		name           string
		s1, n1, s2, n2 int
	}{
		{"spec example", 10, 100, 25, 100},
		{"reversed direction", 25, 100, 10, 100},
		{"equal proportions", 30, 60, 30, 60},
		{"small samples", 1, 5, 4, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantZ, wantP := twoProportionZTestReference(tt.s1, tt.n1, tt.s2, tt.n2)
			gotZ, gotP, err := stats.TwoProportionZTest(tt.s1, tt.n1, tt.s2, tt.n2)
			if err != nil {
				t.Fatalf("TwoProportionZTest returned error: %v", err)
			}
			if math.Abs(gotZ-wantZ) > 1e-9 {
				t.Errorf("z = %g, want %g", gotZ, wantZ)
			}
			if math.Abs(gotP-wantP) > 1e-9 {
				t.Errorf("p = %g, want %g", gotP, wantP)
			}
		})
	}
}

func TestTwoProportionZTestSpecDocumentedExample(t *testing.T) {
	z, p, err := stats.TwoProportionZTest(10, 100, 25, 100)
	if err != nil {
		t.Fatalf("TwoProportionZTest returned error: %v", err)
	}
	if math.Abs(z-2.79) > 1e-2 {
		t.Errorf("z = %g, want ≈2.79", z)
	}
	if math.Abs(p-0.0026) > 1e-3 {
		t.Errorf("p = %g, want ≈0.0026", p)
	}
}

func TestTwoProportionZTestZeroVariance(t *testing.T) {
	z, p, err := stats.TwoProportionZTest(0, 10, 0, 10)
	if err != nil {
		t.Fatalf("TwoProportionZTest returned error: %v", err)
	}
	if z != 0 {
		t.Errorf("z = %g, want 0", z)
	}
	if p != 1 {
		t.Errorf("p = %g, want 1", p)
	}
}

func TestTwoProportionZTestDirection(t *testing.T) {
	_, p, err := stats.TwoProportionZTest(25, 100, 10, 100)
	if err != nil {
		t.Fatalf("TwoProportionZTest returned error: %v", err)
	}
	if p <= 0.5 {
		t.Errorf("p = %g, want > 0.5 when p2 < p1 (evidence against an increase)", p)
	}
}

func TestTwoProportionZTestErrors(t *testing.T) {
	tests := []struct {
		name           string
		s1, n1, s2, n2 int
	}{
		{"n1 zero", 1, 0, 1, 10},
		{"n2 zero", 1, 10, 1, 0},
		{"n1 negative", 1, -5, 1, 10},
		{"s1 negative", -1, 10, 1, 10},
		{"s1 exceeds n1", 11, 10, 1, 10},
		{"s2 negative", 1, 10, -1, 10},
		{"s2 exceeds n2", 1, 10, 11, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := stats.TwoProportionZTest(tt.s1, tt.n1, tt.s2, tt.n2); err == nil {
				t.Fatalf("TwoProportionZTest(%d,%d,%d,%d) returned nil error, want one", tt.s1, tt.n1, tt.s2, tt.n2)
			}
		})
	}
}

func TestBinaryMetrics(t *testing.T) {
	tests := []struct {
		name      string
		predicted []bool
		actual    []bool
		want      stats.BinaryMetrics
	}{
		{
			name:      "mixed",
			predicted: []bool{true, true, false, false},
			actual:    []bool{true, false, true, false},
			want: stats.BinaryMetrics{
				TP: 1, FP: 1, TN: 1, FN: 1,
				Precision: 0.5, Recall: 0.5, F1: 0.5, Accuracy: 0.5,
			},
		},
		{
			name:      "perfect",
			predicted: []bool{true, false, true},
			actual:    []bool{true, false, true},
			want: stats.BinaryMetrics{
				TP: 2, FP: 0, TN: 1, FN: 0,
				Precision: 1, Recall: 1, F1: 1, Accuracy: 1,
			},
		},
		{
			name:      "no predicted positives - precision 0/0",
			predicted: []bool{false, false},
			actual:    []bool{true, false},
			want: stats.BinaryMetrics{
				TP: 0, FP: 0, TN: 1, FN: 1,
				Precision: 0, Recall: 0, F1: 0, Accuracy: 0.5,
			},
		},
		{
			name:      "no actual positives - recall 0/0",
			predicted: []bool{false, false},
			actual:    []bool{false, false},
			want: stats.BinaryMetrics{
				TP: 0, FP: 0, TN: 2, FN: 0,
				Precision: 0, Recall: 0, F1: 0, Accuracy: 1,
			},
		},
		{
			name:      "all false positives - precision and recall both 0",
			predicted: []bool{true, true},
			actual:    []bool{false, false},
			want: stats.BinaryMetrics{
				TP: 0, FP: 2, TN: 0, FN: 0,
				Precision: 0, Recall: 0, F1: 0, Accuracy: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := stats.Binary(tt.predicted, tt.actual)
			if err != nil {
				t.Fatalf("Binary returned error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Binary() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBinaryErrors(t *testing.T) {
	tests := []struct {
		name      string
		predicted []bool
		actual    []bool
	}{
		{"length mismatch", []bool{true, false}, []bool{true}},
		{"both empty", []bool{}, []bool{}},
		{"both nil", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := stats.Binary(tt.predicted, tt.actual); err == nil {
				t.Fatalf("Binary(%v, %v) returned nil error, want one", tt.predicted, tt.actual)
			}
		})
	}
}

func TestBinaryMetricsJSONFieldNames(t *testing.T) {
	m := stats.BinaryMetrics{TP: 1, FP: 2, TN: 3, FN: 4, Precision: 0.5, Recall: 0.25, F1: 0.33, Accuracy: 0.4}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	for _, field := range []string{"tp", "fp", "tn", "fn", "precision", "recall", "f1", "accuracy"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("JSON is missing field %q: %s", field, raw)
		}
	}
}
