package stats_test

import (
	"math"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/stats"
)

func FuzzWilson(f *testing.F) {
	f.Add(5, 10, 0.95)
	f.Add(0, 10, 0.95)
	f.Add(10, 10, 0.99)
	f.Add(1, 1, 0.5)

	f.Fuzz(func(t *testing.T, rawSuccesses, rawTrials int, rawConfidence float64) {
		// Folding arbitrary fuzzer ints into a small valid (successes, trials)
		// pair; wraparound here is intentional, not a correctness bug.
		trials := int(uint32(rawTrials))%1000 + 1             //nolint:gosec // G115: intentional wraparound to fold into [1,1000]
		successes := int(uint32(rawSuccesses)) % (trials + 1) //nolint:gosec // G115: intentional wraparound to fold into [0,trials]

		confidence := rawConfidence
		if math.IsNaN(confidence) || math.IsInf(confidence, 0) {
			confidence = 0.95
		}
		confidence = math.Mod(math.Abs(confidence), 0.98) + 0.01

		interval, err := stats.Wilson(successes, trials, confidence)
		if err != nil {
			t.Fatalf("Wilson(%d, %d, %g) returned error: %v", successes, trials, confidence, err)
		}
		if interval.Lower < 0 || interval.Lower > 1 {
			t.Fatalf("Lower %g out of [0,1]", interval.Lower)
		}
		if interval.Upper < 0 || interval.Upper > 1 {
			t.Fatalf("Upper %g out of [0,1]", interval.Upper)
		}
		if interval.Lower > interval.Upper {
			t.Fatalf("Lower %g > Upper %g", interval.Lower, interval.Upper)
		}
		point := float64(successes) / float64(trials)
		const slack = 1e-9
		if point < interval.Lower-slack || point > interval.Upper+slack {
			t.Fatalf("point estimate %g outside interval [%g, %g] for successes=%d trials=%d confidence=%g",
				point, interval.Lower, interval.Upper, successes, trials, confidence)
		}
	})
}
