package cli

import "testing"

// TestCappedConcurrency is an in-package test of the unexported cappedConcurrency: the external
// black-box tests in run_r3_test.go could never actually exercise the cap, since no fake target
// observed more concurrent calls than jobs available regardless of whether the cap existed.
func TestCappedConcurrency(t *testing.T) {
	tests := []struct {
		name      string
		requested int
		total     int
		want      int
	}{
		{"below one clamps to one", 0, 10, 1},
		{"negative clamps to one", -5, 10, 1},
		{"above total clamps to total", 100, 10, 10},
		{"within range unchanged", 4, 10, 4},
		{"equal to total unchanged", 10, 10, 10},
		{"zero total leaves a valid requested value unchanged", 4, 0, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cappedConcurrency(tt.requested, tt.total); got != tt.want {
				t.Errorf("cappedConcurrency(%d, %d) = %d, want %d", tt.requested, tt.total, got, tt.want)
			}
		})
	}
}
