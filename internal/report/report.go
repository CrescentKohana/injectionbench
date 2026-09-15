// Package report defines InjectionBench's JSON/Markdown report format and the
// baseline-vs-current comparison used as a regression gate.
package report

import "github.com/CrescentKohana/injectionbench/internal/attack"

// Rate is an attack success rate with its confidence interval.
type Rate struct {
	Successes int     `json:"successes"`
	Trials    int     `json:"trials"`
	ASR       float64 `json:"asr"`
	CILower   float64 `json:"ci_lower"`
	CIUpper   float64 `json:"ci_upper"`
}

// AttackResult is one attack's Rate within a Report.
type AttackResult struct {
	ID       string          `json:"id"`
	Category attack.Category `json:"category"`
	Rate     Rate            `json:"rate"`
}

// Report is the result of running the benchmark once.
type Report struct {
	Tool            string          `json:"tool"`
	Version         string          `json:"version"`
	Target          string          `json:"target"`
	Judge           string          `json:"judge"`
	TrialsPerAttack int             `json:"trials_per_attack"`
	Seed            int64           `json:"seed"`
	Confidence      float64         `json:"confidence"`
	Overall         Rate            `json:"overall"`
	Categories      map[string]Rate `json:"categories"`
	Attacks         []AttackResult  `json:"attacks"`
	Errors          int             `json:"errors"`
}

// ToolName identifies an InjectionBench report in Report.Tool.
const ToolName = "injectionbench"

// rateASR derives a Rate's ASR from Successes/Trials, ignoring its stored ASR field (which may
// have been hand-edited or otherwise drifted from the counts it should describe).
func rateASR(r Rate) float64 {
	if r.Trials == 0 {
		return 0
	}
	return float64(r.Successes) / float64(r.Trials)
}
