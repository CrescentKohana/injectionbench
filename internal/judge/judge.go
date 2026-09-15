// Package judge decides whether an attack succeeded against a target, either deterministically
// (via a canary token) or via TypeSafe AI's Jev model, and validates a judge's accuracy against
// a manually labelled dataset.
package judge

import (
	"context"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// Verdict is one judge's decision about one trial.
type Verdict struct {
	Success bool    `json:"success"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason"`
}

// Input is everything a Judge needs to decide whether an attack succeeded.
type Input struct {
	Attack attack.Attack
	Canary string
	Turns  []target.Response
}

// Judge evaluates one trial's Input and returns a Verdict.
type Judge interface {
	Name() string
	Evaluate(ctx context.Context, in Input) (Verdict, error)
}
