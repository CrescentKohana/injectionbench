package judge_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/judge"
)

type fakeJudge struct {
	name    string
	verdict judge.Verdict
	err     error
}

func (f fakeJudge) Name() string { return f.name }

func (f fakeJudge) Evaluate(ctx context.Context, in judge.Input) (judge.Verdict, error) {
	return f.verdict, f.err
}

func TestNewAnyName(t *testing.T) {
	if got := judge.NewAny().Name(); got != "any" {
		t.Errorf("Name() = %q, want any", got)
	}
}

func TestNewAnySuccessIfAnyAndMaxScore(t *testing.T) {
	a := fakeJudge{name: "a", verdict: judge.Verdict{Success: false, Score: 0.3}}
	b := fakeJudge{name: "b", verdict: judge.Verdict{Success: true, Score: 0.7}}
	v, err := judge.NewAny(a, b).Evaluate(context.Background(), judge.Input{})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if !v.Success {
		t.Error("Success = false, want true since one judge succeeded")
	}
	if v.Score != 0.7 {
		t.Errorf("Score = %g, want 0.7 (max across judges)", v.Score)
	}
}

func TestNewAnyNoSuccessButScoreIsMax(t *testing.T) {
	a := fakeJudge{name: "a", verdict: judge.Verdict{Success: false, Score: 0.3}}
	b := fakeJudge{name: "b", verdict: judge.Verdict{Success: false, Score: 0.6}}
	v, err := judge.NewAny(a, b).Evaluate(context.Background(), judge.Input{})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if v.Success {
		t.Error("Success = true, want false since no judge succeeded")
	}
	if v.Score != 0.6 {
		t.Errorf("Score = %g, want 0.6 (max across judges)", v.Score)
	}
}

func TestNewAnyPropagatesError(t *testing.T) {
	boom := errors.New("boom")
	a := fakeJudge{name: "a", verdict: judge.Verdict{Success: true, Score: 1}, err: boom}
	b := fakeJudge{name: "b", verdict: judge.Verdict{Success: false, Score: 0}}
	if _, err := judge.NewAny(a, b).Evaluate(context.Background(), judge.Input{}); err == nil {
		t.Fatal("Evaluate returned nil error when a sub-judge errors, want one")
	}
}
