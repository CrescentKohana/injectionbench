package bench_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/bench"
	"github.com/CrescentKohana/injectionbench/internal/judge"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

type errorPanicTarget struct{}

func (errorPanicTarget) Send(context.Context, target.Request) (target.Response, error) {
	panic(io.ErrUnexpectedEOF)
}

type namePanicJudge struct{}

func (namePanicJudge) Name() string { panic("boom: Name") }
func (namePanicJudge) Evaluate(context.Context, judge.Input) (judge.Verdict, error) {
	return judge.Verdict{}, nil
}

func TestRunWrapsErrorValuedPanic(t *testing.T) {
	cfg := validBenchConfig()
	cfg.NewTarget = func(int64) target.Target { return errorPanicTarget{} }
	_, err := bench.Run(context.Background(), cfg)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want it to wrap the panicked error so errors.Is matches", err)
	}
}

func TestRunRecoversPanicInJudgeName(t *testing.T) {
	cfg := validBenchConfig()
	cfg.Judge = namePanicJudge{}
	rep, err := bench.Run(context.Background(), cfg)
	if err == nil {
		t.Fatalf("Run returned nil error and report %+v for a judge whose Name panics", rep)
	}
}

func TestRunNamesLowestPanickingTrialRegardlessOfConcurrency(t *testing.T) {
	for _, concurrency := range []int{1, 2, 8, 16} {
		assertLowestPanicNamed(t, concurrency)
	}
}

func assertLowestPanicNamed(t *testing.T, concurrency int) {
	t.Helper()
	a := attack.Attack{ID: "DI-001", Name: "n", Category: attack.CategoryDirect, Goal: "g", Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true}}
	panicSeeds := map[int64]bool{}
	for _, trial := range []int{3, 7, 11} {
		panicSeeds[bench.TrialSeed(1, a.ID, trial)] = true
	}
	for i := 0; i < 20; i++ {
		cfg := validBenchConfig()
		cfg.Attacks = []attack.Attack{a}
		cfg.Trials = 16
		cfg.Concurrency = concurrency
		cfg.NewTarget = func(seed int64) target.Target {
			if panicSeeds[seed] {
				return panickingTarget{}
			}
			return canaryEchoTarget{}
		}
		_, err := bench.Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), "trial 3:") {
			t.Fatalf("concurrency %d, iteration %d: err = %v, want it to name trial 3, the lowest panicking trial", concurrency, i, err)
		}
	}
}

func TestRunStopsDispatchAfterFirstPanic(t *testing.T) {
	var started atomic.Int64
	cfg := validBenchConfig()
	cfg.Trials = 10_000
	cfg.Concurrency = 1
	cfg.NewTarget = func(int64) target.Target {
		started.Add(1)
		return panickingTarget{}
	}
	if _, err := bench.Run(context.Background(), cfg); err == nil {
		t.Fatal("Run returned nil error for panicking trials")
	}
	if n := started.Load(); n != 1 {
		t.Errorf("%d trials started, want exactly 1: with Concurrency 1 nothing may start after the first panic", n)
	}
}
