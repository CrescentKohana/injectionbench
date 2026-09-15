package bench_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/bench"
	"github.com/CrescentKohana/injectionbench/internal/judge"
	"github.com/CrescentKohana/injectionbench/internal/report"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

type panickingTarget struct{}

func (panickingTarget) Send(context.Context, target.Request) (target.Response, error) {
	panic("boom: simulated target failure")
}

type panickingJudge struct{}

func (panickingJudge) Name() string { return "panicking" }
func (panickingJudge) Evaluate(context.Context, judge.Input) (judge.Verdict, error) {
	panic("boom: simulated judge failure")
}

func assertPanicRecoveredAndNamed(t *testing.T, attackID string, rep report.Report, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("Run returned nil error for a panicking trial, want one")
	}
	if !strings.Contains(err.Error(), attackID) {
		t.Errorf("err = %v, want it to name the attack ID %q", err, attackID)
	}
	if !reflect.DeepEqual(rep, report.Report{}) {
		t.Errorf("report = %+v, want the zero value when a trial panics", rep)
	}
}

// TestRunRecoversPanicInTargetAndNamesAttackAndTrial covers H1: a panic in a target is recovered
// per trial, turned into an error naming the attack, and never yields a report. Run 30 times to
// prove the recovery is never accidentally masked by goroutine scheduling or data races.
func TestRunRecoversPanicInTargetAndNamesAttackAndTrial(t *testing.T) {
	const panicAttackID = "DI-R4PANIC01"
	const panicTrialIndex = 2
	const trials = 5

	a := attack.Attack{
		ID: panicAttackID, Name: "n", Category: attack.CategoryDirect, Goal: "g",
		Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true},
	}
	panicSeed := bench.TrialSeed(1, panicAttackID, panicTrialIndex)
	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: trials, Seed: 1, Confidence: 0.95, Concurrency: 4,
		TargetName: "test",
		NewTarget: func(trialSeed int64) target.Target {
			if trialSeed == panicSeed {
				return panickingTarget{}
			}
			return canaryEchoTarget{}
		},
		Judge: judge.NewCanary(),
	}

	for i := 0; i < 30; i++ {
		rep, err := bench.Run(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), panicAttackID) || !reflect.DeepEqual(rep, report.Report{}) {
			t.Fatalf("iteration %d: Run(err=%v, rep=%+v), want an error naming %q and the zero report",
				i, err, rep, panicAttackID)
		}
	}
}

func TestRunRecoversPanicInJudgeAndNamesAttackAndTrial(t *testing.T) {
	const panicAttackID = "DI-R4PANIC02"
	a := attack.Attack{
		ID: panicAttackID, Name: "n", Category: attack.CategoryDirect, Goal: "g",
		Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true},
	}
	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: 1, Seed: 1, Confidence: 0.95, Concurrency: 1,
		TargetName: "test",
		NewTarget:  func(trialSeed int64) target.Target { return canaryEchoTarget{} },
		Judge:      panickingJudge{},
	}
	rep, err := bench.Run(context.Background(), cfg)
	assertPanicRecoveredAndNamed(t, panicAttackID, rep, err)
}

func TestRunRecoversPanicInNewTargetAndNamesAttackAndTrial(t *testing.T) {
	const panicAttackID = "DI-R4PANIC03"
	a := attack.Attack{
		ID: panicAttackID, Name: "n", Category: attack.CategoryDirect, Goal: "g",
		Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true},
	}
	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: 1, Seed: 1, Confidence: 0.95, Concurrency: 1,
		TargetName: "test",
		NewTarget: func(trialSeed int64) target.Target {
			panic("boom: simulated NewTarget failure")
		},
		Judge: judge.NewCanary(),
	}
	rep, err := bench.Run(context.Background(), cfg)
	assertPanicRecoveredAndNamed(t, panicAttackID, rep, err)
}

func preRunCancelledError(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := bench.Run(ctx, validBenchConfig())
	if err == nil {
		t.Fatal("Run returned nil error for an already-cancelled context, want one")
	}
	return err
}

// midRunCancelledError deterministically cancels after every worker has entered Send, reusing the
// barrierTarget defined in bench_test.go so there is no timing-dependent race.
func midRunCancelledError(t *testing.T) error {
	t.Helper()
	const concurrency = 4
	a := attack.Attack{
		ID: "DI-R4CANCEL", Name: "n", Category: attack.CategoryDirect, Goal: "g",
		Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true},
	}
	var arrived sync.WaitGroup
	arrived.Add(concurrency)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: concurrency, Seed: 1, Confidence: 0.95, Concurrency: concurrency,
		TargetName: "test",
		NewTarget: func(trialSeed int64) target.Target {
			return &barrierTarget{arrived: &arrived, release: release}
		},
		Judge: judge.NewCanary(),
	}

	done := make(chan error, 1)
	go func() {
		_, err := bench.Run(ctx, cfg)
		done <- err
	}()

	arrived.Wait()
	cancel()
	close(release)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned nil error for a context cancelled mid-run, want one")
		}
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("bench.Run did not return within 5s of releasing the barrier")
		return nil
	}
}

// TestRunBothCancellationPathsWrapContextCanceledWithTheSameMessagePrefix covers H3: whether Run
// notices cancellation before dispatching anything or only after every worker has finished, the
// returned error must wrap context.Canceled with the identical message prefix on both paths.
func TestRunBothCancellationPathsWrapContextCanceledWithTheSameMessagePrefix(t *testing.T) {
	errPre := preRunCancelledError(t)
	errMid := midRunCancelledError(t)

	for name, err := range map[string]error{"pre-run": errPre, "mid-run": errMid} {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s error = %v, want errors.Is(err, context.Canceled)", name, err)
		}
	}

	const canceledMsg = "context canceled"
	prefixPre, okPre := strings.CutSuffix(errPre.Error(), canceledMsg)
	prefixMid, okMid := strings.CutSuffix(errMid.Error(), canceledMsg)
	if !okPre || !okMid {
		t.Fatalf("expected both errors to end with %q: pre-run=%q mid-run=%q", canceledMsg, errPre, errMid)
	}
	if prefixPre != prefixMid {
		t.Errorf("cancellation message prefixes differ: pre-run=%q mid-run=%q, want bench.Run to wrap "+
			"ctx.Err() the same way on both return paths", prefixPre, prefixMid)
	}
}
