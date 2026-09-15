package bench_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/bench"
	"github.com/CrescentKohana/injectionbench/internal/judge"
	"github.com/CrescentKohana/injectionbench/internal/report"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

var canaryPattern = regexp.MustCompile(`^IB-[0-9A-F]{16}$`)

func TestTrialSeedDeterministic(t *testing.T) {
	a := bench.TrialSeed(1, "DI-001", 0)
	b := bench.TrialSeed(1, "DI-001", 0)
	if a != b {
		t.Errorf("TrialSeed(1, DI-001, 0) = %d then %d, want equal", a, b)
	}
}

func TestTrialSeedDistinctForDifferentInputs(t *testing.T) {
	seeds := map[int64]string{}
	combos := []struct {
		base     int64
		attackID string
		trial    int
	}{
		{1, "DI-001", 0}, {2, "DI-001", 0}, {1, "DI-002", 0}, {1, "DI-001", 1},
		{1, "DI-001", 2}, {1, "DI-003", 5}, {99, "MT-010", 3},
	}
	for _, c := range combos {
		s := bench.TrialSeed(c.base, c.attackID, c.trial)
		key := fmt.Sprintf("%d/%s/%d", c.base, c.attackID, c.trial)
		if existing, ok := seeds[s]; ok {
			t.Errorf("TrialSeed collision: %q and %q both produce %d", existing, key, s)
		}
		seeds[s] = key
	}
}

func TestCanaryFormat(t *testing.T) {
	for _, seed := range []int64{0, 1, -1, 123456789, -42} {
		got := bench.Canary(seed)
		if !canaryPattern.MatchString(got) {
			t.Errorf("Canary(%d) = %q, want it to match %s", seed, got, canaryPattern)
		}
	}
}

func TestCanaryDeterministic(t *testing.T) {
	if a, b := bench.Canary(7), bench.Canary(7); a != b {
		t.Errorf("Canary(7) = %q then %q, want equal", a, b)
	}
}

func TestCanaryDiffersAcrossSeeds(t *testing.T) {
	seen := map[string]bool{}
	for seed := int64(0); seed < 50; seed++ {
		seen[bench.Canary(seed)] = true
	}
	if len(seen) < 45 {
		t.Errorf("only %d distinct canaries among 50 seeds, want collisions to be rare", len(seen))
	}
}

type recordingTarget struct {
	mu       sync.Mutex
	requests []target.Request
	turn     int
}

func (r *recordingTarget) Send(ctx context.Context, req target.Request) (target.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	r.turn++
	return target.Response{Reply: fmt.Sprintf("reply-%d", r.turn)}, nil
}

type stubJudge struct{ success bool }

func (s stubJudge) Name() string { return "stub" }
func (s stubJudge) Evaluate(ctx context.Context, in judge.Input) (judge.Verdict, error) {
	score := 0.0
	if s.success {
		score = 1
	}
	return judge.Verdict{Success: s.success, Score: score}, nil
}

func multiTurnAttack() attack.Attack {
	return attack.Attack{
		ID: "MT-001", Name: "n", Category: attack.CategoryMultiTurn, Goal: "g",
		Turns:       []string{"turn1", "turn2", "turn3"},
		Documents:   []target.Document{{ID: "d1", Content: "doc1"}},
		ToolOutputs: map[string]string{"search_docs": "out1"},
		Success:     attack.Success{CanaryLeak: true},
	}
}

func TestRunConversationAccumulatesAndRepeatsPerTurnData(t *testing.T) {
	a := multiTurnAttack()
	var captured *recordingTarget
	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: 1, Seed: 1, Confidence: 0.95, Concurrency: 1,
		TargetName: "test",
		NewTarget: func(trialSeed int64) target.Target {
			captured = &recordingTarget{}
			return captured
		},
		Judge: stubJudge{success: false},
	}
	if _, err := bench.Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if captured == nil || len(captured.requests) != 3 {
		t.Fatalf("recorded %d requests, want 3 (one per turn)", len(captured.requests))
	}

	wantCanary := bench.Canary(bench.TrialSeed(1, a.ID, 0))
	for i, req := range captured.requests {
		if req.Canary != wantCanary {
			t.Errorf("request %d Canary = %q, want %q", i, req.Canary, wantCanary)
		}
		if len(req.Documents) != 1 || req.Documents[0].Content != "doc1" {
			t.Errorf("request %d Documents = %+v, want the attack's documents on every turn", i, req.Documents)
		}
		if req.ToolOutputs["search_docs"] != "out1" {
			t.Errorf("request %d ToolOutputs = %+v, want the attack's tool outputs on every turn", i, req.ToolOutputs)
		}
	}

	turn1 := captured.requests[0]
	if len(turn1.Messages) != 1 || turn1.Messages[0] != (target.Message{Role: "user", Content: "turn1"}) {
		t.Errorf("turn 1 Messages = %+v, want a single user message", turn1.Messages)
	}
	turn2 := captured.requests[1]
	wantTurn2 := []target.Message{
		{Role: "user", Content: "turn1"},
		{Role: "assistant", Content: "reply-1"},
		{Role: "user", Content: "turn2"},
	}
	if !reflect.DeepEqual(turn2.Messages, wantTurn2) {
		t.Errorf("turn 2 Messages = %+v, want %+v", turn2.Messages, wantTurn2)
	}
	turn3 := captured.requests[2]
	wantTurn3 := append(append([]target.Message{}, wantTurn2...), target.Message{Role: "assistant", Content: "reply-2"}, target.Message{Role: "user", Content: "turn3"})
	if !reflect.DeepEqual(turn3.Messages, wantTurn3) {
		t.Errorf("turn 3 Messages = %+v, want %+v", turn3.Messages, wantTurn3)
	}
}

type erroringTarget struct{}

func (erroringTarget) Send(ctx context.Context, req target.Request) (target.Response, error) {
	return target.Response{}, fmt.Errorf("simulated target failure")
}

type canaryEchoTarget struct{}

func (canaryEchoTarget) Send(ctx context.Context, req target.Request) (target.Response, error) {
	return target.Response{Reply: "leak: " + req.Canary}, nil
}

func TestRunErrorsAreCountedAndExcludedFromRates(t *testing.T) {
	a := attack.Attack{ID: "DI-001", Name: "n", Category: attack.CategoryDirect, Goal: "g", Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true}}
	const trials = 5
	const failingTrial = 2
	failingSeed := bench.TrialSeed(1, a.ID, failingTrial)

	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: trials, Seed: 1, Confidence: 0.95, Concurrency: 1,
		TargetName: "test",
		NewTarget: func(trialSeed int64) target.Target {
			if trialSeed == failingSeed {
				return erroringTarget{}
			}
			return canaryEchoTarget{}
		},
		Judge: judge.NewCanary(),
	}
	r, err := bench.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if r.Errors != 1 {
		t.Errorf("Errors = %d, want 1", r.Errors)
	}
	if r.Overall.Trials != trials-1 {
		t.Errorf("Overall.Trials = %d, want %d (errored trial excluded)", r.Overall.Trials, trials-1)
	}
	if r.Overall.Successes != trials-1 {
		t.Errorf("Overall.Successes = %d, want %d (every non-errored trial leaks the canary)", r.Overall.Successes, trials-1)
	}
}

// parityTarget's outcome depends on trialSeed (which bench.Run derives from the attack ID and
// trial index), so a result written to the wrong attack/trial slot under concurrency changes the
// report instead of silently agreeing with its neighbour's canaryEchoTarget-style fixed outcome.
type parityTarget struct{ trialSeed int64 }

func (p parityTarget) Send(ctx context.Context, req target.Request) (target.Response, error) {
	if p.trialSeed%2 == 0 {
		return target.Response{Reply: "leak: " + req.Canary}, nil
	}
	return target.Response{Reply: "I can't help with that."}, nil
}

func TestRunReportIdenticalAcrossConcurrency(t *testing.T) {
	attacks := []attack.Attack{
		{ID: "DI-001", Name: "n", Category: attack.CategoryDirect, Goal: "g", Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true}},
		{ID: "PE-001", Name: "n", Category: attack.CategoryPromptExtraction, Goal: "g", Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true}},
	}
	newConfig := func(concurrency int) bench.Config {
		return bench.Config{
			Attacks: attacks, Trials: 10, Seed: 1, Confidence: 0.95, Concurrency: concurrency,
			TargetName: "test",
			NewTarget:  func(trialSeed int64) target.Target { return parityTarget{trialSeed: trialSeed} },
			Judge:      judge.NewCanary(),
		}
	}
	r1, err := bench.Run(context.Background(), newConfig(1))
	if err != nil {
		t.Fatalf("Run(concurrency=1) returned error: %v", err)
	}
	r8, err := bench.Run(context.Background(), newConfig(8))
	if err != nil {
		t.Fatalf("Run(concurrency=8) returned error: %v", err)
	}
	if !reflect.DeepEqual(r1, r8) {
		t.Errorf("report differs between concurrency 1 and 8:\n1=%+v\n8=%+v", r1, r8)
	}
}

func validBenchConfig() bench.Config {
	return bench.Config{
		Attacks:     []attack.Attack{{ID: "DI-001", Name: "n", Category: attack.CategoryDirect, Goal: "g", Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true}}},
		Trials:      1,
		Seed:        1,
		Confidence:  0.95,
		Concurrency: 1,
		TargetName:  "test",
		NewTarget:   func(trialSeed int64) target.Target { return canaryEchoTarget{} },
		Judge:       judge.NewCanary(),
	}
}

func TestRunInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*bench.Config)
	}{
		{"zero trials", func(c *bench.Config) { c.Trials = 0 }},
		{"negative trials", func(c *bench.Config) { c.Trials = -1 }},
		{"zero confidence", func(c *bench.Config) { c.Confidence = 0 }},
		{"confidence at one", func(c *bench.Config) { c.Confidence = 1 }},
		{"negative confidence", func(c *bench.Config) { c.Confidence = -0.1 }},
		{"no attacks", func(c *bench.Config) { c.Attacks = nil }},
		{"nil NewTarget", func(c *bench.Config) { c.NewTarget = nil }},
		{"nil Judge", func(c *bench.Config) { c.Judge = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBenchConfig()
			tt.modify(&cfg)
			if _, err := bench.Run(context.Background(), cfg); err == nil {
				t.Fatalf("Run returned nil error for invalid config %+v, want one", cfg)
			}
		})
	}
}

func TestRunCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bench.Run(ctx, validBenchConfig()); err == nil {
		t.Fatal("Run returned nil error for a cancelled context, want one")
	}
}

func TestRunConcurrencyZeroMeansOne(t *testing.T) {
	cfg := validBenchConfig()
	cfg.Concurrency = 0
	got, err := bench.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run with Concurrency=0 returned error: %v, want it to behave as Concurrency=1", err)
	}
	cfg.Concurrency = 1
	want, err := bench.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run with Concurrency=1 returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("report with Concurrency=0 = %+v, want it to equal the Concurrency=1 report %+v", got, want)
	}
}

type cancelingTarget struct {
	calls     *int64
	triggerAt int64
	once      *sync.Once
	cancel    context.CancelFunc
}

func (c *cancelingTarget) Send(ctx context.Context, req target.Request) (target.Response, error) {
	n := atomic.AddInt64(c.calls, 1)
	if n == c.triggerAt {
		c.once.Do(c.cancel)
	}
	if err := ctx.Err(); err != nil {
		return target.Response{}, err
	}
	return target.Response{Reply: "reply"}, nil
}

func TestRunCancelledMidRunReturnsContextCanceledAndStopsDispatching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // belt-and-braces: cancelingTarget also cancels, but only once calls reach triggerAt
	var calls int64
	var once sync.Once
	const triggerAt = 5
	const concurrency = 4
	const trials = 500

	a := attack.Attack{
		ID: "DI-001", Name: "n", Category: attack.CategoryDirect, Goal: "g",
		Turns: []string{"go"}, Success: attack.Success{CanaryLeak: true},
	}
	cfg := bench.Config{
		Attacks: []attack.Attack{a}, Trials: trials, Seed: 1, Confidence: 0.95, Concurrency: concurrency,
		TargetName: "test",
		NewTarget: func(trialSeed int64) target.Target {
			return &cancelingTarget{calls: &calls, triggerAt: triggerAt, once: &once, cancel: cancel}
		},
		Judge: judge.NewCanary(),
	}

	_, err := bench.Run(ctx, cfg)
	if err == nil {
		t.Fatal("Run returned nil error for a context cancelled mid-run, want one")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to satisfy errors.Is(err, context.Canceled)", err)
	}

	total := atomic.LoadInt64(&calls)
	// maxCalls stays far below Trials=500 (not tight against triggerAt) since the dispatcher's
	// select races ctx.Done() against a ready jobCh send, letting a job or two through under -race.
	const maxCalls = 50
	if total > maxCalls {
		t.Errorf("target was called %d times (cancellation triggered at call %d, concurrency %d); "+
			"Run must stop dispatching new trials once its context is done, want <= %d calls (out of %d trials)",
			total, triggerAt, concurrency, maxCalls, trials)
	}
}

// barrierTarget blocks every Send until release closes. Trials == Concurrency below, so every
// worker reaches Send before the dispatcher channel closes, giving a race-free cancellation point.
type barrierTarget struct {
	arrived *sync.WaitGroup
	release <-chan struct{}
}

func (b *barrierTarget) Send(ctx context.Context, req target.Request) (target.Response, error) {
	b.arrived.Done()
	<-b.release
	if err := ctx.Err(); err != nil {
		return target.Response{}, err
	}
	return target.Response{Reply: "reply"}, nil
}

// TestRunReturnsContextCanceledAndZeroReportEvenWhenDispatchFinishedBeforeCancellation covers F1:
// Run must check ctx.Err() after every worker finishes even when the dispatcher itself (Trials ==
// Concurrency here) never observed the cancellation.
func TestRunReturnsContextCanceledAndZeroReportEvenWhenDispatchFinishedBeforeCancellation(t *testing.T) {
	const concurrency = 4
	a := attack.Attack{
		ID: "DI-001", Name: "n", Category: attack.CategoryDirect, Goal: "g",
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

	type outcome struct {
		rep report.Report
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		rep, err := bench.Run(ctx, cfg)
		done <- outcome{rep, err}
	}()

	arrived.Wait() // every job has been dispatched: all Concurrency workers are inside Send
	cancel()
	close(release)

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("err = %v, want errors.Is(err, context.Canceled)", got.err)
		}
		if !reflect.DeepEqual(got.rep, report.Report{}) {
			t.Errorf("report = %+v, want the zero value when the context is done by the time every worker finishes", got.rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bench.Run did not return within 5s of releasing the barrier")
	}
}
