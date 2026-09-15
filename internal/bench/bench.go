// Package bench runs an attack corpus against a target many times each and aggregates the
// results into a report.Report.
package bench

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/judge"
	"github.com/CrescentKohana/injectionbench/internal/report"
	"github.com/CrescentKohana/injectionbench/internal/stats"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// Config configures one benchmark run.
type Config struct {
	Attacks     []attack.Attack
	Trials      int
	Seed        int64
	Confidence  float64
	Concurrency int
	TargetName  string
	NewTarget   func(trialSeed int64) target.Target
	Judge       judge.Judge
}

func (cfg Config) validate() error {
	if len(cfg.Attacks) == 0 {
		return errors.New("bench: config: no attacks")
	}
	if cfg.Trials < 1 {
		return errors.New("bench: config: Trials must be >= 1")
	}
	if cfg.Confidence <= 0 || cfg.Confidence >= 1 {
		return errors.New("bench: config: Confidence must be in (0,1)")
	}
	if cfg.NewTarget == nil {
		return errors.New("bench: config: NewTarget is nil")
	}
	if cfg.Judge == nil {
		return errors.New("bench: config: Judge is nil")
	}
	return nil
}

type trialOutcome struct {
	success bool
	errored bool
}

// trialPanic names the trial a recovered panic happened in, for Run's error message.
type trialPanic struct {
	attackIdx int
	attackID  string
	trial     int
	value     any
}

// Run executes every attack in cfg.Attacks cfg.Trials times each, aggregating the results into a
// report.Report identical for any Concurrency value. A panic recovered from a trial, or ctx being
// done once every worker has exited, returns an error instead of a report.
func Run(ctx context.Context, cfg Config) (report.Report, error) {
	if err := ctx.Err(); err != nil {
		return report.Report{}, wrapCancelled(err)
	}
	if err := cfg.validate(); err != nil {
		return report.Report{}, err
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	judgeName, err := judgeNameRecovered(cfg.Judge)
	if err != nil {
		return report.Report{}, err
	}

	outcomes := make([][]trialOutcome, len(cfg.Attacks))
	for i := range outcomes {
		outcomes[i] = make([]trialOutcome, cfg.Trials)
	}

	// Dispatch is ordered and unbuffered, so every job before a panicking one is already running;
	// skipping only later jobs keeps the reported (lowest) panic deterministic.
	dispatchCtx, stopDispatch := context.WithCancel(ctx)
	defer stopDispatch()

	type job struct{ attackIdx, trial int }
	jobCh := make(chan job)
	go func() {
		defer close(jobCh)
		for ai := range cfg.Attacks {
			for t := 0; t < cfg.Trials; t++ {
				select {
				case <-dispatchCtx.Done():
					return
				case jobCh <- job{ai, t}:
				}
			}
		}
	}()

	var wg sync.WaitGroup
	var panicMu sync.Mutex
	var lowestPanic *trialPanic
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range jobCh {
				panicMu.Lock()
				skip := lowestPanic != nil && lowestPanic.before(jb.attackIdx, jb.trial)
				panicMu.Unlock()
				if skip {
					continue
				}
				a := cfg.Attacks[jb.attackIdx]
				outcome, recovered := runTrialRecovered(ctx, cfg, a, jb.trial)
				if recovered != nil {
					panicMu.Lock()
					if lowestPanic == nil || !lowestPanic.before(jb.attackIdx, jb.trial) {
						lowestPanic = &trialPanic{attackIdx: jb.attackIdx, attackID: a.ID, trial: jb.trial, value: recovered}
					}
					panicMu.Unlock()
					stopDispatch()
					continue
				}
				outcomes[jb.attackIdx][jb.trial] = outcome
			}
		}()
	}
	wg.Wait()

	if lowestPanic != nil {
		return report.Report{}, lowestPanic.err()
	}

	if err := ctx.Err(); err != nil {
		return report.Report{}, wrapCancelled(err)
	}

	return aggregateReport(cfg, judgeName, outcomes)
}

func (p *trialPanic) before(attackIdx, trial int) bool {
	return p.attackIdx < attackIdx || (p.attackIdx == attackIdx && p.trial < trial)
}

func (p *trialPanic) err() error {
	if e, ok := p.value.(error); ok {
		return fmt.Errorf("bench: attack %s trial %d: recovered from panic: %w", p.attackID, p.trial, e)
	}
	return fmt.Errorf("bench: attack %s trial %d: recovered from panic: %v", p.attackID, p.trial, p.value)
}

func judgeNameRecovered(j judge.Judge) (name string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("bench: judge Name: recovered from panic: %v", r)
		}
	}()
	return j.Name(), nil
}

func wrapCancelled(err error) error {
	return fmt.Errorf("bench: run cancelled before every trial completed: %w", err)
}

// runTrialRecovered runs one trial, recovering a panic from the target, judge or NewTarget
// instead of letting it crash the worker goroutine.
func runTrialRecovered(ctx context.Context, cfg Config, a attack.Attack, trial int) (outcome trialOutcome, recovered any) {
	defer func() {
		recovered = recover()
	}()
	outcome = runTrial(ctx, cfg, a, trial)
	return
}

func runTrial(ctx context.Context, cfg Config, a attack.Attack, trial int) trialOutcome {
	trialSeed := TrialSeed(cfg.Seed, a.ID, trial)
	canary := Canary(trialSeed)

	rendered, err := a.Render()
	if err != nil {
		return trialOutcome{errored: true}
	}

	tgt := cfg.NewTarget(trialSeed)

	var messages []target.Message
	responses := make([]target.Response, 0, len(rendered.Turns))
	for _, turnText := range rendered.Turns {
		messages = append(messages, target.Message{Role: "user", Content: turnText})
		req := target.Request{
			Messages:    append([]target.Message(nil), messages...),
			Documents:   rendered.Documents,
			ToolOutputs: rendered.ToolOutputs,
			Canary:      canary,
		}
		resp, err := tgt.Send(ctx, req)
		if err != nil {
			return trialOutcome{errored: true}
		}
		responses = append(responses, resp)
		messages = append(messages, target.Message{Role: "assistant", Content: resp.Reply})
	}

	inputAttack := a
	inputAttack.Turns = rendered.Turns
	inputAttack.Documents = rendered.Documents
	inputAttack.ToolOutputs = rendered.ToolOutputs

	verdict, err := cfg.Judge.Evaluate(ctx, judge.Input{Attack: inputAttack, Canary: canary, Turns: responses})
	if err != nil {
		return trialOutcome{errored: true}
	}
	return trialOutcome{success: verdict.Success}
}

type counts struct{ successes, trials, errors int }

func aggregateReport(cfg Config, judgeName string, outcomes [][]trialOutcome) (report.Report, error) {
	var overall counts
	categoryCounts := make(map[string]*counts)
	attackResults := make([]report.AttackResult, len(cfg.Attacks))

	for i, a := range cfg.Attacks {
		var c counts
		for _, o := range outcomes[i] {
			if o.errored {
				c.errors++
				continue
			}
			c.trials++
			if o.success {
				c.successes++
			}
		}

		rate, err := computeRate(c.successes, c.trials, cfg.Confidence)
		if err != nil {
			return report.Report{}, fmt.Errorf("bench: attack %s: %w", a.ID, err)
		}
		attackResults[i] = report.AttackResult{ID: a.ID, Category: a.Category, Rate: rate}

		overall.successes += c.successes
		overall.trials += c.trials
		overall.errors += c.errors

		cc := categoryCounts[string(a.Category)]
		if cc == nil {
			cc = &counts{}
			categoryCounts[string(a.Category)] = cc
		}
		cc.successes += c.successes
		cc.trials += c.trials
		cc.errors += c.errors
	}

	sort.Slice(attackResults, func(i, j int) bool { return attackResults[i].ID < attackResults[j].ID })

	categories := make(map[string]report.Rate, len(categoryCounts))
	for name, c := range categoryCounts {
		rate, err := computeRate(c.successes, c.trials, cfg.Confidence)
		if err != nil {
			return report.Report{}, fmt.Errorf("bench: category %s: %w", name, err)
		}
		categories[name] = rate
	}

	overallRate, err := computeRate(overall.successes, overall.trials, cfg.Confidence)
	if err != nil {
		return report.Report{}, fmt.Errorf("bench: overall: %w", err)
	}

	return report.Report{
		Tool:            report.ToolName,
		Target:          cfg.TargetName,
		Judge:           judgeName,
		TrialsPerAttack: cfg.Trials,
		Seed:            cfg.Seed,
		Confidence:      cfg.Confidence,
		Overall:         overallRate,
		Categories:      categories,
		Attacks:         attackResults,
		Errors:          overall.errors,
	}, nil
}

func computeRate(successes, trials int, confidence float64) (report.Rate, error) {
	if trials == 0 {
		return report.Rate{}, nil
	}
	iv, err := stats.Wilson(successes, trials, confidence)
	if err != nil {
		return report.Rate{}, err
	}
	return report.Rate{
		Successes: successes,
		Trials:    trials,
		ASR:       float64(successes) / float64(trials),
		CILower:   iv.Lower,
		CIUpper:   iv.Upper,
	}, nil
}
