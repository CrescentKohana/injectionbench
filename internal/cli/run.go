package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/bench"
	"github.com/CrescentKohana/injectionbench/internal/report"
)

const (
	defaultTrials      = 20
	defaultSeed        = 1
	defaultConfidence  = 0.95
	defaultJevThresh   = 0.5
	defaultConcurrency = 4
	// maxTrialsPerAttack bounds the in-memory outcome table so an absurd --trials is a usage error, not an OOM.
	maxTrialsPerAttack = 100_000
	// maxConcurrency bounds worker goroutines (about 8 KiB each) independently of the job count.
	maxConcurrency = 1024
)

func cmdRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetFlag := fs.String("target", "", "target: builtin:vulnerable, builtin:hardened, or an http(s):// URL")
	llmFlag := fs.String("llm", "sim", "llm backend for a builtin target: sim|openai")
	attacksDir := fs.String("attacks", "", "directory of attack JSON files (default: embedded corpus)")
	categoryFlag := fs.String("category", "", "comma-separated attack categories to include (default: all)")
	trials := fs.Int("trials", defaultTrials, "trials per attack")
	seed := fs.Int64("seed", defaultSeed, "base seed")
	confidence := fs.Float64("confidence", defaultConfidence, "confidence level for the Wilson interval")
	judgeFlag := fs.String("judge", "canary", "judge: canary|jev|any")
	jevThreshold := fs.Float64("jev-threshold", defaultJevThresh, "jev success-score threshold")
	concurrency := fs.Int("concurrency", defaultConcurrency, "concurrent trials (capped to the number of trials to run)")
	format := fs.String("format", "json", "output format: json|markdown")
	output := fs.String("output", "", "output file (default: stdout)")
	maxASR := fs.Float64("max-asr", 0, "exit 1 if overall ASR exceeds this; only applied when given, must be in [0,1]")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	maxASRGiven := false
	llmGiven := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "max-asr":
			maxASRGiven = true
		case "llm":
			llmGiven = true
		}
	})

	if *targetFlag == "" {
		_, _ = fmt.Fprintln(stderr, "injectionbench: run: --target is required")
		return exitError
	}

	if err := validateFormat(*format, "json", "markdown"); err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: %v\n", err)
		return exitError
	}

	if maxASRGiven && (*maxASR < 0 || *maxASR > 1) {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: --max-asr must be in [0,1], got %v\n", *maxASR)
		return exitError
	}

	if *trials < 1 || *trials > maxTrialsPerAttack {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: --trials must be in [1,%d], got %d\n", maxTrialsPerAttack, *trials)
		return exitError
	}

	if *concurrency > maxConcurrency {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: --concurrency must be at most %d, got %d\n", maxConcurrency, *concurrency)
		return exitError
	}

	categories, code := parseCategories(*categoryFlag, stderr)
	if code != exitOK {
		return code
	}

	attacks, err := loadAttacks(*attacksDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: %v\n", err)
		return exitError
	}
	attacks = attack.Filter(attacks, categories)
	if len(attacks) == 0 {
		_, _ = fmt.Fprintln(stderr, "injectionbench: run: no attacks selected")
		return exitError
	}

	j, code := buildJudge(*judgeFlag, *jevThreshold, stderr)
	if code != exitOK {
		return code
	}

	newTarget, code := buildTargetFactory(*targetFlag, *llmFlag, llmGiven, stderr)
	if code != exitOK {
		return code
	}

	rep, err := bench.Run(ctx, bench.Config{
		Attacks:     attacks,
		Trials:      *trials,
		Seed:        *seed,
		Confidence:  *confidence,
		Concurrency: cappedConcurrency(*concurrency, len(attacks)*(*trials)),
		TargetName:  *targetFlag,
		NewTarget:   newTarget,
		Judge:       j,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: %v\n", err)
		return exitError
	}

	if rep.Overall.Trials == 0 {
		_, _ = fmt.Fprintln(stderr, "injectionbench: run: every trial errored; overall ASR is undefined")
		return exitError
	}
	if rep.Errors > 0 {
		_, _ = fmt.Fprintf(stderr, "warning: %d trials failed and were excluded from every rate\n", rep.Errors)
	}
	rep.Version = Version

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "injectionbench: run: %v\n", err)
			return exitError
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	if *format == "markdown" {
		err = report.WriteMarkdown(w, rep)
	} else {
		err = report.WriteJSON(w, rep)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: run: %v\n", err)
		return exitError
	}

	if maxASRGiven && rep.Overall.ASR > *maxASR {
		return exitThreshold
	}
	return exitOK
}

// cappedConcurrency clamps requested to [1, totalTrials] so a run never spins up more workers
// than it has jobs for.
func cappedConcurrency(requested, totalTrials int) int {
	if requested < 1 {
		requested = 1
	}
	if totalTrials > 0 && requested > totalTrials {
		return totalTrials
	}
	return requested
}

func parseCategories(flagValue string, stderr io.Writer) ([]attack.Category, int) {
	if flagValue == "" {
		return nil, exitOK
	}
	var categories []attack.Category
	for _, name := range strings.Split(flagValue, ",") {
		cat, err := attack.ParseCategory(strings.TrimSpace(name))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "injectionbench: run: %v\n", err)
			return nil, exitError
		}
		categories = append(categories, cat)
	}
	return categories, exitOK
}

func loadAttacks(dir string) ([]attack.Attack, error) {
	if dir == "" {
		return attack.Builtin()
	}
	return attack.LoadDir(dir)
}
