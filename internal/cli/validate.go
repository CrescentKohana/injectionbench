package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/CrescentKohana/injectionbench/internal/judge"
)

func cmdValidateJudges(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate-judges", flag.ContinueOnError)
	fs.SetOutput(stderr)
	labelsPath := fs.String("labels", "", "labelled transcripts, JSON Lines")
	judgeFlag := fs.String("judge", "canary", "judge: canary|jev|any")
	jevThreshold := fs.Float64("jev-threshold", defaultJevThresh, "jev success-score threshold")
	format := fs.String("format", "text", "output format: text|json")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if *labelsPath == "" {
		_, _ = fmt.Fprintln(stderr, "injectionbench: validate-judges: --labels is required")
		return exitError
	}

	if err := validateFormat(*format, "text", "json"); err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: validate-judges: %v\n", err)
		return exitError
	}

	f, err := os.Open(*labelsPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: validate-judges: %v\n", err)
		return exitError
	}
	defer func() { _ = f.Close() }()

	labels, err := judge.LoadLabels(f)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: validate-judges: %v\n", err)
		return exitError
	}

	j, code := buildJudge(*judgeFlag, *jevThreshold, stderr)
	if code != exitOK {
		return code
	}

	metrics, err := judge.Validate(ctx, j, labels)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: validate-judges: %v\n", err)
		return exitError
	}

	if *format == "json" {
		err = writeJSON(stdout, metrics)
	} else {
		_, err = fmt.Fprintf(stdout,
			"tp=%d fp=%d tn=%d fn=%d precision=%.4f recall=%.4f f1=%.4f accuracy=%.4f\n",
			metrics.TP, metrics.FP, metrics.TN, metrics.FN,
			metrics.Precision, metrics.Recall, metrics.F1, metrics.Accuracy,
		)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: validate-judges: %v\n", err)
		return exitError
	}
	return exitOK
}
