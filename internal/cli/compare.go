package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/CrescentKohana/injectionbench/internal/report"
)

const defaultAlpha = 0.05

func cmdCompare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baselinePath := fs.String("baseline", "", "baseline report JSON file")
	currentPath := fs.String("current", "", "current report JSON file")
	alpha := fs.Float64("alpha", defaultAlpha, "significance level for the regression test")
	format := fs.String("format", "markdown", "output format: markdown|json")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if *baselinePath == "" || *currentPath == "" {
		_, _ = fmt.Fprintln(stderr, "injectionbench: compare: --baseline and --current are required")
		return exitError
	}

	if err := validateFormat(*format, "markdown", "json"); err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: compare: %v\n", err)
		return exitError
	}

	baseline, err := readReportFile(*baselinePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: compare: %v\n", err)
		return exitError
	}
	current, err := readReportFile(*currentPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: compare: %v\n", err)
		return exitError
	}

	cmp, err := report.Compare(baseline, current, *alpha)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: compare: %v\n", err)
		return exitError
	}

	for _, name := range cmp.Skipped {
		_, _ = fmt.Fprintf(stderr, "warning: category %s present in only one report; not compared\n", name)
	}

	if *format == "json" {
		err = writeJSON(stdout, cmp)
	} else {
		err = report.WriteComparisonMarkdown(stdout, cmp, *baselinePath, *currentPath)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: compare: %v\n", err)
		return exitError
	}

	if cmp.Regressed {
		return exitThreshold
	}
	return exitOK
}
