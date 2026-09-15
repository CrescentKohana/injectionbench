// Package cli implements the injectionbench command-line tool: parsing arguments, wiring the
// other packages together, and mapping errors to stderr and an exit code.
package cli

import (
	"context"
	"fmt"
	"io"
)

// Version is the tool's reported version; overridable at build time with
// -ldflags "-X github.com/CrescentKohana/injectionbench/internal/cli.Version=...".
var Version = "dev"

const (
	exitOK        = 0
	exitThreshold = 1
	exitError     = 2
)

// Run executes the CLI and returns the process exit code. args excludes the program name.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "injectionbench: missing command (run, compare, validate-judges, attacks, serve, version)")
		return exitError
	}

	command, rest := args[0], args[1:]
	switch command {
	case "run":
		return cmdRun(ctx, rest, stdout, stderr)
	case "compare":
		return cmdCompare(rest, stdout, stderr)
	case "validate-judges":
		return cmdValidateJudges(ctx, rest, stdout, stderr)
	case "attacks":
		return cmdAttacks(rest, stdout, stderr)
	case "serve":
		return cmdServe(ctx, rest, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, Version)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "injectionbench: unknown command %q\n", command)
		return exitError
	}
}
