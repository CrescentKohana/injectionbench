package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/CrescentKohana/injectionbench/internal/attack"
)

func cmdAttacks(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attacks", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text|json")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	if err := validateFormat(*format, "text", "json"); err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: attacks: %v\n", err)
		return exitError
	}

	attacks, err := attack.Builtin()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: attacks: %v\n", err)
		return exitError
	}

	if *format == "json" {
		if err := writeJSON(stdout, attacks); err != nil {
			_, _ = fmt.Fprintf(stderr, "injectionbench: attacks: %v\n", err)
			return exitError
		}
		return exitOK
	}

	for _, a := range attacks {
		_, _ = fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", a.ID, a.Category, a.Name, strings.Join(a.OWASP, ","))
	}
	return exitOK
}
