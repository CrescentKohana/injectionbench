// Command injectionbench runs prompt-injection attacks against an LLM application and reports
// how well its defences hold up. See internal/cli for the command surface.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/CrescentKohana/injectionbench/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
