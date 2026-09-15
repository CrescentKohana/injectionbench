package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/demo"
)

const (
	defaultServeAddr       = "127.0.0.1:8080"
	serveShutdownGrace     = 5 * time.Second
	serveReadHeaderTimeout = 5 * time.Second
)

func cmdServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	modeFlag := fs.String("mode", "", "vulnerable|hardened")
	addr := fs.String("addr", defaultServeAddr, "listen address")
	llmFlag := fs.String("llm", "sim", "llm backend: sim|openai")
	seed := fs.Int64("seed", defaultSeed, "seed for the simulated model")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	mode, err := demo.ParseMode(*modeFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: serve: %v\n", err)
		return exitError
	}

	modelFactory, code := buildModelFactory(*llmFlag, stderr)
	if code != exitOK {
		return code
	}

	app := demo.New(mode, modelFactory(*seed))
	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	var listenConfig net.ListenConfig
	ln, err := listenConfig.Listen(ctx, "tcp", *addr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: serve: %v\n", err)
		return exitError
	}
	// Plain text, before the JSON request log starts, so scripts can read the bound port.
	_, _ = fmt.Fprintf(stderr, "listening on %s\n", ln.Addr().String())

	srv := &http.Server{Handler: app.Handler(logger), ReadHeaderTimeout: serveReadHeaderTimeout}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serveShutdownGrace)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_, _ = fmt.Fprintf(stderr, "injectionbench: serve: shutdown: %v\n", err)
			return exitError
		}
		return exitOK
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_, _ = fmt.Fprintf(stderr, "injectionbench: serve: %v\n", err)
			return exitError
		}
		return exitOK
	}
}
