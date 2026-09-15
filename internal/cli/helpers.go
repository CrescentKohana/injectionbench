package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CrescentKohana/injectionbench/internal/config"
	"github.com/CrescentKohana/injectionbench/internal/demo"
	"github.com/CrescentKohana/injectionbench/internal/jev"
	"github.com/CrescentKohana/injectionbench/internal/judge"
	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/report"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// httpTargetTimeout: 30s tolerates a slow self-hosted backend without stalling a whole run.
const httpTargetTimeout = 30 * time.Second

// buildJudge constructs the named judge, returning a non-zero exit code (with a message already
// written to stderr) on failure.
func buildJudge(name string, jevThreshold float64, stderr io.Writer) (judge.Judge, int) {
	switch name {
	case "canary":
		return judge.NewCanary(), exitOK
	case "jev":
		client, code := buildJevClient(stderr)
		if code != exitOK {
			return nil, code
		}
		return judge.NewJev(client, jevThreshold), exitOK
	case "any":
		client, code := buildJevClient(stderr)
		if code != exitOK {
			return nil, code
		}
		return judge.NewAny(judge.NewCanary(), judge.NewJev(client, jevThreshold)), exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "injectionbench: unknown --judge %q (want canary, jev or any)\n", name)
		return nil, exitError
	}
}

func buildJevClient(stderr io.Writer) (*jev.Client, int) {
	cfg := config.FromEnv()
	if cfg.TypeSafeAPIKey == "" {
		_, _ = fmt.Fprintln(stderr, "injectionbench: the jev judge requires the TYPESAFE_API_KEY environment variable")
		return nil, exitError
	}
	client, err := jev.NewClient(jev.Config{BaseURL: cfg.TypeSafeBaseURL, APIKey: cfg.TypeSafeAPIKey, Model: cfg.JevModel}, &http.Client{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "injectionbench: %v\n", err)
		return nil, exitError
	}
	return client, exitOK
}

// buildModelFactory constructs a per-trial-seed llm.Model factory for the named backend.
func buildModelFactory(llmFlag string, stderr io.Writer) (func(trialSeed int64) llm.Model, int) {
	switch llmFlag {
	case "sim":
		return func(trialSeed int64) llm.Model { return llm.NewSimulated(trialSeed) }, exitOK
	case "openai":
		cfg := config.FromEnv()
		if cfg.OpenAIAPIKey == "" {
			_, _ = fmt.Fprintln(stderr, "injectionbench: --llm openai requires the OPENAI_API_KEY environment variable")
			return nil, exitError
		}
		model, err := llm.NewOpenAI(llm.OpenAIConfig{BaseURL: cfg.OpenAIBaseURL, APIKey: cfg.OpenAIAPIKey, Model: cfg.OpenAIModel}, &http.Client{})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "injectionbench: %v\n", err)
			return nil, exitError
		}
		return func(int64) llm.Model { return model }, exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "injectionbench: unknown --llm %q (want sim or openai)\n", llmFlag)
		return nil, exitError
	}
}

// buildTargetFactory constructs a per-trial-seed target.Target factory for targetSpec ("builtin:
// vulnerable", "builtin:hardened", or an http(s):// URL). llmGiven reports whether --llm was
// explicitly set, which is a usage error for an http(s):// target: it owns its own model.
func buildTargetFactory(targetSpec, llmFlag string, llmGiven bool, stderr io.Writer) (func(trialSeed int64) target.Target, int) {
	switch {
	case targetSpec == "builtin:vulnerable", targetSpec == "builtin:hardened":
		mode := demo.ModeVulnerable
		if targetSpec == "builtin:hardened" {
			mode = demo.ModeHardened
		}
		modelFactory, code := buildModelFactory(llmFlag, stderr)
		if code != exitOK {
			return nil, code
		}
		return func(trialSeed int64) target.Target {
			return demo.New(mode, modelFactory(trialSeed))
		}, exitOK
	case strings.HasPrefix(targetSpec, "http://"), strings.HasPrefix(targetSpec, "https://"):
		if llmGiven {
			_, _ = fmt.Fprintln(stderr, "injectionbench: --llm is not valid for an http(s):// target: the remote app owns its own model")
			return nil, exitError
		}
		httpTarget := target.NewHTTP(targetSpec, httpTargetTimeout)
		return func(int64) target.Target { return httpTarget }, exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "injectionbench: unknown --target %q (want builtin:vulnerable, builtin:hardened, or an http(s):// URL)\n", targetSpec)
		return nil, exitError
	}
}

func readReportFile(path string) (report.Report, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path comes from the user's own --baseline/--current CLI argument
	if err != nil {
		return report.Report{}, err
	}
	defer func() { _ = f.Close() }()
	return report.ReadJSON(f)
}

// validateFormat reports an error naming value and allowed if value is not one of allowed.
func validateFormat(value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("unknown --format %q (want %s)", value, strings.Join(allowed, "|"))
}

func writeJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}
