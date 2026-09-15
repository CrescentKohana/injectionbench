// Package demo provides two sample LLM applications sharing the internal/target HTTP contract:
// a deliberately vulnerable one and a hardened one combining Spotlighting, an instruction
// hierarchy, least-privilege tool exposure and output filtering.
package demo

import (
	"context"
	"errors"
	"fmt"

	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// errNoMessages marks a request the caller must fix, so the HTTP handler answers 400, not 500.
var errNoMessages = errors.New("demo: request has no messages")

// Mode selects which demo app Send implements.
type Mode string

const (
	ModeVulnerable Mode = "vulnerable"
	ModeHardened   Mode = "hardened"
)

// ParseMode validates s against the known modes.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeVulnerable, ModeHardened:
		return Mode(s), nil
	default:
		return "", fmt.Errorf("demo: unknown mode %q", s)
	}
}

// Tool names the demo apps expose, and the email domain the hardened app allows send_email to use.
const (
	ToolSearchDocs     = "search_docs"
	ToolReadInbox      = "read_inbox"
	ToolFetchURL       = "fetch_url"
	ToolSendEmail      = "send_email"
	ToolDeleteFile     = "delete_file"
	AllowedEmailDomain = "example.com"
)

// App is a sample LLM application built around a single llm.Model call per Send.
type App struct {
	mode  Mode
	model llm.Model
}

// New returns an App of the given mode, backed by model.
func New(mode Mode, model llm.Model) *App {
	return &App{mode: mode, model: model}
}

// Send implements target.Target.
func (a *App) Send(ctx context.Context, req target.Request) (target.Response, error) {
	switch a.mode {
	case ModeVulnerable:
		return a.sendVulnerable(ctx, req)
	case ModeHardened:
		return a.sendHardened(ctx, req)
	default:
		return target.Response{}, fmt.Errorf("demo: unknown mode %q", a.mode)
	}
}

func convertToolCalls(calls []llm.ToolCall) []target.ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]target.ToolCall, len(calls))
	for i, c := range calls {
		out[i] = target.ToolCall{Name: c.Name, Arguments: c.Arguments}
	}
	return out
}

func convertMessages(msgs []target.Message) []llm.Message {
	out := make([]llm.Message, len(msgs))
	for i, m := range msgs {
		out[i] = llm.Message{Role: llm.Role(m.Role), Content: m.Content}
	}
	return out
}

func lastUserIndex(msgs []llm.Message) int {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == llm.RoleUser {
			return i
		}
	}
	return -1
}
