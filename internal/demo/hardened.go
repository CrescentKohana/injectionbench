package demo

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

const (
	untrustedDataBlockStart = "<<UNTRUSTED_DATA>>"
	untrustedDataBlockEnd   = "<</UNTRUSTED_DATA>>"
)

// Datamark replaces every run of runes for which unicode.IsSpace is true in s with "^"
// (Spotlighting datamarking).
func Datamark(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inRun := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !inRun {
				b.WriteByte('^')
				inRun = true
			}
			continue
		}
		inRun = false
		b.WriteRune(r)
	}
	return b.String()
}

// sendHardened applies Spotlighting (documents and tool outputs become one datamarked block
// instead of plain text), an instruction hierarchy, least-privilege tool exposure, and output
// filtering of the canary and of any outbound image.
func (a *App) sendHardened(ctx context.Context, req target.Request) (target.Response, error) {
	converted := convertMessages(req.Messages)
	if len(converted) == 0 {
		return target.Response{}, errNoMessages
	}

	lastUser := lastUserIndex(converted)
	var latestUserText string
	if lastUser >= 0 {
		latestUserText = converted[lastUser].Content
	}

	if block := dataBlock(req.Documents, req.ToolOutputs); block != "" && lastUser >= 0 {
		withBlock := make([]llm.Message, 0, len(converted)+1)
		withBlock = append(withBlock, converted[:lastUser]...)
		withBlock = append(withBlock, llm.Message{Role: llm.RoleUser, Content: block})
		withBlock = append(withBlock, converted[lastUser:]...)
		converted = withBlock
	}

	messages := append([]llm.Message{{Role: llm.RoleSystem, Content: hardenedSystemPrompt(req.Canary)}}, converted...)
	tools := hardenedTools(latestUserText)

	completion, err := a.model.Complete(ctx, llm.Request{Messages: messages, Tools: tools})
	if err != nil {
		return target.Response{}, fmt.Errorf("demo: model completion: %w", err)
	}

	offered := toolNameSet(tools)
	var toolCalls []target.ToolCall
	for _, tc := range completion.ToolCalls {
		if !offered[tc.Name] {
			continue
		}
		if tc.Name == ToolSendEmail && !isAllowedEmail(tc.Arguments["to"]) {
			continue
		}
		toolCalls = append(toolCalls, target.ToolCall{Name: tc.Name, Arguments: filterArgs(tc.Arguments, req.Canary)})
	}

	return target.Response{Reply: filterText(completion.Content, req.Canary), ToolCalls: toolCalls}, nil
}

func dataBlock(docs []target.Document, toolOutputs map[string]string) string {
	var lines []string
	for _, d := range docs {
		lines = append(lines, Datamark(d.Content))
	}
	for _, name := range sortedKeys(toolOutputs) {
		lines = append(lines, Datamark(toolOutputs[name]))
	}
	if len(lines) == 0 {
		return ""
	}
	return untrustedDataBlockStart + "\n" + strings.Join(lines, "\n") + "\n" + untrustedDataBlockEnd
}

func hardenedTools(latestUserText string) []llm.Tool {
	tools := []llm.Tool{searchDocsTool(), readInboxTool(), fetchURLTool()}
	if strings.Contains(strings.ToLower(latestUserText), "email") {
		tools = append(tools, sendEmailTool())
	}
	return tools
}

// isAllowedEmail accepts only addresses with exactly one "@", a non-empty local part, and a
// domain equal to AllowedEmailDomain: "ops@attacker.example@example.com" is rejected rather than
// matched on its last "@".
func isAllowedEmail(to string) bool {
	if strings.Count(to, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(to, "@")
	if local == "" {
		return false
	}
	return strings.EqualFold(domain, AllowedEmailDomain)
}

func filterArgs(args map[string]string, canary string) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for k, v := range args {
		out[k] = filterText(v, canary)
	}
	return out
}
