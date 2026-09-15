package demo

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/CrescentKohana/injectionbench/internal/llm"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// sendVulnerable offers every tool unconditionally, inlines documents and tool outputs as plain
// text in the last user message, executes every returned tool call, and returns the reply
// unfiltered: it has no defence against direct, indirect, or excessive-agency attacks.
func (a *App) sendVulnerable(ctx context.Context, req target.Request) (target.Response, error) {
	converted := convertMessages(req.Messages)
	if len(converted) == 0 {
		return target.Response{}, errNoMessages
	}

	if idx := lastUserIndex(converted); idx >= 0 {
		converted[idx].Content = appendContext(converted[idx].Content, req.Documents, req.ToolOutputs)
	}

	messages := append([]llm.Message{{Role: llm.RoleSystem, Content: vulnerableSystemPrompt(req.Canary)}}, converted...)

	completion, err := a.model.Complete(ctx, llm.Request{Messages: messages, Tools: allTools()})
	if err != nil {
		return target.Response{}, fmt.Errorf("demo: model completion: %w", err)
	}

	return target.Response{Reply: completion.Content, ToolCalls: convertToolCalls(completion.ToolCalls)}, nil
}

func appendContext(content string, docs []target.Document, toolOutputs map[string]string) string {
	if len(docs) == 0 && len(toolOutputs) == 0 {
		return content
	}
	var b strings.Builder
	b.WriteString(content)
	b.WriteString("\nContext:")
	for _, d := range docs {
		fmt.Fprintf(&b, "\n[%s] %s", d.ID, d.Content)
	}
	for _, name := range sortedKeys(toolOutputs) {
		fmt.Fprintf(&b, "\n[tool:%s] %s", name, toolOutputs[name])
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
