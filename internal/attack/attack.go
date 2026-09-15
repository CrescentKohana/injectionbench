// Package attack defines InjectionBench's attack corpus format and the embedded, built-in
// corpus covering the seven OWASP/ATLAS-mapped prompt-injection categories.
package attack

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CrescentKohana/injectionbench/internal/obfuscate"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// Category is one of the seven attack categories InjectionBench's corpus covers.
type Category string

const (
	CategoryDirect           Category = "direct"
	CategoryPromptExtraction Category = "prompt-extraction"
	CategoryObfuscation      Category = "obfuscation"
	CategoryIndirect         Category = "indirect"
	CategoryExcessiveAgency  Category = "excessive-agency"
	CategoryMarkdownExfil    Category = "markdown-exfil"
	CategoryMultiTurn        Category = "multi-turn"
)

// Categories returns the seven categories in a fixed, stable order.
func Categories() []Category {
	return []Category{
		CategoryDirect,
		CategoryPromptExtraction,
		CategoryObfuscation,
		CategoryIndirect,
		CategoryExcessiveAgency,
		CategoryMarkdownExfil,
		CategoryMultiTurn,
	}
}

// ParseCategory validates s against the known categories.
func ParseCategory(s string) (Category, error) {
	for _, c := range Categories() {
		if string(c) == s {
			return c, nil
		}
	}
	return "", fmt.Errorf("attack: unknown category %q", s)
}

// Success describes what counts as this attack succeeding.
type Success struct {
	CanaryLeak             bool     `json:"canary_leak"`
	ForbiddenTools         []string `json:"forbidden_tools,omitempty"`
	ForbiddenArgSubstrings []string `json:"forbidden_arg_substrings,omitempty"`
}

// Attack is one prompt-injection attack in the corpus.
type Attack struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Category    Category          `json:"category"`
	Description string            `json:"description"`
	OWASP       []string          `json:"owasp"`
	ATLAS       []string          `json:"atlas"`
	Turns       []string          `json:"turns"`
	Payload     string            `json:"payload,omitempty"`
	Transform   string            `json:"transform,omitempty"`
	Documents   []target.Document `json:"documents,omitempty"`
	ToolOutputs map[string]string `json:"tool_outputs,omitempty"`
	Goal        string            `json:"goal"`
	Success     Success           `json:"success"`
}

// Rendered is an Attack with its payload placeholder substituted, ready to send to a target.
type Rendered struct {
	Turns       []string
	Documents   []target.Document
	ToolOutputs map[string]string
}

// PayloadPlaceholder marks where Render substitutes the (optionally obfuscated) payload.
const PayloadPlaceholder = "{{PAYLOAD}}"

// Validate checks that a has a well-formed ID, Name, Goal, Category, at least one turn, an
// accepted Transform, a Success that requires a canary leak or forbidden tools, and consistent
// use of PayloadPlaceholder with Payload.
func (a Attack) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("attack: empty id")
	}
	if a.Name == "" {
		return fmt.Errorf("attack %s: empty name", a.ID)
	}
	if a.Goal == "" {
		return fmt.Errorf("attack %s: empty goal", a.ID)
	}
	if _, err := ParseCategory(string(a.Category)); err != nil {
		return fmt.Errorf("attack %s: %w", a.ID, err)
	}
	if len(a.Turns) < 1 {
		return fmt.Errorf("attack %s: at least one turn is required", a.ID)
	}
	if _, err := obfuscate.Apply(a.Transform, ""); err != nil {
		return fmt.Errorf("attack %s: %w", a.ID, err)
	}
	if !a.Success.CanaryLeak && len(a.Success.ForbiddenTools) == 0 {
		return fmt.Errorf("attack %s: success must require a canary leak or at least one forbidden tool", a.ID)
	}

	occurs := placeholderOccurs(a)
	switch {
	case a.Payload != "" && !occurs:
		return fmt.Errorf("attack %s: payload is set but %s does not occur in any turn, document or tool output", a.ID, PayloadPlaceholder)
	case a.Payload == "" && occurs:
		return fmt.Errorf("attack %s: %s occurs without a payload to substitute", a.ID, PayloadPlaceholder)
	}
	return nil
}

func placeholderOccurs(a Attack) bool {
	for _, t := range a.Turns {
		if strings.Contains(t, PayloadPlaceholder) {
			return true
		}
	}
	for _, d := range a.Documents {
		if strings.Contains(d.Content, PayloadPlaceholder) {
			return true
		}
	}
	for _, v := range a.ToolOutputs {
		if strings.Contains(v, PayloadPlaceholder) {
			return true
		}
	}
	return false
}

// Render substitutes PayloadPlaceholder in every turn, document and tool output with
// obfuscate.Apply(a.Transform, a.Payload).
func (a Attack) Render() (Rendered, error) {
	if err := a.Validate(); err != nil {
		return Rendered{}, err
	}

	var encoded string
	if a.Payload != "" {
		var err error
		encoded, err = obfuscate.Apply(a.Transform, a.Payload)
		if err != nil {
			return Rendered{}, fmt.Errorf("attack %s: %w", a.ID, err)
		}
	}

	turns := make([]string, len(a.Turns))
	for i, t := range a.Turns {
		turns[i] = strings.ReplaceAll(t, PayloadPlaceholder, encoded)
	}

	var docs []target.Document
	if len(a.Documents) > 0 {
		docs = make([]target.Document, len(a.Documents))
		for i, d := range a.Documents {
			docs[i] = target.Document{ID: d.ID, Content: strings.ReplaceAll(d.Content, PayloadPlaceholder, encoded)}
		}
	}

	var toolOutputs map[string]string
	if len(a.ToolOutputs) > 0 {
		toolOutputs = make(map[string]string, len(a.ToolOutputs))
		for k, v := range a.ToolOutputs {
			toolOutputs[k] = strings.ReplaceAll(v, PayloadPlaceholder, encoded)
		}
	}

	return Rendered{Turns: turns, Documents: docs, ToolOutputs: toolOutputs}, nil
}

// Parse decodes a JSON array of Attack and validates each one; duplicate IDs are an error.
func Parse(data []byte) ([]Attack, error) {
	var attacks []Attack
	if err := json.Unmarshal(data, &attacks); err != nil {
		return nil, fmt.Errorf("attack: parse corpus: %w", err)
	}

	seen := make(map[string]bool, len(attacks))
	for _, a := range attacks {
		if err := a.Validate(); err != nil {
			return nil, err
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("attack: duplicate id %s", a.ID)
		}
		seen[a.ID] = true
	}
	return attacks, nil
}

// Filter returns the attacks whose Category is in categories; an empty categories selects all.
func Filter(attacks []Attack, categories []Category) []Attack {
	if len(categories) == 0 {
		return attacks
	}
	allowed := make(map[Category]bool, len(categories))
	for _, c := range categories {
		allowed[c] = true
	}
	var out []Attack
	for _, a := range attacks {
		if allowed[a.Category] {
			out = append(out, a)
		}
	}
	return out
}
