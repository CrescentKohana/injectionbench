package judge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/CrescentKohana/injectionbench/internal/attack"
	"github.com/CrescentKohana/injectionbench/internal/stats"
	"github.com/CrescentKohana/injectionbench/internal/target"
)

// Label is one manually-labelled transcript used to validate a Judge's accuracy.
type Label struct {
	ID            string            `json:"id"`
	AttackID      string            `json:"attack_id"`
	Category      attack.Category   `json:"category"`
	Goal          string            `json:"goal"`
	Canary        string            `json:"canary"`
	Success       attack.Success    `json:"success"`
	AttackerTurns []string          `json:"attacker_turns,omitempty"`
	Turns         []target.Response `json:"turns"`
	Label         bool              `json:"label"`
	Note          string            `json:"note,omitempty"`
}

// LoadLabels reads JSON Lines, skipping blank lines; an invalid line is an error naming its
// line number, and a duplicate ID is an error.
func LoadLabels(r io.Reader) ([]Label, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var labels []Label
	seen := make(map[string]bool)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var l Label
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			return nil, fmt.Errorf("judge: labels: line %d: %w", lineNo, err)
		}
		if seen[l.ID] {
			return nil, fmt.Errorf("judge: labels: line %d: duplicate id %s", lineNo, l.ID)
		}
		seen[l.ID] = true
		labels = append(labels, l)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("judge: labels: %w", err)
	}
	return labels, nil
}

// Validate runs j over every label and compares its Verdict.Success with Label.Label.
func Validate(ctx context.Context, j Judge, labels []Label) (stats.BinaryMetrics, error) {
	predicted := make([]bool, len(labels))
	actual := make([]bool, len(labels))
	for i, l := range labels {
		in := Input{
			Attack: attack.Attack{
				ID:       l.AttackID,
				Name:     l.AttackID,
				Category: l.Category,
				Goal:     l.Goal,
				Turns:    l.AttackerTurns,
				Success:  l.Success,
			},
			Canary: l.Canary,
			Turns:  l.Turns,
		}
		v, err := j.Evaluate(ctx, in)
		if err != nil {
			return stats.BinaryMetrics{}, fmt.Errorf("judge: validate: label %s: %w", l.ID, err)
		}
		predicted[i] = v.Success
		actual[i] = l.Label
	}
	return stats.Binary(predicted, actual)
}
