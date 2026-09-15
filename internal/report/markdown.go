package report

import (
	"fmt"
	"io"
	"sort"
)

// WriteMarkdown writes a header and a table of category (plus overall) ASR with confidence
// intervals.
func WriteMarkdown(w io.Writer, r Report) error {
	var err error
	write := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	write("# InjectionBench report\n\n")
	write("Tool: %s %s\n\n", r.Tool, r.Version)
	write("Target: %s  \n", r.Target)
	write("Judge: %s  \n", r.Judge)
	write("Trials per attack: %d  \n", r.TrialsPerAttack)
	write("Seed: %d  \n", r.Seed)
	write("Confidence: %.0f%%  \n", r.Confidence*100)
	write("Errors: %d\n\n", r.Errors)

	write("| Category | Successes/Trials | ASR | %.0f%% CI |\n", r.Confidence*100)
	write("|---|---|---|---|\n")
	write("| overall | %s |\n", formatRateRow(r.Overall))

	for _, name := range sortedCategoryNames(r.Categories) {
		write("| %s | %s |\n", name, formatRateRow(r.Categories[name]))
	}
	return err
}

func formatRateRow(rate Rate) string {
	return fmt.Sprintf("%d/%d | %.2f%% | [%.2f%%, %.2f%%]", rate.Successes, rate.Trials, rate.ASR*100, rate.CILower*100, rate.CIUpper*100)
}

func sortedCategoryNames(categories map[string]Rate) []string {
	names := make([]string, 0, len(categories))
	for name := range categories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
