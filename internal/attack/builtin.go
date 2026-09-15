package attack

import (
	"embed"
	"fmt"
	"sort"
)

//go:embed corpus/*.json
var corpusFS embed.FS

// Builtin returns InjectionBench's embedded attack corpus, sorted by ID.
func Builtin() ([]Attack, error) {
	entries, err := corpusFS.ReadDir("corpus")
	if err != nil {
		return nil, fmt.Errorf("attack: read embedded corpus: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var all []Attack
	seen := make(map[string]bool)
	for _, name := range names {
		data, err := corpusFS.ReadFile("corpus/" + name)
		if err != nil {
			return nil, fmt.Errorf("attack: read embedded corpus/%s: %w", name, err)
		}
		attacks, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("attack: embedded corpus/%s: %w", name, err)
		}
		for _, a := range attacks {
			if seen[a.ID] {
				return nil, fmt.Errorf("attack: duplicate id %s in embedded corpus", a.ID)
			}
			seen[a.ID] = true
			all = append(all, a)
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}
