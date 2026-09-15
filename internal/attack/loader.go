package attack

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadDir parses every *.json file directly inside dir (non-recursive) and returns their
// attacks sorted by ID; an ID duplicated across files is an error.
func LoadDir(dir string) ([]Attack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("attack: read dir %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var all []Attack
	seen := make(map[string]bool)
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) //nolint:gosec // G304: path is derived from the user's own --attacks directory argument
		if err != nil {
			return nil, fmt.Errorf("attack: read %s: %w", path, err)
		}
		attacks, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("attack: %s: %w", path, err)
		}
		for _, a := range attacks {
			if seen[a.ID] {
				return nil, fmt.Errorf("attack: duplicate id %s across corpus files in %s", a.ID, dir)
			}
			seen[a.ID] = true
			all = append(all, a)
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}
