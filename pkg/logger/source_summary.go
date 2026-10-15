package logger

import "strings"

// MergeSourceStats preserves untouched source states in a targeted retry.
func MergeSourceStats(previous, current []ToolStatus, selected []string) []ToolStatus {
	if len(selected) == 0 {
		return current
	}
	wanted := map[string]bool{}
	for _, s := range selected {
		wanted[s] = true
	}
	sourceName := func(name string) string { parts := strings.Split(name, " / "); return parts[len(parts)-1] }
	prior := map[string]ToolStatus{}
	for _, s := range previous {
		prior[s.Name] = s
	}
	seen := map[string]bool{}
	for i, s := range current {
		seen[s.Name] = true
		if !wanted[sourceName(s.Name)] {
			if old, ok := prior[s.Name]; ok {
				current[i] = old
			}
		}
	}
	for _, s := range previous {
		if !seen[s.Name] && !wanted[sourceName(s.Name)] {
			current = append(current, s)
		}
	}
	return current
}
