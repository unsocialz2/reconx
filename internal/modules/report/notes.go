package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Escape explicit Markdown syntax and raw HTML in target metadata.
func markdownText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "|", "\\|", "#", "\\#", "!", "\\!").Replace(s)
}

func testingNotes(w workspace) []byte {
	var b strings.Builder
	b.WriteString("# ReconX testing notes\n\n")
	fmt.Fprintf(&b, "Scan: %s  \nGenerated: %s\n\n", markdownText(w.Data.ScanID), markdownText(w.GeneratedAt))
	b.WriteString("Generated from saved observations without network requests. This is a review plan, not a vulnerability report. Priority scores express review interest, not severity, exploitability or confidence. Host availability does not prove that each collected route works.\n\n")
	b.WriteString("This generated file is replaced when the report is rebuilt. Keep personal notes in a separate file or use the report's local review annotations and JSON export.\n\n")
	b.WriteString("## Coverage to review first\n\n")
	phaseNames := make([]string, 0, len(w.Phases))
	for name := range w.Phases {
		phaseNames = append(phaseNames, name)
	}
	sort.Strings(phaseNames)
	if len(phaseNames) == 0 {
		b.WriteString("No phase manifest recorded; coverage is unknown.\n\n")
	}
	for _, name := range phaseNames {
		phase := w.Phases[name]
		fmt.Fprintf(&b, "- %s: **%s**", markdownText(name), markdownText(phase.Status))
		if phase.Reason != "" {
			fmt.Fprintf(&b, " — %s", markdownText(phase.Reason))
		}
		b.WriteString("\n")
	}
	if len(w.Data.Coverage) > 0 {
		b.WriteString("\nHistorical coverage notes (may include resolved attempts):\n\n")
		for _, note := range w.Data.Coverage {
			fmt.Fprintf(&b, "- %s\n", markdownText(note))
		}
	}
	b.WriteString("\n## Review queue\n\n")
	if len(w.ReviewQueue) == 0 {
		b.WriteString("No collected assets to prioritize. Review phase coverage before interpreting empty results.\n")
	}
	for _, a := range w.ReviewQueue {
		fmt.Fprintf(&b, "### %s\n\n", markdownText(a.Host))
		fmt.Fprintf(&b, "Queue: **%s** · interest score: %d/100 · recorded host availability: **%s**  \n", a.Priority, a.Score, a.Availability)
		fmt.Fprintf(&b, "URLs: %d · route groups: %d · JavaScript files: %d · candidates: %d\n\n", a.URLs, a.Groups, a.JS, a.Candidates)
		fmt.Fprintf(&b, "Why: %s.\n\n", markdownText(strings.Join(a.Reasons, "; ")))
		for _, check := range a.Checks {
			fmt.Fprintf(&b, "- [ ] %s\n", markdownText(check))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Endpoint route groups\n\n")
	b.WriteString("Numeric, UUID and long hexadecimal path segments are template placeholders. Grouping is a heuristic; it does not prove equivalent authorization or server behavior. Query values and fragments are omitted here. Observations may be historical. Methods are listed only when recorded by parameter discovery; an empty list means unknown. Full original URL evidence remains in the HTML report/checkpoint.\n\n")
	for _, g := range w.EndpointGroups {
		fmt.Fprintf(&b, "- %s%s — %d URLs; %d query shapes; parameter names: %s; observed methods: %s", markdownText(g.Origin), markdownText(g.Route), g.Count, g.Variants, markdownText(strings.Join(g.Parameters, ", ")), markdownText(strings.Join(g.Methods, ", ")))
		if len(g.Signals) > 0 {
			fmt.Fprintf(&b, "; clues: %s", markdownText(strings.Join(g.Signals, ", ")))
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func writePrivateArtifact(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".review-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func writeReviewArtifacts(w workspace, outDir string) error {
	for _, artifact := range []struct {
		name string
		data any
	}{{"review_queue.json", w.ReviewQueue}, {"endpoint_groups.json", w.EndpointGroups}} {
		data, err := json.MarshalIndent(artifact.data, "", "  ")
		if err != nil {
			return err
		}
		if err = writePrivateArtifact(filepath.Join(outDir, artifact.name), append(data, '\n')); err != nil {
			return err
		}
	}
	return writePrivateArtifact(filepath.Join(outDir, "testing_notes.md"), []byte(w.TestingNotes))
}
