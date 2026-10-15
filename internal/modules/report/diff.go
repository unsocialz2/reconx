package report

import (
	"encoding/json"
	"fmt"
	"github.com/unsocialz2/reconx/internal/store"
	"path/filepath"
	"sort"
	"strings"
)

type delta struct {
	Added      []string `json:"added"`
	Unobserved []string `json:"unobserved"`
}

// Compare records observations, never asserting that a missing record was removed.
func Compare(previous, current string) error {
	old, err := store.LoadSnapshot(filepath.Join(previous, "checkpoint.json"), func(string) bool { return true })
	if err != nil {
		return err
	}
	now, err := store.LoadSnapshot(filepath.Join(current, "checkpoint.json"), func(string) bool { return true })
	if err != nil {
		return err
	}
	a, b := old.Snapshot(), now.Snapshot()
	changes := map[string]delta{}
	diff := func(name string, old, new []string) {
		before, after := map[string]bool{}, map[string]bool{}
		for _, v := range old {
			before[v] = true
		}
		for _, v := range new {
			after[v] = true
		}
		d := delta{}
		for v := range after {
			if !before[v] {
				d.Added = append(d.Added, v)
			}
		}
		for v := range before {
			if !after[v] {
				d.Unobserved = append(d.Unobserved, v)
			}
		}
		sort.Strings(d.Added)
		sort.Strings(d.Unobserved)
		changes[name] = d
	}
	diff("subdomains", a.Subdomains, b.Subdomains)
	diff("urls", a.URLs, b.URLs)
	diff("javascript", a.JSFiles, b.JSFiles)
	ports := func(s store.Snapshot) []string {
		var out []string
		for _, p := range s.Ports {
			out = append(out, fmt.Sprintf("%s:%d/%s", p.Host, p.Port, p.Protocol))
		}
		return out
	}
	diff("ports", ports(a), ports(b))
	findings := func(s store.Snapshot) []string {
		var out []string
		for _, f := range s.Findings {
			out = append(out, f.Template+" "+f.Target)
		}
		return out
	}
	diff("scanner_findings", findings(a), findings(b))
	credentials := append(a.Secrets, b.Secrets...)
	for name, d := range changes {
		for _, values := range [][]string{d.Added, d.Unobserved} {
			for i, value := range values {
				for _, secret := range credentials {
					if secret.Value != "" {
						value = strings.ReplaceAll(value, secret.Value, redactSecretValue(secret.Value))
					}
				}
				values[i] = value
			}
		}
		changes[name] = d
	}
	payload := struct {
		Previous string           `json:"previous_scan"`
		Current  string           `json:"current_scan"`
		Note     string           `json:"note"`
		Changes  map[string]delta `json:"changes"`
	}{a.ScanID, b.ScanID, "Unobserved means absent from this dataset, not confirmed removed. Review both scans' coverage and scope before interpreting changes.", changes}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return store.AtomicWrite(filepath.Join(current, "comparison.json"), raw, 0600)
}
