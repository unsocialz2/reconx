package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sort"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/pkg/runner"
)

// doctor reads settings and executable paths; it never starts a target scan.
func doctor(cfg *config.Config) error {
	type tool struct {
		Name      string `json:"name"`
		Enabled   bool   `json:"enabled"`
		Path      string `json:"path"`
		Available bool   `json:"available"`
		Timeout   int    `json:"timeout_seconds"`
	}
	report := struct {
		Version  string   `json:"version"`
		Platform string   `json:"platform"`
		Workers  int      `json:"workers"`
		Ports    bool     `json:"ports_enabled"`
		Nuclei   bool     `json:"nuclei_enabled"`
		Tools    []tool   `json:"tools"`
		Notes    []string `json:"notes"`
	}{Version: version, Platform: runtime.GOOS + "/" + runtime.GOARCH, Workers: cfg.Workers, Ports: cfg.Phases.PortScan, Nuclei: cfg.Phases.VulnScan}
	if err := cfg.Validate(); err != nil {
		return err
	}
	names := make([]string, 0, len(cfg.Tools))
	for n := range cfg.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := cfg.Tools[n]
		enabled := t.Enabled
		if n == "naabu" && !cfg.Phases.PortScan || n == "nuclei" && !cfg.Phases.VulnScan {
			enabled = false
		}
		path := t.Path
		if path == "" {
			path = n
		}
		resolved := runner.WhichPath(path)
		report.Tools = append(report.Tools, tool{n, enabled, resolved, resolved != "", t.Timeout})
	}
	report.Notes = []string{"Read-only preflight: paths and budgets checked; binary flags, provider access and target scope authorization still need review.", "Missing optional tools are skipped; HTTP probing has a built-in fallback.", "Ports and Nuclei are disabled unless explicitly opted in."}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}
