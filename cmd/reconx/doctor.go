package main

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/pkg/runner"
)

// doctor reads settings and executable paths; it never starts a target scan.
func doctor(cfg *config.Config) error {
	type tool struct {
		Name          string            `json:"name"`
		Enabled       bool              `json:"enabled"`
		Path          string            `json:"path"`
		Available     bool              `json:"available"`
		Timeout       int               `json:"timeout_seconds"`
		Compatibility runner.Inspection `json:"compatibility"`
	}
	report := struct {
		Version         string       `json:"version"`
		Platform        string       `json:"platform"`
		Workers         int          `json:"workers"`
		Ports           bool         `json:"ports_enabled"`
		Nuclei          bool         `json:"nuclei_enabled"`
		Tools           []tool       `json:"tools"`
		AdaptiveBudgets bool         `json:"adaptive_budgets"`
		BudgetCap       int          `json:"adaptive_budget_cap_seconds"`
		HostRPS         float64      `json:"built_in_host_rps"`
		HTTPRetries     int          `json:"built_in_http_retries"`
		Scope           config.Scope `json:"scope"`
		Notes           []string     `json:"notes"`
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
		report.Tools = append(report.Tools, tool{Name: n, Enabled: enabled, Path: resolved, Available: resolved != "", Timeout: t.Timeout, Compatibility: runner.Inspection{Status: "skipped", Version: "unknown"}})
	}
	report.AdaptiveBudgets = cfg.AdaptiveBudgets
	report.BudgetCap = cfg.BudgetCap
	report.HostRPS = cfg.HostRPS
	report.HTTPRetries = cfg.HTTPRetries
	report.Scope = cfg.Scope
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	policy := cfg.RunnerPolicy()
	for i := range report.Tools {
		t := &report.Tools[i]
		if !t.Enabled || !t.Available {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				t.Compatibility.Status = "check_failed"
				t.Compatibility.Note = "Overall preflight deadline exceeded"
				return
			}
			t.Compatibility = runner.Inspect(ctx, t.Name, t.Path, policy)
		}()
	}
	wg.Wait()
	report.Notes = []string{"Local preflight invokes bounded help/version probes without target inputs. Compatibility covers listed required flags; provider access is not tested.", "Missing optional tools are skipped; HTTP probing has a built-in fallback.", "Ports and Nuclei are disabled unless explicitly opted in; their binaries are not probed while disabled.", "Per-host rate/backoff applies to built-in scoped HTTP. Supported subprocesses receive native rate flags per process; HTTPS tunnels do not expose individual responses to the proxy."}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	for _, t := range report.Tools {
		if t.Compatibility.Status == "incompatible" || t.Compatibility.Status == "check_failed" {
			return fmt.Errorf("doctor: enabled tool %s failed compatibility preflight (%s)", t.Name, t.Compatibility.Status)
		}
	}
	return nil
}
