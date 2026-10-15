package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/store"
)

func TestBudgetChangesAllowedButArgumentsAndScopeRemainLocked(t *testing.T) {
	cfg := fixtureConfig(t)
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg.ResumeDir = p.outDir
	tc := cfg.Tools["httpx"]
	tc.Timeout++
	tc.TotalTimeout = 7200
	tc.RateLimit = 1
	cfg.Tools["httpx"] = tc
	cfg.Workers = 3
	q, err := New(cfg)
	if err != nil {
		t.Fatal("budget-only change rejected", err)
	}
	q.log.Close()
	tc.Flags = []string{"-custom-result-changing-flag"}
	cfg.Tools["httpx"] = tc
	if _, err := New(cfg); err == nil {
		t.Fatal("changed arguments accepted")
	}
}
func TestSelectedPhaseLeavesOtherStatesAndScannersUntouched(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Phases.CORS = true
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.manifest.Phases["urls"] = PhaseState{Status: "completed"}
	if err = p.checkpoint(); err != nil {
		t.Fatal(err)
	}
	cfg.ResumeDir = p.outDir
	cfg.RetryPhases = []string{"cors"}
	q, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.manifest.Phases["urls"].Status != "completed" || q.manifest.Phases["cors"].Attempts != 2 {
		t.Fatal(q.manifest.Phases)
	}
	if cfg.Phases.PortScan || cfg.Phases.VulnScan {
		t.Fatal("scanners enabled")
	}
	cfg.RetryPhases = []string{"ports"}
	if _, err := New(cfg); err == nil {
		t.Fatal("disabled phase retry accepted")
	}
}
func TestTargetedKatanaRetryRunsNoOtherSourcesAndKeepsPartialCoverage(t *testing.T) {
	cfg := fixtureConfig(t)
	dir := t.TempDir()
	katana := filepath.Join(dir, "katana")
	gau := filepath.Join(dir, "gau")
	marker := filepath.Join(dir, "gau-ran")
	if err := os.WriteFile(katana, []byte("#!/bin/sh\ncat >/dev/null\necho 'https://app.example.com/new?item=1'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gau, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	tc := cfg.Tools["katana"]
	tc.Path = katana
	cfg.Tools["katana"] = tc
	tc = cfg.Tools["gau"]
	tc.Path = gau
	cfg.Tools["gau"] = tc
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.store.AddHost(&store.Host{Domain: "app.example.com", StatusCode: 200, Meta: map[string]string{"url": "https://app.example.com"}})
	if err = p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.manifest.Phases["urls"] = PhaseState{Status: "partial", Reason: "old source failures"}
	p.manifest.Phases["js"] = PhaseState{Status: "completed"}
	if err = p.checkpoint(); err != nil {
		t.Fatal(err)
	}
	cfg.ResumeDir = p.outDir
	cfg.Phases.URLDiscovery = true
	cfg.RetrySources = []string{"katana"}
	q, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = q.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "prior whole-phase coverage") {
		t.Fatalf("whole phase falsely completed: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unselected source ran")
	}
	if len(q.store.GetURLs()) != 1 || q.manifest.Phases["js"].Status != "stale" || q.manifest.Phases["urls"].Tasks.Executed != 1 {
		t.Fatal(q.manifest.Phases, q.store.GetURLs())
	}
	if len(q.manifest.Runs) != 2 || q.manifest.Runs[1].Mode != "retry-source" || len(q.manifest.Phases["urls"].Budgets) == 0 {
		t.Fatal(q.manifest.Runs)
	}
}

func TestLegacyManifestMigratesWithoutRelaxingOriginalFingerprint(t *testing.T) {
	cfg := fixtureConfig(t)
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.manifest.WorkFingerprint = ""
	if err = p.checkpoint(); err != nil {
		t.Fatal(err)
	}
	cfg.ResumeDir = p.outDir
	q, err := New(cfg)
	if err != nil {
		t.Fatal("compatible legacy manifest rejected", err)
	}
	if err = q.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.manifest.WorkFingerprint == "" {
		t.Fatal("manifest did not migrate")
	}
	tc := cfg.Tools["httpx"]
	tc.Timeout++
	cfg.Tools["httpx"] = tc
	r, err := New(cfg)
	if err != nil {
		t.Fatal("migrated budget change rejected", err)
	}
	r.log.Close()
}
