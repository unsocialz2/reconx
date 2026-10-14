package pipeline

import (
	"context"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func fixtureConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"example.com"}
	cfg.Output.OutputDir = t.TempDir()
	cfg.Phases = config.PhasesConfig{Report: true}
	return cfg
}
func TestEmptySuccessfulPhaseResumes(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Phases.CORS = true
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.manifest.Phases["cors"].Status != "completed" {
		t.Fatal("empty successful phase not completed")
	}
	cfg.ResumeDir = p.outDir
	q, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !q.manifest.Phases["cors"].StartedAt.Equal(p.manifest.Phases["cors"].StartedAt) {
		t.Fatal("completed phase reran")
	}
	cfg.Scope.OutOfScope = []string{"example.com"}
	if _, err = New(cfg); err == nil {
		t.Fatal("changed scope accepted")
	}
}
func TestFailedToolNeverCompletesAndRetries(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Phases.VulnScan = true
	tool := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	tc := cfg.Tools["nuclei"]
	tc.Path = tool
	cfg.Tools["nuclei"] = tc
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.store.AddHost(&store.Host{Domain: "example.com", Meta: map[string]string{"url": "https://example.com"}})
	if err = p.Run(context.Background()); err == nil {
		t.Fatal("tool failure reported success")
	}
	if p.manifest.Phases["vulnerabilities"].Status != "partial" {
		t.Fatal("failed scan completed")
	}
	cfg.ResumeDir = p.outDir
	q, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Run(context.Background()); err == nil {
		t.Fatal("failed phase was not retried")
	}
	if _, err = os.Stat(filepath.Join(p.outDir, ".vuln_done")); !os.IsNotExist(err) {
		t.Fatal("legacy success marker written")
	}
}
func TestDisabledToolAndExportControls(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Phases.VulnScan = true
	tc := cfg.Tools["nuclei"]
	tc.Enabled = false
	cfg.Tools["nuclei"] = tc
	cfg.Output.JSONReport = false
	cfg.Output.SaveRaw = false
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.manifest.Phases["vulnerabilities"].Status != "skipped" {
		t.Fatal("disabled tool completed")
	}
	if _, err = os.Stat(filepath.Join(p.outDir, "results.json")); !os.IsNotExist(err) {
		t.Fatal("JSON export flag ignored")
	}
	if _, err = os.Stat(filepath.Join(p.outDir, "checkpoint.json")); err != nil {
		t.Fatal("private checkpoint missing")
	}
}
