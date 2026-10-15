package main

import (
	"encoding/json"
	"github.com/unsocialz2/reconx/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIOverridesConfigurationAndBuildsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(cfg, []byte("[runtime]\nworkers = 2\n[output]\njson_report = false\nhtml_report = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", cfg, "-d", "example.com", "--output", dir, "--workers", "1", "--skip-subs", "--skip-alive", "--skip-ports", "--skip-urls", "--skip-js", "--skip-vuln", "--skip-cloud", "--skip-cors"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "example.com-*", "checkpoint.json"))
	if len(matches) != 1 {
		t.Fatal("CLI did not run pipeline")
	}
	exports, _ := filepath.Glob(filepath.Join(dir, "example.com-*", "results.json"))
	if len(exports) > 0 {
		t.Fatal("config export control ignored")
	}
}
func TestCLIRejectsInvalidInputs(t *testing.T) {
	for _, args := range [][]string{{"-d", "example.com;bad"}, {"-d", "example.com", "--workers", "0"}, {"--ip", "bad-cidr"}, {"-d", "example.com", "unexpected"}} {
		safeArgs := append([]string{"--skip-subs", "--skip-alive", "--skip-ports", "--skip-urls", "--skip-js", "--skip-vuln", "--skip-cloud", "--skip-cors"}, args...)
		if err := run(safeArgs); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestDomainValidationIsPure(t *testing.T) {
	for _, v := range []string{"example.com;bad", "example.com$()", "-example.com", "a..example.com", "https://example.com", "example.com/path"} {
		if validDomain(v) {
			t.Errorf("accepted %q", v)
		}
	}
	for _, v := range []string{"example.com", "api.example.com", "xn--bcher-kva.example"} {
		if !validDomain(v) {
			t.Errorf("rejected %q", v)
		}
	}
}

func TestDefaultAndExplicitScannerPhasesWithoutTargetsBeingProbed(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		dir := t.TempDir()
		ini := filepath.Join(dir, "config.ini")
		if err := os.WriteFile(ini, []byte("[tool.naabu]\npath = /bin/true\n[tool.nuclei]\npath = /bin/true\n"), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"--config", ini, "-d", "example.test", "--output", dir, "--skip-subs", "--skip-alive", "--skip-urls", "--skip-js", "--skip-cloud", "--skip-cors"}
		if enabled {
			args = append(args, "--ports", "--nuclei")
		}
		if err := run(args); err != nil {
			t.Fatal(err)
		}
		paths, _ := filepath.Glob(filepath.Join(dir, "example.test-*", "manifest.json"))
		raw, _ := os.ReadFile(paths[0])
		var manifest struct {
			Phases map[string]struct {
				Status string `json:"status"`
				Reason string `json:"reason"`
			} `json:"phases"`
		}
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ports", "vulnerabilities"} {
			state := manifest.Phases[name]
			if !enabled && state.Reason != "disabled by configuration" {
				t.Fatal(name, state)
			}
			if enabled && state.Status != "completed" {
				t.Fatal(name, state)
			}
		}
		events, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), "events.jsonl"))
		if err != nil || !strings.Contains(string(events), "phase.finished") {
			t.Fatalf("events=%s %v", events, err)
		}
	}
}
func TestReportOnlyDoesNotLaunchPipeline(t *testing.T) {
	dir := t.TempDir()
	st := store.New("saved")
	st.AddURL("https://example.test/?q=1")
	if err := st.SaveSnapshot(filepath.Join(dir, "checkpoint.json")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--report-only", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.html")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "reconx.log")); !os.IsNotExist(err) {
		t.Fatal("report-only unexpectedly ran pipeline")
	}
}
