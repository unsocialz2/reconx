package main

import (
	"os"
	"path/filepath"
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
