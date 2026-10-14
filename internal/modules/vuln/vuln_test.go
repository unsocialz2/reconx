package vuln

import (
	"context"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNucleiLine(t *testing.T) {
	// Informational findings (like WAF and tech detection) must be discarded
	infoLines := []string{
		`{"template-id":"waf-detect","info":{"name":"WAF Detection","severity":"info"},"matched-at":"https://photos.mfp-integ.myfitnesspal.com"}`,
		`{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info"},"matched-at":"https://app.myfitnesspal.com"}`,
		`{"template-id":"aws-cloudfront-detect","info":{"name":"AWS Service - Detect","severity":"info"},"matched-at":"http://brazestaging.myfitnesspal.com"}`,
		`{"template-id":"oauth-detect","info":{"name":"OAuth 2.0 Authorization Server Detection","severity":"info"},"matched-at":"https://preferences.myfitnesspal.com/oauth/token"}`,
		`{"template-id":"unknown-detect","info":{"name":"Unknown Severity","severity":"unknown"},"matched-at":"https://test.myfitnesspal.com"}`,
	}

	for _, line := range infoLines {
		f := parseNucleiLine(line)
		if f != nil {
			t.Errorf("expected info finding to be nil, got %+v", f)
		}
	}

	// Real security vulnerability findings must be kept
	vulnLines := []struct {
		line     string
		wantName string
		wantSev  string
	}{
		{
			line:     `{"template-id":"cve-2023-1234","info":{"name":"Critical RCE","severity":"critical"},"matched-at":"https://target.com/vuln"}`,
			wantName: "Critical RCE",
			wantSev:  "critical",
		},
		{
			line:     `{"template-id":"sqli-detect","info":{"name":"SQL Injection","severity":"high"},"matched-at":"https://target.com/api"}`,
			wantName: "SQL Injection",
			wantSev:  "high",
		},
		{
			line:     `{"template-id":"cors-misconfig","info":{"name":"CORS Misconfiguration","severity":"medium"},"matched-at":"https://target.com/cors"}`,
			wantName: "CORS Misconfiguration",
			wantSev:  "medium",
		},
		{
			line:     `{"template-id":"open-redirect","info":{"name":"Open Redirect","severity":"low"},"matched-at":"https://target.com/redirect"}`,
			wantName: "Open Redirect",
			wantSev:  "low",
		},
	}

	for _, tc := range vulnLines {
		f := parseNucleiLine(tc.line)
		if f == nil {
			t.Fatalf("expected non-nil finding for %s", tc.wantName)
		}
		if f.Name != tc.wantName {
			t.Errorf("name: got %q, want %q", f.Name, tc.wantName)
		}
		if f.Severity != tc.wantSev {
			t.Errorf("severity: got %q, want %q", f.Severity, tc.wantSev)
		}
	}
}

func TestNucleiStatsStringAndNumericVersions(t *testing.T) {
	for _, line := range []string{`{"percent":"28","requests":"154719","errors":"92684","total":"546943"}`, `{"percent":28,"requests":154719,"errors":92684,"total":546943}`} {
		stats := parseNucleiStats(line)
		if stats == nil || stats.Percent != 28 || stats.Errors != 92684 || stats.Requests != 154719 {
			t.Fatalf("%+v", stats)
		}
	}
	if parseNucleiStats(`{"percent":"unknown","requests":5}`) != nil {
		t.Fatal("malformed stats accepted")
	}
}

func TestIncompleteStatsMarkScanPartialAndKeepFindings(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-nuclei")
	script := `#!/bin/sh
case "$1" in --version|-version) echo 'v3.11.1'; exit 0;; esac
printf '%s\n' '{"percent":"28","requests":"100","errors":"60","total":"350"}' >&2
printf '%s\n' '{"template-id":"fixture","info":{"name":"Fixture","severity":"medium"},"matched-at":"https://example.test"}'
`
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Tools["nuclei"] = config.ToolConfig{Enabled: true, Path: bin, Timeout: 1}
	st := store.New("test")
	st.AddHost(&store.Host{Domain: "example.test", Meta: map[string]string{"url": "https://example.test"}})
	l := logger.New(false, "")
	defer l.Close()
	err := New(cfg, st, l, dir).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "coverage incomplete") || len(st.Findings) == 0 {
		t.Fatalf("err=%v findings=%v", err, st.Findings)
	}
	if !strings.Contains(strings.Join(st.Snapshot().Coverage, ";"), "errors=60") {
		t.Fatal(st.Snapshot().Coverage)
	}
	data, readErr := os.ReadFile(filepath.Join(dir, "data", "nuclei_unknown_takeovers.jsonl"))
	if readErr != nil || !strings.Contains(string(data), "fixture") {
		t.Fatalf("%s %v", data, readErr)
	}
}
