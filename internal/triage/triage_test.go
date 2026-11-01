package triage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/store"
)

func TestAnalyzePhaseSpecificPriorityAndNoConfirmedClaims(t *testing.T) {
	s := store.Snapshot{
		Subdomains: []string{"public.example.com", "auth.example.com"},
		Hosts: []*store.Host{
			{Domain: "auth.example.com", StatusCode: 200},
			{Domain: "down.example.com", StatusCode: 429},
		},
		Ports: []*store.Port{{Host: "auth.example.com", Port: 22, Protocol: "tcp"}},
		Findings: []*store.Finding{
			{Name: "Possible XSS", Severity: "critical", Target: "https://auth.example.com/reset?token=testsecret"},
		},
		Secrets: []*store.Secret{
			{Type: "Password", Value: "SUPER_SECRET_VALUE", Source: "jsecret", File: "https://auth.example.com/app.js?x=SUPER_SECRET_VALUE"},
		},
	}
	items := Analyze(s)
	if len(items) != 7 {
		t.Fatalf("wanted 7 items, got %d: %#v", len(items), items)
	}
	foundCritical, foundDeferred, foundSecret := false, false, false
	for _, it := range items {
		if it.Phase == "vulnerabilities" {
			foundCritical = true
			if it.Priority != "P1" || it.SeverityHint != "critical" || it.Confidence != "scanner-candidate" {
				t.Fatalf("scanner result not correctly labeled: %#v", it)
			}
		}
		if it.Phase == "http" && it.Priority == "Deferred" {
			foundDeferred = true
		}
		if it.Phase == "secrets" {
			foundSecret = true
			if strings.Contains(it.Target, "SUPER_SECRET_VALUE") || strings.Contains(it.Title, "SUPER_SECRET_VALUE") {
				t.Fatalf("secret leaked in triage item: %#v", it)
			}
		}
	}
	if !foundCritical || !foundDeferred || !foundSecret {
		t.Fatalf("phase engines missing: critical=%v deferred=%v secret=%v", foundCritical, foundDeferred, foundSecret)
	}
}

func TestGenerateExportsAndRedaction(t *testing.T) {
	dir := t.TempDir()
	s := store.Snapshot{
		URLs: []string{
			"https://example.com/reset?token=SHOULD_NEVER_APPEAR",
			"https://example.com/u/abcdefghijklmnopqrstuvwxyzabcdef123456",
		},
		Secrets: []*store.Secret{{Type: "Password", Value: "ALSO_SHOULD_NOT_APPEAR", Source: "test", File: "https://example.com/code.js?key=SHOULD_NEVER_APPEAR"}},
	}
	if err := Generate(s, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"triage.json", "triage.csv", "index.html", "SUMMARY.md", "phase_urls.csv", "phase_secrets.csv", "phase_networks.csv", "priority_P1.csv", "priority_P4.csv"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		if strings.Contains(text, "SHOULD_NEVER_APPEAR") || strings.Contains(text, "ALSO_SHOULD_NOT_APPEAR") {
			t.Fatalf("%s leaked a secret", name)
		}
	}
	if got := safeTarget("https://example.com/u/abcdefghijklmnopqrstuvwxyzabcdef123456?token=abc"); !strings.Contains(got, "[redacted]") {
		t.Fatalf("opaque path not masked: %q", got)
	}
}

func TestAnalyzeDedupDeterministicAndNoNetwork(t *testing.T) {
	s := store.Snapshot{Subdomains: []string{"admin.example.com", "admin.example.com"}}
	x, y := Analyze(s), Analyze(s)
	if len(x) != 1 || len(y) != 1 {
		t.Fatalf("expected dedup, got %d and %d", len(x), len(y))
	}
	if x[0].ID != y[0].ID || x[0].Priority != "P2" {
		t.Fatalf("unstable classification: %#v %#v", x[0], y[0])
	}
}
