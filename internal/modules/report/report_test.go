package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reconx/reconx/internal/store"
)

func TestGenerate_EmptyStore(t *testing.T) {
	st := store.New("test-scan-empty")
	tmp := t.TempDir()
	if err := Generate(st, []string{"example.com"}, tmp); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	path := filepath.Join(tmp, "report.html")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("report.html not created: %v", err)
	}
	if info.Size() < 1000 {
		t.Errorf("report.html too small (%d bytes) — template likely didn't render", info.Size())
	}
}

func TestGenerate_PopulatedStore(t *testing.T) {
	st := store.New("test-scan-full")
	st.StartTime = st.StartTime.Add(-60 * 1e9) // 60s ago

	// Add subdomains with sources
	st.AddSubdomainFromSource("api.example.com", "subfinder")
	st.AddSubdomainFromSource("www.example.com", "crt.sh")
	st.AddSubdomainFromSource("dev.example.com", "permute")
	st.AddSubdomainFromSource("admin.example.com", "subfinder")
	st.AddSubdomainFromSource("staging.example.com", "amass")
	// Duplicate source — first wins
	st.AddSubdomainFromSource("api.example.com", "crt.sh")

	// Add hosts
	st.AddHost(&store.Host{
		Domain:     "api.example.com",
		StatusCode: 200,
		Title:      "API Server",
		Server:     "nginx",
		TechStack:  []string{"nginx", "PHP", "MySQL"},
		Tags:       []string{"200-ok"},
		Meta:       map[string]string{"url": "https://api.example.com"},
	})
	st.AddHost(&store.Host{
		Domain:     "www.example.com",
		StatusCode: 403,
		Title:      "Forbidden",
		Server:     "cloudflare",
		TechStack:  []string{"cloudflare", "React"},
		Tags:       []string{"403-bypass-candidate"},
		Meta:       map[string]string{"url": "https://www.example.com"},
	})

	// Add ports
	st.AddPort(&store.Port{Host: "api.example.com", Port: 443, Protocol: "tcp", Service: "https"})
	st.AddPort(&store.Port{Host: "api.example.com", Port: 80, Protocol: "tcp", Service: "http"})
	st.AddPort(&store.Port{Host: "www.example.com", Port: 443, Protocol: "tcp", Service: "https"})

	// Add URLs
	st.AddURLs([]string{
		"https://api.example.com/v1/users",
		"https://api.example.com/login",
		"https://www.example.com/admin",
	})

	// Add JS files
	st.AddJSFile("https://api.example.com/static/app.js")
	st.AddJSFile("https://www.example.com/main.js")

	// Add findings
	st.AddFinding(&store.Finding{Name: "Open Redirect", Severity: "high", Target: "https://api.example.com/redirect", Template: "open-redirect"})
	st.AddFinding(&store.Finding{Name: "XSS in search", Severity: "medium", Target: "https://www.example.com/search?q=<script>", Template: "xss-reflected"})
	st.AddFinding(&store.Finding{Name: "Server Status Disclosure", Severity: "low", Target: "https://api.example.com/", Template: "tech-detect"})

	// Add secrets
	st.AddSecret(&store.Secret{Type: "AWS Access Key", Value: "AKIAIOSFODNN7EXAMPLE", Source: "trufflehog"})
	st.AddSecret(&store.Secret{Type: "GitHub Token", Value: "ghp_xxxxxxxxxxxx", Source: "mantra"})

	tmp := t.TempDir()
	if err := Generate(st, []string{"example.com"}, tmp); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Read the report and verify it has the expected content
	path := filepath.Join(tmp, "report.html")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	html := string(data)

	// Must contain the scan ID
	if !strings.Contains(html, "test-scan-full") {
		t.Error("report should contain scan ID")
	}
	// Must contain all subdomains
	for _, sub := range []string{"api.example.com", "www.example.com", "dev.example.com", "admin.example.com", "staging.example.com"} {
		if !strings.Contains(html, sub) {
			t.Errorf("report should contain subdomain %q", sub)
		}
	}
	// Must contain the sources (so the filter chip can show them)
	for _, src := range []string{"subfinder", "crt.sh", "permute", "amass"} {
		if !strings.Contains(html, src) {
			t.Errorf("report should contain source %q", src)
		}
	}
	// Must contain the findings
	for _, f := range []string{"Open Redirect", "XSS in search"} {
		if !strings.Contains(html, f) {
			t.Errorf("report should contain finding %q", f)
		}
	}
	// Must contain the secrets
	if !strings.Contains(html, "AWS Access Key") {
		t.Error("report should contain AWS Access Key secret")
	}
	// Must have the SCAN_DATA script block for client-side filtering
	if !strings.Contains(html, "SCAN_DATA") {
		t.Error("report should embed SCAN_DATA for client-side filtering")
	}
}

func TestGenerate_SourceAttribution(t *testing.T) {
	st := store.New("test-source-attribution")
	// First source wins
	st.AddSubdomainFromSource("a.example.com", "subfinder")
	st.AddSubdomainFromSource("a.example.com", "crt.sh")
	// Source recorded as subfinder (first)
	subs := st.GetSubdomainsWithSource()
	if len(subs) != 1 {
		t.Fatalf("expected 1 subdomain, got %d", len(subs))
	}
	if subs[0].Source != "subfinder" {
		t.Errorf("source should be 'subfinder' (first wins), got %q", subs[0].Source)
	}
}

func TestUniqueStatusCodes(t *testing.T) {
	hosts := []*store.Host{
		{StatusCode: 200},
		{StatusCode: 200},
		{StatusCode: 403},
		{StatusCode: 404},
		{StatusCode: 0}, // ignored
	}
	got := uniqueStatusCodes(hosts)
	if len(got) != 3 {
		t.Errorf("expected 3 unique status codes, got %d: %v", len(got), got)
	}
}

func TestUniqueTech(t *testing.T) {
	hosts := []*store.Host{
		{TechStack: []string{"nginx", "PHP"}},
		{TechStack: []string{"nginx", "React"}},
		{TechStack: []string{}},
	}
	got := uniqueTech(hosts)
	if len(got) != 3 {
		t.Errorf("expected 3 unique techs, got %d: %v", len(got), got)
	}
}

func TestBuildSourceChart(t *testing.T) {
	subs := []store.SubdomainEntry{
		{Subdomain: "a.example.com", Source: "subfinder"},
		{Subdomain: "b.example.com", Source: "subfinder"},
		{Subdomain: "c.example.com", Source: "crt.sh"},
		{Subdomain: "d.example.com", Source: ""}, // unknown
	}
	chart := buildSourceChart(subs)
	if len(chart) != 3 {
		t.Errorf("expected 3 sources (subfinder, crt.sh, unknown), got %d: %v", len(chart), chart)
	}
	// subfinder should be first (2 results)
	if chart[0].Label != "subfinder" || chart[0].Value != 2 {
		t.Errorf("first entry should be subfinder(2), got %v", chart[0])
	}
}


func TestRedactSecretValue_Short(t *testing.T) {
	// Short values are entirely redacted
	got := redactSecretValue("short")
	if got != "***REDACTED***" {
		t.Errorf("short secret: want %q, got %q", "***REDACTED***", got)
	}
}

func TestRedactSecretValue_Long(t *testing.T) {
	// Longer values get partial redaction — keep first/last 4 chars, mask middle
	got := redactSecretValue("AKIAIOSFODNN7EXAMPLE")
	if !strings.Contains(got, "***") {
		t.Errorf("expected mask in redacted value, got %q", got)
	}
	if strings.Contains(got, "IOSFODNN7EXAMPLE") {
		t.Errorf("middle of secret should be masked, got %q", got)
	}
	if !strings.HasPrefix(got, "AKIA") {
		t.Errorf("should keep first 4 chars, got %q", got)
	}
}
