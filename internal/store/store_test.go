package store

import (
	"sync"
	"testing"
)

func TestAddSubdomain_Dedup(t *testing.T) {
	s := New("test-scan")
	if !s.AddSubdomain("sub.example.com") {
		t.Error("first add should return true")
	}
	if s.AddSubdomain("sub.example.com") {
		t.Error("duplicate add should return false")
	}
	subs := s.GetSubdomains()
	if len(subs) != 1 {
		t.Errorf("expected 1 subdomain, got %d", len(subs))
	}
}

func TestAddSubdomains_Count(t *testing.T) {
	s := New("test-scan")
	added := s.AddSubdomains([]string{"a.com", "b.com", "a.com", "c.com"})
	if added != 3 {
		t.Errorf("expected 3 new subdomains, got %d", added)
	}
}

func TestAddURL_Dedup(t *testing.T) {
	s := New("test-scan")
	s.AddURL("https://example.com/path")
	s.AddURL("https://example.com/path")
	s.AddURL("https://example.com/other")
	urls := s.GetURLs()
	if len(urls) != 2 {
		t.Errorf("expected 2 URLs, got %d", len(urls))
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := New("concurrent-test")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.AddSubdomain("sub" + string(rune('0'+n%10)) + ".example.com")
			s.AddURL("https://example.com/" + string(rune('0'+n%10)))
		}(i)
	}
	wg.Wait()

	stats := s.Stats()
	if stats["subdomains"] == 0 {
		t.Error("expected subdomains after concurrent adds")
	}
}

func TestAddFinding(t *testing.T) {
	s := New("test-scan")
	s.AddFinding(&Finding{
		Name:     "Open Redirect",
		Severity: "high",
		Target:   "https://example.com/redirect?url=evil.com",
	})
	if len(s.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(s.Findings))
	}
	if s.Findings[0].FoundAt.IsZero() {
		t.Error("FoundAt timestamp should be set")
	}
}

func TestStats(t *testing.T) {
	s := New("test-scan")
	s.AddSubdomains([]string{"a.com", "b.com"})
	s.AddHost(&Host{Domain: "a.com", StatusCode: 200})
	s.AddPort(&Port{Host: "a.com", Port: 443})
	s.AddURLs([]string{"https://a.com/", "https://a.com/api"})
	s.AddFinding(&Finding{Name: "test", Severity: "high", Target: "a.com"})
	s.AddSecret(&Secret{Type: "api_key", Value: "xxx", Source: "mantra"})

	stats := s.Stats()
	if stats["subdomains"] != 2 {
		t.Errorf("subdomains: want 2, got %d", stats["subdomains"])
	}
	if stats["live_hosts"] != 1 {
		t.Errorf("live_hosts: want 1, got %d", stats["live_hosts"])
	}
	if stats["open_ports"] != 1 {
		t.Errorf("open_ports: want 1, got %d", stats["open_ports"])
	}
	if stats["urls"] != 2 {
		t.Errorf("urls: want 2, got %d", stats["urls"])
	}
	if stats["findings"] != 1 {
		t.Errorf("findings: want 1, got %d", stats["findings"])
	}
	if stats["secrets"] != 1 {
		t.Errorf("secrets: want 1, got %d", stats["secrets"])
	}
}

// TestAddSubdomainFromSource_PreservesFirst ensures the first source wins on
// re-add. This matters during resume mode: if a tool re-discovers an already-
// known subdomain, the original source string should not be overwritten.
func TestAddSubdomainFromSource_PreservesFirst(t *testing.T) {
	s := New("test-scan")
	if !s.AddSubdomainFromSource("a.com", "subfinder") {
		t.Error("first add should return true")
	}
	if s.AddSubdomainFromSource("a.com", "amass") {
		t.Error("re-add should return false (already known)")
	}
	entries := s.GetSubdomainsWithSource()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Source != "subfinder" {
		t.Errorf("source not preserved: want 'subfinder', got %q", entries[0].Source)
	}
}

// TestAddSubdomainsBulkWithSource tests the transactional batch add.
func TestAddSubdomainsBulkWithSource(t *testing.T) {
	s := New("test-scan")
	added := s.AddSubdomainsBulkWithSource([]string{"a.com", "b.com", "c.com"}, "puredns")
	if added != 3 {
		t.Errorf("expected 3 new, got %d", added)
	}
	// Re-add with different source — should not change source on existing
	s.AddSubdomainsBulkWithSource([]string{"a.com", "d.com"}, "amass")
	entries := s.GetSubdomainsWithSource()
	if len(entries) != 4 {
		t.Errorf("expected 4 total, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Subdomain == "a.com" && e.Source != "puredns" {
			t.Errorf("a.com source should remain 'puredns' (first source wins), got %q", e.Source)
		}
		if e.Subdomain == "d.com" && e.Source != "amass" {
			t.Errorf("d.com source should be 'amass', got %q", e.Source)
		}
	}
}

// TestAddIPRange_Dedup tests IP range deduplication.
func TestAddIPRange_Dedup(t *testing.T) {
	s := New("test-scan")
	s.AddIPRange("10.0.0.0/24")
	s.AddIPRange("10.0.0.0/24") // duplicate
	s.AddIPRange("192.168.0.0/16")
	ranges := s.GetIPRanges()
	if len(ranges) != 2 {
		t.Errorf("expected 2 IP ranges after dedup, got %d", len(ranges))
	}
}

// TestAddSecret_DedupAndStripANSI tests secret deduplication and ANSI stripping.
func TestAddSecret_DedupAndStripANSI(t *testing.T) {
	s := New("test-scan")
	s.AddSecret(&Secret{
		Type:   "API Key",
		Value:  "\x1b[32mAIzaSyD-Secret123456\x1b[0m",
		Source: "mantra",
		File:   "https://example.com/app.js",
	})
	// Duplicate with different ANSI or same content
	s.AddSecret(&Secret{
		Type:   "API Key",
		Value:  "AIzaSyD-Secret123456",
		Source: "gitleaks",
		File:   "https://example.com/app.js",
	})

	if len(s.Secrets) != 1 {
		t.Fatalf("expected 1 secret after dedup, got %d", len(s.Secrets))
	}
	if s.Secrets[0].Value != "AIzaSyD-Secret123456" {
		t.Errorf("expected ANSI stripped value, got %q", s.Secrets[0].Value)
	}
}

