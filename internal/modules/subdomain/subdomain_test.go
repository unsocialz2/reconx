package subdomain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
)

func TestCleanLines(t *testing.T) {
	in := []string{
		"*.example.com",
		"SUB.EXAMPLE.COM",
		"   test.example.com   ",
		"invalid domain with spaces.com",
		"http://example.com",
		"valid-sub.example.com",
	}
	out := cleanLines(in)
	expected := []string{
		"example.com",
		"sub.example.com",
		"test.example.com",
		"valid-sub.example.com",
	}

	if len(out) != len(expected) {
		t.Fatalf("expected %d clean lines, got %d: %v", len(expected), len(out), out)
	}
	for i, exp := range expected {
		if out[i] != exp {
			t.Errorf("at index %d: expected %q, got %q", i, exp, out[i])
		}
	}
}

func TestSubdomainFilter(t *testing.T) {
	f := newSubdomainFilter("example.com")

	cases := []struct {
		in   string
		want bool
	}{
		{"api.example.com", true},
		{"API.EXAMPLE.COM", false},        // dup of api.example.com (lowercased)
		{"*.wild.example.com", true},      // wildcard stripped
		{"prefix", true},                  // bare prefix → prefix.example.com
		{"1.2.3.4,sub.example.com", true}, // CSV from bufferover
		{"https://tls.example.com/path", true},
		{"host.example.com:8443", true},
		{"evil.com", false},             // different domain
		{"notexample.com", false},       // suffix trick
		{"trailing.example.com.", true}, // trailing dot stripped
		{"api.example.com", false},      // duplicate
		{"", false},
		{"192.168.1.1", false}, // bare IP — no dot-label match
	}

	for _, c := range cases {
		got := f.add(c.in)
		if got != c.want {
			t.Errorf("add(%q) = %v, want %v", c.in, got, c.want)
		}
	}

	// Expected unique outputs (in order of first acceptance)
	wantOut := []string{
		"api.example.com",
		"wild.example.com",
		"prefix.example.com",
		"sub.example.com",
		"tls.example.com",
		"host.example.com",
		"trailing.example.com",
	}
	if len(f.out) != len(wantOut) {
		t.Fatalf("out = %v, want %v", f.out, wantOut)
	}
	for i := range wantOut {
		if f.out[i] != wantOut[i] {
			t.Errorf("out[%d] = %q, want %q", i, f.out[i], wantOut[i])
		}
	}
}

func TestSubfinderMyFitnessPal(t *testing.T) {
	if testing.Short() || os.Getenv("RECONX_LIVE_TESTS") != "1" {
		t.Skip("skipping live network test in short mode")
	}
	cfg := config.DefaultConfig()
	log := logger.New(false, "")
	st := store.New("test-debug")
	sc := scope.New(cfg)
	m := New(cfg, st, sc, log, t.TempDir())
	board := log.NewProgressBoard()
	defer board.Stop()

	t0 := time.Now()
	lines, stderr := m.runSubfinder(context.Background(), "myfitnesspal.com", board)
	t.Logf("Elapsed: %v", time.Since(t0))
	t.Logf("Lines count: %d", len(lines))
	t.Logf("Lines (first 10): %v", lines[:min(10, len(lines))])
	t.Logf("Stderr count: %d", len(stderr))
	t.Logf("Stderr: %v", stderr)
}

func TestRateLimitIsTerminalAndKeepsHTTPStatus(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	l := logger.New(false, "")
	defer l.Close()
	_, status, err := apiFetch(context.Background(), server.URL, "fixture", l, nil)
	if err != nil || status != 429 || requests != 1 {
		t.Fatalf("status=%d requests=%d err=%v", status, requests, err)
	}
}

func TestConcurrentAmassTargetsUseSeparateOutputFiles(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-amass")
	script := `#!/bin/sh
while [ "$#" -gt 0 ]; do
 case "$1" in -d) domain="$2";shift;; -o) out="$2";shift;; esac
 shift
done
sleep 0.01
printf '%s (FQDN)\n' "$domain" > "$out"
`
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Tools["amass"] = config.ToolConfig{Enabled: true, Path: bin, Timeout: 1}
	l := logger.New(false, "")
	defer l.Close()
	board := l.NewProgressBoard()
	defer board.Stop()
	m := New(cfg, store.New("test"), scope.New(cfg), l, dir)
	var wg sync.WaitGroup
	for _, domain := range []string{"a.example.test", "b.example.test"} {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			child := board.ForTarget(domain)
			child.Register("amass", domain)
			results, _ := m.runAmass(context.Background(), domain, child)
			if len(results) != 1 || results[0] != domain {
				t.Errorf("domain=%s results=%v", domain, results)
			}
		}(domain)
	}
	wg.Wait()
}
