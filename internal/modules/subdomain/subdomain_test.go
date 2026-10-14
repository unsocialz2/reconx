package subdomain

import (
	"context"
	"testing"
	"time"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/scope"
	"github.com/reconx/reconx/internal/store"
	"github.com/reconx/reconx/pkg/logger"
)

func TestCleanLines(t *testing.T) {	in := []string{
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
		{"API.EXAMPLE.COM", false},         // dup of api.example.com (lowercased)
		{"*.wild.example.com", true},       // wildcard stripped
		{"prefix", true},                   // bare prefix → prefix.example.com
		{"1.2.3.4,sub.example.com", true},  // CSV from bufferover
		{"https://tls.example.com/path", true},
		{"host.example.com:8443", true},
		{"evil.com", false},                // different domain
		{"notexample.com", false},          // suffix trick
		{"trailing.example.com.", true},    // trailing dot stripped
		{"api.example.com", false},         // duplicate
		{"", false},
		{"192.168.1.1", false},             // bare IP — no dot-label match
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
	if testing.Short() {
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
