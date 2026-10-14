package scope

import (
	"testing"

	"github.com/reconx/reconx/internal/config"
)

func makeFilter(inScope, outScope []string, domains []string) *Filter {
	cfg := config.DefaultConfig()
	cfg.Scope.InScope = inScope
	cfg.Scope.OutOfScope = outScope
	cfg.Target.Domains = domains
	return New(cfg)
}

func TestIsInScope_BasicDomain(t *testing.T) {
	f := makeFilter(nil, nil, []string{"example.com"})
	cases := []struct {
		input string
		want  bool
	}{
		{"sub.example.com", true},
		{"example.com", true},
		{"sub.sub.example.com", true},
		{"evil.com", false},
		{"notexample.com", false},
	}
	for _, c := range cases {
		got := f.IsInScope(c.input)
		if got != c.want {
			t.Errorf("IsInScope(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

func TestIsInScope_WithExplicitInScope(t *testing.T) {
	f := makeFilter([]string{"*.example.com", "api.example.com"}, nil, nil)
	if !f.IsInScope("sub.example.com") {
		t.Error("expected sub.example.com in scope")
	}
	if !f.IsInScope("api.example.com") {
		t.Error("expected api.example.com in scope")
	}
	if f.IsInScope("other.com") {
		t.Error("other.com should be out of scope")
	}
}

func TestIsInScope_OutOfScopeWins(t *testing.T) {
	f := makeFilter(
		[]string{"*.example.com"},
		[]string{"staging.example.com"},
		nil,
	)
	if f.IsInScope("staging.example.com") {
		t.Error("staging.example.com should be excluded by out-of-scope rule")
	}
	if !f.IsInScope("prod.example.com") {
		t.Error("prod.example.com should be in scope")
	}
}

func TestIsInScope_URLStripping(t *testing.T) {
	f := makeFilter(nil, nil, []string{"example.com"})
	// Should strip protocol and path before matching
	if !f.IsInScope("https://sub.example.com/path?q=1") {
		t.Error("URL with protocol/path should be recognized as in scope")
	}
}

func TestIsInScope_IPRange(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Target.IPRanges = []string{"10.0.0.0/24"}
	f := New(cfg)
	if !f.IsInScope("10.0.0.50") {
		t.Error("10.0.0.50 should be in scope for 10.0.0.0/24")
	}
	if f.IsInScope("10.0.1.1") {
		t.Error("10.0.1.1 should NOT be in scope for 10.0.0.0/24")
	}
}

func TestFilterList(t *testing.T) {
	f := makeFilter(nil, []string{"staging.example.com"}, []string{"example.com"})
	in := []string{
		"sub.example.com",
		"staging.example.com",
		"other.example.com",
		"evil.com",
	}
	out := f.FilterList(in)
	if len(out) != 2 {
		t.Errorf("expected 2 results, got %d: %v", len(out), out)
	}
}

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		value   string
		pattern string
		want    bool
	}{
		{"sub.example.com", "*.example.com", true},
		{"example.com", "*.example.com", true},
		{"example.com", "example.com", true},
		{"notexample.com", "example.com", false},
		{"sub.example.com", "example.com", true},
		{"other.com", "example.com", false},
	}
	for _, c := range cases {
		got := matchPattern(c.value, c.pattern)
		if got != c.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", c.value, c.pattern, got, c.want)
		}
	}
}
