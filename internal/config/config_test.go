package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultsPreservedWhenNotInFile(t *testing.T) {
	cfg := DefaultConfig()
	originalTimeout := cfg.Tools["subfinder"].Timeout

	tmp := t.TempDir()
	path := filepath.Join(tmp, "reconx.yaml")
	// Config file sets only one value — everything else must stay at default.
	if err := os.WriteFile(path, []byte("[output]\nverbose = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Load(cfg, path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Value from file applied
	if !cfg.Output.Verbose {
		t.Error("verbose should be true after loading config")
	}
	// Untouched value preserved
	if cfg.Tools["subfinder"].Timeout != originalTimeout {
		t.Errorf("subfinder timeout should be unchanged: got %d, want %d",
			cfg.Tools["subfinder"].Timeout, originalTimeout)
	}
}

func TestLoad_ToolSection(t *testing.T) {
	cfg := DefaultConfig()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "reconx.yaml")
	content := `
[tool.subfinder]
enabled = false
timeout = 999
flags = ["-all", "-recursive", "-t", "20"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Load(cfg, path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	sub := cfg.Tools["subfinder"]
	if sub.Enabled {
		t.Error("subfinder should be disabled")
	}
	if sub.Timeout != 999 {
		t.Errorf("subfinder timeout: got %d, want 999", sub.Timeout)
	}
	if len(sub.Flags) != 4 {
		t.Errorf("subfinder flags: got %d, want 4 (%v)", len(sub.Flags), sub.Flags)
	}
}

func TestLoad_PhasesAndTokens(t *testing.T) {
	cfg := DefaultConfig()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "reconx.yaml")
	content := `
[phases]
port_scan = false
vuln_scan = false

[tokens]
virustotal = "abc123"
shodan = "xyz789"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Load(cfg, path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Phases.PortScan {
		t.Error("port_scan should be false")
	}
	if cfg.Phases.VulnScan {
		t.Error("vuln_scan should be false")
	}
	if cfg.Tokens["virustotal"] != "abc123" {
		t.Errorf("virustotal token: got %q, want 'abc123'", cfg.Tokens["virustotal"])
	}
	if cfg.Tokens["shodan"] != "xyz789" {
		t.Errorf("shodan token: got %q, want 'xyz789'", cfg.Tokens["shodan"])
	}
}

func TestLoad_InlineComments(t *testing.T) {
	cfg := DefaultConfig()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "reconx.yaml")
	content := `
[tool.nuclei]
timeout = 3600   # 60 min — headless scan
flags = ["-severity", "critical,high,medium"]  # critical+high+medium only
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Load(cfg, path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	nuc := cfg.Tools["nuclei"]
	if nuc.Timeout != 3600 {
		t.Errorf("nuclei timeout: got %d, want 3600", nuc.Timeout)
	}
	if len(nuc.Flags) != 2 {
		t.Errorf("nuclei flags should be 2 elements: got %v", nuc.Flags)
	}
}

func TestLoad_Paths(t *testing.T) {
	cfg := DefaultConfig()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "reconx.yaml")
	content := `
[paths]
wordlist = /tmp/words.txt
resolvers = /tmp/resolvers.txt
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	if err := Load(cfg, path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.WordlistPath != "/tmp/words.txt" {
		t.Errorf("wordlist: got %q, want /tmp/words.txt", cfg.WordlistPath)
	}
	if cfg.ResolversPath != "/tmp/resolvers.txt" {
		t.Errorf("resolvers: got %q, want /tmp/resolvers.txt", cfg.ResolversPath)
	}
}

func TestParseList_JSONArray(t *testing.T) {
	got := parseList(`["a", "b", "c"]`)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("parseList failed: got %v", got)
	}
}

func TestParseList_CommaSeparated(t *testing.T) {
	got := parseList(`a, b, c`)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("parseList failed: got %v", got)
	}
}

func TestParseList_Empty(t *testing.T) {
	if got := parseList(""); got != nil {
		t.Errorf("parseList('') should return nil, got %v", got)
	}
	if got := parseList("[]"); got != nil {
		t.Errorf("parseList('[]') should return nil, got %v", got)
	}
}

func TestParseBool(t *testing.T) {
	for _, s := range []string{"true", "TRUE", "True", "1", "yes", "on"} {
		if !parseBool(s) {
			t.Errorf("parseBool(%q) should be true", s)
		}
	}
	for _, s := range []string{"false", "0", "no", "off", "", "garbage"} {
		if parseBool(s) {
			t.Errorf("parseBool(%q) should be false", s)
		}
	}
}

func TestParseInt(t *testing.T) {
	cases := map[string]int{
		"0":     0,
		"123":   123,
		"3600":  3600,
		"":      0,
		"abc":   0,
		"12abc": 12,
	}
	for in, want := range cases {
		if got := parseInt(in); got != want {
			t.Errorf("parseInt(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestStripInlineComment(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`3600   # comment`, `3600`},
		{`["a", "b"]  # array`, `["a", "b"]`},
		{`"value#with#hash"`, `"value#with#hash"`},
		{`no_comment`, `no_comment`},
		{``, ``},
	}
	for _, c := range cases {
		got := stripInlineComment(c.in)
		if got != c.want {
			t.Errorf("stripInlineComment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
