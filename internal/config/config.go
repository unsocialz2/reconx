package config

import (
        "bufio"
        "fmt"
        "os"
        "strings"
)

// Target holds all input targets for a scan run
type Target struct {
        Domains   []string
        OrgName   string
        IPRanges  []string
        ASNs      []string
        ScopeFile string
}

// Scope defines in-scope and out-of-scope patterns
type Scope struct {
        InScope    []string
        OutOfScope []string
}

// ToolConfig holds per-tool configuration
type ToolConfig struct {
        Enabled   bool
        Path      string
        Flags     []string
        Timeout   int
        RateLimit int
        Extra     map[string]string
}

// PhasesConfig controls which phases to run
type PhasesConfig struct {
	SubdomainEnum bool
	AliveCheck    bool
	PortScan      bool
	URLDiscovery  bool
	JSAnalysis    bool
	VulnScan      bool
	Report        bool

	// New phases (Batch 1+)
	DirFuzz     bool // Phase 4.7 — Directory & content fuzzing (feroxbuster/ffuf/dirsearch)
	Params      bool // Phase 5   — Hidden parameter discovery (arjun)
	CloudEnum   bool // Phase 6   — Cloud/S3 bucket enumeration
	CORS        bool // Phase 6   — CORS misconfiguration scan
	Screenshots bool // Phase 2.5 — gowitness screenshots of live hosts (optional)
}

// OutputConfig controls output behavior
type OutputConfig struct {
        OutputDir   string
        HTMLReport  bool
        JSONReport  bool
        ColoredTerm bool
        Verbose     bool
        SaveRaw     bool
}

// Config is the root configuration
type Config struct {
        Target          Target
        Scope           Scope
        Phases          PhasesConfig
        Output          OutputConfig
        Tools           map[string]ToolConfig
        Workers         int
        Tokens          map[string]string
        BugBountyHeader string
        NoTimeout       bool   // disable all tool timeouts (run without deadlines)
        ResumeDir       string // path to existing scan dir to resume from
        WordlistPath    string // DNS brute-force wordlist override (--wordlist)
        ResolversPath   string // DNS resolvers file override (--resolvers)
        ConfigPath      string // path to a config file that was loaded (for logging)
}

// DefaultConfig returns production-grade timeouts tested on real bug bounty targets
// All timeouts here are based on real-world runs against large targets (airbnb, etc.)
func DefaultConfig() *Config {
        return &Config{
                Workers: 10,
                Phases: PhasesConfig{
                        SubdomainEnum: true,
                        AliveCheck:    true,
                        PortScan:      true,
                        URLDiscovery:  true,
                        JSAnalysis:    true,
                        VulnScan:      true,
                        Report:        true,
                        DirFuzz:       false, // opt-in: not all bug bounty programs allow directory fuzzing
                        Params:        false, // opt-in: parameter discovery can be slow/intrusive
                        CloudEnum:     true,
                        CORS:          true,
                },
                Output: OutputConfig{
                        OutputDir:   "./reconx-output",
                        HTMLReport:  true,
                        JSONReport:  true,
                        ColoredTerm: true,
                        Verbose:     false,
                        SaveRaw:     true,
                },
                Tools: map[string]ToolConfig{
                        // ── Subdomain tools ──────────────────────────────────────────────
                        "subfinder": {
                                Enabled: true, Path: "subfinder",
                                Flags:   []string{},
                                Timeout: 600, // 10 min — large targets need time
                        },
                        "amass": {
                                Enabled: true, Path: "amass",
                                Timeout: 600, // 10 min cap — amass is slow by design
                        },
                        "assetfinder": {
                                Enabled: true, Path: "assetfinder",
                                Timeout: 300, // 5 min
                        },
                        "findomain": {
                                Enabled: true, Path: "findomain",
                                Timeout: 300, // 5 min
                        },
                        "chaos": {
                                Enabled: true, Path: "chaos",
                                Timeout: 300,
                        },
                        "puredns": {
                                Enabled: true, Path: "puredns",
                                Timeout: 1800, // 30 min — bruteforce takes time
                        },
                        "dnsx": {
                                Enabled: true, Path: "dnsx",
                                Timeout: 1800, // 30 min
                        },

                        // ── Alive detection ──────────────────────────────────────────────
                        // 1681 subdomains @ 50 threads = ~34s minimum network time
                        // Real targets add TLS, redirects, slow hosts → need 20-30 min
                        "httpx": {
                                Enabled: true, Path: "httpx",
                                Flags:   []string{"-follow-redirects", "-status-code", "-title", "-web-server", "-content-length"},
                                Timeout: 1800, // 30 min — critical fix, was 5 min (not enough for 1000+ subs)
                        },

                        // ── Port scanning ────────────────────────────────────────────────
                        "naabu": {
                                Enabled: true, Path: "naabu",
                                Flags:   []string{"-rate", "2000"},
                                Timeout: 1800, // 30 min
                        },

			// ── URL discovery ────────────────────────────────────────────────
			"waybackurls": {
				Enabled: true, Path: "waybackurls",
				Timeout: 300, // 5 min default, 0 with --no-timeout
			},
			"waymore": {
				Enabled: true, Path: "waymore",
				Timeout: 300,
			},
			"gau": {
				Enabled: true, Path: "gau",
				Flags:   []string{"--threads", "50"},
				Timeout: 300,
			},
			"gauplus": {
				Enabled: true, Path: "gauplus",
				Timeout: 300,
			},
			"katana": {
				Enabled: true, Path: "katana",
				Flags:   []string{"-jc", "-kf", "all", "-d", "5", "-silent"},
				Timeout: 600,
			},
			"hakrawler": {
				Enabled: true, Path: "hakrawler",
				Timeout: 300,
			},
			"gospider": {
				Enabled: true, Path: "gospider",
				Timeout: 300,
			},
			"paramspider": {
				Enabled: true, Path: "paramspider",
				Timeout: 300,
			},

                        // ── JS / Secrets ─────────────────────────────────────────────────
                        "trufflehog": {Enabled: true, Path: "trufflehog", Timeout: 1800},
                        "mantra":     {Enabled: true, Path: "mantra",     Timeout: 600},
                        "jsecret":    {Enabled: true, Path: "jsecret",    Timeout: 1800},
                        "subjs":      {Enabled: true, Path: "subjs",      Timeout: 1800},

                        // ── Vuln scanning ────────────────────────────────────────────────
                        "nuclei": {
                                Enabled: true, Path: "nuclei",
                                Flags:   []string{"-severity", "critical,high,medium", "-silent"},
                                Timeout: 3600, // 60 min per template category
                        },

                        // ── Directory fuzzing ───────────────────────────────────────────
                        "feroxbuster": {
                                Enabled: true, Path: "feroxbuster",
                                Flags:   []string{"-k", "-d", "3", "-e", "-x", "php,html,json,js,log,txt,bak,old,zip"},
                                Timeout: 3600,
                        },
                        "ffuf": {
                                Enabled: true, Path: "ffuf",
                                Flags:   []string{"-mc", "200,301,302,403", "-recursion", "-recursion-depth", "2"},
                                Timeout: 3600,
                        },
                        "dirsearch": {
                                Enabled: true, Path: "dirsearch",
                                Flags:   []string{"-e", "php,asp,aspx,jsp,json,xml,bak,old,zip", "--exclude-status=404"},
                                Timeout: 1800,
                        },

                        // ── WAF & TLS (Alive sub-phases) ───────────────────────────────
                        "wafw00f": {
                                Enabled: true, Path: "wafw00f",
                                Timeout: 300,
                        },
                        "tlsx": {
                                Enabled: true, Path: "tlsx",
                                Flags:   []string{"-san", "-cn", "-silent"},
                                Timeout: 300,
                        },
                        "favfreak": {
                                Enabled: true, Path: "favfreak",
                                Timeout: 300,
                        },

                        // ── Wildcard & mass DNS (Subdomain sub-phases) ──────────────────
                        "massdns": {
                                Enabled: true, Path: "massdns",
                                Timeout: 1800,
                        },

                        // ── Hidden parameters ──────────────────────────────────────────
                        "arjun": {
                                Enabled: true, Path: "arjun",
                                Flags:   []string{"--stable"},
                                Timeout: 1800,
                        },
                        "dalfox": {
                                Enabled: true, Path: "dalfox",
                                Timeout: 900,
                        },
                        "getJS": {
                                Enabled: true, Path: "getJS",
                                Timeout: 600,
                        },

                        // ── Subdomain takeover ──────────────────────────────────────────
                        "subjack": {
                                Enabled: true, Path: "subjack",
                                Timeout: 300,
                        },

                        // ── Secrets ─────────────────────────────────────────────────────
                        "gitleaks": {
                                Enabled: true, Path: "gitleaks",
                                Timeout: 600,
                        },

                        // ── Cloud / bucket enum ────────────────────────────────────────
                        "s3scanner": {
                                Enabled: true, Path: "s3scanner",
                                Timeout: 600,
                        },
                        "cloud_enum": {
                                Enabled: true, Path: "cloud_enum",
                                Timeout: 600,
                        },
                },
                Tokens: map[string]string{},
        }
}

// LoadScope loads scope patterns from a file.
// Lines starting with '-' are out-of-scope; '+' or bare lines are in-scope.
func (c *Config) LoadScope(path string) error {
        f, err := os.Open(path)
        if err != nil {
                return fmt.Errorf("opening scope file: %w", err)
        }
        defer f.Close()

        sc := bufio.NewScanner(f)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "!") {
                        c.Scope.OutOfScope = append(c.Scope.OutOfScope, strings.TrimSpace(line[1:]))
                } else {
                        c.Scope.InScope = append(c.Scope.InScope, strings.TrimSpace(strings.TrimPrefix(line, "+")))
                }
        }
        return sc.Err()
}

// WriteDefault writes a commented default config to path
func WriteDefault(path string) error {
        content := `# ╔══════════════════════════════════════╗
# ║     ReconX Configuration File       ║
# ╚══════════════════════════════════════╝
#
# Format: INI-style.
#   - Booleans are true/false
#   - Lists use JSON array syntax: ["a", "b", "c"]
#   - Timeouts are in seconds
#   - Lines starting with # are comments
#
# Load with:  reconx -d example.com --config reconx.yaml
# All values here can still be overridden by CLI flags.

[output]
output_dir       = ./reconx-output
html_report      = true
json_report      = true
colored_terminal = true
verbose          = false
save_raw         = true

[phases]
subdomain_enum = true
alive_check    = true
port_scan      = true
url_discovery  = true
js_analysis    = true
vuln_scan      = true
report         = true

[tokens]
github          = ""
chaos           = ""
shodan          = ""
virustotal      = ""
securitytrails  = ""

[paths]
# Optional — override the auto-detected DNS brute wordlist and resolvers
# wordlist  = /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
# resolvers = /home/user/.config/reconx/resolvers.txt

# Timeouts are in seconds — tuned for large bug bounty targets (1000+ subdomains)
[tool.httpx]
enabled = true
timeout = 1800   # 30 min — needs time for 1000+ subs

[tool.waybackurls]
enabled = true
timeout = 1800   # 30 min — Wayback archive is huge

[tool.katana]
enabled = true
flags   = ["-jc", "-kf", "all", "-d", "5", "-silent"]
timeout = 3600   # 60 min — headless crawl

[tool.gau]
enabled = true
flags   = ["--threads", "50"]
timeout = 3600

[tool.nuclei]
enabled = true
flags   = ["-severity", "critical,high,medium"]
timeout = 3600

[tool.subfinder]
enabled = true
flags   = []
timeout = 600

[tool.naabu]
enabled = true
flags   = ["-rate", "2000"]
timeout = 1800
`
        return os.WriteFile(path, []byte(content), 0644)
}

// Load reads a reconx.yaml config file into an existing Config.
// Existing values in cfg are overwritten where the file specifies a value.
// Unknown sections/keys are silently ignored for forward-compatibility.
func Load(cfg *Config, path string) error {
        f, err := os.Open(path)
        if err != nil {
                return fmt.Errorf("opening config file: %w", err)
        }
        defer f.Close()

        section := ""
        sc := bufio.NewScanner(f)
        sc.Buffer(make([]byte, 1024*1024), 1024*1024)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                // Section header
                if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
                        section = strings.TrimSpace(line[1 : len(line)-1])
                        continue
                }
                // key = value
                eq := strings.Index(line, "=")
                if eq < 0 {
                        continue
                }
                key   := strings.TrimSpace(line[:eq])
                value := strings.TrimSpace(line[eq+1:])
                // Strip trailing inline comment (but not inside quotes)
                value = stripInlineComment(value)
                value = strings.Trim(value, `"`)

                applyConfigValue(cfg, section, key, value)
        }
        return sc.Err()
}

// stripInlineComment removes a trailing # comment from a value, respecting
// double-quoted strings so JSON arrays like ["a", "b"] aren't truncated.
func stripInlineComment(s string) string {
        inQuote := false
        for i, r := range s {
                switch r {
                case '"':
                        inQuote = !inQuote
                case '#':
                        if !inQuote {
                                return strings.TrimSpace(s[:i])
                        }
                }
        }
        return s
}

// applyConfigValue sets a single value on cfg based on section/key.
// Booleans accept "true"/"false". Lists accept JSON array syntax.
func applyConfigValue(cfg *Config, section, key, value string) {
        switch section {
        case "output":
                switch key {
                case "output_dir":
                        cfg.Output.OutputDir = value
                case "html_report":
                        cfg.Output.HTMLReport = parseBool(value)
                case "json_report":
                        cfg.Output.JSONReport = parseBool(value)
                case "colored_terminal":
                        cfg.Output.ColoredTerm = parseBool(value)
                case "verbose":
                        cfg.Output.Verbose = parseBool(value)
                case "save_raw":
                        cfg.Output.SaveRaw = parseBool(value)
                }

        case "phases":
                switch key {
                case "subdomain_enum":
                        cfg.Phases.SubdomainEnum = parseBool(value)
                case "alive_check":
                        cfg.Phases.AliveCheck = parseBool(value)
                case "port_scan":
                        cfg.Phases.PortScan = parseBool(value)
                case "url_discovery":
                        cfg.Phases.URLDiscovery = parseBool(value)
                case "js_analysis":
                        cfg.Phases.JSAnalysis = parseBool(value)
                case "vuln_scan":
                        cfg.Phases.VulnScan = parseBool(value)
                case "report":
                        cfg.Phases.Report = parseBool(value)
                case "dir_fuzz":
                        cfg.Phases.DirFuzz = parseBool(value)
                case "params":
                        cfg.Phases.Params = parseBool(value)
                case "cloud_enum":
                        cfg.Phases.CloudEnum = parseBool(value)
                case "cors":
                        cfg.Phases.CORS = parseBool(value)
                }

        case "tokens":
                if cfg.Tokens == nil {
                        cfg.Tokens = map[string]string{}
                }
                if value != "" {
                        cfg.Tokens[key] = value
                }

        case "paths":
                switch key {
                case "wordlist":
                        cfg.WordlistPath = value
                case "resolvers":
                        cfg.ResolversPath = value
                }

        case "scope":
                switch key {
                case "in_scope":
                        cfg.Scope.InScope = parseList(value)
                case "out_of_scope":
                        cfg.Scope.OutOfScope = parseList(value)
                }

        default:
                // tool.<name> sections
                if strings.HasPrefix(section, "tool.") {
                        name := strings.TrimPrefix(section, "tool.")
                        t := cfg.Tools[name]
                        switch key {
                        case "enabled":
                                t.Enabled = parseBool(value)
                        case "path":
                                t.Path = value
                        case "timeout":
                                t.Timeout = parseInt(value)
                        case "rate_limit":
                                t.RateLimit = parseInt(value)
                        case "flags":
                                t.Flags = parseList(value)
                        }
                        cfg.Tools[name] = t
                }
        }
}

func parseBool(s string) bool {
        s = strings.ToLower(strings.TrimSpace(s))
        return s == "true" || s == "1" || s == "yes" || s == "on"
}

func parseInt(s string) int {
        n := 0
        for _, r := range s {
                if r < '0' || r > '9' {
                        break
                }
                n = n*10 + int(r-'0')
        }
        return n
}

// parseList parses a JSON array string like ["a", "b", "c"] into a slice.
// Tolerant: also accepts comma-separated values without brackets. Respects
// quoted strings so values like "critical,high,medium" stay together.
func parseList(s string) []string {
        s = strings.TrimSpace(s)
        if s == "" {
                return nil
        }
        // Strip surrounding brackets if present
        if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
                s = s[1 : len(s)-1]
        }
        var out []string
        var current strings.Builder
        inQuote := false
        for _, r := range s {
                switch r {
                case '"':
                        inQuote = !inQuote
                case ',':
                        if inQuote {
                                current.WriteRune(r)
                        } else {
                                if p := strings.TrimSpace(current.String()); p != "" {
                                        p = strings.Trim(p, `"`)
                                        if p != "" {
                                                out = append(out, p)
                                        }
                                }
                                current.Reset()
                        }
                default:
                        current.WriteRune(r)
                }
        }
        // Last element
        if p := strings.TrimSpace(current.String()); p != "" {
                p = strings.Trim(p, `"`)
                if p != "" {
                        out = append(out, p)
                }
        }
        return out
}
