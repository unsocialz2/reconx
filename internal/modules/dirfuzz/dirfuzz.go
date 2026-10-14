package dirfuzz

import (
"context"
"fmt"
"os"
"strings"
"time"

"github.com/reconx/reconx/internal/config"
"github.com/reconx/reconx/internal/store"
"github.com/reconx/reconx/pkg/logger"
"github.com/reconx/reconx/pkg/runner"
"github.com/reconx/reconx/pkg/util"
)

// Module runs directory and content fuzzing against live hosts.
//
// Tool strategy (per the methodology):
//   - feroxbuster: primary — recursive, multi-ext, fast
//   - dirsearch:   secondary/fallback
//   - ffuf:        last resort
//
// Resume at pipeline level: if dirs/ already has results, the phase is skipped.
type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

// New creates a dirfuzz module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run executes directory fuzzing against all live hosts.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Directory & Content Fuzzing",
"feroxbuster (primary) → dirsearch (fallback) → ffuf (last resort) — recursive, multi-ext")

	hosts := m.store.GetHosts()
	if len(hosts) == 0 {
		m.log.Warn("No live hosts to fuzz — alive phase may have failed or no hosts are up")
		return nil
	}

	// Create output directory
	dirsDir := m.outDir + "/dirs"
	if err := os.MkdirAll(dirsDir, 0755); err != nil {
		m.log.Warn("Could not create dirs/ directory: %v", err)
	}

	// Build target URL list
	var targets []string
	for _, h := range hosts {
		if url, ok := h.Meta["url"]; ok {
			targets = append(targets, url)
		} else {
			targets = append(targets, "https://"+h.Domain)
		}
	}

	// Find wordlist
	wordlist := findWebWordlist(m.cfg)
	if wordlist == "" {
		m.log.Warn("No web wordlist found — dir fuzzing skipped. Set --wordlist or install seclists.")
		m.log.Warn("Expected: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt")
		return nil
	}
	m.log.Info("Using wordlist: %s (%d targets)", wordlist, len(targets))

	start := time.Now()
	total := 0

	// ── Tool 1: feroxbuster (primary) ────────────────────────────────────────
	feroxcfg := m.cfg.Tools["feroxbuster"]
	feroxPath := "feroxbuster"
	if feroxcfg.Path != "" {
		feroxPath = feroxcfg.Path
	}

	if runner.IsAvailable(feroxPath) {
		n := m.runFeroxbuster(ctx, targets, wordlist, dirsDir, feroxcfg)
		total += n
	} else {
		m.log.ToolSkipped("feroxbuster", "not found — install: cargo install feroxbuster")

		// ── Tool 2: dirsearch (fallback) ─────────────────────────────────────
		dcfg := m.cfg.Tools["dirsearch"]
		dPath := "dirsearch"
		if dcfg.Path != "" {
			dPath = dcfg.Path
		}

		if runner.IsAvailable(dPath) {
			n := m.runDirsearch(ctx, targets, wordlist, dirsDir, dcfg)
			total += n
		} else {
			m.log.ToolSkipped("dirsearch", "not found — install: pip3 install dirsearch")

			// ── Tool 3: ffuf (last resort) ────────────────────────────────────
			ffufcfg := m.cfg.Tools["ffuf"]
			ffufPath := "ffuf"
			if ffufcfg.Path != "" {
				ffufPath = ffufcfg.Path
			}
			if runner.IsAvailable(ffufPath) {
				n := m.runFFUF(ctx, targets, wordlist, dirsDir, ffufcfg)
				total += n
			} else {
				m.log.ToolSkipped("ffuf", "not found — install: go install github.com/ffuf/ffuf/v2@latest")
				m.log.Warn("No directory fuzzing tool available — install feroxbuster, dirsearch, or ffuf")
			}
		}
	}

	m.log.PhaseComplete("Directory & Content Fuzzing", total, time.Since(start))

	// Save combined results list
	results := m.store.DirResults
	if len(results) > 0 {
		lines := make([]string, 0, len(results))
		for _, r := range results {
			lines = append(lines, fmt.Sprintf("[%d] %s (%s)", r.StatusCode, r.URL, r.Tool))
		}
		if err := store.SaveRaw(dirsDir+"/all_dirs.txt", lines); err != nil {
			m.log.Warn("Could not save dirs/all_dirs.txt: %v", err)
		} else {
			m.log.Success("Dir results: %s/all_dirs.txt (%d entries)", dirsDir, len(lines))
		}
	}

	return nil
}

// ── feroxbuster ───────────────────────────────────────────────────────────────

func (m *Module) runFeroxbuster(ctx context.Context, targets []string, wordlist, outDir string, tcfg config.ToolConfig) int {
	outFile := outDir + "/feroxbuster_results.txt"

	args := []string{
		"--stdin",
		"-w", wordlist,
		"-t", "80",
		"-k",
		"-d", "3",
		"-e",
		"-o", outFile,
		"--auto-tune",
		"--no-state",
		"-x", "php,html,json,js,log,txt,bak,old,zip,tar,gz,xml,config,env",
	}
	// Merge extra flags from config avoiding duplicate flags
	seen := make(map[string]bool)
	for _, a := range args {
		seen[a] = true
	}
	for _, f := range tcfg.Flags {
		if f == "-x" || f == "--extensions" || seen[f] {
			continue
		}
		args = append(args, f)
		seen[f] = true
	}

	timeout := time.Duration(tcfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Minute
	}

	input := strings.Join(targets, "\n")
	m.log.Tool("feroxbuster", fmt.Sprintf("%d targets → %s", len(targets), outFile))
	m.log.ToolCmd("feroxbuster", args, fmt.Sprintf("[%d URLs via stdin]", len(targets)))
	start := time.Now()

	count := 0
	r := runner.Run(ctx, "feroxbuster", args,
runner.WithStdin(input),
runner.WithTimeout(timeout),
runner.WithStderrCallback(func(line string) {
m.log.Debug("feroxbuster: %s", line)
}),
runner.WithLineCallback(func(line string) {
line = strings.TrimSpace(line)
if line == "" || strings.HasPrefix(line, "#") {
return
}
d := parseFeroxLine(line)
if d == nil {
return
}
d.Tool = "feroxbuster"
m.store.AddDirResult(d)
count++
if d.StatusCode < 400 {
				m.log.Info("  [%d] %s", d.StatusCode, d.URL)
			}
		}),
	)

	if r.IsTimeout() {
		m.log.ToolTimeout("feroxbuster", count, timeout)
	} else if r.Err != nil && count == 0 {
		m.log.ToolError("feroxbuster", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("feroxbuster", count, time.Since(start))
	}
	return count
}

// parseFeroxLine parses feroxbuster plain-text output.
// Format: "STATUS   SIZE    WORDS   LINES   URL"
func parseFeroxLine(line string) *store.DirResult {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}
	url := fields[len(fields)-1]
	if !strings.HasPrefix(url, "http") {
		return nil
	}
	code := 0
	for _, r := range fields[0] {
		if r < '0' || r > '9' {
			return nil
		}
		code = code*10 + int(r-'0')
	}
	if code < 100 || code > 599 {
		return nil
	}
	target := url
	if idx := strings.Index(target[8:], "/"); idx >= 0 {
		target = target[:8+idx]
	}
	return &store.DirResult{
		URL:        url,
		StatusCode: code,
		Target:     target,
	}
}

// ── dirsearch ─────────────────────────────────────────────────────────────────

func (m *Module) runDirsearch(ctx context.Context, targets []string, wordlist, outDir string, tcfg config.ToolConfig) int {
	count := 0
	for i, target := range targets {
		select {
		case <-ctx.Done():
			return count
		default:
		}

		outFile := fmt.Sprintf("%s/dirsearch_%d.txt", outDir, i)
		args := []string{
			"-u", target,
			"-w", wordlist,
			"-t", "50",
			"--exclude-status=404",
			"-o", outFile,
			"--format", "plain",
			"--quiet",
		}
		args = append(args, tcfg.Flags...)

		timeout := time.Duration(tcfg.Timeout) * time.Second
		if timeout == 0 {
			timeout = 30 * time.Minute
		}

		m.log.Tool("dirsearch", fmt.Sprintf("%s → %s", target, outFile))
		start := time.Now()

		n := 0
		r := runner.Run(ctx, "dirsearch", args,
runner.WithTimeout(timeout),
runner.WithLineCallback(func(line string) {
d := parseDirsearchLine(line, target)
if d == nil {
return
}
d.Tool = "dirsearch"
m.store.AddDirResult(d)
n++
count++
if d.StatusCode < 400 {
					m.log.Info("  [%d] %s", d.StatusCode, d.URL)
				}
			}),
		)
		if r.Err != nil && n == 0 {
			m.log.Debug("dirsearch[%s]: %s", target, r.DiagString())
		} else {
			m.log.ToolDone("dirsearch:"+target, n, time.Since(start))
		}
	}
	return count
}

// parseDirsearchLine parses dirsearch plain output: "STATUS SIZE URL"
func parseDirsearchLine(line, base string) *store.DirResult {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Task") ||
		strings.HasPrefix(line, "[") {
		return nil
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	code := 0
	for _, r := range fields[0] {
		if r < '0' || r > '9' {
			return nil
		}
		code = code*10 + int(r-'0')
	}
	if code < 100 || code > 599 {
		return nil
	}
	path := fields[len(fields)-1]
	url := path
	if !strings.HasPrefix(path, "http") {
		url = strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
	}
	return &store.DirResult{URL: url, StatusCode: code, Target: base}
}

// ── ffuf ──────────────────────────────────────────────────────────────────────

func (m *Module) runFFUF(ctx context.Context, targets []string, wordlist, outDir string, tcfg config.ToolConfig) int {
	count := 0
	for i, target := range targets {
		select {
		case <-ctx.Done():
			return count
		default:
		}

		outFile := fmt.Sprintf("%s/ffuf_%d.json", outDir, i)
		args := []string{
			"-u", target + "/FUZZ",
			"-w", wordlist,
			"-t", "80",
			"-mc", "200,301,302,403,405",
			"-o", outFile,
			"-of", "json",
			"-s",
		}
		args = append(args, tcfg.Flags...)

		timeout := time.Duration(tcfg.Timeout) * time.Second
		if timeout == 0 {
			timeout = 30 * time.Minute
		}

		m.log.Tool("ffuf", fmt.Sprintf("%s → %s", target, outFile))
		start := time.Now()

		n := 0
		r := runner.Run(ctx, "ffuf", args,
runner.WithTimeout(timeout),
runner.WithLineCallback(func(line string) {
if !strings.Contains(line, `"url"`) {
return
}
url := util.JsonStr(line, "url")
statusStr := util.JsonStr(line, "status")
if url == "" || statusStr == "" {
return
}
code := 0
for _, ch := range statusStr {
if ch < '0' || ch > '9' {
						break
					}
					code = code*10 + int(ch-'0')
				}
				if code == 0 {
					return
				}
				d := &store.DirResult{
					URL:        url,
					StatusCode: code,
					Tool:       "ffuf",
					Target:     target,
				}
				m.store.AddDirResult(d)
				n++
				count++
				if code < 400 {
					m.log.Info("  [%d] %s", code, url)
				}
			}),
		)
		if r.Err != nil && n == 0 {
			m.log.Debug("ffuf[%s]: %s", target, r.DiagString())
		} else {
			m.log.ToolDone("ffuf:"+target, n, time.Since(start))
		}
	}
	return count
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// findWebWordlist locates a web content discovery wordlist.
func findWebWordlist(cfg *config.Config) string {
	if cfg != nil && cfg.WordlistPath != "" && util.FileExists(cfg.WordlistPath) {
		return cfg.WordlistPath
	}
	for _, p := range []string{
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt",
		"/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"./wordlists/web-content.txt",
	} {
		if util.FileExists(p) {
			return p
		}
	}
	return ""
}
