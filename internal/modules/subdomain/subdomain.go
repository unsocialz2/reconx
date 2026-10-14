package subdomain

import (
        "context"
        "fmt"
        "net"
        "os"
        "path/filepath"
        "regexp"
        "strings"
        "sync"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/scope"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
        "github.com/reconx/reconx/pkg/util"
)

type Module struct {
        cfg    *config.Config
        store  *store.Store
        scope  *scope.Filter
        log    *logger.Logger
        outDir string
}

func New(cfg *config.Config, st *store.Store, sc *scope.Filter, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, scope: sc, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
        m.log.Phase("Subdomain Enumeration",
                "All tools run in parallel — board updates live — results merged & deduplicated")

        start := time.Now()
        board := m.log.NewProgressBoard()

        // Live totals in the summary header — gives the user an instant
        // "is anything happening?" answer without scrolling per-tool rows.
        board.SetLiveStats(func() map[string]int {
                stats := m.store.Stats()
                return map[string]int{
                        "subdomains": stats["subdomains"],
                        "live_hosts": stats["live_hosts"],
                        "urls":       stats["urls"],
                        "findings":   stats["findings"],
                        "secrets":    stats["secrets"],
                }
        })

        // ── Wildcard detection (MUST run before any bruteforce) ─────────────────────
        // If a domain has wildcard DNS, bruteforce results will be flooded with
        // false positives (every word resolves). We detect this early and warn
        // so the user can decide whether to continue or add --skip-bruteforce.
        for _, domain := range m.cfg.Target.Domains {
                m.runWildcardCheck(ctx, domain, board)
        }

        var wg sync.WaitGroup
        for _, domain := range m.cfg.Target.Domains {
                domain := domain
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        m.enumerateDomain(ctx, domain, board)
                }()
        }

        if len(m.cfg.Target.IPRanges) > 0 && runner.IsAvailable("dnsx") {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        m.runPTRSweep(ctx, board)
                }()
        }

        for _, asn := range m.cfg.Target.ASNs {
                asn := asn
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        m.runASNMap(ctx, asn, board)
                }()
        }

        wg.Wait()

        total := len(m.store.GetSubdomains())
        m.log.PhaseComplete("Subdomain Enumeration", total, time.Since(start))
        m.printSourceSummary(board)
        board.Stop()
        // ── massdns resolve (optional, runs if massdns binary is available) ────────
        // Much faster than puredns/dnsx for very large subdomain sets (10k+).
        // Results are merged back into store so later phases see everything.
        if total > 5000 && runner.IsAvailable("massdns") {
                m.runMassdns(ctx, m.store.GetSubdomains())
        }

	subs := m.store.GetSubdomains()
	if err := store.SaveRaw(m.outDir+"/all_subs.txt", subs); err != nil {
		m.log.Warn("Failed to save all_subs.txt: %v", err)
	} else {
		m.log.Info("all_subs.txt   → %d unique subdomains saved", len(subs))
	}
	if err := store.SaveRaw(m.outDir+"/subdomains.txt", subs); err != nil {
		m.log.Warn("Failed to save subdomains.txt: %v", err)
	}
	return nil
}

// printSourceSummary prints a per-source yield table after enumeration so
// weak/failed sources are visible without grepping the debug log. This is
// the "why did I get fewer domains than subfinder alone?" answer at a glance.
func (m *Module) printSourceSummary(board *logger.ProgressBoard) {
	stats := board.SourceStats()
	if len(stats) == 0 {
		return
	}
	m.log.Separator()
	m.log.Info("Per-source yield:")
	for _, t := range stats {
		switch t.State {
		case "done", "timeout":
			if t.Count > 0 {
				m.log.Info("  ✓ %-18s %4d results%s", t.Name, t.Count, timeoutSuffix(t.State))
			} else {
				m.log.Info("  ? %-18s    0 results (source returned nothing)", t.Name)
			}
		case "error":
			m.log.Warn("  ✗ %-18s failed: %s", t.Name, t.Message)
		case "skipped":
			m.log.Warn("  ○ %-18s skipped: %s", t.Name, t.Message)
		default:
			m.log.Info("  ? %-18s still %s", t.Name, t.State)
		}
	}
	m.log.Separator()
}

func timeoutSuffix(state string) string {
	if state == "timeout" {
		return " (timed out — partial)"
	}
	return ""
}

func (m *Module) enumerateDomain(ctx context.Context, domain string, board *logger.ProgressBoard) {
	type toolDef struct {
		name     string
		binKey   string // binary name to check in PATH; "" = HTTP-only
		tokenKey string // config.Tokens key required to enable; "" = no token needed
		active   bool   // true = DNS-heavy (brute/permute) — runs in wave 2
		fn       func(context.Context, string, *logger.ProgressBoard) ([]string, []string)
	}

	// The set below is intentionally large — every source is tried in
	// parallel and the store deduplicates results. The user's stated goal
	// is "most domains ever", so we err on the side of including every
	// passive source we know about.
	tools := []toolDef{
		// Binary-backed tools (require install.sh)
		{name: "subfinder",   binKey: "subfinder",         fn: m.runSubfinder},
		{name: "assetfinder", binKey: "assetfinder",       fn: m.runAssetfinder},
		{name: "findomain",   binKey: "findomain",         fn: m.runFindomain},
		{name: "amass",       binKey: "amass",             fn: m.runAmass},
		{name: "chaos",       binKey: "chaos", tokenKey: "chaos",       fn: m.runChaos},
		{name: "github-subs", binKey: "github-subdomains", tokenKey: "github", fn: m.runGithubSubs},
		{name: "puredns",     binKey: "puredns", active: true,          fn: m.runPuredns},
		{name: "shuffledns",  binKey: "shuffledns", active: true,       fn: m.runShuffleDNS},
		{name: "dnsx-brute",  binKey: "dnsx", active: true,             fn: m.runDnsxBrute},

		// HTTP-only API sources (no binary needed)
		{name: "crt.sh",          fn: m.runCrtSh},
		{name: "certspotter",     fn: m.runCertspotter},
		{name: "hackertarget",    fn: m.runHackerTarget},
		{name: "anubis",          fn: m.runAnubis},
		{name: "rapiddns",        fn: m.runRapidDNS},
		{name: "subdomaincenter", fn: m.runSubdomainCenter},
		{name: "alienvault-otx",  fn: m.runOTXSubs},
		{name: "urlscan",         fn: m.runURLScan},
		{name: "virustotal",      tokenKey: "virustotal",     fn: m.runVirusTotal},
		{name: "shodan",          tokenKey: "shodan",         fn: m.runShodan},
		{name: "securitytrails",  tokenKey: "securitytrails", fn: m.runSecurityTrails},
		{name: "censys",          tokenKey: "censys",         fn: m.runCensys},
	}

	hasPuredns := runner.IsAvailable("puredns")
	hasShuffledns := runner.IsAvailable("shuffledns")

	// ── WAVE 1: passive/API sources ─────────────────────────────────────────
	// All HTTP/API-based tools run concurrently. This wave is light on DNS
	// (API lookups only). Keeping the DNS brute-forcers OUT of this wave
	// matters: puredns/massdns with thousands of resolvers + permute with
	// thousands of system-resolver lookups previously ran at the same time
	// and starved the passive tools of DNS/network — they'd return a
	// fraction of their real results (observed: subfinder 5 vs 133 when run
	// alone, chaos 0 vs 123).
	runWave := func(defs []toolDef) {
		var wg sync.WaitGroup
		for _, t := range defs {
			t := t

			// Avoid running 3 heavy bruteforcers against the same wordlist
			// concurrently. puredns is massdns-backed and fastest; fallback
			// to shuffledns, then dnsx-brute.
			if t.name == "shuffledns" && hasPuredns {
				board.Skip(t.name, "using puredns (fastest)")
				continue
			}
			if t.name == "dnsx-brute" && (hasPuredns || hasShuffledns) {
				board.Skip(t.name, "using puredns/shuffledns (faster)")
				continue
			}

			if t.tokenKey != "" && m.cfg.Tokens[t.tokenKey] == "" {
				board.Skip(t.name, "no "+t.tokenKey+" token")
				continue
			}
			if t.binKey != "" {
				path := t.binKey
				if tcfg, ok := m.cfg.Tools[t.binKey]; ok {
					if !tcfg.Enabled {
						board.Skip(t.name, "disabled")
						continue
					}
					if tcfg.Path != "" {
						path = tcfg.Path
					}
				}
				if !runner.IsAvailable(path) {
					board.Skip(t.name, "not found — run install.sh")
					continue
				}
			}

			board.Register(t.name, domain)
			wg.Add(1)
			go func() {
				defer wg.Done()
				results, _ := t.fn(ctx, domain, board)
				clean    := cleanLines(results)
				filtered := m.scope.FilterList(clean)
				dropped  := len(clean) - len(filtered)
				// Tag each subdomain with the source that found it
				// so the HTML report can filter by source.
				added := m.store.AddSubdomainsBulkWithSource(filtered, t.name)
				m.log.Debug("%s [%s]: %d raw, %d clean, %d in-scope, %d new (store total: %d)",
					t.name, domain, len(results), len(clean), len(filtered), added,
					len(m.store.GetSubdomains()))
				if dropped > 0 {
					m.log.Debug("%s: %d results dropped as out-of-scope", t.name, dropped)
				}
			}()
		}
		wg.Wait()
	}

	passive := make([]toolDef, 0, len(tools))
	active := make([]toolDef, 0, 4)
	for _, t := range tools {
		if t.active {
			active = append(active, t)
		} else {
			passive = append(passive, t)
		}
	}
	runWave(passive)

	// ── WAVE 2: permutation + DNS brute-force ───────────────────────────────
	// permute runs here (not in wave 1) for two reasons:
	//   1. It floods the system resolver with lookups — isolating it keeps
	//      the passive tools' API queries healthy.
	//   2. It permutes the prefixes found in wave 1, which finds far more
	//      real hosts than permuting the empty set at t=0.
	active = append(active, toolDef{name: "permute", fn: m.runPermute})
	runWave(active)
}

// ── Tool runners ─────────────────────────────────────────────────────────────

func (m *Module) runSubfinder(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	tcfg := m.cfg.Tools["subfinder"]
	path := "subfinder"
	if tcfg.Path != "" {
		path = tcfg.Path
	}
	// -all enables every subfinder source (including keyed ones from
	// subfinder's own provider config). Without it subfinder only queries
	// its default subset — a common cause of "subfinder alone found more".
	// -nc disables ANSI escape codes in subfinder output.
	args := append([]string{"-d", domain, "-all", "-silent", "-nc"}, tcfg.Flags...)

	var count int
	var mu sync.Mutex
	r := runner.Run(ctx, path, args,
		runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
		runner.WithLineCallback(func(line string) {
			mu.Lock()
			count++
			c := count
			mu.Unlock()
			board.Update("subfinder", c)
		}))

	finalize(board, "subfinder", r)
	return r.Lines, r.Stderr
}

func (m *Module) runAssetfinder(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	tcfg := m.cfg.Tools["assetfinder"]

	var count int
	var mu sync.Mutex
	r := runner.Run(ctx, tcfg.Path, []string{"-subs-only"},
		runner.WithStdin(domain),
		runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
		runner.WithLineCallback(func(line string) {
			mu.Lock()
			count++
			c := count
			mu.Unlock()
			board.Update("assetfinder", c)
		}))

	finalize(board, "assetfinder", r)
	return r.Lines, r.Stderr
}

func (m *Module) runFindomain(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	tcfg := m.cfg.Tools["findomain"]

	var count int
	var mu sync.Mutex
	r := runner.Run(ctx, tcfg.Path, []string{"-t", domain, "-q"},
		runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
		runner.WithLineCallback(func(line string) {
			mu.Lock()
			count++
			c := count
			mu.Unlock()
			board.Update("findomain", c)
		}))

	finalize(board, "findomain", r)
	return r.Lines, r.Stderr
}

func (m *Module) runAmass(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	tcfg := m.cfg.Tools["amass"]
	path := "amass"
	if tcfg.Path != "" {
		path = tcfg.Path
	}
	// Cap the deadline at 10 min (cfg default) — amass passive enum on big
	// targets can otherwise run for hours: -timeout only limits the data
	// collection window; amass's post-collection DNS resolution can run far
	// longer, so the runner deadline is the hard stop.
	timeout := 10 * time.Minute
	if tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	// amass v4 quirk: with -silent, results do NOT appear on stdout — they
	// must be captured via -o <file>. Without -o, -silent silently discards
	// everything (observed: 0 results vs 233 without the flag).
	outFile := filepath.Join(m.outDir, "amass_raw.txt")
	args := []string{"enum", "-passive", "-d", domain, "-silent", "-o", outFile}
	// Under --no-timeout, omit -timeout entirely so amass runs to completion.
	if timeout > 0 {
		amassMin := int(timeout / time.Minute)
		if amassMin < 1 {
			amassMin = 1
		}
		args = append(args, "-timeout", fmt.Sprintf("%d", amassMin))
	}

	board.Heartbeat("amass")
	r := runner.Run(ctx, path, args,
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { board.Heartbeat("amass") }))

	var lines []string
	if data, err := os.ReadFile(outFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
	}
	// amass -o writes graph lines like:
	//   sub.domain.com (FQDN) --> cname_record --> target (FQDN)
	// Extract both sides so CNAME targets on the target domain are kept too.
	var results []string
	for _, l := range lines {
		for _, side := range strings.Split(l, " --> ") {
			side = strings.TrimSpace(side)
			if idx := strings.Index(side, " ("); idx > 0 {
				side = side[:idx]
			}
			results = append(results, side)
		}
	}

	if r.IsTimeout() {
		board.Timeout("amass", len(results))
	} else if r.Err != nil && len(results) == 0 {
		board.Fail("amass", r.DiagString())
	} else {
		board.Done("amass", len(results))
	}
	return results, r.Stderr
}

func (m *Module) runChaos(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	tcfg := m.cfg.Tools["chaos"]
	token := m.cfg.Tokens["chaos"]
	path := "chaos"
	if tcfg.Path != "" {
		path = tcfg.Path
	}

	var count int
	var mu sync.Mutex
	r := runner.Run(ctx, path, []string{"-d", domain, "-silent"},
		runner.WithEnv([]string{"PDCP_API_KEY=" + token}),
		runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
		runner.WithLineCallback(func(line string) {
			mu.Lock()
			count++
			c := count
			mu.Unlock()
			board.Update("chaos", c)
		}))

	finalize(board, "chaos", r)
	return r.Lines, r.Stderr
}

func (m *Module) runGithubSubs(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["github"]
	path := "github-subdomains"
	timeout := 3 * time.Minute
	// github-subdomains is not in cfg.Tools by default, but allow override.
	if tcfg, ok := m.cfg.Tools["github-subdomains"]; ok {
		if tcfg.Path != "" {
			path = tcfg.Path
		}
		if tcfg.Timeout > 0 {
			timeout = time.Duration(tcfg.Timeout) * time.Second
		}
	}

	// github-subdomains prefixes every stdout line with "[HH:MM:SS] " even
	// in quiet mode — e.g. "[02:01:17] cargo.indrive.com". Without stripping
	// the timestamp, cleanLines rejects every line (contains a space) and
	// the source yields 0 results despite finding 700+.
	// Results also go to -o <file> clean; we use that as the source of truth
	// and keep stdout only for the live board counter.
	outFile := filepath.Join(m.outDir, "github_subs_raw.txt")

	var count int
	var mu sync.Mutex
	r := runner.Run(ctx, path,
		[]string{"-d", domain, "-t", token, "-q", "-o", outFile},
		runner.WithTimeout(timeout),
		runner.WithLineCallback(func(line string) {
			clean := ghTsPrefix.ReplaceAllString(line, "")
			if !isValidDomain(strings.ToLower(clean)) {
				return // banner/log lines only
			}
			mu.Lock()
			count++
			board.Update("github-subs", count)
			mu.Unlock()
		}))

	var results []string
	if data, err := os.ReadFile(outFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				results = append(results, l)
			}
		}
	}
	if len(results) == 0 {
		// Older tool versions without -o support: strip timestamps manually.
		for _, l := range r.Lines {
			if clean := ghTsPrefix.ReplaceAllString(l, ""); isValidDomain(strings.ToLower(clean)) {
				results = append(results, clean)
			}
		}
	}

	finalize(board, "github-subs", r)
	return results, r.Stderr
}

// ghTsPrefix matches the "[HH:MM:SS] " prefix github-subdomains puts on
// every stdout line, even in quiet mode.
var ghTsPrefix = regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\]\s*`)

func (m *Module) runDnsxBrute(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
        wordlist := findWordlist(m.cfg)
        if wordlist == "" {
                board.Skip("dnsx-brute", "no wordlist found")
                return nil, nil
        }
        tcfg := m.cfg.Tools["dnsx"]
        path := "dnsx"
        if tcfg.Path != "" {
                path = tcfg.Path
        }
        args := []string{"-silent", "-d", domain, "-w", wordlist, "-t", "100", "-rl", "500"}
        resolvers := findResolvers(m.cfg)
        if resolvers != "" {
                args = append(args, "-r", resolvers)
        }
        timeout := 10 * time.Minute
        if tcfg.Timeout > 0 {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        r := runner.Run(ctx, path, args,
                runner.WithTimeout(timeout),
                runner.WithLineCallback(func(line string) { board.Heartbeat("dnsx-brute") }),
                runner.WithStderrCallback(func(line string) { board.Heartbeat("dnsx-brute") }))

        finalize(board, "dnsx-brute", r)
        return r.Lines, r.Stderr
}

func (m *Module) runPuredns(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	wordlist := findWordlist(m.cfg)
	if wordlist == "" {
		board.Skip("puredns", "no wordlist found")
		return nil, nil
	}
	resolvers := findResolvers(m.cfg)
	path := "puredns"
	if tcfg, ok := m.cfg.Tools["puredns"]; ok && tcfg.Path != "" {
		path = tcfg.Path
	}
	timeout := 15 * time.Minute
	if tcfg, ok := m.cfg.Tools["puredns"]; ok && tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	// puredns bruteforce domain [flags] reads wordlist from stdin.
	// Passing wordlist as an argument causes puredns to treat the wordlist path
	// as the target domain and read 0 bytes from stdin, producing 0 results.
	outFile := filepath.Join(m.outDir, "puredns_raw.txt")
	args := []string{"bruteforce", domain, "-w", outFile}
	if resolvers != "" {
		args = append(args, "-r", resolvers)
	}

	r := runner.Run(ctx, path, args,
		runner.WithStdinFile(wordlist),
		runner.WithTimeout(timeout),
		runner.WithLineCallback(func(line string) { board.Heartbeat("puredns") }),
		runner.WithStderrCallback(func(line string) { board.Heartbeat("puredns") }))

	var results []string
	if data, err := os.ReadFile(outFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				results = append(results, l)
			}
		}
	}
	if len(results) > 0 {
		board.Done("puredns", len(results))
		return results, r.Stderr
	}

	// If puredns returned 0 results (due to massdns environment or resolver issues),
	// automatically fall back to dnsx-brute so DNS bruteforcing never fails silently.
	if runner.IsAvailable("dnsx") {
		m.log.Debug("puredns found 0 domains — attempting dnsx-brute fallback for %s", domain)
		return m.runDnsxBrute(ctx, domain, board)
	}

	finalize(board, "puredns", r)
	return r.Lines, r.Stderr
}

func (m *Module) runPTRSweep(ctx context.Context, board *logger.ProgressBoard) {
        for _, cidr := range m.cfg.Target.IPRanges {
                board.Register("dnsx-ptr", cidr)
                // Pipe CIDR into dnsx via stdin — no shell, no injection risk.
                // Previously used `sh -c "echo $CIDR | dnsx ..."` which would
                // execute arbitrary commands if a CIDR contained a backtick,
                // $, ;, or any other shell metacharacter.
                r := runner.Run(ctx, "dnsx", []string{"-silent", "-resp-only", "-ptr"},
                        runner.WithStdin(cidr),
                        runner.WithTimeout(5*time.Minute))
                if r.Err == nil && len(r.Lines) > 0 {
                        m.store.AddSubdomains(m.scope.FilterList(r.Lines))
                        board.Done("dnsx-ptr", len(r.Lines))
                } else {
                        board.Fail("dnsx-ptr", r.DiagString())
                }
        }
}

func (m *Module) runASNMap(ctx context.Context, asn string, board *logger.ProgressBoard) {
        path := "asnmap"
        if tcfg, ok := m.cfg.Tools["asnmap"]; ok && tcfg.Path != "" {
                path = tcfg.Path
        }
        if !runner.IsAvailable(path) {
                board.Skip("asnmap", "not found — install: go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
                return
        }
        board.Register("asnmap", asn)
        r := runner.Run(ctx, path, []string{"-a", asn, "-silent"}, runner.WithTimeout(2*time.Minute))
        finalize(board, "asnmap", r)
        // asnmap returns IP ranges (CIDRs like "1.2.3.0/24"). Storing
        // them as subdomains was a semantic bug — they're not hostnames.
        // The store now has a dedicated IPRanges field. asnmap also
        // returns hostnames it discovers while walking the ASN; we
        // route those to the subdomain store.
        if len(r.Lines) > 0 {
                var cidrs, domains []string
                for _, line := range r.Lines {
                        line = strings.TrimSpace(line)
                        if line == "" {
                                continue
                        }
                        if strings.Contains(line, "/") {
                                // CIDR — store in IP ranges
                                m.store.AddIPRange(line)
                                cidrs = append(cidrs, line)
                        } else if strings.Contains(line, ".") && !strings.ContainsAny(line, " \t/\\") {
                                // hostname — store as subdomain
                                domains = append(domains, line)
                        }
                }
                if len(domains) > 0 {
                        m.store.AddSubdomainsFromSource(m.scope.FilterList(domains), "asnmap")
                }
                m.log.Debug("asnmap: %d CIDRs + %d domains", len(cidrs), len(domains))
        }
}

// finalize updates the board based on a runner.Result
func finalize(board *logger.ProgressBoard, name string, r *runner.Result) {
        if r.IsTimeout() {
                board.Timeout(name, len(r.Lines))
        } else if r.Err != nil && len(r.Lines) == 0 {
                board.Fail(name, r.DiagString())
        } else {
                board.Done(name, len(r.Lines))
        }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

var ansiEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func cleanLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "\x1b") {
			l = ansiEscapeRegex.ReplaceAllString(l, "")
		}
		// Discard lines with spaces or invalid control characters
		if strings.ContainsAny(l, " \t\r\n/\\") {
			continue
		}
		// If line is comma-separated (e.g. "domain,ip" or multiple domains)
		if strings.Contains(l, ",") {
			parts := strings.Split(l, ",")
			for _, p := range parts {
				p = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(p), "*."))
				if host, _, err := net.SplitHostPort(p); err == nil {
					p = host
				}
				if isValidDomain(p) {
					out = append(out, p)
				}
			}
			continue
		}

		l = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(l), "*."))
		if host, _, err := net.SplitHostPort(l); err == nil {
			l = host
		}
		if l != "" && isValidDomain(l) {
			out = append(out, l)
		}
	}
	return out
}

func isValidDomain(s string) bool {
	return s != "" && len(s) <= 253 && strings.Contains(s, ".") &&
		!strings.ContainsAny(s, " \n\t/\\")
}

// findWordlist finds a DNS brute-force wordlist. Priority:
//  1. cfg.WordlistPath (from --wordlist flag or config)
//  2. reconx config dir (downloaded by install.sh)
//  3. Well-known SecLists paths
//  4. ./wordlists/subdomains.txt
func findWordlist(cfg *config.Config) string {
        // Allow user override via config / CLI flag
        if cfg != nil && cfg.WordlistPath != "" && util.FileExists(cfg.WordlistPath) {
                return cfg.WordlistPath
        }
        home, _ := os.UserHomeDir()
        for _, p := range []string{
                filepath.Join(home, ".config", "reconx", "wordlists", "subdomains.txt"),
                "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
                "/usr/share/wordlists/best-dns-wordlist.txt",
                "./wordlists/subdomains.txt",
        } {
                if util.FileExists(p) {
                        return p
                }
        }
        return ""
}

// findResolvers finds a DNS resolvers list. Priority:
//  1. cfg.ResolversPath (from --resolvers flag or config)
//  2. reconx config dir
//  3. ./resolvers.txt
func findResolvers(cfg *config.Config) string {
        if cfg != nil && cfg.ResolversPath != "" && util.FileExists(cfg.ResolversPath) {
                return cfg.ResolversPath
        }
        for _, p := range []string{
                os.ExpandEnv("$HOME/.config/reconx/resolvers.txt"),
                "/root/.config/reconx/resolvers.txt",
                "./resolvers.txt",
        } {
                if util.FileExists(p) {
                        return p
                }
        }
        return ""
}

// ── Wildcard detection ────────────────────────────────────────────────────────────────

// runWildcardCheck probes whether a domain has wildcard DNS configured.
// Strategy:
//  1. Resolve a random non-existent hostname with dig.
//     If it resolves to any IP → wildcard present.
//  2. If puredns is available, use --wildcard-tests 50 as a second pass.
//
// Wildcard detection is a WARN only — it does not stop the scan.
// The user is informed so they can interpret brute-force results carefully.
func (m *Module) runWildcardCheck(ctx context.Context, domain string, board *logger.ProgressBoard) {
        board.Register("wildcard-check", domain)

        // Generate a random label that almost certainly doesn't exist
        rndLabel := fmt.Sprintf("reconx-wc-test-77293819.%s", domain)

        // First: use dig (universally available on Linux/macOS)
        detected := false
        if runner.IsAvailable("dig") {
                digCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
                defer cancel()
                r := runner.Run(digCtx, "dig", []string{"+short", rndLabel})
                if r.Err == nil && len(r.Lines) > 0 {
                        for _, line := range r.Lines {
                                line = strings.TrimSpace(line)
                                if line != "" && !strings.HasPrefix(line, ";;") {
                                        detected = true
                                        break
                                }
                        }
                }
        }

        // Second pass: puredns --wildcard-tests if available
        if !detected && runner.IsAvailable("puredns") {
                resolvers := findResolvers(m.cfg)
                pureArgs := []string{"bruteforce", "/dev/null", domain, "--wildcard-tests", "50"}
                if resolvers != "" {
                        pureArgs = append(pureArgs, "-r", resolvers)
                }
                pureCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
                defer cancel()
                r := runner.Run(pureCtx, "puredns", pureArgs)
                // puredns exits non-zero when wildcard is detected — check stderr
                if r.Err != nil && len(r.Stderr) > 0 {
                        for _, line := range r.Stderr {
                                if strings.Contains(strings.ToLower(line), "wildcard") {
                                        detected = true
                                        break
                                }
                        }
                }
        }

        if detected {
                board.Fail("wildcard-check", fmt.Sprintf(
                        "WILDCARD DNS detected for %s — brute-force may have false positives", domain))
                m.log.Warn("Wildcard DNS detected for %s — brute-force results will need additional filtering.", domain)
                m.log.Warn("puredns/dnsx will attempt to filter wildcards automatically using their built-in wildcard filter.")
        } else {
                board.Done("wildcard-check", 0)
                m.log.Debug("No wildcard DNS detected for %s", domain)
        }
}

// ── Massdns (large-scale resolution) ────────────────────────────────────────────────────

// runMassdns resolves a large list of subdomains using massdns, which is
// significantly faster than puredns/dnsx for 10k+ entries.
// Results are merged back into the store as additional subdomains.
func (m *Module) runMassdns(ctx context.Context, domains []string) {
        if len(domains) == 0 {
                return
        }
        tcfg := m.cfg.Tools["massdns"]
        path := "massdns"
        if tcfg.Path != "" {
                path = tcfg.Path
        }
        if !runner.IsAvailable(path) {
                m.log.Debug("massdns not found — skipping mass resolution (puredns already ran)")
                return
        }

        resolvers := findResolvers(m.cfg)
        if resolvers == "" {
                m.log.Debug("massdns: no resolvers file found — skipping")
                return
        }

        // Write domains to a temp file
        tmpFile := m.outDir + "/.massdns_input.tmp"
        if err := store.SaveRaw(tmpFile, domains); err != nil {
                m.log.Warn("massdns: could not write input file: %v", err)
                return
        }
        defer os.Remove(tmpFile)

        outFile := m.outDir + "/massdns_raw.txt"
        args := []string{"-r", resolvers, "-t", "A", "-o", "S", "-w", outFile, tmpFile}

        m.log.Tool("massdns", fmt.Sprintf("%d subdomains → %s", len(domains), outFile))
        m.log.ToolCmd("massdns", args, "")

        start := time.Now()
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 30 * time.Minute
        }
	r := runner.Run(ctx, path, args, runner.WithTimeout(timeout))

	// Massdns writes output directly to outFile (-w). Read it from disk.
	lines := r.Lines
	if data, err := os.ReadFile(outFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, l)
			}
		}
	}

	if r.Err != nil && len(lines) == 0 {
		m.log.ToolError("massdns", fmt.Errorf("%s", r.DiagString()), r.Stderr)
		return
	}

	// Parse massdns simple output (format: "hostname A ip")
	var newSubs []string
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 && strings.EqualFold(parts[1], "A") {
			sub := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parts[0])), ".")
			if isValidDomain(sub) {
				newSubs = append(newSubs, sub)
			}
		}
	}

	added := m.store.AddSubdomainsFromSource(m.scope.FilterList(newSubs), "massdns")
	m.log.ToolDone("massdns", added, time.Since(start))
	m.log.Debug("massdns: %d lines parsed, %d new subdomains added", len(lines), added)
}
