package alive

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/store"
	"github.com/reconx/reconx/pkg/logger"
	"github.com/reconx/reconx/pkg/runner"
	"github.com/reconx/reconx/pkg/util"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripAnsi(s string) string {
	return ansiPattern.ReplaceAllString(s, "")
}

// Module probes discovered subdomains for live HTTP/S hosts
type Module struct {
        cfg    *config.Config
        store  *store.Store
        log    *logger.Logger
        outDir string
}

// New creates an alive-check module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run probes all discovered subdomains
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Alive Host Detection",
		"Probing all subdomains — status code, title, server, tech fingerprint")

	subs := m.store.GetSubdomains()
	if len(subs) == 0 {
		// If subdomain enum was skipped (single target mode / --skip-subs), use Target.Domains
		if len(m.cfg.Target.Domains) > 0 {
			subs = m.cfg.Target.Domains
			m.store.AddSubdomains(subs)
			m.log.Info("Single target mode / Subdomains skipped: Probing %d target domains directly...", len(subs))
		} else {
			m.log.Warn("No subdomains or target domains to probe — subdomain phase may have failed")
			return nil
		}
	} else {
		m.log.Info("Probing %d subdomains with httpx...", len(subs))
	}

	tcfg := m.cfg.Tools["httpx"]
	httpxPath := "httpx"
	if tcfg.Path != "" {
		httpxPath = tcfg.Path
	}

	var err error
	if !runner.IsAvailable(httpxPath) {
		m.log.ToolSkipped("httpx", fmt.Sprintf("binary '%s' not found in PATH — falling back to curl", httpxPath))
		err = m.runCurlFallback(ctx, subs)
	} else {
		// Show httpx version for debugging
		ver := runner.Version(httpxPath)
		m.log.Debug("httpx version: %s (path: %s)", ver, runner.WhichPath(httpxPath))
		err = m.runHttpx(ctx, subs, httpxPath, tcfg)
		if len(m.store.GetHosts()) == 0 && len(subs) > 0 {
			m.log.Info("httpx returned 0 live hosts — attempting built-in curl probe fallback...")
			_ = m.runCurlFallback(ctx, subs)
		}
	}

	// ── WAF Detection (after httpx, before fuzzing/vuln scan) ───────────────
	// Knowing whether a WAF is present lets us tune threads/timing in later
	// phases to avoid getting blocked or rate-limited.
	m.runWAFDetection(ctx)
	m.saveAliveWAFSplit() // write live_waf.txt / live_nowaf.txt

	// ── TLS / Certificate info ─────────────────────────────────────────────
	// SANs from TLS certs often reveal subdomains not found by passive tools.
	// Any new SANs discovered here are added back to the subdomain store.
	m.runTLSX(ctx)

	// ── Subdomain Takeover Check (subjack) ──────────────────────────────────
	// Checks all discovered subdomains for dangling CNAMEs (AWS S3, GitHub Pages, Heroku, etc.)
	m.runSubjack(ctx)

	return err
}

func (m *Module) runHttpx(ctx context.Context, subs []string, path string, tcfg config.ToolConfig) error {
        input := strings.Join(subs, "\n")
        start := time.Now()

        // Minimal safe flag set that works across httpx versions
        args := []string{
                "-silent",
                "-json",
                "-follow-redirects",
                "-threads", "50",
                "-timeout", "10",
                "-retries", "2",
                "-status-code",
                "-title",
                "-web-server",
                "-content-length",
                "-tech-detect",
                "-favicon",
        }

        m.log.Tool("httpx", fmt.Sprintf("%d subdomains", len(subs)))
        m.log.ToolCmd("httpx", args, fmt.Sprintf("[%d subdomains via stdin]", len(subs)))

        var (
                mu          sync.Mutex
                liveCount   int
                parseErrors int
                httpxErrors []string
        )
        board := m.log.NewProgressBoard()
        board.Register("httpx", fmt.Sprintf("%d subdomains", len(subs)))

        // Live totals in the summary header
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

        r := runner.Run(ctx, path, args,
                runner.WithStdin(input),
                runner.WithTimeout(time.Duration(tcfg.Timeout)*time.Second),
                runner.WithStderrCallback(func(line string) {
                        // httpx writes non-fatal warnings to stderr — log them as debug
                        m.log.Debug("httpx stderr: %s", line)
                        mu.Lock()
                        httpxErrors = append(httpxErrors, line)
                        mu.Unlock()
                        // Heartbeat — keeps the board from showing httpx as "stuck"
                        // while it's actively probing hosts that don't respond.
                        board.Heartbeat("httpx")
                }),
                runner.WithLineCallback(func(line string) {
                        line = strings.TrimSpace(line)
                        if line == "" || !strings.HasPrefix(line, "{") {
                                // httpx sometimes writes banner lines before JSON — skip them
                                m.log.Debug("httpx non-JSON line: %s", line)
                                return
                        }
                        host := parseHTTPXLine(line)
                        if host == nil {
                                parseErrors++
                                m.log.Debug("httpx: failed to parse JSON line: %s", util.Truncate(line, 120))
                                return
                        }
                        m.store.AddHost(host)
                        mu.Lock()
                        liveCount++
                        mu.Unlock()
                        board.Update("httpx", liveCount)
                        m.log.LiveHost(host.Domain, host.StatusCode, host.Title, host.Server)
                }),
        )

        elapsed := time.Since(start)

        if r.IsTimeout() {
                board.Timeout("httpx", liveCount)
                m.log.ToolTimeout("httpx", liveCount, time.Duration(tcfg.Timeout)*time.Second)
        } else if r.Err != nil && liveCount == 0 {
                // httpx exits non-zero when 0 hosts respond — check stderr for real errors
                m.log.ToolError("httpx", fmt.Errorf(r.DiagString()), r.Stderr)
                m.log.Warn("httpx returned 0 live hosts — possible issues:")
                m.log.Warn("  1. All %d subdomains are actually dead/unreachable", len(subs))
                m.log.Warn("  2. httpx flags incompatible with installed version (%s)", runner.Version(path))
                m.log.Warn("  3. Network connectivity issue — try: curl -s https://%s", subs[0])
                m.log.Warn("  Check %s/reconx.log for full stderr output", m.outDir)
        } else {
                board.Done("httpx", liveCount)
                m.log.ToolDone("httpx", liveCount, elapsed)
                if parseErrors > 0 {
                        m.log.Warn("httpx: %d JSON parse errors — check reconx.log for details", parseErrors)
                }
        }

        m.log.Debug("httpx stats: %d probed → %d live (%.1f%% hit rate)",
                len(subs), liveCount, float64(liveCount)/float64(len(subs))*100)

        board.Stop()
        return m.saveAlive()
}

// runCurlFallback probes hosts with curl when httpx isn't installed
func (m *Module) runCurlFallback(ctx context.Context, subs []string) error {
        if !runner.IsAvailable("curl") {
                m.log.Warn("Neither httpx nor curl found — install httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
                return nil
        }

        start := time.Now()
        m.log.Tool("curl-probe", fmt.Sprintf("%d subdomains (concurrency: 30)", len(subs)))

        type probeResult struct {
                domain string
                status int
                server string
        }

        sem     := make(chan struct{}, 30)
        results := make(chan probeResult, len(subs))

        for _, sub := range subs {
                sub := sub
                go func() {
                        sem <- struct{}{}
                        defer func() { <-sem }()

                        for _, scheme := range []string{"https", "http"} {
                                url := scheme + "://" + sub
                                r := runner.Run(ctx, "curl",
                                        []string{
                                                "-s", "-o", "/dev/null",
                                                "-w", "%{http_code}|||%{url_effective}",
                                                "--max-time", "8",
                                                "--connect-timeout", "5",
                                                "-L", "--max-redirs", "3",
                                                "-A", "Mozilla/5.0 (reconx)",
                                                url,
                                        },
                                        runner.WithTimeout(12*time.Second))

                                if r.Err == nil && len(r.Lines) > 0 {
                                        parts := strings.SplitN(r.Lines[0], "|||", 2)
                                        code, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
                                        if code > 0 {
                                                results <- probeResult{domain: sub, status: code}
                                                return
                                        }
                                }
                        }
                        results <- probeResult{}
                }()
        }

        liveCount := 0
        for range subs {
                if res := <-results; res.domain != "" {
                        h := &store.Host{
                                Domain:     res.domain,
                                StatusCode: res.status,
                                Meta:       map[string]string{"url": "https://" + res.domain},
                        }
                        tagHost(h)
                        m.store.AddHost(h)
                        liveCount++
                        m.log.LiveHost(res.domain, res.status, "", "")
                }
        }

        m.log.ToolDone("curl-probe", liveCount, time.Since(start))
        return m.saveAlive()
}

func (m *Module) saveAlive() error {
	hosts := m.store.GetHosts()
	lines := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if url, ok := h.Meta["url"]; ok {
			lines = append(lines, url)
		} else {
			lines = append(lines, "https://"+h.Domain)
		}
	}
	if err := store.SaveRaw(m.outDir+"/alive.txt", lines); err != nil {
		m.log.Warn("Failed to save alive.txt: %v", err)
		return err
	}
	m.log.Debug("Saved alive.txt (%d entries)", len(lines))
	return nil
}

// saveAliveWAFSplit writes live_waf.txt and live_nowaf.txt after WAF detection.
// Called from Run() after runWAFDetection() so WAFResults are populated.
func (m *Module) saveAliveWAFSplit() {
	wafHosts := m.store.GetWAFHosts()
	nowafHosts := m.store.GetNonWAFHosts()

	if err := store.SaveRaw(m.outDir+"/live_waf.txt", wafHosts); err != nil {
		m.log.Warn("Failed to save live_waf.txt: %v", err)
	} else {
		m.log.Info("live_waf.txt   → %d WAF-protected hosts", len(wafHosts))
	}
	if err := store.SaveRaw(m.outDir+"/live_nowaf.txt", nowafHosts); err != nil {
		m.log.Warn("Failed to save live_nowaf.txt: %v", err)
	} else {
		m.log.Info("live_nowaf.txt → %d non-WAF hosts", len(nowafHosts))
	}
}

// parseHTTPXLine parses a httpx -json output line
// Handles schema differences between httpx versions
func parseHTTPXLine(line string) *store.Host {
        if !strings.Contains(line, "{") {
                return nil
        }

        host := &store.Host{Meta: make(map[string]string)}

        rawURL := firstOf(line, "url", "URL", "input", "Input")
        if rawURL == "" {
                return nil
        }
        host.Meta["url"] = rawURL

        // Clean to hostname
        clean := rawURL
        for _, p := range []string{"https://", "http://"} {
                clean = strings.TrimPrefix(clean, p)
        }
        if idx := strings.IndexAny(clean, "/?#"); idx != -1 {
                clean = clean[:idx]
        }
        if idx := strings.LastIndex(clean, ":"); idx > 0 {
                portStr := clean[idx+1:]
                if p, err := strconv.Atoi(portStr); err == nil {
                        host.Port = p
                        clean = clean[:idx]
                }
        }
        host.Domain = strings.ToLower(strings.TrimSpace(clean))
        if host.Domain == "" {
                return nil
        }

        // Status code — multiple possible field names across versions
        sc := firstOf(line, "status-code", "status_code", "StatusCode", "status")
        host.StatusCode, _ = strconv.Atoi(sc)

        host.Title  = firstOf(line, "title", "Title", "page-title")
        host.Server = firstOf(line, "webserver", "web-server", "server", "Server")
        // Clean IP address
        rawIP := firstOf(line, "a", "ip", "IP")
        rawIP = strings.Trim(rawIP, `[]"' `)
        if idx := strings.Index(rawIP, ","); idx > 0 {
                rawIP = strings.Trim(rawIP[:idx], `[]"' `)
        }
        host.IP = rawIP

        // Content length
        cl := firstOf(line, "content-length", "content_length")
        if cl != "" {
                host.Meta["content-length"] = cl
        }

        // Favicon hash (mmh3 or md5)
        fav := firstOf(line, "favicon", "favicon-hash", "favicon_hash", "favicon_md5", "fav_md5")
        if fav != "" {
                host.Meta["favicon_hash"] = fav
        }

        // Tech stack array
        if idx := strings.Index(line, `"tech":`); idx != -1 {
                rest := line[idx+7:]
                if end := strings.Index(rest, "]"); end != -1 {
                        for _, t := range strings.Split(rest[:end], `"`) {
                                t = strings.Trim(t, `[]," `)
                                if t != "" && t != "null" && t != "," {
                                        host.TechStack = append(host.TechStack, t)
                                }
                        }
                }
        }

        // Technologies (newer httpx field name)
        if idx := strings.Index(line, `"technologies":`); idx != -1 {
                rest := line[idx+15:]
                if end := strings.Index(rest, "]"); end != -1 {
                        for _, t := range strings.Split(rest[:end], `"`) {
                                t = strings.Trim(t, `[]," `)
                                if t != "" && t != "null" {
                                        host.TechStack = append(host.TechStack, t)
                                }
                        }
                }
        }

        tagHost(host)
        return host
}

func tagHost(h *store.Host) {
        switch {
        case h.StatusCode == 403:
                h.Tags = append(h.Tags, "403-bypass-candidate")
        case h.StatusCode == 401:
                h.Tags = append(h.Tags, "auth-required")
        case h.StatusCode >= 500:
                h.Tags = append(h.Tags, "server-error")
        case h.StatusCode == 301 || h.StatusCode == 302:
                h.Tags = append(h.Tags, "redirect")
        case h.StatusCode == 200:
                h.Tags = append(h.Tags, "200-ok")
        }
}

func firstOf(s string, keys ...string) string {
        for _, key := range keys {
                if v := util.JsonStr(s, key); v != "" {
                        return v
                }
        }
        return ""
}

// ── WAF Detection ────────────────────────────────────────────────────────────────────────

// runWAFDetection runs wafw00f against all live hosts to identify WAF presence.
// Results are stored in alive/waf_results.txt and logged with a prominent warning
// if any WAFs are detected — this helps tune threading/rate in later fuzzing phases.
func (m *Module) runWAFDetection(ctx context.Context) {
        tcfg := m.cfg.Tools["wafw00f"]
        path := "wafw00f"
        if tcfg.Path != "" {
                path = tcfg.Path
        }

        if !runner.IsAvailable(path) {
                m.log.ToolSkipped("wafw00f", "not found — install: pip3 install wafw00f")
                return
        }

        aliveFile := m.outDir + "/alive.txt"
        if _, err := os.Stat(aliveFile); os.IsNotExist(err) {
                m.log.Debug("wafw00f: alive.txt not found, skipping")
                return
        }

        outFile := store.DataDir(m.outDir) + "/wafw00f.txt"
        args := []string{"-i", aliveFile, "-o", outFile, "-a"}
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 5 * time.Minute
        }

        m.log.Tool("wafw00f", "detecting WAF on all live hosts")
        m.log.ToolCmd("wafw00f", args, "")
        start := time.Now()

        r := runner.Run(ctx, path, args, runner.WithTimeout(timeout))

        wafCount := 0
        seenWAF := make(map[string]bool)
        for _, line := range r.Lines {
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                // wafw00f output: "The site http://... is behind <WAF> WAF."
                // or:             "No WAF detected"
                lower := strings.ToLower(line)
                detected := !strings.Contains(lower, "no waf") &&
                        !strings.Contains(lower, "generic") &&
                        strings.Contains(lower, "behind")

                if detected {
                        // Extract host and WAF name
                        host := ""
                        waf := "unknown"
                        if idx := strings.Index(line, "http"); idx >= 0 {
                                rest := line[idx:]
                                if end := strings.IndexAny(rest, " )"); end > 0 {
                                        host = rest[:end]
                                }
                        }
                        if idx := strings.Index(lower, "behind "); idx >= 0 {
                                rest := strings.TrimSpace(line[idx+7:])
                                if strings.HasPrefix(strings.ToLower(rest), "a ") {
                                        rest = strings.TrimSpace(rest[2:])
                                } else if strings.HasPrefix(strings.ToLower(rest), "an ") {
                                        rest = strings.TrimSpace(rest[3:])
                                }
                                if end := strings.IndexAny(rest, " .("); end > 0 {
                                        waf = rest[:end]
                                } else {
                                        waf = rest
                                }
                        }
                        host = strings.TrimSpace(stripAnsi(host))
                        waf = strings.TrimSpace(stripAnsi(waf))
                        if host != "" && waf != "" && waf != "a" && waf != "an" {
                                key := host + ":" + waf
                                if !seenWAF[key] {
                                        seenWAF[key] = true
                                        wafCount++
                                        m.store.AddWAFResult(&store.WAFResult{Host: host, WAF: waf, Detected: true})
                                        m.log.Warn("WAF detected: %s — %s", host, waf)
                                }
                        }
                }
        }

        if r.Err != nil && wafCount == 0 {
                m.log.ToolError("wafw00f", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("wafw00f", wafCount, time.Since(start))
                if wafCount > 0 {
                        m.log.Warn("⚠  %d WAF(s) detected — consider reducing thread counts in dir fuzzing & vuln scan", wafCount)
                } else {
                        m.log.Info("wafw00f: no WAFs detected")
                }
        }
}

// ── TLS / Certificate info ─────────────────────────────────────────────────────────────────────

// runTLSX gathers TLS certificate information (SANs, CN) from live HTTPS hosts.
// This is a complementary source to crt.sh — it directly queries the servers
// rather than relying on logged certificates, catching recently-issued certs
// that haven’t propagated to certificate transparency logs yet.
//
// Any new SAN domains found here are added back to store.Subdomains so they
// can be picked up by the alive check in the next run (or in a resume).
func (m *Module) runTLSX(ctx context.Context) {
        tcfg := m.cfg.Tools["tlsx"]
        path := "tlsx"
        if tcfg.Path != "" {
                path = tcfg.Path
        }

        if !runner.IsAvailable(path) {
                m.log.ToolSkipped("tlsx", "not found — install: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")
                return
        }

        aliveFile := m.outDir + "/alive.txt"
        if _, err := os.Stat(aliveFile); os.IsNotExist(err) {
                m.log.Debug("tlsx: alive.txt not found, skipping")
                return
        }

        // tlsx writes output to stdout when no -o flag is given.
        // Previously -o was passed, causing stdout to be empty and LineCallback to receive nothing.
        // Args: note -san and -cn extract the SAN/CN fields; -silent suppresses banners.
        args := []string{"-l", aliveFile, "-san", "-cn", "-silent"}
        // Do NOT append tcfg.Flags here — defaults include -san/-cn/-silent which would duplicate them.

        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 5 * time.Minute
        }

        m.log.Tool("tlsx", "extracting TLS certificate SANs and CNs")
        m.log.ToolCmd("tlsx", args, "")
        start := time.Now()

        newSubs := 0
        r := runner.Run(ctx, path, args,
                runner.WithTimeout(timeout),
                runner.WithLineCallback(func(line string) {
                        line = strings.TrimSpace(line)
                        if line == "" || strings.HasPrefix(line, "#") {
                                return
                        }
                        // tlsx output format: "host:port [san1 san2 ...]"
                        // Extract the bracketed SANs when present, otherwise treat whole line as domain
                        var candidates []string
                        if idx := strings.Index(line, "["); idx >= 0 {
                                inner := line[idx+1:]
                                if end := strings.Index(inner, "]"); end >= 0 {
                                        inner = inner[:end]
                                }
                                candidates = strings.Fields(inner)
                        } else {
                                candidates = []string{line}
                        }
                        for _, d := range candidates {
                                d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "*."))
                                if !strings.Contains(d, ".") {
                                        continue
                                }
                                for _, td := range m.cfg.Target.Domains {
                                        if strings.HasSuffix(d, "."+td) || d == td {
                                                if m.store.AddSubdomainFromSource(d, "tlsx") {
                                                        newSubs++
                                                        m.log.Debug("tlsx: new SAN subdomain: %s", d)
                                                }
                                                break
                                        }
                                }
                        }
                }),
        )

        if r.IsTimeout() {
                m.log.ToolTimeout("tlsx", newSubs, timeout)
        } else if r.Err != nil && newSubs == 0 {
                m.log.ToolError("tlsx", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("tlsx", newSubs, time.Since(start))
                if newSubs > 0 {
                        m.log.Info("tlsx: %d new subdomains from TLS SANs added to scope", newSubs)
                }
        }
}

// runSubjack scans all subdomains for takeover vulnerabilities (dangling DNS records)
func (m *Module) runSubjack(ctx context.Context) {
	if !runner.IsAvailable("subjack") {
		m.log.Debug("subjack not found — skipping subdomain takeover scan")
		return
	}
	subsFile := m.outDir + "/subdomains.txt"
	if _, err := os.Stat(subsFile); os.IsNotExist(err) {
		return
	}
	outFile := m.outDir + "/takeovers.txt"
	args := []string{"-w", subsFile, "-t", "50", "-timeout", "10", "-o", outFile, "-ssl"}
	m.log.Tool("subjack", "checking for subdomain takeovers (dangling CNAMEs)")
	m.log.ToolCmd("subjack", args, "")
	start := time.Now()

	takeoverCount := 0
	r := runner.Run(ctx, "subjack", args,
		runner.WithTimeout(5*time.Minute),
		runner.WithLineCallback(func(line string) {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				return
			}
			takeoverCount++
			m.log.Finding("critical", "Subdomain Takeover: "+line, "subjack")
			m.store.AddFinding(&store.Finding{
				Name:     "Subdomain Takeover (" + line + ")",
				Severity: "critical",
				Target:   line,
				Template: "subjack",
			})
		}),
	)

	if r.Err != nil && takeoverCount == 0 && !util.FileExists(outFile) {
		m.log.Debug("subjack: %s", r.DiagString())
	} else {
		m.log.ToolDone("subjack", takeoverCount, time.Since(start))
		if takeoverCount > 0 {
			m.log.Warn("🚨 subjack found %d POTENTIAL SUBDOMAIN TAKEOVERS!", takeoverCount)
		}
	}
}
