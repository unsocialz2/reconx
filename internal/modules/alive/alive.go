package alive

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/unsocialz2/reconx/internal/scope"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
	"github.com/unsocialz2/reconx/pkg/util"
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

	subs := scope.New(m.cfg).FilterList(m.store.GetSubdomains())
	if len(subs) == 0 && m.cfg.SelectsSource("httpx") {
		// If subdomain enum was skipped (single target mode / --skip-subs), use Target.Domains
		if len(m.cfg.Target.Domains) > 0 {
			subs = scope.New(m.cfg).FilterList(m.cfg.Target.Domains)
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
	if !m.cfg.SelectsSource("httpx") {
		err = m.saveAlive()
	} else if !m.cfg.ToolAvailable(httpxPath) {
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
	var wafErr error
	if m.cfg.SelectsSource("wafw00f") {
		wafErr = m.runWAFDetection(ctx)
	}
	m.saveAliveWAFSplit() // write live_waf.txt / live_nowaf.txt

	// ── TLS / Certificate info ─────────────────────────────────────────────
	// SANs from TLS certs often reveal subdomains not found by passive tools.
	// Any new SANs discovered here are added back to the subdomain store.
	if len(m.cfg.RetrySources) == 0 {
		m.runTLSX(ctx)
	}

	// ── Subdomain Takeover Check (subjack) ──────────────────────────────────
	// Checks all discovered subdomains for dangling CNAMEs (AWS S3, GitHub Pages, Heroku, etc.)
	if len(m.cfg.RetrySources) == 0 {
		m.runSubjack(ctx)
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(err, wafErr)
}

func (m *Module) runHttpx(ctx context.Context, subs []string, path string, tcfg config.ToolConfig) error {
	input := strings.Join(subs, "\n")
	start := time.Now()

	// Minimal safe flag set that works across httpx versions
	args := []string{
		"-silent",
		"-json",
		"-nf",
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

	budget := m.cfg.SourceBudget("httpx", len(subs), time.Hour)
	ctx = runner.WithProcessObserver(ctx, func(pid int, alive bool) { board.Process("httpx", pid, alive) })
	r := runner.RunInputBatches(ctx, path, args, input, 32, budget, "",
		runner.WithUniqueLines(),
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
			if !scope.New(m.cfg).IsInScope(host.Meta["url"]) {
				return
			}
			m.store.AddHost(host)
			mu.Lock()
			if host.IsLive() {
				liveCount++
			}
			mu.Unlock()
			board.Update("httpx", liveCount)
			m.logHTTPObservation(host)
		}),
	)

	elapsed := time.Since(start)

	if r.IsTimeout() {
		board.Timeout("httpx", liveCount)
		if r.TimeoutKind == "source-budget" {
			m.log.Warn("%s — elapsed=%s, live results=%d", r.DiagString(), r.Duration.Round(time.Second), liveCount)
		} else {
			m.log.ToolTimeout("httpx", liveCount, time.Duration(tcfg.Timeout)*time.Second)
		}
	} else if r.Err != nil && len(m.store.GetHosts()) == 0 {
		// httpx exits non-zero when 0 hosts respond — check stderr for real errors
		m.log.ToolError("httpx", fmt.Errorf("%s", r.DiagString()), r.Stderr)
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
// runCurlFallback is retained as the fallback entry point; probes use a scoped Go client.
func (m *Module) runCurlFallback(ctx context.Context, subs []string) error {
	var endpoints []string
	for _, sub := range subs {
		for _, scheme := range []string{"https", "http"} {
			endpoints = append(endpoints, scheme+"://"+sub)
		}
	}
	return m.probeEndpoints(ctx, endpoints)
}
func (m *Module) probeEndpoints(ctx context.Context, endpoints []string) error {
	filter := scope.New(m.cfg)
	client := filter.Client(10 * time.Second)
	// A live redirect is evidence about the original endpoint, not permission to probe its destination.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	workers := m.cfg.Workers
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, raw := range endpoints {
		if !filter.IsInScope(raw) {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "ReconX/1.1")
			if parts := strings.SplitN(m.cfg.BugBountyHeader, ":", 2); len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			u, _ := url.Parse(raw)
			port, _ := strconv.Atoi(u.Port())
			h := &store.Host{Domain: u.Hostname(), Port: port, StatusCode: resp.StatusCode, Server: resp.Header.Get("Server"), Meta: map[string]string{"url": raw}}
			tagHost(h)
			m.store.AddHost(h)
			m.logHTTPObservation(h)
		}(raw)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return m.saveAlive()
}

// ProbePorts closes the port-discovery feedback loop without overwriting existing endpoints.
func (m *Module) ProbePorts(ctx context.Context) error {
	var endpoints []string
	for _, p := range m.store.Snapshot().Ports {
		host := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
		switch p.Port {
		case 80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090:
			for _, scheme := range []string{"https", "http"} {
				endpoints = append(endpoints, scheme+"://"+host)
			}
		}
	}
	return m.probeEndpoints(ctx, endpoints)
}

func (m *Module) saveAlive() error {
	hosts := m.store.GetHosts()
	lines := make([]string, 0, len(hosts))
	var observed, unavailable, limited []string
	for _, h := range hosts {
		raw := h.Meta["url"]
		if raw == "" {
			raw = "https://" + h.Domain
		}
		observed = append(observed, raw)
		if h.IsLive() {
			lines = append(lines, raw)
		}
		if store.HTTPState(h.StatusCode) == "unavailable" {
			unavailable = append(unavailable, raw)
		}
		if h.StatusCode == 429 {
			limited = append(limited, raw)
		}
	}
	for name, values := range map[string][]string{"http_responded.txt": observed, "http_unavailable.txt": unavailable, "http_rate_limited.txt": limited} {
		if err := store.SaveRaw(m.outDir+"/"+name, values); err != nil {
			return err
		}
	}
	if err := store.SaveRaw(m.outDir+"/alive.txt", lines); err != nil {
		m.log.Warn("Failed to save alive.txt: %v", err)
		return err
	}
	m.log.Debug("Saved alive.txt (%d entries)", len(lines))
	m.log.Info("HTTP observations: %d | live seeds: %d | unavailable (5xx): %d | rate limited (429): %d", len(observed), len(lines), len(unavailable), len(limited))
	return nil
}

func (m *Module) logHTTPObservation(h *store.Host) {
	if h.IsLive() {
		m.log.LiveHost(h.Domain, h.StatusCode, h.Title, h.Server)
	} else {
		m.log.Debug("HTTP observed: %s [%d] %s — excluded from live seeds", h.Domain, h.StatusCode, store.HTTPState(h.StatusCode))
	}
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

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	if parsedURL.Host == "" {
		parsedURL, err = url.Parse("https://" + rawURL)
		if err != nil {
			return nil
		}
	}
	host.Domain = strings.ToLower(parsedURL.Hostname())
	host.Port, _ = strconv.Atoi(parsedURL.Port())
	host.Meta["url"] = parsedURL.String()
	if host.Domain == "" {
		return nil
	}

	// Status code — multiple possible field names across versions
	sc := firstOf(line, "status-code", "status_code", "StatusCode", "status")
	host.StatusCode, _ = strconv.Atoi(sc)

	host.Title = firstOf(line, "title", "Title", "page-title")
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
func (m *Module) runWAFDetection(ctx context.Context) error {
	tcfg := m.cfg.Tools["wafw00f"]
	path := "wafw00f"
	if tcfg.Path != "" {
		path = tcfg.Path
	}

	if !m.cfg.ToolAvailable(path) {
		m.log.ToolSkipped("wafw00f", "not found — install: pip3 install wafw00f")
		return nil
	}

	aliveFile := m.outDir + "/alive.txt"
	if _, err := os.Stat(aliveFile); os.IsNotExist(err) {
		m.log.Debug("wafw00f: alive.txt not found, skipping")
		return nil
	}

	timeout := time.Duration(tcfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	start := time.Now()
	hosts := m.store.GetHosts()
	budget := m.cfg.SourceBudget("wafw00f", len(hosts), 30*time.Minute)
	runCtx, cancel := context.WithTimeoutCause(ctx, budget, runner.ErrSourceBudget)
	defer cancel()
	sem := make(chan struct{}, max(1, m.cfg.Workers))
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	checked := 0
schedule:
	for _, h := range hosts {
		target := h.Meta["url"]
		if target == "" {
			target = "https://" + h.Domain
		}
		key := fmt.Sprintf("%x", sha256.Sum256([]byte(target)))
		pendingFile := filepath.Join(store.DataDir(m.outDir), "waf-"+key+".json.pending")
		_, pendingErr := os.Stat(pendingFile)
		if _, known := m.store.WAFStatus(target); known && !runner.IsRefresh(ctx) && os.IsNotExist(pendingErr) {
			runner.RecordTask(ctx, "wafw00f", "reused", 1)
			mu.Lock()
			checked++
			mu.Unlock()
			continue
		}
		if runCtx.Err() != nil {
			runner.RecordTask(ctx, "wafw00f", "pending", 1)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-runCtx.Done():
			runner.RecordTask(ctx, "wafw00f", "pending", 1)
			continue schedule
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			key := fmt.Sprintf("%x", sha256.Sum256([]byte(target)))
			outFile := filepath.Join(store.DataDir(m.outDir), "waf-"+key+".json")
			doneFile := outFile + ".done"
			pendingFile := outFile + ".pending"
			_, pendingErr := os.Stat(pendingFile)
			var results []*store.WAFResult
			if _, err := os.Stat(doneFile); err == nil && !runner.IsRefresh(ctx) && os.IsNotExist(pendingErr) {
				if data, err := os.ReadFile(outFile); err == nil {
					results, _ = parseWAFJSON(data)
				}
			}
			if len(results) > 0 {
				runner.RecordTask(ctx, "wafw00f", "reused", 1)
			}
			if len(results) == 0 {
				// One host per job prevents one slow target consuming the whole list's timeout.
				if err := os.WriteFile(pendingFile, []byte("retry pending"), 0600); err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
					runner.RecordTask(ctx, "wafw00f", "partial", 1)
					return
				}
				_ = os.Remove(doneFile)
				if err := os.Remove(outFile); err != nil && !os.IsNotExist(err) {
					mu.Lock()
					failed++
					mu.Unlock()
					runner.RecordTask(ctx, "wafw00f", "partial", 1)
					return
				}
				perHost := min(timeout, 45*time.Second)
				taskCtx, stop := context.WithTimeout(runCtx, perHost)
				r := runner.Run(taskCtx, path, []string{"-i", writeWAFTarget(outFile, target), "-o", outFile, "-a"}, runner.WithTimeout(perHost))
				stop()
				if data, err := os.ReadFile(outFile); err == nil {
					results, _ = parseWAFJSON(data)
				}
				state := "completed"
				if r.Err != nil || len(results) == 0 {
					state = "partial"
				}
				runner.RecordTask(ctx, "wafw00f", state, 1)
				if r.Err != nil || len(results) == 0 {
					mu.Lock()
					failed++
					mu.Unlock()
				} else {
					if err := os.WriteFile(doneFile, []byte("completed"), 0600); err == nil {
						_ = os.Remove(pendingFile)
					}
				}
			}
			for _, result := range results {
				if scope.New(m.cfg).IsInScope(result.Host) {
					m.store.AddWAFResult(result)
				}
			}
			mu.Lock()
			checked++
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	if failed > 0 || checked < len(hosts) {
		reason := fmt.Sprintf("wafw00f: partial — %d/%d hosts processed; %d failed; unknown statuses preserved", checked, len(hosts), failed)
		m.store.AddCoverage(reason)
		m.log.Warn("%s", reason)
		return errors.New(reason)
	} else {
		m.log.ToolDone("wafw00f", checked, time.Since(start))
	}

	return nil
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

	if !m.cfg.ToolAvailable(path) {
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
				if !scope.New(m.cfg).IsInScope(d) {
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
		m.log.ToolError("tlsx", fmt.Errorf("%s", r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("tlsx", newSubs, time.Since(start))
		if newSubs > 0 {
			m.log.Info("tlsx: %d new subdomains from TLS SANs added to scope", newSubs)
		}
	}
}

// runSubjack scans all subdomains for takeover vulnerabilities (dangling DNS records)
func (m *Module) runSubjack(ctx context.Context) {
	if !m.cfg.ToolAvailable("subjack") {
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

// parseWAFJSON preserves both positive and explicit negative detections.
func parseWAFJSON(data []byte) ([]*store.WAFResult, error) {
	var records []struct {
		URL      string `json:"url"`
		Firewall string `json:"firewall"`
		Detected *bool  `json:"detected"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	var out []*store.WAFResult
	seen := map[string]bool{}
	for _, record := range records {
		if record.URL == "" || record.Detected == nil {
			continue
		}
		key := record.URL + ":" + record.Firewall
		if !seen[key] {
			seen[key] = true
			out = append(out, &store.WAFResult{Host: record.URL, WAF: record.Firewall, Detected: *record.Detected})
		}
	}
	return out, nil
}

func writeWAFTarget(outFile, target string) string {
	path := outFile + ".input"
	_ = os.WriteFile(path, []byte(target+"\n"), 0600)
	return path
}
