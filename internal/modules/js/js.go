package js

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
	"github.com/unsocialz2/reconx/pkg/util"
)

type Module struct {
	cfg      *config.Config
	store    *store.Store
	log      *logger.Logger
	outDir   string
	activeJS []string
}

func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("JS & Secret Analysis",
		"JS Download → SecretFinder → Gitleaks → TruffleHog Detection")

	// ── Pre-step: Discover active JS files from live web hosts ─────────────
	if m.cfg.ToolAvailable("subjs") {
		var liveURLs []string
		for _, h := range m.store.GetHosts() {
			if u, ok := h.Meta["url"]; ok && u != "" {
				liveURLs = append(liveURLs, u)
			} else {
				liveURLs = append(liveURLs, "https://"+h.Domain)
			}
		}
		sort.Strings(liveURLs)
		if len(liveURLs) > 0 {
			if len(liveURLs) > 100 {
				m.store.AddCoverage("subjs: live host discovery limited to 100 endpoints")
				liveURLs = liveURLs[:100]
			}
			m.runSubjsOnLive(ctx, strings.Join(liveURLs, "\n"))
		}
	}

	start := time.Now()
	jsFiles := prioritizeJS(scope.New(m.cfg).FilterList(m.store.GetJSFiles()), m.activeJS)

	if len(jsFiles) == 0 {
		m.log.Warn("No JS files discovered — check that URL discovery ran and found JS files")
		m.log.Warn("Tip: ensure waybackurls/katana/hakrawler are installed and live hosts exist")
		return nil
	}

	dataDir := store.DataDir(m.outDir)
	m.log.Info("Analyzing %d JavaScript files", len(jsFiles))
	if err := store.SaveRaw(filepath.Join(dataDir, "js_files.txt"), jsFiles); err != nil {
		m.log.Warn("Could not save js_files.txt: %v", err)
	}

	// ── Step 1: Download JS files into data/js_downloads/ ───────────────────
	jsDownloadsDir := filepath.Join(dataDir, "js_downloads")
	urlMap := m.downloadJSFiles(ctx, jsFiles, jsDownloadsDir)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(urlMap) == 0 {
		return fmt.Errorf("js: no JavaScript files downloaded; secret analysis incomplete")
	}

	// Build target URL list for mantra and jsecret:
	// Prioritize the ALIVE/downloaded JS URLs (from urlMap) to avoid hanging on dead 404/403 archives.
	var aliveURLs []string
	seenAlive := make(map[string]bool)
	for _, origURL := range urlMap {
		if origURL != "" && !seenAlive[origURL] {
			seenAlive[origURL] = true
			aliveURLs = append(aliveURLs, origURL)
		}
	}
	urlInput := strings.Join(aliveURLs, "\n")
	sort.Strings(aliveURLs)
	urlInput = strings.Join(aliveURLs, "\n")

	var wg sync.WaitGroup

	// ── Step 2: SecretFinder on downloaded files ────────────────────────────
	if m.cfg.ToolAvailable("secretfinder") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runSecretFinder(ctx, jsDownloadsDir, urlMap)
		}()
	} else {
		m.log.ToolSkipped("secretfinder", "not found — install: pip3 install secretfinder")
	}

	// ── Step 3: Gitleaks on downloaded files ────────────────────────────────
	if m.cfg.ToolAvailable("gitleaks") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runGitleaks(ctx, jsDownloadsDir, urlMap)
		}()
	} else {
		m.log.ToolSkipped("gitleaks", "not found — install: brew install gitleaks")
	}

	// ── Step 4: TruffleHog offline detection on downloaded files ─────────────────
	if m.cfg.ToolAvailable("trufflehog") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runTrufflehog(ctx, jsDownloadsDir, urlMap)
		}()
	} else {
		m.log.ToolSkipped("trufflehog", "not found — install: brew install trufflehog")
	}

	// ── Complementary tools on URLs ─────────────────────────────────────────

	if m.cfg.ToolAvailable("mantra") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runMantra(ctx, urlInput)
		}()
	}
	if m.cfg.ToolAvailable("jsecret") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runJsecret(ctx, urlInput)
		}()
	}

	wg.Wait()

	// GitHub org scan: only runs if both github token and --org are set.
	if m.cfg.Tokens["github"] != "" && m.cfg.Target.OrgName != "" {
		m.log.Info("GitHub org scan enabled (org=%s) — this may take several minutes", m.cfg.Target.OrgName)
		m.runTrufflehogGitHub(ctx)
	}

	// Save secrets.txt so resume mode can pick up where we left off
	if secrets := m.store.Secrets; len(secrets) > 0 {
		lines := make([]string, 0, len(secrets))
		for _, s := range secrets {
			lines = append(lines, fmt.Sprintf("[%s] %s — source=%s file=%s", s.Type, s.Value, s.Source, s.File))
		}
		if err := store.SaveRaw(m.outDir+"/secrets.txt", lines); err != nil {
			m.log.Warn("Could not save secrets.txt: %v", err)
		}
		_ = store.SaveRaw(filepath.Join(dataDir, "secrets_raw.txt"), lines)
	}

	stats := m.store.Stats()
	m.log.PhaseComplete("JS & Secret Analysis", stats["secrets"], time.Since(start))
	return nil
}

// downloadJSFiles downloads JS files in parallel to destDir, capped at 2500 files.
// Returns a map of filename -> original URL.
//
// Timeout matters a lot here: gitleaks/trufflehog/secretfinder can only scan
// what we download. A 5s per-file timeout got 44/300 files on real targets
// (large JS bundles + slow CDNs) — 30s gets the vast majority.
func (m *Module) downloadJSFiles(ctx context.Context, jsFiles []string, destDir string) map[string]string {
	urlMap := make(map[string]string)
	if err := os.MkdirAll(destDir, 0700); err != nil {
		m.store.AddCoverage("js: download directory unavailable")
		return urlMap
	}
	// A retry must not feed stale downloads from the previous selection to scanners.
	entries, err := os.ReadDir(destDir)
	if err != nil {
		m.store.AddCoverage("js: download directory unreadable")
		return urlMap
	}
	for _, entry := range entries {
		if !entry.IsDir() && ((strings.HasPrefix(entry.Name(), "js_") && strings.HasSuffix(entry.Name(), ".js")) || entry.Name() == "url_map.json") {
			if err := os.Remove(filepath.Join(destDir, entry.Name())); err != nil {
				m.store.AddCoverage("js: stale download cleanup failed")
				return urlMap
			}
		}
	}
	var mu sync.Mutex

	limit := len(jsFiles)
	if limit > 2500 {
		limit = 2500
		m.store.AddCoverage("js: downloads limited to 2500 files")
	}

	client := scope.New(m.cfg).Client(30 * time.Second)

	sem := make(chan struct{}, m.cfg.Workers)
	var wg sync.WaitGroup

	m.log.Info("Downloading %d JS files for deep secret inspection...", limit)
	downloaded := 0
	failures := map[string]int{}
	failed := func(reason string) { mu.Lock(); failures[reason]++; mu.Unlock() }

	for i := 0; i < limit; i++ {
		u := strings.TrimSpace(jsFiles[i])
		if strings.HasPrefix(u, "//") {
			u = "https:" + u
		} else if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "https://" + u
		}
		fileName := fmt.Sprintf("js_%d.js", i)
		filePath := filepath.Join(destDir, fileName)

		wg.Add(1)
		go func(targetURL, outPath, fName string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				failed("cancelled")
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
				failed("invalid URL")
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
			// CDNs like CloudFront sometimes reject cross-origin bare fetches
			if req.URL.Host != "" {
				req.Header.Set("Referer", "https://"+req.URL.Host+"/")
			}
			if m.cfg.BugBountyHeader != "" {
				parts := strings.SplitN(m.cfg.BugBountyHeader, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				failed("request error (network, timeout or scope)")
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				failed(fmt.Sprintf("HTTP %d", resp.StatusCode))
				return
			}

			lr := io.LimitReader(resp.Body, 10*1024*1024+1)
			data, err := io.ReadAll(lr)
			if len(data) > 10*1024*1024 {
				failed("larger than 10 MiB")
				return
			}
			if err != nil || len(data) < 10 {
				failed("body read error or empty body")
				return
			}

			prefix := strings.ToLower(strings.TrimSpace(string(data[:min(len(data), 512)])))
			if strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html") {
				failed("HTML response instead of JavaScript")
				return
			}
			if err := os.WriteFile(outPath, data, 0600); err == nil {
				mu.Lock()
				urlMap[fName] = targetURL
				urlMap[filepath.Base(outPath)] = targetURL
				downloaded++
				mu.Unlock()
			} else {
				failed("file write error")
			}
		}(u, filePath, fileName)
	}

	wg.Wait()
	m.log.Info("Downloaded %d/%d JS files to %s/ (gitleaks+trufflehog scan these)", downloaded, limit, destDir)

	if len(failures) > 0 {
		keys := make([]string, 0, len(failures))
		for reason := range failures {
			keys = append(keys, reason)
		}
		sort.Strings(keys)
		var parts []string
		for _, reason := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", reason, failures[reason]))
		}
		summary := fmt.Sprintf("js: downloaded %d/%d; %s", downloaded, limit, strings.Join(parts, "; "))
		m.log.Warn("%s", summary)
		m.store.AddCoverage(summary)
	}

	if mapData, err := json.MarshalIndent(urlMap, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(destDir, "url_map.json"), mapData, 0644)
	}

	return urlMap
}

// runSecretFinder scans downloaded JS files for secrets using SecretFinder.
func (m *Module) runSecretFinder(ctx context.Context, jsDir string, urlMap map[string]string) {
	start := time.Now()
	entries, err := os.ReadDir(jsDir)
	if err != nil || len(entries) == 0 {
		return
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".js") {
			files = append(files, filepath.Join(jsDir, e.Name()))
		}
	}
	if len(files) == 0 {
		return
	}

	m.log.Tool("secretfinder", fmt.Sprintf("%d JS files", len(files)))
	board := m.log.NewProgressBoard()
	board.Register("secretfinder", fmt.Sprintf("%d files", len(files)))

	secretCount := 0
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, fPath := range files {
		fName := filepath.Base(fPath)
		origURL := urlMap[fName]
		if origURL == "" {
			origURL = fName
		}

		wg.Add(1)
		go func(path, targetURL string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			board.Heartbeat("secretfinder")
			args := []string{"-i", path, "-o", "cli"}
			r := runner.Run(ctx, "secretfinder", args, runner.WithTimeout(30*time.Second))
			for _, line := range r.Lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "->") {
					parts := strings.SplitN(line, "->", 2)
					if len(parts) == 2 {
						secType := strings.TrimSpace(parts[0])
						secVal := strings.TrimSpace(parts[1])
						if secVal != "" && secType != "" && isValidSecretValue(secVal) {
							mu.Lock()
							m.store.AddSecret(&store.Secret{
								Type:   secType,
								Value:  util.Truncate(secVal, 200),
								Source: "secretfinder",
								File:   targetURL,
							})
							secretCount++
							m.log.Secret(secType, "secretfinder", util.Truncate(secVal, 60))
							m.log.Info("Candidate secret (%s), needs review: %s", secType, targetURL)
							mu.Unlock()
						}
					}
				}
			}
		}(fPath, origURL)
	}

	wg.Wait()
	board.Done("secretfinder", secretCount)
	board.Stop()
	m.log.ToolDone("secretfinder", secretCount, time.Since(start))
}

// detectTrufflehogV3 returns true if the installed trufflehog is v3+
// (which removed --results=verified in favor of --include-detectors/--exclude-detectors).
func (m *Module) detectTrufflehogV3(ctx context.Context) bool {
	r := runner.Run(ctx, "trufflehog",
		[]string{"--help"}, runner.WithTimeout(5*time.Second))
	for _, line := range r.Lines {
		ll := strings.ToLower(line)
		// v3 prints "include-detectors" / "exclude-detectors"; v2 prints
		// "results=verified" / "results=unknown".
		if strings.Contains(ll, "include-detectors") {
			return true
		}
	}
	for _, line := range r.Stderr {
		ll := strings.ToLower(line)
		if strings.Contains(ll, "include-detectors") {
			return true
		}
	}
	return false
}

// runSubjsOnLive runs subjs against live web hosts to discover active JS files.
func (m *Module) runSubjsOnLive(ctx context.Context, input string) {
	start := time.Now()
	rawLines := strings.Split(strings.TrimSpace(input), "\n")
	count := len(rawLines)
	m.log.Tool("subjs", fmt.Sprintf("%d live hosts — extracting active JS files", count))

	tcfg := m.cfg.Tools["subjs"]
	timeout := 45 * time.Second
	if tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	r := runner.Run(ctx, "subjs", nil,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("subjs[live]: %s", line) }))

	newJS := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") && strings.Contains(strings.ToLower(line), ".js") {
			if scope.New(m.cfg).IsInScope(line) {
				m.activeJS = append(m.activeJS, line)
				if m.store.AddJSFile(line) {
					newJS++
				}
			}
		}
	}
	m.log.ToolDone("subjs", len(r.Lines), time.Since(start))
	if newJS > 0 {
		m.log.Info("subjs: discovered %d active JS files from live hosts", newJS)
	}
}

func (m *Module) runSubjs(ctx context.Context, input string) {
	start := time.Now()
	count := strings.Count(input, "\n") + 1
	m.log.Tool("subjs", fmt.Sprintf("%d JS URLs", count))
	m.log.ToolCmd("subjs", []string{}, fmt.Sprintf("[%d JS URLs via stdin]", count))

	tcfg := m.cfg.Tools["subjs"]
	timeout := time.Duration(tcfg.Timeout) * time.Second

	r := runner.Run(ctx, "subjs", nil,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("subjs: %s", line) }))

	if r.IsTimeout() {
		m.log.ToolTimeout("subjs", len(r.Lines), timeout)
	} else if r.Err != nil && len(r.Lines) == 0 {
		m.log.ToolError("subjs", fmt.Errorf("%s", r.DiagString()), r.Stderr)
		return
	}

	newJS := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") && strings.Contains(strings.ToLower(line), ".js") {
			if scope.New(m.cfg).IsInScope(line) && m.store.AddJSFile(line) {
				newJS++
			}
		}
	}
	m.log.ToolDone("subjs", len(r.Lines), time.Since(start))
	if newJS > 0 {
		m.log.Info("subjs: discovered %d additional JS files (added to analysis queue)", newJS)
	}
}

func (m *Module) runMantra(ctx context.Context, input string) {
	start := time.Now()
	rawLines := strings.Split(strings.TrimSpace(input), "\n")
	count := len(rawLines)
	m.log.Tool("mantra", fmt.Sprintf("%d JS files — pattern matching", count))
	m.log.ToolCmd("mantra", []string{"-s", "-t", "50"}, fmt.Sprintf("[%d URLs via stdin]", count))

	secretCount := 0
	extractFileAndValue := func(line string) (string, string) {
		line = strings.TrimSpace(util.StripANSI(line))
		file := ""
		val := line
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.HasPrefix(f, "http") {
				file = f
				break
			}
		}
		if file != "" {
			val = strings.Replace(line, file, "", 1)
			val = strings.TrimSpace(strings.ReplaceAll(val, "[+]", ""))
			val = strings.TrimSpace(strings.TrimPrefix(val, "+"))
		}
		return file, val
	}

	tcfg := m.cfg.Tools["mantra"]
	timeout := 5 * time.Minute
	if tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	r := runner.Run(ctx, "mantra", []string{"-s", "-t", "50"},
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("mantra: %s", line) }),
		runner.WithLineCallback(func(line string) {
			line = util.StripANSI(line)
			if !isSecretLine(line) {
				return
			}
			file, val := extractFileAndValue(line)
			val = strings.TrimSpace(util.StripANSI(val))
			if !isValidSecretValue(val) {
				return
			}
			t := classifySecret(line)
			m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(val, 200), Source: "mantra", File: file})
			secretCount++
			m.log.Secret(t, "mantra", util.Truncate(val, 80))
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("mantra", secretCount, timeout)
	} else if r.Err != nil {
		m.log.ToolError("mantra", fmt.Errorf("%s", r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("mantra", secretCount, time.Since(start))
		m.log.Debug("mantra: scanned %d lines total, %d matched secret patterns", len(r.Lines), secretCount)
	}
}

func (m *Module) runJsecret(ctx context.Context, input string) {
	start := time.Now()
	count := strings.Count(input, "\n") + 1
	m.log.Tool("jsecret", fmt.Sprintf("%d JS files", count))
	m.log.ToolCmd("jsecret", []string{}, fmt.Sprintf("[%d URLs via stdin]", count))

	secretCount := 0
	extractFileAndValue := func(line string) (string, string) {
		line = strings.TrimSpace(util.StripANSI(line))
		file := ""
		val := line
		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.HasPrefix(f, "http") {
				file = f
				break
			}
		}
		if file != "" {
			val = strings.Replace(line, file, "", 1)
			val = strings.TrimSpace(strings.ReplaceAll(val, "[+]", ""))
		}
		return file, val
	}

	tcfg := m.cfg.Tools["jsecret"]
	timeout := 5 * time.Minute
	if tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	r := runner.Run(ctx, "jsecret", nil,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("jsecret: %s", line) }),
		runner.WithLineCallback(func(line string) {
			line = util.StripANSI(line)
			if !isSecretLine(line) {
				return
			}
			file, val := extractFileAndValue(line)
			val = strings.TrimSpace(util.StripANSI(val))
			if !isValidSecretValue(val) {
				return
			}
			t := classifySecret(line)
			m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(val, 200), Source: "jsecret", File: file})
			secretCount++
			m.log.Secret(t, "jsecret", util.Truncate(val, 80))
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("jsecret", secretCount, timeout)
	} else if r.Err != nil {
		m.log.ToolError("jsecret", fmt.Errorf("%s", r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("jsecret", secretCount, time.Since(start))
	}
}

func (m *Module) runTrufflehog(ctx context.Context, jsDir string, urlMap map[string]string) {
	tcfg := m.cfg.Tools["trufflehog"]
	start := time.Now()

	isV3 := m.detectTrufflehogV3(ctx)
	var args []string
	if isV3 {
		args = []string{"filesystem", jsDir, "--json", "--no-verification", "--no-update"}
	} else {
		args = []string{"filesystem", jsDir, "--json", "--no-verification", "--no-update"}
	}

	timeout := 10 * time.Minute
	if tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	m.log.Tool("trufflehog", "detecting candidate secrets offline")
	m.log.ToolCmd("trufflehog", args, "")

	secretCount := 0
	r := runner.Run(ctx, tcfg.Path, args,
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("trufflehog: %s", line) }),
		runner.WithLineCallback(func(line string) {
			if !strings.HasPrefix(strings.TrimSpace(line), "{") {
				return
			}
			sec := parseTrufflehogCandidate(line, urlMap)
			if sec != nil && m.store.AddSecret(sec) {
				secretCount++
				m.log.Secret(sec.Type, "trufflehog (candidate)", "")
			}
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("trufflehog", secretCount, timeout)
	} else if r.Err != nil && secretCount == 0 {
		m.log.ToolError("trufflehog", fmt.Errorf("%s", r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("trufflehog", secretCount, time.Since(start))
		m.log.Debug("trufflehog: processed %d scan lines, %d candidate secrets", len(r.Lines), secretCount)
	}
}

func (m *Module) runTrufflehogGitHub(ctx context.Context) {
	if !m.cfg.ToolAvailable("trufflehog") {
		return
	}
	start := time.Now()
	org := m.cfg.Target.OrgName
	token := m.cfg.Tokens["github"]
	isV3 := m.detectTrufflehogV3(ctx)
	var args []string
	if isV3 {
		args = []string{"github", "--org=" + org, "--no-verification", "--token=" + token, "--json", "--no-update"}
	} else {
		args = []string{"github", "--org=" + org, "--no-verification", "--token=" + token, "--json", "--no-update"}
	}
	m.log.Tool("trufflehog-github", org)
	m.log.ToolCmd("trufflehog", []string{"github", "--org=" + org, "--no-verification", "--token=***", "--json", "--no-update"}, "")

	secretCount := 0
	r := runner.Run(ctx, "trufflehog", args,
		runner.WithEnv([]string{"GITHUB_TOKEN=" + token}),
		runner.WithTimeout(10*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("trufflehog-github: %s", line) }),
		runner.WithLineCallback(func(line string) {
			if !strings.HasPrefix(strings.TrimSpace(line), "{") {
				return
			}
			t := util.JsonStr(line, "DetectorName")
			if t == "" {
				t = "github-secret"
			}
			m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(line, 200), Source: "trufflehog-github"})
			secretCount++
			m.log.Secret(t, "trufflehog-github", org)
			m.log.Finding("info", "Candidate GitHub Secret: "+t, org)
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("trufflehog-github", secretCount, 10*time.Minute)
	} else if r.Err != nil && secretCount == 0 {
		m.log.ToolError("trufflehog-github", fmt.Errorf("%s", r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("trufflehog-github", secretCount, time.Since(start))
	}
}

func (m *Module) runGitleaks(ctx context.Context, jsDir string, urlMap map[string]string) {
	start := time.Now()
	reportFile := filepath.Join(store.DataDir(m.outDir), "gitleaks_report.json")
	if err := os.Remove(reportFile); err != nil && !os.IsNotExist(err) {
		m.log.ToolError("gitleaks", err, nil)
		return
	}
	args := []string{"detect", "--no-git", "--source", jsDir, "--report-format", "json", "--report-path", reportFile}
	m.log.Tool("gitleaks", "scanning downloaded JS files")
	m.log.ToolCmd("gitleaks", args, "")

	secretCount := 0
	r := runner.Run(ctx, "gitleaks", args,
		runner.WithTimeout(10*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("gitleaks: %s", line) }),
	)

	if data, err := os.ReadFile(reportFile); err == nil && len(data) > 2 {
		var findings []struct {
			Description string `json:"Description"`
			Secret      string `json:"Secret"`
			File        string `json:"File"`
			RuleID      string `json:"RuleID"`
		}
		if err := json.Unmarshal(data, &findings); err == nil {
			for _, f := range findings {
				cleanSecret := strings.TrimSpace(util.StripANSI(f.Secret))
				if !isValidSecretValue(cleanSecret) {
					continue
				}
				secType := f.Description
				if secType == "" {
					secType = f.RuleID
				}
				if secType == "" {
					secType = "Potential Secret"
				}
				origFile := filepath.Base(f.File)
				if u, ok := urlMap[origFile]; ok {
					origFile = u
				}
				if m.store.AddSecret(&store.Secret{
					Type:   secType + " (candidate)",
					Value:  cleanSecret,
					Source: "gitleaks",
					File:   origFile,
				}) {
					secretCount++
					m.log.Secret(secType, "gitleaks", util.Truncate(cleanSecret, 60))
					m.log.Info("Candidate secret (%s), needs review: %s", secType, origFile)
				}
			}
		}
	}

	if r.IsTimeout() {
		m.log.ToolTimeout("gitleaks", secretCount, 10*time.Minute)
	} else if r.Err != nil && r.ExitCode != 1 {
		m.log.ToolError("gitleaks", fmt.Errorf("%s", r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("gitleaks", secretCount, time.Since(start))
	}
}

func classifySecret(line string) string {
	ll := strings.ToLower(line)
	switch {
	case strings.Contains(ll, "aiza"):
		return "Google API Key"
	case strings.Contains(ll, "akia") || strings.Contains(ll, "aws_access"):
		return "AWS Access Key"
	case strings.Contains(ll, "aws_secret"):
		return "AWS Secret Key"
	case strings.Contains(ll, "ghp_") || strings.Contains(ll, "github_pat_"):
		return "GitHub Token"
	case strings.Contains(ll, "eyj"):
		return "JWT Token"
	case strings.Contains(ll, "xoxb-") || strings.Contains(ll, "xoxp-") || strings.Contains(ll, "xoxa-"):
		return "Slack Token"
	case strings.Contains(ll, "sk_live_"):
		return "Stripe Secret Key"
	case strings.Contains(ll, "-----begin"):
		return "Private Key"
	case strings.Contains(ll, "bearer "):
		return "Bearer Token"
	case strings.Contains(ll, "securitytoken="):
		return "Auth Token"
	case strings.Contains(ll, "api_key") || strings.Contains(ll, "apikey"):
		return "API Key"
	case strings.Contains(ll, "password") || strings.Contains(ll, "passwd"):
		return "Password"
	case strings.Contains(ll, "token"):
		return "Auth Token"
	default:
		return "Potential Secret"
	}
}

func isSecretLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}

	// 1. Filter out error/status messages from tools (mantra, jsecret, etc.)
	if strings.HasPrefix(line, "[-]") ||
		strings.HasPrefix(line, "[!]") ||
		strings.Contains(line, "Unable to make a request") ||
		strings.Contains(line, "Unable to read the body") ||
		strings.Contains(line, "Regex Error") ||
		strings.Contains(line, "error:") ||
		strings.Contains(line, "failed to") ||
		strings.Contains(line, "Usage:") {
		return false
	}

	// 2. Filter out generic JS code patterns (function declarations, method definitions)
	ll := strings.ToLower(line)
	if strings.Contains(ll, ":function") ||
		strings.Contains(ll, "=function") ||
		strings.Contains(ll, ": function") ||
		strings.Contains(ll, "= function") ||
		strings.Contains(ll, "function(") ||
		strings.Contains(ll, "=>") {
		return false
	}

	// 3. Filter out UI / Framework schema dictionary keys (huge false positive source)
	if strings.Contains(ll, "key:\"") ||
		strings.Contains(ll, "key='") ||
		strings.Contains(ll, "key=\"") ||
		strings.Contains(ll, "datakey:") ||
		strings.Contains(ll, "titlekey:") ||
		strings.Contains(ll, "arialabelkey:") ||
		strings.Contains(ll, "mozprintablekey:") ||
		strings.Contains(ll, "selectednavitemkey") ||
		strings.Contains(ll, "ruleskey:") ||
		strings.Contains(ll, "i18nkey:") ||
		strings.Contains(ll, "ref_key:") ||
		strings.Contains(ll, "action:") ||
		strings.Contains(ll, "displaykey:") {
		return false
	}

	// 4. Filter out dummy / boilerplate matches
	if strings.Contains(ll, "https://a@") ||
		strings.Contains(ll, "password=\"password\"") ||
		strings.Contains(ll, "password:\"wrongpassword\"") ||
		strings.Contains(ll, "password=secure_string") ||
		strings.Contains(ll, "email:function") ||
		strings.Contains(ll, "email:\"account@mail") ||
		strings.Contains(ll, "email:\"test@example") ||
		strings.Contains(ll, "email:\"teste@") {
		return false
	}

	// 5. Must contain a meaningful secret keyword or high-confidence signature
	for _, kw := range []string{
		"aiza", "akia", "ghp_", "sk_live_", "-----begin", "securitytoken=",
		"api_key", "apikey", "api-key", "token", "secret", "bearer ",
		"password", "passwd", "auth_token", "access_token",
	} {
		if strings.Contains(ll, kw) {
			return true
		}
	}
	return false
}

// isValidSecretValue filters out minified JS identifiers, dummy tokens, error
// messages, and config keys that regularly cause false positives in mantra,
// jsecret, and gitleaks.
func isValidSecretValue(val string) bool {
	val = strings.TrimSpace(util.StripANSI(val))
	if val == "" {
		return false
	}
	// Strip enclosing brackets and quotes
	val = strings.Trim(val, "[](){}\"'` ")

	// If it's an assignment/pair (e.g. "authToken = null" or "apiKey: e"), extract the right-hand side
	for _, sep := range []string{"=>", "==", "=", ":"} {
		if idx := strings.Index(val, sep); idx != -1 {
			rhs := strings.TrimSpace(val[idx+len(sep):])
			if rhs != "" {
				val = strings.Trim(rhs, "[](){}\"'` ")
				break
			}
		}
	}

	ll := strings.ToLower(val)

	// 1. Minified variables or very short tokens (e.g. e, n, t, a, nB, null)
	if len(val) < 6 {
		return false
	}

	// 2. Reject common JavaScript primitives, keywords, and config placeholders
	falsePrimitives := []string{
		"null", "undefined", "true", "false", "void 0", "none", "nil",
		"config", "options", "headers", "params", "props", "state", "response",
		"request", "data", "default", "window", "document", "this", "self",
		"function", "return", "typeof", "instanceof", "object", "string",
		"dummy", "placeholder", "example", "test", "sample", "your-api-key",
		"api_key_here", "secret_here", "token_here", "xxxx", "0000",
		"rundoublec25k", "production", "development", "staging", "localhost", "127.0.0.1", "0.0.0.0",
	}
	for _, p := range falsePrimitives {
		if ll == p {
			return false
		}
	}

	// 3. Reject JS library error messages, throw statements, assertions
	if strings.Contains(ll, "throw ") ||
		strings.Contains(ll, "typeerror") ||
		strings.Contains(ll, "new error") ||
		strings.Contains(ll, "error(") ||
		strings.Contains(ll, "console.") ||
		strings.Contains(ll, "assert(") {
		return false
	}

	// 4. Reject dummy repeated character secrets (e.g. AIDAAAAAAAAAAAAAAAAA)
	if isDummyRepeatedSecret(val) {
		return false
	}

	// 5. Reject JS object property accesses (e.g. this.token, config.apikey, process.env.KEY)
	if strings.HasPrefix(ll, "this.") || strings.HasPrefix(ll, "config.") || strings.HasPrefix(ll, "options.") ||
		strings.HasPrefix(ll, "req.") || strings.HasPrefix(ll, "res.") || strings.HasPrefix(ll, "process.env") {
		return false
	}

	return true
}

func isDummyRepeatedSecret(s string) bool {
	if len(s) < 8 {
		return false
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	for _, count := range counts {
		if float64(count)/float64(len(s)) > 0.65 {
			return true
		}
	}
	sUpper := strings.ToUpper(s)
	if strings.Contains(sUpper, "AKIAIOSFODNN7EXAMPLE") ||
		strings.Contains(sUpper, "WJALRXUTNFEMIK7MDENG") ||
		strings.Contains(sUpper, "EXAMPLE") {
		return true
	}
	return false
}

// prioritizeJS keeps active discoveries first, strips fragments and deduplicates
// before applying the download cap. Query strings are preserved for signed URLs.
func prioritizeJS(all, active []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(all))
	appendSorted := func(items []string) {
		items = append([]string(nil), items...)
		sort.Strings(items)
		for _, raw := range items {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			u.Fragment = ""
			normalized := u.String()
			if normalized != "" && !seen[normalized] {
				seen[normalized] = true
				out = append(out, normalized)
			}
		}
	}
	appendSorted(active)
	appendSorted(all)
	return out
}

func parseTrufflehogCandidate(line string, urlMap map[string]string) *store.Secret {
	var item struct {
		DetectorName   string
		Raw            string
		File           string
		SourceMetadata struct {
			Data struct {
				Filesystem struct {
					File string `json:"file"`
				}
			}
		}
	}
	if json.Unmarshal([]byte(line), &item) != nil || strings.TrimSpace(item.Raw) == "" {
		return nil
	}
	sourceFile := item.SourceMetadata.Data.Filesystem.File
	if sourceFile == "" {
		sourceFile = item.File
	}
	if u, ok := urlMap[filepath.Base(sourceFile)]; ok {
		sourceFile = u
	}
	if item.DetectorName == "" {
		item.DetectorName = "unknown"
	}
	return &store.Secret{Type: item.DetectorName + " (candidate)", Value: item.Raw, Source: "trufflehog", File: sourceFile}
}
