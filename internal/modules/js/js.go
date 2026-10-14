package js

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/store"
	"github.com/reconx/reconx/pkg/logger"
	"github.com/reconx/reconx/pkg/runner"
	"github.com/reconx/reconx/pkg/util"
)

type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("JS & Secret Analysis",
		"JS Download → SecretFinder → Gitleaks → TruffleHog Verification")

	// ── Pre-step: Discover active JS files from live web hosts ─────────────
	if runner.IsAvailable("subjs") {
		var liveURLs []string
		for _, h := range m.store.GetHosts() {
			if u, ok := h.Meta["url"]; ok && u != "" {
				liveURLs = append(liveURLs, u)
			} else {
				liveURLs = append(liveURLs, "https://"+h.Domain)
			}
		}
		if len(liveURLs) > 0 {
			if len(liveURLs) > 100 {
				liveURLs = liveURLs[:100]
			}
			m.runSubjsOnLive(ctx, strings.Join(liveURLs, "\n"))
		}
	}

	start := time.Now()
	jsFiles := m.store.GetJSFiles()

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
	if len(aliveURLs) == 0 {
		urlInput = strings.Join(jsFiles, "\n")
	}

	input := strings.Join(jsFiles, "\n")
	var wg sync.WaitGroup

	// ── Step 2: SecretFinder on downloaded files ────────────────────────────
	if runner.IsAvailable("secretfinder") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runSecretFinder(ctx, jsDownloadsDir, urlMap)
		}()
	} else {
		m.log.ToolSkipped("secretfinder", "not found — install: pip3 install secretfinder")
	}

	// ── Step 3: Gitleaks on downloaded files ────────────────────────────────
	if runner.IsAvailable("gitleaks") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runGitleaks(ctx, jsDownloadsDir, urlMap)
		}()
	} else {
		m.log.ToolSkipped("gitleaks", "not found — install: brew install gitleaks")
	}

	// ── Step 4: TruffleHog verification on downloaded files ─────────────────
	if runner.IsAvailable("trufflehog") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runTrufflehog(ctx, jsDownloadsDir, urlMap)
		}()
	} else {
		m.log.ToolSkipped("trufflehog", "not found — install: brew install trufflehog")
	}

	// ── Complementary tools on URLs ─────────────────────────────────────────
	if runner.IsAvailable("subjs") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runSubjs(ctx, input)
		}()
	}
	if runner.IsAvailable("mantra") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runMantra(ctx, urlInput)
		}()
	}
	if runner.IsAvailable("jsecret") {
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

// downloadJSFiles downloads JS files in parallel to destDir, capped at 1000 files.
// Returns a map of filename -> original URL.
//
// Timeout matters a lot here: gitleaks/trufflehog/secretfinder can only scan
// what we download. A 5s per-file timeout got 44/300 files on real targets
// (large JS bundles + slow CDNs) — 30s gets the vast majority.
func (m *Module) downloadJSFiles(ctx context.Context, jsFiles []string, destDir string) map[string]string {
	_ = os.MkdirAll(destDir, 0755)
	urlMap := make(map[string]string)
	var mu sync.Mutex

	limit := len(jsFiles)
	if limit > 2500 {
		limit = 2500
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	sem := make(chan struct{}, 40)
	var wg sync.WaitGroup

	m.log.Info("Downloading %d JS files for deep secret inspection...", limit)
	downloaded := 0

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
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
			if err != nil {
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
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return
			}

			lr := io.LimitReader(resp.Body, 10*1024*1024)
			data, err := io.ReadAll(lr)
			if err != nil || len(data) < 10 {
				return
			}

			if err := os.WriteFile(outPath, data, 0644); err == nil {
				mu.Lock()
				urlMap[fName] = targetURL
				urlMap[filepath.Base(outPath)] = targetURL
				downloaded++
				mu.Unlock()
			}
		}(u, filePath, fileName)
	}

	wg.Wait()
	m.log.Info("Downloaded %d/%d JS files to %s/ (gitleaks+trufflehog scan these)", downloaded, limit, destDir)

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
							m.log.Finding("high", "Secret ("+secType+")", targetURL)
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
func (m *Module) detectTrufflehogV3() bool {
	r := runner.Run(context.Background(), "trufflehog",
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
			if m.store.AddJSFile(line) {
				newJS++
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
                m.log.ToolError("subjs", fmt.Errorf(r.DiagString()), r.Stderr)
                return
        }

        newJS := 0
        for _, line := range r.Lines {
                line = strings.TrimSpace(line)
                if strings.HasPrefix(line, "http") && strings.Contains(strings.ToLower(line), ".js") {
                        if m.store.AddJSFile(line) {
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
		m.log.ToolError("mantra", fmt.Errorf(r.DiagString()), r.Stderr)
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
                m.log.ToolError("jsecret", fmt.Errorf(r.DiagString()), r.Stderr)
        } else {
                m.log.ToolDone("jsecret", secretCount, time.Since(start))
        }
}

func (m *Module) runTrufflehog(ctx context.Context, jsDir string, urlMap map[string]string) {
	tcfg := m.cfg.Tools["trufflehog"]
	start := time.Now()

	isV3 := m.detectTrufflehogV3()
	var args []string
	if isV3 {
		args = []string{"filesystem", jsDir, "--json", "--only-verified", "--no-update"}
	} else {
		args = []string{"filesystem", jsDir, "--json", "--results=verified", "--no-update"}
	}

	timeout := 10 * time.Minute
	if tcfg.Timeout > 0 {
		timeout = time.Duration(tcfg.Timeout) * time.Second
	}

	m.log.Tool("trufflehog", "verifying secrets against live APIs")
	m.log.ToolCmd("trufflehog", args, "")

	secretCount := 0
	r := runner.Run(ctx, tcfg.Path, args,
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) { m.log.Debug("trufflehog: %s", line) }),
		runner.WithLineCallback(func(line string) {
			if !strings.Contains(line, `"Verified":true`) && !strings.Contains(line, `"verified":true`) {
				return
			}
			t := util.JsonStr(line, "DetectorName")
			if t == "" {
				t = util.JsonStr(line, "detector_name")
			}
			if t == "" {
				t = "unknown"
			}
			raw := util.JsonStr(line, "Raw")
			if raw == "" {
				raw = util.Truncate(line, 200)
			}
			sourceFile := util.JsonStr(line, "SourceName")
			if sourceFile == "" {
				sourceFile = util.JsonStr(line, "File")
			}
			origURL := filepath.Base(sourceFile)
			if u, ok := urlMap[origURL]; ok {
				origURL = u
			}

			m.store.AddSecret(&store.Secret{
				Type:   t + " (VERIFIED)",
				Value:  util.Truncate(raw, 200),
				Source: "trufflehog",
				File:   origURL,
			})
			secretCount++
			m.log.Secret(t, "trufflehog (VERIFIED)", util.Truncate(raw, 60))
			m.log.Finding("critical", "Verified Secret: "+t, origURL)
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("trufflehog", secretCount, timeout)
	} else if r.Err != nil && secretCount == 0 {
		m.log.ToolError("trufflehog", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("trufflehog", secretCount, time.Since(start))
		m.log.Debug("trufflehog: processed %d scan lines, %d verified secrets", len(r.Lines), secretCount)
	}
}

func (m *Module) runTrufflehogGitHub(ctx context.Context) {
	if !runner.IsAvailable("trufflehog") {
		return
	}
	start := time.Now()
	org := m.cfg.Target.OrgName
	token := m.cfg.Tokens["github"]
	isV3 := m.detectTrufflehogV3()
	var args []string
	if isV3 {
		args = []string{"github", "--org=" + org, "--only-verified", "--token=" + token, "--json", "--no-update"}
	} else {
		args = []string{"github", "--org=" + org, "--results=verified", "--token=" + token, "--json", "--no-update"}
	}
	m.log.Tool("trufflehog-github", org)
	m.log.ToolCmd("trufflehog", []string{"github", "--org=" + org, "--results=verified", "--token=***", "--json", "--no-update"}, "")

	secretCount := 0
	r := runner.Run(ctx, "trufflehog", args,
		runner.WithEnv([]string{"GITHUB_TOKEN=" + token}),
		runner.WithTimeout(10*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("trufflehog-github: %s", line) }),
		runner.WithLineCallback(func(line string) {
			if !strings.Contains(line, `"Verified":true`) {
				return
			}
			t := util.JsonStr(line, "DetectorName")
			if t == "" {
				t = "github-secret"
			}
			m.store.AddSecret(&store.Secret{Type: t, Value: util.Truncate(line, 200), Source: "trufflehog-github"})
			secretCount++
			m.log.Secret(t, "trufflehog-github", org)
			m.log.Finding("critical", "Verified GitHub Secret: "+t, org)
		}))

	if r.IsTimeout() {
		m.log.ToolTimeout("trufflehog-github", secretCount, 10*time.Minute)
	} else if r.Err != nil && secretCount == 0 {
		m.log.ToolError("trufflehog-github", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("trufflehog-github", secretCount, time.Since(start))
	}
}

func (m *Module) runGitleaks(ctx context.Context, jsDir string, urlMap map[string]string) {
	start := time.Now()
	reportFile := filepath.Join(store.DataDir(m.outDir), "gitleaks_report.json")
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
				m.store.AddSecret(&store.Secret{
					Type:   secType,
					Value:  util.Truncate(cleanSecret, 200),
					Source: "gitleaks",
					File:   origFile,
				})
				secretCount++
				m.log.Secret(secType, "gitleaks", util.Truncate(cleanSecret, 60))
				m.log.Finding("high", "Secret ("+secType+")", origFile)
			}
		}
	}

	if r.IsTimeout() {
		m.log.ToolTimeout("gitleaks", secretCount, 10*time.Minute)
	} else if r.Err != nil && secretCount == 0 && !util.FileExists(reportFile) {
		m.log.ToolError("gitleaks", fmt.Errorf(r.DiagString()), r.Stderr)
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

