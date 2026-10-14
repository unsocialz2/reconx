package params

import (
"context"
"encoding/json"
"fmt"
"os"
"path/filepath"
"strings"
"sync"
"time"

"github.com/reconx/reconx/internal/config"
"github.com/reconx/reconx/internal/store"
"github.com/reconx/reconx/pkg/logger"
"github.com/reconx/reconx/pkg/runner"
)

// Module discovers hidden GET/POST/JSON parameters using multiple tools.
type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

// New creates a parameter discovery module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run orchestrates all parameter discovery tools and writes WAF-split output files.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Hidden Parameter Discovery",
"URL Parser → unfurl → ParamSpider → Arjun → x8 → dalfox → getJS")

	paramsDir := filepath.Join(m.outDir, "params")
	if err := os.MkdirAll(paramsDir, 0755); err != nil {
		m.log.Warn("Could not create params/ directory: %v", err)
	}
	dataDir := store.DataDir(m.outDir)

	// ── Step 1: Go URL parser (no external tool needed) ──────────────────────
	allURLs := m.store.GetURLs()
	if len(allURLs) == 0 {
		// Fallback to live hosts
		for _, h := range m.store.GetHosts() {
			if u, ok := h.Meta["url"]; ok {
				allURLs = append(allURLs, u)
			} else {
				allURLs = append(allURLs, "https://"+h.Domain)
			}
		}
	}
	if len(allURLs) == 0 {
		m.log.Warn("No URLs or live hosts to test for parameters")
		return nil
	}

	// Extract params from URLs with query strings (pure Go — fast, no subprocess)
	urlsWithParams := FilterURLsWithParams(allURLs)
	goParams := ExtractParamsFromURLs(urlsWithParams)
	m.log.Info("URL parser: %d URLs with params → %d unique param keys extracted", len(urlsWithParams), len(goParams))
	for _, u := range urlsWithParams {
		pKeys := ExtractParamsFromURL(u)
		if len(pKeys) > 0 {
			m.store.AddParamFinding(&store.ParamFinding{
				URL:    u,
				Method: "GET",
				Params: pKeys,
				Tool:   "url_parser",
			})
		}
	}
	if err := store.SaveRaw(filepath.Join(dataDir, "url_parser_params.txt"), goParams); err != nil {
		m.log.Warn("Could not save url_parser_params.txt: %v", err)
	}

	// ── Step 2: Build smart target lists ─────────────────────────────────────
	// Split targets by WAF status — tune tool behavior accordingly
	wafURLs, nowafURLs := m.store.SplitURLsByWAF(allURLs)
	m.log.Info("Target split — WAF: %d URLs / non-WAF: %d URLs", len(wafURLs), len(nowafURLs))

	arjunPriority := m.buildPriorityList(allURLs, 30)
	arjunWAF := m.buildPriorityList(wafURLs, 8)
	arjunNoWAF := m.buildPriorityList(nowafURLs, 15)
	dalfoxURLs := m.buildPriorityList(allURLs, 150)

	// Save target lists
	if err := store.SaveRaw(filepath.Join(paramsDir, "targets.txt"), dalfoxURLs); err != nil {
		m.log.Warn("Could not save targets.txt: %v", err)
	}
	_ = store.SaveRaw(filepath.Join(paramsDir, "arjun_targets_waf.txt"), arjunWAF)
	_ = store.SaveRaw(filepath.Join(paramsDir, "arjun_targets_nowaf.txt"), arjunNoWAF)
	_ = arjunPriority

	m.log.Info("Parameter discovery: %d stream targets, %d WAF arjun targets, %d non-WAF arjun targets",
len(dalfoxURLs), len(arjunWAF), len(arjunNoWAF))

	// ── Run all tools in parallel ─────────────────────────────────────────────
	start := time.Now()
	var mu sync.Mutex
	var wg sync.WaitGroup
	allFoundParams := append([]string{}, goParams...)

	addParams := func(params []string) {
		mu.Lock()
		allFoundParams = append(allFoundParams, params...)
		mu.Unlock()
	}

	// Tool: arjun on WAF hosts (slow, stable mode)
	if runner.IsAvailable("arjun") && len(arjunWAF) > 0 {
		wafFile := filepath.Join(paramsDir, "arjun_targets_waf.txt")
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.runArjun(ctx, wafFile, paramsDir, "arjun-waf", true)
			addParams(p)
		}()
	} else if len(arjunWAF) == 0 {
		m.log.Debug("arjun-waf: no WAF-protected targets, skipping")
	} else {
		m.log.ToolSkipped("arjun", "not found — install: pip3 install arjun")
	}

	// Tool: arjun on non-WAF hosts (faster)
	if runner.IsAvailable("arjun") && len(arjunNoWAF) > 0 {
		nowafFile := filepath.Join(paramsDir, "arjun_targets_nowaf.txt")
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.runArjun(ctx, nowafFile, paramsDir, "arjun-nowaf", false)
			addParams(p)
		}()
	} else if len(arjunNoWAF) == 0 {
		m.log.Debug("arjun-nowaf: no non-WAF targets, skipping")
	}

	// Tool: x8 (hidden param brute-force alternative)
	if runner.IsAvailable("x8") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.runX8(ctx, dalfoxURLs, paramsDir)
			addParams(p)
		}()
	} else {
		m.log.ToolSkipped("x8", "not found — install: https://github.com/Sh1Yo/x8/releases")
	}

	// Tool: ParamSpider
	if runner.IsAvailable("paramspider") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.runParamSpider(ctx, paramsDir)
			addParams(p)
		}()
	} else {
		m.log.ToolSkipped("paramspider", "not found — install: pip3 install paramspider")
	}

	// Tool: unfurl (deep URL param parsing)
	if runner.IsAvailable("unfurl") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.runUnfurl(ctx, allURLs, paramsDir)
			addParams(p)
		}()
	} else {
		m.log.ToolSkipped("unfurl", "not found — install: go install github.com/tomnomnom/unfurl@latest")
	}

	// Tool: dalfox --only-discovery
	if runner.IsAvailable("dalfox") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := m.runDalfox(ctx, dalfoxURLs, paramsDir)
			addParams(p)
		}()
	} else {
		m.log.ToolSkipped("dalfox", "not found — install: go install github.com/hahwul/dalfox/v2@latest")
	}

	// Tool: getJS — extract endpoints from JS files
	if runner.IsAvailable("getJS") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runGetJS(ctx, paramsDir)
		}()
	} else {
		m.log.ToolSkipped("getJS", "not found — install: go install github.com/003random/getJS@latest")
	}

	wg.Wait()

	// ── Final output: deduplicated WAF-split param files ──────────────────────
	allFoundParams = DedupeParams(allFoundParams)

	// Re-split by WAF for final output files
	// We look at which URLs each param came from — simpler: split URL-with-params list
	wafParams := ExtractParamsFromURLs(wafURLs)
	nowafParams := ExtractParamsFromURLs(nowafURLs)

	// Merge store ParamResults into WAF/non-WAF buckets
	for _, pr := range m.store.GetParamResults() {
		if m.store.IsWAFProtected(pr.URL) {
			wafParams = append(wafParams, pr.Params...)
		} else {
			nowafParams = append(nowafParams, pr.Params...)
		}
	}
	wafParams = DedupeParams(wafParams)
	nowafParams = DedupeParams(nowafParams)

	if err := store.SaveRaw(m.outDir+"/params_waf.txt", wafParams); err != nil {
		m.log.Warn("Could not save params_waf.txt: %v", err)
	} else {
		m.log.Info("params_waf.txt   → %d unique params (WAF-protected)", len(wafParams))
	}
	if err := store.SaveRaw(m.outDir+"/params_nowaf.txt", nowafParams); err != nil {
		m.log.Warn("Could not save params_nowaf.txt: %v", err)
	} else {
		m.log.Info("params_nowaf.txt → %d unique params (non-WAF)", len(nowafParams))
	}
	// Also save combined
	if err := store.SaveRaw(m.outDir+"/params_all.txt", allFoundParams); err != nil {
		m.log.Warn("Could not save params_all.txt: %v", err)
	}

	m.log.PhaseComplete("Hidden Parameter Discovery", len(allFoundParams), time.Since(start))
	return nil
}

// ── Tool runners ─────────────────────────────────────────────────────────────

// runArjun runs arjun against a targets file. isWAF=true enables slower/stable mode.
func (m *Module) runArjun(ctx context.Context, targetsFile, paramsDir, label string, isWAF bool) []string {
	outFile := filepath.Join(paramsDir, label+"_results.json")

	threads := "15"
	chunk := "250"
	if isWAF {
		threads = "5"   // balanced concurrency for WAF hosts
		chunk = "200"   // 4x fewer HTTP requests than chunk 50
	}

	args := []string{
		"-i", targetsFile,
		"-oJ", outFile,
		"-t", threads,
		"-c", chunk,
	}
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "--headers", m.cfg.BugBountyHeader)
	}

	timeout := 45 * time.Minute
	wafLabel := ""
	if isWAF {
		wafLabel = " (WAF mode: slow/stable)"
		timeout = 90 * time.Minute
	}
	if m.cfg.NoTimeout || runner.IsNoTimeout() {
		timeout = 0
	}

	lines := countLines(targetsFile)
	m.log.Tool("arjun", fmt.Sprintf("%s → %d endpoints%s", label, lines, wafLabel))
	m.log.ToolCmd("arjun", args, "")
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("arjun:"+label, fmt.Sprintf("%d endpoints", lines))

	r := runner.Run(ctx, "arjun", args,
		runner.WithTimeout(timeout),
		runner.WithLineCallback(func(line string) {
			board.Heartbeat("arjun:" + label)
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Valid parameter found") || strings.Contains(line, "[+]") {
				m.log.InfoBoard(board, "  [arjun/%s] %s", label, line)
			}
		}),
runner.WithStderrCallback(func(line string) {
m.log.DebugBoard(board, "arjun/%s: %s", label, line)
board.Heartbeat("arjun:" + label)
}),
)

	found := m.parseArjunJSON(outFile)
	board.Done("arjun:"+label, len(found))
	board.Stop()

	if r.IsTimeout() {
		m.log.ToolTimeout("arjun:"+label, len(found), timeout)
	} else if r.Err != nil && len(found) == 0 {
		m.log.ToolError("arjun:"+label, fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("arjun:"+label, len(found), time.Since(start))
	}
	return found
}

func (m *Module) parseArjunJSON(outFile string) []string {
	data, err := os.ReadFile(outFile)
	if err != nil || len(data) < 2 {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	var params []string
	for url, v := range result {
		methods, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		for method, paramList := range methods {
			if pl, ok := paramList.([]interface{}); ok {
				ps := make([]string, 0, len(pl))
				for _, p := range pl {
					if s, ok := p.(string); ok {
						ps = append(ps, s)
					}
				}
				if len(ps) > 0 {
					m.store.AddParamFinding(&store.ParamFinding{
						URL:    url,
						Method: method,
						Params: ps,
						Tool:   "arjun",
					})
					params = append(params, ps...)
					m.log.Info("  [Param/arjun] %s → %s (%s)", url, strings.Join(ps, ", "), method)
				}
			}
		}
	}
	return params
}

// runX8 runs x8 hidden parameter brute-force on a sample of targets.
func (m *Module) runX8(ctx context.Context, targets []string, paramsDir string) []string {
	if len(targets) == 0 {
		return nil
	}
	outFile := filepath.Join(store.DataDir(m.outDir), "x8_results.txt")
	targetsSample := targets[:min(len(targets), 100)] // cap at 100 for x8

	targetsTmp, err := os.CreateTemp("", "x8-targets-*.txt")
	if err != nil {
		m.log.Warn("x8: could not create temp targets file: %v", err)
		return nil
	}
	defer os.Remove(targetsTmp.Name())
	if _, err := targetsTmp.WriteString(strings.Join(targetsSample, "\n")); err != nil {
		_ = targetsTmp.Close()
		return nil
	}
	_ = targetsTmp.Close()

	args := []string{
		"-u", targetsTmp.Name(),
		"-o", outFile,
		"-O", "url",
	}
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "-H", m.cfg.BugBountyHeader)
	}

	timeout := 30 * time.Minute
	if m.cfg.NoTimeout || runner.IsNoTimeout() {
		timeout = 0
	}

	m.log.Tool("x8", fmt.Sprintf("%d URLs (param brute-force)", len(targetsSample)))
	m.log.ToolCmd("x8", args, "")
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("x8", "discovering params")

	r := runner.Run(ctx, "x8", args,
		runner.WithTimeout(timeout),
		runner.WithLineCallback(func(line string) { board.Heartbeat("x8") }),
		runner.WithStderrCallback(func(line string) { m.log.DebugBoard(board, "x8: %s", line) }),
	)

	var found []string
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// x8 outputs full URLs with discovered params
		params := ExtractParamsFromURL(line)
		if len(params) > 0 {
			m.store.AddParamFinding(&store.ParamFinding{
				URL:    line,
				Method: "GET",
				Params: params,
				Tool:   "x8",
			})
			found = append(found, params...)
			m.log.InfoBoard(board, "  [Param/x8] %s → %s", line, strings.Join(params, ", "))
		}
	}

	board.Done("x8", len(found))
	board.Stop()

	if r.IsTimeout() {
		m.log.ToolTimeout("x8", len(found), 30*time.Minute)
	} else if r.Err != nil && len(found) == 0 {
		m.log.ToolError("x8", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("x8", len(found), time.Since(start))
	}
	return found
}

// runParamSpider runs paramspider to find parameters from Wayback Machine archives.
func (m *Module) runParamSpider(ctx context.Context, paramsDir string) []string {
	domains := m.cfg.Target.Domains
	if len(domains) == 0 {
		return nil
	}

	var allParams []string
	for _, domain := range domains {
		outFile := filepath.Join(store.DataDir(m.outDir), fmt.Sprintf("paramspider_%s.txt", domain))
		args := []string{"-d", domain, "-s"}

		m.log.Tool("paramspider", fmt.Sprintf("domain: %s", domain))
		m.log.ToolCmd("paramspider", args, "")
		start := time.Now()

		board := m.log.NewProgressBoard()
		board.Register("paramspider", domain)

		timeout := 10 * time.Minute
		if m.cfg.NoTimeout || runner.IsNoTimeout() {
			timeout = 0
		}
		count := 0
		r := runner.Run(ctx, "paramspider", args,
			runner.WithTimeout(timeout),
			runner.WithLineCallback(func(line string) {
				board.Heartbeat("paramspider")
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "http") {
					params := ExtractParamsFromURL(line)
					if len(params) > 0 {
						allParams = append(allParams, params...)
						m.store.AddParamFinding(&store.ParamFinding{
							URL:    line,
							Method: "GET",
							Params: params,
							Tool:   "paramspider",
						})
						count++
					}
				}
			}),
			runner.WithStderrCallback(func(line string) { m.log.DebugBoard(board, "paramspider: %s", line) }),
		)

		board.Done("paramspider", count)
		board.Stop()

		if len(r.Lines) > 0 {
			_ = store.SaveRaw(outFile, r.Lines)
		}

		if r.IsTimeout() {
			m.log.ToolTimeout("paramspider", count, 10*time.Minute)
		} else if r.Err != nil && count == 0 {
			m.log.ToolError("paramspider", fmt.Errorf(r.DiagString()), r.Stderr)
		} else {
			m.log.ToolDone("paramspider", count, time.Since(start))
		}
	}
	return allParams
}

// runUnfurl runs unfurl to extract parameter keys from all discovered URLs.
func (m *Module) runUnfurl(ctx context.Context, urls []string, paramsDir string) []string {
	if len(urls) == 0 {
		return nil
	}

	// Filter to URLs with query strings
	urlsWithQ := FilterURLsWithParams(urls)
	if len(urlsWithQ) == 0 {
		m.log.Debug("unfurl: no URLs with query params, skipping")
		return nil
	}

	input := strings.Join(urlsWithQ, "\n")
	outFile := filepath.Join(store.DataDir(m.outDir), "unfurl_keys.txt")

	// unfurl keys extracts query parameter keys
	args := []string{"keys"}

	m.log.Tool("unfurl", fmt.Sprintf("%d URLs → extracting param keys", len(urlsWithQ)))
	m.log.ToolCmd("unfurl", args, fmt.Sprintf("[%d URLs via stdin]", len(urlsWithQ)))
	start := time.Now()

	timeout := 5 * time.Minute
	if m.cfg.NoTimeout || runner.IsNoTimeout() {
		timeout = 0
	}

	board := m.log.NewProgressBoard()
	board.Register("unfurl", "extracting keys")

	r := runner.Run(ctx, "unfurl", args,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
		runner.WithLineCallback(func(line string) { board.Heartbeat("unfurl") }),
		runner.WithStderrCallback(func(line string) { m.log.DebugBoard(board, "unfurl: %s", line) }),
	)

	// Deduplicate unfurl output
	seen := make(map[string]bool)
	var params []string
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if line != "" && !seen[line] {
			seen[line] = true
			params = append(params, line)
		}
	}

	_ = store.SaveRaw(outFile, params)
	board.Done("unfurl", len(params))
	board.Stop()

	if r.IsTimeout() {
		m.log.ToolTimeout("unfurl", len(params), 5*time.Minute)
	} else if r.Err != nil && len(params) == 0 {
		m.log.ToolError("unfurl", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("unfurl", len(params), time.Since(start))
	}
	return params
}

// runDalfox runs dalfox in --only-discovery mode (param analysis, no XSS payloads).
func (m *Module) runDalfox(ctx context.Context, urls []string, paramsDir string) []string {
	outFile := filepath.Join(store.DataDir(m.outDir), "dalfox_params.json")

	args := []string{
		"pipe",
		"--only-discovery",
		"--no-color",
		"--format", "json",
		"--workers", "10",
		"--max-concurrent-targets", "10",
		"--rate-limit", "30",
		"-o", outFile,
	}
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "-H", m.cfg.BugBountyHeader)
	}

	input := strings.Join(urls, "\n")
	timeout := 15 * time.Minute
	if m.cfg.NoTimeout || runner.IsNoTimeout() {
		timeout = 0
	}

	m.log.Tool("dalfox", fmt.Sprintf("%d URLs — param analysis only", len(urls)))
	m.log.ToolCmd("dalfox", args, fmt.Sprintf("[%d URLs via stdin]", len(urls)))
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("dalfox", "analyzing")

	count := 0
	r := runner.Run(ctx, "dalfox", args,
		runner.WithStdin(input),
		runner.WithTimeout(timeout),
runner.WithStderrCallback(func(line string) { m.log.DebugBoard(board, "dalfox: %s", line) }),
runner.WithLineCallback(func(line string) {
board.Heartbeat("dalfox")
line = strings.TrimSpace(line)
if line == "" || !strings.HasPrefix(line, "{") {
return
}
paramName := jsonStr(line, "param")
targetURL := jsonStr(line, "url")
method := jsonStr(line, "method")
if paramName == "" || targetURL == "" {
return
}
m.store.AddParamFinding(&store.ParamFinding{
				URL:    targetURL,
				Method: method,
				Params: []string{paramName},
				Tool:   "dalfox",
			})
			count++
			m.log.InfoBoard(board, "  [Param/dalfox] %s → %s (%s)", targetURL, paramName, method)
		}),
	)

	board.Done("dalfox", count)
	board.Stop()

	if r.IsTimeout() {
		m.log.ToolTimeout("dalfox", count, timeout)
	} else if r.Err != nil && count == 0 && !strings.Contains(strings.Join(r.Stderr, " "), "UNREACHABLE") {
		m.log.ToolError("dalfox", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("dalfox", count, time.Since(start))
	}

	return m.parseDalfoxJSON(outFile)
}

func (m *Module) parseDalfoxJSON(jsonFile string) []string {
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil
	}

	var params []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var finding struct {
			URL    string `json:"url"`
			Method string `json:"method"`
			Param  string `json:"param"`
		}
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}
		if finding.Param != "" {
			m.store.AddParamFinding(&store.ParamFinding{
				URL:    finding.URL,
				Method: finding.Method,
				Params: []string{finding.Param},
				Tool:   "dalfox",
			})
			params = append(params, finding.Param)
		}
	}
	return params
}

// getJSFlagSupported reports whether the installed getJS supports the given
// flag (checked against --help output). Cache the probe result — getJS runs
// once per scan but the probe is cheap to reuse.
var (
	getJSFlagCacheMu    sync.Mutex
	getJSFlagCache      = map[string]bool{}
	getJSFlagCacheLoaded = false
)

func getJSFlagSupported(flag string) bool {
	getJSFlagCacheMu.Lock()
	defer getJSFlagCacheMu.Unlock()
	if !getJSFlagCacheLoaded {
		getJSFlagCacheLoaded = true
		r := runner.Run(context.Background(), "getJS", []string{"--help"}, runner.WithTimeout(10*time.Second))
		for _, line := range append(r.Lines, r.Stderr...) {
			line = strings.TrimSpace(line)
			for _, part := range strings.Fields(line) {
				clean := strings.TrimPrefix(strings.TrimPrefix(part, "--"), "-")
				clean = strings.TrimSuffix(clean, ",")
				if clean != "" {
					getJSFlagCache[strings.ToLower(clean)] = true
				}
			}
		}
	}
	return getJSFlagCache[strings.ToLower(flag)]
}

// runGetJS runs getJS to find JS files from live hosts and extract endpoint URLs.
func (m *Module) runGetJS(ctx context.Context, paramsDir string) {
	var targetURLs []string
	for _, h := range m.store.GetHosts() {
		if u, ok := h.Meta["url"]; ok && u != "" {
			targetURLs = append(targetURLs, u)
		} else {
			targetURLs = append(targetURLs, "https://"+h.Domain)
		}
	}
	if len(targetURLs) == 0 {
		for _, d := range m.cfg.Target.Domains {
			targetURLs = append(targetURLs, "https://"+d)
		}
	}
	if len(targetURLs) == 0 {
		m.log.Debug("getJS: no target URLs to extract JS from, skipping")
		return
	}
	if len(targetURLs) > 100 {
		targetURLs = targetURLs[:100]
	}

	tmpFile, err := os.CreateTemp("", "getjs-input-*.txt")
	if err != nil {
		m.log.Warn("getJS: could not create temp file: %v", err)
		return
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(strings.Join(targetURLs, "\n")); err != nil {
		tmpFile.Close()
		return
	}
	tmpFile.Close()

	outFile := filepath.Join(store.DataDir(m.outDir), "getjs_endpoints.txt")
	args := []string{"--input", tmpFile.Name(), "--output", outFile, "--complete"}
	// Older getJS builds don't have --insecure — passing it makes the tool
	// exit 2 with "flag provided but not defined". Probe --help once.
	if getJSFlagSupported("insecure") {
		args = append(args, "--insecure")
	}
	if getJSFlagSupported("threads") {
		args = append(args, "--threads", "10")
	}
	if m.cfg.BugBountyHeader != "" {
		// Use --header which is accepted by both pflag and standard flag getJS builds
		args = append(args, "--header", m.cfg.BugBountyHeader)
	}

	timeout := 10 * time.Minute
	if m.cfg.NoTimeout || runner.IsNoTimeout() {
		timeout = 0
	}

	m.log.Tool("getJS", fmt.Sprintf("%d live hosts — extracting JS endpoints", len(targetURLs)))
	m.log.ToolCmd("getJS", args, "")
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("getJS", "extracting JS")

	r := runner.Run(ctx, "getJS", args,
		runner.WithTimeout(timeout),
		runner.WithStderrCallback(func(line string) {
			m.log.DebugBoard(board, "getJS: %s", line)
			board.Heartbeat("getJS")
		}),
	)

	count := 0
	for _, line := range r.Lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			m.store.AddURL(line)
			if strings.Contains(line, ".js") {
				m.store.AddJSFile(line)
			}
			count++
		}
	}

	board.Done("getJS", count)
	board.Stop()

	if r.Err != nil && count == 0 {
		m.log.ToolError("getJS", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("getJS", count, time.Since(start))
		if count > 0 {
			m.log.InfoBoard(board, "getJS: %d new endpoints discovered from JS files", count)
		}
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// buildPriorityList selects the best URLs for param brute-force with smart prioritization.
func (m *Module) buildPriorityList(urls []string, maxURLs int) []string {
	skipExt := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
		".zip", ".tar", ".gz", ".map",
	}

	var withParams, apiPaths, loginPaths, other []string
	seen := make(map[string]bool)

	for _, u := range urls {
		lower := strings.ToLower(u)
		skip := false
		for _, ext := range skipExt {
			if strings.HasSuffix(lower, ext) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		base := u
		if idx := strings.Index(base, "?"); idx != -1 {
			base = base[:idx]
		}
		if seen[base] {
			continue
		}
		seen[base] = true

		switch {
		case strings.Contains(u, "="):
			withParams = append(withParams, u)
		case matchAny(lower, "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql", ".json", ".xml"):
			apiPaths = append(apiPaths, u)
		case matchAny(lower, "login", "signin", "auth", "register", "account", "reset", "forgot", "search", "query", "filter"):
			loginPaths = append(loginPaths, u)
		default:
			other = append(other, u)
		}
	}

	var result []string
	for _, bucket := range [][]string{withParams, apiPaths, loginPaths, other} {
		for _, u := range bucket {
			result = append(result, u)
			if len(result) >= maxURLs {
				return result
			}
		}
	}
	return result
}

func matchAny(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(data), "\n") + 1
}

func jsonStr(line, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
