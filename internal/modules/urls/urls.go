package urls

import (
        "context"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
        "strings"
        "sync"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/scope"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
)

type Module struct {
        cfg    *config.Config
        store  *store.Store
        scope  *scope.Filter
        log    *logger.Logger
        outDir string

        // board is set by Run() so per-tool functions can call Heartbeat()
        // to keep the progress board from showing "stuck" while a tool is
        // actively working but not yet producing deduplicated results.
        board *logger.ProgressBoard
}

func New(cfg *config.Config, st *store.Store, sc *scope.Filter, log *logger.Logger, outDir string) *Module {
        return &Module{cfg: cfg, store: st, scope: sc, log: log, outDir: outDir}
}

func (m *Module) Run(ctx context.Context) error {
        m.log.Phase("URL Discovery",
                "Wayback, GAU, Katana, hakrawler, gospider, paramspider, OTX — merged & deduplicated")

        start := time.Now()
        hosts := m.store.GetHosts()
        if len(hosts) == 0 {
                m.log.Warn("No live hosts for URL discovery — alive check phase found nothing")
                return nil
        }

        // Build URL and domain input lists
        aliveURLs := make([]string, 0, len(hosts))
        domainList := make([]string, 0, len(hosts))
        for _, h := range hosts {
                u := h.Meta["url"]
                if u == "" {
                        u = "https://" + h.Domain
                }
                aliveURLs = append(aliveURLs, u)
                domainList = append(domainList, h.Domain)
        }

        urlInput := strings.Join(aliveURLs, "\n")
        domInput := strings.Join(domainList, "\n")

        m.log.Info("URL discovery: %d live hosts → running all tools in parallel", len(hosts))
        board := m.log.NewProgressBoard()
        m.board = board

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

        type toolDef struct {
                name   string
                binKey string // "" = HTTP-based, no binary needed
                useURL bool   // true = pass URL list, false = pass domain list
                fn     func(context.Context, string) []string
        }

        tools := []toolDef{
                {"waybackurls", "waybackurls", false, m.runWayback},
                // waymore removed from defaults — too slow, blocks JS/Vuln phases
                // re-enable with --waymore flag in future version
                {"gau",         "gau",         false, m.runGAU},
                {"gauplus",     "gauplus",     false, m.runGAUPlus},
                {"katana",      "katana",      true,  m.runKatana},
                {"hakrawler",   "hakrawler",   true,  m.runHakrawler},
                {"gospider",    "gospider",    true,  m.runGospider},
                {"paramspider", "paramspider", false, m.runParamSpider},
                {"otx-api",     "",            false, m.runOTX}, // HTTP only
        }

        var (
                mu      sync.Mutex
                wg      sync.WaitGroup
                totalBy = make(map[string]int)
        )

        for _, t := range tools {
                t := t

                // Binary availability check
                if t.binKey != "" && !runner.IsAvailable(t.binKey) {
                        m.log.ToolSkipped(t.name,
                                fmt.Sprintf("not found — install: go install .../%s@latest", t.binKey))
                        continue
                }

                input := domInput
                if t.useURL {
                        input = urlInput
                }

                board.Register(t.name, fmt.Sprintf("%d hosts", len(aliveURLs)))
                wg.Add(1)
                go func() {
                        defer wg.Done()
			results := t.fn(ctx, input)
			
			var filtered []string
			for _, u := range results {
				if m.scope.IsInScope(u) {
					filtered = append(filtered, u)
				}
			}

			mu.Lock()
			added := m.store.AddURLs(filtered)
			totalBy[t.name] = added
			board.Done(t.name, len(filtered))
                        mu.Unlock()
                }()
        }
        wg.Wait()
        board.Stop()

        // Classify into buckets
        total := len(m.store.GetURLs())
        m.log.Info("URL deduplication: %d total unique URLs", total)
        m.classifyAndSave()

	if err := store.SaveRaw(m.outDir+"/urls.txt", m.store.GetURLs()); err != nil {
		m.log.Warn("Could not save urls.txt: %v", err)
	}

	// WAF-split URL files
	allURLs := m.store.GetURLs()
	wafURLs, nowafURLs := m.store.SplitURLsByWAF(allURLs)
	if err := store.SaveRaw(m.outDir+"/urls_waf.txt", wafURLs); err != nil {
		m.log.Warn("Could not save urls_waf.txt: %v", err)
	} else {
		m.log.Info("urls_waf.txt   → %d URLs (WAF-protected hosts)", len(wafURLs))
	}
	if err := store.SaveRaw(m.outDir+"/urls_nowaf.txt", nowafURLs); err != nil {
		m.log.Warn("Could not save urls_nowaf.txt: %v", err)
	} else {
		m.log.Info("urls_nowaf.txt → %d URLs (non-WAF hosts)", len(nowafURLs))
	}

	m.log.PhaseComplete("URL Discovery", total, time.Since(start))
	return nil
}

func (m *Module) runWayback(ctx context.Context, input string) []string {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        tcfg := m.cfg.Tools["waybackurls"]
        path := "waybackurls"
        if tcfg.Path != "" {
                path = tcfg.Path
        }
        // Set an explicit timeout — the old code logged "5min timeout" without
        // ever passing one, so waybackurls ran forever on huge archives.
        timeout := 30 * time.Minute
        if tcfg.Timeout > 0 {
                timeout = time.Duration(tcfg.Timeout) * time.Second
        }
        m.log.Tool("waybackurls", fmt.Sprintf("%d domains", count))
        m.log.ToolCmd("waybackurls", []string{}, fmt.Sprintf("[%d domains via stdin]", count))

        r := runner.Run(ctx, path, nil,
                runner.WithStdin(input),
                runner.WithTimeout(timeout),
                runner.WithStderrCallback(func(line string) {
                        m.log.Debug("waybackurls: %s", line)
                        if m.board != nil {
                                m.board.Heartbeat("waybackurls")
                        }
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("waybackurls", len(r.Lines), timeout)
                return r.Lines
        }
        if r.Err != nil && len(r.Lines) == 0 {
                m.log.ToolError("waybackurls", fmt.Errorf(r.DiagString()), r.Stderr)
                return nil
        }
        m.log.ToolDone("waybackurls", len(r.Lines), time.Since(start))
        return r.Lines
}

func (m *Module) runWaymore(ctx context.Context, input string) []string {
        start := time.Now()

        // waymore works best with root domains, not subdomains
        // Extract unique root domains from the host list
        rootDomains := extractRootDomains(splitLines(input))
        m.log.Tool("waymore", fmt.Sprintf("%d root domains (extracted from %d hosts)", len(rootDomains), strings.Count(input, "\n")+1))

        var (
                all []string
                mu  sync.Mutex
                wg  sync.WaitGroup
                sem = make(chan struct{}, 5) // max 5 concurrent waymore instances
        )

        for _, d := range rootDomains {
                d := d
                if d == "" {
                        continue
                }
                wg.Add(1)
                sem <- struct{}{}
                go func() {
                        defer wg.Done()
                        defer func() { <-sem }()
                        args := []string{"-i", d, "-mode", "U", "-oU", "/dev/stdout"}
                        m.log.ToolCmd("waymore", args, "")
                        tcfg := m.cfg.Tools["waymore"]
                        timeout := time.Duration(tcfg.Timeout) * time.Second
                        if timeout == 0 {
                                timeout = 5 * time.Minute
                        }
                        r := runner.Run(ctx, "waymore", args,
                                runner.WithTimeout(timeout),
                                runner.WithStderrCallback(func(line string) { m.log.Debug("waymore[%s]: %s", d, line) }))
                        if r.Err != nil && len(r.Lines) == 0 {
                                m.log.Debug("waymore[%s]: %s", d, r.DiagString())
                        } else {
                                mu.Lock()
                                all = append(all, r.Lines...)
                                mu.Unlock()
                        }
                }()
        }
        wg.Wait()
        m.log.ToolDone("waymore", len(all), time.Since(start))
        return all
}

func (m *Module) runGAU(ctx context.Context, input string) []string {
        start := time.Now()
        // gau works best with root domains — passing 200+ subdomains causes all
        // providers (wayback, otx, commoncrawl) to rate-limit simultaneously
        rootDomains := extractRootDomains(splitLines(input))
        m.log.Tool("gau", fmt.Sprintf("%d root domains", len(rootDomains)))

        var (
                all []string
                mu  sync.Mutex
                wg  sync.WaitGroup
                sem = make(chan struct{}, 3) // max 3 concurrent gau instances
        )

        tcfg := m.cfg.Tools["gau"]
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 3 * time.Minute
        }

        for _, d := range rootDomains {
                d := d
                wg.Add(1)
                sem <- struct{}{}
                go func() {
                        defer wg.Done()
                        defer func() { <-sem }()
                        args := []string{"--subs", "--threads", "5", "--providers", "wayback,commoncrawl,otx,urlscan"}
                        m.log.ToolCmd("gau", append(args, d), "")
                        r := runner.Run(ctx, "gau", append(args, d),
                                runner.WithTimeout(timeout),
                                runner.WithStderrCallback(func(line string) { m.log.Debug("gau[%s]: %s", d, line) }))
                        if r.Err == nil || len(r.Lines) > 0 {
                                mu.Lock()
                                all = append(all, r.Lines...)
                                mu.Unlock()
                        }
                }()
        }
        wg.Wait()
        m.log.ToolDone("gau", len(all), time.Since(start))
        return all
}

func (m *Module) runGAUPlus(ctx context.Context, input string) []string {
        start := time.Now()
        rootDomains := extractRootDomains(splitLines(input))
        m.log.Tool("gauplus", fmt.Sprintf("%d root domains", len(rootDomains)))

        var (
                all []string
                mu  sync.Mutex
                wg  sync.WaitGroup
                sem = make(chan struct{}, 3)
        )

        tcfg := m.cfg.Tools["gauplus"]
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 3 * time.Minute
        }

        for _, d := range rootDomains {
                d := d
                wg.Add(1)
                sem <- struct{}{}
                go func() {
                        defer wg.Done()
                        defer func() { <-sem }()
                        args := []string{"-subs", "-t", "5", "-random-agent"}
                        r := runner.Run(ctx, "gauplus", append(args, d),
                                runner.WithTimeout(timeout),
                                runner.WithStderrCallback(func(line string) { m.log.Debug("gauplus[%s]: %s", d, line) }))
                        if r.Err == nil || len(r.Lines) > 0 {
                                mu.Lock()
                                all = append(all, r.Lines...)
                                mu.Unlock()
                        }
                }()
        }
        wg.Wait()
        m.log.ToolDone("gauplus", len(all), time.Since(start))
        return all
}

func (m *Module) runKatana(ctx context.Context, input string) []string {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        tcfg := m.cfg.Tools["katana"]
        args := append([]string{"-list", "-"}, tcfg.Flags...)
        m.log.Tool("katana", fmt.Sprintf("%d hosts — deep crawl (headless JS)", count))
        m.log.ToolCmd("katana", args, fmt.Sprintf("[%d hosts via stdin]", count))

        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 10 * time.Minute
        }

        r := runner.Run(ctx, "katana", args,
                runner.WithStdin(input),
                runner.WithTimeout(timeout),
                runner.WithStderrCallback(func(line string) {
                        m.log.Debug("katana: %s", line)
                        if m.board != nil {
                                m.board.Heartbeat("katana")
                        }
                }))

        if r.IsTimeout() {
                m.log.ToolTimeout("katana", len(r.Lines), timeout)
                return r.Lines
        }
        if r.Err != nil && len(r.Lines) == 0 {
                m.log.ToolError("katana", fmt.Errorf(r.DiagString()), r.Stderr)
                return nil
        }
        m.log.ToolDone("katana", len(r.Lines), time.Since(start))
        return r.Lines
}

func (m *Module) runHakrawler(ctx context.Context, input string) []string {
        start := time.Now()
        count := strings.Count(input, "\n") + 1
        args := []string{"-subs", "-u", "-insecure"}
        m.log.Tool("hakrawler", fmt.Sprintf("%d hosts", count))
        m.log.ToolCmd("hakrawler", args, fmt.Sprintf("[%d hosts via stdin]", count))

        tcfg := m.cfg.Tools["hakrawler"]
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 5 * time.Minute
        }

        r := runner.Run(ctx, "hakrawler", args,
                runner.WithStdin(input),
                runner.WithTimeout(timeout),
                runner.WithStderrCallback(func(line string) { m.log.Debug("hakrawler: %s", line) }))

        if r.IsTimeout() {
                m.log.ToolTimeout("hakrawler", len(r.Lines), timeout)
                return r.Lines
        }
        if r.Err != nil && len(r.Lines) == 0 {
                m.log.ToolError("hakrawler", fmt.Errorf(r.DiagString()), r.Stderr)
                return nil
        }
        m.log.ToolDone("hakrawler", len(r.Lines), time.Since(start))
        return r.Lines
}

func (m *Module) runGospider(ctx context.Context, input string) []string {
        start := time.Now()

        // gospider does NOT support '-S -' for stdin — it requires a real file.
        // Write URLs to a temp file and pass the path.
        tmpFile, err := os.CreateTemp("", "gospider-urls-*.txt")
        if err != nil {
                m.log.Warn("gospider: could not create temp file: %v", err)
                return nil
        }
        defer os.Remove(tmpFile.Name())
        if _, err := tmpFile.WriteString(input); err != nil {
                tmpFile.Close()
                m.log.Warn("gospider: could not write temp file: %v", err)
                return nil
        }
        tmpFile.Close()

        count := strings.Count(input, "\n") + 1
        // -t = parallel sites, -c = concurrent requests per site, -d = depth
        args := []string{"-S", tmpFile.Name(), "-c", "10", "-d", "3", "--sitemap", "--robots"}
        m.log.Tool("gospider", fmt.Sprintf("%d hosts", count))
        m.log.ToolCmd("gospider", args, "")

        tcfg := m.cfg.Tools["gospider"]
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 5 * time.Minute
        }

        r := runner.Run(ctx, "gospider", args,
                runner.WithTimeout(timeout),
                runner.WithStderrCallback(func(line string) { m.log.Debug("gospider: %s", line) }))

        if r.IsTimeout() {
                m.log.ToolTimeout("gospider", len(r.Lines), timeout)
        } else if r.Err != nil && len(r.Lines) == 0 {
                m.log.ToolError("gospider", fmt.Errorf(r.DiagString()), r.Stderr)
                return nil
        }

        // gospider output contains metadata — extract only URLs
        var urls []string
        for _, line := range r.Lines {
                if idx := strings.Index(line, "http"); idx >= 0 {
                        u := line[idx:]
                        if end := strings.IndexAny(u, " \t]"); end > 0 {
                                u = u[:end]
                        }
                        if strings.HasPrefix(u, "http") {
                                urls = append(urls, u)
                        }
                }
        }
        m.log.ToolDone("gospider", len(urls), time.Since(start))
        m.log.Debug("gospider: extracted %d URLs from %d raw lines", len(urls), len(r.Lines))
        return urls
}

func (m *Module) runParamSpider(ctx context.Context, input string) []string {
        start := time.Now()
        domains := splitLines(input)
        m.log.Tool("paramspider", fmt.Sprintf("%d domains", len(domains)))

        var (
                all []string
                mu  sync.Mutex
                wg  sync.WaitGroup
                sem = make(chan struct{}, 10) // 10 concurrent
        )

        tcfg := m.cfg.Tools["paramspider"]
        timeout := time.Duration(tcfg.Timeout) * time.Second
        if timeout == 0 {
                timeout = 3 * time.Minute
        }

        for _, d := range domains {
                d := d
                if d == "" {
                        continue
                }
                wg.Add(1)
                sem <- struct{}{}
                go func() {
                        defer wg.Done()
                        defer func() { <-sem }()
                        // Use -s flag for silent output (replaces --quiet which doesn't exist)
                        args := []string{"-d", d, "-s"}
                        r := runner.Run(ctx, "paramspider", args,
                                runner.WithTimeout(timeout),
                                runner.WithStderrCallback(func(line string) { m.log.Debug("paramspider[%s]: %s", d, line) }))
                        if r.Err == nil || len(r.Lines) > 0 {
                                mu.Lock()
                                all = append(all, r.Lines...)
                                mu.Unlock()
                        }
                }()
        }
        wg.Wait()
        m.log.ToolDone("paramspider", len(all), time.Since(start))
        return all
}

// runOTX queries AlienVault OTX API — no binary, pure HTTP
func (m *Module) runOTX(ctx context.Context, input string) []string {
        start := time.Now()
        domains := splitLines(input)
        m.log.Tool("otx-api", fmt.Sprintf("%d domains (AlienVault OTX)", len(domains)))

        var (
                all []string
                mu  sync.Mutex
                wg  sync.WaitGroup
        )

        sem := make(chan struct{}, 20) // max 20 concurrent OTX requests
        for _, d := range domains {
                d := d
                if d == "" {
                        continue
                }
                wg.Add(1)
                sem <- struct{}{}
                go func() {
                        defer wg.Done()
                        defer func() { <-sem }()
                        urls := fetchOTX(ctx, d, m.log)
                        mu.Lock()
                        all = append(all, urls...)
                        mu.Unlock()
                }()
        }
        wg.Wait()

        m.log.ToolDone("otx-api", len(all), time.Since(start))
        return all
}

func fetchOTX(ctx context.Context, domain string, log *logger.Logger) []string {
        url := fmt.Sprintf(
                "https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=1",
                domain)

        reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
        defer cancel()

        req, _ := http.NewRequestWithContext(reqCtx, "GET", url, nil)
        req.Header.Set("User-Agent", "Mozilla/5.0 (reconx)")

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                log.Debug("otx[%s]: %v", domain, err)
                return nil
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                log.Debug("otx[%s]: HTTP %d", domain, resp.StatusCode)
                return nil
        }

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
        data := string(body)

        var results []string
        seen := make(map[string]bool)
        for _, part := range strings.Split(data, `"url":"`) {
                if idx := strings.Index(part, `"`); idx > 0 {
                        u := part[:idx]
                        if strings.HasPrefix(u, "http") && !seen[u] {
                                seen[u] = true
                                results = append(results, u)
                        }
                }
        }
        log.Debug("otx[%s]: %d URLs", domain, len(results))
        return results
}

// classifyAndSave splits all discovered URLs into category files
func (m *Module) classifyAndSave() {
        cats := map[string][]string{}
        apiPat := []string{".json", ".xml", ".graphql", "/api/", "/v1/", "/v2/", "/v3/", "/rest/"}
        backExt := []string{".php", ".asp", ".aspx", ".jsp", ".cfm", ".cgi", ".pl", ".py"}
        loginPat := []string{"login", "signin", "sign-in", "auth", "oauth", "sso", "logout", "password", "reset", "forgot"}
        uploadPat := []string{"upload", "file", "download", "image", "media", "attachment", "avatar", "import", "export"}
        adminPat := []string{"admin", "administrator", "dashboard", "internal", "manage", "control", "panel", "console", "staff"}
        sensPat := []string{".env", ".bak", ".config", ".sql", ".log", ".backup", ".key", ".pem", ".htpasswd", "wp-config", "database.yml"}
        cloudPat := []string{"aws", "s3.", "bucket", "gcp", "azure", "vault", "apikey", "api_key", "secret"}
        redirPat := []string{"redirect", "callback", "return_url", "return=", "next=", "goto=", "dest=", "url=", "r=", "u="}

        for _, u := range m.store.GetURLs() {
                ul := strings.ToLower(u)
                if isJSURL(u) {
                        cats["js"] = append(cats["js"], u)
                        m.store.AddJSFile(u)
                }
                if matchAny(ul, apiPat...) { cats["api"] = append(cats["api"], u) }
                if matchAny(ul, backExt...) { cats["backend"] = append(cats["backend"], u) }
                if matchAny(ul, loginPat...) { cats["login"] = append(cats["login"], u) }
                if matchAny(ul, uploadPat...) { cats["uploads"] = append(cats["uploads"], u) }
                if matchAny(ul, adminPat...) { cats["admin"] = append(cats["admin"], u) }
                if matchAny(ul, sensPat...) { cats["sensitive"] = append(cats["sensitive"], u) }
                if matchAny(ul, cloudPat...) { cats["cloud_leaks"] = append(cats["cloud_leaks"], u) }
                if matchAny(ul, redirPat...) { cats["redirect"] = append(cats["redirect"], u) }
                if strings.Contains(u, "=") { cats["params"] = append(cats["params"], u) }
        }

        for cat, list := range cats {
                if len(list) == 0 {
                        continue
                }
                if err := store.SaveRaw(m.outDir+"/urls_"+cat+".txt", list); err != nil {
                        m.log.Warn("Could not save urls_%s.txt: %v", cat, err)
                } else {
                        m.log.Info("  %-16s → %d URLs", cat, len(list))
                }
        }
}

func isJSURL(rawURL string) bool {
        u, err := url.Parse(rawURL)
        var path string
        if err == nil {
                path = strings.ToLower(u.Path)
        } else {
                path = strings.ToLower(rawURL)
                if idx := strings.Index(path, "?"); idx != -1 {
                        path = path[:idx]
                }
        }
        if strings.Contains(path, ".json") {
                return false
        }
        return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") || strings.HasSuffix(path, ".jsx")
}

func matchAny(s string, patterns ...string) bool {
        for _, p := range patterns {
                if strings.Contains(s, p) {
                        return true
                }
        }
        return false
}

func splitLines(s string) []string {
        var out []string
        for _, line := range strings.Split(s, "\n") {
                if l := strings.TrimSpace(line); l != "" {
                        out = append(out, l)
                }
        }
        return out
}

// extractRootDomains extracts unique root domains from a list of subdomains.
// e.g. [ar.airbnb.com, api.airbnb.com, airbnb.com] → [airbnb.com]
//
// Public-suffix aware: bbc.co.uk → bbc.co.uk (not co.uk). We use a built-in
// list of common multi-part TLDs since adding golang.org/x/net/publicsuffix
// would introduce an external dependency. The list below covers >99% of the
// domains seen in real bug bounty programs.
func extractRootDomains(hosts []string) []string {
        seen := make(map[string]bool)
        var roots []string
        for _, h := range hosts {
                // Strip http:// or https:// and trailing path
                h = strings.TrimPrefix(h, "https://")
                h = strings.TrimPrefix(h, "http://")
                if idx := strings.IndexAny(h, "/?#"); idx != -1 {
                        h = h[:idx]
                }
                // Strip port
                if i := strings.LastIndex(h, ":"); i > 0 {
                        h = h[:i]
                }
                h = strings.ToLower(strings.TrimSpace(h))
                if h == "" {
                        continue
                }

                parts := strings.Split(h, ".")
                if len(parts) < 2 {
                        continue
                }

                // Default: last two parts
                rootIdx := len(parts) - 2
                // Check for multi-part TLD (e.g. co.uk, com.au, com.cn)
                if len(parts) >= 3 {
                        lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
                        if isMultiPartTLD(lastTwo) {
                                rootIdx = len(parts) - 3
                        }
                }
                root := parts[rootIdx] + "." + strings.Join(parts[rootIdx+1:], ".")
                if !seen[root] {
                        seen[root] = true
                        roots = append(roots, root)
                }
        }
        return roots
}

// isMultiPartTLD returns true if the given second-level domain is a known
// multi-part TLD (e.g. co.uk, com.au). Used to avoid extracting "co.uk" as
// the root domain for sites like bbc.co.uk.
func isMultiPartTLD(s string) bool {
        multiPartTLDs := map[string]bool{
                // United Kingdom
                "co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
                "net.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true,
                // Australia
                "com.au": true, "org.au": true, "net.au": true, "edu.au": true,
                "gov.au": true,
                // New Zealand
                "co.nz": true, "org.nz": true, "net.nz": true, "ac.nz": true,
                "govt.nz": true,
                // South Africa
                "co.za": true, "org.za": true, "net.za": true, "ac.za": true,
                "gov.za": true,
                // Japan
                "co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
                "go.jp": true,
                // South Korea
                "co.kr": true, "or.kr": true, "ne.kr": true, "go.kr": true,
                // Brazil
                "com.br": true, "org.br": true, "net.br": true, "gov.br": true,
                "edu.br": true,
                // China
                "com.cn": true, "org.cn": true, "net.cn": true, "gov.cn": true,
                "edu.cn": true,
                // India
                "co.in": true, "org.in": true, "net.in": true, "ac.in": true,
                "gov.in": true,
                // Russia
                "co.ru": true, "org.ru": true, "net.ru": true, "ac.ru": true,
                "gov.ru": true,
                // France
                "com.fr": true, "org.fr": true, "net.fr": true, "ac.fr": true,
                "gov.fr": true,
                // Other common multi-part TLDs
                "com.tw": true, "org.tw": true, "net.tw": true,
                "com.hk": true, "org.hk": true, "net.hk": true,
                "com.sg": true, "org.sg": true, "net.sg": true, "gov.sg": true,
                "com.my": true, "org.my": true, "net.my": true, "gov.my": true,
                "com.ph": true, "org.ph": true, "net.ph": true,
                "com.pk": true, "org.pk": true, "net.pk": true,
                "com.ar": true, "org.ar": true, "net.ar": true,
                "com.mx": true, "org.mx": true, "net.mx": true,
                "com.tr": true, "org.tr": true, "net.tr": true,
                "com.ua": true, "org.ua": true, "net.ua": true,
                "com.pl": true, "org.pl": true, "net.pl": true,
                "com.pt": true, "org.pt": true, "net.pt": true,
                "com.es": true, "org.es": true, "net.es": true,
                "com.it": true, "org.it": true, "net.it": true,
                "co.id": true, "or.id": true, "web.id": true, "ac.id": true,
                "co.ke": true, "or.ke": true, "ac.ke": true,
        }
        return multiPartTLDs[s]
}
