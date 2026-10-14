package pipeline

import (
        "bufio"
        "context"
        "fmt"
        "net"
        "os"
        "path/filepath"
        "strconv"
        "strings"
        "time"

        "github.com/reconx/reconx/internal/config"
        "github.com/reconx/reconx/internal/modules/alive"
        "github.com/reconx/reconx/internal/modules/cloud"
        "github.com/reconx/reconx/internal/modules/cors"
        "github.com/reconx/reconx/internal/modules/dirfuzz"
        "github.com/reconx/reconx/internal/modules/js"
        "github.com/reconx/reconx/internal/modules/params"
        "github.com/reconx/reconx/internal/modules/portscan"
        "github.com/reconx/reconx/internal/modules/report"
        "github.com/reconx/reconx/internal/modules/screenshot"
        "github.com/reconx/reconx/internal/modules/subdomain"
        "github.com/reconx/reconx/internal/modules/urls"
        "github.com/reconx/reconx/internal/modules/vuln"
        "github.com/reconx/reconx/internal/scope"
        "github.com/reconx/reconx/internal/store"
        "github.com/reconx/reconx/pkg/logger"
        "github.com/reconx/reconx/pkg/runner"
)

// guessPortService returns a friendly service name for common ports.
// Used when restoring ports from ports.txt during resume.
func guessPortService(port int) string {
        switch port {
        case 21:
                return "ftp"
        case 22:
                return "ssh"
        case 23:
                return "telnet"
        case 25:
                return "smtp"
        case 53:
                return "dns"
        case 80:
                return "http"
        case 110:
                return "pop3"
        case 143:
                return "imap"
        case 443:
                return "https"
        case 445:
                return "smb"
        case 587:
                return "smtp-tls"
        case 993:
                return "imaps"
        case 995:
                return "pop3s"
        case 1433:
                return "mssql"
        case 3306:
                return "mysql"
        case 3389:
                return "rdp"
        case 5432:
                return "postgres"
        case 5900:
                return "vnc"
        case 6379:
                return "redis"
        case 8080:
                return "http-alt"
        case 8443:
                return "https-alt"
        case 8888:
                return "jupyter"
        case 9200:
                return "elasticsearch"
        case 27017:
                return "mongodb"
        }
        return "unknown"
}

// Pipeline orchestrates the full recon workflow
type Pipeline struct {
        cfg    *config.Config
        store  *store.Store
        scope  *scope.Filter
        log    *logger.Logger
        outDir string
}

// New creates a Pipeline and its output directory.
// If cfg.ResumeDir is set, resumes from an existing scan directory.
func New(cfg *config.Config) (*Pipeline, error) {
        var outDir, scanID string

        if cfg.ResumeDir != "" {
                // Resume mode: use existing directory
                outDir = cfg.ResumeDir
                scanID = filepath.Base(outDir)
                if _, err := os.Stat(outDir); os.IsNotExist(err) {
                        return nil, fmt.Errorf("resume dir does not exist: %s", outDir)
                }
        } else {
                // Normal mode: create new scan directory
                scanID = fmt.Sprintf("scan-%d", time.Now().Unix())
                if len(cfg.Target.Domains) > 0 {
                        // For hyphenated domains, we keep the original
                        // format ("evil-corp.com-<ts>") and rely on
                        // extractDomainFromResumeDir to strip the
                        // trailing timestamp using a digits scan rather
                        // than LastIndex("-"). The string here stays
                        // human-readable.
                        scanID = cfg.Target.Domains[0] + "-" + fmt.Sprintf("%d", time.Now().Unix())
                }
                outDir = filepath.Join(cfg.Output.OutputDir, scanID)
                // 0700 (not 0755) — results.json can contain secrets
                // and the report is HTML with embedded credentials.
                // Owner-only access protects against local users
                // snooping on the scan output.
                if err := os.MkdirAll(outDir, 0700); err != nil {
                        return nil, fmt.Errorf("creating output dir: %w", err)
                }
        }

        logPath := filepath.Join(outDir, "reconx.log")
        log := logger.New(cfg.Output.Verbose, logPath)

        p := &Pipeline{
                cfg:    cfg,
                store:  store.New(scanID),
                scope:  scope.New(cfg),
                log:    log,
                outDir: outDir,
        }

        // If resuming, load existing results into store
        if cfg.ResumeDir != "" {
                if err := p.loadExistingResults(); err != nil {
                        log.Warn("Some existing results could not be loaded: %v", err)
                }
        }

        return p, nil
}

// loadExistingResults loads subdomains, alive hosts, URLs, and JS files
// from a previous scan output directory so later phases can resume.
//
// File formats (written by the corresponding phase modules):
//   subdomains.txt  → bare hostnames, one per line
//   alive.txt       → full URLs (https://host or http://host), one per line
//   urls.txt        → discovered URLs, one per line
//   urls_js.txt     → JS file URLs, one per line
//   ports.txt       → "host:port" lines, one per open port
func (p *Pipeline) loadExistingResults() error {
        loaded := []string{}

        // Load subdomains
        if subs, err := readLines(filepath.Join(p.outDir, "subdomains.txt")); err == nil {
                p.store.AddSubdomains(subs)
                loaded = append(loaded, fmt.Sprintf("%d subdomains", len(subs)))
        }

        // Load alive hosts — file contains URLs (https://host) per alive.go.saveAlive
        if hosts, err := readLines(filepath.Join(p.outDir, "alive.txt")); err == nil {
                for _, line := range hosts {
                        domain := stripURLToHost(line)
                        if domain == "" {
                                continue
                        }
                        url := line
                        if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
                                url = "https://" + line
                        }
                        p.store.AddHost(&store.Host{Domain: domain, Meta: map[string]string{"url": url}})
                }
                loaded = append(loaded, fmt.Sprintf("%d alive hosts", len(hosts)))
        }

        // Load URLs
        if urlList, err := readLines(filepath.Join(p.outDir, "urls.txt")); err == nil {
                p.store.AddURLs(urlList)
                loaded = append(loaded, fmt.Sprintf("%d URLs", len(urlList)))

                // Also populate parameter findings from discovered URLs (sample up to 1,000)
                urlsWithParams := params.FilterURLsWithParams(urlList)
                paramFindingsCount := 0
                sampleParams := urlsWithParams
                if len(sampleParams) > 1000 {
                        sampleParams = sampleParams[:1000]
                }
                for _, u := range sampleParams {
                        pKeys := params.ExtractParamsFromURL(u)
                        if len(pKeys) > 0 {
                                p.store.AddParamFinding(&store.ParamFinding{
                                        URL:    u,
                                        Method: "GET",
                                        Params: pKeys,
                                        Tool:   "url_parser",
                                })
                                paramFindingsCount++
                        }
                }
                if paramFindingsCount > 0 {
                        loaded = append(loaded, fmt.Sprintf("%d parameter endpoints", paramFindingsCount))
                }
        }

        // Load JS files
        if jsList, err := readLines(filepath.Join(p.outDir, "urls_js.txt")); err == nil {
                for _, js := range jsList {
                        p.store.AddJSFile(js)
                }
                loaded = append(loaded, fmt.Sprintf("%d JS files", len(jsList)))
        }

		// Load ports (optional — written by portscan module when SavePortsToTxt is called)
		if portList, err := readLines(filepath.Join(p.outDir, "ports.txt")); err == nil {
			for _, line := range portList {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) != 2 {
					continue
				}
				port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err != nil || port == 0 {
					continue
				}
				p.store.AddPort(&store.Port{
					Host:     strings.TrimSpace(parts[0]),
					Port:     port,
					Protocol: "tcp",
					Service:  guessPortService(port),
				})
			}
			loaded = append(loaded, fmt.Sprintf("%d ports", len(portList)))
		}

		// Load secrets (written by JS module: "[Type] Value — source=... file=...")
		if secLines, err := readLines(filepath.Join(p.outDir, "secrets.txt")); err == nil {
			secCount := 0
			for _, line := range secLines {
				line = strings.TrimSpace(line)
				if line == "" || !strings.HasPrefix(line, "[") {
					continue
				}
				endBracket := strings.Index(line, "]")
				if endBracket == -1 {
					continue
				}
				secType := line[1:endBracket]
				rest := strings.TrimSpace(line[endBracket+1:])

				var val, src, file string
				parts := strings.Split(rest, " — ")
				if len(parts) >= 1 {
					val = parts[0]
				}
				if len(parts) >= 2 {
					metaParts := strings.Split(parts[1], " ")
					for _, mp := range metaParts {
						if strings.HasPrefix(mp, "source=") {
							src = strings.TrimPrefix(mp, "source=")
						} else if strings.HasPrefix(mp, "file=") {
							file = strings.TrimPrefix(mp, "file=")
						}
					}
				}
				p.store.AddSecret(&store.Secret{
					Type:   secType,
					Value:  val,
					Source: src,
					File:   file,
				})
				secCount++
			}
			if secCount > 0 {
				loaded = append(loaded, fmt.Sprintf("%d secrets", secCount))
			}
		}

		// Load findings (written by vuln module: "[SEV] Name — Target (Template)")
		if findLines, err := readLines(filepath.Join(p.outDir, "findings.txt")); err == nil {
			findCount := 0
			for _, line := range findLines {
				line = strings.TrimSpace(line)
				if line == "" || !strings.HasPrefix(line, "[") {
					continue
				}
				endBracket := strings.Index(line, "]")
				if endBracket == -1 {
					continue
				}
				sev := strings.ToLower(line[1:endBracket])
				rest := strings.TrimSpace(line[endBracket+1:])

				parts := strings.Split(rest, " — ")
				name := rest
				target := ""
				tmpl := ""
				if len(parts) == 2 {
					name = parts[0]
					rem := parts[1]
					if startParen := strings.LastIndex(rem, " ("); startParen != -1 && strings.HasSuffix(rem, ")") {
						target = rem[:startParen]
						tmpl = rem[startParen+2 : len(rem)-1]
					} else {
						target = rem
					}
				}
				p.store.AddFinding(&store.Finding{
					Name:     name,
					Severity: sev,
					Target:   target,
					Template: tmpl,
				})
				findCount++
			}
			if findCount > 0 {
				loaded = append(loaded, fmt.Sprintf("%d findings", findCount))
			}
		}

		if len(loaded) > 0 {
			p.log.Info("Resumed: loaded %s", strings.Join(loaded, ", "))
		}
        return nil
}

// stripURLToHost extracts the hostname from a URL or hostname string.
// Returns "" if no host can be extracted.
func stripURLToHost(s string) string {
        s = strings.TrimSpace(s)
        // Case-insensitive scheme stripping — https://, HTTPS://, Http://
        lower := strings.ToLower(s)
        for _, scheme := range []string{"https://", "http://", "ftp://"} {
                if strings.HasPrefix(lower, scheme) {
                        s = s[len(scheme):]
                        break
                }
        }
        if idx := strings.IndexAny(s, "/?#"); idx != -1 {
                s = s[:idx]
        }
        // Strip :port
        if h, _, err := net.SplitHostPort(s); err == nil {
                s = h
        }
        return strings.ToLower(strings.TrimSpace(s))
}

// readLines reads a text file and returns non-empty lines
func readLines(path string) ([]string, error) {
        f, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer f.Close()
        var lines []string
        sc := bufio.NewScanner(f)
        sc.Buffer(make([]byte, 10*1024*1024), 10*1024*1024)
        for sc.Scan() {
                if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
                        lines = append(lines, l)
                }
        }
        return lines, sc.Err()
}

// Run executes the full pipeline
func (p *Pipeline) Run(ctx context.Context) error {
        defer p.log.Close()

        p.log.Banner("v1.0.0")

        // Print scan header
        p.log.Info("Scan ID:   %s", p.store.ScanID)
        p.log.Info("Output:    %s", p.outDir)
        p.log.Info("Log file:  %s/reconx.log", p.outDir)
        if len(p.cfg.Target.Domains) > 0 {
                p.log.Info("Domains:   %v", p.cfg.Target.Domains)
        }
        if len(p.cfg.Target.IPRanges) > 0 {
                p.log.Info("IP Ranges: %v", p.cfg.Target.IPRanges)
        }
        if len(p.cfg.Target.ASNs) > 0 {
                p.log.Info("ASNs:      %v", p.cfg.Target.ASNs)
        }
        if len(p.cfg.Scope.InScope) > 0 {
                p.log.Info("In-scope:  %d patterns", len(p.cfg.Scope.InScope))
        }
        if len(p.cfg.Scope.OutOfScope) > 0 {
                p.log.Info("Out-scope: %d patterns", len(p.cfg.Scope.OutOfScope))
        }
        if p.cfg.BugBountyHeader != "" {
                p.log.Info("BB Header: %s", p.cfg.BugBountyHeader)
        }
        p.log.Separator()

        p.checkTools()

        start := time.Now()

        // In resume mode, skip phases that already have output files.
        // Each phase writes a marker file when it completes successfully,
        // so we can reliably detect what to skip on --resume.
        	isResume := p.cfg.ResumeDir != ""
	hasSubdomains := fileHasContent(filepath.Join(p.outDir, "all_subs.txt")) || fileHasContent(filepath.Join(p.outDir, "subdomains.txt"))
	hasAlive     := fileHasContent(filepath.Join(p.outDir, "alive.txt"))
	hasPorts     := fileHasContent(filepath.Join(p.outDir, "ports.txt"))
	hasURLs      := fileHasContent(filepath.Join(p.outDir, "urls.txt"))
	hasDirs      := fileHasContent(filepath.Join(p.outDir, "dirs", "all_dirs.txt"))

        if isResume {
                stats := p.store.Stats()
                p.log.Info("Resume mode — loaded: %d subdomains, %d live hosts, %d ports, %d URLs",
                        stats["subdomains"], stats["live_hosts"], stats["open_ports"], stats["urls"])
        }

	// ── PHASE 1: Subdomain Enumeration ──────────────────────────────────────
	if p.cfg.Phases.SubdomainEnum && !(isResume && hasSubdomains) && ctx.Err() == nil {
		mod := subdomain.New(p.cfg, p.store, p.scope, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Subdomain phase: %v", err)
		}
		p.printInterim("After subdomain enum")
	}

	// ── PHASE 2: Alive Host Detection ───────────────────────────────────────
	if p.cfg.Phases.AliveCheck && !(isResume && hasAlive) && ctx.Err() == nil {
		mod := alive.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Alive check phase: %v", err)
		}
		p.printInterim("After alive check")
	}

	// ── PHASE 2.5: Screenshots (optional) ───────────────────────────────────
	if p.cfg.Phases.Screenshots && ctx.Err() == nil {
		mod := screenshot.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Screenshots phase: %v", err)
		}
	}

	// ── PHASE 3: Port Scanning ───────────────────────────────────────────────
	if p.cfg.Phases.PortScan && !(isResume && hasPorts) && ctx.Err() == nil {
		mod := portscan.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Port scan phase: %v", err)
		}
	}

	// ── PHASE 4: URL Discovery ───────────────────────────────────────────────
	if p.cfg.Phases.URLDiscovery && !(isResume && hasURLs) && ctx.Err() == nil {
		mod := urls.New(p.cfg, p.store, p.scope, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("URL discovery phase: %v", err)
		}
		p.printInterim("After URL discovery")
	}

	// ── PHASE 4.7: Directory & Content Fuzzing (Opt-in) ────────────────────
	if p.cfg.Phases.DirFuzz && !(isResume && hasDirs) && ctx.Err() == nil {
		mod := dirfuzz.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Dir fuzz phase: %v", err)
		}
		p.printInterim("After dir fuzzing")
	}

	// ── PHASE 4.8: Hidden Parameter Discovery ──────────────────────────────
	if p.cfg.Phases.Params && ctx.Err() == nil {
		mod := params.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Param discovery phase: %v", err)
		}
	}

	// ── PHASE 4.9: Cloud & S3 Bucket Enumeration ───────────────────────────
	if p.cfg.Phases.CloudEnum && ctx.Err() == nil {
		mod := cloud.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Cloud enum phase: %v", err)
		}
	}

	// ── PHASE 4.10: CORS Misconfiguration Scan ─────────────────────────────
	if p.cfg.Phases.CORS && ctx.Err() == nil {
		mod := cors.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("CORS scan phase: %v", err)
		}
	}

	// ── PHASE 5: JS & Secret Analysis ───────────────────────────────────────
	hasJSAnalysis := fileHasContent(filepath.Join(p.outDir, ".js_done"))
	if p.cfg.Phases.JSAnalysis && !(isResume && hasJSAnalysis) && ctx.Err() == nil {
		mod := js.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("JS analysis phase: %v", err)
		}
		_ = os.WriteFile(filepath.Join(p.outDir, ".js_done"), []byte("done"), 0644)
	}

	// ── PHASE 6: Vulnerability Scanning ─────────────────────────────────────
	hasVulnScan := fileHasContent(filepath.Join(p.outDir, ".vuln_done"))
	if p.cfg.Phases.VulnScan && !(isResume && hasVulnScan) && ctx.Err() == nil {
		mod := vuln.New(p.cfg, p.store, p.log, p.outDir)
		if err := mod.Run(ctx); err != nil && err != context.Canceled {
			p.log.Error("Vuln scan phase: %v", err)
		}
		_ = os.WriteFile(filepath.Join(p.outDir, ".vuln_done"), []byte("done"), 0600)
	}

        // ── PHASE 7: Report ──────────────────────────────────────────────────────
        if p.cfg.Phases.Report {
                p.log.Phase("Report Generation", "Saving results and building HTML report")

                if err := p.store.SaveJSON(p.outDir); err != nil {
                        p.log.Error("Failed to save JSON: %v", err)
                } else {
                        p.log.Success("JSON results: %s/results.json", p.outDir)
                }

                if p.cfg.Output.HTMLReport {
                        allTargets := append(p.cfg.Target.Domains, p.cfg.Target.IPRanges...)
                        if err := report.Generate(p.store, allTargets, p.outDir); err != nil {
                                p.log.Error("HTML report failed: %v", err)
                        } else {
                                p.log.Success("HTML report:  %s/report.html", p.outDir)
                        }
                }
        }

        p.printSummary(time.Since(start))
        return nil
}

// fileHasContent returns true if path exists and is non-empty.
// Used by resume mode to decide which phases to skip. Returns false
// for missing files; returns true as long as the file has any bytes.
func fileHasContent(path string) bool {
        fi, err := os.Stat(path)
        if err != nil {
                return false
        }
        return fi.Size() > 0
}

func (p *Pipeline) printInterim(label string) {
        stats := p.store.Stats()
        p.log.Info("[%s] subdomains:%d  live:%d  urls:%d  js:%d  findings:%d  secrets:%d",
                label,
                stats["subdomains"], stats["live_hosts"], stats["urls"],
                stats["js_files"], stats["findings"], stats["secrets"])
        p.log.Separator()
}

func (p *Pipeline) printSummary(dur time.Duration) {
        stats := p.store.Stats()
        fmt.Println()
        p.log.Phase("SCAN COMPLETE", fmt.Sprintf("Total elapsed: %s", dur.Round(time.Second)))
        p.log.Stat("Subdomains discovered", stats["subdomains"])
        p.log.Stat("Live hosts",           stats["live_hosts"])
        p.log.Stat("Open ports",           stats["open_ports"])
        p.log.Stat("URLs discovered",      stats["urls"])
        p.log.Stat("Directory findings",   stats["dir_results"])
        p.log.Stat("Parameters found",     stats["param_results"])
        p.log.Stat("JS files",             stats["js_files"])
        p.log.Stat("Cloud assets",         stats["cloud_assets"])
        p.log.Stat("CORS findings",        stats["cors_results"])
        p.log.Stat("Vulnerabilities",      stats["findings"])
        p.log.Stat("Secrets found",        stats["secrets"])
        p.log.Separator()
        p.log.Stat("Output directory",     p.outDir)
        p.log.Stat("Full log",             p.outDir+"/reconx.log")
        if p.cfg.Output.HTMLReport {
                p.log.Stat("HTML report",       p.outDir+"/report.html")
        }
        p.log.Stat("JSON results",         p.outDir+"/results.json")
        fmt.Println()
}

func (p *Pipeline) checkTools() {
        categories := []struct {
                label string
                tools []string
        }{
                {"Subdomain",  []string{"subfinder", "assetfinder", "amass", "findomain", "chaos", "puredns", "dnsx", "github-subdomains", "shuffledns", "massdns"}},
                {"Alive",      []string{"httpx", "curl", "wafw00f", "tlsx", "subjack"}},
                {"Ports",      []string{"naabu"}},
                {"URLs",       []string{"waybackurls", "gau", "gauplus", "katana", "hakrawler", "gospider", "paramspider"}},
                {"DirFuzz",    []string{"feroxbuster", "ffuf", "dirsearch"}},
                {"Params",     []string{"arjun", "dalfox", "getJS"}},
                {"Cloud/CORS", []string{"s3scanner", "cloud_enum", "corsy"}},
                {"JS/Secrets", []string{"mantra", "jsecret", "subjs", "trufflehog", "gitleaks"}},
                {"Vuln",       []string{"nuclei"}},
        }

        p.log.Phase("Tool Check", "Verifying installed tools and API tokens")

        totalAvail := 0
        totalMissing := 0

        for _, cat := range categories {
                var avail, missing []string
                for _, t := range cat.tools {
                        if runner.IsAvailable(t) {
                                avail = append(avail, t)
                                totalAvail++
                        } else {
                                missing = append(missing, t)
                                totalMissing++
                        }
                }
                if len(avail) > 0 {
                        p.log.Info("  %-12s ✓ %s", cat.label+":", joinGreen(avail))
                }
                if len(missing) > 0 {
                        p.log.Warn("  %-12s ✗ %s", cat.label+":", joinGray(missing))
                }
        }

        p.log.Separator()

        // Token check — every token unlocks an additional API source.
        // Even without any tokens, the pipeline still runs the binary-backed
        // tools + the free HTTP APIs (crt.sh, OTX, Anubis, etc.).
        tokens := []struct{ key, env, label string }{
                {"github",         "GITHUB_TOKEN",            "GitHub (github-subdomains + trufflehog)"},
                {"chaos",          "PDCP_API_KEY",            "Chaos dataset (ProjectDiscovery)"},
                {"shodan",         "SHODAN_API_KEY",          "Shodan (subdomains + ports)"},
                {"virustotal",     "VT_API_KEY",              "VirusTotal (subdomains, free tier OK)"},
                {"securitytrails", "SECURITYTRAILS_API_KEY",  "SecurityTrails (50 free reqs/month)"},
                {"censys",         "CENSYS_API_ID:SECRET",    "Censys (certificates, free tier OK)"},
        }
        anyToken := false
        for _, t := range tokens {
                if p.cfg.Tokens[t.key] != "" {
                        p.log.Info("  Token %-22s %s", t.key+":", "✓ set — "+t.label)
                        anyToken = true
                } else {
                        p.log.Debug("  Token %-22s not set (%s)", t.key+":", t.label)
                }
        }
        if !anyToken {
                p.log.Info("  No API tokens set — free sources still run (crt.sh, OTX, Anubis, etc.)")
                p.log.Info("  Set tokens via CLI flags (--shodan-key, --vt-key, ...) or env vars")
        }

        p.log.Info("Tools: %d available, %d missing", totalAvail, totalMissing)
        if totalMissing > 0 {
                p.log.Warn("Run 'bash install.sh' to install missing tools")
        }
        p.log.Separator()
}

func joinGreen(items []string) string {
        return "\033[92m" + joinItems(items) + "\033[0m"
}

func joinGray(items []string) string {
        return "\033[90m" + joinItems(items) + "\033[0m"
}

func joinItems(items []string) string {
        result := ""
        for i, s := range items {
                if i > 0 {
                        result += ", "
                }
                result += s
        }
        return result
}

// extractDomainFromResumeDir pulls the domain out of a directory name like
// "evil-corp.com-1700000000" or "example.com-1700000000". The previous code
// used strings.LastIndex("-") which broke for hyphenated domains — it would
// return "evil" instead of "evil-corp.com". We use a trailing-digits scan
// instead, which is more robust.
func extractDomainFromResumeDir(dir string) string {
        base := filepath.Base(dir)
        // Find the last "-" followed by a run of digits (the unix timestamp)
        for i := len(base) - 1; i >= 0; i-- {
                if base[i] == '-' {
                        rest := base[i+1:]
                        if rest != "" && isAllDigits(rest) {
                                return base[:i]
                        }
                }
        }
        // No trailing timestamp — assume the whole basename is the domain
        return base
}

func isAllDigits(s string) bool {
        if s == "" {
                return false
        }
        for _, c := range s {
                if c < '0' || c > '9' {
                        return false
                }
        }
        return true
}
