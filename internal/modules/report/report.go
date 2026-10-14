package report

import (
        "fmt"
        "html/template"
        "net/url"
        "os"
        "path/filepath"
        "sort"
        "strings"
        "time"

        "github.com/reconx/reconx/internal/store"
)

// ReportData holds everything needed to render the HTML report
type ReportData struct {
	ScanID      string
	Targets     []string
	StartTime   time.Time
	Duration    string
	GeneratedAt string

	TotalSubdomains int
	TotalLiveHosts  int
	TotalPorts      int
	TotalURLs       int
	TotalJSFiles    int
	TotalFindings   int
	TotalSecrets    int
	TotalParams     int
	TotalWAFHosts   int
	TotalNonWAFHosts int

	Subdomains []store.SubdomainEntry
	Hosts      []*store.Host
	WAFHosts   []*store.Host  // hosts behind WAF
	NoWAFHosts []*store.Host  // hosts not behind WAF
	WAFMap     map[string]bool // domain -> is WAF protected (fast O(1) lookup in template)
	Ports      []*store.Port
	Findings   []*store.Finding
	Secrets    []*store.Secret
	URLs       []string // sorted list of all discovered URLs (capped)
	JSFiles    []string // sorted list of all JS file URLs
	Params     []string // discovered parameter keys (all, deduplicated)
	WAFParams  []string // params from WAF-protected hosts
	NoWAFParams []string // params from non-WAF hosts
	ParamFindings []*ParamFindingItem // Detailed parameter-to-endpoint mappings
	WAFResults  []*store.WAFResult // WAF detection results

	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int

	HasScreenshots bool
	ScreenshotDir  string
	// HostScreenshots maps domain → relative path to screenshot.png
	HostScreenshots map[string]string

	// Pre-computed chart data so the template stays simple
	SeverityChart []chartSlice
	StatusChart   []chartSlice
	PortChart     []chartSlice
	TechChart     []chartSlice
	SourceChart   []chartSlice

	// Unique values for filter chips
	AllStatusCodes []int
	AllTech        []string
	AllSources     []string
	AllPorts       []int
	AllSeverities  []string
}

type chartSlice struct {
        Label string
        Value int
}

// ParamFindingItem represents an endpoint-parameter pair with security context
type ParamFindingItem struct {
	Param   string
	URL     string
	TestURL string // Full endpoint URL with the parameter attached for testing
	Method  string
	IsWAF   bool
	Tool    string
}

// buildTestURL ensures the parameter is visibly present in the URL for direct testing and linking.
func buildTestURL(targetURL, param string) string {
	if strings.Contains(targetURL, param+"=") {
		return targetURL
	}
	sep := "?"
	if strings.Contains(targetURL, "?") {
		sep = "&"
	}
	return targetURL + sep + param + "=FUZZ"
}

// Generate creates the HTML report file
func Generate(st *store.Store, targets []string, outDir string) error {
        hosts := st.GetHosts()
        subs := st.GetSubdomainsWithSource()
        // subs is already sorted by subdomain name from the store
        sort.Slice(subs, func(i, j int) bool {
                return subs[i].Subdomain < subs[j].Subdomain
        })

        // Sort hosts by domain
        sort.Slice(hosts, func(i, j int) bool {
                return hosts[i].Domain < hosts[j].Domain
        })

        // Sort findings by severity (critical first)
        findings := st.Findings
        sort.Slice(findings, func(i, j int) bool {
                return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
        })

        // Sort ports by host then port
        ports := st.Ports
        sort.Slice(ports, func(i, j int) bool {
                if ports[i].Host != ports[j].Host {
                        return ports[i].Host < ports[j].Host
                }
                return ports[i].Port < ports[j].Port
        })

        // Get URLs and JS files via public API (returns sorted slices)
        urlList := st.GetURLs()
        jsList := st.GetJSFiles()

        // In the HTML report, cap rendered URLs to top 5,000 to keep the report file lightweight
        // (all 1M+ raw URLs are permanently saved in urls/urls_all.txt and category files)
        displayURLs := urlList
        sort.Strings(displayURLs) // deterministic truncation (GetURLs() is already sorted, but defensive)
        if len(displayURLs) > 5000 {
                displayURLs = displayURLs[:5000]
        }

	allSecrets := st.Secrets
	if len(allSecrets) == 0 {
		if raw, err := os.ReadFile(filepath.Join(outDir, "secrets.txt")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
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
					for _, mp := range strings.Split(parts[1], " ") {
						if strings.HasPrefix(mp, "source=") {
							src = strings.TrimPrefix(mp, "source=")
						} else if strings.HasPrefix(mp, "file=") {
							file = strings.TrimPrefix(mp, "file=")
						}
					}
				}
				allSecrets = append(allSecrets, &store.Secret{
					Type:   secType,
					Value:  val,
					Source: src,
					File:   file,
				})
			}
		}
	}

	allFindings := findings
	if len(allFindings) == 0 {
		if raw, err := os.ReadFile(filepath.Join(outDir, "findings.txt")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
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
				allFindings = append(allFindings, &store.Finding{
					Name:     name,
					Severity: sev,
					Target:   target,
					Template: tmpl,
				})
			}
		}
	}

	// Redact secret values before they go into the HTML report.
	redactedSecrets := redactSecrets(allSecrets)

	data := &ReportData{
		ScanID:          st.ScanID,
		Targets:         targets,
		StartTime:       st.StartTime,
		Duration:        time.Since(st.StartTime).Round(time.Second).String(),
		GeneratedAt:     time.Now().Format("2006-01-02 15:04:05 UTC"),
		TotalSubdomains: len(subs),
		TotalLiveHosts:  len(hosts),
		TotalPorts:      len(ports),
		TotalURLs:       len(urlList),
		TotalJSFiles:    len(jsList),
		TotalFindings:   len(allFindings),
		TotalSecrets:    len(allSecrets),
		Subdomains:      subs,
		Hosts:           hosts,
		Ports:           ports,
		Findings:        allFindings,
		Secrets:         redactedSecrets,
		URLs:            displayURLs,
                JSFiles:         jsList,
                WAFResults:      st.WAFResults,
        }

	// WAF-split hosts
	data.WAFMap = make(map[string]bool)
	for _, h := range hosts {
		if st.IsWAFProtected(h.Domain) {
			data.WAFHosts = append(data.WAFHosts, h)
			data.WAFMap[h.Domain] = true
		} else {
			data.NoWAFHosts = append(data.NoWAFHosts, h)
		}
	}
	data.TotalWAFHosts = len(data.WAFHosts)
	data.TotalNonWAFHosts = len(data.NoWAFHosts)

	// Params from files
	if raw, err := os.ReadFile(filepath.Join(outDir, "params_all.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				data.Params = append(data.Params, line)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(outDir, "params_waf.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				data.WAFParams = append(data.WAFParams, line)
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(outDir, "params_nowaf.txt")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				data.NoWAFParams = append(data.NoWAFParams, line)
			}
		}
	}
	data.TotalParams = len(data.Params)

	// Build detailed parameter endpoints table
	seenParamFinding := make(map[string]bool)
	paramURLCount := make(map[string]int)
	const maxEndpointsPerParam = 5
	const maxTotalParamFindings = 2000

	// 1. First include active tool discoveries (arjun, x8, dalfox, paramspider)
	for _, pr := range st.GetParamResults() {
		if pr.Tool == "url_parser" || pr.Tool == "" {
			continue // handled in step 2 with sampling
		}
		for _, p := range pr.Params {
			key := fmt.Sprintf("%s|%s|%s", p, pr.URL, pr.Method)
			if !seenParamFinding[key] {
				seenParamFinding[key] = true
				data.ParamFindings = append(data.ParamFindings, &ParamFindingItem{
					Param:   p,
					URL:     pr.URL,
					TestURL: buildTestURL(pr.URL, p),
					Method:  pr.Method,
					IsWAF:   st.IsWAFProtected(pr.URL),
					Tool:    pr.Tool,
				})
			}
		}
	}

	// 2. Then sample from url_parser endpoints up to maxTotalParamFindings
	for _, pr := range st.GetParamResults() {
		if len(data.ParamFindings) >= maxTotalParamFindings {
			break
		}
		if pr.Tool != "url_parser" && pr.Tool != "" {
			continue // already handled above
		}
		for _, p := range pr.Params {
			if paramURLCount[p] >= maxEndpointsPerParam {
				continue
			}
			key := fmt.Sprintf("%s|%s|%s", p, pr.URL, pr.Method)
			if !seenParamFinding[key] {
				seenParamFinding[key] = true
				paramURLCount[p]++
				tool := pr.Tool
				if tool == "" {
					tool = "url_query"
				}
				data.ParamFindings = append(data.ParamFindings, &ParamFindingItem{
					Param:   p,
					URL:     pr.URL,
					TestURL: buildTestURL(pr.URL, p),
					Method:  pr.Method,
					IsWAF:   st.IsWAFProtected(pr.URL),
					Tool:    tool,
				})
				if len(data.ParamFindings) >= maxTotalParamFindings {
					break
				}
			}
		}
	}

	// 3. Sample representative parameter-bearing endpoints directly from all discovered URLs
	for _, rawURL := range urlList {
		if len(data.ParamFindings) >= maxTotalParamFindings {
			break
		}
		if strings.Contains(rawURL, "?") && strings.Contains(rawURL, "=") {
			u, err := url.Parse(rawURL)
			if err != nil || u.RawQuery == "" {
				continue
			}
			vals, err := url.ParseQuery(u.RawQuery)
			if err != nil {
				continue
			}
			isWaf := st.IsWAFProtected(rawURL)
			for k := range vals {
				k = strings.TrimSpace(k)
				if k == "" || paramURLCount[k] >= maxEndpointsPerParam {
					continue
				}
				key := fmt.Sprintf("%s|%s|GET", k, rawURL)
				if !seenParamFinding[key] {
					seenParamFinding[key] = true
					paramURLCount[k]++
					data.ParamFindings = append(data.ParamFindings, &ParamFindingItem{
						Param:   k,
						URL:     rawURL,
						TestURL: buildTestURL(rawURL, k),
						Method:  "GET",
						IsWAF:   isWaf,
						Tool:    "url_query",
					})
					if len(data.ParamFindings) >= maxTotalParamFindings {
						break
					}
				}
			}
		}
	}

	// Sort ParamFindings alphabetically by param then URL
	sort.Slice(data.ParamFindings, func(i, j int) bool {
		if data.ParamFindings[i].Param != data.ParamFindings[j].Param {
			return data.ParamFindings[i].Param < data.ParamFindings[j].Param
		}
		return data.ParamFindings[i].URL < data.ParamFindings[j].URL
	})

	// Screenshot discovery: look for screenshots/<domain>/screenshot.png
	ssDir := filepath.Join(outDir, "screenshots")
	data.HostScreenshots = make(map[string]string)
	if entries, err := os.ReadDir(ssDir); err == nil {
		data.HasScreenshots = true
		data.ScreenshotDir = "screenshots"
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			ssPath := filepath.Join(ssDir, e.Name(), "screenshot.png")
			if _, err := os.Stat(ssPath); err == nil {
				// Relative path from outDir for HTML src attribute
				data.HostScreenshots[e.Name()] = "screenshots/" + e.Name() + "/screenshot.png"
			}
		}
		if len(data.HostScreenshots) == 0 {
			data.HasScreenshots = false
		}
	}


        for _, f := range findings {
                switch strings.ToLower(f.Severity) {
                case "critical":
                        data.CriticalCount++
                case "high":
                        data.HighCount++
                case "medium":
                        data.MediumCount++
                case "low":
                        data.LowCount++
                }
        }

        // Build chart data
        data.SeverityChart = []chartSlice{
                {"Critical", data.CriticalCount},
                {"High", data.HighCount},
                {"Medium", data.MediumCount},
                {"Low", data.LowCount},
        }
        data.StatusChart = buildStatusChart(hosts)
        data.PortChart = buildPortChart(ports)
        data.TechChart = buildTechChart(hosts)
        data.SourceChart = buildSourceChart(subs)

        // Build filter chip values
        data.AllStatusCodes = uniqueStatusCodes(hosts)
        data.AllTech = uniqueTech(hosts)
        data.AllSources = uniqueSources(subs)
        data.AllPorts = uniquePorts(ports)
        data.AllSeverities = []string{"critical", "high", "medium", "low"}

        tmpl, err := template.New("report").Funcs(template.FuncMap{
                "upper": strings.ToUpper,
                "lower": strings.ToLower,
                "severityClass": func(s string) string {
                        switch strings.ToLower(s) {
                        case "critical":
                                return "sev-critical"
                        case "high":
                                return "sev-high"
                        case "medium":
                                return "sev-medium"
                        case "low":
                                return "sev-low"
                        default:
                                return "sev-info"
                        }
                },
                "statusClass": func(code int) string {
                        switch {
                        case code >= 200 && code < 300:
                                return "status-ok"
                        case code >= 300 && code < 400:
                                return "status-redirect"
                        case code == 403 || code == 401:
                                return "status-auth"
                        case code >= 400:
                                return "status-err"
                        default:
                                return ""
                        }
                },
                "divInt": func(num, denom, scale int) int {
                        if denom == 0 {
                                return 0
                        }
                        return num * scale / denom
                },
                "isURL": func(s string) bool {
                        return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
                },
                "urlsToList": func(d *ReportData) []string {
                        return d.URLs
                },
                "jsFilesToList": func(d *ReportData) []string {
                        return d.JSFiles
                },
                "liveSubdomainsList": func(d *ReportData) []string {
                        out := make([]string, 0, len(d.Hosts))
                        for _, h := range d.Hosts {
                                out = append(out, h.Domain)
                        }
                        return out
                },
                "json": func(v interface{}) (template.JS, error) {
                        // Marshal inline as JSON for the embedded data block.
                        // We use template.JS so the rendered output isn't escaped.
                        b, err := jsonMarshal(v)
                        if err != nil {
                                return "", err
                        }
                        return template.JS(b), nil
                },
        }).Parse(htmlTemplate)
        if err != nil {
                return fmt.Errorf("parsing template: %w", err)
        }

        path := filepath.Join(outDir, "report.html")
        f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
        if err != nil {
                return fmt.Errorf("creating report file: %w", err)
        }
        defer f.Close()

        if err := tmpl.Execute(f, data); err != nil {
                return fmt.Errorf("rendering template: %w", err)
        }
        return nil
}

// redactSecretValue returns a redacted form of a secret value. We keep
// enough to identify the secret (type + last 4 chars) but mask the body
// so the HTML report can be shared without leaking credentials.
func redactSecretValue(value string) string {
        if len(value) <= 8 {
                return "***REDACTED***"
        }
        return value[:4] + "***" + value[len(value)-4:]
}

// redactSecrets produces a copy of secrets with values redacted.
// The Type, Source, and File fields are preserved so the report still
// shows "AWS Access Key from jsecret in app.js" — just hides the key.
func redactSecrets(secrets []*store.Secret) []*store.Secret {
        out := make([]*store.Secret, len(secrets))
        for i, s := range secrets {
                out[i] = &store.Secret{
                        Type:   s.Type,
                        Value:  redactSecretValue(s.Value),
                        Source: s.Source,
                        File:   s.File,
                }
        }
        return out
}

// jsonMarshal is a thin wrapper around encoding/json that we can stub in tests.
// We use a custom function instead of importing encoding/json directly so the
// report package stays self-contained for review.
func jsonMarshal(v interface{}) ([]byte, error) {
        return jsonMarshalImpl(v)
}

func severityRank(s string) int {
        switch strings.ToLower(s) {
        case "critical":
                return 4
        case "high":
                return 3
        case "medium":
                return 2
        case "low":
                return 1
        default:
                return 0
        }
}

func buildStatusChart(hosts []*store.Host) []chartSlice {
        counts := map[int]int{}
        for _, h := range hosts {
                if h.StatusCode > 0 {
                        counts[h.StatusCode]++
                }
        }
        out := make([]chartSlice, 0, len(counts))
        for code, n := range counts {
                out = append(out, chartSlice{Label: fmt.Sprintf("%d", code), Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 10 {
                out = out[:10]
        }
        return out
}

func buildPortChart(ports []*store.Port) []chartSlice {
        counts := map[int]int{}
        for _, p := range ports {
                counts[p.Port]++
        }
        out := make([]chartSlice, 0, len(counts))
        for port, n := range counts {
                out = append(out, chartSlice{Label: fmt.Sprintf("%d", port), Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 15 {
                out = out[:15]
        }
        return out
}

func buildTechChart(hosts []*store.Host) []chartSlice {
        counts := map[string]int{}
        for _, h := range hosts {
                for _, t := range h.TechStack {
                        counts[t]++
                }
        }
        out := make([]chartSlice, 0, len(counts))
        for tech, n := range counts {
                out = append(out, chartSlice{Label: tech, Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 12 {
                out = out[:12]
        }
        return out
}

func buildSourceChart(subs []store.SubdomainEntry) []chartSlice {
        counts := map[string]int{}
        for _, s := range subs {
                if s.Source == "" {
                        s.Source = "unknown"
                }
                counts[s.Source]++
        }
        out := make([]chartSlice, 0, len(counts))
        for src, n := range counts {
                out = append(out, chartSlice{Label: src, Value: n})
        }
        sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
        if len(out) > 15 {
                out = out[:15]
        }
        return out
}

func uniqueStatusCodes(hosts []*store.Host) []int {
        seen := map[int]bool{}
        var out []int
        for _, h := range hosts {
                if h.StatusCode > 0 && !seen[h.StatusCode] {
                        seen[h.StatusCode] = true
                        out = append(out, h.StatusCode)
                }
        }
        sort.Ints(out)
        return out
}

func uniqueTech(hosts []*store.Host) []string {
        seen := map[string]bool{}
        var out []string
        for _, h := range hosts {
                for _, t := range h.TechStack {
                        if !seen[t] {
                                seen[t] = true
                                out = append(out, t)
                        }
                }
        }
        sort.Strings(out)
        return out
}

func uniqueSources(subs []store.SubdomainEntry) []string {
        seen := map[string]bool{}
        var out []string
        for _, s := range subs {
                if s.Source == "" {
                        s.Source = "unknown"
                }
                if !seen[s.Source] {
                        seen[s.Source] = true
                        out = append(out, s.Source)
                }
        }
        sort.Strings(out)
        return out
}

func uniquePorts(ports []*store.Port) []int {
        seen := map[int]bool{}
        var out []int
        for _, p := range ports {
                if !seen[p.Port] {
                        seen[p.Port] = true
                        out = append(out, p.Port)
                }
        }
        sort.Ints(out)
        return out
}
