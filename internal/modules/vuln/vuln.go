package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
	"github.com/unsocialz2/reconx/pkg/util"
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
	m.log.Phase("Vulnerability Scanning",
		"nuclei templates: exposures, CVEs, misconfigs, takeovers, default-logins")

	start := time.Now()
	hosts := m.store.GetHosts()
	if len(hosts) == 0 {
		m.log.Warn("No live hosts to scan — vuln scanning skipped")
		return nil
	}

	tcfg := m.cfg.Tools["nuclei"]
	nucleiPath := "nuclei"
	if tcfg.Path != "" {
		nucleiPath = tcfg.Path
	}

	if !m.cfg.ToolAvailable(nucleiPath) {
		m.log.ToolSkipped("nuclei",
			"binary not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
		m.log.Info("After installing: nuclei -update-templates")
		return nil
	}

	m.log.Debug("nuclei version: %s (path: %s)", runner.Version(nucleiPath), runner.WhichPath(nucleiPath))

	// Build target lists separated by WAF status
	allURLs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if u, ok := h.Meta["url"]; ok {
			allURLs = append(allURLs, u)
		} else {
			allURLs = append(allURLs, "https://"+h.Domain)
		}
	}

	dataDir := store.DataDir(m.outDir)
	wafURLs, nowafURLs := m.store.SplitURLsByWAF(allURLs)

	// Save targets in data/
	targetFileNoWAF := dataDir + "/nuclei_targets_nowaf.txt"
	targetFileWAF := dataDir + "/nuclei_targets_waf.txt"
	_ = store.SaveRaw(targetFileNoWAF, nowafURLs)
	_ = store.SaveRaw(targetFileWAF, wafURLs)
	_ = store.SaveRaw(dataDir+"/nuclei_targets_all.txt", allURLs)

	m.log.Info("nuclei targets — non-WAF: %d URLs (fast) | WAF-protected: %d URLs (stealth)",
		len(nowafURLs), len(wafURLs))

	// Template categories ordered by speed and impact (fastest & highest-yield first).
	// Running fast, high-confidence categories first (takeovers, misconfigs, exposures, default-logins)
	// ensures immediate findings without being blocked behind 4,000+ CVE templates.
	categories := []struct {
		name     string
		template string
		timeout  int // base per-category timeout in seconds
	}{
		{"takeovers", "http/takeovers", 180},
		{"misconfigs", "http/misconfiguration", 240},
		{"exposures", "http/exposures", 300},
		{"default-logins", "http/default-logins", 240},
		{"cves", "http/cves", 420},
	}

	totalFindings := 0

	type targetGroup struct {
		label      string
		targetFile string
		count      int
		rateLimit  string
		retries    string
		timeoutSec string
	}

	groups := []targetGroup{
		{label: "non-waf", targetFile: targetFileNoWAF, count: len(nowafURLs), rateLimit: "150", retries: "2", timeoutSec: "5"},
		{label: "waf", targetFile: targetFileWAF, count: len(wafURLs), rateLimit: "60", retries: "1", timeoutSec: "5"},
	}

	for _, g := range groups {
		if g.count == 0 {
			continue
		}

		m.log.Info("Running nuclei on %s targets (%d endpoints, rate-limit: %s)...", g.label, g.count, g.rateLimit)

		baseArgs := []string{
			"-l", g.targetFile,
			"-jsonl",
			"-no-color",
			"-retries", g.retries,
			"-timeout", g.timeoutSec,
			"-rate-limit", g.rateLimit,
			"-max-host-error", "30",
			"-c", "50",
			"-bulk-size", "25",
			"-stats",
			"-si", "30",
		}

		if m.cfg.BugBountyHeader != "" {
			baseArgs = append(baseArgs, "-H", m.cfg.BugBountyHeader)
		}
		baseArgs = append(baseArgs, tcfg.Flags...)

		// Per-category timeouts scale with target count: factor +1 step per 50 targets,
		// capped at 15 min for quick categories and 25 min for CVEs.
		// A hard timeout is strictly enforced even when global --no-timeout is active.
		scale := (g.count + 49) / 50 // ceil(count/50)
		if scale < 1 {
			scale = 1
		}
		const maxCatTimeout = 15 * time.Minute
		const maxCveTimeout = 25 * time.Minute

		for _, cat := range categories {
			select {
			case <-ctx.Done():
				m.log.Warn("nuclei: context cancelled — stopping at category %s (%s)", cat.name, g.label)
				return ctx.Err()
			default:
			}

			catCap := maxCatTimeout
			if cat.name == "cves" {
				catCap = maxCveTimeout
			}

			catTimeout := time.Duration(cat.timeout*scale) * time.Second
			if catTimeout > catCap {
				catTimeout = catCap
			}
			if (m.cfg.NoTimeout || runner.IsNoTimeout()) && catTimeout < 25*time.Minute {
				catTimeout = 25 * time.Minute
			}

			args := append(append([]string{}, baseArgs...), "-t", cat.template)
			toolTag := fmt.Sprintf("nuclei:%s:%s", g.label, cat.name)
			m.log.Tool(toolTag, fmt.Sprintf("%d targets", g.count))
			m.log.ToolCmd("nuclei", args, "")

			catStart := time.Now()
			catFindings := 0
			parseErrors := 0

			rawFile, openErr := os.OpenFile(filepath.Join(dataDir, "nuclei_"+g.label+"_"+cat.name+".jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if openErr != nil {
				return openErr
			}
			r := runner.Run(ctx, nucleiPath, args,
				runner.WithTimeout(catTimeout),
				runner.WithHardTimeout(catTimeout),
				runner.WithStderrCallback(func(line string) {
					line = strings.TrimSpace(util.StripANSI(line))
					if strings.Contains(line, "Templates:") || strings.Contains(line, "RPS:") || strings.Contains(line, "%") {
						m.log.Info("nuclei[%s/%s]: %s", g.label, cat.name, line)
					} else {
						m.log.Debug("nuclei[%s/%s]: %s", g.label, cat.name, util.Truncate(line, 120))
					}
				}),
				runner.WithLineCallback(func(line string) {
					line = strings.TrimSpace(line)
					if line == "" || !strings.HasPrefix(line, "{") {
						return
					}
					if _, err := fmt.Fprintln(rawFile, line); err != nil {
						parseErrors++
						return
					}
					f := parseNucleiLine(line)
					if f == nil {
						parseErrors++
						return
					}
					m.store.AddFinding(f)
					catFindings++
					totalFindings++
					m.log.Finding(f.Severity, f.Name, f.Target)
				}))

			if err := rawFile.Close(); err != nil {
				return err
			}
			if r.IsTimeout() {
				m.log.ToolTimeout(toolTag, catFindings, catTimeout)
			} else if r.Err != nil && catFindings == 0 {
				if len(r.Stderr) > 0 {
					m.log.ToolError(toolTag, fmt.Errorf("%s", r.DiagString()), r.Stderr)
				} else {
					m.log.Debug("nuclei[%s/%s]: no findings (exit %d)", g.label, cat.name, r.ExitCode)
					m.log.ToolDone(toolTag, 0, time.Since(catStart))
				}
			} else {
				m.log.ToolDone(toolTag, catFindings, time.Since(catStart))
			}

			if parseErrors > 0 {
				m.log.Warn("nuclei[%s/%s]: %d JSON parse errors", g.label, cat.name, parseErrors)
			}
		}
	}

	m.log.PhaseComplete("Vulnerability Scanning", totalFindings, time.Since(start))

	if totalFindings > 0 {
		m.logFindingSummary()
		// Save findings.txt for resume support + downstream tools
		lines := make([]string, 0, len(m.store.Findings))
		for _, f := range m.store.Findings {
			lines = append(lines, fmt.Sprintf("[%s] %s — %s (%s)",
				strings.ToUpper(f.Severity), f.Name, f.Target, f.Template))
		}
		if err := store.SaveRaw(m.outDir+"/findings.txt", lines); err != nil {
			m.log.Warn("Could not save findings.txt: %v", err)
		}
	}
	return nil
}

func (m *Module) logFindingSummary() {
	counts := map[string]int{}
	for _, f := range m.store.Findings {
		counts[strings.ToLower(f.Severity)]++
	}
	parts := []string{}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", strings.ToUpper(sev), n))
		}
	}
	if len(parts) > 0 {
		m.log.Info("Finding severity breakdown: %s", strings.Join(parts, "  "))
	}
}

func parseNucleiLine(line string) *store.Finding {
	var result struct {
		Template   string `json:"template-id"`
		TemplateID string `json:"templateID"`
		Info       struct {
			Name        string `json:"name"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
		} `json:"info"`
		MatchedAt string `json:"matched-at"`
		Host      string `json:"host"`
		URL       string `json:"url"`
	}
	if json.Unmarshal([]byte(line), &result) != nil {
		return nil
	}
	if result.Template == "" {
		result.Template = result.TemplateID
	}
	if result.Template == "" {
		return nil
	}
	severity := strings.ToLower(result.Info.Severity)
	switch severity {
	case "critical", "high", "medium", "low":
	default:
		return nil
	}
	name := result.Info.Name
	if name == "" {
		name = result.Template
	}
	target := result.MatchedAt
	if target == "" {
		target = result.Host
	}
	if target == "" {
		target = result.URL
	}
	return &store.Finding{Name: name, Severity: severity, Target: target, Template: result.Template, Description: result.Info.Description, Evidence: line}
}
