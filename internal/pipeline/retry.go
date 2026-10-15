package pipeline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/pkg/runner"
)

type RunRecord struct {
	Status     string           `json:"status"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt time.Time        `json:"finished_at"`
	Mode       string           `json:"mode"`
	Phases     []string         `json:"phases,omitempty"`
	Sources    []string         `json:"sources,omitempty"`
	Tasks      runner.TaskStats `json:"tasks"`
}

func workFingerprint(cfg *config.Config) string {
	type semanticTool struct {
		Enabled bool
		Path    string
		Flags   []string
		Extra   map[string]string
	}
	tools := map[string]semanticTool{}
	for name, t := range cfg.Tools {
		tools[name] = semanticTool{t.Enabled, t.Path, t.Flags, t.Extra}
	}
	data, _ := json.Marshal(struct {
		Target config.Target
		Scope  config.Scope
		Tools  map[string]semanticTool
		Header string
	}{cfg.Target, cfg.Scope, tools, cfg.BugBountyHeader})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func (p *Pipeline) phaseEnabled(name string) bool {
	switch name {
	case "subdomains":
		return p.cfg.Phases.SubdomainEnum
	case "alive":
		return p.cfg.Phases.AliveCheck
	case "ports":
		return p.cfg.Phases.PortScan
	case "port-http":
		return p.cfg.Phases.PortScan && p.cfg.Phases.AliveCheck
	case "urls":
		return p.cfg.Phases.URLDiscovery
	case "js":
		return p.cfg.Phases.JSAnalysis
	case "cors":
		return p.cfg.Phases.CORS
	case "cloud":
		return p.cfg.Phases.CloudEnum
	case "directories":
		return p.cfg.Phases.DirFuzz
	case "params":
		return p.cfg.Phases.Params
	case "screenshots":
		return p.cfg.Phases.Screenshots
	case "vulnerabilities":
		return p.cfg.Phases.VulnScan
	}
	return false
}
func (p *Pipeline) validateSelection() error {
	if !p.cfg.HasRetry() {
		return nil
	}
	for _, name := range config.PhaseNames {
		if p.cfg.SelectsPhase(name) && !p.phaseEnabled(name) {
			return fmt.Errorf("selected phase %s is disabled; supply its explicit opt-in flag/configuration", name)
		}
	}
	for _, name := range p.cfg.RetrySources {
		if name != "otx-api" && name != "httpx" && !p.cfg.ToolAvailable(name) {
			return fmt.Errorf("selected source %s is unavailable; install it or check its configured path", name)
		}
		if tool, ok := p.cfg.Tools[name]; ok && !tool.Enabled {
			return fmt.Errorf("selected source %s is disabled in configuration", name)
		}
	}
	return nil
}

// Changed upstream observations leave downstream results intact but stale.
func (p *Pipeline) markDependentsStale(upstream string) {
	dependencies := map[string][]string{
		"subdomains": {"alive", "ports", "port-http", "urls", "screenshots", "directories", "params", "cors", "js", "vulnerabilities"},
		"alive":      {"ports", "port-http", "urls", "screenshots", "directories", "params", "cors", "js", "vulnerabilities"},
		"ports":      {"port-http", "urls", "screenshots", "directories", "params", "cors", "js", "vulnerabilities"},
		"port-http":  {"urls", "screenshots", "directories", "params", "cors", "js", "vulnerabilities"},
		"urls":       {"params", "js", "vulnerabilities"}, "params": {"vulnerabilities"}, "js": {"vulnerabilities"},
	}
	for _, name := range dependencies[upstream] {
		state, ok := p.manifest.Phases[name]
		if ok && state.Status == "completed" {
			state.Status = "stale"
			state.Reason = "Upstream " + upstream + " was retried; retained observations need a follow-up phase run"
			p.manifest.Phases[name] = state
		}
	}
}
