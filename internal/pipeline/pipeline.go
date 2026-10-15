package pipeline

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/modules/alive"
	"github.com/unsocialz2/reconx/internal/modules/cloud"
	"github.com/unsocialz2/reconx/internal/modules/cors"
	"github.com/unsocialz2/reconx/internal/modules/dirfuzz"
	"github.com/unsocialz2/reconx/internal/modules/js"
	"github.com/unsocialz2/reconx/internal/modules/params"
	"github.com/unsocialz2/reconx/internal/modules/portscan"
	"github.com/unsocialz2/reconx/internal/modules/report"
	"github.com/unsocialz2/reconx/internal/modules/screenshot"
	"github.com/unsocialz2/reconx/internal/modules/subdomain"
	"github.com/unsocialz2/reconx/internal/modules/urls"
	"github.com/unsocialz2/reconx/internal/modules/vuln"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
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
	cfg      *config.Config
	store    *store.Store
	scope    *scope.Filter
	log      *logger.Logger
	outDir   string
	manifest *Manifest
}

// New creates a Pipeline and its output directory.
// If cfg.ResumeDir is set, resumes from an existing scan directory.
func New(cfg *config.Config) (*Pipeline, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Workers < 1 {
		return nil, fmt.Errorf("workers must be positive")
	}
	var outDir string
	manifest := &Manifest{SchemaVersion: 1, Phases: map[string]PhaseState{}}
	if cfg.ResumeDir != "" {
		outDir = cfg.ResumeDir
		data, err := os.ReadFile(filepath.Join(outDir, "manifest.json"))
		if err != nil {
			return nil, fmt.Errorf("resume requires a versioned manifest: %w", err)
		}
		if err = json.Unmarshal(data, manifest); err != nil {
			return nil, err
		}
		if manifest.SchemaVersion != 1 {
			return nil, fmt.Errorf("unsupported manifest schema")
		}
		if len(cfg.Target.Domains)+len(cfg.Target.IPRanges)+len(cfg.Target.ASNs) == 0 {
			cfg.Target = manifest.Target
		}
		// Restore recorded scope only if the caller did not supply replacement patterns.
		if len(cfg.Scope.InScope)+len(cfg.Scope.OutOfScope) == 0 && cfg.Scope.Imported == nil {
			cfg.Scope = manifest.Scope
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		if manifest.WorkFingerprint != "" {
			if manifest.WorkFingerprint != workFingerprint(cfg) {
				return nil, fmt.Errorf("resume target/scope/tool arguments changed; start a new scan")
			}
		} else if manifest.Fingerprint != fingerprint(cfg) {
			return nil, fmt.Errorf("legacy resume fingerprint changed; use original configuration once to migrate before adjusting budgets")
		}
		manifest.WorkFingerprint = workFingerprint(cfg)
	} else {
		if err := os.MkdirAll(cfg.Output.OutputDir, 0700); err != nil {
			return nil, err
		}
		prefix := "scan-"
		if len(cfg.Target.Domains) > 0 {
			prefix = cfg.Target.Domains[0] + "-"
		}
		var err error
		outDir, err = os.MkdirTemp(cfg.Output.OutputDir, prefix)
		if err != nil {
			return nil, err
		}
		manifest.Target = cfg.Target
		manifest.Scope = cfg.Scope
		manifest.Fingerprint = fingerprint(cfg)
		manifest.WorkFingerprint = workFingerprint(cfg)
	}
	log := logger.New(cfg.Output.Verbose, filepath.Join(outDir, "reconx.log"))
	if err := scope.New(cfg).ValidateDiscoverySeeds(); err != nil {
		log.Close()
		return nil, err
	}
	p := &Pipeline{cfg: cfg, store: store.New(filepath.Base(outDir)), scope: scope.New(cfg), log: log, outDir: outDir, manifest: manifest}
	if err := p.validateSelection(); err != nil {
		log.Close()
		return nil, err
	}
	if cfg.ResumeDir != "" {
		st, err := store.LoadSnapshot(filepath.Join(outDir, "checkpoint.json"), p.scope.IsInScope)
		if err != nil {
			log.Close()
			return nil, fmt.Errorf("loading checkpoint: %w", err)
		}
		p.store = st
	}
	return p, nil
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
	p.cfg.ToolStatus = func(tool, status string) { p.store.AddCoverage("tool " + tool + ": " + status) }
	proxyURL, stopProxy, err := p.scope.StartProxy(ctx)
	if err != nil {
		return err
	}
	defer stopProxy()
	policy := p.cfg.RunnerPolicy()
	policy.ProxyURL = proxyURL
	ctx = runner.WithPolicy(ctx, policy)
	ctx = runner.WithTaskDirectory(ctx, filepath.Join(p.outDir, "tasks"))
	ctx = runner.WithRefresh(ctx, p.cfg.Refresh)
	mode := "new"
	if p.cfg.ResumeDir != "" {
		mode = "resume"
	}
	if len(p.cfg.RetryPhases) > 0 {
		mode = "retry-phase"
	}
	if len(p.cfg.RetrySources) > 0 {
		mode = "retry-source"
	}
	if p.cfg.Refresh {
		mode = "refresh"
	}
	p.manifest.Runs = append(p.manifest.Runs, RunRecord{StartedAt: time.Now(), Mode: mode, Phases: p.cfg.RetryPhases, Sources: p.cfg.RetrySources})
	currentRun := &p.manifest.Runs[len(p.manifest.Runs)-1]
	p.log.Banner("v1.2.0")
	p.log.Info("Scan ID: %s", p.store.ScanID)
	p.log.Info("Output: %s", p.outDir)
	p.log.Info("Scope: %d domain seeds, %d IP/ranges | ports=%t nuclei=%t", len(p.cfg.Target.Domains), len(p.cfg.Target.IPRanges), p.cfg.Phases.PortScan, p.cfg.Phases.VulnScan)
	if imported := p.cfg.Scope.Imported; imported != nil {
		allowed, excluded := 0, 0
		for _, a := range imported.Assets {
			if a.Excluded {
				excluded++
			} else {
				allowed++
			}
		}
		p.log.Info("Imported scope: %s | %d include, %d exclude, %d unsupported rows skipped", imported.Format, allowed, excluded, len(imported.Skipped))
		p.log.Info("CSV boundaries: exact hosts, subdomains-only wildcards, scheme/port-specific HTTP origins; exclusions win")
	}
	p.log.Info("HTTP controls: %.2f requests/s per host (built-in), %d retries for GET/HEAD 429/503", p.cfg.HostRPS, p.cfg.HTTPRetries)
	events, err := os.OpenFile(filepath.Join(p.outDir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer events.Close()
	var eventMu sync.Mutex
	var eventErr error
	emit := func(kind, phase, tool, status string) {
		eventMu.Lock()
		defer eventMu.Unlock()
		record := map[string]any{"time": time.Now().UTC(), "event": kind, "phase": phase, "tool": tool, "status": status}
		if err := json.NewEncoder(events).Encode(record); err != nil {
			eventErr = errors.Join(eventErr, err)
		}
	}
	var phaseErrors []error
	run := func(name string, enabled bool, fn func(context.Context) error) {
		if !p.cfg.SelectsPhase(name) {
			return
		}
		prior, recorded := p.manifest.Phases[name]
		if !enabled && p.cfg.ResumeDir != "" && recorded {
			return
		}
		if !enabled {
			p.manifest.Phases[name] = PhaseState{Status: "skipped", Reason: "disabled by configuration"}
			emit("phase.finished", name, "", "skipped")
			return
		}
		if p.cfg.ResumeDir != "" && !p.cfg.HasRetry() && prior.Status == "completed" {
			p.log.Info("Resume: %s completed; skipping", name)
			return
		}
		if ctx.Err() != nil {
			p.manifest.Phases[name] = PhaseState{Status: "skipped", Reason: "scan canceled"}
			return
		}
		state := PhaseState{Status: "running", StartedAt: time.Now(), Attempts: prior.Attempts + 1, Sources: p.cfg.RetrySources}
		if p.cfg.ResumeDir != "" {
			p.markDependentsStale(name)
		}
		emit("phase.started", name, "", "running")
		p.manifest.Phases[name] = state
		if err := p.checkpoint(); err != nil {
			phaseErrors = append(phaseErrors, err)
			return
		}
		var failures []string
		var mu sync.Mutex
		phaseCtx := runner.WithCommandObserver(ctx, func(path string, args []string) {
			p.log.EffectiveToolCmd(path, args)
		})
		phaseCtx = runner.WithTaskObserver(phaseCtx, func(e runner.TaskEvent) {
			mu.Lock()
			defer mu.Unlock()
			switch e.State {
			case "reused":
				state.Tasks.Reused++
			case "completed":
				state.Tasks.Executed++
			case "partial":
				state.Tasks.Executed++
				state.Tasks.Failed++
			case "pending":
				state.Tasks.Pending++
			}
			emit("task."+e.State, name, e.Tool, e.State)
		})
		plans := map[string]bool{}
		p.cfg.BudgetStatus = func(plan config.BudgetPlan) {
			mu.Lock()
			defer mu.Unlock()
			key := fmt.Sprintf("%s:%d:%d", plan.Tool, plan.Inputs, plan.Seconds)
			if plans[key] {
				return
			}
			plans[key] = true
			state.Budgets = append(state.Budgets, plan)
			p.log.Info("Budget %s: %s | %d inputs | %s | estimate=%ds capped=%t", plan.Tool, (time.Duration(plan.Seconds) * time.Second).String(), plan.Inputs, plan.Mode, plan.EstimatedSeconds, plan.Capped)
		}
		phaseCtx = runner.WithObserver(phaseCtx, func(r *runner.Result) {
			mu.Lock()
			state.Tasks.CommandAttempts++
			mu.Unlock()
			status := "completed"
			if r.Err != nil {
				status = "partial"
			}
			emit("tool.finished", name, filepath.Base(r.Tool), status)
			if r.Err != nil && !errors.Is(r.Err, runner.ErrDisabled) && !(strings.Contains(r.Tool, "gitleaks") && r.ExitCode == 1) {
				mu.Lock()
				failures = append(failures, r.DiagString())
				mu.Unlock()
			}
		})
		err := fn(phaseCtx)
		p.cfg.BudgetStatus = nil
		state.FinishedAt = time.Now()
		state.Status = "completed"
		if errors.Is(err, runner.ErrUnavailable) || errors.Is(err, runner.ErrDisabled) {
			state.Status = "skipped"
			state.Reason = err.Error()
		} else if err != nil || len(failures) > 0 || ctx.Err() != nil {
			state.Status = "partial"
			state.Reason = strings.Join(failures, "; ")
			if err != nil {
				state.Reason = err.Error()
			}
			if ctx.Err() != nil {
				state.Reason = ctx.Err().Error()
			}
			phaseErrors = append(phaseErrors, fmt.Errorf("%s incomplete: %s", name, state.Reason))
		}
		if state.Status == "completed" && len(p.cfg.RetrySources) > 0 && prior.Status != "completed" {
			state.Status = "partial"
			state.Reason = "Selected sources completed; prior whole-phase coverage was " + prior.Status + ". Retry the full phase to reassess remaining coverage."
			phaseErrors = append(phaseErrors, fmt.Errorf("%s incomplete: %s", name, state.Reason))
		}
		currentRun.Tasks.CommandAttempts += state.Tasks.CommandAttempts
		currentRun.Tasks.Reused += state.Tasks.Reused
		currentRun.Tasks.Executed += state.Tasks.Executed
		currentRun.Tasks.Failed += state.Tasks.Failed
		currentRun.Tasks.Pending += state.Tasks.Pending
		p.log.Info("Phase %s jobs: %d reused, %d executed, %d failed, %d pending", name, state.Tasks.Reused, state.Tasks.Executed, state.Tasks.Failed, state.Tasks.Pending)
		if state.Status != "completed" {
			p.log.Warn("Phase %s: %s — %s", name, state.Status, state.Reason)
			p.store.AddCoverage(name + ": " + state.Status + " — " + state.Reason)
		}
		p.manifest.Phases[name] = state
		emit("phase.finished", name, "", state.Status)
		if err := p.checkpoint(); err != nil {
			phaseErrors = append(phaseErrors, err)
		}
	}
	run("subdomains", p.cfg.Phases.SubdomainEnum, func(c context.Context) error { return subdomain.New(p.cfg, p.store, p.scope, p.log, p.outDir).Run(c) })
	run("alive", p.cfg.Phases.AliveCheck, func(c context.Context) error { return alive.New(p.cfg, p.store, p.log, p.outDir).Run(c) })
	run("ports", p.cfg.Phases.PortScan, func(c context.Context) error {
		if !p.cfg.ToolAvailable("naabu") {
			return runner.ErrUnavailable
		}
		return portscan.New(p.cfg, p.store, p.log, p.outDir).Run(c)
	})
	run("port-http", p.cfg.Phases.AliveCheck && p.cfg.Phases.PortScan, func(c context.Context) error { return alive.New(p.cfg, p.store, p.log, p.outDir).ProbePorts(c) })
	run("screenshots", p.cfg.Phases.Screenshots, func(c context.Context) error {
		if !p.cfg.ToolAvailable("gowitness") {
			return runner.ErrUnavailable
		}
		return screenshot.New(p.cfg, p.store, p.log, p.outDir).Run(c)
	})
	run("urls", p.cfg.Phases.URLDiscovery, func(c context.Context) error { return urls.New(p.cfg, p.store, p.scope, p.log, p.outDir).Run(c) })
	run("directories", p.cfg.Phases.DirFuzz, func(c context.Context) error {
		if !p.cfg.ToolAvailable("feroxbuster") && !p.cfg.ToolAvailable("dirsearch") && !p.cfg.ToolAvailable("ffuf") {
			return runner.ErrUnavailable
		}
		return dirfuzz.New(p.cfg, p.store, p.log, p.outDir).Run(c)
	})
	run("params", p.cfg.Phases.Params, func(c context.Context) error { return params.New(p.cfg, p.store, p.log, p.outDir).Run(c) })
	run("cloud", p.cfg.Phases.CloudEnum, func(c context.Context) error { return cloud.New(p.cfg, p.store, p.log, p.outDir).Run(c) })
	run("cors", p.cfg.Phases.CORS, func(c context.Context) error { return cors.New(p.cfg, p.store, p.log, p.outDir).Run(c) })
	run("js", p.cfg.Phases.JSAnalysis, func(c context.Context) error {
		if !p.cfg.ToolAvailable("secretfinder") && !p.cfg.ToolAvailable("gitleaks") && !p.cfg.ToolAvailable("trufflehog") && !p.cfg.ToolAvailable("mantra") && !p.cfg.ToolAvailable("jsecret") {
			return runner.ErrUnavailable
		}
		return js.New(p.cfg, p.store, p.log, p.outDir).Run(c)
	})
	run("vulnerabilities", p.cfg.Phases.VulnScan, func(c context.Context) error {
		if !p.cfg.ToolAvailable("nuclei") {
			return runner.ErrUnavailable
		}
		return vuln.New(p.cfg, p.store, p.log, p.outDir).Run(c)
	})
	currentRun.FinishedAt = time.Now()
	currentRun.Status = "completed"
	if len(phaseErrors) > 0 {
		currentRun.Status = "partial"
	}
	if ctx.Err() != nil {
		currentRun.Status = "cancelled"
	}
	if err := p.checkpoint(); err != nil {
		phaseErrors = append(phaseErrors, err)
	}
	if p.cfg.Phases.Report {
		if p.cfg.Output.JSONReport {
			if err := p.store.SaveJSON(p.outDir); err != nil {
				phaseErrors = append(phaseErrors, err)
			}
		}
		if p.cfg.Output.HTMLReport {
			if err := report.Generate(p.store, p.cfg.Target.Domains, p.outDir); err != nil {
				phaseErrors = append(phaseErrors, err)
			}
		}
	}
	if !p.cfg.Output.SaveRaw {
		if err := p.removeRawOutputs(); err != nil {
			phaseErrors = append(phaseErrors, err)
		}
	}
	if eventErr != nil {
		phaseErrors = append(phaseErrors, eventErr)
	}
	p.printSummary(time.Since(p.store.StartTime))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(phaseErrors...)
}

type PhaseState struct {
	Attempts   int                 `json:"attempts,omitempty"`
	Sources    []string            `json:"sources,omitempty"`
	Tasks      runner.TaskStats    `json:"tasks"`
	Budgets    []config.BudgetPlan `json:"budgets,omitempty"`
	Status     string              `json:"status"`
	Reason     string              `json:"reason,omitempty"`
	StartedAt  time.Time           `json:"started_at,omitempty"`
	FinishedAt time.Time           `json:"finished_at,omitempty"`
}
type Manifest struct {
	WorkFingerprint string                `json:"work_fingerprint,omitempty"`
	Runs            []RunRecord           `json:"runs,omitempty"`
	SchemaVersion   int                   `json:"schema_version"`
	Fingerprint     string                `json:"fingerprint"`
	Target          config.Target         `json:"target"`
	Scope           config.Scope          `json:"scope"`
	Phases          map[string]PhaseState `json:"phases"`
}

func fingerprint(cfg *config.Config) string {
	data, _ := json.Marshal(struct {
		Target config.Target
		Scope  config.Scope
		Tools  map[string]config.ToolConfig
	}{cfg.Target, cfg.Scope, cfg.Tools})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func (p *Pipeline) checkpoint() error {
	if err := p.store.SaveSnapshot(filepath.Join(p.outDir, "checkpoint.json")); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p.manifest, "", "  ")
	if err != nil {
		return err
	}
	return store.AtomicWrite(filepath.Join(p.outDir, "manifest.json"), data, 0600)
}
func (p *Pipeline) removeRawOutputs() error {
	entries, err := os.ReadDir(p.outDir)
	if err != nil {
		return err
	}
	keep := map[string]bool{"checkpoint.json": true, "manifest.json": true, "results.json": p.cfg.Output.JSONReport, "report.html": p.cfg.Output.HTMLReport, "reconx.log": true, "screenshots": true, "tasks": true, "events.jsonl": true}
	for _, e := range entries {
		if !keep[e.Name()] {
			if err := os.RemoveAll(filepath.Join(p.outDir, e.Name())); err != nil {
				return err
			}
		}
	}
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
	p.log.Phase("SCAN FINISHED", fmt.Sprintf("Total elapsed: %s", dur.Round(time.Second)))
	p.log.Stat("Subdomains discovered", stats["subdomains"])
	p.log.Stat("Live hosts", stats["live_hosts"])
	p.log.Stat("Open ports", stats["open_ports"])
	p.log.Stat("URLs discovered", stats["urls"])
	p.log.Stat("Directory findings", stats["dir_results"])
	p.log.Stat("Parameters found", stats["param_results"])
	p.log.Stat("JS files", stats["js_files"])
	p.log.Stat("Cloud assets", stats["cloud_assets"])
	p.log.Stat("CORS findings", stats["cors_results"])
	p.log.Stat("Vulnerabilities", stats["findings"])
	p.log.Stat("Secrets found", stats["secrets"])
	p.log.Separator()
	p.log.Stat("Output directory", p.outDir)
	p.log.Stat("Full log", p.outDir+"/reconx.log")
	if p.cfg.Output.HTMLReport {
		p.log.Stat("HTML report", p.outDir+"/report.html")
	}
	p.log.Stat("JSON results", p.outDir+"/results.json")
	fmt.Println()
}

func (p *Pipeline) checkTools() {
	categories := []struct {
		label string
		tools []string
	}{
		{"Subdomain", []string{"subfinder", "assetfinder", "amass", "findomain", "chaos", "puredns", "dnsx", "github-subdomains", "shuffledns", "massdns"}},
		{"Alive", []string{"httpx", "curl", "wafw00f", "tlsx", "subjack"}},
		{"Ports", []string{"naabu"}},
		{"URLs", []string{"waybackurls", "gau", "gauplus", "katana", "hakrawler", "gospider", "paramspider"}},
		{"DirFuzz", []string{"feroxbuster", "ffuf", "dirsearch"}},
		{"Params", []string{"arjun", "dalfox", "getJS"}},
		{"Cloud/CORS", []string{"s3scanner", "cloud_enum", "corsy"}},
		{"JS/Secrets", []string{"mantra", "jsecret", "subjs", "trufflehog", "gitleaks"}},
		{"Vuln", []string{"nuclei"}},
	}

	p.log.Phase("Tool Check", "Verifying installed tools and API tokens")

	totalAvail := 0
	totalMissing := 0

	for _, cat := range categories {
		if (cat.label == "Ports" && !p.cfg.Phases.PortScan) || (cat.label == "Vuln" && !p.cfg.Phases.VulnScan) {
			p.log.Info("  %s: disabled (opt in)", cat.label)
			continue
		}
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
		{"github", "GITHUB_TOKEN", "GitHub (github-subdomains + trufflehog)"},
		{"chaos", "PDCP_API_KEY", "Chaos dataset (ProjectDiscovery)"},
		{"shodan", "SHODAN_API_KEY", "Shodan (subdomains + ports)"},
		{"virustotal", "VT_API_KEY", "VirusTotal (subdomains, free tier OK)"},
		{"securitytrails", "SECURITYTRAILS_API_KEY", "SecurityTrails (50 free reqs/month)"},
		{"censys", "CENSYS_API_ID:SECRET", "Censys (certificates, free tier OK)"},
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
