// ReconX is a scoped reconnaissance pipeline. All subprocesses inherit cancellation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/unsocialz2/reconx/internal/modules/report"
	"github.com/unsocialz2/reconx/internal/store"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/pipeline"
)

var version = "v1.2.0"

type listFlag []string

func (s *listFlag) String() string     { return strings.Join(*s, ",") }
func (s *listFlag) Set(v string) error { *s = append(*s, strings.TrimSpace(v)); return nil }
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	cfg := config.DefaultConfig()
	profile := "standard"
	for i, a := range args {
		if strings.HasPrefix(a, "--profile=") {
			profile = strings.TrimPrefix(a, "--profile=")
		} else if a == "--profile" || a == "-profile" {
			if i+1 >= len(args) {
				return fmt.Errorf("--profile requires a value")
			}
			profile = args[i+1]
		}
	}
	if err := config.ApplyProfile(cfg, profile); err != nil {
		return err
	}
	// Load configuration first so explicitly supplied CLI options win regardless of order.
	for i, arg := range args {
		if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			if err := config.Load(cfg, strings.SplitN(arg, "=", 2)[1]); err != nil {
				return err
			}
		} else if arg == "--config" || arg == "-config" {
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a path")
			}
			if err := config.Load(cfg, args[i+1]); err != nil {
				return err
			}
		}
	}
	fs := flag.NewFlagSet("reconx", flag.ContinueOnError)
	var domains, ips, asns, cloudAssets listFlag
	var configPath, scopePath, reportDir, previousDir string
	var initConfig, showVersion, showDoctor bool
	fs.Var(&domains, "d", "Authorized domain (repeatable)")
	fs.Var(&ips, "ip", "Authorized IP or CIDR (repeatable)")
	fs.Var(&asns, "asn", "ASN for passive discovery (repeatable)")
	fs.Var(&cloudAssets, "cloud-asset", "Explicitly authorized cloud URL (repeatable)")
	fs.StringVar(&profile, "profile", profile, "Recon profile: quick, standard, deep or custom")
	fs.BoolVar(&showDoctor, "doctor", false, "Read-only tool and settings preflight (JSON)")
	fs.StringVar(&previousDir, "compare-with", "", "Compare an older checkpoint when rebuilding a report")
	fs.StringVar(&reportDir, "report-only", "", "Rebuild HTML from an existing checkpoint without scanning")
	fs.StringVar(&configPath, "config", "", "INI configuration path")
	fs.StringVar(&scopePath, "scope", "", "Scope include/exclude file")
	fs.StringVar(&cfg.Target.OrgName, "org", cfg.Target.OrgName, "Explicit GitHub organization")
	fs.StringVar(&cfg.Output.OutputDir, "output", cfg.Output.OutputDir, "Output directory")
	fs.StringVar(&cfg.ResumeDir, "resume", "", "Resume a scan with the same target/scope")
	fs.StringVar(&cfg.BugBountyHeader, "header", cfg.BugBountyHeader, "Testing header Name: Value")
	fs.StringVar(&cfg.WordlistPath, "wordlist", cfg.WordlistPath, "DNS wordlist")
	fs.StringVar(&cfg.ResolversPath, "resolvers", cfg.ResolversPath, "DNS resolvers file")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "Maximum concurrent subprocesses/requests")
	fs.BoolVar(&cfg.Output.Verbose, "verbose", cfg.Output.Verbose, "Verbose logs")
	fs.BoolVar(&cfg.NoTimeout, "no-timeout", cfg.NoTimeout, "Disable soft tool timeouts")
	fs.BoolVar(&cfg.Output.HTMLReport, "html-report", cfg.Output.HTMLReport, "Write HTML report")
	fs.BoolVar(&cfg.Output.JSONReport, "json-report", cfg.Output.JSONReport, "Write results.json export")
	fs.BoolVar(&cfg.Output.SaveRaw, "save-raw", cfg.Output.SaveRaw, "Keep raw files (checkpoint is always retained)")
	fs.BoolVar(&initConfig, "init", false, "Write reconx.ini and exit")
	fs.BoolVar(&showVersion, "version", false, "Print version and exit")
	skips := map[string]*bool{"subs": &cfg.Phases.SubdomainEnum, "alive": &cfg.Phases.AliveCheck, "ports": &cfg.Phases.PortScan, "urls": &cfg.Phases.URLDiscovery, "js": &cfg.Phases.JSAnalysis, "vuln": &cfg.Phases.VulnScan, "cloud": &cfg.Phases.CloudEnum, "cors": &cfg.Phases.CORS}
	skipValues := map[string]*bool{}
	for name, enabled := range skips {
		v := !*enabled
		skipValues[name] = &v
		fs.BoolVar(&v, "skip-"+name, v, "Skip "+name+" phase")
	}
	fs.BoolVar(&cfg.Phases.PortScan, "ports", cfg.Phases.PortScan, "Opt in to port scanning when permitted")
	fs.BoolVar(&cfg.Phases.VulnScan, "nuclei", cfg.Phases.VulnScan, "Opt in to Nuclei scanning when permitted")
	fs.BoolVar(&cfg.Phases.DirFuzz, "fuzz", cfg.Phases.DirFuzz, "Enable directory discovery")
	fs.BoolVar(&cfg.Phases.Params, "params", cfg.Phases.Params, "Enable parameter discovery")
	fs.BoolVar(&cfg.Phases.Screenshots, "screenshots", cfg.Phases.Screenshots, "Enable screenshots")
	tokenFlags := map[string]string{"github": "github-token", "chaos": "chaos-key", "shodan": "shodan-key", "virustotal": "vt-key", "securitytrails": "securitytrails-key"}
	tokenEnv := map[string]string{"github": "GITHUB_TOKEN", "chaos": "PDCP_API_KEY", "shodan": "SHODAN_API_KEY", "virustotal": "VT_API_KEY", "securitytrails": "SECURITYTRAILS_API_KEY"}
	tokenValues := map[string]*string{}
	for key, name := range tokenFlags {
		v := cfg.Tokens[key]
		if v == "" {
			v = os.Getenv(tokenEnv[key])
		}
		tokenValues[key] = &v
		fs.StringVar(&v, name, v, "API token; environment variable preferred")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if showVersion {
		fmt.Println(version)
		return nil
	}
	if initConfig {
		return config.WriteDefault("reconx.ini")
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if previousDir != "" && reportDir == "" {
		return fmt.Errorf("--compare-with requires --report-only")
	}
	if reportDir != "" {
		st, err := store.LoadSnapshot(filepath.Join(reportDir, "checkpoint.json"), func(string) bool { return true })
		if err != nil {
			return err
		}
		var manifest struct {
			Target config.Target `json:"target"`
		}
		if raw, err := os.ReadFile(filepath.Join(reportDir, "manifest.json")); err == nil {
			_ = json.Unmarshal(raw, &manifest)
		}
		if previousDir != "" {
			if err := report.Compare(previousDir, reportDir); err != nil {
				return err
			}
		}
		return report.Generate(st, manifest.Target.Domains, reportDir)
	}
	for name, value := range skipValues {
		if visited["skip-"+name] {
			*skips[name] = !*value
		}
	}
	if showDoctor {
		return doctor(cfg)
	}
	for key, value := range tokenValues {
		cfg.Tokens[key] = *value
	}
	if len(domains) > 0 {
		cfg.Target.Domains = domains
	}
	if len(ips) > 0 {
		cfg.Target.IPRanges = ips
	}
	if len(asns) > 0 {
		cfg.Target.ASNs = asns
	}
	if len(cloudAssets) > 0 {
		cfg.Target.CloudAssets = cloudAssets
	}
	for i, d := range cfg.Target.Domains {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
		if !validDomain(d) {
			return fmt.Errorf("invalid domain %q", d)
		}
		cfg.Target.Domains[i] = d
	}
	for _, ip := range cfg.Target.IPRanges {
		if net.ParseIP(ip) == nil {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				return fmt.Errorf("invalid IP/CIDR %q", ip)
			}
		}
	}
	if cfg.Workers < 1 || cfg.Workers > 256 {
		return fmt.Errorf("workers must be between 1 and 256")
	}
	if scopePath != "" {
		if err := cfg.LoadScope(scopePath); err != nil {
			return err
		}
	}
	if len(cfg.Target.Domains)+len(cfg.Target.IPRanges)+len(cfg.Target.ASNs) == 0 && cfg.ResumeDir == "" {
		return fmt.Errorf("provide -d, --ip, --asn, or --resume")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	p, err := pipeline.New(cfg)
	if err != nil {
		return err
	}
	return p.Run(ctx)
}

var domainPattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validDomain(value string) bool { return len(value) <= 253 && domainPattern.MatchString(value) }
