// ReconX is a scoped reconnaissance pipeline. All subprocesses inherit cancellation.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/pipeline"
)

var version = "v1.1.0"

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
	var configPath, scopePath string
	var initConfig, showVersion bool
	fs.Var(&domains, "d", "Authorized domain (repeatable)")
	fs.Var(&ips, "ip", "Authorized IP or CIDR (repeatable)")
	fs.Var(&asns, "asn", "ASN for passive discovery (repeatable)")
	fs.Var(&cloudAssets, "cloud-asset", "Explicitly authorized cloud URL (repeatable)")
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
	for name, value := range skipValues {
		*skips[name] = !*value
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
