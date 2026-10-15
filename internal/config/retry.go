package config

import (
	"fmt"
	"sort"
	"strings"
)

// Source retry is deliberately limited to adapters with isolated execution paths.
var RetrySourcePhases = map[string]string{
	"httpx": "alive", "wafw00f": "alive", "amass": "subdomains", "subfinder": "subdomains",
	"waybackurls": "urls", "gau": "urls", "gauplus": "urls", "katana": "urls", "hakrawler": "urls", "gospider": "urls", "otx-api": "urls", "paramspider": "urls",
}
var PhaseNames = []string{"subdomains", "alive", "ports", "port-http", "screenshots", "urls", "directories", "params", "cloud", "cors", "js", "vulnerabilities"}

func NormalizeRetry(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		for _, name := range strings.Split(v, ",") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name != "" && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}
func (c *Config) ValidateRetry() error {
	if len(c.RetryPhases)+len(c.RetrySources) == 0 {
		if c.Refresh {
			return fmt.Errorf("--refresh requires --retry-phase or --retry-source with --resume")
		}
		return nil
	}
	if c.ResumeDir == "" {
		return fmt.Errorf("--retry-phase/--retry-source require --resume")
	}
	if len(c.RetryPhases) > 0 && len(c.RetrySources) > 0 {
		return fmt.Errorf("choose --retry-phase or --retry-source, not both")
	}
	for _, phase := range c.RetryPhases {
		valid := false
		for _, p := range PhaseNames {
			if phase == p {
				valid = true
			}
		}
		if !valid {
			return fmt.Errorf("unknown retry phase %q; use %s", phase, strings.Join(PhaseNames, ","))
		}
	}
	for _, source := range c.RetrySources {
		if _, ok := RetrySourcePhases[source]; !ok {
			var names []string
			for n := range RetrySourcePhases {
				names = append(names, n)
			}
			sort.Strings(names)
			return fmt.Errorf("unsupported retry source %q; use %s", source, strings.Join(names, ","))
		}
	}
	return nil
}
func (c *Config) HasRetry() bool { return len(c.RetryPhases)+len(c.RetrySources) > 0 }
func (c *Config) SelectsPhase(name string) bool {
	if !c.HasRetry() {
		return true
	}
	for _, phase := range c.RetryPhases {
		if phase == name {
			return true
		}
	}
	for _, source := range c.RetrySources {
		if RetrySourcePhases[source] == name {
			return true
		}
	}
	return false
}
func (c *Config) SelectsSource(name string) bool {
	if len(c.RetrySources) == 0 {
		return true
	}
	for _, source := range c.RetrySources {
		if source == name {
			return true
		}
	}
	return false
}
