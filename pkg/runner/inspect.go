package runner

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Inspection struct {
	Status      string   `json:"status"`
	Version     string   `json:"version"`
	Required    []string `json:"required_flags,omitempty"`
	Unsupported []string `json:"unsupported_flags,omitempty"`
	Note        string   `json:"note,omitempty"`
}

var helpFlagPattern = regexp.MustCompile(`--?[A-Za-z][A-Za-z0-9_-]*`)

func advertisedFlags(help string) map[string]bool {
	out := map[string]bool{}
	for _, bounds := range helpFlagPattern.FindAllStringIndex(help, -1) {
		start, end := bounds[0], bounds[1]
		if start > 0 && !strings.ContainsRune(" \t\r\n,[|('", rune(help[start-1])) {
			continue
		}
		if end < len(help) && !strings.ContainsRune(" \t\r\n,=]|)'", rune(help[end])) {
			continue
		}
		out[help[start:end]] = true
	}
	return out
}

// Inspect only invokes help/version with empty stdin and bounded process groups.
// It checks adapters' required and effective policy flags, not API credentials.
func Inspect(ctx context.Context, key, path string, p Policy) Inspection {
	required := map[string][]string{
		"httpx":  {"-json", "-nf", "-threads", "-timeout", "-retries", "-status-code", "-title", "-web-server", "-content-length", "-tech-detect", "-favicon"},
		"katana": {"-list", "-c", "-p"}, "mantra": {"-s", "-t"},
		"gau": {"--subs", "--threads", "--providers"}, "hakrawler": {"-subs", "-u", "-insecure", "-t"},
		"gospider":  {"-S", "-t", "-c", "-d", "--sitemap", "--robots"},
		"naabu":     {"-json", "-silent", "-top-ports", "-c"},
		"nuclei":    {"-l", "-jsonl", "-no-color", "-retries", "-timeout", "-max-host-error", "-bulk-size", "-stats", "-si", "-t", "-c", "-dr"},
		"subfinder": {"-d", "-all", "-silent", "-nc"}, "dnsx": {"-silent", "-resp-only", "-ptr"},
	}
	base, known := required[key]
	if !known {
		return Inspection{Status: "not_checked", Version: "unknown", Note: "No validated help adapter; availability alone does not establish flag compatibility."}
	}
	_, t, _ := toolPolicy(&p, key)
	p.ProxyURL = "http://127.0.0.1:1"
	args := policyArgs(key, base, &p, t)
	expected := map[string]bool{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			expected[strings.SplitN(arg, "=", 2)[0]] = true
		}
	}
	result := Inspection{Status: "compatible", Version: "unknown"}
	for flag := range expected {
		result.Required = append(result.Required, flag)
	}
	sort.Strings(result.Required)
	r := Run(ctx, path, []string{"-h"}, WithHardTimeout(2*time.Second), WithStdin(""))
	if r.IsTimeout() || ctx.Err() != nil {
		result.Status = "check_failed"
		result.Note = "Help probe deadline exceeded"
		return result
	}
	help := strings.Join(append(r.Lines, r.Stderr...), "\n")
	flags := advertisedFlags(help)
	if len(flags) == 0 {
		result.Status = "check_failed"
		result.Note = "Help output did not advertise flags"
		return result
	}
	for _, flag := range result.Required {
		if !flags[flag] {
			result.Unsupported = append(result.Unsupported, flag)
		}
	}
	if len(result.Unsupported) > 0 {
		result.Status = "incompatible"
		result.Note = "Required flags missing from installed binary help"
	}
	result.Version = versionFromLines(strings.Split(help, "\n"))
	if result.Version == "unknown" {
		versionFlag := ""
		switch key {
		case "httpx", "katana", "subfinder", "dnsx", "naabu", "nuclei":
			versionFlag = "-version"
		case "gau", "gospider":
			versionFlag = "--version"
		}
		if versionFlag != "" {
			r = Run(ctx, path, []string{versionFlag}, WithHardTimeout(2*time.Second), WithStdin(""))
			result.Version = versionFromLines(append(r.Lines, r.Stderr...))
		}
	}
	return result
}
