package runner

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrDisabled = errors.New("tool disabled")
var ErrUnavailable = errors.New("required tool unavailable")

type ToolPolicy struct {
	Enabled   bool
	Path      string
	Flags     []string
	Timeout   time.Duration
	RateLimit int
}
type Policy struct {
	Tools     map[string]ToolPolicy
	Workers   int
	NoTimeout bool
	Header    string
	ProxyURL  string
	slots     chan struct{}
}
type policyKey struct{}
type observerKey struct{}
type commandObserverKey struct{}

// WithCommandObserver reports the resolved executable and effective arguments.
// Consumers must redact credentials before logging them.
func WithCommandObserver(ctx context.Context, fn func(string, []string)) context.Context {
	return context.WithValue(ctx, commandObserverKey{}, fn)
}

func WithPolicy(ctx context.Context, p Policy) context.Context {
	if p.Workers < 1 {
		p.Workers = 1
	}
	p.slots = make(chan struct{}, p.Workers)
	return context.WithValue(ctx, policyKey{}, &p)
}
func WithObserver(ctx context.Context, fn func(*Result)) context.Context {
	return context.WithValue(ctx, observerKey{}, fn)
}
func toolPolicy(p *Policy, name string) (string, ToolPolicy, bool) {
	for key, t := range p.Tools {
		if name == key || name == t.Path || filepath.Base(name) == key {
			return key, t, true
		}
	}
	return filepath.Base(name), ToolPolicy{}, false
}

// MergeFlags replaces complete flag/value pairs, never leaving orphan values behind.
// Fixed positional operands remain in their original order.
func MergeFlags(base, override []string) []string {
	type item struct {
		key  string
		args []string
	}
	booleans := map[string]bool{}
	for _, k := range strings.Fields("-silent -json -jsonl -no-color -stats -nf -nc -dr -fr -follow-redirects -fhr -follow-host-redirects -a -all -recursive -jc -k -e -subs --subs --insecure --no-state --auto-tune --stable --no-git --json --no-update --no-verification -recursion -resp-only -ptr -san -cn -s --quiet --quickscan") {
		booleans[k] = true
	}
	parse := func(a []string) []item {
		var out []item
		for i := 0; i < len(a); i++ {
			key := ""
			v := []string{a[i]}
			if strings.HasPrefix(a[i], "-") {
				key = strings.SplitN(a[i], "=", 2)[0]
				if !booleans[key] && !strings.Contains(a[i], "=") && i+1 < len(a) && !strings.HasPrefix(a[i+1], "-") {
					i++
					v = append(v, a[i])
				}
			}
			out = append(out, item{key, v})
		}
		return out
	}
	items := append(parse(base), parse(override)...)
	last := map[string]int{}
	for i, v := range items {
		if v.key != "" {
			last[v.key] = i
		}
	}
	var out []string
	for i, v := range items {
		if v.key == "" || last[v.key] == i {
			out = append(out, v.args...)
		}
	}
	return out
}
func policyArgs(key string, args []string, p *Policy, t ToolPolicy) []string {
	args = MergeFlags(args, t.Flags)
	if t.RateLimit > 0 {
		rate := strconv.Itoa(t.RateLimit)
		switch key {
		case "httpx", "nuclei":
			args = MergeFlags(args, []string{"-rate-limit", rate})
		case "naabu", "ffuf":
			args = MergeFlags(args, []string{"-rate", rate})
		case "katana":
			args = MergeFlags(args, []string{"-rl", rate})
		case "feroxbuster":
			args = MergeFlags(args, []string{"--rate-limit", rate})
		}
	}
	// Bound tool-internal parallelism as well as concurrent subprocesses.
	n := strconv.Itoa(p.Workers)
	switch key {
	case "httpx":
		args = MergeFlags(args, []string{"-threads", n})
	case "naabu", "nuclei", "katana":
		args = MergeFlags(args, []string{"-c", n})
	case "mantra", "ffuf", "feroxbuster":
		args = MergeFlags(args, []string{"-t", n})
	}
	if p.Header != "" {
		switch key {
		case "httpx", "nuclei", "katana", "ffuf", "feroxbuster", "dirsearch":
			args = append(args, "-H", p.Header)
		case "curl":
			args = append(args, "-H", p.Header)
		}
	}
	// Do not allow custom flags to re-enable cross-host redirect following.
	if key == "httpx" {
		var clean []string
		for _, a := range args {
			if a != "-follow-redirects" && a != "-fr" && a != "-follow-host-redirects" && a != "-fhr" {
				clean = append(clean, a)
			}
		}
		args = clean
	}
	if key == "nuclei" {
		args = MergeFlags(args, []string{"-dr"})
	}
	if p.ProxyURL != "" {
		switch key {
		case "httpx", "nuclei", "katana", "hakrawler", "gospider":
			args = MergeFlags(args, []string{"-proxy", p.ProxyURL})
		case "ffuf":
			args = MergeFlags(args, []string{"-x", p.ProxyURL})
		case "feroxbuster", "dirsearch":
			args = MergeFlags(args, []string{"--proxy", p.ProxyURL})
		case "wafw00f":
			args = MergeFlags(args, []string{"-p", p.ProxyURL})
		case "gowitness":
			args = MergeFlags(args, []string{"--chrome-proxy", p.ProxyURL})
		}
	}

	return args
}
