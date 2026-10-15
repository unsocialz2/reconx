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
	RequestRate int
	Tools       map[string]ToolPolicy
	Workers     int
	NoTimeout   bool
	Header      string
	ProxyURL    string
	slots       chan struct{}
}
type policyKey struct{}
type observerKey struct{}
type commandObserverKey struct{}
type processObserverKey struct{}

// WithProcessObserver reports subprocess start and reap, including quiet tools.
func WithProcessObserver(ctx context.Context, fn func(pid int, alive bool)) context.Context {
	return context.WithValue(ctx, processObserverKey{}, fn)
}

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
	if parent, ok := ctx.Value(observerKey{}).(func(*Result)); ok {
		return context.WithValue(ctx, observerKey{}, func(r *Result) { parent(r); fn(r) })
	}
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
	// Migrate legacy aliases so old INI files cannot reintroduce invalid flags.
	normalize := func(items []string) []string {
		out := append([]string(nil), items...)
		for i, arg := range out {
			parts := strings.SplitN(arg, "=", 2)
			if (key == "mantra" || key == "naabu") && (parts[0] == "-threads" || parts[0] == "--threads") {
				flag := "-t"
				if key == "naabu" {
					flag = "-c"
				}
				out[i] = flag
				if len(parts) == 2 {
					out[i] += "=" + parts[1]
				}
			}
		}
		return out
	}
	args = MergeFlags(normalize(args), normalize(t.Flags))
	rateLimit := t.RateLimit
	if p.RequestRate > 0 && (rateLimit == 0 || rateLimit > p.RequestRate) {
		rateLimit = p.RequestRate
	}
	if rateLimit > 0 {
		rate := strconv.Itoa(rateLimit)
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
	case "katana":
		args = MergeFlags(args, []string{"-c", n, "-p", "1"})
	case "naabu", "nuclei":
		args = MergeFlags(args, []string{"-c", n})
	case "gau":
		// GAU/GAUPlus already fan out across hosts up to Workers subprocesses.
		args = MergeFlags(args, []string{"--threads", "1"})
	case "gauplus":
		args = MergeFlags(args, []string{"-t", "1"})
	case "gospider":
		args = MergeFlags(args, []string{"-t", "1", "-c", n})
	case "mantra", "ffuf", "feroxbuster", "hakrawler":
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
