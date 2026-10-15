package report

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/unsocialz2/reconx/internal/store"
)

// These are review heuristics over saved observations, never vulnerability scores.
type reviewAsset struct {
	Host         string   `json:"host"`
	Priority     string   `json:"priority"`
	Score        int      `json:"score"`
	Availability string   `json:"availability"`
	URLs         int      `json:"urls"`
	Groups       int      `json:"endpoint_groups"`
	JS           int      `json:"js_files"`
	Candidates   int      `json:"candidates"`
	Reasons      []string `json:"reasons"`
	Checks       []string `json:"suggested_checks"`
}

type endpointGroup struct {
	Origin     string   `json:"origin"`
	Host       string   `json:"host"`
	Route      string   `json:"route"`
	Count      int      `json:"observations"`
	Variants   int      `json:"query_shapes"`
	Parameters []string `json:"parameters"`
	Methods    []string `json:"observed_methods"`
	Signals    []string `json:"signals"`
	Examples   []string `json:"examples"`
	Sources    []string `json:"evidence_sources"`
}

type groupBuilder struct {
	endpointGroup
	urls, shapes, params, methods, signals, sources map[string]bool
}

var numericSegment = regexp.MustCompile(`^[0-9]+$`)
var uuidSegment = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hexSegment = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Keep scheme, port, path case, repeated slashes and encoded separators distinct.
// Only default ports are canonicalized; opaque URLs and userinfo are rejected.
func reviewURL(raw string) (*url.URL, string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, "", false
	}
	port := u.Port()
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	u.Host = host
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if port != "" && !(u.Scheme == "https" && port == "443") && !(u.Scheme == "http" && port == "80") {
		u.Host = net.JoinHostPort(host, port)
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u, u.Scheme + "://" + u.Host, true
}

func routeShape(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		switch {
		case numericSegment.MatchString(part):
			parts[i] = "{number}"
		case uuidSegment.MatchString(part):
			parts[i] = "{uuid}"
		case hexSegment.MatchString(part):
			parts[i] = "{hex}"
		}
	}
	return strings.Join(parts, "/")
}

func endpointSignals(u *url.URL, params []string) []string {
	signals := map[string]bool{}
	for _, segment := range strings.FieldsFunc(strings.ToLower(u.Path), func(r rune) bool { return r == '/' || r == '-' || r == '_' || r == '.' }) {
		switch segment {
		case "api", "graphql", "rest", "rpc":
			signals["API surface"] = true
		case "login", "signin", "signup", "oauth", "sso", "auth", "password", "reset":
			signals["Authentication flow"] = true
		case "admin", "dashboard", "console", "manage":
			signals["Management surface"] = true
		case "upload", "download", "export", "import", "attachment", "file", "files":
			signals["File workflow"] = true
		}
	}
	for _, name := range params {
		switch strings.ToLower(name) {
		case "id", "user_id", "userid", "account_id", "tenant", "tenant_id", "org_id", "document_id":
			signals["Object reference parameter"] = true
		case "url", "next", "redirect", "redirect_uri", "return", "returnurl", "return_url", "callback":
			signals["Navigation parameter"] = true
		}
	}
	return sortedKeys(signals)
}

func buildReview(snap store.Snapshot) ([]reviewAsset, []endpointGroup) {
	groups := map[string]*groupBuilder{}
	assets := map[string]*reviewAsset{}
	statuses := map[string]map[string]bool{}
	jsSeen := map[string]bool{}
	asset := func(host string) *reviewAsset {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if host == "" {
			return nil
		}
		if assets[host] == nil {
			assets[host] = &reviewAsset{Host: host}
		}
		return assets[host]
	}
	for _, host := range snap.Subdomains {
		asset(host)
	}
	addURL := func(raw, method string, params []string, source string) {
		u, origin, ok := reviewURL(raw)
		if !ok {
			return
		}
		a := asset(u.Hostname())
		key := origin + "\x00" + routeShape(u)
		g := groups[key]
		if g == nil {
			g = &groupBuilder{endpointGroup: endpointGroup{Origin: origin, Host: a.Host, Route: routeShape(u)}, urls: map[string]bool{}, shapes: map[string]bool{}, params: map[string]bool{}, methods: map[string]bool{}, signals: map[string]bool{}, sources: map[string]bool{}}
			groups[key] = g
		}
		g.sources[source] = true
		query, err := url.ParseQuery(u.RawQuery)
		if err == nil {
			for name := range query {
				g.params[name] = true
			}
		}
		shape := map[string]bool{}
		for name := range query {
			shape[name] = true
		}
		g.shapes[strings.Join(sortedKeys(shape), "\x00")] = true
		for _, name := range params {
			if name != "" {
				g.params[name] = true
			}
		}
		if method != "" {
			g.methods[strings.ToUpper(method)] = true
		}
		for _, signal := range endpointSignals(u, append(sortedKeys(shape), params...)) {
			g.signals[signal] = true
		}
		canonical := u.String()
		if !g.urls[canonical] {
			g.urls[canonical] = true
			a.URLs++
		}
	}
	for _, raw := range snap.URLs {
		addURL(raw, "", nil, "URL inventory") // A URL alone does not establish a supported HTTP method.
	}
	for _, p := range snap.ParamResults {
		if p != nil {
			addURL(p.URL, p.Method, p.Params, "Parameter discovery")
		}
	}
	for _, p := range snap.DirResults {
		if p != nil {
			addURL(p.URL, "", nil, "Directory discovery")
		}
	}
	for _, raw := range snap.JSFiles {
		u, _, ok := reviewURL(raw)
		if ok && !jsSeen[u.String()] {
			asset(u.Hostname()).JS++
			jsSeen[u.String()] = true
		}
	}
	for _, h := range snap.Hosts {
		if h == nil {
			continue
		}
		host := h.Domain
		raw := h.Meta["url"]
		if raw == "" {
			raw = "https://" + h.Domain
		}
		if u, _, ok := reviewURL(raw); ok {
			host = u.Hostname()
		}
		a := asset(host)
		if a == nil {
			continue
		}
		if statuses[a.Host] == nil {
			statuses[a.Host] = map[string]bool{}
		}
		statuses[a.Host][store.HTTPState(h.StatusCode)] = true
	}
	for _, f := range snap.Findings {
		if f != nil {
			if u, _, ok := reviewURL(f.Target); ok {
				asset(u.Hostname()).Candidates++
			}
		}
	}
	for _, secret := range snap.Secrets {
		if secret != nil {
			if u, _, ok := reviewURL(secret.File); ok {
				asset(u.Hostname()).Candidates++
			}
		}
	}
	endpoints := make([]endpointGroup, 0, len(groups))
	signalsByHost := map[string]map[string]bool{}
	for _, g := range groups {
		g.Count = len(g.urls)
		g.Variants = len(g.shapes)
		g.Parameters, g.Methods, g.Signals = sortedKeys(g.params), sortedKeys(g.methods), sortedKeys(g.signals)
		g.Sources = sortedKeys(g.sources)
		// Examples use route templates and parameter names only, never path IDs or values.
		g.Examples = []string{g.Origin + g.Route}
		assets[g.Host].Groups++
		if signalsByHost[g.Host] == nil {
			signalsByHost[g.Host] = map[string]bool{}
		}
		for _, signal := range g.Signals {
			signalsByHost[g.Host][signal] = true
		}
		endpoints = append(endpoints, g.endpointGroup)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Origin != endpoints[j].Origin {
			return endpoints[i].Origin < endpoints[j].Origin
		}
		return endpoints[i].Route < endpoints[j].Route
	})
	queue := make([]reviewAsset, 0, len(assets))
	for _, a := range assets {
		a.Availability = "unverified"
		for _, state := range []string{"available", "redirect", "restricted", "client-error", "rate-limited", "unavailable", "unknown"} {
			if statuses[a.Host][state] {
				a.Availability = state
				break
			}
		}
		a.Checks = []string{"Confirm current program scope and review the collected evidence before testing."}
		if a.Candidates > 0 {
			a.Score += 25
			a.Reasons = append(a.Reasons, fmt.Sprintf("%d scanner/secret candidates require manual validation", a.Candidates))
			a.Checks = append(a.Checks, "Validate candidate context and security impact; a scanner match alone is not a finding.")
		}
		for _, signal := range sortedKeys(signalsByHost[a.Host]) {
			a.Score += 10
			a.Reasons = append(a.Reasons, signal)
			switch signal {
			case "Object reference parameter", "API surface":
				a.Checks = append(a.Checks, "Map object ownership and authorization boundaries using your own permitted test accounts.")
			case "Authentication flow":
				a.Checks = append(a.Checks, "Map sign-in, session and recovery flows within program rules.")
			case "Navigation parameter":
				a.Checks = append(a.Checks, "Trace navigation parameters to their consumers before deciding what to test.")
			case "File workflow":
				a.Checks = append(a.Checks, "Review file ownership and upload/download handling with harmless test files.")
			case "Management surface":
				a.Checks = append(a.Checks, "Review intended roles and access boundaries; a management path is only a naming clue.")
			}
		}
		if a.Groups > 0 {
			a.Score += min(10, a.Groups)
			a.Reasons = append(a.Reasons, fmt.Sprintf("%d distinct route groups", a.Groups))
		}
		if a.JS > 0 {
			a.Score += 10
			a.Reasons = append(a.Reasons, fmt.Sprintf("%d JavaScript files collected", a.JS))
			a.Checks = append(a.Checks, "Review saved JavaScript for routes and data flows; establish reachability and impact before reporting.")
		}
		a.Priority = "explore"
		switch a.Availability {
		case "available", "redirect", "restricted":
			a.Score += 15
			a.Priority = "review"
			a.Reasons = append(a.Reasons, "At least one reachable HTTP observation; individual route health remains unverified")
		case "rate-limited", "unavailable":
			a.Priority = "deferred"
			a.Checks = append(a.Checks, "Review existing evidence offline; respect backoff and confirm service availability before further requests.")
		default:
			a.Checks = append(a.Checks, "Confirm current reachability: archived URLs and names alone do not prove a working endpoint.")
		}
		a.Score = min(100, a.Score)
		if len(a.Reasons) == 0 {
			a.Reasons = []string{"Name only; no HTTP or route evidence collected"}
		}
		seenChecks := map[string]bool{}
		checks := a.Checks
		a.Checks = nil
		for _, check := range checks {
			if !seenChecks[check] {
				a.Checks = append(a.Checks, check)
				seenChecks[check] = true
			}
		}
		queue = append(queue, *a)
	}
	rank := map[string]int{"review": 0, "explore": 1, "deferred": 2}
	sort.Slice(queue, func(i, j int) bool {
		a, b := queue[i], queue[j]
		if a.Priority != b.Priority {
			return rank[a.Priority] < rank[b.Priority]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Host < b.Host
	})
	return queue, endpoints
}
