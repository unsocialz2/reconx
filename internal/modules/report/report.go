package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/unsocialz2/reconx/internal/store"
)

// ReportData holds everything needed to render the HTML report
type PhaseSummary struct {
	Name   string
	Status string
	Reason string
}
type ReportData struct {
	Coverage       []string
	Phases         []PhaseSummary
	Directories    []*store.DirResult
	CloudAssets    []*store.CloudAsset
	CORSCandidates []*store.CORSFinding

	ScanID      string
	Targets     []string
	StartTime   time.Time
	Duration    string
	GeneratedAt string

	TotalSubdomains  int
	TotalLiveHosts   int
	TotalPorts       int
	TotalURLs        int
	TotalJSFiles     int
	TotalFindings    int
	TotalSecrets     int
	TotalParams      int
	TotalWAFHosts    int
	TotalNonWAFHosts int

	Subdomains    []store.SubdomainEntry
	Hosts         []*store.Host
	WAFHosts      []*store.Host   // hosts behind WAF
	NoWAFHosts    []*store.Host   // hosts not behind WAF
	WAFMap        map[string]bool // domain -> is WAF protected (fast O(1) lookup in template)
	Ports         []*store.Port
	Findings      []*store.Finding
	Secrets       []*store.Secret
	URLs          []string            // sorted list of all discovered URLs (capped)
	JSFiles       []string            // sorted list of all JS file URLs
	Params        []string            // discovered parameter keys (all, deduplicated)
	WAFParams     []string            // params from WAF-protected hosts
	NoWAFParams   []string            // params from non-WAF hosts
	ParamFindings []*ParamFindingItem // Detailed parameter-to-endpoint mappings
	WAFResults    []*store.WAFResult  // WAF detection results

	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int

	HasScreenshots bool
	ScreenshotDir  string
	// HostScreenshots maps domain → relative path to screenshot.png
	HostScreenshots map[string]string

	// Pre-computed chart data so the template stays simple
	SeverityChart []chartSlice
	StatusChart   []chartSlice
	PortChart     []chartSlice
	TechChart     []chartSlice
	SourceChart   []chartSlice

	// Unique values for filter chips
	AllStatusCodes []int
	AllTech        []string
	AllSources     []string
	AllPorts       []int
	AllSeverities  []string
}

type chartSlice struct {
	Label string
	Value int
}

// ParamFindingItem represents an endpoint-parameter pair with security context
type ParamFindingItem struct {
	Param   string
	URL     string
	TestURL string // Full endpoint URL with the parameter attached for testing
	Method  string
	IsWAF   bool
	Tool    string
}

// buildTestURL ensures the parameter is visibly present in the URL for direct testing and linking.
func buildTestURL(targetURL, param string) string {
	if strings.Contains(targetURL, param+"=") {
		return targetURL
	}
	sep := "?"
	if strings.Contains(targetURL, "?") {
		sep = "&"
	}
	return targetURL + sep + param + "=FUZZ"
}

// Generate creates a self-contained, paginated report containing all results.
func Generate(st *store.Store, targets []string, outDir string) error {
	return generateWorkspace(st, targets, outDir)
}

// redactSecretValue returns a redacted form of a secret value. We keep
// enough to identify the secret (type + last 4 chars) but mask the body
// so the HTML report can be shared without leaking credentials.
func redactSecretValue(value string) string {
	if len(value) <= 8 {
		return "***REDACTED***"
	}
	return value[:4] + "***" + value[len(value)-4:]
}

// redactSecrets produces a copy of secrets with values redacted.
// The Type, Source, and File fields are preserved so the report still
// shows "AWS Access Key from jsecret in app.js" — just hides the key.
func redactSecrets(secrets []*store.Secret) []*store.Secret {
	out := make([]*store.Secret, len(secrets))
	for i, s := range secrets {
		out[i] = &store.Secret{
			Type:   s.Type,
			Value:  redactSecretValue(s.Value),
			Source: s.Source,
			File:   s.File,
		}
	}
	return out
}

// jsonMarshal is a thin wrapper around encoding/json that we can stub in tests.
// We use a custom function instead of importing encoding/json directly so the
// report package stays self-contained for review.
func jsonMarshal(v interface{}) ([]byte, error) {
	return jsonMarshalImpl(v)
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func buildStatusChart(hosts []*store.Host) []chartSlice {
	counts := map[int]int{}
	for _, h := range hosts {
		if h.StatusCode > 0 {
			counts[h.StatusCode]++
		}
	}
	out := make([]chartSlice, 0, len(counts))
	for code, n := range counts {
		out = append(out, chartSlice{Label: fmt.Sprintf("%d", code), Value: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func buildPortChart(ports []*store.Port) []chartSlice {
	counts := map[int]int{}
	for _, p := range ports {
		counts[p.Port]++
	}
	out := make([]chartSlice, 0, len(counts))
	for port, n := range counts {
		out = append(out, chartSlice{Label: fmt.Sprintf("%d", port), Value: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

func buildTechChart(hosts []*store.Host) []chartSlice {
	counts := map[string]int{}
	for _, h := range hosts {
		for _, t := range h.TechStack {
			counts[t]++
		}
	}
	out := make([]chartSlice, 0, len(counts))
	for tech, n := range counts {
		out = append(out, chartSlice{Label: tech, Value: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func buildSourceChart(subs []store.SubdomainEntry) []chartSlice {
	counts := map[string]int{}
	for _, s := range subs {
		if s.Source == "" {
			s.Source = "unknown"
		}
		counts[s.Source]++
	}
	out := make([]chartSlice, 0, len(counts))
	for src, n := range counts {
		out = append(out, chartSlice{Label: src, Value: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

func uniqueStatusCodes(hosts []*store.Host) []int {
	seen := map[int]bool{}
	var out []int
	for _, h := range hosts {
		if h.StatusCode > 0 && !seen[h.StatusCode] {
			seen[h.StatusCode] = true
			out = append(out, h.StatusCode)
		}
	}
	sort.Ints(out)
	return out
}

func uniqueTech(hosts []*store.Host) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		for _, t := range h.TechStack {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSources(subs []store.SubdomainEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range subs {
		if s.Source == "" {
			s.Source = "unknown"
		}
		if !seen[s.Source] {
			seen[s.Source] = true
			out = append(out, s.Source)
		}
	}
	sort.Strings(out)
	return out
}

func uniquePorts(ports []*store.Port) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if !seen[p.Port] {
			seen[p.Port] = true
			out = append(out, p.Port)
		}
	}
	sort.Ints(out)
	return out
}
