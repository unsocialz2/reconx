package triage

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/unsocialz2/reconx/internal/store"
)

// Item is a review lead, NOT a validated vulnerability. Priority describes
// analyst attention, while SeverityHint preserves any unverified scanner claim.
type Item struct {
	ID           string `json:"id"`
	Phase        string `json:"phase"`
	Title        string `json:"title"`
	Target       string `json:"target"`
	Priority     string `json:"priority"`
	Score        int    `json:"priority_score"`
	Occurrences  int    `json:"occurrences"`
	SeverityHint string `json:"severity_hint"`
	Confidence   string `json:"confidence"`
	Reason       string `json:"reason"`
	NextStep     string `json:"next_step"`
}

type Output struct {
	SchemaVersion int            `json:"schema_version"`
	Disclaimer    string         `json:"disclaimer"`
	Counts        map[string]int `json:"counts"`
	Items         []Item         `json:"items"`
}

const disclaimer = "Review priority is not vulnerability severity, proof of exploitation, or bounty eligibility. All results require manual validation and program-policy review."

var phaseNames = []string{
	"subdomains", "http", "ports", "urls", "javascript", "vulnerabilities",
	"secrets", "directories", "cloud", "cors", "parameters", "waf", "networks",
}

type phaseEngine func(store.Snapshot) []Item

var phaseEngines = []phaseEngine{
	analyzeSubdomains, analyzeHTTP, analyzePorts, analyzeURLs, analyzeJavaScript,
	analyzeVulnerabilities, analyzeSecrets, analyzeDirectories, analyzeCloud,
	analyzeCORS, analyzeParameters, analyzeWAF, analyzeNetworks,
}

func rank(score int) string {
	switch {
	case score >= 80:
		return "P1"
	case score >= 60:
		return "P2"
	case score >= 40:
		return "P3"
	default:
		return "P4"
	}
}

func candidate(phase, title, target string, score int, reason, next string) Item {
	return Item{
		Phase: phase, Title: title, Target: safeTarget(target),
		Priority: rank(score), Score: score, Occurrences: 1, SeverityHint: "unknown",
		Confidence: "observation", Reason: reason, NextStep: next,
	}
}

func containsAny(value string, needles ...string) bool {
	value = strings.ToLower(value)
	for _, n := range needles {
		if strings.Contains(value, n) {
			return true
		}
	}
	return false
}

// Keep URL paths for useful review while removing query values and fragments.
// Mask long opaque path segments, which frequently contain reset/invite tokens.
func safeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if u, err := url.Parse(raw); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		segs := strings.Split(u.EscapedPath(), "/")
		for i, segment := range segs {
			decoded, err := url.PathUnescape(segment)
			if err != nil {
				segs[i] = "[redacted]"
			} else if len(decoded) >= 24 && opaque(decoded) {
				segs[i] = "[redacted]"
			}
		}
		return u.Scheme + "://" + u.Host + strings.Join(segs, "/")
	}
	if len(raw) > 300 {
		return raw[:120] + "...[truncated]"
	}
	return raw
}

func opaque(segment string) bool {
	for _, ch := range segment {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func analyzeSubdomains(s store.Snapshot) []Item {
	var out []Item
	for _, host := range s.Subdomains {
		score := 25
		if containsAny(host, "admin.", "auth.", "sso.", "login.", "vpn.", "internal.", "portal.") {
			score = 65
		} else if containsAny(host, "api.", "dev.", "staging.", "test.", "prod.") {
			score = 50
		}
		out = append(out, candidate("subdomains", "Discovered hostname", host, score,
			"DNS discovery is an inventory signal, not evidence of exposure.",
			"Confirm authorization, ownership and service availability before review."))
	}
	return out
}

func analyzeHTTP(s store.Snapshot) []Item {
	var out []Item
	for _, h := range s.Hosts {
		if h == nil {
			continue
		}
		target := h.Domain
		if h.Meta != nil && h.Meta["url"] != "" {
			target = h.Meta["url"]
		}
		score := 30
		title := "HTTP endpoint observation"
		if h.StatusCode == 429 || h.StatusCode >= 500 || h.StatusCode == 0 {
			score = 10
			title = "Unavailable / deferred HTTP endpoint"
		} else if containsAny(target, "admin.", "auth.", "sso.", "login.", "internal.", "api.") {
			score = 65
		}
		it := candidate("http", title, target, score,
			fmt.Sprintf("Observed HTTP %d (%s); status alone is not a vulnerability.", h.StatusCode, store.HTTPState(h.StatusCode)),
			"Inspect endpoints and authentication behavior using permitted manual testing.")
		if score == 10 {
			it.Priority = "Deferred"
			it.NextStep = "Do not retry aggressively; honor rate limits and service health."
		}
		out = append(out, it)
	}
	return out
}

func analyzePorts(s store.Snapshot) []Item {
	var out []Item
	for _, p := range s.Ports {
		if p == nil {
			continue
		}
		score := 35
		if p.Port == 22 || p.Port == 3389 || p.Port == 3306 || p.Port == 5432 || p.Port == 6379 || p.Port == 9200 || p.Port == 27017 || p.Port == 2375 {
			score = 70
		}
		out = append(out, candidate("ports", fmt.Sprintf("Observed port %d/%s", p.Port, p.Protocol),
			p.Host, score, "An open service is not proof of unauthorized access.",
			"Check program authorization and corroborate service identity; do not attempt brute force."))
	}
	return out
}

func analyzeURLs(s store.Snapshot) []Item {
	var out []Item
	for _, raw := range s.URLs {
		target := safeTarget(raw)
		score := 25
		if containsAny(target, "/.env", "/.git/", ".bak", ".sql", ".pem", "/backup", "/config") {
			score = 75
		} else if containsAny(target, "/api/", "/graphql", "/admin", "/oauth", "/callback", "/upload", "/webhook", "/reset", "/payment", "/account") {
			score = 65
		}
		out = append(out, candidate("urls", "Discovered URL / route", raw, score,
			"An archived or discovered route might be missing or inaccessible.",
			"Verify live behavior and authorization before treating it as a finding."))
	}
	return out
}

func analyzeJavaScript(s store.Snapshot) []Item {
	var out []Item
	for _, raw := range s.JSFiles {
		score := 30
		if containsAny(raw, "admin", "auth", "config", "private", "account", "payment", "secret", ".map") {
			score = 62
		}
		out = append(out, candidate("javascript", "JavaScript asset", raw, score,
			"Client-side asset naming does not establish secret exposure.",
			"Review collected source and secret-scanner evidence offline."))
	}
	return out
}

func analyzeVulnerabilities(s store.Snapshot) []Item {
	var out []Item
	for _, f := range s.Findings {
		if f == nil {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(f.Severity))
		score := 30
		switch severity {
		case "critical":
			score = 95
		case "high":
			score = 85
		case "medium":
			score = 70
		case "low":
			score = 45
		}
		it := candidate("vulnerabilities", "Scanner finding: "+safeTitle(f.Name), f.Target, score,
			"Severity originates from a scanner/template, not a verified exploit.",
			"Reproduce safely; document impact and negative controls before reporting.")
		it.SeverityHint = severity
		it.Confidence = "scanner-candidate"
		out = append(out, it)
	}
	return out
}

func safeTitle(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) > 120 {
		return raw[:120] + "..."
	}
	return raw
}

func analyzeSecrets(s store.Snapshot) []Item {
	var out []Item
	for _, sec := range s.Secrets {
		if sec == nil {
			continue
		}
		score := 65
		if containsAny(sec.Type, "private key", "password", "credential", "aws", "secret", "oauth", "bearer") {
			score = 85
		} else if containsAny(sec.Type, "google maps", "analytics", "measurement", "public", "client id") {
			score = 38
		}
		target := sec.File
		if target == "" {
			target = "source: " + safeTitle(sec.Source)
		}
		it := candidate("secrets", "Potential hardcoded secret (value omitted)", target, score,
			"Pattern match only; the value is intentionally excluded from triage artifacts.",
			"Confirm context and permitted impact without misusing credentials.")
		it.Confidence = "scanner-candidate"
		out = append(out, it)
	}
	return out
}

func analyzeDirectories(s store.Snapshot) []Item {
	var out []Item
	for _, d := range s.DirResults {
		if d == nil {
			continue
		}
		score := 30
		sensitive := containsAny(d.URL, "/.git", "/.env", "/backup", "/config", ".bak", ".sql", ".zip")
		if sensitive && d.StatusCode >= 200 && d.StatusCode < 300 {
			score = 82
		} else if sensitive {
			score = 58
		}
		out = append(out, candidate("directories", fmt.Sprintf("Discovered path (HTTP %d)", d.StatusCode), d.URL, score,
			"Status and filename alone cannot prove the contents are sensitive.",
			"Inspect only minimally necessary, authorized evidence."))
	}
	return out
}

func analyzeCloud(s store.Snapshot) []Item {
	var out []Item
	for _, c := range s.CloudAssets {
		if c == nil {
			continue
		}
		score := 30
		if c.Accessible || strings.EqualFold(c.Status, "public") {
			score = 75
		}
		it := candidate("cloud", "Cloud asset observation", c.URL, score,
			"Reachability or HEAD success does not establish public data access.",
			"Validate ownership and access policy without bulk data retrieval.")
		it.Confidence = "unverified-access"
		out = append(out, it)
	}
	return out
}

func analyzeCORS(s store.Snapshot) []Item {
	var out []Item
	for _, c := range s.CORSResults {
		if c == nil {
			continue
		}
		score := 45
		if strings.EqualFold(strings.TrimSpace(c.ACAC), "true") && c.ACAO != "" {
			score = 70
		}
		it := candidate("cors", "CORS configuration candidate", c.URL, score,
			"Response headers alone do not prove cross-origin data access.",
			"Check real credentialed origin behavior with owned accounts only.")
		it.Confidence = "scanner-candidate"
		out = append(out, it)
	}
	return out
}

func analyzeParameters(s store.Snapshot) []Item {
	var out []Item
	for _, p := range s.ParamResults {
		if p == nil {
			continue
		}
		for _, param := range p.Params {
			score := 30
			if containsAny(strings.ToLower(param), "user", "account", "token", "auth", "file", "redirect", "url", "id") {
				score = 58
			}
			if score >= 58 && containsAny(p.URL, "/api/", "/account", "/user", "/admin") {
				score = 66
			}
			out = append(out, candidate("parameters", "Discovered parameter: "+safeTitle(param), p.URL, score,
				"Parameter names only indicate possible review surfaces.",
				"Test access controls safely using accounts and objects you own."))
		}
	}
	return out
}

func analyzeWAF(s store.Snapshot) []Item {
	var out []Item
	for _, w := range s.WAFResults {
		if w == nil {
			continue
		}
		out = append(out, candidate("waf", "WAF observation", w.Host, 20,
			"WAF detection is contextual, not a vulnerability.",
			"Keep detection notes alongside affected hosts; avoid evasion or high-volume tests."))
	}
	return out
}

func analyzeNetworks(s store.Snapshot) []Item {
	var out []Item
	for _, cidr := range s.IPRanges {
		out = append(out, candidate("networks", "Network inventory", cidr, 15,
			"Network association is not proof of scope authorization.",
			"Confirm exact IP/CIDR authorization before any active probe."))
	}
	return out
}

// Analyze runs one independent classifier per discovery phase without network
// requests. Outputs are deterministic and deduplicated across each phase.
func Analyze(s store.Snapshot) []Item {
	seen := make(map[string]int)
	var items []Item
	for _, engine := range phaseEngines {
		for _, item := range engine(s) {
			key := item.Phase + "\x00" + item.Title + "\x00" + item.Target
			if previous, exists := seen[key]; exists {
				items[previous].Occurrences++
				continue
			}
			seen[key] = len(items)
			sum := sha256.Sum256([]byte(key))
			item.ID = hex.EncodeToString(sum[:8])
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Priority == "Deferred" && b.Priority != "Deferred" {
			return false
		}
		if b.Priority == "Deferred" && a.Priority != "Deferred" {
			return true
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Phase != b.Phase {
			return a.Phase < b.Phase
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Title < b.Title
	})
	return items
}

func writeCSV(path string, items []Item) error {
	var buf strings.Builder
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"id", "phase", "priority", "score", "occurrences", "severity_hint", "confidence", "title", "target", "reason", "next_step"}); err != nil {
		return err
	}
	for _, x := range items {
		if err := w.Write([]string{x.ID, x.Phase, x.Priority, strconv.Itoa(x.Score), strconv.Itoa(x.Occurrences), x.SeverityHint, x.Confidence, x.Title, x.Target, x.Reason, x.NextStep}); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return store.AtomicWrite(path, []byte(buf.String()), 0600)
}

func summary(items []Item, counts map[string]int) []byte {
	var b strings.Builder
	b.WriteString("# ReconX phase triage\n\n")
	b.WriteString("**Important:** " + disclaimer + "\n\n")
	b.WriteString("| Phase | Leads |\n|---|---:|\n")
	for _, phase := range phaseNames {
		fmt.Fprintf(&b, "| %s | %d |\n", phase, counts["phase:"+phase])
	}
	b.WriteString("\n| Priority | Leads |\n|---|---:|\n")
	for _, p := range []string{"P1", "P2", "P3", "P4", "Deferred"} {
		fmt.Fprintf(&b, "| %s | %d |\n", p, counts["priority:"+p])
	}
	b.WriteString("\nP1 = inspect first, P4 = low analyst priority, Deferred = back off. All leads remain unverified.\n")
	b.WriteString("Full data: triage.json, triage.csv, phase_*.csv, priority_*.csv. Secrets are never exported as values.\n")
	return []byte(b.String())
}

const htmlPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ReconX phase triage</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{font:14px system-ui, sans-serif;max-width:1300px;margin:3rem auto;padding:0 1rem;color:#dbe5ed;background:#101820}
h1{margin-bottom:.5rem}p{color:#b5c3d0}a{color:#81c6ff}table{border-collapse:collapse;width:100%;margin:1.5rem 0}th,td{padding:.65rem;border-bottom:1px solid #33424d;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{position:sticky;top:0;background:#182630}.p1{color:#ff9595}.p2{color:#ffc78c}.p3{color:#e5d88e}.p4{color:#9bd1b4}.pill{font-weight:700}nav{display:flex;gap:1rem;flex-wrap:wrap}small{color:#b5c3d0}
</style></head><body><h1>ReconX phase triage</h1><p>{{.Disclaimer}}</p><nav><a href="triage.csv">All leads CSV</a><a href="triage.json">JSON</a><a href="SUMMARY.md">Summary</a></nav><p>Showing first {{len .Items}} leads (complete data in exports).</p><table><thead><tr><th>Priority</th><th>Count</th><th>Phase</th><th>Title</th><th>Target</th><th>Evidence caveat</th></tr></thead><tbody>{{range .Items}}<tr><td class="pill {{.CSS}}">{{.Priority}}</td><td>{{.Occurrences}}</td><td>{{.Phase}}</td><td>{{.Title}}</td><td>{{.Target}}</td><td><small>{{.Reason}}</small></td></tr>{{end}}</tbody></table></body></html>`

type htmlItem struct {
	Item
	CSS string
}
type htmlView struct {
	Disclaimer string
	Items      []htmlItem
}

func writeHTML(path string, items []Item) error {
	view := htmlView{Disclaimer: disclaimer}
	for i, item := range items {
		if i >= 500 {
			break
		}
		view.Items = append(view.Items, htmlItem{Item: item, CSS: strings.ToLower(item.Priority)})
	}
	tpl, err := template.New("triage").Parse(htmlPage)
	if err != nil {
		return err
	}
	var b strings.Builder
	if err := tpl.Execute(&b, view); err != nil {
		return err
	}
	return store.AtomicWrite(path, []byte(b.String()), 0600)
}

// Generate emits offline-only triage files for every phase and every priority.
// The existing report generation and --report-only path both call this.
func Generate(snapshot store.Snapshot, dir string) error {
	items := Analyze(snapshot)
	counts := map[string]int{}
	byPhase := map[string][]Item{}
	byPriority := map[string][]Item{}
	for _, it := range items {
		counts["phase:"+it.Phase]++
		counts["priority:"+it.Priority]++
		byPhase[it.Phase] = append(byPhase[it.Phase], it)
		byPriority[it.Priority] = append(byPriority[it.Priority], it)
	}
	output := Output{SchemaVersion: 1, Disclaimer: disclaimer, Counts: counts, Items: items}
	raw, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	if err := store.AtomicWrite(filepath.Join(dir, "triage.json"), raw, 0600); err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(dir, "triage.csv"), items); err != nil {
		return err
	}
	for _, phase := range phaseNames {
		if err := writeCSV(filepath.Join(dir, "phase_"+phase+".csv"), byPhase[phase]); err != nil {
			return err
		}
	}
	for _, p := range []string{"P1", "P2", "P3", "P4", "Deferred"} {
		if err := writeCSV(filepath.Join(dir, "priority_"+p+".csv"), byPriority[p]); err != nil {
			return err
		}
	}
	if err := store.AtomicWrite(filepath.Join(dir, "SUMMARY.md"), summary(items, counts), 0600); err != nil {
		return err
	}
	return writeHTML(filepath.Join(dir, "index.html"), items)
}
