package store

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unsocialz2/reconx/pkg/util"
)

// Host represents an observed HTTP endpoint, including unavailable services.
type Host struct {
	Domain     string            `json:"domain"`
	IP         string            `json:"ip,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	HTTPState  string            `json:"http_state"`
	Title      string            `json:"title,omitempty"`
	Server     string            `json:"server,omitempty"`
	Port       int               `json:"port,omitempty"`
	TechStack  []string          `json:"tech_stack,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

// HTTPState classifies the observed response, not the health of the origin
// behind a proxy or WAF. A missing/invalid status is never proof of liveness.
func HTTPState(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "available"
	case code >= 300 && code < 400:
		return "redirect"
	case code == 401 || code == 403:
		return "restricted"
	case code == 429:
		return "rate-limited"
	case code >= 400 && code < 500:
		return "client-error"
	case code >= 500 && code < 600:
		return "unavailable"
	default:
		return "unknown"
	}
}

// IsLive excludes server failures, rate limits, and unverified responses.
// 4xx (except 429) remain reachable surfaces, not successful page loads.
func (h *Host) IsLive() bool {
	return h != nil && h.StatusCode >= 200 && h.StatusCode < 500 && h.StatusCode != 429
}

// Port holds a discovered open port
type Port struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// Finding represents a vulnerability or sensitive finding
type Finding struct {
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Target      string    `json:"target"`
	Description string    `json:"description,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Template    string    `json:"template,omitempty"`
	FoundAt     time.Time `json:"found_at"`
}

// Secret represents a discovered credential/token
type Secret struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
	File   string `json:"file,omitempty"`
}

// DirResult represents a directory/file discovered during content fuzzing
type DirResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size,omitempty"`
	Tool       string `json:"tool"`
	Target     string `json:"target"`
}

// WAFResult holds WAF detection output for a host
type WAFResult struct {
	Host     string `json:"host"`
	WAF      string `json:"waf"`
	Detected bool   `json:"detected"`
}

// CloudAsset represents an enumerated cloud storage bucket or asset
type CloudAsset struct {
	Provider   string `json:"provider"` // aws, gcp, azure
	Name       string `json:"name"`
	URL        string `json:"url"`
	Status     string `json:"status"` // public, authenticated, private
	Accessible bool   `json:"accessible"`
}

// CORSFinding represents a CORS misconfiguration finding
type CORSFinding struct {
	URL         string `json:"url"`
	Origin      string `json:"origin"`
	ACAO        string `json:"acao"`
	ACAC        string `json:"acac"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// ParamFinding represents hidden parameters discovered on a URL
type ParamFinding struct {
	URL    string   `json:"url"`
	Method string   `json:"method"`
	Params []string `json:"params"`
	Tool   string   `json:"tool"`
}

// Store is the central thread-safe data store
type Store struct {
	mu sync.RWMutex

	Subdomains   map[string]bool   // deduplicated subdomain set
	SubSources   map[string]string // subdomain → source that found it (for report filter)
	Hosts        map[string]*Host  // domain → host info
	IPRanges     []string          // IP CIDRs from asnmap / --ip flags
	Ports        []*Port
	URLs         map[string]bool // deduplicated URL set
	JSFiles      map[string]bool
	Findings     []*Finding
	Secrets      []*Secret
	SecretKeys   map[string]bool // deduplicated secret set (type:value:file)
	DirResults   []*DirResult
	WAFResults   []*WAFResult
	CloudAssets  []*CloudAsset
	CORSResults  []*CORSFinding
	ParamResults []*ParamFinding

	ScanID    string
	StartTime time.Time
	Coverage  []string
}

// New creates a fresh Store
func New(scanID string) *Store {
	return &Store{
		Subdomains: make(map[string]bool),
		SubSources: make(map[string]string),
		Hosts:      make(map[string]*Host),
		URLs:       make(map[string]bool),
		JSFiles:    make(map[string]bool),
		SecretKeys: make(map[string]bool),
		ScanID:     scanID,
		StartTime:  time.Now(),
	}
}

// AddSubdomain adds a subdomain, returns true if it's new
func (s *Store) AddSubdomain(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Subdomains[sub] {
		return false
	}
	s.Subdomains[sub] = true
	return true
}

// AddSubdomainFromSource adds a subdomain and records which source found it.
// If the subdomain was already known, the source is updated only if the
// existing source is empty (first source wins for stability).
func (s *Store) AddSubdomainFromSource(sub, source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	isNew := !s.Subdomains[sub]
	s.Subdomains[sub] = true
	if isNew || s.SubSources[sub] == "" {
		if source != "" {
			s.SubSources[sub] = source
		}
	}
	return isNew
}

// AddSubdomainsFromSource bulk-adds subdomains from a named source.
func (s *Store) AddSubdomainsFromSource(subs []string, source string) int {
	count := 0
	for _, sub := range subs {
		if s.AddSubdomainFromSource(sub, source) {
			count++
		}
	}
	return count
}

// AddSubdomainsBulkWithSource is a faster transactional variant of
// AddSubdomainsFromSource — acquires the write lock once for the whole
// batch instead of per-element. Use this when adding thousands of
// subdomains from a single tool result (e.g. after puredns bruteforce).
// Preserves existing source attribution on re-add (first source wins).
func (s *Store) AddSubdomainsBulkWithSource(subs []string, source string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, sub := range subs {
		isNew := !s.Subdomains[sub]
		s.Subdomains[sub] = true
		if isNew {
			count++
			if source != "" && s.SubSources[sub] == "" {
				s.SubSources[sub] = source
			}
		} else if s.SubSources[sub] == "" && source != "" {
			// First source wins on re-add
			s.SubSources[sub] = source
		}
	}
	return count
}

// AddSubdomains bulk-adds subdomains, returns count of new ones
func (s *Store) AddSubdomains(subs []string) int {
	count := 0
	for _, sub := range subs {
		if s.AddSubdomain(sub) {
			count++
		}
	}
	return count
}

// GetSubdomainsWithSource returns a sorted slice of (subdomain, source) pairs.
// Used by the report to show which tool found each subdomain.
func (s *Store) GetSubdomainsWithSource() []SubdomainEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SubdomainEntry, 0, len(s.Subdomains))
	for sub := range s.Subdomains {
		out = append(out, SubdomainEntry{
			Subdomain: sub,
			Source:    s.SubSources[sub],
		})
	}
	return out
}

// SubdomainEntry pairs a subdomain with the source that discovered it.
type SubdomainEntry struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
}

// GetSubdomains returns all unique subdomains as a slice
func (s *Store) GetSubdomains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.Subdomains))
	for sub := range s.Subdomains {
		out = append(out, sub)
	}
	return out
}

// AddIPRange records an IP CIDR (from asnmap, --ip flag, etc.)
func (s *Store) AddIPRange(cidr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.IPRanges {
		if existing == cidr {
			return
		}
	}
	s.IPRanges = append(s.IPRanges, cidr)
}

// GetIPRanges returns all IP CIDRs
func (s *Store) GetIPRanges() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.IPRanges))
	copy(out, s.IPRanges)
	return out
}

// AddHost records an observed endpoint without discarding failed HTTP responses.
func (s *Store) AddHost(h *Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h.HTTPState = HTTPState(h.StatusCode)
	key := h.Meta["url"]
	if u, err := url.Parse(key); err == nil && u.Host != "" {
		key = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	} else {
		key = fmt.Sprintf("%s:%d", h.Domain, h.Port)
	}
	s.Hosts[key] = h
}

// GetHosts returns all observed endpoints, including unavailable services.
func (s *Store) GetHosts() []*Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Host, 0, len(s.Hosts))
	for _, h := range s.Hosts {
		out = append(out, h)
	}
	return out
}

// GetLiveHosts returns endpoints suitable as seeds for active discovery.
func (s *Store) GetLiveHosts() []*Host {
	var out []*Host
	for _, h := range s.GetHosts() {
		if h.IsLive() {
			out = append(out, h)
		}
	}
	return out
}

// AddPort records an open port
func (s *Store) AddPort(p *Port) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.Ports {
		if v.Host == p.Host && v.Port == p.Port && v.Protocol == p.Protocol {
			return
		}
	}
	s.Ports = append(s.Ports, p)
}

// AddURL adds a URL, returns true if new
func (s *Store) AddURL(u string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.URLs[u] {
		return false
	}
	s.URLs[u] = true
	return true
}

// AddURLs bulk-adds URLs
func (s *Store) AddURLs(urls []string) int {
	count := 0
	for _, u := range urls {
		if s.AddURL(u) {
			count++
		}
	}
	return count
}

// GetURLs returns all unique URLs
func (s *Store) GetURLs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.URLs))
	for u := range s.URLs {
		out = append(out, u)
	}
	return out
}

// AddJSFile records a JS file URL
func (s *Store) AddJSFile(u string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.JSFiles[u] {
		return false
	}
	s.JSFiles[u] = true
	return true
}

// GetJSFiles returns all JS file URLs
func (s *Store) GetJSFiles() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.JSFiles))
	for u := range s.JSFiles {
		out = append(out, u)
	}
	return out
}

// AddFinding records a vulnerability finding
func (s *Store) AddFinding(f *Finding) {
	if f.FoundAt.IsZero() {
		f.FoundAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.Findings {
		if v.Template == f.Template && v.Target == f.Target && v.Name == f.Name {
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

// AddSecret records a discovered secret, deduplicating identical findings
func (s *Store) AddSecret(sec *Secret) bool {
	if sec == nil {
		return false
	}
	sec.Value = strings.TrimSpace(util.StripANSI(sec.Value))
	sec.Type = strings.TrimSpace(util.StripANSI(sec.Type))
	key := sec.Type + ":" + sec.Value + ":" + sec.File

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SecretKeys == nil {
		s.SecretKeys = make(map[string]bool)
	}
	if s.SecretKeys[key] {
		return false
	}
	s.SecretKeys[key] = true
	s.Secrets = append(s.Secrets, sec)
	return true
}

// AddDirResult records a directory/file fuzzing hit
func (s *Store) AddDirResult(d *DirResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DirResults = append(s.DirResults, d)
}

// AddWAFResult records WAF detection for a host
func (s *Store) AddWAFResult(w *WAFResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.WAFResults = append(s.WAFResults, w)
}

// AddCloudAsset records a discovered cloud bucket/asset
func (s *Store) AddCloudAsset(c *CloudAsset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CloudAssets = append(s.CloudAssets, c)
}

// AddCORSFinding records a CORS misconfiguration
func (s *Store) AddCORSFinding(c *CORSFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CORSResults = append(s.CORSResults, c)
}

// AddParamFinding records discovered hidden parameters
func (s *Store) AddParamFinding(p *ParamFinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ParamResults = append(s.ParamResults, p)
}

// GetParamResults returns all discovered parameter findings
func (s *Store) GetParamResults() []*ParamFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ParamFinding, len(s.ParamResults))
	copy(out, s.ParamResults)
	return out
}

// Stats returns a summary map
func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	live, unavailable, limited := 0, 0, 0
	for _, h := range s.Hosts {
		if h.IsLive() {
			live++
		}
		if HTTPState(h.StatusCode) == "unavailable" {
			unavailable++
		}
		if h.StatusCode == 429 {
			limited++
		}
	}
	return map[string]int{
		"subdomains":         len(s.Subdomains),
		"live_hosts":         live,
		"http_endpoints":     len(s.Hosts),
		"unavailable_hosts":  unavailable,
		"rate_limited_hosts": limited,
		"open_ports":         len(s.Ports),
		"urls":               len(s.URLs),
		"js_files":           len(s.JSFiles),
		"findings":           len(s.Findings),
		"secrets":            len(s.Secrets),
		"dir_results":        len(s.DirResults),
		"waf_results":        len(s.WAFResults),
		"cloud_assets":       len(s.CloudAssets),
		"cors_results":       len(s.CORSResults),
		"param_results":      len(s.ParamResults),
	}
}

// Snapshot is the versioned, complete machine-readable scan state.
type Snapshot struct {
	SchemaVersion int              `json:"schema_version"`
	ScanID        string           `json:"scan_id"`
	StartTime     time.Time        `json:"start_time"`
	Duration      string           `json:"duration"`
	Subdomains    []string         `json:"subdomains"`
	SubSources    []SubdomainEntry `json:"subdomain_sources"`
	IPRanges      []string         `json:"ip_ranges,omitempty"`
	Hosts         []*Host          `json:"hosts"`
	Ports         []*Port          `json:"ports"`
	URLs          []string         `json:"urls"`
	JSFiles       []string         `json:"js_files"`
	Findings      []*Finding       `json:"findings"`
	Secrets       []*Secret        `json:"secrets"`
	DirResults    []*DirResult     `json:"dir_results,omitempty"`
	WAFResults    []*WAFResult     `json:"waf_results,omitempty"`
	CloudAssets   []*CloudAsset    `json:"cloud_assets,omitempty"`
	CORSResults   []*CORSFinding   `json:"cors_results,omitempty"`
	ParamResults  []*ParamFinding  `json:"param_results,omitempty"`
	Coverage      []string         `json:"coverage,omitempty"`
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{SchemaVersion: 1, ScanID: s.ScanID, StartTime: s.StartTime, Duration: time.Since(s.StartTime).Round(time.Second).String(), IPRanges: s.IPRanges, Ports: s.Ports, Findings: s.Findings, Secrets: s.Secrets, DirResults: s.DirResults, WAFResults: s.WAFResults, CloudAssets: s.CloudAssets, CORSResults: s.CORSResults, ParamResults: s.ParamResults, Coverage: s.Coverage}
	for sub := range s.Subdomains {
		snap.Subdomains = append(snap.Subdomains, sub)
		snap.SubSources = append(snap.SubSources, SubdomainEntry{sub, s.SubSources[sub]})
	}
	sort.Strings(snap.Subdomains)
	for _, host := range s.Hosts {
		snap.Hosts = append(snap.Hosts, host)
	}
	sort.Slice(snap.Hosts, func(i, j int) bool { return snap.Hosts[i].Meta["url"] < snap.Hosts[j].Meta["url"] })
	for u := range s.URLs {
		snap.URLs = append(snap.URLs, u)
	}
	sort.Strings(snap.URLs)
	for u := range s.JSFiles {
		snap.JSFiles = append(snap.JSFiles, u)
	}
	sort.Strings(snap.JSFiles)
	// Detach pointer/slice data so callers cannot mutate the synchronized store.
	data, _ := json.Marshal(snap)
	var copy Snapshot
	_ = json.Unmarshal(data, &copy)
	for _, h := range copy.Hosts {
		h.HTTPState = HTTPState(h.StatusCode)
	}
	return copy
}
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".reconx-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp, path)
}
func (s *Store) SaveSnapshot(path string) error {
	data, err := json.MarshalIndent(s.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(path, data, 0600)
}
func (s *Store) SaveJSON(outDir string) error {
	return s.SaveSnapshot(filepath.Join(outDir, "results.json"))
}

// LoadSnapshot reapplies current scope to every active asset before later phases run.
func LoadSnapshot(path string, allowed func(string) bool) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err = json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported snapshot schema %d", snap.SchemaVersion)
	}
	s := New(snap.ScanID)
	s.StartTime = snap.StartTime
	s.Coverage = snap.Coverage
	for _, v := range snap.Subdomains {
		if allowed(v) {
			s.AddSubdomain(v)
		}
	}
	for _, v := range snap.SubSources {
		if allowed(v.Subdomain) {
			s.AddSubdomainFromSource(v.Subdomain, v.Source)
		}
	}
	for _, v := range snap.Hosts {
		target := v.Meta["url"]
		if target == "" {
			target = v.Domain
		}
		if allowed(target) {
			s.AddHost(v)
		}
	}
	for _, v := range snap.Ports {
		if allowed(v.Host) {
			s.AddPort(v)
		}
	}
	for _, v := range snap.URLs {
		if allowed(v) {
			s.AddURL(v)
		}
	}
	for _, v := range snap.JSFiles {
		if allowed(v) {
			s.AddJSFile(v)
		}
	}
	for _, v := range snap.Findings {
		if allowed(v.Target) {
			s.AddFinding(v)
		}
	}
	for _, v := range snap.Secrets {
		if v.File == "" || allowed(v.File) || v.Source == "trufflehog-github" {
			s.AddSecret(v)
		}
	}
	for _, v := range snap.DirResults {
		if allowed(v.URL) {
			s.AddDirResult(v)
		}
	}
	for _, v := range snap.WAFResults {
		if allowed(v.Host) {
			s.AddWAFResult(v)
		}
	}
	for _, v := range snap.CloudAssets {
		if allowed(v.URL) {
			s.AddCloudAsset(v)
		}
	}
	for _, v := range snap.CORSResults {
		if allowed(v.URL) {
			s.AddCORSFinding(v)
		}
	}
	for _, v := range snap.ParamResults {
		if allowed(v.URL) {
			s.AddParamFinding(v)
		}
	}
	for _, v := range snap.IPRanges {
		s.AddIPRange(v)
	}
	return s, nil
}
func (s *Store) AddCoverage(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.Coverage {
		if v == message {
			return
		}
	}
	s.Coverage = append(s.Coverage, message)
}

// SaveRaw atomically writes private raw evidence and propagates write errors.
func SaveRaw(path string, lines []string) error {
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	return AtomicWrite(path, []byte(data), 0600)
}

// DataDir returns the path to the raw tool-output directory (outDir/data/).
// All individual tool outputs should be written here to keep the top-level
// scan directory clean. The directory is created on first call.
func DataDir(outDir string) string {
	d := filepath.Join(outDir, "data")
	_ = os.MkdirAll(d, 0755)
	return d
}

// ── WAF-split helpers ────────────────────────────────────────────────────────

// IsWAFProtected returns true if wafw00f detected a WAF on the given host URL/domain.
func (s *Store) IsWAFProtected(hostOrURL string) bool {
	detected, _ := s.WAFStatus(hostOrURL)
	return detected
}

// WAFStatus distinguishes untested endpoints from explicit negative detections.
// Detection on a parent domain does not imply detection on every subdomain.
func (s *Store) WAFStatus(hostOrURL string) (detected, known bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	normalize := func(raw string) string {
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Scheme + "://" + u.Host)
	}
	clean := normalize(hostOrURL)
	for _, w := range s.WAFResults {
		if clean != "" && normalize(w.Host) == clean {
			known = true
			if w.Detected {
				return true, true
			}
		}
	}
	return false, known
}

// GetWAFHosts returns live seed URLs that are behind a WAF.
func (s *Store) GetWAFHosts() []string {
	hosts := s.GetLiveHosts()
	var out []string
	for _, h := range hosts {
		url := h.Meta["url"]
		if url == "" {
			url = "https://" + h.Domain
		}
		if s.IsWAFProtected(url) {
			out = append(out, url)
		}
	}
	return out
}

// GetNonWAFHosts returns live host URLs that are NOT behind a WAF.
func (s *Store) GetNonWAFHosts() []string {
	hosts := s.GetLiveHosts()
	var out []string
	for _, h := range hosts {
		url := h.Meta["url"]
		if url == "" {
			url = "https://" + h.Domain
		}
		if !s.IsWAFProtected(url) {
			out = append(out, url)
		}
	}
	return out
}

// SplitURLsByWAF partitions a URL list into (waf, nowaf) slices
// based on whether the URL's host is WAF-protected.
func (s *Store) SplitURLsByWAF(urls []string) (waf, nowaf []string) {
	for _, u := range urls {
		if s.IsWAFProtected(u) {
			waf = append(waf, u)
		} else {
			nowaf = append(nowaf, u)
		}
	}
	return
}
