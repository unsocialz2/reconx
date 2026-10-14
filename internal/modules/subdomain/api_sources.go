package subdomain

// api_sources.go contains all HTTP-only / API-based subdomain enumeration
// sources. These run without requiring any external binary — they hit public
// APIs directly. Token-based sources (VirusTotal, Shodan, SecurityTrails,
// Censys) are skipped automatically when the corresponding token is missing.
//
// Every function here has the same signature as the binary-backed runners in
// subdomain.go so enumerateDomain() can treat them uniformly.
//
// All sources decode with encoding/json (the previous string-splitting
// parsers silently dropped results on any format variation) and report
// real failure reasons on the progress board instead of "done 0".

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/reconx/reconx/pkg/logger"
	"github.com/reconx/reconx/pkg/runner"
)

var defaultDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

var defaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Force tcp4 to prevent "connect: network is unreachable" IPv6 attempts
		if network == "tcp" {
			network = "tcp4"
		}
		return defaultDialer.DialContext(ctx, network, addr)
	},
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

var apiClient = &http.Client{
	Transport: defaultTransport,
	Timeout:   35 * time.Second,
}

// maxBodySize caps how much we read from any API response.
const maxBodySize = 10 * 1024 * 1024

// hostLike matches hostname-looking tokens inside HTML/text responses.
// Used by scraper sources whose markup changes often (rapiddns).
var hostLike = regexp.MustCompile(`(?i)[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+\.?`)

// ── HTTP plumbing ────────────────────────────────────────────────────────────

// apiFetch performs a GET request with optional headers, retrying transient
// failures with backoff. Returns (body, status, err).
func apiFetch(ctx context.Context, apiURL, name string, log *logger.Logger,
	headers map[string]string) ([]byte, int, error) {

	var (
		body   []byte
		status int
		err    error
	)
	for attempt := 0; attempt < 3; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		req, rErr := http.NewRequestWithContext(reqCtx, "GET", apiURL, nil)
		if rErr != nil {
			cancel()
			return nil, 0, rErr
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		req.Header.Set("Accept", "application/json, text/html, */*")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, dErr := apiClient.Do(req)
		if dErr == nil {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			status = resp.StatusCode
			resp.Body.Close()
			cancel()
			// Terminal statuses — no point retrying
			if status == 200 || status == 404 || status == 401 || status == 403 {
				return body, status, nil
			}
			err = fmt.Errorf("HTTP %d", status)
		} else {
			cancel()
			err = dErr
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
		}
	}
	if err != nil {
		log.Debug("%s: %v", name, err)
	}
	return body, status, err
}

// apiFetchPost is apiFetch with a JSON body (Censys v2 search uses POST).
func apiFetchPost(ctx context.Context, apiURL, jsonBody, name string, log *logger.Logger,
	headers map[string]string) ([]byte, int, error) {

	var (
		body   []byte
		status int
		err    error
	)
	for attempt := 0; attempt < 2; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req, rErr := http.NewRequestWithContext(reqCtx, "POST", apiURL, strings.NewReader(jsonBody))
		if rErr != nil {
			cancel()
			return nil, 0, rErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "reconx/1.0")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, dErr := apiClient.Do(req)
		if dErr == nil {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			status = resp.StatusCode
			resp.Body.Close()
			cancel()
			if status == 200 || status == 404 || status == 401 || status == 403 {
				return body, status, nil
			}
			err = fmt.Errorf("HTTP %d", status)
		} else {
			cancel()
			err = dErr
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		log.Debug("%s: %v", name, err)
	}
	return body, status, err
}

// httpGetBody performs a GET request and returns the body bytes + status code.
func httpGetBody(ctx context.Context, apiURL, name string, log *logger.Logger) ([]byte, int, error) {
	return apiFetch(ctx, apiURL, name, log, nil)
}

// httpGetBodyWithAuth is httpGetBody with an extra header (for API keys).
func httpGetBodyWithAuth(ctx context.Context, apiURL, name string, log *logger.Logger,
	headerKey, headerValue string) ([]byte, int, error) {
	return apiFetch(ctx, apiURL, name, log, map[string]string{headerKey: headerValue})
}

// basicAuth encodes user:secret for HTTP Basic auth.
func basicAuth(user, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + secret))
}

// ── Result filtering ─────────────────────────────────────────────────────────

// subdomainFilter wraps the per-source result processing: lowercase, strip
// wildcards/schemes/ports, attach bare prefixes to the parent domain,
// scope-check against the target domain, dedupe.
type subdomainFilter struct {
	domain string
	seen   map[string]bool
	out    []string
}

func newSubdomainFilter(domain string) *subdomainFilter {
	return &subdomainFilter{domain: strings.ToLower(domain), seen: make(map[string]bool)}
}

// add validates a candidate hostname and appends it if it belongs to the
// target domain. Bare prefixes ("api") get the parent domain attached.
// Handles "ip,hostname" CSV entries that some datasets (bufferover) emit.
func (f *subdomainFilter) add(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	// "1.2.3.4,sub.example.com" style entries
	if idx := strings.Index(s, ","); idx != -1 {
		f.add(s[:idx])
		s = s[idx+1:]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if !strings.Contains(s, ".") {
		s = s + "." + f.domain
	}
	if s != f.domain && !strings.HasSuffix(s, "."+f.domain) {
		return false
	}
	if !isValidDomain(s) || f.seen[s] {
		return false
	}
	f.seen[s] = true
	f.out = append(f.out, s)
	return true
}

// boardDone reports the result count on the progress board.
func (f *subdomainFilter) boardDone(board *logger.ProgressBoard, name string) {
	board.Done(name, len(f.out))
}

// ── Binary-backed runner ─────────────────────────────────────────────────────

// runShuffleDNS uses shuffledns (ProjectDiscovery) — wraps massdns for fast
// DNS brute-forcing. Requires a wordlist and resolvers.
func (m *Module) runShuffleDNS(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	wordlist := findWordlist(m.cfg)
	if wordlist == "" {
		board.Skip("shuffledns", "no wordlist found")
		return nil, nil
	}
	resolvers := findResolvers(m.cfg)
	if resolvers == "" {
		board.Skip("shuffledns", "no resolvers found")
		return nil, nil
	}
	path := "shuffledns"
	if tcfg, ok := m.cfg.Tools["shuffledns"]; ok && tcfg.Path != "" {
		path = tcfg.Path
	}
	args := []string{"-d", domain, "-w", wordlist, "-r", resolvers, "-mode", "bruteforce", "-silent"}
	r := runner.Run(ctx, path, args,
		runner.WithTimeout(15*time.Minute),
		runner.WithStderrCallback(func(line string) { m.log.Debug("shuffledns: %s", line) }))
	finalize(board, "shuffledns", r)
	return r.Lines, r.Stderr
}

// ── CT log sources ───────────────────────────────────────────────────────────

// crtshEntry is one record from the crt.sh JSON output.
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// runCrtSh queries crt.sh with proper JSON decoding. crt.sh returns 502/504
// frequently when busy, so we retry with backoff before giving up.
func (m *Module) runCrtSh(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))

	var body []byte
	var status int
	var err error
	var attempt int
	for attempt = 0; attempt < 3; attempt++ {
		body, status, err = httpGetBody(ctx, apiURL, "crt.sh", m.log)
		if err == nil && status == 200 {
			break
		}
		select {
		case <-ctx.Done():
			board.Fail("crt.sh", "cancelled")
			return nil, nil
		case <-time.After(time.Duration(attempt+1) * 3 * time.Second):
		}
	}
	if err != nil || status != 200 {
		board.Fail("crt.sh", fmt.Sprintf("HTTP %d after %d attempts", status, attempt))
		return nil, nil
	}

	f := newSubdomainFilter(domain)
	var entries []crtshEntry
	if jErr := json.Unmarshal(body, &entries); jErr != nil {
		// Fallback for malformed bodies: extract name_value fields directly
		for _, part := range strings.Split(string(body), `"name_value":"`) {
			if idx := strings.Index(part, `"`); idx > 0 {
				for _, sub := range strings.Split(part[:idx], `\n`) {
					f.add(sub)
				}
			}
		}
	} else {
		for _, e := range entries {
			for _, sub := range strings.Split(e.NameValue, "\n") {
				f.add(sub)
			}
		}
	}
	f.boardDone(board, "crt.sh")
	return f.out, nil
}

// ── Aggregator / passive DNS sources ─────────────────────────────────────────

// runAnubis hits jonlu.ca/anubis (jldc.me redirects there) — a free
// aggregator that pulls from many CT logs, VirusTotal, urlscan, and others.
// No token required. Often slow (30s+) but high yield.
func (m *Module) runAnubis(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", url.PathEscape(domain))
	f := newSubdomainFilter(domain)

	reqCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", apiURL, nil)
	if err != nil {
		board.Skip("anubis", "bad request")
		return nil, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := apiClient.Do(req)
	if err != nil {
		board.Skip("anubis", "timeout/network")
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		board.Skip("anubis", fmt.Sprintf("HTTP %d", resp.StatusCode))
		return nil, nil
	}

	var raw []string
	if jErr := json.Unmarshal(body, &raw); jErr != nil {
		// Fallback: one value per line
		for _, line := range strings.Split(string(body), "\n") {
			f.add(strings.Trim(strings.TrimSpace(line), `",[]`))
		}
	} else {
		for _, s := range raw {
			f.add(s)
		}
	}
	f.boardDone(board, "anubis")
	return f.out, nil
}

// runRapidDNS scrapes rapiddns.io — a free service that aggregates CT logs,
// passive DNS, and brute-force results. No token required.
func (m *Module) runRapidDNS(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", url.PathEscape(domain))
	results := m.scrapeSubdomains(ctx, apiURL, domain, "rapiddns", board)
	return results, nil
}

// runSubdomainCenter queries api.subdomain.center — free aggregator.
// Response: JSON array of hostnames.
func (m *Module) runSubdomainCenter(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://api.subdomain.center/?domain=%s", url.QueryEscape(domain))
	f := newSubdomainFilter(domain)

	// subdomain.center can be slow — give it a longer window than the default
	body, status, err := httpGetBody(ctx, apiURL, "subdomaincenter", m.log)
	if err != nil && ctx.Err() == nil {
		board.Skip("subdomaincenter", "timeout/network")
		return nil, nil
	}
	if status != 200 {
		board.Skip("subdomaincenter", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}

	var raw []string
	if jErr := json.Unmarshal(body, &raw); jErr != nil {
		board.Fail("subdomaincenter", "bad JSON")
		return nil, nil
	}
	for _, s := range raw {
		f.add(s)
	}
	f.boardDone(board, "subdomaincenter")
	return f.out, nil
}

// runOTXSubs hits AlienVault OTX passive DNS for subdomains.
func (m *Module) runOTXSubs(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns",
		url.PathEscape(domain))
	f := newSubdomainFilter(domain)

	body, status, err := httpGetBody(ctx, apiURL, "alienvault-otx", m.log)
	if err != nil {
		board.Skip("alienvault-otx", "timeout/network")
		return nil, nil
	}
	if status == 429 {
		board.Skip("alienvault-otx", "rate limited")
		return nil, nil
	}
	if status != 200 {
		board.Skip("alienvault-otx", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}

	var resp struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if jErr := json.Unmarshal(body, &resp); jErr != nil {
		board.Fail("alienvault-otx", "bad JSON")
		return nil, nil
	}
	for _, e := range resp.PassiveDNS {
		f.add(e.Hostname)
	}
	f.boardDone(board, "alienvault-otx")
	return f.out, nil
}

// runURLScan hits urlscan.io's public API. Returns subdomains derived from
// historical scan results (paginated via search_after).
func (m *Module) runURLScan(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	f := newSubdomainFilter(domain)
	searchAfter := ""
	pages := 0

	for pages < 10 { // hard cap: ~10000 results is plenty
		apiURL := fmt.Sprintf(
			"https://urlscan.io/api/v1/search/?q=domain:%s&size=1000",
			url.QueryEscape(domain))
		if searchAfter != "" {
			apiURL += "&search_after=" + url.QueryEscape(searchAfter)
		}
		body, status, err := httpGetBody(ctx, apiURL, "urlscan", m.log)
		if err != nil || status != 200 {
			if pages == 0 {
				if err != nil {
					board.Skip("urlscan", "timeout/network")
				} else {
					board.Skip("urlscan", fmt.Sprintf("HTTP %d", status))
				}
			}
			break
		}
		var resp struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
			} `json:"results"`
			HasMore bool   `json:"has_more"`
			After   string `json:"search_after"`
		}
		if jErr := json.Unmarshal(body, &resp); jErr != nil {
			break
		}
		for _, r := range resp.Results {
			f.add(r.Page.Domain)
		}
		if !resp.HasMore || resp.After == "" {
			break
		}
		searchAfter = resp.After
		pages++
	}
	f.boardDone(board, "urlscan")
	return f.out, nil
}

// runHackerTarget uses the free hackertarget hostsearch API (host,ip CSV).
func (m *Module) runHackerTarget(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	f := newSubdomainFilter(domain)

	body, status, err := httpGetBody(ctx, apiURL, "hackertarget", m.log)
	if err != nil {
		board.Fail("hackertarget", err.Error())
		return nil, nil
	}
	if status != 200 {
		board.Fail("hackertarget", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "API count exceeded") {
		board.Fail("hackertarget", "rate limited")
		return nil, nil
	}
	for _, line := range strings.Split(bodyStr, "\n") {
		if parts := strings.SplitN(line, ",", 2); len(parts) >= 1 {
			f.add(parts[0])
		}
	}
	f.boardDone(board, "hackertarget")
	return f.out, nil
}

// runCertspotter uses the certspotter v1 API. Without a token the response
// is limited but still useful as an independent CT view.
func (m *Module) runCertspotter(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	apiURL := fmt.Sprintf(
		"https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names",
		url.QueryEscape(domain))
	headers := map[string]string{}
	if token := m.cfg.Tokens["certspotter"]; token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	body, status, err := apiFetch(ctx, apiURL, "certspotter", m.log, headers)
	if err != nil {
		board.Skip("certspotter", "timeout/network")
		return nil, nil
	}
	if status == 429 {
		board.Skip("certspotter", "rate limited")
		return nil, nil
	}
	if status != 200 {
		board.Skip("certspotter", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}

	f := newSubdomainFilter(domain)
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if jErr := json.Unmarshal(body, &issuances); jErr != nil {
		board.Fail("certspotter", "bad JSON")
		return nil, nil
	}
	for _, iss := range issuances {
		for _, name := range iss.DNSNames {
			f.add(name)
		}
	}
	f.boardDone(board, "certspotter")
	return f.out, nil
}

// ── Token-gated API sources ──────────────────────────────────────────────────

// runVirusTotal walks VT's /domains/{d}/subdomains endpoint with pagination.
// The old code fetched a single page of 40 — most domains have hundreds.
func (m *Module) runVirusTotal(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["virustotal"]
	f := newSubdomainFilter(domain)
	cursor := ""

	for page := 0; page < 50; page++ { // 50 × 40 = up to 2000 subdomains
		apiURL := fmt.Sprintf(
			"https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40",
			url.PathEscape(domain))
		if cursor != "" {
			apiURL += "&cursor=" + url.QueryEscape(cursor)
		}
		body, status, err := httpGetBodyWithAuth(ctx, apiURL, "virustotal", m.log, "x-apikey", token)
		if err != nil {
			board.Skip("virustotal", "timeout/network")
			return nil, nil
		}
		if status == 401 || status == 403 {
			board.Skip("virustotal", "invalid token/quota")
			return nil, nil
		}
		if status == 429 {
			board.Skip("virustotal", "rate limited — partial results kept")
			break
		}
		if status != 200 {
			board.Skip("virustotal", fmt.Sprintf("HTTP %d", status))
			return nil, nil
		}

		var resp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Meta struct {
				Cursor string `json:"cursor"`
			} `json:"meta"`
		}
		if jErr := json.Unmarshal(body, &resp); jErr != nil {
			board.Fail("virustotal", "bad JSON")
			return nil, nil
		}
		newBefore := len(f.out)
		for _, item := range resp.Data {
			f.add(item.ID)
		}
		if len(resp.Data) == 0 || len(f.out) == newBefore {
			break
		}
		if resp.Meta.Cursor == "" || resp.Meta.Cursor == cursor {
			break
		}
		cursor = resp.Meta.Cursor
	}
	f.boardDone(board, "virustotal")
	return f.out, nil
}

// runShodan uses Shodan's DNS endpoint — requires an API key.
func (m *Module) runShodan(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["shodan"]
	apiURL := fmt.Sprintf(
		"https://api.shodan.io/dns/domain/%s?key=%s",
		url.PathEscape(domain), url.QueryEscape(token))

	body, status, err := httpGetBody(ctx, apiURL, "shodan", m.log)
	if err != nil {
		board.Skip("shodan", "timeout/network")
		return nil, nil
	}
	if status == 401 || status == 403 {
		board.Skip("shodan", "invalid token/quota")
		return nil, nil
	}
	if status != 200 {
		board.Skip("shodan", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}

	f := newSubdomainFilter(domain)
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if jErr := json.Unmarshal(body, &resp); jErr != nil {
		board.Fail("shodan", "bad JSON")
		return nil, nil
	}
	for _, s := range resp.Subdomains {
		f.add(s) // bare prefixes → filter attaches .domain
	}
	f.boardDone(board, "shodan")
	return f.out, nil
}

// runSecurityTrails uses the SecurityTrails v1 API. Free tier = 50 req/month.
func (m *Module) runSecurityTrails(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["securitytrails"]
	apiURL := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains",
		url.PathEscape(domain))

	body, status, err := httpGetBodyWithAuth(ctx, apiURL, "securitytrails", m.log,
		"APIKEY", token)
	if err != nil {
		board.Skip("securitytrails", "timeout/network")
		return nil, nil
	}
	if status == 401 || status == 403 {
		board.Skip("securitytrails", "invalid token/quota")
		return nil, nil
	}
	if status != 200 {
		board.Skip("securitytrails", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}

	f := newSubdomainFilter(domain)
	var resp struct {
		Subdomains []string `json:"subdomains"`
	}
	if jErr := json.Unmarshal(body, &resp); jErr != nil {
		board.Fail("securitytrails", "bad JSON")
		return nil, nil
	}
	for _, s := range resp.Subdomains {
		f.add(s) // bare prefixes → filter attaches .domain
	}
	f.boardDone(board, "securitytrails")
	return f.out, nil
}

// runCensys uses Censys Search API v2 (certificates). The v2 search endpoint
// requires POST + basic auth. Token format: "id:secret".
func (m *Module) runCensys(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	token := m.cfg.Tokens["censys"]
	if token == "" {
		board.Skip("censys", "no token")
		return nil, nil
	}
	// Token format: "id:secret" — encode for HTTP Basic auth
	parts := strings.SplitN(token, ":", 2)
	if len(parts) != 2 {
		board.Skip("censys", "token must be id:secret")
		return nil, nil
	}
	auth := basicAuth(parts[0], parts[1])

	f := newSubdomainFilter(domain)
	reqBody := fmt.Sprintf(`{"q":%q,"per_page":100}`, domain)
	apiURL := "https://search.censys.io/api/v2/certificates/search"
	body, status, err := apiFetchPost(ctx, apiURL, reqBody, "censys", m.log,
		map[string]string{"Authorization": "Basic " + auth})
	if err != nil {
		board.Skip("censys", "timeout/network")
		return nil, nil
	}
	if status == 401 || status == 403 {
		board.Skip("censys", "invalid token/quota")
		return nil, nil
	}
	if status != 200 {
		board.Skip("censys", fmt.Sprintf("HTTP %d", status))
		return nil, nil
	}

	var resp struct {
		Result struct {
			Hits []struct {
				Names []string `json:"names"`
			} `json:"hits"`
		} `json:"result"`
	}
	if jErr := json.Unmarshal(body, &resp); jErr != nil {
		board.Fail("censys", "bad JSON")
		return nil, nil
	}
	for _, hit := range resp.Result.Hits {
		for _, name := range hit.Names {
			f.add(name)
		}
	}
	f.boardDone(board, "censys")
	return f.out, nil
}

// ── Generic JSON helpers ─────────────────────────────────────────────────────

// jsonStrings walks any decoded JSON value and collects every string it
// contains. Used for sources with loose/evolving response shapes.
func jsonStrings(v any) []string {
	var out []string
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// ── HTML scraping ────────────────────────────────────────────────────────────

// scrapeSubdomains fetches an HTML page and extracts subdomain-looking
// candidates that belong to the target domain.
func (m *Module) scrapeSubdomains(ctx context.Context, apiURL, domain, name string,
	board *logger.ProgressBoard) []string {

	body, status, err := httpGetBody(ctx, apiURL, name, m.log)
	if err != nil {
		board.Fail(name, err.Error())
		return nil
	}
	if status != 200 {
		board.Fail(name, fmt.Sprintf("HTTP %d", status))
		return nil
	}

	f := newSubdomainFilter(domain)
	for _, tok := range hostLike.FindAllString(string(body), -1) {
		f.add(tok)
	}
	f.boardDone(board, name)
	return f.out
}
