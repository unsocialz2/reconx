package config

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ScopeAsset preserves exact host, wildcard, network and origin boundaries.
// Paths cannot be enforced through encrypted subprocess proxy tunnels.
type ScopeAsset struct {
	Identifier   string `json:"identifier"`
	Kind         string `json:"kind"`
	Host         string `json:"host"`
	Scheme       string `json:"scheme,omitempty"`
	Port         string `json:"port,omitempty"`
	Excluded     bool   `json:"excluded"`
	Instructions string `json:"instructions,omitempty"`
}
type ScopeImport struct {
	Format  string       `json:"format"`
	Assets  []ScopeAsset `json:"assets"`
	Skipped []string     `json:"skipped,omitempty"`
}

var csvDomain = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func csvHeader(v string) string {
	v = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(v, "\ufeff")))
	return strings.NewReplacer(" ", "_", "-", "_").Replace(v)
}
func csvEligibility(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1", "in_scope", "in scope", "in-scope":
		return true, nil
	case "false", "no", "0", "out_of_scope", "out of scope", "out-of-scope":
		return false, nil
	default:
		return false, fmt.Errorf("missing or unrecognized scope eligibility %q", v)
	}
}
func parseScopeAsset(identifier string) (ScopeAsset, error) {
	a := ScopeAsset{Identifier: strings.TrimSpace(identifier)}
	value := strings.ToLower(strings.TrimSpace(identifier))
	if ip := net.ParseIP(value); ip != nil {
		a.Kind = "ip"
		a.Host = ip.String()
		return a, nil
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		a.Kind = "cidr"
		a.Host = network.String()
		return a, nil
	}
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return a, fmt.Errorf("invalid HTTP origin")
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
			return a, fmt.Errorf("path/query-specific scope requires manual handling; it cannot be enforced through HTTPS tunnels")
		}
		a.Kind = "origin"
		a.Host = strings.TrimSuffix(u.Hostname(), ".")
		a.Scheme = u.Scheme
		a.Port = u.Port()
		if a.Port == "" {
			a.Port = "80"
			if a.Scheme == "https" {
				a.Port = "443"
			}
		}
		port, err := strconv.Atoi(a.Port)
		if err != nil || port < 1 || port > 65535 {
			return a, fmt.Errorf("invalid origin port")
		}
		a.Port = strconv.Itoa(port)
		if net.ParseIP(a.Host) == nil && !csvDomain.MatchString(a.Host) {
			return a, fmt.Errorf("invalid origin hostname")
		}
		return a, nil
	}
	a.Kind = "host"
	if strings.HasPrefix(value, "*.") {
		a.Kind = "wildcard"
		value = strings.TrimPrefix(value, "*.")
	}
	value = strings.TrimSuffix(value, ".")
	if len(value) > 253 || !csvDomain.MatchString(value) {
		return a, fmt.Errorf("not a supported hostname, wildcard, IP, CIDR or HTTP origin")
	}
	a.Host = value
	return a, nil
}

// LoadScopeCSV is transactional: ambiguous rows never partly change scope.
// H1 bounty eligibility is deliberately ignored: VDP assets remain eligible.
func (c *Config) LoadScopeCSV(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8*1024*1024+1))
	if err != nil {
		return err
	}
	if len(data) > 8*1024*1024 {
		return fmt.Errorf("scope CSV exceeds 8 MiB")
	}
	reader := csv.NewReader(strings.NewReader(string(data)))
	headers, err := reader.Read()
	if err != nil {
		return fmt.Errorf("scope CSV header: %w", err)
	}
	index := map[string]int{}
	for i, h := range headers {
		h = csvHeader(h)
		if _, ok := index[h]; ok {
			return fmt.Errorf("duplicate CSV header %q", h)
		}
		index[h] = i
	}
	find := func(names ...string) int {
		for _, n := range names {
			if i, ok := index[n]; ok {
				return i
			}
		}
		return -1
	}
	id := find("asset_identifier", "target", "target_url", "url", "identifier")
	eligible := find("eligible_for_submission", "in_scope", "scope")
	kind := find("asset_type", "category", "target_type", "type")
	instructions := find("instruction", "instructions", "description")
	if id < 0 || eligible < 0 {
		return fmt.Errorf("scope CSV requires asset_identifier/target/url and eligible_for_submission/in_scope/scope columns; eligibility is never inferred from bounty")
	}
	imported := &ScopeImport{Format: "targets-csv"}
	if _, ok := index["asset_identifier"]; ok {
		imported.Format = "hackerone-csv"
	}
	if _, ok := index["in_scope"]; ok {
		if _, h1 := index["asset_identifier"]; !h1 {
			imported.Format = "target-groups-csv"
		}
	}
	domains, ips := map[string]bool{}, map[string]bool{}
	includes := 0
	for row := 2; ; row++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("scope CSV row %d: %w", row, err)
		}
		if row > 10001 {
			return fmt.Errorf("scope CSV exceeds 10000 rows")
		}
		in, err := csvEligibility(record[eligible])
		if err != nil {
			return fmt.Errorf("scope CSV row %d: %w", row, err)
		}
		// Reject conflicting eligibility columns rather than trusting one silently.
		for _, column := range []string{"eligible_for_submission", "in_scope", "scope"} {
			if i, ok := index[column]; ok && i != eligible {
				other, e := csvEligibility(record[i])
				if e != nil || other != in {
					return fmt.Errorf("scope CSV row %d: conflicting eligibility columns", row)
				}
			}
		}
		assetType := ""
		if kind >= 0 {
			assetType = csvHeader(record[kind])
		}
		switch assetType {
		case "", "url", "website", "web", "web_application", "api", "domain", "wildcard", "ip", "ip_address", "cidr":
		default:
			if !in {
				switch assetType {
				case "android_app_id", "android", "androidplaystore", "ios_app_store_id", "ios", "iosappstore", "hardware", "source_code", "sourcecode":
				default:
					if _, err := parseScopeAsset(record[id]); err == nil {
						return fmt.Errorf("scope CSV row %d: excluded web/network identifier has unsupported type %q; classify this row explicitly", row, assetType)
					}
				}
			}
			imported.Skipped = append(imported.Skipped, fmt.Sprintf("row %d: unsupported asset type %s (%s)", row, assetType, record[id]))
			continue
		}
		a, err := parseScopeAsset(record[id])
		if err != nil {
			return fmt.Errorf("scope CSV row %d (%s): %w", row, record[id], err)
		}
		a.Excluded = !in
		if instructions >= 0 {
			a.Instructions = record[instructions]
		}
		imported.Assets = append(imported.Assets, a)
		if in {
			includes++
			if a.Kind == "ip" || a.Kind == "cidr" {
				ips[a.Host] = true
			} else {
				domains[a.Host] = true
			}
		}
	}
	if includes == 0 {
		return fmt.Errorf("scope CSV contains no supported in-scope web/network assets (skipped %d rows)", len(imported.Skipped))
	}
	if c.Phases.PortScan {
		for _, a := range imported.Assets {
			if a.Kind == "origin" && !a.Excluded {
				return fmt.Errorf("origin-specific CSV scope cannot authorize raw port scanning; keep --ports disabled")
			}
		}
	}
	c.Scope.Imported = imported
	// Explicit CLI/INI targets select a subset; otherwise derive discovery seeds.
	if len(c.Target.Domains)+len(c.Target.IPRanges) == 0 {
		if len(c.Target.Domains) == 0 {
			for d := range domains {
				c.Target.Domains = append(c.Target.Domains, d)
			}
			sort.Strings(c.Target.Domains)
		}
		if len(c.Target.IPRanges) == 0 {
			for ip := range ips {
				c.Target.IPRanges = append(c.Target.IPRanges, ip)
			}
			sort.Strings(c.Target.IPRanges)
		}
	}
	return nil
}
