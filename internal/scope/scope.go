package scope

import (
	"net"
	"strings"

	"github.com/reconx/reconx/internal/config"
)

// Filter enforces scope rules on discovered assets
type Filter struct {
	cfg *config.Config
}

// New creates a new scope filter
func New(cfg *config.Config) *Filter {
	return &Filter{cfg: cfg}
}

// IsInScope returns true if the given value (domain, IP, URL) is within scope
func (f *Filter) IsInScope(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return false
	}

	// Strip protocol for matching
	clean := value
	for _, prefix := range []string{"https://", "http://", "ftp://"} {
		clean = strings.TrimPrefix(clean, prefix)
	}
	// Strip path
	if idx := strings.Index(clean, "/"); idx != -1 {
		clean = clean[:idx]
	}
	// Strip port
	if host, _, err := net.SplitHostPort(clean); err == nil {
		clean = host
	}

	// Check out-of-scope first (deny wins)
	for _, pattern := range f.cfg.Scope.OutOfScope {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if matchPattern(clean, pattern) {
			return false
		}
	}

	// If in_scope list is empty, everything that's not out-of-scope is in
	if len(f.cfg.Scope.InScope) == 0 {
		// Still check against target domains
		for _, domain := range f.cfg.Target.Domains {
			d := strings.ToLower(domain)
			if clean == d || strings.HasSuffix(clean, "."+d) {
				return true
			}
		}
		// Check IP ranges
		for _, cidr := range f.cfg.Target.IPRanges {
			if ipInCIDR(clean, cidr) {
				return true
			}
		}
		return false
	}

	// Check explicit in-scope list
	for _, pattern := range f.cfg.Scope.InScope {
		pattern = strings.TrimSpace(strings.ToLower(pattern))
		if matchPattern(clean, pattern) {
			return true
		}
	}

	return false
}

// FilterList returns only in-scope items from a list
func (f *Filter) FilterList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if f.IsInScope(item) {
			out = append(out, item)
		}
	}
	return out
}

// matchPattern checks if value matches a scope pattern.
// Supports wildcards: *.example.com matches any subdomain.
// "example.com" matches exactly example.com and *.example.com — NOT notexample.com.
func matchPattern(value, pattern string) bool {
	if pattern == value {
		return true
	}
	// Wildcard subdomain: *.example.com → sub.example.com, example.com
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return value == base || strings.HasSuffix(value, "."+base)
	}
	// Plain domain: example.com → sub.example.com (must be a proper subdomain)
	// Require a dot boundary: value ends with "."+pattern, not just pattern as substring
	return strings.HasSuffix(value, "."+pattern)
}

// ipInCIDR checks if an IP string is within a CIDR range
func ipInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}
