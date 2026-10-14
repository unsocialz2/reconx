package scope

import (
	"fmt"
	"github.com/unsocialz2/reconx/internal/config"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Filter struct{ cfg *config.Config }

func New(cfg *config.Config) *Filter { return &Filter{cfg} }

// Host parses URLs rather than interpreting userinfo, ports or query text as a hostname.
func Host(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "://") || strings.HasPrefix(value, "//") {
		u, err := url.Parse(value)
		if err != nil || u.User != nil || u.Hostname() == "" {
			return ""
		}
		return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	}
	if net.ParseIP(value) != nil {
		return strings.ToLower(value)
	}
	u, err := url.Parse("//" + value)
	if err != nil || u.User != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}
func (f *Filter) IsInScope(value string) bool {
	host := Host(value)
	if host == "" {
		return false
	}
	for _, p := range f.cfg.Scope.OutOfScope {
		if matchPattern(host, strings.ToLower(strings.TrimSpace(p))) {
			return false
		}
	}
	if len(f.cfg.Scope.InScope) > 0 {
		for _, p := range f.cfg.Scope.InScope {
			if matchPattern(host, strings.ToLower(strings.TrimSpace(p))) {
				return true
			}
		}
		return false
	}
	for _, d := range f.cfg.Target.Domains {
		if matchPattern(host, strings.ToLower(d)) {
			return true
		}
	}
	for _, cidr := range f.cfg.Target.IPRanges {
		if ipInCIDR(host, cidr) || host == cidr {
			return true
		}
	}
	for _, asset := range f.cfg.Target.CloudAssets {
		if Host(asset) == host {
			return true
		}
	}
	return false
}
func (f *Filter) FilterList(items []string) []string {
	var out []string
	for _, v := range items {
		if f.IsInScope(v) {
			out = append(out, v)
		}
	}
	return out
}
func matchPattern(value, pattern string) bool {
	if strings.Contains(pattern, "/") {
		return ipInCIDR(value, pattern)
	}
	if value == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		pattern = pattern[2:]
		return value == pattern || strings.HasSuffix(value, "."+pattern)
	}
	return strings.HasSuffix(value, "."+pattern)
}
func ipInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	_, network, err := net.ParseCIDR(cidr)
	return ip != nil && err == nil && network.Contains(ip)
}

// Client checks every request, including each redirect, before contacting an asset.
func (f *Filter) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: scopedTransport{f, http.DefaultTransport}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("redirect limit exceeded")
		}
		if !f.IsInScope(req.URL.String()) {
			return fmt.Errorf("redirect outside scope: %s", req.URL.Host)
		}
		return nil
	}}
}

type scopedTransport struct {
	filter *Filter
	base   http.RoundTripper
}

func (t scopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if (req.URL.Scheme != "http" && req.URL.Scheme != "https") || !t.filter.IsInScope(req.URL.String()) {
		return nil, fmt.Errorf("request outside scope: %s", req.URL.Host)
	}
	return t.base.RoundTrip(req)
}
