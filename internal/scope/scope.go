package scope

import (
	"fmt"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/pkg/httpcontrol"
	"io"
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
	if imported := f.cfg.Scope.Imported; imported != nil {
		allowed := false
		for _, asset := range imported.Assets {
			if matchAsset(value, host, asset) {
				if asset.Excluded {
					return false
				}
				allowed = true
			}
		}
		if !allowed {
			return false
		}
		if len(f.cfg.Scope.InScope) == 0 {
			return true
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
	controller := t.filter.cfg.HTTPController()
	cfg := t.filter.cfg
	host := strings.ToLower(req.URL.Hostname())
	replayable := (req.Method == http.MethodGet || req.Method == http.MethodHead) && (req.Body == nil || req.Body == http.NoBody || req.GetBody != nil)
	current := req
	for attempt := 0; ; attempt++ {
		if err := controller.Wait(req.Context(), host, cfg.HostRPS); err != nil {
			return nil, err
		}
		response, err := t.base.RoundTrip(current)
		if err != nil || response == nil {
			return response, err
		}
		if response.StatusCode != 429 && response.StatusCode != 503 {
			return response, nil
		}
		maxBackoff := time.Duration(cfg.HTTPMaxBackoff) * time.Second
		delay := httpcontrol.RetryDelay(response.Header.Get("Retry-After"), attempt, time.Now(), maxBackoff)
		controller.Cooldown(host, delay)
		deadline, hasDeadline := req.Context().Deadline()
		if !replayable || attempt >= cfg.HTTPRetries || delay > maxBackoff || (hasDeadline && time.Until(deadline) <= delay) {
			return response, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		current = req.Clone(req.Context())
		if req.GetBody != nil {
			current.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
		}
	}
}

// Imported assets use exact semantics, unlike legacy domain-tree text rules.
func matchAsset(value, host string, a config.ScopeAsset) bool {
	switch a.Kind {
	case "cidr":
		return ipInCIDR(host, a.Host)
	case "wildcard":
		return host != a.Host && strings.HasSuffix(host, "."+a.Host)
	case "host", "ip":
		return host == a.Host
	case "origin":
		if host != a.Host {
			return false
		}
		if strings.Contains(value, "://") {
			u, err := url.Parse(value)
			if err != nil {
				return false
			}
			port := u.Port()
			if port == "" {
				if u.Scheme == "https" {
					port = "443"
				} else if u.Scheme == "http" {
					port = "80"
				}
			}
			return u.Scheme == a.Scheme && port == a.Port
		}
		if a.Excluded {
			return false
		}
		// Bare names are discovery candidates, not authorization for every origin.
		u, err := url.Parse("//" + value)
		return err == nil && (u.Port() == "" || u.Port() == a.Port)
	}
	return false
}

// ValidateDiscoverySeeds prevents explicit selections outside an imported CSV
// from starting enumeration. Wildcard base names are passive discovery seeds,
// not HTTP authorization for the apex itself.
func (f *Filter) ValidateDiscoverySeeds() error {
	imported := f.cfg.Scope.Imported
	if imported == nil {
		return nil
	}
	for _, domain := range f.cfg.Target.Domains {
		allowed := f.IsInScope(domain)
		for _, a := range imported.Assets {
			if !a.Excluded && a.Kind == "wildcard" && a.Host == domain {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("domain seed %s is outside imported scope", domain)
		}
	}
	for _, raw := range f.cfg.Target.IPRanges {
		ip, network, err := net.ParseCIDR(raw)
		if err != nil {
			if !f.IsInScope(raw) {
				return fmt.Errorf("IP seed %s is outside imported scope", raw)
			}
			continue
		}
		ip = ip.Mask(network.Mask)
		last := append(net.IP(nil), ip...)
		for i := range last {
			last[i] |= ^network.Mask[i]
		}
		allowed := false
		for _, a := range imported.Assets {
			if a.Excluded {
				continue
			}
			if a.Kind == "cidr" && ipInCIDR(ip.String(), a.Host) && ipInCIDR(last.String(), a.Host) {
				allowed = true
			}
			if a.Kind == "ip" && ip.Equal(last) && ip.String() == a.Host {
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("IP range seed %s is not contained in an imported allowed network", raw)
		}
	}
	return nil
}
