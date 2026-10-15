package scope

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
)

func TestImportedScopeExactWildcardAndOriginBoundaries(t *testing.T) {
	cfg := config.DefaultConfig()
	p := filepath.Join(t.TempDir(), "scope.csv")
	data := "target,in_scope\n*.example.test,true\nblocked.example.test,false\nexact.other.test,true\nhttps://api.origin.test:8443/,true\n10.2.0.0/16,true\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cfg.LoadScopeCSV(p); err != nil {
		t.Fatal(err)
	}
	f := New(cfg)
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"example.test", false}, {"app.example.test", true}, {"deep.app.example.test", true}, {"blocked.example.test", false},
		{"exact.other.test", true}, {"sub.exact.other.test", false}, {"api.origin.test", true},
		{"https://api.origin.test:8443/path", true}, {"http://api.origin.test:8443/", false}, {"https://api.origin.test/", false},
		{"https://user:pass@app.example.test/", false}, {"https://app.example.test.evil.test/", false},
		{"10.2.1.2", true}, {"10.3.1.2", false},
	} {
		if got := f.IsInScope(tc.value); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.value, got, tc.want)
		}
	}
	cfg.Scope.InScope = []string{"exact.other.test"}
	if f.IsInScope("app.example.test") {
		t.Fatal("legacy allowlist bypassed")
	}
	cfg.Scope.OutOfScope = []string{"exact.other.test"}
	if f.IsInScope("exact.other.test") {
		t.Fatal("legacy exclusion bypassed")
	}
}
func TestImportedOriginProxyRejectsCONNECTOnOtherPort(t *testing.T) {
	var visits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visits.Add(1) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	cfg := config.DefaultConfig()
	cfg.Scope.Imported = &config.ScopeImport{Assets: []config.ScopeAsset{{Kind: "origin", Host: u.Hostname(), Scheme: "https", Port: "443"}}}
	proxy, stop, err := New(cfg).StartProxy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	p, _ := url.Parse(proxy)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(p)}}
	if _, err := client.Get("https://" + u.Host); err == nil {
		t.Fatal("out-of-origin tunnel allowed")
	}
	if visits.Load() != 0 {
		t.Fatal("excluded endpoint contacted")
	}
}

func TestCSVSelectedSeedsCannotBroadenNetworksOrDomains(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Scope.Imported = &config.ScopeImport{Assets: []config.ScopeAsset{{Kind: "wildcard", Host: "example.test"}, {Kind: "cidr", Host: "10.2.0.0/16"}}}
	cfg.Target.Domains = []string{"example.test"}
	cfg.Target.IPRanges = []string{"10.2.0.0/24"}
	if err := New(cfg).ValidateDiscoverySeeds(); err != nil {
		t.Fatal(err)
	}
	cfg.Target.IPRanges = []string{"10.2.0.0/8"}
	if New(cfg).ValidateDiscoverySeeds() == nil {
		t.Fatal("broader network seed accepted")
	}
	cfg.Target.IPRanges = nil
	cfg.Target.Domains = []string{"outside.test"}
	if New(cfg).ValidateDiscoverySeeds() == nil {
		t.Fatal("outside domain seed accepted")
	}
}
