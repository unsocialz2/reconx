package alive

import (
	"context"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFallbackPreservesSuccessfulHTTPScheme(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	st := store.New("fixture")
	m := New(cfg, st, logger.New(false, ""), t.TempDir())
	if err := m.runCurlFallback(context.Background(), []string{strings.TrimPrefix(server.URL, "http://")}); err != nil {
		t.Fatal(err)
	}
	hosts := st.GetHosts()
	if len(hosts) != 1 || hosts[0].Meta["url"] != server.URL {
		t.Fatalf("HTTP endpoint lost: %+v", hosts)
	}
}
func TestHTTPXParsesIPv6EndpointAndEscapedTitle(t *testing.T) {
	h := parseHTTPXLine(`{"url":"https://[2001:db8::1]:8443/","title":"A \"quoted\" title","status_code":200}`)
	if h == nil || h.Domain != "2001:db8::1" || h.Port != 8443 || h.Title != `A "quoted" title` {
		t.Fatalf("bad parse: %+v", h)
	}
}

func TestWAFJSONPreservesNegativeAndGenericDetections(t *testing.T) {
	results, err := parseWAFJSON([]byte(`[{"url":"https://plain.example.test","detected":false,"firewall":"None"},{"url":"https://protected.example.test","detected":true,"firewall":"Generic"},{"url":"https://unknown.example.test"}]`))
	if err != nil || len(results) != 2 || results[0].Detected || !results[1].Detected {
		t.Fatalf("%+v %v", results, err)
	}
}

func TestWAFPerHostBudgetAndCompletedJobReuse(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "waf-fixture")
	calls := filepath.Join(dir, "calls")
	ready := filepath.Join(dir, "ready")
	script := `#!/bin/sh
while [ "$#" -gt 0 ];do case "$1" in -i) input="$2";shift;;-o) out="$2";shift;;esac;shift;done
url=$(cat "$input")
printf '%s\n' "$url" >> '` + calls + `'
case "$url" in *slow*) if [ ! -f '` + ready + `' ];then sleep 5;fi;;esac
printf '[{"url":"%s","detected":false,"firewall":"None"}]' "$url" > "$out"
`
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Workers = 2
	cfg.Target.Domains = []string{"example.test"}
	cfg.Tools["wafw00f"] = config.ToolConfig{Enabled: true, Path: bin, Timeout: 1, TotalTimeout: 1}
	st := store.New("waf-test")
	for _, host := range []string{"fast.example.test", "slow.example.test"} {
		st.AddHost(&store.Host{Domain: host, Meta: map[string]string{"url": "https://" + host}})
	}
	if err := os.WriteFile(filepath.Join(dir, "alive.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	l := logger.New(false, "")
	defer l.Close()
	m := New(cfg, st, l, dir)
	if err := m.runWAFDetection(context.Background()); err == nil {
		t.Fatal("partial WAF run marked complete")
	}
	if _, known := st.WAFStatus("https://fast.example.test"); !known {
		t.Fatal("completed host result lost")
	}
	if err := os.WriteFile(ready, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.runWAFDetection(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(calls)
	if strings.Count(string(raw), "fast.example.test") != 1 {
		t.Fatalf("completed host reran: %s", raw)
	}
}
