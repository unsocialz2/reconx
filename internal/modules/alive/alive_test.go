package alive

import (
	"context"
	"fmt"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
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

func TestUnavailableFallbackPreservesEvidenceButNotLiveSeeds(t *testing.T) {
	for _, code := range []int{200, 403, 429, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
			defer server.Close()
			cfg := config.DefaultConfig()
			cfg.Target.Domains = []string{"127.0.0.1"}
			st := store.New("availability")
			dir := t.TempDir()
			l := logger.New(false, "")
			defer l.Close()
			m := New(cfg, st, l, dir)
			if err := m.runCurlFallback(context.Background(), []string{strings.TrimPrefix(server.URL, "http://")}); err != nil {
				t.Fatal(err)
			}
			if len(st.GetHosts()) != 1 || st.GetHosts()[0].StatusCode != code {
				t.Fatal("HTTP evidence lost")
			}
			observed, err := os.ReadFile(filepath.Join(dir, "http_responded.txt"))
			if err != nil || !strings.Contains(string(observed), server.URL) {
				t.Fatal("observed endpoint missing", err)
			}
			alive, err := os.ReadFile(filepath.Join(dir, "alive.txt"))
			if err != nil {
				t.Fatal(err)
			}
			wantLive := code == 200 || code == 403
			if strings.Contains(string(alive), server.URL) != wantLive {
				t.Fatalf("status %d wrongly included/excluded from live list: %s", code, alive)
			}
			name := "http_unavailable.txt"
			if code == 429 {
				name = "http_rate_limited.txt"
			}
			if !wantLive {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !strings.Contains(string(raw), server.URL) {
					t.Fatal("unavailable/rate-limit evidence missing", err)
				}
			}
		})
	}
}

func TestHTTPX503IsObservedButNeverLive(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "httpx-fixture")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"url\":\"https://down.example.test\",\"status_code\":503,\"title\":\"Service Unavailable\"}'\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"example.test"}
	st := store.New("httpx-unavailable")
	log := logger.New(false, "")
	defer log.Close()
	m := New(cfg, st, log, dir)
	if err := m.runHttpx(context.Background(), []string{"down.example.test"}, bin, config.ToolConfig{Timeout: 1}); err != nil {
		t.Fatal(err)
	}
	if len(st.GetHosts()) != 1 || st.GetHosts()[0].StatusCode != 503 || st.Stats()["live_hosts"] != 0 {
		t.Fatal("503 incorrectly classified", st.Snapshot().Hosts, st.Stats())
	}
	alive, err := os.ReadFile(filepath.Join(dir, "alive.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(alive)) != "" {
		t.Fatal("503 leaked into live seeds", string(alive))
	}
	unavailable, err := os.ReadFile(filepath.Join(dir, "http_unavailable.txt"))
	if err != nil || !strings.Contains(string(unavailable), "https://down.example.test") {
		t.Fatal("503 evidence lost", err)
	}
}

func TestFailedWAFRefreshCannotReuseOldSuccessOnNextRetry(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "waf-fixture")
	fail := filepath.Join(dir, "fail")
	calls := filepath.Join(dir, "calls")
	script := `#!/bin/sh
while [ "$#" -gt 0 ];do case "$1" in -i) input="$2";shift;;-o) out="$2";shift;;esac;shift;done
echo call >> '` + calls + `'
if [ -f '` + fail + `' ];then exit 2;fi
url=$(cat "$input")
printf '[{"url":"%s","detected":false,"firewall":"None"}]' "$url" > "$out"
`
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"example.test"}
	cfg.Tools["wafw00f"] = config.ToolConfig{Enabled: true, Path: bin, Timeout: 1, TotalTimeout: 1}
	st := store.New("waf-refresh")
	st.AddHost(&store.Host{Domain: "app.example.test", StatusCode: 200, Meta: map[string]string{"url": "https://app.example.test"}})
	if err := os.WriteFile(filepath.Join(dir, "alive.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	log := logger.New(false, "")
	defer log.Close()
	m := New(cfg, st, log, dir)
	if err := m.runWAFDetection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fail, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.runWAFDetection(runner.WithRefresh(context.Background(), true)); err == nil {
		t.Fatal("failed refresh hidden")
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	if err := m.runWAFDetection(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(calls)
	if len(strings.Fields(string(data))) != 3 {
		t.Fatalf("stale success reused: %s", data)
	}
}
