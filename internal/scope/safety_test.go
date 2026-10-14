package scope

import (
	"context"
	"github.com/unsocialz2/reconx/internal/config"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLAndCIDRParsing(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Scope.InScope = []string{"10.0.0.0/24", "*.example.com"}
	cfg.Scope.OutOfScope = []string{"blocked.example.com"}
	f := New(cfg)
	for _, v := range []string{"http://10.0.0.2:8080/", "https://ok.example.com/", "https://EXAMPLE.COM./"} {
		if !f.IsInScope(v) {
			t.Errorf("denied %s", v)
		}
	}
	for _, v := range []string{"http://10.0.1.2/", "https://blocked.example.com/", "https://example.com@evil.test/", "https://evil.test@example.com/", "https://example.com.evil.test/"} {
		if f.IsInScope(v) {
			t.Errorf("allowed %s", v)
		}
	}
}
func TestRedirectAndDirectRequestBlockedBeforeContact(t *testing.T) {
	var visits atomic.Int32
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visits.Add(1) }))
	defer denied.Close()
	deniedURL := strings.Replace(denied.URL, "127.0.0.1", "localhost", 1)
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, deniedURL, 302) }))
	defer allowed.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	client := New(cfg).Client(time.Second)
	if _, err := client.Get(allowed.URL); err == nil {
		t.Fatal("out-of-scope redirect accepted")
	}
	if _, err := client.Get(deniedURL); err == nil {
		t.Fatal("direct request accepted")
	}
	if visits.Load() != 0 {
		t.Fatal("excluded server received a request")
	}
}
func TestProxyBlocksHTTPAndHTTPSBeforeContact(t *testing.T) {
	var visits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visits.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	proxy, stop, err := New(cfg).StartProxy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	u, _ := url.Parse(proxy)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatal(resp.Status)
	}
	for _, raw := range []string{strings.Replace(server.URL, "127.0.0.1", "localhost", 1), "https://localhost:443"} {
		resp, err := client.Get(raw)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 403 {
				t.Fatal("excluded request accepted")
			}
		}
	}
	if visits.Load() != 1 {
		t.Fatal("excluded requests reached origin")
	}
}
