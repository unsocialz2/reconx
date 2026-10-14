package alive

import (
	"context"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"net/http"
	"net/http/httptest"
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
