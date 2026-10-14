package js

import (
	"context"
	"fmt"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestIsValidSecretValue(t *testing.T) {
	// These are actual false positives from the myfitnesspal scan log
	falsePositives := []string{
		"[authToken = null]",
		"[apiKey=e]",
		"[ApiKey = config]",
		"[apiKey:nB]",
		"[refresh_token:n]",
		"[access_token:t]",
		"AIDAAAAAAAAAAAAAAAAA",
		"-----BEGIN PRIVATE KEY-----\"))throw TypeError('\"pkcs8\" must be PKCS#8 formatted string')",
		"rundoublec25k",
		"null",
		"undefined",
		"true",
		"false",
		"options",
		"this.apiKey",
	}

	for _, fp := range falsePositives {
		if isValidSecretValue(fp) {
			t.Errorf("isValidSecretValue(%q) = true, want false (false positive)", fp)
		}
	}

	// These are genuine secrets that should pass
	realSecrets := []string{
		"bearer_token_9918273645a4b3c2d1e0f",
		"secret_key_prod_882910384756201938475",
		"jwt_signature_payload_h8392jf83h20dj",
		"super_secret_production_password_2024",
	}

	for _, sec := range realSecrets {
		if !isValidSecretValue(sec) {
			t.Errorf("isValidSecretValue(%q) = false, want true (valid secret)", sec)
		}
	}
}

func TestActiveJSFirstDeterministicAndFragmentDedup(t *testing.T) {
	all := []string{"https://example.test/old.js", "https://example.test/live.js#old", "https://example.test/a.js"}
	active := []string{"https://example.test/live.js#new"}
	got := prioritizeJS(all, active)
	want := []string{"https://example.test/live.js", "https://example.test/a.js", "https://example.test/old.js"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestTrufflehogFilesystemSourceAndDedup(t *testing.T) {
	line := `{"DetectorName":"Loggly","Raw":"fixture-candidate-value","SourceName":"trufflehog - filesystem","SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/downloads/js_7.js"}}}}`
	sec := parseTrufflehogCandidate(line, map[string]string{"js_7.js": "https://example.test/app.js"})
	if sec == nil || sec.File != "https://example.test/app.js" || sec.Type != "Loggly (candidate)" {
		t.Fatalf("%+v", sec)
	}
	st := store.New("test")
	if !st.AddSecret(sec) || st.AddSecret(sec) || len(st.Secrets) != 1 {
		t.Fatal("duplicate candidate counted")
	}
	if parseTrufflehogCandidate(`{"message":"diagnostic"}`, nil) != nil {
		t.Fatal("diagnostic treated as a secret")
	}
}

func TestJSDownloadFailureBreakdownAndHTMLRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/good.js":
			fmt.Fprint(w, "const fixture = 12345;")
		case "/missing.js":
			w.WriteHeader(404)
		default:
			fmt.Fprint(w, "<!doctype html><html>fallback</html>")
		}
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.Target.IPRanges = []string{"127.0.0.1/32"}
	cfg.Workers = 2
	st := store.New("test")
	l := logger.New(false, "")
	defer l.Close()
	m := New(cfg, st, l, t.TempDir())
	urls := []string{server.URL + "/good.js", server.URL + "/missing.js", server.URL + "/fallback.js"}
	got := m.downloadJSFiles(context.Background(), urls, t.TempDir())
	if len(got) != 1 || got["js_0.js"] != urls[0] {
		t.Fatal(got)
	}
	coverage := strings.Join(st.Snapshot().Coverage, ";")
	if !strings.Contains(coverage, "HTTP 404=1") || !strings.Contains(coverage, "HTML response instead of JavaScript=1") || !strings.Contains(coverage, "downloaded 1/3") {
		t.Fatal(coverage)
	}
}
