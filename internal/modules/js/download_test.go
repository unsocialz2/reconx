package js

import (
	"context"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDownloadRejectsOffScopeRedirect(t *testing.T) {
	var visits atomic.Int32
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visits.Add(1)
		w.Write([]byte("const secret='fixture';"))
	}))
	defer denied.Close()
	deniedURL := strings.Replace(denied.URL, "127.0.0.1", "localhost", 1)
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect.js" {
			http.Redirect(w, r, deniedURL, 302)
			return
		}
		w.Write([]byte("const value='fixture';"))
	}))
	defer allowed.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	st := store.New("fixture")
	m := New(cfg, st, logger.New(false, ""), t.TempDir())
	got := m.downloadJSFiles(context.Background(), []string{allowed.URL + "/ok.js", allowed.URL + "/redirect.js", deniedURL + "/offscope.js"}, t.TempDir())
	if len(got) != 1 || visits.Load() != 0 {
		t.Fatalf("redirect escaped scope: %v visits=%d", got, visits.Load())
	}
}
