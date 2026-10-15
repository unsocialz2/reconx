package urls

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
)

func TestParamHostPriorityDedupAndFallbackCap(t *testing.T) {
	input := []string{"z.example.test", "b.example.test", "api.example.test", "admin.example.test", "known.example.test", "params.example.test", "params.example.test"}
	urls := []string{"https://known.example.test/app", "https://params.example.test/search?q=fixture", "https://outside.test/?q=fixture"}
	got, total := selectParamHosts(input, urls, 1)
	want := []string{"params.example.test", "known.example.test", "api.example.test", "admin.example.test", "b.example.test"}
	if total != 6 || !reflect.DeepEqual(got, want) {
		t.Fatalf("total=%d hosts=%v", total, got)
	}
	got, _ = selectParamHosts(input, urls, 0)
	if len(got) != 4 {
		t.Fatal(got)
	}
}

func TestURLWorkerPoolHonorsWorkersAndCancellation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Workers = 2
	m := &Module{cfg: cfg}
	var active, peak atomic.Int32
	m.forEachDomain(context.Background(), make([]string, 20), func(string) {
		n := active.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
	})
	if peak.Load() != 2 || active.Load() != 0 {
		t.Fatalf("peak=%d active=%d", peak.Load(), active.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.forEachDomain(ctx, []string{"never"}, func(string) { t.Error("scheduled cancelled job") })
}

func fixtureModule(t *testing.T, script string) (*Module, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "paramspider")
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"example.test"}
	cfg.Workers = 1
	cfg.Tools["paramspider"] = config.ToolConfig{Enabled: true, Path: bin, Timeout: 30, TotalTimeout: 1, LateTimeout: 1, FallbackHosts: 100}
	l := logger.New(false, "")
	t.Cleanup(l.Close)
	m := New(cfg, store.New("fixture"), scope.New(cfg), l, dir)
	m.board = l.NewProgressBoard()
	t.Cleanup(m.board.Stop)
	return m, cfg
}

const slowParamFixture = `#!/bin/sh
printf '%s\n' 'https://a.example.test/search?p=fixture' 'https://out-of-scope.test/?p=fixture'
sleep 30
`

func TestParamGlobalBudgetPreservesStreamedResultsUnderNoTimeout(t *testing.T) {
	m, cfg := fixtureModule(t, slowParamFixture)
	cfg.NoTimeout = true
	ctx := runner.WithPolicy(context.Background(), cfg.RunnerPolicy())
	start := time.Now()
	got := m.runParamSpider(ctx, "a.example.test\nb.example.test\nc.example.test")
	if time.Since(start) > 5*time.Second {
		t.Fatal("global budget did not terminate process group")
	}
	if ctx.Err() != nil {
		t.Fatal("parent pipeline context was cancelled")
	}
	if !reflect.DeepEqual(got, []string{"https://a.example.test/search?p=fixture"}) || len(m.store.GetURLs()) != 1 {
		t.Fatal(got, m.store.GetURLs())
	}
	stats := m.board.SourceStats()
	if len(stats) != 1 || stats[0].State != "partial" || stats[0].Total != 3 || stats[0].Count != 1 || stats[0].Processes != 0 || stats[0].FinishedAt.IsZero() {
		t.Fatal(stats)
	}
	if !strings.Contains(strings.Join(m.store.Snapshot().Coverage, ";"), "total runtime budget exhausted") {
		t.Fatal(m.store.Snapshot().Coverage)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestURLPhaseLateBudgetWritesPartialSummaryAndReturns(t *testing.T) {
	m, cfg := fixtureModule(t, slowParamFixture)
	// No real provider or target requests: native HTTP is intercepted and binaries are fixtures.
	previous := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}
	defer func() { http.DefaultClient = previous }()
	param := cfg.Tools["paramspider"]
	param.TotalTimeout = 30
	cfg.Tools["paramspider"] = param
	for name, tool := range cfg.Tools {
		if name != "paramspider" {
			tool.Enabled = false
			cfg.Tools[name] = tool
		}
	}
	fake := filepath.Join(t.TempDir(), "waybackurls")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'https://a.example.test/app.js'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.Tools["waybackurls"] = config.ToolConfig{Enabled: true, Path: fake, Timeout: 5}
	m.store.AddHost(&store.Host{Domain: "a.example.test", Meta: map[string]string{"url": "https://a.example.test"}})
	// Run creates its own board; avoid leaving the fixture board active.
	m.board.Stop()
	ctx := runner.WithPolicy(context.Background(), cfg.RunnerPolicy())
	start := time.Now()
	err := m.Run(ctx)
	if err == nil || time.Since(start) > 5*time.Second || ctx.Err() != nil {
		t.Fatalf("err=%v elapsed=%s parent=%v", err, time.Since(start), ctx.Err())
	}
	if len(m.store.GetURLs()) != 2 || len(m.store.GetJSFiles()) != 1 {
		t.Fatal(m.store.GetURLs(), m.store.GetJSFiles())
	}
	summary, readErr := os.ReadFile(filepath.Join(m.outDir, "data", "url_discovery_summary.json"))
	if readErr != nil || !strings.Contains(string(summary), "late enrichment budget exhausted") || !strings.Contains(string(summary), `"State": "partial"`) {
		t.Fatalf("summary=%s err=%v", summary, readErr)
	}
	if _, err := os.Stat(filepath.Join(m.outDir, "urls.txt")); err != nil {
		t.Fatal(err)
	}
}
