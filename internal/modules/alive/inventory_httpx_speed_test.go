package alive

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"github.com/unsocialz2/reconx/pkg/runner"
)

// A local fake httpx verifies that hundreds of inventory inputs are piped
// to one executable without added rate/thread caps. No target is contacted.
func TestInventoryHTTPXUsesOneProcessForEntireInput(t *testing.T) {
	work := t.TempDir()
	binary := filepath.Join(work, "fake-httpx")
	calls := filepath.Join(work, "calls")
	script := `#!/bin/sh
case " $* " in
  *" -rate-limit "*) exit 40;;
  *" -rl "*) exit 41;;
  *" -threads "*) exit 42;;
esac
echo call >> "$RECONX_HTTPX_FIXTURE_CALLS"
while IFS= read -r origin; do
  [ -z "$origin" ] && continue
  printf '{"url":"%s","status_code":200,"tech":["nginx"]}\n' "$origin"
done
`
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil { t.Fatal(err) }
	t.Setenv("RECONX_HTTPX_FIXTURE_CALLS", calls)
	cfg := config.DefaultConfig()
	cfg.InventoryOnly = true
	cfg.InventoryThorough = true
	cfg.Workers = 2
	cfg.HostRPS = 1
	cfg.Scope.Imported = &config.ScopeImport{Assets: []config.ScopeAsset{
		{Kind: "wildcard", Host: "example.org"},
	}}
	cfg.Tools["httpx"] = config.ToolConfig{Enabled: true, Path: binary, Timeout: 30}
	st := store.New("test-httpx-single-process")
	var endpoints []string
	for i := 0; i < 300; i++ {
		endpoints = append(endpoints, fmt.Sprintf("https://host-%03d.example.org", i))
	}
	log := logger.New(false, "")
	defer log.Close()
	ctx := runner.WithPolicy(context.Background(), cfg.RunnerPolicy())
	ctx = runner.WithTaskDirectory(ctx, filepath.Join(work, "tasks"))
	mod := New(cfg, st, log, work)
	if err := mod.runHttpx(ctx, endpoints, binary, cfg.Tools["httpx"]); err != nil { t.Fatal(err) }
	count, err := os.ReadFile(calls)
	if err != nil { t.Fatal(err) }
	if strings.Count(string(count), "call") != 1 {
		t.Fatalf("expected one httpx subprocess for 300 endpoints; got %q", count)
	}
	if got := len(st.GetHosts()); got != len(endpoints) {
		t.Fatalf("expected %d HTTP observations, got %d", len(endpoints), got)
	}
}
