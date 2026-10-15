package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectDetectsLegacyFlagsAndBoundsQuietProcesses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "renamed-mantra")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' 'Usage: -s silent' ' -t int thread count'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Workers: 2, Tools: map[string]ToolPolicy{"mantra": {Enabled: true, Path: path, Flags: []string{"-threads", "10"}}}}
	good := Inspect(context.Background(), "mantra", path, policy)
	if good.Status != "compatible" {
		t.Fatalf("legacy thread alias not normalized: %+v", good)
	}
	tcfg := policy.Tools["mantra"]
	tcfg.Flags = []string{"-unsupported"}
	policy.Tools["mantra"] = tcfg
	bad := Inspect(context.Background(), "mantra", path, policy)
	if bad.Status != "incompatible" || len(bad.Unsupported) != 1 || bad.Unsupported[0] != "-unsupported" {
		t.Fatal(bad)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if got := Inspect(ctx, "mantra", path, policy); got.Status != "check_failed" {
		t.Fatal(got)
	}
}
