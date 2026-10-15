package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInputBatchesRetryOnlyIncompleteAndReplayParsers(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake")
	calls := filepath.Join(dir, "calls")
	gate := filepath.Join(dir, "ready")
	script := "#!/bin/sh\nread value\nprintf '%s\\n' \"$value\" >> '" + calls + "'\necho \"$value\"\nif [ \"$value\" = slow ] && [ ! -f '" + gate + "' ];then sleep 5;fi\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx := WithTaskDirectory(context.Background(), filepath.Join(dir, "tasks"))
	var lines []string
	// Leave room for subprocess startup under the race detector and a busy CI host.
	opts := []Option{WithTimeout(300 * time.Millisecond), WithLineCallback(func(s string) { lines = append(lines, s) })}
	r := RunInputBatches(ctx, bin, nil, "fast\nslow\nafter", 1, 3*time.Second, "", opts...)
	if r.Err == nil || strings.Join(r.Lines, ",") != "fast,slow,after" {
		t.Fatalf("%+v", r)
	}
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	lines = nil
	r = RunInputBatches(ctx, bin, nil, "fast\nslow\nafter", 1, 3*time.Second, "", opts...)
	raw, _ := os.ReadFile(calls)
	if r.Err != nil || strings.Join(lines, ",") != "fast,slow,after" || strings.Join(strings.Fields(string(raw)), ",") != "fast,slow,after,slow" {
		t.Fatalf("result=%+v lines=%v calls=%s", r, lines, raw)
	}
}
func TestInputBatchesFileAdapterAndParentCancellation(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "file-tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ncat \"$2\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := RunInputBatches(context.Background(), bin, []string{"-S", "placeholder"}, "a\nb\nc", 2, time.Second, "-S")
	if r.Err != nil || strings.Join(r.Lines, ",") != "a,b,c" {
		t.Fatalf("%+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = RunInputBatches(ctx, bin, nil, "a", 1, time.Second, "")
	if r.Err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestExpiredBudgetStillReplaysLaterCachedBatches(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nread v\necho \"$v\"\nif [ \"$v\" = slow ];then sleep 3;fi\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx := WithTaskDirectory(context.Background(), filepath.Join(dir, "tasks"))
	if r := RunInputBatches(ctx, bin, nil, "cached", 1, time.Second, ""); r.Err != nil {
		t.Fatal(r.Err)
	}
	var events []TaskEvent
	ctx = WithTaskObserver(ctx, func(e TaskEvent) { events = append(events, e) })
	r := RunInputBatches(ctx, bin, nil, "slow\npending\ncached", 1, 300*time.Millisecond, "")
	if r.Err == nil || r.TimeoutKind != "source-budget" || strings.Join(r.Lines, ",") != "slow,cached" {
		t.Fatalf("%+v", r)
	}
	if len(events) != 3 || events[0].State != "partial" || events[1].State != "pending" || events[2].State != "reused" {
		t.Fatal(events)
	}
}
func TestPacingChangesReuseSuccessAndFailedRefreshStaysRetryable(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "katana")
	calls := filepath.Join(dir, "calls")
	fail := filepath.Join(dir, "fail")
	script := "#!/bin/sh\necho call >> '" + calls + "'\ncat\nif [ -f '" + fail + "' ];then exit 2;fi\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Workers: 1, Tools: map[string]ToolPolicy{"katana": {Enabled: true, Path: bin, Timeout: time.Second}}}
	ctx := WithTaskDirectory(WithPolicy(context.Background(), policy), filepath.Join(dir, "tasks"))
	if r := RunInputBatches(ctx, "katana", []string{"-c", "1", "-p", "1"}, "host", 1, time.Second, ""); r.Err != nil {
		t.Fatal(r.Err)
	}
	policy.Workers = 3
	tc := policy.Tools["katana"]
	tc.Timeout = 2 * time.Second
	tc.RateLimit = 1
	policy.Tools["katana"] = tc
	ctx = WithTaskDirectory(WithPolicy(context.Background(), policy), filepath.Join(dir, "tasks"))
	var events []TaskEvent
	ctx = WithTaskObserver(ctx, func(e TaskEvent) { events = append(events, e) })
	args := []string{"-c", "3", "-p", "1"}
	if r := RunInputBatches(ctx, "katana", args, "host", 1, time.Second, ""); r.Err != nil || len(events) != 1 || events[0].State != "reused" {
		t.Fatal(r, events)
	}
	if err := os.WriteFile(fail, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if r := RunInputBatches(WithRefresh(ctx, true), "katana", args, "host", 1, time.Second, ""); r.Err == nil {
		t.Fatal("refresh failure lost")
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	if r := RunInputBatches(ctx, "katana", args, "host", 1, time.Second, ""); r.Err != nil {
		t.Fatal(r.Err)
	}
	data, _ := os.ReadFile(calls)
	if len(strings.Fields(string(data))) != 3 {
		t.Fatalf("old success hid failed refresh: %s", data)
	}
}

func TestFailedRefreshInvalidatesLegacyCacheAcrossWorkerCounts(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "katana")
	calls := filepath.Join(dir, "calls")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho call >> '"+calls+"'\ncat\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	tool := ToolPolicy{Enabled: true, Path: bin, Timeout: time.Second}
	args := []string{"-c", "1", "-p", "1"}
	identity, _ := json.Marshal([]any{"v1.2", "katana", args, "host", tool, 1, ""})
	key := fmt.Sprintf("%x.json", sha256.Sum256(identity))
	cache := filepath.Join(dir, "tasks")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Result{Tool: bin, Lines: []string{"host"}, ExitCode: 0})
	if err := os.WriteFile(filepath.Join(cache, key), data, 0600); err != nil {
		t.Fatal(err)
	}
	makeCtx := func(workers int) context.Context {
		return WithTaskDirectory(WithPolicy(context.Background(), Policy{Workers: workers, Tools: map[string]ToolPolicy{"katana": tool}}), cache)
	}
	if r := RunInputBatches(makeCtx(1), "katana", args, "host", 1, time.Second, ""); r.Err != nil {
		t.Fatal("legacy success did not replay", r.Err)
	}
	if r := RunInputBatches(WithRefresh(makeCtx(3), true), "katana", []string{"-c", "3", "-p", "1"}, "host", 1, time.Second, ""); r.Err == nil {
		t.Fatal("refresh failure lost")
	}
	if r := RunInputBatches(makeCtx(1), "katana", args, "host", 1, time.Second, ""); r.Err == nil {
		t.Fatal("legacy success masked failed refresh")
	}
	raw, _ := os.ReadFile(calls)
	if len(strings.Fields(string(raw))) != 2 {
		t.Fatal(string(raw))
	}
}

func TestSourceDeadlineAndBatchTimeoutHaveDifferentDiagnostics(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "slow")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	source := RunInputBatches(context.Background(), bin, nil, "host", 1, 20*time.Millisecond, "", WithTimeout(time.Second))
	batch := RunInputBatches(context.Background(), bin, nil, "host", 1, time.Second, "", WithTimeout(20*time.Millisecond))
	if !source.IsTimeout() || source.TimeoutKind != "source-budget" || !strings.Contains(source.DiagString(), "total source budget") {
		t.Fatal(source)
	}
	if !batch.IsTimeout() || batch.TimeoutKind != "" || strings.Contains(batch.DiagString(), "total source budget") {
		t.Fatal(batch)
	}
}
