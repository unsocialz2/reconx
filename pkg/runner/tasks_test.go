package runner

import (
	"context"
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
	opts := []Option{WithTimeout(50 * time.Millisecond), WithLineCallback(func(s string) { lines = append(lines, s) })}
	r := RunInputBatches(ctx, bin, nil, "fast\nslow\nafter", 1, time.Second, "", opts...)
	if r.Err == nil || strings.Join(r.Lines, ",") != "fast,slow,after" {
		t.Fatalf("%+v", r)
	}
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	lines = nil
	r = RunInputBatches(ctx, bin, nil, "fast\nslow\nafter", 1, time.Second, "", opts...)
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
