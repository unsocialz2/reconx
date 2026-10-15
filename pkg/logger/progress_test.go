package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPerTargetCountersAndPartialState(t *testing.T) {
	b := &ProgressBoard{tools: map[string]*ToolStatus{}}
	var wg sync.WaitGroup
	for target, count := range map[string]int{"a.example.test": 181, "b.example.test": 40} {
		wg.Add(1)
		go func(target string, count int) {
			defer wg.Done()
			child := b.ForTarget(target)
			child.Register("subfinder", target)
			child.Done("subfinder", count)
		}(target, count)
	}
	wg.Wait()
	stats := b.SourceStats()
	if len(stats) != 2 || stats[0].Count+stats[1].Count != 221 {
		t.Fatal(stats)
	}
	child := b.ForTarget("a.example.test")
	child.Register("katana", "target")
	child.Timeout("katana", 10)
	child.DoneIfRunning("katana", 8)
	for _, s := range b.SourceStats() {
		if strings.HasSuffix(s.Name, " / katana") && (s.State != "timeout" || s.Count != 8) {
			t.Fatal(s)
		}
	}
}

func TestEffectiveCommandsRedactInjectedHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.log")
	l := New(false, path)
	l.EffectiveToolCmd("/tools/httpx", []string{"-threads", "3", "-H", "Authorization: fixture-secret", "--token=another-secret", "--header=Cookie: inline-secret"})
	l.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "fixture-secret") || strings.Contains(string(data), "another-secret") || strings.Contains(string(data), "inline-secret") || !strings.Contains(string(data), "[CMD] /tools/httpx -threads 3") {
		t.Fatal(string(data))
	}
}

func TestTerminalDurationsFreezeAndProgressSurvivesMerge(t *testing.T) {
	for _, state := range []string{"done", "timeout", "partial", "error", "skipped"} {
		t.Run(state, func(t *testing.T) {
			b := &ProgressBoard{tools: map[string]*ToolStatus{}}
			b.Register("tool", "fixture")
			b.Progress("tool", 2, 5, 7)
			switch state {
			case "done":
				b.Done("tool", 7)
			case "timeout":
				b.Timeout("tool", 7)
			case "partial":
				b.Partial("tool", "budget")
			case "error":
				b.Fail("tool", "failure")
			case "skipped":
				b.Skip("tool", "disabled")
			}
			first := b.SourceStats()[0]
			b.DoneIfRunning("tool", 7)
			last := b.SourceStats()[0]
			if first.FinishedAt.IsZero() || !first.FinishedAt.Equal(last.FinishedAt) || first.Elapsed(time.Now()) != last.Elapsed(time.Now().Add(time.Hour)) {
				t.Fatalf("first=%+v last=%+v", first, last)
			}
			if state == "done" && !strings.Contains(last.Message, "2/5 hosts | 7 URLs") {
				t.Fatal(last.Message)
			}
		})
	}
}

func TestProcessLifecycleTracksQuietSubprocesses(t *testing.T) {
	b := &ProgressBoard{tools: map[string]*ToolStatus{}}
	child := b.ForTarget("fixture")
	child.Register("tool", "target")
	child.Process("tool", 123, true)
	child.Process("tool", 456, true)
	if got := b.SourceStats()[0].Processes; got != 2 {
		t.Fatal(got)
	}
	child.Process("tool", 123, false)
	child.Process("tool", 456, false)
	if got := b.SourceStats()[0].Processes; got != 0 {
		t.Fatal(got)
	}
}
