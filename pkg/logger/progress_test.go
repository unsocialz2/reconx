package logger

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
