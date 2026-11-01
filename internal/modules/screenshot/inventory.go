package screenshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"strings"
	"time"

	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/runner"
)

// InventoryScreenshot stores a verifiable URL-to-file mapping. Each origin
// gets its own directory, so HTTP/HTTPS/ports never overwrite one another.
type InventoryScreenshot struct {
	URL    string `json:"url"`
	Path   string `json:"path,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func safeScreenshotTarget(host *store.Host, filter *scope.Filter) (string, string) {
	if host == nil {
		return "", "empty host"
	}
	raw := host.Meta["url"]
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", "missing HTTP origin URL"
	}
	if !filter.IsInScope(raw) {
		return "", "target outside permitted scope"
	}
	if host.StatusCode < 200 || host.StatusCode >= 500 || host.StatusCode == 429 {
		return "", "no screenshot for rate-limited, unavailable or unconfirmed HTTP response"
	}
	if host.StatusCode >= 300 && host.StatusCode < 400 {
		location := host.Meta["location"]
		if location == "" {
			return "", "redirect target unknown; screenshot skipped to prevent off-scope navigation"
		}
		next, err := url.Parse(location)
		if err != nil || !filter.IsInScope(u.ResolveReference(next).String()) {
			return "", "redirect outside scope or invalid; screenshot skipped"
		}
	}
	return raw, ""
}

// RunInventory captures each observed, reachable HTTP endpoint in a separate
// gowitness directory, using a bounded worker pool instead of serial Chrome startups.
// Browser subrequests and JS redirects cannot be fully scope-constrained by
// an HTTPS CONNECT proxy; program rules and third-party ownership still apply.
// inventoryScreenshotArgs uses only flags supported by gowitness v3's
// "scan single" command. An explicit URL keeps HTTP-only origins on HTTP.
func inventoryScreenshotArgs(raw, directory string) []string {
	return []string{"scan", "single", "--url", raw,
		"--screenshot-path", directory, "--screenshot-format", "png",
		"--timeout", "20", "--threads", "1"}
}

func (m *Module) RunInventory(ctx context.Context) error {
	if !m.cfg.ToolAvailable("gowitness") {
		return fmt.Errorf("inventory screenshots require gowitness v3 in PATH")
	}
	filter := scope.New(m.cfg)
	root := filepath.Join(m.outDir, "screenshots", "inventory")
	if err := os.MkdirAll(root, 0700); err != nil { return err }
	hosts := m.store.GetHosts()
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i] == nil || hosts[j] == nil { return hosts[i] != nil }
		return hosts[i].Meta["url"] < hosts[j].Meta["url"]
	})

	type job struct { index int; url string }
	type finished struct { index int; entry InventoryScreenshot }
	var items []InventoryScreenshot
	var jobsToRun []job
	done := make(map[string]bool)
	for _, host := range hosts {
		if host == nil || host.Meta == nil { continue }
		raw := host.Meta["url"]
		if raw == "" || done[raw] { continue }
		done[raw] = true
		idx := len(items)
		entry := InventoryScreenshot{URL:raw,Status:"skipped"}
		if _, reason := safeScreenshotTarget(host, filter); reason != "" {
			entry.Reason = reason
		} else {
			// The blank status marks work that is still pending; manifests
			// only contain completed observations.
			entry.Status = ""
			jobsToRun = append(jobsToRun, job{idx, raw})
		}
		items = append(items, entry)
	}
	manifestPath := filepath.Join(m.outDir, "screenshots", "inventory_manifest.json")
	save := func() error {
		finished := make([]InventoryScreenshot, 0, len(items))
		for _, item := range items {
			if item.Status != "" { finished = append(finished, item) }
		}
		data, err := json.MarshalIndent(finished, "", "  ")
		if err != nil { return err }
		return store.AtomicWrite(manifestPath, data, 0600)
	}
	if err := save(); err != nil { return err }
	workers := m.cfg.ScreenshotWorkers
	if workers < 1 { workers = 1 }
	if workers > 8 { workers = 8 }
	workers = min(workers, max(1, len(jobsToRun)))
	m.log.Info("Inventory screenshots: %d HTTP origins eligible; %d parallel browser workers", len(jobsToRun), workers)

	jobCh := make(chan job)
	resultCh := make(chan finished, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range jobCh {
				if ctx.Err() != nil { return }
				entry := captureInventoryOrigin(ctx, task.url, root)
				resultCh <- finished{index:task.index, entry:entry}
			}
		}()
	}
	go func() {
		defer close(resultCh)
		defer wg.Wait()
	loop:
		for _, task := range jobsToRun {
			select {
			case jobCh <- task:
			case <-ctx.Done():
				break loop
			}
		}
		close(jobCh)
	}()
	var count, captured, failed int
	var persistErr error
	for result := range resultCh {
		items[result.index] = result.entry
		count++
		if result.entry.Status == "captured" { captured++ }
		if result.entry.Status == "failed" { failed++ }
		// Do not rewrite a growing JSON manifest after every screenshot;
		// periodically checkpoint plus a final atomic write.
		if count%8 == 0 && persistErr == nil { persistErr = save() }
	}
	if persistErr == nil { persistErr = save() }
	if persistErr != nil { return persistErr }
	m.log.Info("Inventory screenshots: %d/%d captured (%d failed), %d worker(s); manifest screenshots/inventory_manifest.json", captured, len(jobsToRun), failed, workers)
	if ctx.Err() != nil { return ctx.Err() }
	if failed != 0 {
		return fmt.Errorf("inventory: %d/%d screenshot captures failed; see screenshots/inventory_manifest.json", failed, len(jobsToRun))
	}
	return nil
}

func captureInventoryOrigin(ctx context.Context, raw, root string) InventoryScreenshot {
	entry := InventoryScreenshot{URL: raw, Status:"failed"}
	sum := sha256.Sum256([]byte(raw))
	key := hex.EncodeToString(sum[:10])
	destDir := filepath.Join(root,key)
	dest := filepath.Join(destDir,"screenshot.png")
	if err := os.MkdirAll(destDir, 0700); err != nil {
		entry.Reason = "cannot create screenshot directory: " + err.Error()
		return entry
	}
	entry.Path = filepath.ToSlash(filepath.Join("screenshots", "inventory", key, "screenshot.png"))
	if info, err := os.Stat(dest); err == nil && info.Size() > 100 {
		entry.Status = "captured"
		return entry
	}
	tmp := filepath.Join(destDir,".raw")
	if err := os.MkdirAll(tmp, 0700); err != nil {
		entry.Path = ""
		entry.Reason = err.Error()
		return entry
	}
	defer os.RemoveAll(tmp)
	args := inventoryScreenshotArgs(raw,tmp)
	run := runner.Run(ctx, "gowitness", args, runner.WithHardTimeout(35*time.Second))
	// Each worker owns its URL-hash directory, and no other worker can
	// create or overwrite its temporary screenshots.
	var found string
	_ = filepath.WalkDir(tmp,func(path string,d fs.DirEntry,err error) error {
		if err != nil || d.IsDir() { return nil }
		if strings.HasSuffix(strings.ToLower(path),".png") {
			if stat,e := os.Stat(path); e == nil && stat.Size() > 100 { found=path }
		}
		return nil
	})
	if found == "" {
		entry.Path = ""
		if run.Err != nil {
			entry.Reason = "gowitness failed: " + run.Err.Error()
			if len(run.Stderr) > 0 {
				start := max(0,len(run.Stderr)-5)
				detail := strings.TrimSpace(strings.Join(run.Stderr[start:]," | "))
				if len(detail)>400 {detail=detail[:400]+"..."}
				if detail!=""{entry.Reason+=" — "+detail}
			}
		} else {entry.Reason = "gowitness did not produce a nonempty PNG"}
		return entry
	}
	if err := os.Rename(found,dest); err != nil {
		entry.Path = ""
		entry.Reason = "could not move screenshot: "+err.Error()
		return entry
	}
	entry.Status="captured"
	return entry
}
