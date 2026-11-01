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
// gowitness directory. Calls are serial to avoid a multi-browser burst.
// Browser subrequests and JS redirects cannot be fully scope-constrained by
// an HTTPS CONNECT proxy; program rules and third-party ownership still apply.
func (m *Module) RunInventory(ctx context.Context) error {
	if !m.cfg.ToolAvailable("gowitness") {
		return fmt.Errorf("inventory screenshots require gowitness v3 in PATH")
	}
	filter := scope.New(m.cfg)
	root := filepath.Join(m.outDir, "screenshots", "inventory")
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	hosts := m.store.GetHosts()
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i] == nil || hosts[j] == nil { return hosts[i] != nil }
		return hosts[i].Meta["url"] < hosts[j].Meta["url"]
	})
	results := make([]InventoryScreenshot, 0, len(hosts))
	done := map[string]bool{}
	var completed int
	// Persist progress after every target so interruption keeps mappings.
	save := func() error {
		body, err := json.MarshalIndent(results, "", "  ")
		if err != nil { return err }
		return store.AtomicWrite(filepath.Join(m.outDir, "screenshots", "inventory_manifest.json"), body, 0600)
	}
	for _, h := range hosts {
		if h == nil || h.Meta == nil { continue }
		raw := h.Meta["url"]
		if raw == "" || done[raw] { continue }
		done[raw] = true
		entry := InventoryScreenshot{URL: raw, Status: "skipped"}
		if ctx.Err() != nil { return ctx.Err() }
		eligible, reason := safeScreenshotTarget(h, filter)
		if eligible == "" {
			entry.Reason = reason
			results = append(results, entry)
			if err := save(); err != nil { return err }
			continue
		}
		sum := sha256.Sum256([]byte(raw))
		key := hex.EncodeToString(sum[:10])
		destDir := filepath.Join(root, key)
		dest := filepath.Join(destDir, "screenshot.png")
		if err := os.MkdirAll(destDir, 0700); err != nil { return err }
		if info, err := os.Stat(dest); err == nil && info.Size() > 100 {
			entry.Status = "captured"
			entry.Path = filepath.ToSlash(filepath.Join("screenshots", "inventory", key, "screenshot.png"))
		} else {
			tmp := filepath.Join(destDir, ".raw")
			if err := os.MkdirAll(tmp, 0700); err != nil { return err }
			args := []string{"scan", "single", "--url", raw, "--screenshot-path", tmp,
				"--screenshot-format", "png", "--timeout", "20", "--no-http", "--no-https"}
			run := runner.Run(ctx, "gowitness", args, runner.WithTimeout(50*time.Second))
			// The temporary directory contains screenshots for exactly one URL.
			var found string
			_ = filepath.WalkDir(tmp, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() { return nil }
				if strings.HasSuffix(strings.ToLower(path), ".png") {
					if info, e := os.Stat(path); e == nil && info.Size() > 100 { found = path }
				}
				return nil
			})
			if found == "" {
				entry.Status = "failed"
				if run.Err != nil {
					entry.Reason = "gowitness failed: " + fmt.Sprint(run.Err)
				} else {
					entry.Reason = "gowitness did not produce a nonempty PNG"
				}
			} else if err := os.Rename(found, dest); err != nil {
				entry.Status = "failed"
				entry.Reason = "could not move screenshot: " + err.Error()
			} else {
				entry.Status = "captured"
				entry.Path = filepath.ToSlash(filepath.Join("screenshots", "inventory", key, "screenshot.png"))
			}
			_ = os.RemoveAll(tmp)
		}
		results = append(results, entry)
		if entry.Status == "captured" { completed++ }
		if err := save(); err != nil { return err }
	}
	m.log.Info("Inventory screenshots: %d/%d captured; manifest screenshots/inventory_manifest.json", completed, len(results))
	return save()
}
