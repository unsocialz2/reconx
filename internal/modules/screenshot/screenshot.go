package screenshot

import (
"context"
"fmt"
"os"
"path/filepath"
"strings"
"time"

"github.com/reconx/reconx/internal/config"
"github.com/reconx/reconx/internal/store"
"github.com/reconx/reconx/pkg/logger"
"github.com/reconx/reconx/pkg/runner"
)

// Module takes screenshots of live hosts using gowitness.
// Screenshots are saved per-domain: screenshots/<domain>/screenshot.png
type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

// New creates a screenshot module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run takes screenshots of all live hosts.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Screenshots", "gowitness — capturing live host previews (per-domain folders)")

	hosts := m.store.GetHosts()
	if len(hosts) == 0 {
		m.log.Warn("No live hosts to screenshot")
		return nil
	}

	tool := "gowitness"
	if !runner.IsAvailable(tool) {
		m.log.ToolSkipped(tool,
"not found — install: go install github.com/sensepost/gowitness@latest")
		return nil
	}

	// Root screenshots dir
	ssRoot := filepath.Join(m.outDir, "screenshots")
	if err := os.MkdirAll(ssRoot, 0755); err != nil {
		return fmt.Errorf("creating screenshots dir: %w", err)
	}

	// Build alive.txt if needed
	aliveFile := m.outDir + "/alive.txt"
	if _, err := os.Stat(aliveFile); os.IsNotExist(err) {
		var lines []string
		for _, h := range hosts {
			if u, ok := h.Meta["url"]; ok {
				lines = append(lines, u)
			} else {
				lines = append(lines, "https://"+h.Domain)
			}
		}
		if err := store.SaveRaw(aliveFile, lines); err != nil {
			return fmt.Errorf("writing alive.txt: %w", err)
		}
	}

	// gowitness scan: flat output first, then we organize per-domain
	flatDir := filepath.Join(ssRoot, ".raw")
	_ = os.MkdirAll(flatDir, 0755)

	args := []string{
		"scan", "file",
		"-f", aliveFile,
		"--screenshot-path", flatDir,
		"--screenshot-format", "png",
		"--timeout", "20",
		"--threads", "5",
		"--no-http",
		"--no-https",
	}
	if m.cfg.BugBountyHeader != "" {
		args = append(args, "--chrome-header", m.cfg.BugBountyHeader)
	}

	m.log.Tool("gowitness", fmt.Sprintf("%d live hosts", len(hosts)))
	m.log.ToolCmd("gowitness", args, "")
	start := time.Now()

	board := m.log.NewProgressBoard()
	board.Register("gowitness", fmt.Sprintf("%d hosts", len(hosts)))

	// Budget: ~10s per host at 5 threads, with a floor of 15 min and a cap
	// of 60 min for very large host lists. The previous fixed 15 min cap
	// truncated screenshots on 150+ host scans.
	budget := time.Duration(len(hosts)*10/5+60) * time.Second
	if budget < 15*time.Minute {
		budget = 15 * time.Minute
	}
	if budget > 60*time.Minute {
		budget = 60 * time.Minute
	}
	if m.cfg.NoTimeout || runner.IsNoTimeout() {
		budget = 0
	}

	r := runner.Run(ctx, tool, args,
		runner.WithTimeout(budget),
		runner.WithLineCallback(func(line string) {
			board.Heartbeat("gowitness")
		}),
		runner.WithStderrCallback(func(line string) {
			m.log.DebugBoard(board, "gowitness: %s", line)
			board.Heartbeat("gowitness")
		}),
	)

	// Organize screenshots into per-domain folders
	// gowitness names files like: http-api.example.com-443.png
	organized := m.organizeByDomain(flatDir, ssRoot)

	board.Done("gowitness", organized)
	board.Stop()

	if r.IsTimeout() {
		m.log.ToolTimeout("gowitness", organized, budget)
	} else if r.Err != nil && organized == 0 {
		m.log.ToolError("gowitness", fmt.Errorf(r.DiagString()), r.Stderr)
	} else {
		m.log.ToolDone("gowitness", organized, time.Since(start))
		m.log.Info("Screenshots → %s/ (%d domains)", ssRoot, organized)
	}

	// Clean up raw dir if everything was moved
	_ = os.Remove(flatDir) // only removes if empty

	return nil
}

// organizeByDomain moves flat gowitness PNGs into per-domain subdirectories.
// gowitness output filenames encode the URL: http-example.com-443.png
// We parse the domain out and create screenshots/<domain>/screenshot.png
func (m *Module) organizeByDomain(srcDir, dstRoot string) int {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if e.IsDir() || (!strings.HasSuffix(name, ".png") && !strings.HasSuffix(name, ".jpeg") && !strings.HasSuffix(name, ".jpg")) {
			continue
		}

		domain := parseDomainFromFilename(e.Name())
		if domain == "" {
			domain = "unknown"
		}

		// Create per-domain folder
		domainDir := filepath.Join(dstRoot, domain)
		if err := os.MkdirAll(domainDir, 0755); err != nil {
			continue
		}

		src := filepath.Join(srcDir, e.Name())
		dst := filepath.Join(domainDir, "screenshot.png")

		// Move file
		if err := os.Rename(src, dst); err != nil {
			// Try copy if rename fails (cross-device)
			if data, err := os.ReadFile(src); err == nil {
				if err := os.WriteFile(dst, data, 0644); err == nil {
					_ = os.Remove(src)
				}
			}
		}

		m.log.Info("  [screenshot] %s → %s/screenshot.png", domain, domain)
		count++
	}
	return count
}

// parseDomainFromFilename extracts the domain from gowitness filenames.
// gowitness v3 format: https---sub.example.com-443.png (or .jpeg)
//             or v2:   https-sub.example.com-443.png
func parseDomainFromFilename(name string) string {
	// Strip extension
	base := name
	for _, ext := range []string{".png", ".PNG", ".jpeg", ".JPEG", ".jpg", ".JPG"} {
		base = strings.TrimSuffix(base, ext)
	}

	// Strip protocol prefixes: https---, http---, https-, http-
	for _, proto := range []string{"https---", "http---", "https-", "http-"} {
		if strings.HasPrefix(base, proto) {
			base = base[len(proto):]
			break
		}
	}

	// Remove trailing -<port>-<hash> parts
	// In v3: sub.example.com-443
	parts := strings.Split(base, "-")
	if len(parts) >= 2 {
		end := len(parts)
		if end > 0 && isNumericOrHex(parts[end-1]) {
			end--
		}
		if end > 0 && isNumeric(parts[end-1]) {
			end--
		}
		if end > 0 {
			base = strings.Join(parts[:end], "-")
		}
	}

	// Sanitize
	base = strings.ToLower(strings.TrimSpace(base))
	if base == "" {
		return "unknown"
	}
	return base
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isNumericOrHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
