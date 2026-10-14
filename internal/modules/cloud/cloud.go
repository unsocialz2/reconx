package cloud

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

// Module enumerates exposed cloud buckets (AWS S3, GCP, Azure Blob)
type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

// New creates a cloud enum module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run executes cloud asset discovery.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("Cloud & S3 Bucket Enumeration", "Checking AWS S3, GCP Storage, Azure Blobs")

	cloudDir := filepath.Join(m.outDir, "cloud")
	if err := os.MkdirAll(cloudDir, 0755); err != nil {
		m.log.Warn("Could not create cloud/ directory: %v", err)
	}

	start := time.Now()
	total := 0

	// Generate target keywords from domains and org name
	keywords := m.extractKeywords()
	if len(keywords) == 0 {
		m.log.Warn("No keywords or domains available for cloud enumeration")
		return nil
	}

	// 1. s3scanner
	if runner.IsAvailable("s3scanner") {
		n := m.runS3Scanner(ctx, keywords, cloudDir)
		total += n
	} else {
		m.log.ToolSkipped("s3scanner", "not found — install: pip3 install s3scanner")
	}

	// 2. cloud_enum
	if runner.IsAvailable("cloud_enum") {
		n := m.runCloudEnum(ctx, keywords, cloudDir)
		total += n
	} else {
		m.log.ToolSkipped("cloud_enum", "not found — install: pip3 install cloud_enum")
	}

	m.log.PhaseComplete("Cloud & S3 Bucket Enumeration", total, time.Since(start))
	return nil
}

func (m *Module) extractKeywords() []string {
	seen := make(map[string]bool)
	var list []string

	if m.cfg.Target.OrgName != "" {
		name := strings.ToLower(strings.TrimSpace(m.cfg.Target.OrgName))
		if !seen[name] {
			seen[name] = true
			list = append(list, name)
		}
	}

	for _, d := range m.cfg.Target.Domains {
		parts := strings.Split(d, ".")
		if len(parts) >= 2 {
			kw := parts[len(parts)-2]
			if len(kw) > 2 && !seen[kw] {
				seen[kw] = true
				list = append(list, kw)
			}
		}
	}
	return list
}

func (m *Module) runS3Scanner(ctx context.Context, keywords []string, outDir string) int {
	bucketsFile := filepath.Join(outDir, "s3scanner_input.txt")
	if err := os.WriteFile(bucketsFile, []byte(strings.Join(keywords, "\n")+"\n"), 0644); err != nil {
		m.log.Warn("s3scanner: could not write input file: %v", err)
		return 0
	}
	defer os.Remove(bucketsFile)

	args := []string{"scan", "-f", bucketsFile}
	m.log.Tool("s3scanner", fmt.Sprintf("Scanning %d keywords for public S3 buckets", len(keywords)))
	m.log.ToolCmd("s3scanner", args, "")
	start := time.Now()
	count := 0

	cb := func(line string) {
		line = strings.TrimSpace(line)
		ll := strings.ToLower(line)
		if strings.Contains(ll, "found") ||
			strings.Contains(ll, "open") ||
			strings.Contains(ll, "public") {
			count++
			m.store.AddCloudAsset(&store.CloudAsset{
				Provider:   "aws",
				Name:       line,
				URL:        fmt.Sprintf("https://%s.s3.amazonaws.com", line),
				Status:     "public",
				Accessible: true,
			})
			m.log.Warn("  [Cloud] Public S3 Bucket: %s", line)
		}
	}

	r := runner.Run(ctx, "s3scanner", args,
		runner.WithTimeout(10*time.Minute),
		runner.WithLineCallback(cb),
	)

	// If the installed version is the Go s3scanner binary, it requires -bucket-file
	if r.Err != nil && strings.Contains(strings.Join(r.Stderr, " "), "bucket-file") {
		args = []string{"-bucket-file", bucketsFile}
		r = runner.Run(ctx, "s3scanner", args,
			runner.WithTimeout(10*time.Minute),
			runner.WithLineCallback(cb),
		)
	}

	if r.Err != nil && count == 0 {
		m.log.Debug("s3scanner: %s", r.DiagString())
	} else {
		m.log.ToolDone("s3scanner", count, time.Since(start))
	}
	return count
}

func (m *Module) runCloudEnum(ctx context.Context, keywords []string, outDir string) int {
	count := 0
	for _, kw := range keywords {
		outFile := filepath.Join(outDir, fmt.Sprintf("cloud_enum_%s.txt", kw))
		args := []string{"-k", kw, "-l", outFile, "--quickscan"}

		m.log.Tool("cloud_enum", fmt.Sprintf("keyword: %s → %s", kw, outFile))
		start := time.Now()
		n := 0

		r := runner.Run(ctx, "cloud_enum", args,
			runner.WithTimeout(10*time.Minute),
			runner.WithLineCallback(func(line string) {
				line = strings.TrimSpace(line)
				ll := strings.ToLower(line)
				// Require a URL-shaped result before counting. cloud_enum
				// prints "FOUND N items" banners that match the naive filter
				// and produced false positives. Look for an actual URL plus a
				// public/open status indicator.
				isURL := strings.HasPrefix(ll, "http://") || strings.HasPrefix(ll, "https://")
				hasOpen := strings.Contains(ll, "open") || strings.Contains(ll, "public") || strings.Contains(ll, "listable")
				if isURL && hasOpen {
					n++
					count++
					m.store.AddCloudAsset(&store.CloudAsset{
						Provider:   "multi",
						Name:       kw,
						URL:        line,
						Status:     "open",
						Accessible: true,
					})
					m.log.Warn("  [Cloud Asset] %s", line)
				}
			}),
		)

		if r.Err != nil && n == 0 {
			m.log.Debug("cloud_enum[%s]: %s", kw, r.DiagString())
		} else {
			m.log.ToolDone("cloud_enum:"+kw, n, time.Since(start))
		}
	}
	return count
}
