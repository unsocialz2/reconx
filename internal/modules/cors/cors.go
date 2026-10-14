package cors

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/reconx/reconx/internal/config"
	"github.com/reconx/reconx/internal/store"
	"github.com/reconx/reconx/pkg/logger"
	"github.com/reconx/reconx/pkg/runner"
)

// Module tests live HTTP/S hosts for CORS misconfigurations.
type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

// New creates a CORS testing module
func New(cfg *config.Config, st *store.Store, log *logger.Logger, outDir string) *Module {
	return &Module{cfg: cfg, store: st, log: log, outDir: outDir}
}

// Run executes CORS misconfiguration tests on live hosts.
func (m *Module) Run(ctx context.Context) error {
	m.log.Phase("CORS Misconfiguration Scan", "Testing live hosts for insecure CORS policies")

	corsDir := filepath.Join(m.outDir, "cors")
	if err := os.MkdirAll(corsDir, 0755); err != nil {
		m.log.Warn("Could not create cors/ directory: %v", err)
	}

	hosts := m.store.GetHosts()
	if len(hosts) == 0 {
		m.log.Warn("No live hosts to test for CORS")
		return nil
	}

	start := time.Now()
	total := 0

	// 1. If Corsy or cors-scanner is available, run it
	if runner.IsAvailable("corsy") {
		total = m.runCorsy(ctx, hosts, corsDir)
	} else {
		// Built-in lightweight concurrent CORS probe
		total = m.runBuiltinCORSProbe(ctx, hosts)
	}

	m.log.PhaseComplete("CORS Misconfiguration Scan", total, time.Since(start))
	return nil
}

func (m *Module) runCorsy(ctx context.Context, hosts []*store.Host, outDir string) int {
	aliveFile := filepath.Join(m.outDir, "alive.txt")
	outFile := filepath.Join(outDir, "corsy_results.json")
	args := []string{"-i", aliveFile, "-o", outFile, "-q"}

	m.log.Tool("corsy", fmt.Sprintf("%d hosts → %s", len(hosts), outFile))
	start := time.Now()
	count := 0

	r := runner.Run(ctx, "corsy", args,
runner.WithTimeout(15*time.Minute),
runner.WithLineCallback(func(line string) {
line = strings.TrimSpace(line)
if strings.Contains(line, "ACAO") || strings.Contains(line, "VULN") {
count++
m.store.AddCORSFinding(&store.CORSFinding{
					URL:         line,
					Origin:      "evil.com",
					Severity:    "medium",
					Description: "Insecure CORS configuration discovered by corsy",
				})
			}
		}),
	)

	if r.Err != nil && count == 0 {
		m.log.Debug("corsy: %s", r.DiagString())
	} else {
		m.log.ToolDone("corsy", count, time.Since(start))
	}
	return count
}

func (m *Module) runBuiltinCORSProbe(ctx context.Context, hosts []*store.Host) int {
	m.log.Info("Running built-in CORS origin reflection checks...")
	start := time.Now()
	count := 0
	var mu sync.Mutex

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup

	testOrigins := []string{
		"https://evil.com",
		"https://null",
		"https://attacker.org",
	}

	for _, h := range hosts {
		targetURL := "https://" + h.Domain
		if u, ok := h.Meta["url"]; ok {
			targetURL = u
		}

		for _, testOrigin := range testOrigins {
			wg.Add(1)
			sem <- struct{}{}

			// Add jitter before each request. Without this, 20 concurrent
			// requests × 3 origins per host hit a server in a perfectly
			// metronomic pattern that gets rate-limited / blocked by
			// Cloudflare / Akamai. A random 10-50ms delay per request
			// spreads the load and looks more like browser traffic.
			time.Sleep(time.Duration(10+rand.Intn(40)) * time.Millisecond)

			go func(urlStr, origin string) {
				defer wg.Done()
				defer func() { <-sem }()

				req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
				if err != nil {
					return
				}
				req.Header.Set("Origin", origin)
				req.Header.Set("User-Agent", "Mozilla/5.0 (reconx-cors-audit)")

				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				acao := resp.Header.Get("Access-Control-Allow-Origin")
				acac := resp.Header.Get("Access-Control-Allow-Credentials")

				if acao == origin || acao == "*" {
					isVuln := false
					severity := "low"
					desc := fmt.Sprintf("Reflected Origin: %s", acao)

					if strings.EqualFold(acac, "true") && acao == origin {
						isVuln = true
						severity = "high"
						desc = fmt.Sprintf("Critical CORS Misconfiguration: Origin %s reflected with Credentials Allowed", origin)
					} else if acao == "*" && strings.EqualFold(acac, "true") {
						isVuln = true
						severity = "medium"
						desc = "Wildcard Origin with Credentials Allowed"
					} else if acao == origin {
						isVuln = true
						severity = "medium"
					}

					if isVuln {
						mu.Lock()
						count++
						m.store.AddCORSFinding(&store.CORSFinding{
							URL:         urlStr,
							Origin:      origin,
							ACAO:        acao,
							ACAC:        acac,
							Severity:    severity,
							Description: desc,
						})
						mu.Unlock()
						m.log.Warn("  [CORS %s] %s (ACAO: %s, ACAC: %s)", severity, urlStr, acao, acac)
					}
				}
			}(targetURL, testOrigin)
		}
	}

	wg.Wait()
	m.log.ToolDone("cors-probe", count, time.Since(start))
	return count
}
