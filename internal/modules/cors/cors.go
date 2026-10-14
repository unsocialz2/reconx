package cors

import (
	"context"
	"fmt"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Module struct {
	cfg    *config.Config
	store  *store.Store
	log    *logger.Logger
	outDir string
}

func New(cfg *config.Config, st *store.Store, log *logger.Logger, out string) *Module {
	return &Module{cfg, st, log, out}
}

// classify records browser-relevant policy observations, never validated exploit impact.
func classify(origin, acao, acac string) (string, bool) {
	if acao != origin {
		return "", false
	} // '*' + credentials is rejected by browsers.
	if strings.EqualFold(acac, "true") {
		return "Reflected origin permits credentials; browser access and sensitive-data impact require validation", true
	}
	return "Reflected origin without credentials; sensitive-data impact requires validation", true
}
func (m *Module) Run(ctx context.Context) error {
	client := scope.New(m.cfg).Client(5 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	n := m.cfg.Workers
	if n < 1 {
		n = 1
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, h := range m.store.GetHosts() {
		raw := h.Meta["url"]
		if raw == "" {
			raw = "https://" + h.Domain
		}
		for _, origin := range []string{"https://reconx.invalid", "null"} {
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(raw, origin string) {
				defer wg.Done()
				defer func() { <-sem }()
				req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
				if err != nil {
					return
				}
				req.Header.Set("Origin", origin)
				if p := strings.SplitN(m.cfg.BugBountyHeader, ":", 2); len(p) == 2 {
					req.Header.Set(strings.TrimSpace(p[0]), strings.TrimSpace(p[1]))
				}
				resp, err := client.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				acao, acac := resp.Header.Get("Access-Control-Allow-Origin"), resp.Header.Get("Access-Control-Allow-Credentials")
				if desc, ok := classify(origin, acao, acac); ok {
					m.store.AddCORSFinding(&store.CORSFinding{URL: raw, Origin: origin, ACAO: acao, ACAC: acac, Severity: "info", Description: fmt.Sprintf("Candidate: %s", desc)})
				}
			}(raw, origin)
		}
	}
	wg.Wait()
	return ctx.Err()
}
