package cloud

import (
	"context"
	"fmt"
	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
	"net/http"
	"net/url"
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

// Run checks only explicit cloud assets; brand keywords never establish ownership.
func (m *Module) Run(ctx context.Context) error {
	if len(m.cfg.Target.CloudAssets) == 0 {
		m.store.AddCoverage("cloud: skipped — no explicitly authorized cloud URLs")
		return nil
	}
	filter := scope.New(m.cfg)
	client := filter.Client(10 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, raw := range m.cfg.Target.CloudAssets {
		if !filter.IsInScope(raw) {
			return fmt.Errorf("cloud asset outside scope: %s", raw)
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return fmt.Errorf("invalid cloud URL")
		}
		req, err := http.NewRequestWithContext(ctx, "HEAD", raw, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			m.store.AddCoverage("cloud: request failed for " + u.Host)
			return err
		}
		resp.Body.Close()
		status := "restricted"
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			status = "reachable (impact unvalidated)"
		}
		m.store.AddCloudAsset(&store.CloudAsset{Provider: "explicit", Name: u.Host, URL: raw, Status: status, Accessible: resp.StatusCode >= 200 && resp.StatusCode < 300})
	}
	return ctx.Err()
}
