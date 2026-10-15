package urls

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unsocialz2/reconx/pkg/runner"
	"github.com/unsocialz2/reconx/pkg/util"
)

var errParamTotalBudget = errors.New("ParamSpider total runtime budget exhausted")
var errParamLateBudget = errors.New("ParamSpider late enrichment budget exhausted")

func (m *Module) workers() int { return max(1, min(m.cfg.Workers, 256)) }

func (m *Module) waitForEnrichment(ctx context.Context, done <-chan struct{}, cancel context.CancelCauseFunc) {
	seconds := m.cfg.Tools["paramspider"].LateTimeout
	if seconds <= 0 {
		seconds = 120
	}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-ctx.Done():
		cancel(ctx.Err())
	case <-timer.C:
		cancel(errParamLateBudget)
	}
	// runner kills and reaps the entire child process group before returning.
	<-done
}

// selectParamHosts ranks exact in-scope hosts, without expanding to parent domains.
// Parameter-bearing URLs win, followed by known URLs, API and application hosts.
// Only the low-signal tail is capped. Ties are deterministic.
func selectParamHosts(input []string, urls []string, fallback int) ([]string, int) {
	host := func(raw string) string {
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	}
	scores := map[string]int{}
	for _, raw := range input {
		h := host(raw)
		if h == "" {
			continue
		}
		score := 0
		for _, label := range strings.Split(h, ".") {
			switch label {
			case "api", "graphql", "rest":
				score = max(score, 30)
			case "login", "auth", "admin", "app", "application", "portal", "dashboard", "account":
				score = max(score, 20)
			}
		}
		scores[h] = score
	}
	for _, raw := range urls {
		h := host(raw)
		score, ok := scores[h]
		if !ok {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		score = max(score, 40)
		if u.RawQuery != "" {
			score = 100
		}
		scores[h] = score
	}
	ranked := make([]string, 0, len(scores))
	for h := range scores {
		ranked = append(ranked, h)
	}
	sort.Slice(ranked, func(i, j int) bool {
		if scores[ranked[i]] != scores[ranked[j]] {
			return scores[ranked[i]] > scores[ranked[j]]
		}
		return ranked[i] < ranked[j]
	})
	selected := make([]string, 0, len(ranked))
	usedFallback := 0
	for _, h := range ranked {
		if scores[h] == 0 {
			if usedFallback >= max(0, fallback) {
				continue
			}
			usedFallback++
		}
		selected = append(selected, h)
	}
	return selected, len(ranked)
}

func (m *Module) runParamSpider(ctx context.Context, input string) []string {
	start := time.Now()
	cfg := m.cfg.Tools["paramspider"]
	domains, total := selectParamHosts(m.scope.FilterList(splitLines(input)), m.store.GetURLs(), cfg.FallbackHosts)
	m.log.Tool("paramspider", fmt.Sprintf("%d/%d prioritized hosts, workers=%d", len(domains), total, m.workers()))
	budget := m.cfg.SourceBudget("paramspider", len(domains), 45*time.Minute)
	runCtx, cancel := context.WithTimeoutCause(ctx, budget, errParamTotalBudget)
	defer cancel()
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	if m.board != nil {
		m.board.Register("paramspider", fmt.Sprintf("%d prioritized hosts", len(domains)))
		m.board.Progress("paramspider", 0, total, 0)
		runCtx = runner.WithProcessObserver(runCtx, func(pid int, alive bool) { m.board.Process("paramspider", pid, alive) })
	}
	path := "paramspider"
	if cfg.Path != "" {
		path = cfg.Path
	}
	var mu sync.Mutex
	found := map[string]bool{}
	processed, failed := 0, 0
	update := func() {
		if m.board != nil {
			m.board.Progress("paramspider", processed, total, len(found))
		}
	}
	m.forEachDomain(runCtx, domains, func(domain string) {
		m.heartbeat("paramspider")
		defer m.heartbeat("paramspider")
		r := runner.Run(runCtx, path, []string{"-d", domain, "-s"},
			runner.WithTimeout(timeout), runner.WithoutCapture(),
			runner.WithStderrCallback(func(line string) { m.log.Debug("paramspider[%s]: %s", domain, line); m.heartbeat("paramspider") }),
			runner.WithLineCallback(func(line string) {
				for _, raw := range strings.Fields(util.StripANSI(line)) {
					raw = strings.Trim(raw, "\"'<>[](),")
					u, err := url.Parse(raw)
					if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || !m.scope.IsInScope(raw) {
						continue
					}
					m.store.AddURL(raw)
					mu.Lock()
					found[raw] = true
					update()
					mu.Unlock()
				}
			}))
		mu.Lock()
		if runCtx.Err() == nil {
			processed++
			if r.Err != nil {
				failed++
			}
		}
		update()
		mu.Unlock()
	})
	all := make([]string, 0, len(found))
	for u := range found {
		all = append(all, u)
	}
	sort.Strings(all)
	var reasons []string
	if runCtx.Err() != nil {
		reasons = append(reasons, context.Cause(runCtx).Error())
	}
	if len(domains) < total {
		reasons = append(reasons, fmt.Sprintf("low-signal fallback capped at %d hosts", cfg.FallbackHosts))
	}
	if failed > 0 {
		reasons = append(reasons, fmt.Sprintf("%d domain runs failed or timed out", failed))
	}
	if len(reasons) > 0 {
		reason := strings.Join(reasons, "; ")
		m.store.AddCoverage(fmt.Sprintf("paramspider: partial — %d/%d hosts processed, %d URLs; %s", processed, total, len(all), reason))
		if m.board != nil {
			m.board.Partial("paramspider", reason)
		}
		m.log.Warn("ParamSpider partial: %d/%d hosts | %d URLs — %s; continuing pipeline", processed, total, len(all), reason)
	} else {
		if m.board != nil {
			m.board.Done("paramspider", len(all))
		}
		m.log.ToolDone("paramspider", len(all), time.Since(start))
	}
	return all
}

func (m *Module) heartbeat(name string) {
	if m.board != nil {
		m.board.Heartbeat(name)
	}
}

// forEachDomain bounds both goroutines and concurrent jobs and joins them on cancel.
func (m *Module) forEachDomain(ctx context.Context, domains []string, fn func(string)) {
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < min(m.workers(), len(domains)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				if ctx.Err() != nil {
					return
				}
				fn(d)
			}
		}()
	}
schedule:
	for _, d := range domains {
		select {
		case <-ctx.Done():
			break schedule
		case jobs <- d:
		}
	}
	close(jobs)
	wg.Wait()
}
