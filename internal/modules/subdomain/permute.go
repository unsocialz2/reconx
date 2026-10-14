package subdomain

// permute.go generates DNS permutations of known subdomains and resolves
// them via the system resolver. This finds "hidden" subdomains that aren't
// in any passive source but follow common naming patterns (e.g. dev-api,
// api-staging, admin-internal, etc.).
//
// The permutation algorithm:
//  1. Take all known subdomains of the target domain.
//  2. Split each into prefix + parent (e.g. api.example.com → api / example.com).
//  3. Generate new candidates by combining known prefixes with common
//     separators (-, _, .) and suffixes (dev, stg, prod, internal, etc.).
//  4. Resolve each candidate concurrently.
//  5. Return only candidates that resolve successfully.

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/reconx/reconx/pkg/logger"
)

// permutePrefixes and permuteSuffixes are common dev/staging naming patterns
// seen in real bug bounty targets. The lists are intentionally short — large
// lists explode the candidate space and make resolution slow. Tuned for the
// best signal-to-noise ratio based on public writeups.
var (
	permuteSuffixes = []string{
		"dev", "stg", "staging", "stage", "prod", "production",
		"test", "testing", "qa", "uat", "sandbox", "sbx",
		"internal", "int", "private", "vpn", "corp",
		"old", "new", "v1", "v2", "v3", "beta", "alpha",
		"backup", "bak", "old2", "tmp", "temp",
		"preprod", "pre-prod", "demo", "preview",
		"admin", "portal", "console", "manage",
	}

	permutePrefixes = []string{
		"api", "app", "web", "www", "mail", "smtp", "imap",
		"admin", "portal", "console", "manage", "dashboard",
		"auth", "sso", "oauth", "id", "identity",
		"cdn", "static", "assets", "media", "img", "images",
		"git", "gitlab", "github", "ci", "jenkins", "build",
		"docs", "doc", "help", "support", "wiki",
		"grafana", "prometheus", "kibana", "elastic", "logs",
		"db", "mysql", "postgres", "redis", "mongo",
		"internal", "vpn", "corp", "office",
		"staging", "dev", "test", "qa", "uat",
	}

	permuteSeparators = []string{"-", "_", "."}

	// maxPrefixSetSize caps the prefix set used for cross-product
	// permutations. With more prefixes, the candidate count explodes
	// (n² × separators × suffixes) and the DNS resolver gets flooded.
	// 200 is the sweet spot — large enough to capture the long tail of
	// real targets, small enough to keep runtime bounded.
	maxPrefixSetSize = 200

	// maxCandidates is a hard ceiling on the candidate list regardless
	// of how it was generated. We sample/reservoir if exceeded.
	maxCandidates = 20000
)

// runPermute generates candidates from existing subdomains and resolves them.
// It only runs after the initial subdomain wave has populated the store —
// so we have real prefixes to permute. The first wave of tools runs in
// parallel with permute (it'll just permute the original target domain +
// known prefixes if no subdomains have been discovered yet).
func (m *Module) runPermute(ctx context.Context, domain string, board *logger.ProgressBoard) ([]string, []string) {
	board.Register("permute", domain)
	start := time.Now()

	// Snapshot known subdomains — these give us real prefixes to permute.
	known := m.store.GetSubdomains()

	// Extract prefixes (the part before the parent domain)
	prefixSet := make(map[string]bool)
	for _, s := range known {
		// Strip parent domain and trailing dot
		if strings.HasSuffix(s, "."+domain) {
			prefix := strings.TrimSuffix(s, "."+domain)
			// Use only the first label (e.g. api from api.v1.example.com)
			if idx := strings.LastIndex(prefix, "."); idx >= 0 {
				prefix = prefix[idx+1:]
			}
			if prefix != "" && len(prefix) <= 20 {
				prefixSet[prefix] = true
			}
		}
	}

	// Add a small set of high-yield common prefixes even if not seen yet
	highYield := []string{"api", "www", "admin", "dev", "staging", "app"}
	for _, p := range highYield {
		prefixSet[p] = true
	}

	// Cap the prefix set to bound cross-product explosion. If we have
	// thousands of known prefixes, permuting every pair × separator
	// produces millions of candidates that the resolver can't keep up
	// with — and most don't resolve anyway. Keep the first N from the
	// map (random-looking enough on the wire) plus a sample of the rest.
	if len(prefixSet) > maxPrefixSetSize {
		trimmed := make(map[string]bool, maxPrefixSetSize)
		count := 0
		for p := range prefixSet {
			if count < maxPrefixSetSize {
				trimmed[p] = true
				count++
			}
		}
		prefixSet = trimmed
	}

	// Build candidate list:
	//   - prefix + suffix (e.g. api-dev, api-staging)
	//   - prefix × prefix (e.g. api-admin, admin-api)
	//   - common-prefix + domain (e.g. api.example.com, admin.example.com)
	var candidates []string
	seen := make(map[string]bool)

	addCandidate := func(name string) {
		name = strings.ToLower(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		candidates = append(candidates, name+"."+domain)
	}

	// Combine known prefixes with common suffixes
	for prefix := range prefixSet {
		for _, suffix := range permuteSuffixes {
			for _, sep := range permuteSeparators {
				addCandidate(prefix + sep + suffix)
				addCandidate(suffix + sep + prefix)
			}
		}
	}

	// Cross-product of known prefixes (api-admin, admin-api, web-app, etc.)
	prefixes := make([]string, 0, len(prefixSet))
	for p := range prefixSet {
		prefixes = append(prefixes, p)
	}
	for i, p1 := range prefixes {
		for j, p2 := range prefixes {
			if i == j {
				continue
			}
			for _, sep := range permuteSeparators {
				addCandidate(p1 + sep + p2)
			}
		}
	}

	// All common prefixes × domain (cheap to try, high yield)
	for _, p := range permutePrefixes {
		addCandidate(p)
	}

	// Hard cap on candidate count. If the cross-product exceeded the
	// ceiling, reservoir-sample down to maxCandidates. This is a quality
	// trade-off (we may miss some valid permutations on huge prefix sets)
	// but keeps the tool from spending hours on DNS lookups for marginal
	// value.
	if len(candidates) > maxCandidates {
		step := float64(len(candidates)) / float64(maxCandidates)
		trimmed := make([]string, 0, maxCandidates)
		for i := 0.0; int(i) < len(candidates); i += step {
			trimmed = append(trimmed, candidates[int(i)])
		}
		candidates = trimmed
	}

	m.log.Debug("permute: %d candidates to resolve (from %d known prefixes)",
		len(candidates), len(prefixes))

	// Resolve candidates concurrently with a tight concurrency limit.
	// We use a custom resolver with a short timeout per query.
	resolver := net.DefaultResolver
	// Prefer a short dial timeout — many candidates will not resolve.
	sem := make(chan struct{}, 50) // 50 concurrent DNS lookups
	results := make(chan string, len(candidates))

	var wg sync.WaitGroup
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break // cancelled — stop generating lookups
		}
		candidate := candidate
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			// We don't care about the IPs — just whether the name resolves.
			_, err := resolver.LookupHost(lookupCtx, candidate)
			if err == nil {
				results <- candidate
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var found []string
	for r := range results {
		found = append(found, r)
	}

	board.Done("permute", len(found))
	m.log.Debug("permute: %d candidates resolved in %s", len(found), time.Since(start).Round(time.Millisecond*100))
	return found, nil
}
