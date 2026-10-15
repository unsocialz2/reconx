package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/store"
)

func TestRouteGroupsPreserveBoundariesAndRecordedMethods(t *testing.T) {
	snap := store.Snapshot{URLs: []string{
		"https://API.example.test:443/v1/users/123?id=1#section",
		"https://api.example.test/v1/users/456?id=2",
		"https://api.example.test/v1/users/456?next=/login",
		"http://api.example.test/v1/users/123?id=1",
		"https://api.example.test:8443/v1/users/123?id=1",
		"https://api.example.test/V1/users/123?id=1",
		"https://api.example.test/v1/users%2F123?id=1",
		"https://api.example.test/v1//users/123?id=1",
		"https://api.example.test/v1/users/123/?id=1",
		"https://user:password@api.example.test/credentials",
		"javascript:alert(1)", "not a URL",
	}, ParamResults: []*store.ParamFinding{{URL: "https://api.example.test/v1/users/456?id=2", Method: "POST", Params: []string{"account_id"}}}}
	queue, groups := buildReview(snap)
	if len(groups) != 7 || len(queue) != 1 {
		t.Fatalf("lost a URL boundary: groups=%+v queue=%+v", groups, queue)
	}
	var group endpointGroup
	for _, g := range groups {
		if g.Origin == "https://api.example.test" && g.Route == "/v1/users/{number}" {
			group = g
		}
	}
	if group.Count != 3 || group.Variants != 2 || !reflect.DeepEqual(group.Parameters, []string{"account_id", "id", "next"}) || !reflect.DeepEqual(group.Methods, []string{"POST"}) {
		t.Fatalf("incorrect aggregation: %+v", group)
	}
	if !reflect.DeepEqual(group.Signals, []string{"Navigation parameter", "Object reference parameter"}) || len(group.Sources) != 2 {
		t.Fatal("missing review clues or provenance", group)
	}
	if queue[0].URLs != 9 || queue[0].Availability != "unverified" || queue[0].Priority != "explore" {
		t.Fatal("archived URLs promoted to live", queue)
	}
	for _, g := range groups {
		if g.Origin != "https://api.example.test" && len(g.Methods) != 0 {
			t.Fatal("invented an HTTP method", g)
		}
	}
	// Map traversal and input order cannot change exported priorities/groups.
	for i, j := 0, len(snap.URLs)-1; i < j; i, j = i+1, j-1 {
		snap.URLs[i], snap.URLs[j] = snap.URLs[j], snap.URLs[i]
	}
	q2, g2 := buildReview(snap)
	if !reflect.DeepEqual(queue, q2) || !reflect.DeepEqual(groups, g2) {
		t.Fatal("analysis is not deterministic")
	}
}

func TestIdentifierTemplatesDoNotConflateLiteralPathStructure(t *testing.T) {
	snap := store.Snapshot{URLs: []string{
		"https://example.test/api/123", "https://example.test/api/987",
		"https://example.test/api/550e8400-e29b-41d4-a716-446655440000",
		"https://example.test/api/550e8400-e29b-41d4-a716-446655440001",
		"https://example.test/api/abcdef0123456789", "https://example.test/api/ABCDEF0123456780",
		"https://example.test/api/v1", "https://example.test/api/v2",
	}}
	_, groups := buildReview(snap)
	counts := map[string]int{}
	for _, g := range groups {
		counts[g.Route] = g.Count
	}
	if !reflect.DeepEqual(counts, map[string]int{"/api/{number}": 2, "/api/{uuid}": 2, "/api/{hex}": 2, "/api/v1": 1, "/api/v2": 1}) {
		t.Fatal(counts)
	}
}

func TestUnavailableAssetsRemainDeferredDespiteInterestingClues(t *testing.T) {
	snap := store.Snapshot{Hosts: []*store.Host{
		{Domain: "ready.example.test", StatusCode: 200},
		{Domain: "busy.example.test", StatusCode: 429},
		{Domain: "down.example.test", StatusCode: 503},
		{Domain: "restricted.example.test", StatusCode: 403},
		{Domain: "unknown.example.test", StatusCode: 0},
		{Domain: "mixed.example.test", StatusCode: 503, Meta: map[string]string{"url": "https://mixed.example.test"}},
		{Domain: "mixed.example.test", StatusCode: 200, Meta: map[string]string{"url": "https://mixed.example.test:8443"}},
	}, URLs: []string{"https://down.example.test/api/admin/upload/login?id=1&next=/", "https://busy.example.test/api/user?id=1"}, Findings: []*store.Finding{{Target: "https://down.example.test/api/", Severity: "critical"}}}
	queue, _ := buildReview(snap)
	byHost := map[string]reviewAsset{}
	for _, a := range queue {
		byHost[a.Host] = a
	}
	if queue[0].Priority != "review" || queue[len(queue)-1].Priority != "deferred" {
		t.Fatal("queue ignores reachability", queue)
	}
	for _, host := range []string{"down.example.test", "busy.example.test"} {
		if byHost[host].Priority != "deferred" {
			t.Fatal("503/429 promoted to active work", byHost[host])
		}
	}
	if byHost["restricted.example.test"].Priority != "review" || byHost["unknown.example.test"].Priority != "explore" {
		t.Fatal(byHost)
	}
	if byHost["mixed.example.test"].Availability != "available" || byHost["mixed.example.test"].Priority != "review" {
		t.Fatal("unavailable endpoint hid an independently reachable endpoint", byHost["mixed.example.test"])
	}
	if byHost["down.example.test"].Score > 100 || byHost["down.example.test"].Candidates != 1 {
		t.Fatal(byHost["down.example.test"])
	}
}

func TestDerivedArtifactsMaskEvidenceAndRemainPrivate(t *testing.T) {
	st := store.New("review-fixture")
	secret := "fixture-sensitive-token-12345678"
	st.AddHost(&store.Host{Domain: "app.example.test", StatusCode: 200})
	st.AddURL("https://app.example.test/api/" + secret + "?token=" + secret)
	st.AddSecret(&store.Secret{Type: "test", Value: secret, File: "https://app.example.test/app.js"})
	st.AddCoverage("<img src=x onerror=alert(1)>\n# injected | " + secret)
	dir := t.TempDir()
	if err := Generate(st, []string{"example.test"}, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"review_queue.json", "endpoint_groups.json", "testing_notes.md"} {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "<img") || strings.Contains(string(raw), "\n# injected") {
			t.Fatal("unsafe derived artifact", name)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("artifact is not owner-private", name)
		}
	}
	var groups []endpointGroup
	raw, _ := os.ReadFile(filepath.Join(dir, "endpoint_groups.json"))
	if err := json.Unmarshal(raw, &groups); err != nil || len(groups) != 1 || strings.Contains(groups[0].Examples[0], "token=") {
		t.Fatal("unsafe route summary", string(raw), err)
	}
	if !strings.Contains(st.Snapshot().URLs[0], secret) {
		t.Fatal("report generation mutated raw evidence")
	}
}
