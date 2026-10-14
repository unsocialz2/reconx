package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotRoundTripNoTruncation(t *testing.T) {
	s := New("fixture")
	for i := 0; i < 10005; i++ {
		s.AddURL(fmt.Sprintf("https://example.com/?n=%d", i))
	}
	s.AddHost(&Host{Domain: "example.com", Meta: map[string]string{"url": "https://example.com"}})
	s.AddHost(&Host{Domain: "example.com", Meta: map[string]string{"url": "http://example.com:8080"}})
	s.AddJSFile("https://example.com/app.js")
	s.AddFinding(&Finding{Name: "candidate", Target: "https://example.com", Evidence: "raw evidence"})
	s.AddCORSFinding(&CORSFinding{URL: "https://example.com"})
	s.AddCloudAsset(&CloudAsset{URL: "https://example.com/bucket"})
	s.AddDirResult(&DirResult{URL: "https://example.com/admin"})
	s.AddWAFResult(&WAFResult{Host: "example.com"})
	s.AddParamFinding(&ParamFinding{URL: "https://example.com"})
	s.AddCoverage("partial source")
	file := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := s.SaveSnapshot(file); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadSnapshot(file, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	snap := restored.Snapshot()
	if len(snap.URLs) != 10005 || len(snap.Hosts) != 2 || len(snap.JSFiles) != 1 || len(snap.CORSResults) != 1 || len(snap.CloudAssets) != 1 || len(snap.DirResults) != 1 || len(snap.WAFResults) != 1 || len(snap.ParamResults) != 1 || len(snap.Coverage) != 1 || snap.Findings[0].Evidence != "raw evidence" {
		t.Fatal("snapshot lost data")
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0600 {
		t.Fatal("checkpoint is not private")
	}
	filtered, err := LoadSnapshot(file, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Stats()["live_hosts"]+filtered.Stats()["urls"] != 0 {
		t.Fatal("scope was not reapplied")
	}
}
