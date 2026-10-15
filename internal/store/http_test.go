package store

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestHTTPClassificationAndSavedObservations(t *testing.T) {
	s := New("http-states")
	cases := []struct {
		code  int
		state string
		live  bool
	}{
		{0, "unknown", false}, {101, "unknown", false}, {199, "unknown", false},
		{200, "available", true}, {204, "available", true}, {299, "available", true},
		{301, "redirect", true}, {304, "redirect", true}, {399, "redirect", true},
		{401, "restricted", true}, {403, "restricted", true}, {404, "client-error", true},
		{429, "rate-limited", false}, {499, "client-error", true},
		{500, "unavailable", false}, {502, "unavailable", false}, {503, "unavailable", false},
		{504, "unavailable", false}, {599, "unavailable", false}, {600, "unknown", false},
	}
	wantLive := 0
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			h := &Host{Domain: fmt.Sprintf("status-%d.example.test", tc.code), StatusCode: tc.code, HTTPState: "stale", Meta: map[string]string{"url": fmt.Sprintf("https://status-%d.example.test", tc.code)}}
			if got := HTTPState(tc.code); got != tc.state {
				t.Fatalf("state=%s want %s", got, tc.state)
			}
			if h.IsLive() != tc.live {
				t.Fatalf("live=%v", h.IsLive())
			}
			s.AddHost(h)
		})
		if tc.live {
			wantLive++
		}
	}
	if len(s.GetHosts()) != len(cases) || len(s.GetLiveHosts()) != wantLive {
		t.Fatal("observations lost or failed services counted live")
	}
	stats := s.Stats()
	if stats["live_hosts"] != wantLive || stats["http_endpoints"] != len(cases) || stats["unavailable_hosts"] != 5 || stats["rate_limited_hosts"] != 1 {
		t.Fatal(stats)
	}
	checkpoint := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := s.SaveSnapshot(checkpoint); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadSnapshot(checkpoint, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.GetHosts()) != len(cases) || len(restored.GetLiveHosts()) != wantLive {
		t.Fatal("resume changed HTTP classification")
	}
	for _, h := range restored.Snapshot().Hosts {
		if h.HTTPState != HTTPState(h.StatusCode) {
			t.Fatalf("stale state trusted: %+v", h)
		}
	}
}
