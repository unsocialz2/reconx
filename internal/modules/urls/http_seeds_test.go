package urls

import (
	"reflect"
	"testing"

	"github.com/unsocialz2/reconx/internal/store"
)

func TestDiscoveryInputsExcludeUnavailableButKeepPassiveCoverage(t *testing.T) {
	hosts := []*store.Host{
		{Domain: "live.example.test", StatusCode: 200, Meta: map[string]string{"url": "http://live.example.test"}},
		{Domain: "restricted.example.test", StatusCode: 403},
		{Domain: "failed.example.test", StatusCode: 503},
		{Domain: "limited.example.test", StatusCode: 429},
		{Domain: "unknown.example.test"},
	}
	active, passive := discoveryInputs(hosts)
	if !reflect.DeepEqual(active, []string{"http://live.example.test", "https://restricted.example.test"}) {
		t.Fatal(active)
	}
	if !reflect.DeepEqual(passive, []string{"failed.example.test", "limited.example.test", "live.example.test", "restricted.example.test", "unknown.example.test"}) {
		t.Fatal("passive coverage lost", passive)
	}
}
