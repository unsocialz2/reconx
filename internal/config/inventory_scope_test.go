package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryScopeSelectsOnlyEligibleWildcardsAndPreservesExclusions(t *testing.T) {
	csv := "identifier,asset_type,eligible_for_submission\n" +
		"*.example.com,WILDCARD,true\n" +
		"http://*.example.org,WILDCARD,true\n" +
		"www.example.com,URL,true\n" +
		"blocked.example.com,URL,false\n" +
		"*.outside.test,WILDCARD,false\n" +
		"com.vendor.app,GOOGLE_PLAY_APP_ID,false\n"
	path := filepath.Join(t.TempDir(),"scope.csv")
	if err := os.WriteFile(path, []byte(csv), 0600); err != nil {t.Fatal(err)}
	cfg := DefaultConfig()
	cfg.InventoryOnly=true
	if err := cfg.LoadScopeCSV(path); err != nil {t.Fatal(err)}
	if len(cfg.Target.Domains)!=2 {t.Fatalf("expected 2 wildcard seeds, got %#v",cfg.Target.Domains)}
	if len(cfg.Scope.Imported.Assets)!=4 {t.Fatalf("expected two includes + 2 excludes, got %#v",cfg.Scope.Imported.Assets)}
	found := false
	for _, a := range cfg.Scope.Imported.Assets {
		if strings.HasPrefix(a.Identifier,"http://") {
			if a.Kind!="wildcard-origin" || a.Scheme!="http" || a.Host!="example.org" {
				t.Fatalf("bad wildcard origin: %+v",a)
			}
			found = true
		}
	}
	if !found {t.Fatal("HTTP wildcard origin missing")}
}
