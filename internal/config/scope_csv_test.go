package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeCSV(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.csv")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestCSVEligibilityAndExactAssets(t *testing.T) {
	cfg := DefaultConfig()
	path := writeCSV(t, "\ufeffasset_identifier,asset_type,eligible_for_submission,eligible_for_bounty,instruction\r\n*.example.test,WILDCARD,true,false,\"No port scans, no Nuclei\"\r\nadmin.example.test,URL,false,false,Excluded\r\nhttps://api.example.test:8443/,URL,true,false,VDP\r\n10.0.0.0/24,CIDR,true,false,Network\r\ncom.example.app,ANDROID_APP_ID,true,false,Mobile\r\n")
	if err := cfg.LoadScopeCSV(path); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Scope.Imported.Assets) != 4 || len(cfg.Scope.Imported.Skipped) != 1 {
		t.Fatal(cfg.Scope.Imported)
	}
	if !cfg.Scope.Imported.Assets[1].Excluded || cfg.Scope.Imported.Assets[2].Port != "8443" {
		t.Fatal(cfg.Scope.Imported)
	}
	if !reflect.DeepEqual(cfg.Target.Domains, []string{"api.example.test", "example.test"}) || !reflect.DeepEqual(cfg.Target.IPRanges, []string{"10.0.0.0/24"}) {
		t.Fatal(cfg.Target)
	}
	if cfg.Phases.PortScan || cfg.Phases.VulnScan {
		t.Fatal("CSV enabled scanners")
	}
}
func TestCSVRejectsAmbiguityTransactionally(t *testing.T) {
	for _, data := range []string{
		"asset_identifier,eligible_for_bounty\nexample.test,true\n",
		"target,in_scope\nexample.test,maybe\n",
		"target,in_scope,eligible_for_submission\nexample.test,true,false\n",
		"target,in_scope\nexample.test,true\nhttps://example.test/admin,false\n",
		"target,in_scope\nexample.test,true\nhttps://user:pass@example.test/,true\n",
		"target,in_scope\nexample.test,true\n*,true\n",
		"target,in_scope\nexample.test,false\n",
		"target,in_scope\nexample.test,true,extra\n",
		"target,in_scope,in scope\nexample.test,true,true\n",
	} {
		cfg := DefaultConfig()
		cfg.Target.Domains = []string{"selected.test"}
		if err := cfg.LoadScopeCSV(writeCSV(t, data)); err == nil {
			t.Fatalf("accepted %s", data)
		}
		if cfg.Scope.Imported != nil || !reflect.DeepEqual(cfg.Target.Domains, []string{"selected.test"}) {
			t.Fatal("partial import")
		}
	}
}
func TestTargetGroupCSVPreservesExplicitTargetSelection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Target.Domains = []string{"selected.example.test"}
	csv := "Target,Category,In Scope\n*.example.test,website,yes\n10.0.0.0/8,cidr,yes\nblocked.example.test,website,no\n"
	if err := cfg.LoadScopeCSV(writeCSV(t, csv)); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Target.IPRanges) != 0 || strings.Join(cfg.Target.Domains, ",") != "selected.example.test" {
		t.Fatal(cfg.Target)
	}
}
