package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
)

// End-to-end fixture: CLI repair uses saved metadata and a local fake
// gowitness. No DNS discovery, HTTP scanner or external requests are used.
func TestInventoryRepairRegeneratesScreenshotsAndLinksOffline(t *testing.T) {
	dir := t.TempDir()
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "gowitness")
	fake := `#!/bin/sh
[ "$1" = scan ] && [ "$2" = single ] || exit 9
shift 2
while [ "$#" -gt 0 ]; do
 case "$1" in
  --url) url="$2"; shift 2;;
  --screenshot-path) dest="$2"; shift 2;;
  --screenshot-format|--timeout|--threads) shift 2;;
  *) exit 10;;
 esac
done
[ "$url" = "http://web.example.org" ] || exit 11
mkdir -p "$dest"
head -c 256 /dev/zero > "$dest/mock.png"
`
	if err := os.WriteFile(bin, []byte(fake), 0755); err != nil { t.Fatal(err) }
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg:=config.DefaultConfig()
	cfg.Scope.Imported=&config.ScopeImport{Assets:[]config.ScopeAsset{
		{Identifier:"http://*.example.org",Kind:"wildcard-origin",Host:"example.org",Scheme:"http",Port:"80"},
	}}
	saved:=struct{
		SchemaVersion int `json:"schema_version"`
		Scope config.Scope `json:"scope"`
		Target config.Target `json:"target"`
	}{1,cfg.Scope,config.Target{Domains:[]string{"example.org"}}}
	data,err:=json.Marshal(saved)
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(filepath.Join(dir,"manifest.json"),data,0600);err!=nil{t.Fatal(err)}
	st:=store.New("saved-inventory")
	st.AddSubdomain("web.example.org")
	st.AddHost(&store.Host{Domain:"web.example.org",StatusCode:200,Meta:map[string]string{"url":"http://web.example.org"}})
	if err:=st.SaveSnapshot(filepath.Join(dir,"checkpoint.json"));err!=nil{t.Fatal(err)}
	if err:=runInventoryRepair(dir);err!=nil{t.Fatal(err)}
	for _,file:=range []string{"inventory/index.html","inventory/subdomains_ranked.csv","report.html","screenshots/inventory_manifest.json","inventory-repair.log"}{
		if _,err:=os.Stat(filepath.Join(dir,file));err!=nil{t.Fatalf("missing %s: %v",file,err)}
	}
	contents,err:=os.ReadFile(filepath.Join(dir,"inventory","index.html"))
	if err!=nil{t.Fatal(err)}
	if !strings.Contains(string(contents),`href="http://web.example.org"`){
		t.Fatal("repair did not produce clickable original-scheme link")
	}
}
