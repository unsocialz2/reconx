package screenshot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
	"github.com/unsocialz2/reconx/pkg/logger"
)

// This fixture only checks CLI arguments and PNG mapping; no targets are contacted.
func TestRunInventoryUsesGowitnessV3CLIAndKeepsHTTPOnly(t *testing.T) {
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "gowitness")
	script := `#!/bin/sh
[ "$1" = scan ] && [ "$2" = single ] || exit 17
shift 2
while [ "$#" -gt 0 ]; do
 case "$1" in
  --url) target="$2"; shift 2;;
  --screenshot-path) dest="$2"; shift 2;;
  --screenshot-format|--timeout|--threads) shift 2;;
  *) echo "unsupported argument $1" >&2; exit 18;;
 esac
done
[ "$target" = "http://web.example.org" ] || exit 19
mkdir -p "$dest"
head -c 256 /dev/zero > "$dest/test.png"
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil { t.Fatal(err) }
	t.Setenv("PATH", binDir + string(os.PathListSeparator) + os.Getenv("PATH"))
	cfg := config.DefaultConfig()
	cfg.InventoryOnly = true
	cfg.Scope.Imported = &config.ScopeImport{Assets: []config.ScopeAsset{
		{Kind: "wildcard-origin", Host: "example.org", Scheme: "http", Port: "80"},
	}}
	st := store.New("test-image")
	st.AddHost(&store.Host{Domain: "web.example.org", StatusCode: 200, Meta: map[string]string{"url": "http://web.example.org"}})
	st.AddHost(&store.Host{Domain: "web.example.org", StatusCode: 200, Meta: map[string]string{"url": "https://web.example.org"}})
	dir := t.TempDir()
	log := logger.New(false, "")
	defer log.Close()
	if err := New(cfg,st,log,dir).RunInventory(context.Background()); err != nil { t.Fatal(err) }
	content, err := os.ReadFile(filepath.Join(dir,"screenshots","inventory_manifest.json"))
	if err != nil { t.Fatal(err) }
	var rows []InventoryScreenshot
	if err := json.Unmarshal(content,&rows); err != nil { t.Fatal(err) }
	captured := 0
	for _,row := range rows {
		if row.Status == "captured" {
			captured++
			if row.URL != "http://web.example.org" {t.Fatalf("wrong captured URL: %+v",row)}
			if !strings.HasPrefix(row.Path,"screenshots/inventory/") {t.Fatalf("unexpected PNG path: %+v",row)}
			if _,err := os.Stat(filepath.Join(dir,filepath.FromSlash(row.Path))); err != nil {t.Fatal(err)}
		}
	}
	if captured != 1 {t.Fatalf("wanted one scoped screenshot, got %d in %#v",captured,rows)}
}

func TestRunInventoryMultipleWorkersUniqueFiles(t *testing.T) {
	dir := t.TempDir()
	binDir := t.TempDir()
	fake := filepath.Join(binDir,"gowitness")
	script := `#!/bin/sh
[ "$1" = scan ] && [ "$2" = single ] || exit 17
shift 2
while [ "$#" -gt 0 ]; do
 case "$1" in
  --url) target="$2"; shift 2;;
  --screenshot-path) dest="$2"; shift 2;;
  --screenshot-format|--timeout|--threads) shift 2;;
  *) exit 18;;
 esac
done
[ -n "$target" ] || exit 19
mkdir -p "$dest"
head -c 256 /dev/zero > "$dest/shot.png"
`
	if err := os.WriteFile(fake,[]byte(script),0755);err!=nil{t.Fatal(err)}
	t.Setenv("PATH",binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg:=config.DefaultConfig()
	cfg.InventoryOnly=true
	cfg.ScreenshotWorkers=4
	cfg.Scope.Imported=&config.ScopeImport{Assets:[]config.ScopeAsset{
		{Kind:"wildcard",Host:"example.test"},
	}}
	st:=store.New("many-screenshots")
	for _,host := range []string{"a.example.test","b.example.test","c.example.test","d.example.test","e.example.test"}{
		st.AddHost(&store.Host{Domain:host,StatusCode:200,Meta:map[string]string{"url":"https://"+host}})
	}
	log:=logger.New(false,"")
	defer log.Close()
	if err:=New(cfg,st,log,dir).RunInventory(context.Background());err!=nil{t.Fatal(err)}
	raw,err:=os.ReadFile(filepath.Join(dir,"screenshots","inventory_manifest.json"))
	if err!=nil{t.Fatal(err)}
	var got []InventoryScreenshot
	if err:=json.Unmarshal(raw,&got);err!=nil{t.Fatal(err)}
	if len(got)!=5 {t.Fatalf("expected five origin screenshots, got %d",len(got))}
	paths:=map[string]bool{}
	for _,item:=range got {
		if item.Status!="captured" || paths[item.Path] {t.Errorf("missing or duplicate screenshot: %+v",item)}
		paths[item.Path]=true
		if _,err:=os.Stat(filepath.Join(dir,filepath.FromSlash(item.Path)));err!=nil{t.Error(err)}
	}
}
