package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/store"
)

func sampleImport() *config.ScopeImport {
	return &config.ScopeImport{Assets:[]config.ScopeAsset{
		{Identifier:"*.example.com",Kind:"wildcard",Host:"example.com"},
		{Identifier:"http://*.example.org",Kind:"wildcard-origin",Host:"example.org",Scheme:"http",Port:"80"},
		{Identifier:"blocked.example.com",Kind:"host",Host:"blocked.example.com",Excluded:true},
	}}
}
func TestBuildWildcardGroupsAndEndpoints(t *testing.T) {
	s := store.Snapshot{
		Subdomains:[]string{"admin.example.com","blocked.example.com","lost.example.com","site.example.org"},
		Hosts:[]*store.Host{
			{Domain:"admin.example.com",StatusCode:200,Server:"nginx",Title:"Admin Login",TechStack:[]string{"React"},Meta:map[string]string{"url":"https://admin.example.com"}},
			{Domain:"site.example.org",StatusCode:200,TechStack:[]string{"WordPress"},Meta:map[string]string{"url":"http://site.example.org"}},
			{Domain:"site.example.org",StatusCode:200,Meta:map[string]string{"url":"https://site.example.org"}},
			{Domain:"blocked.example.com",StatusCode:200,Meta:map[string]string{"url":"https://blocked.example.com"}},
		},
	}
	r := Build(s,sampleImport(),map[string]string{"https://admin.example.com":"screenshots/inventory/hash/screenshot.png"})
	if len(r.Hosts)!=3 {t.Fatalf("expected admin, lost, site: %+v",r.Hosts)}
	if len(r.Endpoints)!=2 {t.Fatalf("HTTP-only wildcard or exclusion failed: %+v",r.Endpoints)}
	if r.Hosts[0].Subdomain!="admin.example.com" || r.Hosts[0].Priority=="Deferred" {
		t.Fatalf("admin should be prioritized: %+v",r.Hosts)
	}
	for _,h:=range r.Hosts {
		if h.Subdomain=="lost.example.com" && h.Priority!="Deferred" {t.Fatalf("unknown reachability should defer: %+v",h)}
		if h.Subdomain=="site.example.org" && h.Wildcard!="http://*.example.org" {t.Fatalf("wrong wildcard group: %+v",h)}
	}
	if !strings.HasPrefix(r.Hosts[0].Screenshot,"../screenshots/") {t.Fatalf("no screenshot link: %+v",r.Hosts[0])}
}
func TestInventoryFilesOffline(t *testing.T){
	tmp:=t.TempDir()
	s:=store.Snapshot{Subdomains:[]string{"api.example.com","lost.example.com"}}
	if err:=Generate(s,sampleImport(),tmp);err!=nil{t.Fatal(err)}
	for _,p:=range []string{
		"inventory/index.html","inventory/report.json","inventory/subdomains_ranked.csv","inventory/endpoints.csv",
		"inventory/per_wildcard/__example_com/subdomains_ranked.csv",
		"inventory/per_wildcard/__example_com/by_status/unreachable.csv",
		"inventory/per_wildcard/__example_com/by_priority/Deferred.csv",
	}{
		if _,err:=os.Stat(filepath.Join(tmp,p));err!=nil{t.Fatalf("missing %s: %v",p,err)}
	}
}
