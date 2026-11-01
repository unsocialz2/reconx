package screenshot

import (
	"testing"
	"strings"

	"github.com/unsocialz2/reconx/internal/config"
	"github.com/unsocialz2/reconx/internal/scope"
	"github.com/unsocialz2/reconx/internal/store"
)

func TestSafeInventoryScreenshotTargets(t *testing.T) {
	cfg:=config.DefaultConfig()
	cfg.Scope.Imported=&config.ScopeImport{Assets:[]config.ScopeAsset{
		{Kind:"wildcard-origin",Host:"example.org",Scheme:"http",Port:"80"},
	}}
	filter:=scope.New(cfg)
	cases:=[]struct{url string;code int;location string;allowed bool}{
		{"http://site.example.org",200,"",true},
		{"https://site.example.org",200,"",false},
		{"http://site.example.org",429,"",false},
		{"http://site.example.org",302,"https://external.example.com",false},
		{"http://site.example.org",302,"http://another.example.org/login",true},
		{"http://site.example.org",302,"",false},
		{"http://site.example.org",404,"",true},
	}
	for _,test:=range cases{
		h:=&store.Host{Domain:"site.example.org",StatusCode:test.code,Meta:map[string]string{"url":test.url,"location":test.location}}
		target,_:=safeScreenshotTarget(h,filter)
		if (target!="")!=test.allowed{t.Errorf("url=%s code=%d location=%s allowed=%v got=%q",test.url,test.code,test.location,test.allowed,target)}
	}
}

func TestGowitnessV3SingleArgsNoUnsupportedSchemeFlags(t *testing.T) {
	url := "http://allowed.example.org"
	args := inventoryScreenshotArgs(url, "/tmp/one-image")
	line := strings.Join(args, " ")
	for _,required := range []string{"scan single", "--url "+url, "--screenshot-format png", "--threads 1"} {
		if !strings.Contains(line,required) {t.Errorf("missing v3 argument %q from %q",required,line)}
	}
	for _,forbidden := range []string{"--no-http","--no-https"} {
		if strings.Contains(line,forbidden) {t.Errorf("unsupported gowitness v3 flag %s",forbidden)}
	}
}
