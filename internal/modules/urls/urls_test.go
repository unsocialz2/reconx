package urls

import (
        "sort"
        "testing"
)

func TestExtractRootDomains_SimpleTLD(t *testing.T) {
        hosts := []string{
                "https://api.airbnb.com",
                "https://www.airbnb.com/path",
                "https://airbnb.com:443",
                "ar.airbnb.com",
        }
        got := extractRootDomains(hosts)
        want := []string{"airbnb.com"}
        if len(got) != 1 || got[0] != want[0] {
                t.Errorf("got %v, want %v", got, want)
        }
}

func TestExtractRootDomains_MultiPartTLD(t *testing.T) {
        hosts := []string{
                "https://www.bbc.co.uk",
                "https://api.bbc.co.uk",
                "news.bbc.co.uk",
        }
        got := extractRootDomains(hosts)
        want := []string{"bbc.co.uk"}
        if len(got) != 1 || got[0] != want[0] {
                t.Errorf("got %v, want %v", got, want)
        }
}

func TestExtractRootDomains_MixedTLDs(t *testing.T) {
        hosts := []string{
                "api.airbnb.com",       // root: airbnb.com
                "www.bbc.co.uk",        // root: bbc.co.uk (multi-part TLD)
                "shop.company.com.au",  // root: company.com.au (multi-part TLD)
                "sub.example.com",      // root: example.com
        }
        got := extractRootDomains(hosts)
        sort.Strings(got)
        want := []string{"airbnb.com", "bbc.co.uk", "company.com.au", "example.com"}
        sort.Strings(want)
        if len(got) != len(want) {
                t.Fatalf("got %d roots %v, want %d %v", len(got), got, len(want), want)
        }
        for i := range got {
                if got[i] != want[i] {
                        t.Errorf("root[%d]: got %q, want %q", i, got[i], want[i])
                }
        }
}

func TestExtractRootDomains_StripsPortAndPath(t *testing.T) {
        hosts := []string{
                "https://api.example.com:8443/v1/foo",
                "http://www.example.com:8080",
                "example.com/?q=1",
        }
        got := extractRootDomains(hosts)
        if len(got) != 1 || got[0] != "example.com" {
                t.Errorf("got %v, want [example.com]", got)
        }
}

func TestIsMultiPartTLD(t *testing.T) {
        yes := []string{"co.uk", "com.au", "co.jp", "co.nz", "com.br", "com.cn", "co.in", "co.za"}
        for _, s := range yes {
                if !isMultiPartTLD(s) {
                        t.Errorf("isMultiPartTLD(%q) should be true", s)
                }
        }
        no := []string{"com", "org", "net", "io", "dev", "example.com", "co", "uk"}
        for _, s := range no {
                if isMultiPartTLD(s) {
                        t.Errorf("isMultiPartTLD(%q) should be false", s)
                }
        }
}
