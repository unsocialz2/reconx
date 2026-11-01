package subdomain

import "testing"

func TestFastInventorySourceSubset(t *testing.T) {
	for _, name := range []string{"subfinder","assetfinder","certspotter","hackertarget","rapiddns","subdomaincenter","urlscan"} {
		if !fastInventorySource(name) {t.Fatalf("expected fast source %s",name)}
	}
	for _, name := range []string{"amass","puredns","shuffledns","dnsx-brute","permute","crt.sh","alienvault-otx","anubis"} {
		if fastInventorySource(name) {t.Fatalf("slow source %s should require --inventory-thorough",name)}
	}
}
