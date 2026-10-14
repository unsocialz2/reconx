// gen_test_report.go — generates a sample HTML report for visual inspection.
// Run: go run scripts/gen_test_report.go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/reconx/reconx/internal/modules/report"
	"github.com/reconx/reconx/internal/store"
)

func main() {
	st := store.New("example.com-1782000000")

	// Subdomains with sources
	subs := []struct {
		sub, src string
	}{
		{"api.example.com", "subfinder"},
		{"www.example.com", "crt.sh"},
		{"dev.example.com", "permute"},
		{"admin.example.com", "subfinder"},
		{"staging.example.com", "amass"},
		{"graphql.example.com", "virustotal"},
		{"v1.api.example.com", "crt.sh"},
		{"v2.api.example.com", "crt.sh"},
		{"static.example.com", "subfinder"},
		{"assets.example.com", "anubis"},
		{"cdn.example.com", "rapiddns"},
		{"auth.example.com", "shodan"},
		{"sso.example.com", "assetfinder"},
		{"oauth.example.com", "findomain"},
		{"docs.example.com", "otx"},
		{"help.example.com", "hackertarget"},
		{"status.example.com", "urlscan"},
		{"blog.example.com", "sonar"},
		{"news.example.com", "threatcrowd"},
		{"mail.example.com", "permute"},
	}
	for _, s := range subs {
		st.AddSubdomainFromSource(s.sub, s.src)
	}

	// Hosts
	hosts := []struct {
		domain string
		status int
		title  string
		server string
		tech   []string
		tags   []string
	}{
		{"api.example.com", 200, "API Server", "nginx", []string{"nginx", "PHP", "MySQL"}, []string{"200-ok"}},
		{"www.example.com", 403, "Forbidden", "cloudflare", []string{"cloudflare", "React"}, []string{"403-bypass-candidate"}},
		{"admin.example.com", 401, "Admin Login", "Apache", []string{"Apache", "PHP"}, []string{"auth-required"}},
		{"staging.example.com", 302, "Redirect", "nginx", []string{"nginx"}, []string{"redirect"}},
		{"graphql.example.com", 500, "Server Error", "", []string{"Node.js"}, []string{"server-error"}},
		{"auth.example.com", 200, "Auth Service", "nginx", []string{"nginx", "Go"}, []string{"200-ok"}},
	}
	for _, h := range hosts {
		st.AddHost(&store.Host{
			Domain:     h.domain,
			StatusCode: h.status,
			Title:      h.title,
			Server:     h.server,
			TechStack:  h.tech,
			Tags:       h.tags,
			Meta:       map[string]string{"url": "https://" + h.domain},
		})
	}

	// Ports
	ports := []struct {
		host string
		port int
		svc  string
	}{
		{"api.example.com", 443, "https"},
		{"api.example.com", 80, "http"},
		{"api.example.com", 22, "ssh"},
		{"api.example.com", 3306, "mysql"},
		{"www.example.com", 443, "https"},
		{"admin.example.com", 443, "https"},
		{"admin.example.com", 8080, "http-alt"},
		{"staging.example.com", 443, "https"},
		{"graphql.example.com", 443, "https"},
		{"auth.example.com", 443, "https"},
		{"auth.example.com", 8443, "https-alt"},
	}
	for _, p := range ports {
		st.AddPort(&store.Port{Host: p.host, Port: p.port, Protocol: "tcp", Service: p.svc})
	}

	// URLs
	urls := []string{
		"https://api.example.com/v1/users",
		"https://api.example.com/v1/users/{id}",
		"https://api.example.com/login",
		"https://api.example.com/admin",
		"https://api.example.com/.env",
		"https://api.example.com/.git/config",
		"https://www.example.com/admin",
		"https://www.example.com/login",
		"https://www.example.com/redirect?url=",
		"https://www.example.com/static/app.js",
		"https://admin.example.com/admin/users",
		"https://staging.example.com/api/test",
	}
	st.AddURLs(urls)

	// JS files
	st.AddJSFile("https://api.example.com/static/app.js")
	st.AddJSFile("https://www.example.com/main.js")
	st.AddJSFile("https://www.example.com/vendor.js")

	// Findings
	findings := []struct {
		name, severity, target, template string
	}{
		{"Open Redirect", "high", "https://api.example.com/redirect?url=evil.com", "open-redirect"},
		{"XSS in search", "medium", "https://www.example.com/search?q=<script>", "xss-reflected"},
		{"Server Status Disclosure", "low", "https://api.example.com/", "tech-detect"},
		{"SQL Injection in login", "critical", "https://admin.example.com/login", "sqli-error-based"},
		{"Exposed .env file", "critical", "https://api.example.com/.env", "exposed-config"},
		{"Default admin credentials", "high", "https://admin.example.com/admin", "default-login"},
		{"Missing security headers", "low", "https://www.example.com/", "missing-headers"},
		{"CORS misconfiguration", "medium", "https://api.example.com/", "cors-misconfig"},
	}
	for _, f := range findings {
		st.AddFinding(&store.Finding{Name: f.name, Severity: f.severity, Target: f.target, Template: f.template})
	}

	// Secrets
	secrets := []struct {
		typ, val, src string
	}{
		{"AWS Access Key", "AKIAIOSFODNN7EXAMPLE", "trufflehog"},
		{"GitHub Token", "ghp_xxxxxxxxxxxxxxxxxxxx", "mantra"},
		{"Stripe Secret Key", "sk_live_xxxxxxxxxxxxxxxx", "jsecret"},
		{"Slack Token", "xoxb-xxxxxxxxxxxx", "trufflehog"},
		{"Private Key", "-----BEGIN RSA PRIVATE KEY-----", "mantra"},
	}
	for _, s := range secrets {
		st.AddSecret(&store.Secret{Type: s.typ, Value: s.val, Source: s.src})
	}

	outDir := "/home/z/my-project/download"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := report.Generate(st, []string{"example.com"}, outDir); err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Report generated:", filepath.Join(outDir, "report.html"))
}
