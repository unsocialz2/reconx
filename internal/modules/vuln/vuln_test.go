package vuln

import (
	"testing"
)

func TestParseNucleiLine(t *testing.T) {
	// Informational findings (like WAF and tech detection) must be discarded
	infoLines := []string{
		`{"template-id":"waf-detect","info":{"name":"WAF Detection","severity":"info"},"matched-at":"https://photos.mfp-integ.myfitnesspal.com"}`,
		`{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"info"},"matched-at":"https://app.myfitnesspal.com"}`,
		`{"template-id":"aws-cloudfront-detect","info":{"name":"AWS Service - Detect","severity":"info"},"matched-at":"http://brazestaging.myfitnesspal.com"}`,
		`{"template-id":"oauth-detect","info":{"name":"OAuth 2.0 Authorization Server Detection","severity":"info"},"matched-at":"https://preferences.myfitnesspal.com/oauth/token"}`,
		`{"template-id":"unknown-detect","info":{"name":"Unknown Severity","severity":"unknown"},"matched-at":"https://test.myfitnesspal.com"}`,
	}

	for _, line := range infoLines {
		f := parseNucleiLine(line)
		if f != nil {
			t.Errorf("expected info finding to be nil, got %+v", f)
		}
	}

	// Real security vulnerability findings must be kept
	vulnLines := []struct {
		line     string
		wantName string
		wantSev  string
	}{
		{
			line:     `{"template-id":"cve-2023-1234","info":{"name":"Critical RCE","severity":"critical"},"matched-at":"https://target.com/vuln"}`,
			wantName: "Critical RCE",
			wantSev:  "critical",
		},
		{
			line:     `{"template-id":"sqli-detect","info":{"name":"SQL Injection","severity":"high"},"matched-at":"https://target.com/api"}`,
			wantName: "SQL Injection",
			wantSev:  "high",
		},
		{
			line:     `{"template-id":"cors-misconfig","info":{"name":"CORS Misconfiguration","severity":"medium"},"matched-at":"https://target.com/cors"}`,
			wantName: "CORS Misconfiguration",
			wantSev:  "medium",
		},
		{
			line:     `{"template-id":"open-redirect","info":{"name":"Open Redirect","severity":"low"},"matched-at":"https://target.com/redirect"}`,
			wantName: "Open Redirect",
			wantSev:  "low",
		},
	}

	for _, tc := range vulnLines {
		f := parseNucleiLine(tc.line)
		if f == nil {
			t.Fatalf("expected non-nil finding for %s", tc.wantName)
		}
		if f.Name != tc.wantName {
			t.Errorf("name: got %q, want %q", f.Name, tc.wantName)
		}
		if f.Severity != tc.wantSev {
			t.Errorf("severity: got %q, want %q", f.Severity, tc.wantSev)
		}
	}
}
