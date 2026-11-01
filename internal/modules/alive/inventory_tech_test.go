package alive

import (
  "testing"
)

func TestHTTPXTechJSON(t *testing.T) {
  line := `{"url":"https://api.example.test","status_code":200,"tech":["nginx","React"],"technologies":["React","Cloudflare"]}`
  got := parseHTTPXLine(line)
  if got == nil || len(got.TechStack) != 3 {
    t.Fatalf("unexpected technology fingerprint: %+v", got)
  }
}
