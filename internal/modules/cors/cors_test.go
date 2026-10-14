package cors

import "testing"

func TestCORSBrowserSemantics(t *testing.T) {
	for _, tc := range []struct {
		origin, acao, acac string
		want               bool
	}{{"https://reconx.invalid", "*", "true", false}, {"https://reconx.invalid", "*", "", false}, {"null", "null", "true", true}, {"https://reconx.invalid", "https://reconx.invalid", "true", true}, {"https://reconx.invalid", "https://other.invalid", "true", false}} {
		_, got := classify(tc.origin, tc.acao, tc.acac)
		if got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
	}
}
