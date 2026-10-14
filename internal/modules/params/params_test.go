package params

import (
	"testing"
)

func TestGetJSFlagSupported(t *testing.T) {
	// Should not panic, and should return consistent bool
	hasHeader := getJSFlagSupported("header")
	hasInsecure := getJSFlagSupported("insecure")
	hasFake := getJSFlagSupported("non_existent_flag_xyz")

	if !hasHeader {
		t.Errorf("expected header to be supported, got false")
	}
	if hasFake {
		t.Errorf("expected non_existent_flag_xyz to NOT be supported, got true")
	}
	t.Logf("Probe results: header=%v, insecure=%v, fake=%v", hasHeader, hasInsecure, hasFake)
}
