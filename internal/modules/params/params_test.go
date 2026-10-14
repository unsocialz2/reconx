package params

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetJSFlagSupported(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "getJS")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' '--header value --insecure'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	getJSFlagCacheLoaded = false
	getJSFlagCache = map[string]bool{}
	t.Cleanup(func() { getJSFlagCacheLoaded = false; getJSFlagCache = map[string]bool{} })
	if !getJSFlagSupported("header") || !getJSFlagSupported("insecure") {
		t.Fatal("help flags were not parsed")
	}
	if getJSFlagSupported("non_existent_flag_xyz") {
		t.Fatal("unknown flag accepted")
	}
}
