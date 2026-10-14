package util

import (
	"testing"
)

func TestStripANSI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"\x1b[32mhello\x1b[0m", "hello"},
		{"\x1b[1;32m\x1b[37m[authToken = null]\x1b[0m", "[authToken = null]"},
		{"\x1b[00m credentials-disclosure[696] : credsPassword:\"meowmeowmeow\" \x1b[00m", " credentials-disclosure[696] : credsPassword:\"meowmeowmeow\" "},
		{"plain text", "plain text"},
		{"", ""},
	}

	for _, tc := range tests {
		got := StripANSI(tc.input)
		if got != tc.want {
			t.Errorf("StripANSI(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
