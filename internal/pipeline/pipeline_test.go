package pipeline

import (
	"testing"
)

func TestStripURLToHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://sub.example.com/path?q=1", "sub.example.com"},
		{"http://sub.example.com", "sub.example.com"},
		{"https://sub.example.com:8443/x", "sub.example.com"},
		{"sub.example.com", "sub.example.com"},
		{"sub.example.com:443", "sub.example.com"},
		{"HTTPS://UPPER.Example.COM", "upper.example.com"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		got := stripURLToHost(c.in)
		if got != c.want {
			t.Errorf("stripURLToHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGuessPortService(t *testing.T) {
	cases := map[int]string{
		22:   "ssh",
		80:   "http",
		443:  "https",
		3306: "mysql",
		8080: "http-alt",
		1:    "unknown",
		0:    "unknown",
	}
	for port, want := range cases {
		if got := guessPortService(port); got != want {
			t.Errorf("guessPortService(%d) = %q, want %q", port, got, want)
		}
	}
}


func TestExtractDomainFromResumeDir(t *testing.T) {
	cases := []struct {
		dir  string
		want string
	}{
		{"/path/example.com-1700000000", "example.com"},
		{"/path/evil-corp.com-1700000000", "evil-corp.com"},
		{"/path/with-many-dashes-123.com-1700000000", "with-many-dashes-123.com"},
		{"/path/no-timestamp", "no-timestamp"},
		{"/path/just-a-domain.com", "just-a-domain.com"},
	}
	for _, c := range cases {
		got := extractDomainFromResumeDir(c.dir)
		if got != c.want {
			t.Errorf("extractDomainFromResumeDir(%q): want %q, got %q", c.dir, c.want, got)
		}
	}
}

func TestIsAllDigits(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"123", true},
		{"0", true},
		{"", false},
		{"12a", false},
		{"-123", false},
	}
	for _, c := range cases {
		got := isAllDigits(c.input)
		if got != c.want {
			t.Errorf("isAllDigits(%q): want %v, got %v", c.input, c.want, got)
		}
	}
}
