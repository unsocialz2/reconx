package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestToolPolicyEnabledPathAndTimeout(t *testing.T) {
	ctx := WithPolicy(context.Background(), Policy{Workers: 1, Tools: map[string]ToolPolicy{"fake": {Enabled: false, Path: "sh"}}})
	if r := Run(ctx, "fake", []string{"-c", "echo should-not-run"}); !errors.Is(r.Err, ErrDisabled) || len(r.Lines) > 0 {
		t.Fatal("disabled tool executed")
	}
	ctx = WithPolicy(context.Background(), Policy{Workers: 1, Tools: map[string]ToolPolicy{"fake": {Enabled: true, Path: "sh", Timeout: 20 * time.Millisecond}}})
	if r := Run(ctx, "fake", []string{"-c", "sleep 1"}); !r.IsTimeout() {
		t.Fatalf("path/timeout override failed: %+v", r)
	}
}
func TestFlagsReplacePairsAndPreserveBooleanPositionals(t *testing.T) {
	got := MergeFlags([]string{"--subs", "example.com", "--threads", "50"}, []string{"--subs", "--threads", "2"})
	if !reflect.DeepEqual(got, []string{"example.com", "--subs", "--threads", "2"}) {
		t.Fatalf("bad args: %v", got)
	}
	args := policyArgs("nuclei", []string{"-c", "50", "-rate-limit", "150"}, &Policy{Workers: 2}, ToolPolicy{RateLimit: 5})
	if !reflect.DeepEqual(args, []string{"-rate-limit", "5", "-c", "2", "-dr"}) {
		t.Fatal(args)
	}
}

func TestEffectiveWorkerFlagsAndCommandObserver(t *testing.T) {
	for _, tc := range []struct{ tool, flag string }{{"naabu", "-c"}, {"mantra", "-t"}, {"httpx", "-threads"}, {"nuclei", "-c"}, {"katana", "-c"}, {"ffuf", "-t"}, {"hakrawler", "-t"}, {"gospider", "-c"}} {
		t.Run(tc.tool, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), tc.tool)
			if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			ctx := WithPolicy(context.Background(), Policy{Workers: 3, Tools: map[string]ToolPolicy{tc.tool: {Enabled: true, Path: bin}}})
			var actual []string
			ctx = WithCommandObserver(ctx, func(path string, args []string) {
				if path != bin {
					t.Errorf("path=%s", path)
				}
				actual = args
			})
			r := Run(ctx, tc.tool, []string{tc.flag, "50"})
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			if !reflect.DeepEqual(actual, r.Lines) || !reflect.DeepEqual(actual, r.Args) {
				t.Fatalf("observed %v executed %v", actual, r.Lines)
			}
			for i, a := range actual {
				if a == tc.flag && actual[i+1] != "3" {
					t.Fatal(actual)
				}
				if tc.tool != "httpx" && a == "-threads" {
					t.Fatal(actual)
				}
			}
		})
	}
}

func TestURLToolConcurrencyDoesNotMultiplyWorkers(t *testing.T) {
	for _, tc := range []struct {
		tool, flag string
		want       string
	}{{"gau", "--threads", "1"}, {"gauplus", "-t", "1"}, {"katana", "-p", "1"}, {"gospider", "-t", "1"}} {
		args := policyArgs(tc.tool, []string{tc.flag, "50"}, &Policy{Workers: 3}, ToolPolicy{})
		seen := false
		for i, a := range args {
			if a == tc.flag {
				seen = true
				if i+1 >= len(args) || args[i+1] != tc.want {
					t.Fatalf("%s: %v", tc.tool, args)
				}
			}
		}
		if !seen {
			t.Fatal(tc.tool, args)
		}
	}
}
