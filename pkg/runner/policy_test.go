package runner

import (
	"context"
	"errors"
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
