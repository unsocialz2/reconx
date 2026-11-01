package runner

import (
	"slices"
	"testing"
)

func hasFlagValue(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value { return true }
	}
	return false
}
func hasFlag(args []string, key string) bool { return slices.Contains(args, key) }

func TestInventoryHTTPXDoesNotInheritRequestRateOrWorkerCap(t *testing.T) {
	p := &Policy{RequestRate: 1, Workers: 2, InventoryHTTPXFast: true}
	input := []string{"-json", "-threads", "50", "-tech-detect"}
	args := policyArgs("httpx", input, p, ToolPolicy{})
	if hasFlag(args, "-rate-limit") || hasFlag(args, "-rl") {
		t.Fatalf("unexpected ReconX rate cap: %#v", args)
	}
	if !hasFlagValue(args, "-threads", "50") {
		t.Fatalf("worker cap overwrote native concurrency: %#v", args)
	}
}

func TestInventoryHTTPXHonorsExplicitToolRateLimit(t *testing.T) {
	p := &Policy{RequestRate: 1, Workers: 2, InventoryHTTPXFast: true}
	args := policyArgs("httpx", []string{"-threads", "50"}, p, ToolPolicy{RateLimit: 17})
	if !hasFlagValue(args, "-rate-limit", "17") {
		t.Fatalf("explicitly configured HTTPX rate not retained: %#v", args)
	}
	if !hasFlagValue(args, "-threads", "50") {
		t.Fatalf("native HTTPX threads changed: %#v", args)
	}
}

func TestOtherModesKeepExistingPolicies(t *testing.T) {
	p := &Policy{RequestRate: 3, Workers: 4}
	args := policyArgs("httpx", []string{"-threads", "50"}, p, ToolPolicy{})
	if !hasFlagValue(args, "-rate-limit", "3") || !hasFlagValue(args, "-threads", "4") {
		t.Fatalf("existing standard scan rate policy regressed: %#v", args)
	}
}
