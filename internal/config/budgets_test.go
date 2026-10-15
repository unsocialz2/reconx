package config

import (
	"testing"
	"time"
)

func TestAdaptiveBudgetScalesAndExplicitCeilingsWin(t *testing.T) {
	c := DefaultConfig()
	var plans []BudgetPlan
	c.BudgetStatus = func(p BudgetPlan) { plans = append(plans, p) }
	small := c.SourceBudget("httpx", 10, time.Hour)
	large := c.SourceBudget("httpx", 1000, time.Hour)
	if small >= large || large > time.Hour || plans[0].Mode != "adaptive" {
		t.Fatal(plans)
	}
	c.BudgetCap = 60
	if got := c.SourceBudget("katana", 1000000, 30*time.Minute); got != time.Minute || !plans[len(plans)-1].Capped {
		t.Fatal(got, plans)
	}
	tc := c.Tools["katana"]
	tc.TotalTimeout = 180
	c.Tools["katana"] = tc
	if got := c.SourceBudget("katana", 1, 30*time.Minute); got != 3*time.Minute || plans[len(plans)-1].Mode != "explicit" {
		t.Fatal(got, plans)
	}
	c.AdaptiveBudgets = false
	if got := c.SourceBudget("httpx", 1, time.Hour); got != time.Hour {
		t.Fatal(got)
	}
}
func TestRetrySelectionRequiresResumeAndNeverEnablesScanners(t *testing.T) {
	for _, c := range []*Config{
		{RetryPhases: []string{"urls"}}, {ResumeDir: "scan", RetryPhases: []string{"bad"}},
		{ResumeDir: "scan", RetrySources: []string{"nuclei"}}, {ResumeDir: "scan", RetryPhases: []string{"urls"}, RetrySources: []string{"katana"}}, {Refresh: true},
	} {
		if c.ValidateRetry() == nil {
			t.Fatal("invalid retry accepted", c)
		}
	}
	c := DefaultConfig()
	c.ResumeDir = "scan"
	c.RetrySources = NormalizeRetry([]string{"katana,httpx", "katana"})
	if err := c.ValidateRetry(); err != nil {
		t.Fatal(err)
	}
	if !c.SelectsPhase("urls") || !c.SelectsPhase("alive") || c.SelectsPhase("js") || c.Phases.PortScan || c.Phases.VulnScan {
		t.Fatal("selection broadened execution")
	}
}
