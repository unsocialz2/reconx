package config

import (
	"math"
	"time"
)

type BudgetPlan struct {
	Tool             string  `json:"tool"`
	Inputs           int     `json:"inputs"`
	Workers          int     `json:"workers"`
	Rate             float64 `json:"rate"`
	Seconds          int     `json:"seconds"`
	EstimatedSeconds int     `json:"estimated_seconds"`
	Capped           bool    `json:"capped"`
	Mode             string  `json:"mode"`
	Reason           string  `json:"reason"`
}

// SourceBudget is a bounded planning heuristic, never a completeness guarantee.
// Explicit total_timeout takes precedence over adaptive settings and is still hard.
func (c *Config) SourceBudget(name string, inputs int, fallback time.Duration) time.Duration {
	t := c.Tools[name]
	plan := BudgetPlan{Tool: name, Inputs: max(0, inputs), Workers: max(1, c.Workers), Rate: c.HostRPS}
	if t.RateLimit > 0 {
		plan.Rate = math.Min(plan.Rate, float64(t.RateLimit))
	}
	seconds := int(fallback / time.Second)
	if t.TotalTimeout > 0 {
		seconds = t.TotalTimeout
		plan.Mode = "explicit"
		plan.Reason = "Configured total_timeout; hard deadline retained under --no-timeout"
	} else if !c.AdaptiveBudgets {
		plan.Mode = "fixed"
		plan.Reason = "Adaptive planning disabled; legacy source ceiling"
	} else {
		plan.Mode = "adaptive"
		ceiling := min(seconds, c.BudgetCap)
		floor := min(120, ceiling)
		perInput := 10.0 / float64(plan.Workers)
		switch name {
		case "httpx":
			perInput = math.Max(6/math.Max(1, plan.Rate), 30/float64(plan.Workers))
			floor = min(300, ceiling)
		case "katana", "gospider":
			perInput = 60 / math.Max(1, plan.Rate)
			floor = min(300, ceiling)
		case "hakrawler":
			perInput = 40 / math.Max(1, plan.Rate)
			floor = min(300, ceiling)
		case "wafw00f":
			perInput = 45 / float64(plan.Workers)
		case "paramspider":
			perInput = float64(max(1, t.Timeout)) / float64(plan.Workers)
			floor = min(300, ceiling)
		case "amass":
			perInput = float64(max(600, t.Timeout))
			floor = min(600, ceiling)
		}
		estimate := math.Ceil(30 + float64(plan.Inputs)*perInput)
		plan.EstimatedSeconds = int(math.Min(estimate, float64(math.MaxInt32)))
		seconds = max(floor, min(plan.EstimatedSeconds, ceiling))
		plan.Capped = estimate > float64(ceiling)
		plan.Reason = "Heuristic from input count, workers and configured pacing; bounded by source/adaptive cap"
	}
	seconds = max(1, seconds)
	plan.Seconds = seconds
	if c.BudgetStatus != nil {
		c.BudgetStatus(plan)
	}
	return time.Duration(seconds) * time.Second
}
