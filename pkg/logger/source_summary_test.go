package logger

import "testing"

func TestSourceRetryPreservesUntouchedFailureAndCompletionTimes(t *testing.T) {
	previous := []ToolStatus{{Name: "example.test / amass", State: "timeout", Count: 8}, {Name: "example.test / subfinder", State: "done", Count: 20}}
	current := []ToolStatus{{Name: "example.test / amass", State: "done", Count: 12}, {Name: "example.test / subfinder", State: "skipped", Message: "not selected for retry"}}
	merged := MergeSourceStats(previous, current, []string{"amass"})
	if len(merged) != 2 || merged[0].State != "done" || merged[1].State != "done" || merged[1].Count != 20 {
		t.Fatal(merged)
	}
	previous[1].State = "timeout"
	current[1].State = "skipped"
	merged = MergeSourceStats(previous, current, []string{"amass"})
	if merged[1].State != "timeout" {
		t.Fatal("untouched failure hidden", merged)
	}
}
