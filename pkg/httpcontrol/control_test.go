package httpcontrol

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestRetryAfterParsingAndBackoff(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		header  string
		attempt int
		want    time.Duration
	}{
		{"120", 0, 120 * time.Second}, {"0", 0, 0}, {now.Add(20 * time.Second).Format(http.TimeFormat), 0, 20 * time.Second},
		{now.Add(-time.Second).Format(http.TimeFormat), 0, 0}, {"bad", 0, time.Second}, {"-1", 2, 4 * time.Second}, {"", 10, 30 * time.Second},
	} {
		if got := RetryDelay(tc.header, tc.attempt, now, 30*time.Second); got != tc.want {
			t.Fatalf("%+v got %s", tc, got)
		}
	}
}
func TestCancellationAndHostIsolation(t *testing.T) {
	c := New()
	c.Cooldown("busy", time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Wait(ctx, "busy", 2) == nil {
		t.Fatal("cancellation ignored")
	}
	if err := c.Wait(context.Background(), "other", 2); err != nil {
		t.Fatal(err)
	}
}
