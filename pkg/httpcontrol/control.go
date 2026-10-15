// Package httpcontrol coordinates built-in HTTP traffic across scan modules.
package httpcontrol

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type state struct{ next, blocked time.Time }
type Controller struct {
	mu    sync.Mutex
	hosts map[string]state
}

func New() *Controller { return &Controller{hosts: map[string]state{}} }
func (c *Controller) Wait(ctx context.Context, host string, rps float64) error {
	if !(rps > 0 && rps <= 1000) {
		return fmt.Errorf("invalid HTTP request rate")
	}
	interval := time.Duration(float64(time.Second) / rps)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		s := c.hosts[host]
		ready := s.next
		if s.blocked.After(ready) {
			ready = s.blocked
		}
		now := time.Now()
		if !ready.After(now) {
			s.next = now.Add(interval)
			c.hosts[host] = s
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		timer := time.NewTimer(time.Until(ready))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func (c *Controller) Cooldown(host string, delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.hosts[host]
	until := time.Now().Add(delay)
	if until.After(s.blocked) {
		s.blocked = until
	}
	c.hosts[host] = s
}

// RetryDelay respects numeric seconds and HTTP dates. Long server delays are
// returned intact: callers must not cap them into an early retry.
func RetryDelay(header string, attempt int, now time.Time, max time.Duration) time.Duration {
	header = strings.TrimSpace(header)
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds >= 0 {
		// Avoid duration overflow for a malformed or extremely long Retry-After.
		if seconds > int64((time.Duration(1<<63-1))/time.Second) {
			return time.Duration(1<<63 - 1)
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(header); err == nil {
		if at.After(now) {
			return at.Sub(now)
		}
		return 0
	}
	delay := time.Second * time.Duration(1<<uint(min(attempt, 10)))
	if delay > max {
		delay = max
	}
	return delay
}
