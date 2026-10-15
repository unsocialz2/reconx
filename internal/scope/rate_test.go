package scope

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unsocialz2/reconx/internal/config"
)

func TestBuiltInRetryAndNoWriteReplay(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(503)
					return
				}
				w.WriteHeader(200)
			}))
			defer server.Close()
			cfg := config.DefaultConfig()
			cfg.Target.Domains = []string{"127.0.0.1"}
			cfg.HostRPS = 1000
			req, _ := http.NewRequest(method, server.URL, strings.NewReader("fixture"))
			resp, err := New(cfg).Client(time.Second).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			want := int32(2)
			status := 200
			if method == http.MethodPost {
				want = 1
				status = 503
			}
			if calls.Load() != want || resp.StatusCode != status {
				t.Fatalf("calls=%d status=%d", calls.Load(), resp.StatusCode)
			}
		})
	}
}
func TestLongRetryAfterDefersOtherClientsWithoutEarlyRetry(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(429)
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	cfg.HostRPS = 1000
	cfg.HTTPMaxBackoff = 1
	first, err := New(cfg).Client(time.Second).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != 429 || calls.Load() != 1 {
		t.Fatal("long delay retried early")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	_, err = New(cfg).Client(time.Second).Do(req)
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("cooldown not shared: calls=%d err=%v", calls.Load(), err)
	}
}
func TestHostRateIsSharedAcrossModuleClients(t *testing.T) {
	var mu sync.Mutex
	var arrivals []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivals = append(arrivals, time.Now())
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	cfg.HostRPS = 50
	clients := []*http.Client{New(cfg).Client(2 * time.Second), New(cfg).Client(2 * time.Second)}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := clients[i%2].Get(server.URL)
			if err != nil {
				t.Error(err)
				return
			}
			res.Body.Close()
		}(i)
	}
	wg.Wait()
	if len(arrivals) != 6 || arrivals[5].Sub(arrivals[0]) < 80*time.Millisecond {
		t.Fatalf("shared host cap bypassed: %v", arrivals)
	}
}

func TestRetryDelayPastClientDeadlinePreservesHTTPObservation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(503)
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	cfg.Target.Domains = []string{"127.0.0.1"}
	cfg.HTTPMaxBackoff = 30
	resp, err := New(cfg).Client(50 * time.Millisecond).Get(server.URL)
	if err != nil {
		t.Fatal("available HTTP observation was discarded", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 503 || calls.Load() != 1 {
		t.Fatal("retried beyond deadline")
	}
}
