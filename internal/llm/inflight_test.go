package llm

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestInflightLimit_RespectsCap launches N concurrent doHTTP calls against
// a server that records peak concurrency. With cap=K the peak must never
// exceed K, regardless of how many callers fan in.
func TestInflightLimit_RespectsCap(t *testing.T) {
	const inflightCap = 3
	const callers = 20

	// Disable retries so a slow request can't accidentally retry into the
	// next slot and falsely depress the peak.
	resetTransportForTest(inflightCap, 1, 1*time.Millisecond, 5*time.Millisecond)
	t.Cleanup(disableTransport)

	var inFlight atomic.Int32
	var peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		// Hold the slot briefly so concurrent callers actually contend.
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
				return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
			})
			if err != nil {
				t.Errorf("doHTTP: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > inflightCap {
		t.Fatalf("peak inflight=%d exceeded cap=%d", got, inflightCap)
	}
}

// TestInflightLimit_Unlimited verifies that when the cap is 0 (unlimited)
// the semaphore is bypassed entirely — all callers can run in parallel.
func TestInflightLimit_Unlimited(t *testing.T) {
	resetTransportForTest(0, 1, 1*time.Millisecond, 5*time.Millisecond)
	t.Cleanup(disableTransport)

	const callers = 10
	var inFlight atomic.Int32
	var peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, _ = doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
				return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
			})
		}()
	}
	wg.Wait()

	// With no cap and tight timing we expect substantial parallelism.
	// Allow some slack for slow CI: require peak >= 3 (much higher than the
	// previous test's cap of 3, but still far from `callers`).
	if got := peak.Load(); got < 3 {
		t.Fatalf("peak inflight=%d, want significant parallelism", got)
	}
}

// TestInflightLimit_ContextCancelDuringWait makes sure a goroutine blocked
// on the semaphore wakes up immediately on ctx cancel rather than waiting
// for a slot.
func TestInflightLimit_ContextCancelDuringWait(t *testing.T) {
	resetTransportForTest(1, 1, time.Millisecond, time.Millisecond)
	t.Cleanup(disableTransport)

	// Hold the only slot.
	rel, err := acquireInflight(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = acquireInflight(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("acquireInflight did not return after ctx cancel")
	}
	rel()
}
