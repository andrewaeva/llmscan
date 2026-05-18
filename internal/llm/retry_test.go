package llm

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// resetTransport is a test-only helper to dial the global transport policy
// up or down between subtests. resetTransportForTest bypasses sync.Once.
func resetTransport(t *testing.T, inflight, maxRetries int, base, maxDelay time.Duration) {
	t.Helper()
	resetTransportForTest(inflight, maxRetries, base, maxDelay)
}

// disableTransport returns the global policy to its zero-retry, no-cap state.
// Tests that mutate the transport must defer this so unrelated tests in the
// package don't inherit retry tuning and end up sleeping seconds on 5xx.
func disableTransport() {
	resetTransportForTest(0, 1, 0, 0)
}

func TestDoHTTP_RetriesOn429ThenSucceeds(t *testing.T) {
	// Tiny backoff so the test is fast (a few ms total).
	resetTransport(t, 0, 4, 1*time.Millisecond, 10*time.Millisecond)
	t.Cleanup(disableTransport)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"inflight limit exceeded"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	res, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	if err != nil {
		t.Fatalf("doHTTP: %v", err)
	}
	if res.status != 200 {
		t.Fatalf("status=%d", res.status)
	}
	if string(res.body) != "ok" {
		t.Fatalf("body=%q", string(res.body))
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("hits=%d, want 3 (2 retries + 1 success)", got)
	}
}

func TestDoHTTP_GivesUpAfterMaxRetries(t *testing.T) {
	resetTransport(t, 0, 3, 1*time.Millisecond, 5*time.Millisecond)
	t.Cleanup(disableTransport)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	_, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	if err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("err=%v; want wrap of ErrRateLimit", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("hits=%d, want 3 attempts", got)
	}
}

func TestDoHTTP_NoRetryOnPermanent4xx(t *testing.T) {
	resetTransport(t, 0, 5, 1*time.Millisecond, 5*time.Millisecond)
	t.Cleanup(disableTransport)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`bad`))
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	res, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("err=%v; want ErrBadRequest", err)
	}
	if res.status != 400 {
		t.Fatalf("status=%d", res.status)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("hits=%d, want 1 (permanent 4xx must not retry)", got)
	}
}

func TestDoHTTP_RetriesOn5xx(t *testing.T) {
	resetTransport(t, 0, 4, 1*time.Millisecond, 5*time.Millisecond)
	t.Cleanup(disableTransport)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	res, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	if err != nil {
		t.Fatalf("doHTTP: %v", err)
	}
	if res.status != 200 {
		t.Fatalf("status=%d", res.status)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("hits=%d, want 2", got)
	}
}

func TestDoHTTP_HonorsRetryAfterSeconds(t *testing.T) {
	// Base delay tiny so the only material wait should come from Retry-After.
	resetTransport(t, 0, 3, 1*time.Millisecond, 200*time.Millisecond)
	t.Cleanup(disableTransport)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			// Ask for 1ms via numeric form ("0" might be ignored; "1" rounds to 1s).
			// Cap-via-max will reduce it back to maxDelay (200ms) so the test stays quick.
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	start := time.Now()
	_, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	if err != nil {
		t.Fatalf("doHTTP: %v", err)
	}
	elapsed := time.Since(start)
	// We capped retry delay at 200ms, so it should never wait the full 1s.
	if elapsed > 800*time.Millisecond {
		t.Fatalf("elapsed=%s — retry slept past max_delay cap", elapsed)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits=%d, want 2", hits.Load())
	}
}

func TestDoHTTP_ContextCancelInterruptsBackoff(t *testing.T) {
	// Big base+max so the loop *would* sleep for a long time if not cancelled.
	resetTransport(t, 0, 5, 5*time.Second, 60*time.Second)
	t.Cleanup(disableTransport)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := doHTTP(ctx, hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context cancel error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ctx cancel did not interrupt backoff (elapsed %s)", elapsed)
	}
}

func TestBackoffDelay_ClampsAndScales(t *testing.T) {
	base := 100 * time.Millisecond
	maxDelay := 1 * time.Second
	for attempt := 1; attempt <= 10; attempt++ {
		d := backoffDelay(base, maxDelay, attempt)
		if d < 0 || d > maxDelay+maxDelay/4 { // small jitter slack
			t.Errorf("attempt=%d d=%s outside [0,max+jitter]", attempt, d)
		}
		if d > maxDelay {
			t.Errorf("attempt=%d d=%s exceeds max=%s", attempt, d, maxDelay)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter(""); d != 0 {
		t.Errorf("empty: got %v", d)
	}
	if d := parseRetryAfter("3"); d != 3*time.Second {
		t.Errorf("3: got %v", d)
	}
	if d := parseRetryAfter("garbage"); d != 0 {
		t.Errorf("garbage: got %v", d)
	}
	// HTTP-date form: 30s in the future.
	when := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if d := parseRetryAfter(when); d <= 0 || d > 31*time.Second {
		t.Errorf("http-date: got %v", d)
	}
}

// Sanity check: status header numbers we read in tests survive round-trip.
func TestDoHTTP_ResponseHeadersExposed(t *testing.T) {
	resetTransport(t, 0, 1, 1*time.Millisecond, 5*time.Millisecond)
	t.Cleanup(disableTransport)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", strconv.Itoa(42))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	hc := &http.Client{Timeout: 2 * time.Second}
	res, err := doHTTP(context.Background(), hc, "test", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`x`)))
	})
	if err != nil {
		t.Fatalf("doHTTP: %v", err)
	}
	if got := res.header.Get("X-Test"); got != "42" {
		t.Errorf("X-Test=%q", got)
	}
}
