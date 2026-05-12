package llm

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// transportPolicy holds the process-global inflight cap and retry tuning.
// Set once via ConfigureTransport (idempotent on first call); subsequent
// calls in the same process are no-ops, so the first config wins.
type transportPolicy struct {
	sem        chan struct{} // nil = unlimited
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
}

var (
	policyOnce sync.Once
	policy     atomicPolicy
)

// atomicPolicy is read by every HTTP-issuing call. We snapshot to a value
// once at configure time; subsequent reads are lock-free.
type atomicPolicy struct {
	mu sync.RWMutex
	p  transportPolicy
}

func (a *atomicPolicy) load() transportPolicy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.p
}

func (a *atomicPolicy) store(p transportPolicy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.p = p
}

// ConfigureTransport installs the process-wide inflight cap and retry tuning
// for every LLM client created via New. Safe to call multiple times — only
// the first call has effect (sync.Once). Callers should invoke this from
// main / setup code BEFORE any llm.New() call.
//
//	inflightLimit: 0 = unlimited, N>0 = max N concurrent HTTP requests in flight
//	maxRetries:    cap on retry attempts (1 means no retry past the first attempt)
//	baseDelay:     first backoff sleep
//	maxDelay:      clamp on backoff sleep
func ConfigureTransport(inflightLimit, maxRetries int, baseDelay, maxDelay time.Duration) {
	policyOnce.Do(func() {
		var sem chan struct{}
		if inflightLimit > 0 {
			sem = make(chan struct{}, inflightLimit)
		}
		if maxRetries <= 0 {
			maxRetries = 6
		}
		if baseDelay <= 0 {
			baseDelay = time.Second
		}
		if maxDelay <= 0 {
			maxDelay = 30 * time.Second
		}
		policy.store(transportPolicy{
			sem:        sem,
			maxRetries: maxRetries,
			baseDelay:  baseDelay,
			maxDelay:   maxDelay,
		})
		if inflightLimit > 0 {
			log.Printf("[llm] transport: inflight_limit=%d max_retries=%d base=%s max=%s",
				inflightLimit, maxRetries, baseDelay, maxDelay)
		} else {
			log.Printf("[llm] transport: inflight_limit=unlimited max_retries=%d base=%s max=%s",
				maxRetries, baseDelay, maxDelay)
		}
	})
}

// resetTransportForTest is the only sanctioned way to reconfigure the
// transport from tests. Production code must use ConfigureTransport.
func resetTransportForTest(inflightLimit, maxRetries int, baseDelay, maxDelay time.Duration) {
	var sem chan struct{}
	if inflightLimit > 0 {
		sem = make(chan struct{}, inflightLimit)
	}
	if maxRetries <= 0 {
		maxRetries = 1
	}
	if baseDelay < 0 {
		baseDelay = 0
	}
	if maxDelay < 0 {
		maxDelay = 0
	}
	policy.store(transportPolicy{
		sem:        sem,
		maxRetries: maxRetries,
		baseDelay:  baseDelay,
		maxDelay:   maxDelay,
	})
}

// acquireInflight blocks until a slot in the global semaphore is available
// or ctx is cancelled. Returns a release func; safe to call even when the
// semaphore is unlimited (release is a no-op then).
func acquireInflight(ctx context.Context) (release func(), err error) {
	p := policy.load()
	if p.sem == nil {
		return func() {}, nil
	}
	select {
	case p.sem <- struct{}{}:
		return func() { <-p.sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// httpAttemptResult is a single HTTP attempt outcome from inside the retry loop.
type httpAttemptResult struct {
	status int
	body   []byte
	header http.Header
}

// doHTTP is the single chokepoint every HTTP call to an LLM provider goes
// through. It:
//
//   - acquires the global inflight semaphore (so concurrent calls across
//     scanner / verifier / deep agents respect the proxy cap),
//   - invokes attempt() to issue one HTTP request,
//   - if the status maps to ErrRateLimit / ErrTransient, retries with
//     exponential backoff + jitter, honoring Retry-After when present,
//   - respects ctx cancellation between attempts.
//
// label is a short human tag included in retry logs (e.g. "openai",
// "anthropic"). attempt is called once per try and must build a fresh
// *http.Request each time (request bodies are one-shot readers).
func doHTTP(ctx context.Context, hc *http.Client, label string, build func(context.Context) (*http.Request, error)) (httpAttemptResult, error) {
	p := policy.load()
	maxAttempts := p.maxRetries
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	var lastErr error
	var lastResult httpAttemptResult
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return httpAttemptResult{}, err
		}
		release, err := acquireInflight(ctx)
		if err != nil {
			return httpAttemptResult{}, err
		}
		result, callErr := singleHTTPAttempt(ctx, hc, label, build)
		release()
		lastResult = result
		// Treat network errors as transient — they often come from proxy
		// jitter, TLS reset, dropped sockets, and should retry.
		if callErr != nil {
			callErr = fmt.Errorf("%s http: %w: %v", label, ErrTransient, callErr)
		} else if sentinel := classifyHTTP(result.status); sentinel != nil {
			callErr = fmt.Errorf("%s http %d: %s: %w", label, result.status, string(result.body), sentinel)
		}
		if callErr == nil {
			return result, nil
		}
		lastErr = callErr
		if !isRetryable(callErr) || attempt == maxAttempts {
			return result, callErr
		}
		delay := backoffDelay(p.baseDelay, p.maxDelay, attempt)
		if result.header != nil {
			if ra := parseRetryAfter(result.header.Get("Retry-After")); ra > 0 {
				if p.maxDelay > 0 && ra > p.maxDelay {
					delay = p.maxDelay
				} else {
					delay = ra
				}
			}
		}
		log.Printf("[llm] retry %d/%d after %.1fs: %v",
			attempt+1, maxAttempts, delay.Seconds(), callErr) //nolint:gosec // structured log
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return httpAttemptResult{}, ctx.Err()
		case <-t.C:
		}
	}
	return lastResult, lastErr
}

func singleHTTPAttempt(ctx context.Context, hc *http.Client, _ string, build func(context.Context) (*http.Request, error)) (httpAttemptResult, error) {
	req, err := build(ctx)
	if err != nil {
		return httpAttemptResult{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return httpAttemptResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return httpAttemptResult{
		status: resp.StatusCode,
		body:   raw,
		header: resp.Header,
	}, nil
}

// backoffDelay returns base * 2^(attempt-1) plus jitter, clamped to max.
// attempt is 1-based: attempt=1 -> base, attempt=2 -> 2*base, etc.
func backoffDelay(base, max time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	mult := 1 << (attempt - 1)
	if mult < 1 || mult > 1024 {
		mult = 1024
	}
	d := time.Duration(mult) * base
	if max > 0 && d > max {
		d = max
	}
	// ±25% jitter on the chosen value.
	jitter := time.Duration(rand.Int63n(int64(d/2 + 1))) //nolint:gosec // non-cryptographic jitter
	d = d - d/4 + jitter
	if max > 0 && d > max {
		d = max
	}
	return d
}

// parseRetryAfter accepts both delta-seconds and HTTP-date forms. Returns
// 0 if the header is missing or unparseable.
func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

