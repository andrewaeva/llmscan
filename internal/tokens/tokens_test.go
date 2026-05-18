package tokens

import (
	"strings"
	"testing"
)

func TestEstimate_EmptyAndShort(t *testing.T) {
	if got := Estimate(""); got != 0 {
		t.Errorf("empty -> %d, want 0", got)
	}
	if got := Estimate("abc"); got <= 0 || got > 3 {
		t.Errorf("short -> %d, want 1-3", got)
	}
}

func TestEstimate_Monotonic(t *testing.T) {
	a := Estimate("hello world")
	b := Estimate(strings.Repeat("hello world ", 100))
	if b <= a {
		t.Errorf("longer string should produce more tokens; got a=%d b=%d", a, b)
	}
}

func TestEstimate_ApproxRange(t *testing.T) {
	// Synthetic Go-like code: 1000 bytes should be ~250-350 tokens.
	const sample = `func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if name == "" {
        http.Error(w, "missing name", http.StatusBadRequest)
        return
    }
    fmt.Fprintf(w, "hello, %s", name)
}
`
	// Make ~1KB by repeating.
	big := strings.Repeat(sample, 1000/len(sample)+1)[:1000]
	n := Estimate(big)
	if n < 150 || n > 500 {
		t.Errorf("approx tokens for 1KB Go = %d, expected 150-500", n)
	}
}

func TestSetCounter(t *testing.T) {
	defer SetCounter(nil)
	SetCounter(func(s string) int { return len(s) }) // 1 token = 1 byte
	if got := Estimate("hello"); got != 5 {
		t.Errorf("custom counter not applied: got %d, want 5", got)
	}
	SetCounter(nil) // restore
	def := Estimate("hello")
	if def == 5 {
		t.Errorf("counter not restored")
	}
}

func TestCountLines(t *testing.T) {
	cases := map[string]int{
		"":          0,
		"one":       1,
		"one\ntwo":  2,
		"a\nb\nc\n": 4, // trailing newline = empty 4th line in split, but Count returns 3 + 1
		"\n\n":      3,
	}
	for in, want := range cases {
		if got := CountLines(in); got != want {
			t.Errorf("CountLines(%q)=%d, want %d", in, got, want)
		}
	}
}

func TestEstimate_ConcurrentSafe(t *testing.T) {
	// Smoke test: many goroutines hammering Estimate must not race.
	done := make(chan struct{})
	for i := 0; i < 32; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = Estimate("some code with various tokens 123")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 32; i++ {
		<-done
	}
}
