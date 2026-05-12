package progress

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"", ModeAuto, false},
		{"auto", ModeAuto, false},
		{"AUTO", ModeAuto, false},
		{"tty", ModeTUI, false},
		{"tui", ModeTUI, false},
		{"plain", ModePlain, false},
		{"none", ModeNone, false},
		{"off", ModeNone, false},
		{"false", ModeNone, false},
		{"  plain  ", ModePlain, false},
		{"garbage", ModeAuto, true},
		{"verbose", ModeAuto, true},
	}
	for _, c := range cases {
		got, err := ParseMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseMode(%q): expected error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMode(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseMode(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNoopReporter(t *testing.T) {
	// All methods must be safe on a zero-value NoopReporter, and they must
	// not panic when called in any order.
	var r Reporter = &NoopReporter{}
	r.Stage("x", 10)
	r.Inc("x", 1)
	r.SetTotal("x", 20)
	r.Logf("hello %d", 1)
	r.Done("x")
	r.Stop()
}

func TestNewAuto_RoutesByMode(t *testing.T) {
	var buf bytes.Buffer
	if _, ok := NewAuto(ModeNone, &buf, true).(*NoopReporter); !ok {
		t.Errorf("ModeNone: want NoopReporter")
	}
	if _, ok := NewAuto(ModePlain, &buf, true).(*PlainReporter); !ok {
		t.Errorf("ModePlain: want PlainReporter")
	}
	tui, ok := NewAuto(ModeTUI, &buf, false).(*TUIReporter)
	if !ok {
		t.Fatalf("ModeTUI: want TUIReporter")
	}
	tui.Stop()
	// ModeAuto + isTTY=false → Plain.
	if _, ok := NewAuto(ModeAuto, &buf, false).(*PlainReporter); !ok {
		t.Errorf("ModeAuto+nonTTY: want PlainReporter")
	}
	// ModeAuto + isTTY=true → TUI.
	tui2, ok := NewAuto(ModeAuto, &buf, true).(*TUIReporter)
	if !ok {
		t.Fatalf("ModeAuto+TTY: want TUIReporter")
	}
	tui2.Stop()
}

func TestPlainReporter_StagesAndDone(t *testing.T) {
	var buf bytes.Buffer
	p := NewPlain(&buf)
	p.Stage("discover", 10)
	for i := 0; i < 10; i++ {
		p.Inc("discover", 1)
	}
	p.Done("discover")
	p.Stop()

	out := buf.String()
	if !strings.Contains(out, "discover: start (total=10)") {
		t.Errorf("missing start line; got:\n%s", out)
	}
	if !strings.Contains(out, "discover: done 10/10 in ") {
		t.Errorf("missing done line; got:\n%s", out)
	}
}

func TestPlainReporter_NoTotal(t *testing.T) {
	var buf bytes.Buffer
	p := NewPlain(&buf)
	p.Stage("orchestrator", 0)
	p.Done("orchestrator")
	out := buf.String()
	if !strings.Contains(out, "orchestrator: start\n") {
		t.Errorf("expected start without total; got:\n%s", out)
	}
	if !strings.Contains(out, "orchestrator: done in ") {
		t.Errorf("expected done without counters; got:\n%s", out)
	}
}

func TestPlainReporter_SetTotalAndLogf(t *testing.T) {
	var buf bytes.Buffer
	p := NewPlain(&buf)
	p.Stage("scanners", 0)
	p.SetTotal("scanners", 50)
	p.Inc("scanners", 5)
	p.Done("scanners")
	p.Logf("warning: %s", "rate limit")
	out := buf.String()
	if !strings.Contains(out, "scanners: done 5/50 in ") {
		t.Errorf("SetTotal didn't update; got:\n%s", out)
	}
	if !strings.Contains(out, "warning: rate limit") {
		t.Errorf("Logf missing; got:\n%s", out)
	}
}

func TestPlainReporter_DoneUnknown(t *testing.T) {
	var buf bytes.Buffer
	p := NewPlain(&buf)
	p.Done("never-started") // must be a no-op, not a panic
	if buf.Len() != 0 {
		t.Errorf("Done(unknown) should not write; got %q", buf.String())
	}
}

func TestTUIReporter_Lifecycle(t *testing.T) {
	var buf bytes.Buffer
	tui := NewTUI(&buf)
	tui.Stage("discover", 10)
	for i := 0; i < 10; i++ {
		tui.Inc("discover", 1)
	}
	tui.Done("discover")
	tui.Stage("scanners", 4)
	tui.Inc("scanners", 2)
	tui.Logf("hello from scanner")
	// Let the loop paint at least once.
	time.Sleep(150 * time.Millisecond)
	tui.Done("scanners")
	tui.Stop()

	out := buf.String()
	if !strings.Contains(out, "llmscan") {
		t.Errorf("expected header; got %q", out)
	}
	if !strings.Contains(out, "discover") {
		t.Errorf("expected discover stage in output")
	}
	if !strings.Contains(out, "scanners") {
		t.Errorf("expected scanners stage in output")
	}
	// After Stop() the rendered region must be cleared so the caller can print
	// the final report on a clean slate. We require the output to end with the
	// erase-line sequence (cursor-up + erase-line emitted once per painted row).
	if !strings.HasSuffix(out, "\x1b[1A\x1b[2K") {
		t.Errorf("expected output to end with cursor-up+erase-line sequences after Stop(); last 40 bytes=%q", lastN(out, 40))
	}
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func TestTUIReporter_StopClearsFrame(t *testing.T) {
	// Drives the explicit clear-on-Stop contract: after Stop, the previously
	// painted lines must be erased so a subsequent printer (the report writer)
	// starts on a blank line.
	var buf bytes.Buffer
	tui := NewTUI(&buf)
	tui.Stage("phase", 4)
	tui.Inc("phase", 2)
	// Let one render frame land.
	time.Sleep(150 * time.Millisecond)
	tui.Stop()

	out := buf.String()
	if !strings.Contains(out, "\x1b[1A\x1b[2K") {
		t.Errorf("expected clear sequence in output; got %q", out)
	}
	// No "done in" footer — Stop must not paint a final frame.
	if strings.Contains(out, "done in ") {
		t.Errorf("Stop() must not paint a final frame; got %q", out)
	}
}

func TestTUIReporter_StopIdempotent(t *testing.T) {
	tui := NewTUI(&bytes.Buffer{})
	tui.Stop()
	// Second Stop must not panic or deadlock.
	tui.Stop()
}

func TestTUIReporter_RestartStage(t *testing.T) {
	tui := NewTUI(&bytes.Buffer{})
	tui.Stage("phase", 5)
	tui.Inc("phase", 5)
	tui.Done("phase")
	// Re-start same stage: counters must reset.
	tui.Stage("phase", 3)
	tui.Inc("phase", 1)
	tui.mu.Lock()
	s := tui.stages[tui.stagesIdx["phase"]]
	if s.total != 3 || s.done != 1 || !s.active {
		t.Errorf("restart: got total=%d done=%d active=%v; want total=3 done=1 active=true",
			s.total, s.done, s.active)
	}
	tui.mu.Unlock()
	tui.Stop()
}

func TestTUIReporter_Concurrent(t *testing.T) {
	// Must be safe under concurrent goroutines (scanner DAG runs in parallel).
	tui := NewTUI(&bytes.Buffer{})
	tui.Stage("scanners", 1000)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tui.Inc("scanners", 1)
			}
		}()
	}
	wg.Wait()
	tui.Done("scanners")
	tui.Stop()
}

func TestTUIReporter_LogBufferBounded(t *testing.T) {
	tui := NewTUI(&bytes.Buffer{})
	for i := 0; i < 100; i++ {
		tui.Logf("msg %d", i)
	}
	tui.mu.Lock()
	n := len(tui.logs)
	tui.mu.Unlock()
	if n > 5 {
		t.Errorf("log buffer not bounded: got %d entries, want <=5", n)
	}
	tui.Stop()
}

func TestRenderBar(t *testing.T) {
	cases := []struct {
		pct, width int
	}{
		{0, 10},
		{50, 10},
		{100, 10},
		{120, 10}, // clamp
		{-5, 10},  // clamp
		{50, 0},
	}
	for _, c := range cases {
		s := renderBar(c.pct, c.width)
		// Should never panic; for width=0 should be empty.
		if c.width == 0 && s != "" {
			t.Errorf("renderBar(%d,0) = %q, want empty", c.pct, s)
		}
	}
}

func TestFmtDur(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{500 * time.Millisecond, "500ms"},
		{1500 * time.Millisecond, "1.5s"},
		{90 * time.Second, "1:30"},
		{3*time.Minute + 7*time.Second, "3:07"},
	}
	for _, c := range cases {
		if got := fmtDur(c.in); got != c.want {
			t.Errorf("fmtDur(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsTerminal_PipeFalse(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(w) {
		t.Errorf("pipe writer reported as terminal")
	}
	if IsTerminal(&bytes.Buffer{}) {
		t.Errorf("bytes.Buffer reported as terminal")
	}
}
