// Package progress provides a Reporter abstraction for live scan progress.
//
// Three implementations are shipped:
//
//   - NoopReporter — silent, used when --progress=none.
//   - PlainReporter — line-oriented, used in non-TTY contexts (CI, pipes).
//     Each Stage/Done emits one timestamped line; safe to redirect to a log.
//   - TUIReporter — full-screen overwrite using ANSI escape codes. Spinner,
//     overall bar, per-stage state, total counters, ETA. ~80x10 chars.
//
// Mode auto-detection (NewAuto) picks TUI when stderr is a real terminal and
// the user hasn't forced CI/plain mode; otherwise falls back to PlainReporter.
// No third-party TUI dependencies — pure ANSI / pure Go.
//
// All Reporter methods are safe to call from multiple goroutines.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Reporter is the abstract progress sink. Use NewAuto in normal code.
type Reporter interface {
	// Stage signals the start of a high-level stage (discover/parse/scan/...).
	// `total` is the expected number of units (files, chunks, findings); pass
	// 0 if unknown.
	Stage(name string, total int)

	// Inc advances the *current* stage's counter by delta.
	Inc(name string, delta int)

	// SetTotal updates the expected total for an in-flight stage (e.g. after
	// a filter halved the file set).
	SetTotal(name string, total int)

	// Done marks a stage as finished and records its wall time.
	Done(name string)

	// Logf emits a one-off message that should appear above the progress
	// surface. Useful for warnings / non-stage events.
	Logf(format string, args ...any)

	// Stop tears down the reporter. Called once at the end of Run.
	Stop()
}

// Mode selects a Reporter implementation.
type Mode int

const (
	// ModeAuto picks TUI on TTY, Plain otherwise.
	ModeAuto Mode = iota
	// ModeTUI forces full-screen TUI (only valid if stderr is a TTY).
	ModeTUI
	// ModePlain forces line-oriented output.
	ModePlain
	// ModeNone silences progress entirely.
	ModeNone
)

// ParseMode parses the --progress flag value.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return ModeAuto, nil
	case "tty", "tui":
		return ModeTUI, nil
	case "plain":
		return ModePlain, nil
	case "none", "off", "false":
		return ModeNone, nil
	}
	return ModeAuto, fmt.Errorf("unknown progress mode %q (want auto|tty|plain|none)", s)
}

// NewAuto returns a Reporter chosen for the given mode and output writer.
// `isTTY` should be `term.IsTerminal(int(w.(*os.File).Fd()))` or equivalent.
func NewAuto(mode Mode, w io.Writer, isTTY bool) Reporter {
	switch mode {
	case ModeNone:
		return &NoopReporter{}
	case ModePlain:
		return NewPlain(w)
	case ModeTUI:
		return NewTUI(w)
	}
	if isTTY {
		return NewTUI(w)
	}
	return NewPlain(w)
}

// ---------- NoopReporter ----------

// NoopReporter discards all events.
type NoopReporter struct{}

func (*NoopReporter) Stage(string, int)    {}
func (*NoopReporter) Inc(string, int)      {}
func (*NoopReporter) SetTotal(string, int) {}
func (*NoopReporter) Done(string)          {}
func (*NoopReporter) Logf(string, ...any)  {}
func (*NoopReporter) Stop()                {}

// ---------- Stage record (shared by Plain and TUI) ----------

type stageState struct {
	name    string
	total   int
	done    int
	started time.Time
	ended   time.Time
	active  bool
}

// ---------- PlainReporter ----------

// PlainReporter writes one line per significant event. Safe in CI / pipes.
type PlainReporter struct {
	mu     sync.Mutex
	w      io.Writer
	stages map[string]*stageState
}

// NewPlain builds a PlainReporter.
func NewPlain(w io.Writer) *PlainReporter {
	return &PlainReporter{w: w, stages: map[string]*stageState{}}
}

// Stage begins a new stage and prints a "▶ stage" header.
func (p *PlainReporter) Stage(name string, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := &stageState{name: name, total: total, started: time.Now(), active: true}
	p.stages[name] = s
	if total > 0 {
		fmt.Fprintf(p.w, "[%s] %s: start (total=%d)\n", time.Now().Format("15:04:05"), name, total)
	} else {
		fmt.Fprintf(p.w, "[%s] %s: start\n", time.Now().Format("15:04:05"), name)
	}
}

// Inc increments a stage counter (no per-tick output to avoid log spam).
func (p *PlainReporter) Inc(name string, delta int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.stages[name]; ok {
		s.done += delta
	}
}

// SetTotal updates the expected total.
func (p *PlainReporter) SetTotal(name string, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.stages[name]; ok {
		s.total = total
	}
}

// Done prints "✓ stage done=N total=M in DURATION".
func (p *PlainReporter) Done(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.stages[name]
	if !ok {
		return
	}
	s.ended = time.Now()
	s.active = false
	dur := s.ended.Sub(s.started).Round(time.Millisecond)
	if s.total > 0 {
		fmt.Fprintf(p.w, "[%s] %s: done %d/%d in %s\n",
			time.Now().Format("15:04:05"), name, s.done, s.total, dur)
	} else {
		fmt.Fprintf(p.w, "[%s] %s: done in %s\n",
			time.Now().Format("15:04:05"), name, dur)
	}
}

// Logf prints an inline message.
func (p *PlainReporter) Logf(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// Stop is a no-op for PlainReporter.
func (p *PlainReporter) Stop() {}

// ---------- TUIReporter ----------

const (
	tuiTickInterval = 100 * time.Millisecond
	tuiBarWidth     = 28
)

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// TUIReporter renders a full-screen progress surface using ANSI escape codes.
// Repaints every 100ms; the rendered region is exactly `lastLines` tall so
// repaints overwrite cleanly without scrolling the terminal.
type TUIReporter struct {
	mu sync.Mutex
	w  io.Writer

	stages    []*stageState
	stagesIdx map[string]int
	logs      []string // bounded buffer of one-off messages
	tick      int
	started   time.Time

	stop      chan struct{}
	stopped   bool
	wg        sync.WaitGroup
	lastLines int
}

// NewTUI builds a TUIReporter and starts its render loop.
func NewTUI(w io.Writer) *TUIReporter {
	t := &TUIReporter{
		w:         w,
		stagesIdx: map[string]int{},
		started:   time.Now(),
		stop:      make(chan struct{}),
	}
	t.wg.Add(1)
	go t.loop()
	return t
}

// Stage begins a new stage; appended to the visible list.
func (t *TUIReporter) Stage(name string, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx, ok := t.stagesIdx[name]; ok {
		// Re-starting an existing stage — reset its counters.
		s := t.stages[idx]
		s.total = total
		s.done = 0
		s.started = time.Now()
		s.active = true
		return
	}
	s := &stageState{name: name, total: total, started: time.Now(), active: true}
	t.stagesIdx[name] = len(t.stages)
	t.stages = append(t.stages, s)
}

// Inc advances a stage counter.
func (t *TUIReporter) Inc(name string, delta int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx, ok := t.stagesIdx[name]; ok {
		t.stages[idx].done += delta
	}
}

// SetTotal updates an in-flight expected total.
func (t *TUIReporter) SetTotal(name string, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx, ok := t.stagesIdx[name]; ok {
		t.stages[idx].total = total
	}
}

// Done marks a stage finished.
func (t *TUIReporter) Done(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if idx, ok := t.stagesIdx[name]; ok {
		s := t.stages[idx]
		s.ended = time.Now()
		s.active = false
	}
}

// Logf appends a short message to the visible log buffer (last 5 kept).
func (t *TUIReporter) Logf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	t.logs = append(t.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
	if len(t.logs) > 5 {
		t.logs = t.logs[len(t.logs)-5:]
	}
}

// Writer returns an io.Writer that callers should use for any out-of-band
// writes to the same stream the TUI paints on (typically os.Stderr). The
// writer first clears the painted frame, performs the write, then resets the
// re-paint counter so the next render starts on a fresh row instead of
// emitting cursor-up sequences that would land in the middle of the foreign
// text. Without this coordination, a stray log.Printf between two ticks makes
// the TUI's `\x1b[1A\x1b[2K` rise into the log line and leave the old frame
// header stranded above — the source of duplicate `┌─ llmscan · …` lines.
func (t *TUIReporter) Writer() io.Writer {
	return &tuiSyncWriter{t: t}
}

type tuiSyncWriter struct {
	t *TUIReporter
}

func (s *tuiSyncWriter) Write(p []byte) (int, error) {
	s.t.mu.Lock()
	defer s.t.mu.Unlock()
	s.t.clearFrame()
	n, err := s.t.w.Write(p)
	// After foreign output, the next render must repaint from scratch — the
	// terminal has scrolled and our previous-frame line count no longer maps
	// to any real on-screen geometry.
	s.t.lastLines = 0
	return n, err
}

// Stop tears down the render loop and erases the rendered region entirely.
// No "final frame" is painted: this keeps stdout clean for any text the
// caller prints next (e.g. the final report) and prevents the last TUI frame
// from overwriting that output via residual cursor-up sequences.
func (t *TUIReporter) Stop() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	t.mu.Unlock()
	close(t.stop)
	t.wg.Wait()
	t.mu.Lock()
	t.clearFrame()
	t.mu.Unlock()
}

// clearFrame erases the previously rendered region by emitting `lastLines`
// cursor-up + erase-line pairs. After this call the cursor sits at the
// column it was at before the first render — i.e. wherever subsequent output
// would naturally start. Called with the lock held.
func (t *TUIReporter) clearFrame() {
	if t.lastLines <= 0 {
		return
	}
	var b strings.Builder
	for i := 0; i < t.lastLines; i++ {
		b.WriteString("\x1b[1A\x1b[2K") // cursor up + erase line
	}
	fmt.Fprint(t.w, b.String())
	t.lastLines = 0
}

func (t *TUIReporter) loop() {
	defer t.wg.Done()
	tk := time.NewTicker(tuiTickInterval)
	defer tk.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tk.C:
			t.mu.Lock()
			t.tick++
			t.render()
			t.mu.Unlock()
		}
	}
}

// render paints the current state. Called with the lock held.
//
// Layout (heights are predictable so we can clear the previous frame by
// emitting `lastLines` "cursor up + erase line" pairs before the next paint):
//
//	┌─ llmscan · 0:12 ──────────────────────────────┐
//	  spinner overall:  [████████░░░░░░░░] 47%  files  142/300
//	  • discover         done   300 files       0.3s
//	  • parse-ast        ▶      217/300         1.8s
//	  • scanners         ▶       42/300        14.1s
//	  log: …
func (t *TUIReporter) render() {
	// Build into a buffer first to count lines exactly.
	var b strings.Builder
	elapsed := time.Since(t.started).Round(time.Second)
	spin := spinnerFrames[t.tick%len(spinnerFrames)]

	// Header.
	fmt.Fprintf(&b, "\x1b[36m┌─ llmscan · %s ─\x1b[0m\n", fmtDur(elapsed))

	// Overall progress = sum of all stage totals / sum of done. Fall back to
	// stage count if no totals declared.
	var totSum, doneSum int
	for _, s := range t.stages {
		totSum += s.total
		doneSum += s.done
	}
	var bar string
	pct := 0
	if totSum > 0 {
		pct = doneSum * 100 / totSum
		if pct > 100 {
			pct = 100
		}
	}
	bar = renderBar(pct, tuiBarWidth)
	fmt.Fprintf(&b, "  \x1b[33m%c\x1b[0m %s \x1b[2m%3d%%\x1b[0m  units: %d/%d\n",
		spin, bar, pct, doneSum, totSum)

	// Per-stage rows.
	for _, s := range t.stages {
		marker := "·"
		color := "\x1b[2m" // dim
		switch {
		case s.active:
			marker = "▶"
			color = "\x1b[36m" // cyan
		case !s.ended.IsZero():
			marker = "✓"
			color = "\x1b[32m" // green
		}
		var counter string
		switch {
		case s.total > 0:
			counter = fmt.Sprintf("%d/%d", s.done, s.total)
		case s.done > 0:
			counter = fmt.Sprintf("%d", s.done)
		default:
			counter = ""
		}
		var dur time.Duration
		if !s.ended.IsZero() {
			dur = s.ended.Sub(s.started)
		} else {
			dur = time.Since(s.started)
		}
		fmt.Fprintf(&b, "  %s%s\x1b[0m %-18s %12s  \x1b[2m%6s\x1b[0m\n",
			color, marker, s.name, counter, fmtDur(dur.Round(100*time.Millisecond)))
	}

	// Recent logs.
	for _, l := range t.logs {
		// Truncate to a reasonable width to keep the frame stable.
		if len(l) > 120 {
			l = l[:117] + "..."
		}
		fmt.Fprintf(&b, "  \x1b[2m· %s\x1b[0m\n", l)
	}

	// Clear previous frame.
	out := b.String()
	if t.lastLines > 0 {
		var clr strings.Builder
		for i := 0; i < t.lastLines; i++ {
			clr.WriteString("\x1b[1A\x1b[2K") // cursor up + erase line
		}
		fmt.Fprint(t.w, clr.String())
	}
	fmt.Fprint(t.w, out)
	t.lastLines = strings.Count(out, "\n")
}

func renderBar(pct, width int) string {
	if width <= 0 {
		return ""
	}
	filled := pct * width / 100
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return "\x1b[32m" + strings.Repeat("█", filled) + "\x1b[2m" + strings.Repeat("░", width-filled) + "\x1b[0m"
}

func fmtDur(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	return fmt.Sprintf("%d:%02d", m, s)
}

// IsTerminal is a tiny wrapper around os.File.Fd() + isatty-free TTY check.
// It avoids pulling go-isatty into our direct deps; we already detect TTY in
// internal/report so we re-use the same approach: stat + ModeCharDevice.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}
