package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// LogEntry is one JSONL line written by the LLM logger. One line per
// Complete call (success or failure). Stage carries the caller tag set via
// Tag() or WithStage(ctx,...).
type LogEntry struct {
	TS         string `json:"ts"`
	Stage      string `json:"stage"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	TokensIn   int    `json:"tokens_in"`
	TokensOut  int    `json:"tokens_out"`
	LatencyMS  int64  `json:"latency_ms"`
	OK         bool   `json:"ok"`
	Err        string `json:"error,omitempty"`
	JSONMode   bool   `json:"json_mode,omitempty"`
	MsgCount   int    `json:"msg_count,omitempty"`
}

// Sink is anywhere LogEntry rows go (typically a JSONL file).
type Sink interface {
	Write(LogEntry) error
	Close() error
}

// fileSink writes JSONL to a file under a mutex.
type fileSink struct {
	mu    sync.Mutex
	w     io.WriteCloser
	count atomic.Int64
}

func (s *fileSink) Write(e LogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return errors.New("llm log sink closed")
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := s.w.Write(b); err != nil {
		return err
	}
	s.count.Add(1)
	return nil
}

func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	err := s.w.Close()
	s.w = nil
	return err
}

// NewFileSink opens path for writing JSONL log entries (overwrites).
func NewFileSink(path string) (Sink, error) {
	fh, err := os.Create(path) //nolint:gosec // path is operator-supplied CLI flag
	if err != nil {
		return nil, err
	}
	return &fileSink{w: fh}, nil
}

var (
	globalSinkMu sync.RWMutex
	globalSink   Sink
)

// SetSink installs a process-wide Sink consulted by every wrapped Client.
// Passing nil disables logging. Safe to call before any llm.New().
func SetSink(s Sink) {
	globalSinkMu.Lock()
	defer globalSinkMu.Unlock()
	globalSink = s
}

// CloseSink closes the active sink (if any) and removes it.
func CloseSink() error {
	globalSinkMu.Lock()
	s := globalSink
	globalSink = nil
	globalSinkMu.Unlock()
	if s == nil {
		return nil
	}
	return s.Close()
}

func currentSink() Sink {
	globalSinkMu.RLock()
	defer globalSinkMu.RUnlock()
	return globalSink
}

type stageKey struct{}

// WithStage attaches a stage tag to ctx. Used when a single shared client
// (e.g. the deep tool-loop) services multiple logical stages.
func WithStage(ctx context.Context, tag string) context.Context {
	if tag == "" {
		return ctx
	}
	return context.WithValue(ctx, stageKey{}, tag)
}

// stageFromCtx returns the stage tag attached to ctx, or "" if none.
func stageFromCtx(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(stageKey{}).(string)
	return v
}

// loggingClient wraps a Client to emit one LogEntry per Complete call.
// Stage resolution: ctx override beats the client's static defaultTag.
type loggingClient struct {
	inner      Client
	defaultTag string
}

func (l *loggingClient) Name() string { return l.inner.Name() }

func (l *loggingClient) Complete(ctx context.Context, req Request) (Response, error) {
	sink := currentSink()
	if sink == nil {
		return l.inner.Complete(ctx, req)
	}
	stage := stageFromCtx(ctx)
	if stage == "" {
		stage = l.defaultTag
	}
	t0 := time.Now()
	resp, err := l.inner.Complete(ctx, req)
	entry := LogEntry{
		TS:        t0.UTC().Format(time.RFC3339Nano),
		Stage:     stage,
		Provider:  resp.Provider,
		Model:     resp.Model,
		TokensIn:  resp.TokensIn,
		TokensOut: resp.TokensOut,
		LatencyMS: time.Since(t0).Milliseconds(),
		OK:        err == nil,
		JSONMode:  req.JSON,
		MsgCount:  len(req.Messages),
	}
	if entry.Provider == "" {
		entry.Provider = l.inner.Name()
	}
	if err != nil {
		entry.Err = err.Error()
	}
	_ = sink.Write(entry) // never fail a real LLM call because logging broke
	return resp, err
}

// loggingToolClient is the ToolClient counterpart. We only wrap CompleteWithTools
// at the top level: the inner provider's own tool-loop iterations are summarized
// as one entry (matching how cost is billed: per top-level call, but token usage
// is the cumulative tool-loop usage already aggregated in Response by provider).
type loggingToolClient struct {
	loggingClient
	tools ToolClient
}

func (l *loggingToolClient) CompleteWithTools(ctx context.Context, req ToolRequest) (ToolResponse, error) {
	sink := currentSink()
	if sink == nil {
		return l.tools.CompleteWithTools(ctx, req)
	}
	stage := stageFromCtx(ctx)
	if stage == "" {
		stage = l.defaultTag
	}
	t0 := time.Now()
	resp, err := l.tools.CompleteWithTools(ctx, req)
	entry := LogEntry{
		TS:        t0.UTC().Format(time.RFC3339Nano),
		Stage:     stage,
		Provider:  resp.Provider,
		Model:     resp.Model,
		TokensIn:  resp.TokensIn,
		TokensOut: resp.TokensOut,
		LatencyMS: time.Since(t0).Milliseconds(),
		OK:        err == nil,
		MsgCount:  len(req.Messages),
	}
	if entry.Provider == "" {
		entry.Provider = l.inner.Name()
	}
	if err != nil {
		entry.Err = err.Error()
	}
	_ = sink.Write(entry)
	return resp, err
}

// Tag wraps c so every Complete it makes is logged under the given stage tag
// (unless the request context overrides it via WithStage). Safe to call with
// nil; returns nil unchanged. Also preserves ToolClient capability.
func Tag(c Client, tag string) Client {
	if c == nil {
		return nil
	}
	base := loggingClient{inner: c, defaultTag: tag}
	if tc, ok := c.(ToolClient); ok {
		return &loggingToolClient{loggingClient: base, tools: tc}
	}
	return &base
}
