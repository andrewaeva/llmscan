package llm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeLogClient is a minimal Client used to drive Tag().
type fakeLogClient struct {
	resp Response
	err  error
}

func (f *fakeLogClient) Name() string { return "fake" }
func (f *fakeLogClient) Complete(_ context.Context, _ Request) (Response, error) {
	return f.resp, f.err
}

func TestTagWritesJSONLPerCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "calls.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	SetSink(sink)
	t.Cleanup(func() {
		SetSink(nil)
		_ = sink.Close()
	})

	inner := &fakeLogClient{resp: Response{
		Text:      "ok",
		Provider:  "openai",
		Model:     "gpt-5",
		TokensIn:  120,
		TokensOut: 17,
	}}
	c := Tag(inner, "scanner.injection")

	// One success.
	if _, err := c.Complete(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hi"}}}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	// One failure, with ctx override.
	inner.err = errors.New("rate limited")
	if _, err := c.Complete(WithStage(context.Background(), "scanner.injection-retry"), Request{}); err == nil {
		t.Fatalf("expected err")
	}

	// Flush + read back.
	_ = CloseSink()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	var entries []LogEntry
	for sc.Scan() {
		var e LogEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("decode %q: %v", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d (%v)", len(entries), entries)
	}
	if got := entries[0]; got.Stage != "scanner.injection" || got.TokensIn != 120 || got.TokensOut != 17 || !got.OK || got.Provider != "openai" || got.Model != "gpt-5" {
		t.Fatalf("entry[0] mismatch: %+v", got)
	}
	if got := entries[1]; got.Stage != "scanner.injection-retry" || got.OK || !strings.Contains(got.Err, "rate limited") {
		t.Fatalf("entry[1] mismatch: %+v", got)
	}
}

func TestTagNoSinkIsNoop(t *testing.T) {
	SetSink(nil) // explicit
	inner := &fakeLogClient{resp: Response{Text: "ok"}}
	c := Tag(inner, "x")
	if _, err := c.Complete(context.Background(), Request{}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	// nothing to assert; just verify no panic / file writes anywhere.
}
