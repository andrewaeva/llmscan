package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExtractJSON(t *testing.T) {
	cases := map[string]string{
		`{"a":1}`:                                   `{"a":1}`,
		"```json\n{\"a\":1}\n```":                   `{"a":1}`,
		"```\n{\"x\":\"y\"}\n```":                   `{"x":"y"}`,
		"prefix text {\"a\":1} trailing":            `{"a":1}`,
		"  \n```json\n{\"k\":\"v\",\"n\":2}\n```\n": `{"k":"v","n":2}`,
		`no braces here`:                            `no braces here`,
		// Trailing content / double-encoded JSON / chatty epilogue — cut at
		// the matching brace, not at the last `}` in the buffer.
		`{"a":1} {"b":2}`:                              `{"a":1}`,
		`{"s":"} not a close"}`:                        `{"s":"} not a close"}`,
		`{"nested":{"x":1}} trailing prose`:            `{"nested":{"x":1}}`,
		`[1,2,3] trailing`:                             `[1,2,3]`,
	}
	for in, want := range cases {
		got := ExtractJSON(in)
		if got != want {
			t.Errorf("ExtractJSON(%q)=%q want %q", in, got, want)
		}
	}
}

// fakeClient lets us script Complete responses for CompleteJSON tests.
type fakeClient struct {
	responses []string
	errs      []error
	calls     int
}

func (f *fakeClient) Name() string { return "fake" }
func (f *fakeClient) Complete(_ context.Context, _ Request) (Response, error) {
	i := f.calls
	f.calls++
	if i < len(f.errs) && f.errs[i] != nil {
		return Response{}, f.errs[i]
	}
	if i >= len(f.responses) {
		return Response{Text: f.responses[len(f.responses)-1]}, nil
	}
	return Response{Text: f.responses[i]}, nil
}

func TestCompleteJSONHappyPath(t *testing.T) {
	c := &fakeClient{responses: []string{`{"ok":true}`}}
	resp, raw, err := CompleteJSON(context.Background(), c, Request{}, 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(raw) != `{"ok":true}` {
		t.Errorf("raw=%s", raw)
	}
	if resp.Text != `{"ok":true}` {
		t.Errorf("resp.Text=%s", resp.Text)
	}
	if c.calls != 1 {
		t.Errorf("expected 1 call, got %d", c.calls)
	}
}

func TestCompleteJSONRetryThenSuccess(t *testing.T) {
	c := &fakeClient{responses: []string{`not json at all`, `{"ok":1}`}}
	_, raw, err := CompleteJSON(context.Background(), c, Request{}, 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(raw) != `{"ok":1}` {
		t.Errorf("raw=%s", raw)
	}
	if c.calls != 2 {
		t.Errorf("expected 2 calls, got %d", c.calls)
	}
}

func TestCompleteJSONExhaustsRetries(t *testing.T) {
	c := &fakeClient{responses: []string{`nope`, `still nope`, `still nope`}}
	_, _, err := CompleteJSON(context.Background(), c, Request{}, 1)
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("unexpected err: %v", err)
	}
}

func TestCompleteJSONPropagatesError(t *testing.T) {
	want := errors.New("boom")
	c := &fakeClient{responses: []string{""}, errs: []error{want}}
	_, _, err := CompleteJSON(context.Background(), c, Request{}, 3)
	if !errors.Is(err, want) {
		t.Errorf("err=%v want=%v", err, want)
	}
}

func TestCompleteJSONForcesJSONFlag(t *testing.T) {
	var seen Request
	c := captureClient{onComplete: func(r Request) (Response, error) {
		seen = r
		return Response{Text: `{}`}, nil
	}}
	if _, _, err := CompleteJSON(context.Background(), &c, Request{}, 0); err != nil {
		t.Fatal(err)
	}
	if !seen.JSON {
		t.Error("JSON flag not propagated")
	}
}

type captureClient struct {
	onComplete func(Request) (Response, error)
}

func (c *captureClient) Name() string { return "capture" }
func (c *captureClient) Complete(_ context.Context, r Request) (Response, error) {
	return c.onComplete(r)
}

func BenchmarkExtractJSON(b *testing.B) {
	in := "```json\n{\"key\":\"value\",\"n\":42,\"arr\":[1,2,3]}\n```"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractJSON(in)
	}
}
