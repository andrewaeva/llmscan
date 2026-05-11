package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
)

// scriptedServer flips through a list of canned responses on each POST.
func scriptedServer(t *testing.T, responses []string, bodies *[][]byte) (*httptest.Server, *anthropicClient) {
	t.Helper()
	var hit int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(atomic.AddInt32(&hit, 1) - 1)
		if idx >= len(responses) {
			idx = len(responses) - 1
		}
		if bodies != nil {
			body, _ := io.ReadAll(r.Body)
			*bodies = append(*bodies, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(responses[idx]))
	}))
	t.Cleanup(srv.Close)
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("ANTHROPIC_API_KEY", "test")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c, err := newAnthropicClient(config.ModelSpec{
		Provider:    "anthropic",
		Model:       "claude-tool",
		Temperature: 0.1,
		MaxTokens:   500,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

func TestCompleteWithToolsLoop(t *testing.T) {
	// Round 1: model wants to call read_file and grep.
	round1 := `{
		"content": [
			{"type": "text", "text": "let me look"},
			{"type": "tool_use", "id": "call_1", "name": "read_file", "input": {"path": "a.go"}},
			{"type": "tool_use", "id": "call_2", "name": "grep", "input": {"pattern": "Exec"}}
		],
		"stop_reason": "tool_use",
		"usage": {"input_tokens": 10, "output_tokens": 5}
	}`
	// Round 2: final answer.
	round2 := `{
		"content": [{"type": "text", "text": "final verdict"}],
		"stop_reason": "end_turn",
		"usage": {"input_tokens": 8, "output_tokens": 4}
	}`

	var bodies [][]byte
	_, c := scriptedServer(t, []string{round1, round2}, &bodies)

	var handlerCalls int32
	handler := func(ctx context.Context, call ToolCall) ToolResult {
		atomic.AddInt32(&handlerCalls, 1)
		return ToolResult{ID: call.ID, Content: "tool output for " + call.Name}
	}
	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		System:   "sys",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Tools: []ToolDef{
			{Name: "read_file", Description: "read", InputSchema: map[string]any{"type": "object"}},
			{Name: "grep", Description: "grep", InputSchema: map[string]any{"type": "object"}},
		},
		Handler:  handler,
		MaxSteps: 5,
	})
	if err != nil {
		t.Fatalf("CompleteWithTools: %v", err)
	}
	if resp.FinalText != "final verdict" {
		t.Errorf("final text=%q", resp.FinalText)
	}
	if len(resp.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(resp.Steps))
	}
	if resp.Steps[0].Call.Name != "read_file" || resp.Steps[1].Call.Name != "grep" {
		t.Errorf("wrong step order: %+v", resp.Steps)
	}
	if handlerCalls != 2 {
		t.Errorf("handler called %d times", handlerCalls)
	}
	if resp.TokensIn != 18 || resp.TokensOut != 9 {
		t.Errorf("tokens: in=%d out=%d", resp.TokensIn, resp.TokensOut)
	}
	if resp.Provider != "anthropic" || resp.Model != "claude-tool" {
		t.Errorf("provider/model: %+v", resp)
	}

	// The 2nd request body must contain tool_result messages mirroring call ids.
	if len(bodies) < 2 {
		t.Fatalf("need 2 request bodies, got %d", len(bodies))
	}
	var req2 antToolRequest
	if err := json.Unmarshal(bodies[1], &req2); err != nil {
		t.Fatalf("req2 decode: %v", err)
	}
	// First message is the original user, second is the assistant, third must be tool_result user turn.
	if len(req2.Messages) < 3 {
		t.Fatalf("expected ≥3 messages in second request, got %d", len(req2.Messages))
	}
	last := req2.Messages[len(req2.Messages)-1]
	if last.Role != "user" {
		t.Errorf("last message role = %q", last.Role)
	}
	var sawCall1, sawCall2 bool
	for _, b := range last.Content {
		if b.Type != "tool_result" {
			continue
		}
		switch b.ToolUseID {
		case "call_1":
			sawCall1 = true
		case "call_2":
			sawCall2 = true
		}
		if !strings.Contains(b.Content, "tool output for ") {
			t.Errorf("unexpected tool_result content: %q", b.Content)
		}
	}
	if !sawCall1 || !sawCall2 {
		t.Errorf("tool_result ids not forwarded: call1=%v call2=%v", sawCall1, sawCall2)
	}
}

func TestCompleteWithToolsBudgetExhausted(t *testing.T) {
	// Always asks for a tool call → never ends naturally; should stop at MaxSteps.
	always := `{
		"content": [{"type": "tool_use", "id": "c1", "name": "read_file", "input": {}}],
		"stop_reason": "tool_use"
	}`
	_, c := scriptedServer(t, []string{always}, nil)
	var calls int32
	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "start"}},
		Tools:    []ToolDef{{Name: "read_file", InputSchema: map[string]any{}}},
		Handler: func(ctx context.Context, _ ToolCall) ToolResult {
			atomic.AddInt32(&calls, 1)
			return ToolResult{ID: "c1", Content: "out"}
		},
		MaxSteps: 3,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if int(calls) != 3 {
		t.Errorf("handler calls=%d want=3", calls)
	}
	if len(resp.Steps) != 3 {
		t.Errorf("steps=%d want=3", len(resp.Steps))
	}
	if resp.FinalText != "" {
		t.Errorf("should not have final text when budget exhausted, got %q", resp.FinalText)
	}
}

func TestCompleteWithToolsNilHandler(t *testing.T) {
	_, c := scriptedServer(t, []string{`{"content":[]}`}, nil)
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{})
	if err == nil || !strings.Contains(err.Error(), "nil tool handler") {
		t.Errorf("expected nil handler err, got %v", err)
	}
}

func TestCompleteWithToolsDefaultMaxSteps(t *testing.T) {
	// Returns end_turn immediately so we finish in one step regardless of budget.
	_, c := scriptedServer(t, []string{`{
		"content": [{"type":"text","text":"done"}],
		"stop_reason":"end_turn"
	}`}, nil)
	h := func(ctx context.Context, _ ToolCall) ToolResult { return ToolResult{} }
	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  h,
		// MaxSteps=0 → default 20 applied internally.
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.FinalText != "done" {
		t.Errorf("FinalText=%q", resp.FinalText)
	}
}

func TestCompleteWithToolsAPIError(t *testing.T) {
	_, c := scriptedServer(t, []string{`{"error":{"message":"nope"}}`}, nil)
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  func(ctx context.Context, _ ToolCall) ToolResult { return ToolResult{} },
		MaxSteps: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("expected API error, got %v", err)
	}
}

func TestCompleteWithToolsDecodeError(t *testing.T) {
	_, c := scriptedServer(t, []string{`not-json`}, nil)
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  func(ctx context.Context, _ ToolCall) ToolResult { return ToolResult{} },
		MaxSteps: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode error, got %v", err)
	}
}

func TestCompleteWithToolsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte("overloaded"))
	}))
	defer srv.Close()
	t.Setenv("ANTHROPIC_API_KEY", "k")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c, _ := newAnthropicClient(config.ModelSpec{Provider: "anthropic", Model: "m"})
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  func(ctx context.Context, _ ToolCall) ToolResult { return ToolResult{} },
		MaxSteps: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("expected 503 err: %v", err)
	}
}

func TestCompleteWithToolsSkipsSystemMessages(t *testing.T) {
	var bodies [][]byte
	_, c := scriptedServer(t, []string{`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`}, &bodies)
	h := func(ctx context.Context, _ ToolCall) ToolResult { return ToolResult{} }
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		System:   "sys",
		Messages: []Message{{Role: "system", Content: "SKIP ME"}, {Role: "user", Content: "go"}},
		Handler:  h,
		MaxSteps: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var req antToolRequest
	_ = json.Unmarshal(bodies[0], &req)
	if len(req.Messages) != 1 || req.Messages[0].Role != "user" {
		t.Errorf("system not stripped: %+v", req.Messages)
	}
}
