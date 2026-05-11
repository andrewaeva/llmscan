package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
)

// openAIScript is a tiny test harness: each POST returns the next canned
// response, optionally indexed by path so we can mix /responses and
// /chat/completions on the same server.
type openAIScript struct {
	byPath map[string][]string
	hits   map[string]int
	bodies map[string][][]byte
}

func newOpenAIScript() *openAIScript {
	return &openAIScript{
		byPath: map[string][]string{},
		hits:   map[string]int{},
		bodies: map[string][][]byte{},
	}
}

func (s *openAIScript) queue(path string, responses ...string) {
	s.byPath[path] = append(s.byPath[path], responses...)
}

func (s *openAIScript) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		body, _ := io.ReadAll(r.Body)
		s.bodies[path] = append(s.bodies[path], body)
		queue := s.byPath[path]
		idx := s.hits[path]
		s.hits[path] = idx + 1
		if idx >= len(queue) {
			http.Error(w, "no scripted response for "+path, 599)
			return
		}
		raw := queue[idx]
		// A response can be prefixed with "STATUS=NNN|" to override status.
		status := 200
		if strings.HasPrefix(raw, "STATUS=") {
			parts := strings.SplitN(raw, "|", 2)
			if len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimPrefix(parts[0], "STATUS=")); err == nil {
					status = n
				}
				raw = parts[1]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(raw))
	})
}

// newOpenAIToolClient wires the test server to an openAIClient pointed at
// `model` (gpt-5 family selects Responses API; others go to Chat Completions).
func newOpenAIToolClient(t *testing.T, srv *httptest.Server, model string) *openAIClient {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "test")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	c, err := newOpenAIClient(config.ModelSpec{
		Provider:    "openai",
		Model:       model,
		Temperature: 0.2,
		MaxTokens:   500,
	}, "openai")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ---------------- Responses API ----------------

func TestOpenAIToolsResponsesAPILoop(t *testing.T) {
	script := newOpenAIScript()
	// Round 1: GPT-5 asks for one tool call via /responses.
	script.queue("/responses",
		`{
			"output": [
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "let me look"}]},
				{"type": "function_call", "call_id": "fc_1", "name": "read_file", "arguments": "{\"path\":\"a.go\"}"}
			],
			"usage": {"input_tokens": 9, "output_tokens": 3}
		}`,
		// Round 2: final.
		`{
			"output": [
				{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "all done"}]}
			],
			"usage": {"input_tokens": 5, "output_tokens": 2}
		}`,
	)
	srv := httptest.NewServer(script.handler(t))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-5.5")

	var handlerCalls int32
	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		System:   "sys",
		Messages: []Message{{Role: "user", Content: "verify"}},
		Tools: []ToolDef{{
			Name: "read_file", Description: "read", InputSchema: map[string]any{"type": "object"},
		}},
		Handler: func(ctx context.Context, call ToolCall) ToolResult {
			atomic.AddInt32(&handlerCalls, 1)
			if call.Name != "read_file" || call.ID != "fc_1" {
				t.Errorf("unexpected call: %+v", call)
			}
			return ToolResult{ID: call.ID, Content: "line1\nline2\n"}
		},
		MaxSteps: 5,
	})
	if err != nil {
		t.Fatalf("CompleteWithTools: %v", err)
	}
	if resp.FinalText != "all done" {
		t.Errorf("final text=%q", resp.FinalText)
	}
	if len(resp.Steps) != 1 || resp.Steps[0].Call.Name != "read_file" {
		t.Errorf("steps=%+v", resp.Steps)
	}
	if handlerCalls != 1 {
		t.Errorf("handler calls=%d", handlerCalls)
	}
	if resp.TokensIn != 14 || resp.TokensOut != 5 {
		t.Errorf("tokens: in=%d out=%d", resp.TokensIn, resp.TokensOut)
	}
	if resp.Provider != "openai" || resp.Model != "gpt-5.5" {
		t.Errorf("provider/model: %+v", resp)
	}

	// Second request body must carry function_call + function_call_output
	// items, plus the original user message.
	if len(script.bodies["/responses"]) < 2 {
		t.Fatalf("expected ≥2 /responses bodies, got %d", len(script.bodies["/responses"]))
	}
	var req2 oaResponsesRequest
	if err := json.Unmarshal(script.bodies["/responses"][1], &req2); err != nil {
		t.Fatalf("decode req2: %v", err)
	}
	if req2.Instructions != "sys" {
		t.Errorf("instructions=%q", req2.Instructions)
	}
	var sawCall, sawOut bool
	for _, item := range req2.Input {
		switch item.Type {
		case "function_call":
			if item.CallID == "fc_1" && item.Name == "read_file" {
				sawCall = true
			}
		case "function_call_output":
			if item.CallID == "fc_1" && strings.Contains(item.Output, "line1") {
				sawOut = true
			}
		}
	}
	if !sawCall || !sawOut {
		t.Errorf("missing call/output replay: call=%v out=%v body=%s",
			sawCall, sawOut, script.bodies["/responses"][1])
	}
}

// ---------------- Chat Completions (legacy model) ----------------

func TestOpenAIToolsChatCompletionsLoop(t *testing.T) {
	script := newOpenAIScript()
	script.queue("/chat/completions",
		`{
			"choices": [{
				"message": {
					"role": "assistant",
					"content": null,
					"tool_calls": [
						{"id": "call_a", "type": "function",
						 "function": {"name": "grep", "arguments": "{\"pattern\":\"Exec\"}"}}
					]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 8, "completion_tokens": 4}
		}`,
		`{
			"choices": [{"message": {"role": "assistant", "content": "found it"}, "finish_reason": "stop"}],
			"usage": {"prompt_tokens": 6, "completion_tokens": 3}
		}`,
	)
	srv := httptest.NewServer(script.handler(t))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-4o-mini")

	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		System:   "you are a verifier",
		Messages: []Message{{Role: "user", Content: "go"}},
		Tools: []ToolDef{{
			Name: "grep", InputSchema: map[string]any{"type": "object"},
		}},
		Handler: func(ctx context.Context, call ToolCall) ToolResult {
			return ToolResult{ID: call.ID, Content: "match at a.go:12"}
		},
		MaxSteps: 5,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.FinalText != "found it" {
		t.Errorf("final=%q", resp.FinalText)
	}
	if len(resp.Steps) != 1 || resp.Steps[0].Call.Name != "grep" {
		t.Errorf("steps=%+v", resp.Steps)
	}

	// Round-2 body must include role:"tool" message with tool_call_id.
	if len(script.bodies["/chat/completions"]) < 2 {
		t.Fatalf("expected ≥2 chat bodies, got %d", len(script.bodies["/chat/completions"]))
	}
	var req2 oaChatToolRequest
	if err := json.Unmarshal(script.bodies["/chat/completions"][1], &req2); err != nil {
		t.Fatalf("decode req2: %v", err)
	}
	if req2.Model != "gpt-4o-mini" {
		t.Errorf("model=%q", req2.Model)
	}
	if req2.MaxTokens != 500 || req2.MaxCompletionTokens != 0 {
		t.Errorf("legacy model must use max_tokens; got max=%d mct=%d",
			req2.MaxTokens, req2.MaxCompletionTokens)
	}
	if req2.Temperature == nil {
		t.Error("legacy model must send temperature")
	}
	last := req2.Messages[len(req2.Messages)-1]
	if last.Role != "tool" || last.ToolCallID != "call_a" || !strings.Contains(last.Content, "match at") {
		t.Errorf("tool result message wrong: %+v", last)
	}
}

// ---------------- Auto-fallback /responses 404 → /chat/completions ----------------

func TestOpenAIToolsResponses404FallsBack(t *testing.T) {
	script := newOpenAIScript()
	script.queue("/responses", "STATUS=404|{\"error\":{\"message\":\"unknown route\"}}")
	// Chat Completions handles the same first round (with tool call) plus the final answer.
	script.queue("/chat/completions",
		`{
			"choices": [{
				"message": {
					"role": "assistant",
					"tool_calls": [{"id":"c1","type":"function",
					                "function":{"name":"read_file","arguments":"{}"}}]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 4, "completion_tokens": 2}
		}`,
		`{
			"choices": [{"message": {"role":"assistant","content":"final"}, "finish_reason":"stop"}],
			"usage": {"prompt_tokens": 3, "completion_tokens": 1}
		}`,
	)
	srv := httptest.NewServer(script.handler(t))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-5.5") // would normally use Responses

	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Tools:    []ToolDef{{Name: "read_file", InputSchema: map[string]any{"type": "object"}}},
		Handler:  func(ctx context.Context, c ToolCall) ToolResult { return ToolResult{ID: c.ID, Content: "ok"} },
		MaxSteps: 5,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.FinalText != "final" {
		t.Errorf("final=%q", resp.FinalText)
	}
	if len(resp.Steps) != 1 {
		t.Errorf("expected 1 step after fallback, got %d", len(resp.Steps))
	}
	// One probe to /responses (404), then chat-completions for the rest.
	if script.hits["/responses"] != 1 {
		t.Errorf("/responses hits = %d (want 1 probe)", script.hits["/responses"])
	}
	if script.hits["/chat/completions"] != 2 {
		t.Errorf("/chat/completions hits = %d (want 2)", script.hits["/chat/completions"])
	}
}

// ---------------- Multi-turn tool loop on Chat ----------------

func TestOpenAIToolsChatMultiTurn(t *testing.T) {
	script := newOpenAIScript()
	// Three rounds: tool → tool → final.
	script.queue("/chat/completions",
		`{
			"choices": [{
				"message": {"role":"assistant","tool_calls":[
				   {"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.go\"}"}}]},
				"finish_reason":"tool_calls"
			}],
			"usage": {"prompt_tokens": 5, "completion_tokens": 2}
		}`,
		`{
			"choices": [{
				"message": {"role":"assistant","tool_calls":[
				   {"id":"c2","type":"function","function":{"name":"grep","arguments":"{\"pattern\":\"x\"}"}}]},
				"finish_reason":"tool_calls"
			}],
			"usage": {"prompt_tokens": 4, "completion_tokens": 2}
		}`,
		`{
			"choices": [{"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],
			"usage": {"prompt_tokens": 3, "completion_tokens": 1}
		}`,
	)
	srv := httptest.NewServer(script.handler(t))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-4o")

	resp, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "go"}},
		Tools: []ToolDef{
			{Name: "read_file", InputSchema: map[string]any{"type": "object"}},
			{Name: "grep", InputSchema: map[string]any{"type": "object"}},
		},
		Handler: func(ctx context.Context, call ToolCall) ToolResult {
			return ToolResult{ID: call.ID, Content: "out:" + call.Name}
		},
		MaxSteps: 5,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.FinalText != "done" {
		t.Errorf("final=%q", resp.FinalText)
	}
	if len(resp.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(resp.Steps))
	}
	if resp.Steps[0].Call.Name != "read_file" || resp.Steps[1].Call.Name != "grep" {
		t.Errorf("step order: %+v", resp.Steps)
	}
}

// ---------------- Error propagation ----------------

func TestOpenAIToolsChatHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream gone"}}`))
	}))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-4o-mini")
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  func(ctx context.Context, c ToolCall) ToolResult { return ToolResult{} },
		MaxSteps: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "upstream gone") {
		t.Errorf("expected detailed 500, got %v", err)
	}
}

func TestOpenAIToolsResponsesAPIErrorPropagates(t *testing.T) {
	script := newOpenAIScript()
	script.queue("/responses", `{"error":{"message":"context too long"}}`)
	srv := httptest.NewServer(script.handler(t))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-5.5")
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  func(ctx context.Context, c ToolCall) ToolResult { return ToolResult{} },
		MaxSteps: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "context too long") {
		t.Errorf("expected api error, got %v", err)
	}
}

func TestOpenAIToolsNilHandler(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-4o")
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{})
	if err == nil || !strings.Contains(err.Error(), "nil tool handler") {
		t.Errorf("expected nil-handler err, got %v", err)
	}
}

// ---------------- Reasoning models omit temperature ----------------

func TestOpenAIToolsReasoningModelOmitsTemperatureAndUsesMCT(t *testing.T) {
	script := newOpenAIScript()
	// Force the Responses path with one final response (no tool calls).
	script.queue("/responses", `{
		"output": [{"type":"message","role":"assistant",
		            "content":[{"type":"output_text","text":"hi"}]}],
		"usage": {"input_tokens": 1, "output_tokens": 1}
	}`)
	srv := httptest.NewServer(script.handler(t))
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "o3-mini")
	_, err := c.CompleteWithTools(context.Background(), ToolRequest{
		Messages: []Message{{Role: "user", Content: "x"}},
		Handler:  func(ctx context.Context, c ToolCall) ToolResult { return ToolResult{} },
		MaxSteps: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var req oaResponsesRequest
	if err := json.Unmarshal(script.bodies["/responses"][0], &req); err != nil {
		t.Fatal(err)
	}
	if req.Temperature != nil {
		t.Errorf("reasoning model must omit temperature; got %v", *req.Temperature)
	}
	if req.MaxOutputTokens != 500 {
		t.Errorf("max_output_tokens=%d want 500", req.MaxOutputTokens)
	}
}

// ---------------- ToolClient interface assertion ----------------

func TestOpenAIClientImplementsToolClient(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := newOpenAIToolClient(t, srv, "gpt-4o")
	var client Client = c
	if _, ok := AsToolLooper(client); !ok {
		t.Error("openAIClient must implement ToolClient / pass AsToolLooper")
	}
}
