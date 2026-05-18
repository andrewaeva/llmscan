package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
)

func newAnthropicTestServer(t *testing.T, handler func(*http.Request, []byte) (int, string)) (*httptest.Server, *anthropicClient) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		code, resp := handler(r, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c, err := newAnthropicClient(config.ModelSpec{
		Provider:    "anthropic",
		Model:       "claude-test",
		Temperature: 0.2,
		MaxTokens:   1234,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return srv, c
}

func TestAnthropicCompleteSuccess(t *testing.T) {
	var (
		gotPath, gotAPIKey, gotBearer, gotVersion, gotCT string
		gotBody                                          antRequest
	)
	_, c := newAnthropicTestServer(t, func(r *http.Request, body []byte) (int, string) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotBearer = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("anthropic-version")
		gotCT = r.Header.Get("Content-Type")
		_ = json.Unmarshal(body, &gotBody)
		return 200, `{"content":[{"type":"text","text":"hello world"}],"usage":{"input_tokens":7,"output_tokens":3}}`
	})
	resp, err := c.Complete(context.Background(), Request{
		System:   "you are helpful",
		Messages: []Message{{Role: "system", Content: "ignored"}, {Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("path=%s", gotPath)
	}
	if gotAPIKey != "sk-ant-test" {
		t.Errorf("x-api-key=%q", gotAPIKey)
	}
	if gotBearer != "" {
		t.Errorf("expected no Authorization for native auth; got %q", gotBearer)
	}
	if gotVersion == "" {
		t.Error("anthropic-version missing")
	}
	if gotCT != "application/json" {
		t.Errorf("content-type=%s", gotCT)
	}
	if gotBody.Model != "claude-test" || gotBody.MaxTokens != 1234 {
		t.Errorf("body=%+v", gotBody)
	}
	if gotBody.System != "you are helpful" {
		t.Errorf("system=%q", gotBody.System)
	}
	if len(gotBody.Messages) != 1 || gotBody.Messages[0].Role != "user" {
		t.Errorf("messages=%+v", gotBody.Messages)
	}
	if resp.Text != "hello world" || resp.TokensIn != 7 || resp.TokensOut != 3 {
		t.Errorf("response: %+v", resp)
	}
	if resp.Provider != "anthropic" || resp.Model != "claude-test" {
		t.Errorf("response model/provider: %+v", resp)
	}
}

func TestAnthropicCompleteJSONFlagAndSchema(t *testing.T) {
	var got antRequest
	_, c := newAnthropicTestServer(t, func(r *http.Request, body []byte) (int, string) {
		_ = json.Unmarshal(body, &got)
		return 200, `{"content":[{"type":"text","text":"{}"}]}`
	})
	if _, err := c.Complete(context.Background(), Request{
		System: "base",
		JSON:   true,
		Schema: map[string]any{"type": "object"},
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.System, "respond with a single JSON object") {
		t.Errorf("system should carry JSON instruction; got %q", got.System)
	}
	if !strings.Contains(got.System, "Must conform to schema") {
		t.Errorf("system should mention schema; got %q", got.System)
	}
}

func TestAnthropicCompleteTemperatureOverride(t *testing.T) {
	var got antRequest
	_, c := newAnthropicTestServer(t, func(r *http.Request, body []byte) (int, string) {
		_ = json.Unmarshal(body, &got)
		return 200, `{"content":[{"type":"text","text":"x"}]}`
	})
	temp := 0.9
	if _, err := c.Complete(context.Background(), Request{TemperatureOverride: &temp}); err != nil {
		t.Fatal(err)
	}
	if got.Temperature != 0.9 {
		t.Errorf("temperature=%v want 0.9", got.Temperature)
	}
}

func TestBuildCompleteSystemPromptJSONAndSchema(t *testing.T) {
	got := buildCompleteSystemPrompt(Request{
		System: "base prompt",
		JSON:   true,
		Schema: map[string]any{"type": "object"},
	})
	if !strings.Contains(got, "base prompt") {
		t.Fatalf("system prompt lost base text: %q", got)
	}
	if !strings.Contains(got, "respond with a single JSON object") {
		t.Fatalf("missing json directive: %q", got)
	}
	if !strings.Contains(got, "Must conform to schema") {
		t.Fatalf("missing schema directive: %q", got)
	}
}

func TestBuildCompleteMessagesSkipsSystem(t *testing.T) {
	msgs := buildCompleteMessages([]Message{
		{Role: "system", Content: "ignored"},
		{Role: "user", Content: "u"},
		{Role: "assistant", Content: "a"},
	})
	if len(msgs) != 2 {
		t.Fatalf("messages=%+v", msgs)
	}
	if msgs[0].Role != "user" || msgs[0].Content[0].Text != "u" {
		t.Fatalf("first message=%+v", msgs[0])
	}
	if msgs[1].Role != "assistant" || msgs[1].Content[0].Text != "a" {
		t.Fatalf("second message=%+v", msgs[1])
	}
}

func TestExtractAnthropicTextIgnoresNonTextBlocks(t *testing.T) {
	got := extractAnthropicText([]antContentBlock{
		{Type: "text", Text: "hello"},
		{Type: "tool_use", Text: "ignored"},
		{Type: "text", Text: " world"},
	})
	if got != "hello world" {
		t.Fatalf("text=%q", got)
	}
}

func TestAnthropicCompleteHTTPError(t *testing.T) {
	_, c := newAnthropicTestServer(t, func(r *http.Request, body []byte) (int, string) {
		return 500, `boom`
	})
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 err: %v", err)
	}
}

func TestAnthropicCompleteAPIError(t *testing.T) {
	_, c := newAnthropicTestServer(t, func(r *http.Request, body []byte) (int, string) {
		return 200, `{"error":{"message":"bad"}}`
	})
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("expected api err: %v", err)
	}
}

func TestAnthropicCompleteBadJSON(t *testing.T) {
	_, c := newAnthropicTestServer(t, func(r *http.Request, body []byte) (int, string) {
		return 200, `not-json`
	})
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode err: %v", err)
	}
}

func TestAnthropicName(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	c, err := newAnthropicClient(config.ModelSpec{Provider: "anthropic", Model: "claude-3-5-sonnet"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name() != "anthropic/claude-3-5-sonnet" {
		t.Errorf("name=%s", c.Name())
	}
}

func TestAnthropicProxyAuthBearer(t *testing.T) {
	var gotBearer, gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBearer = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("x-api-key")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer srv.Close()
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"} {
		t.Setenv(k, "")
	}
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "bearer-xyz")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	c, err := newAnthropicClient(config.ModelSpec{Provider: "anthropic", Model: "claude-x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete(context.Background(), Request{}); err != nil {
		t.Fatal(err)
	}
	if gotBearer != "Bearer bearer-xyz" {
		t.Errorf("Authorization=%q", gotBearer)
	}
	if gotAPIKey != "" {
		t.Errorf("unexpected x-api-key=%q", gotAPIKey)
	}
}

func TestNewClientAnthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	c, err := New(config.ModelSpec{Provider: "anthropic", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Name(), "anthropic/") {
		t.Errorf("name=%s", c.Name())
	}
}

func TestNewClientOpenCode(t *testing.T) {
	t.Setenv("OPENCODE_API_KEY", "k")
	c, err := New(config.ModelSpec{Provider: "opencode", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Name(), "opencode/") {
		t.Errorf("name=%s", c.Name())
	}
}

func TestOpenAIJoinEnvNames(t *testing.T) {
	if got := joinEnvNames("MY_KEY", "openai"); got != "MY_KEY, OPENAI_API_KEY" {
		t.Errorf("openai+spec: %q", got)
	}
	if got := joinEnvNames("", "openai"); got != "OPENAI_API_KEY" {
		t.Errorf("openai: %q", got)
	}
	if got := joinEnvNames("MY_KEY", "opencode"); got != "MY_KEY, OPENCODE_API_KEY, OPENAI_API_KEY" {
		t.Errorf("opencode+spec: %q", got)
	}
	if got := joinEnvNames("", "opencode"); got != "OPENCODE_API_KEY, OPENAI_API_KEY" {
		t.Errorf("opencode: %q", got)
	}
}

func TestOpenAINameFallback(t *testing.T) {
	c := &openAIClient{label: "", spec: config.ModelSpec{Model: "m"}}
	if c.Name() != "openai/m" {
		t.Errorf("name=%s", c.Name())
	}
}

func TestOpenAITransportError(t *testing.T) {
	c := &openAIClient{
		baseURL: "http://127.0.0.1:1", // closed port → connection refused
		apiKey:  "k",
		spec:    config.ModelSpec{Model: "m"},
		http:    defaultHTTP(),
		label:   "openai",
	}
	_, err := c.Complete(context.Background(), Request{})
	if err == nil {
		t.Error("expected transport error")
	}
}

func TestAnthropicTransportError(t *testing.T) {
	c := &anthropicClient{
		baseURL:          "http://127.0.0.1:1",
		apiKey:           "k",
		spec:             config.ModelSpec{Model: "m"},
		http:             defaultHTTP(),
		anthropicVersion: "2023-06-01",
	}
	_, err := c.Complete(context.Background(), Request{})
	if err == nil {
		t.Error("expected transport error")
	}
}

func TestLogEndpointOnceIsIdempotent(t *testing.T) {
	// just ensure repeated calls don't panic; state coverage is fine
	logEndpointOnce("openai", "m", "http://x", "http://x", "OPENAI_API_KEY")
	logEndpointOnce("openai", "m", "http://x", "http://x", "OPENAI_API_KEY")
}
