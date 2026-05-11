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

func newOpenAITestServer(t *testing.T, handler func(*http.Request, []byte) (int, string)) (*httptest.Server, *openAIClient) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		code, resp := handler(r, body)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OPENAI_API_KEY", "test-key-xyz")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	c, err := newOpenAIClient(config.ModelSpec{Provider: "openai", Model: "gpt-test", Temperature: 0.7}, "openai")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return srv, c
}

func TestOpenAICompleteSuccess(t *testing.T) {
	var gotReq oaRequest
	var gotPath, gotAuth, gotCT string
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		_ = json.Unmarshal(body, &gotReq)
		return 200, `{"choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`
	})
	resp, err := c.Complete(context.Background(), Request{
		System:   "you are helpful",
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("path=%s", gotPath)
	}
	if gotAuth != "Bearer test-key-xyz" {
		t.Errorf("auth=%q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("ct=%q", gotCT)
	}
	if gotReq.Model != "gpt-test" {
		t.Errorf("model=%s", gotReq.Model)
	}
	if len(gotReq.Messages) != 2 || gotReq.Messages[0].Role != "system" {
		t.Errorf("messages=%+v", gotReq.Messages)
	}
	if resp.Text != "hi" || resp.TokensIn != 10 || resp.TokensOut != 2 {
		t.Errorf("resp=%+v", resp)
	}
	if resp.Provider != "openai" || resp.Model != "gpt-test" {
		t.Errorf("provider/model: %+v", resp)
	}
}

func TestOpenAICompleteJSONMode(t *testing.T) {
	var gotReq oaRequest
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		_ = json.Unmarshal(body, &gotReq)
		return 200, `{"choices":[{"message":{"content":"{}"}}]}`
	})
	if _, err := c.Complete(context.Background(), Request{JSON: true}); err != nil {
		t.Fatal(err)
	}
	if gotReq.ResponseFormat["type"] != "json_object" {
		t.Errorf("expected json_object, got %v", gotReq.ResponseFormat)
	}
}

func TestOpenAICompleteJSONSchema(t *testing.T) {
	var gotReq oaRequest
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		_ = json.Unmarshal(body, &gotReq)
		return 200, `{"choices":[{"message":{"content":"{}"}}]}`
	})
	schema := map[string]any{"type": "object"}
	if _, err := c.Complete(context.Background(), Request{
		JSON: true, Schema: schema, SchemaName: "myresp",
	}); err != nil {
		t.Fatal(err)
	}
	if gotReq.ResponseFormat["type"] != "json_schema" {
		t.Errorf("got %v", gotReq.ResponseFormat)
	}
	js, _ := gotReq.ResponseFormat["json_schema"].(map[string]any)
	if js["name"] != "myresp" {
		t.Errorf("name=%v", js["name"])
	}
}

func TestOpenAITemperatureOverride(t *testing.T) {
	var gotReq oaRequest
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		_ = json.Unmarshal(body, &gotReq)
		return 200, `{"choices":[{"message":{"content":"x"}}]}`
	})
	override := 1.3
	if _, err := c.Complete(context.Background(), Request{TemperatureOverride: &override}); err != nil {
		t.Fatal(err)
	}
	if gotReq.Temperature == nil || *gotReq.Temperature != 1.3 {
		t.Errorf("temp=%v want 1.3", gotReq.Temperature)
	}
}

func TestOpenAIReasoningModelOmitsTemperatureAndUsesMaxCompletionTokens(t *testing.T) {
	cases := []string{"gpt-5.5", "gpt-5", "o1", "o3-mini", "o4-mini", "chat-latest"}
	for _, model := range cases {
		t.Run(model, func(t *testing.T) {
			var gotReq oaRequest
			var raw map[string]any
			srv, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
				_ = json.Unmarshal(body, &gotReq)
				_ = json.Unmarshal(body, &raw)
				return 200, `{"choices":[{"message":{"content":"x"}}]}`
			})
			_ = srv
			c.spec.Model = model
			c.spec.MaxTokens = 1234
			override := 0.4
			if _, err := c.Complete(context.Background(), Request{TemperatureOverride: &override}); err != nil {
				t.Fatal(err)
			}
			if _, present := raw["temperature"]; present {
				t.Errorf("temperature must be omitted for reasoning model %s", model)
			}
			if _, present := raw["max_tokens"]; present {
				t.Errorf("max_tokens must be omitted for reasoning model %s", model)
			}
			if gotReq.MaxCompletionTokens != 1234 {
				t.Errorf("max_completion_tokens=%d want 1234", gotReq.MaxCompletionTokens)
			}
		})
	}
}

func TestOpenAILegacyModelKeepsTemperatureAndMaxTokens(t *testing.T) {
	var raw map[string]any
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		_ = json.Unmarshal(body, &raw)
		return 200, `{"choices":[{"message":{"content":"x"}}]}`
	})
	c.spec.Model = "gpt-4o"
	c.spec.MaxTokens = 999
	c.spec.Temperature = 0.0
	if _, err := c.Complete(context.Background(), Request{}); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["temperature"]; !present {
		t.Errorf("temperature must be present for legacy model (even when 0)")
	}
	if v, _ := raw["max_tokens"].(float64); v != 999 {
		t.Errorf("max_tokens=%v want 999", raw["max_tokens"])
	}
	if _, present := raw["max_completion_tokens"]; present {
		t.Errorf("max_completion_tokens must NOT be sent for legacy model")
	}
}

func TestOpenAIHTTPError(t *testing.T) {
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		return 500, `{"error":{"message":"server boom"}}`
	})
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("expected 500 error, got: %v", err)
	}
}

func TestOpenAIAPIError(t *testing.T) {
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		return 200, `{"error":{"message":"bad"}}`
	})
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("expected api error, got: %v", err)
	}
}

func TestOpenAIEmptyChoices(t *testing.T) {
	_, c := newOpenAITestServer(t, func(r *http.Request, body []byte) (int, string) {
		return 200, `{"choices":[]}`
	})
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "empty choices") {
		t.Errorf("expected empty choices error, got: %v", err)
	}
}

func TestOpenAIMissingAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	_, err := newOpenAIClient(config.ModelSpec{Provider: "openai", Model: "m"}, "openai")
	if err == nil {
		t.Error("expected missing API key error")
	}
}

func TestOpenAIClientName(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "k")
	c, err := newOpenAIClient(config.ModelSpec{Model: "gpt-4o-mini"}, "openai")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name() != "openai/gpt-4o-mini" {
		t.Errorf("name=%s", c.Name())
	}
}

func TestEnvFirstNonEmpty(t *testing.T) {
	t.Setenv("FOO_A", "")
	t.Setenv("FOO_B", "  bee  ")
	t.Setenv("FOO_C", "see")
	v, name := envFirstNonEmpty("FOO_A", "FOO_B", "FOO_C")
	if v != "bee" || name != "FOO_B" {
		t.Errorf("v=%q name=%q", v, name)
	}
	v, name = envFirstNonEmpty("MISSING_X", "MISSING_Y")
	if v != "" || name != "" {
		t.Errorf("expected empty, got %q/%q", v, name)
	}
}

func TestResolveBaseURL(t *testing.T) {
	t.Setenv("BU_A", "")
	t.Setenv("BU_B", "https://env.example/")
	if got := resolveBaseURL("https://spec.example/", "https://fb/", "BU_A", "BU_B"); got != "https://spec.example" {
		t.Errorf("spec wins, got %q", got)
	}
	if got := resolveBaseURL("", "https://fb/", "BU_A", "BU_B"); got != "https://env.example" {
		t.Errorf("env wins, got %q", got)
	}
	if got := resolveBaseURL("", "https://fb/", "BU_A"); got != "https://fb" {
		t.Errorf("fallback, got %q", got)
	}
}

func TestNewClientUnknownProvider(t *testing.T) {
	_, err := New(config.ModelSpec{Provider: "weird"})
	if err == nil {
		t.Error("expected error")
	}
}

func TestNewClientOpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "k")
	c, err := New(config.ModelSpec{Provider: "openai", Model: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Name(), "openai/") {
		t.Errorf("name=%s", c.Name())
	}
}
