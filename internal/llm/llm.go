// Package llm provides a thin, provider-agnostic LLM client used by all agents.
//
// Two providers are supported:
//   - "openai":    OpenAI-compatible Chat Completions API (works for OpenAI and any OpenAI-compatible endpoint).
//   - "anthropic": Anthropic Messages API.
//
// The package intentionally avoids external SDKs to keep dependencies minimal.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/config"
)

// Message is a single chat message.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

// Request describes a completion request.
type Request struct {
	System   string
	Messages []Message
	// JSON indicates JSON-only response is expected (provider-specific hints applied).
	JSON bool
	// Schema, if non-nil, is sent as a strict JSON-schema (OpenAI response_format=json_schema).
	// For providers without native support, it is appended to the system prompt.
	Schema map[string]any
	// SchemaName labels the schema (required by OpenAI strict mode).
	SchemaName string
	// TemperatureOverride lets callers bump temperature for voting/self-consistency.
	TemperatureOverride *float64
}

// Response carries the textual completion and basic usage info.
type Response struct {
	Text       string
	TokensIn   int
	TokensOut  int
	Provider   string
	Model      string
	FinishedAt time.Time
}

// Client is the high-level LLM interface used by agents.
type Client interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// New returns a client for the given model spec.
func New(spec config.ModelSpec) (Client, error) {
	apiKey := os.Getenv(spec.APIKeyEnv)
	switch strings.ToLower(spec.Provider) {
	case "", "openai":
		base := spec.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		if apiKey == "" {
			return nil, fmt.Errorf("missing API key in env %s for openai model %s", spec.APIKeyEnv, spec.Model)
		}
		return &openAIClient{baseURL: base, apiKey: apiKey, spec: spec, http: defaultHTTP()}, nil
	case "opencode":
		base := spec.BaseURL
		if base == "" {
			base = "https://api.opencode.ai/v1"
		}
		if spec.APIKeyEnv == "" || spec.APIKeyEnv == "OPENAI_API_KEY" {
			spec.APIKeyEnv = "OPENCODE_API_KEY"
			apiKey = os.Getenv("OPENCODE_API_KEY")
		}
		if apiKey == "" {
			return nil, fmt.Errorf("missing API key in env %s for opencode model %s", spec.APIKeyEnv, spec.Model)
		}
		return &openAIClient{baseURL: base, apiKey: apiKey, spec: spec, http: defaultHTTP(), label: "opencode"}, nil
	case "anthropic":
		base := spec.BaseURL
		if base == "" {
			base = "https://api.anthropic.com"
		}
		if apiKey == "" {
			return nil, fmt.Errorf("missing API key in env %s for anthropic model %s", spec.APIKeyEnv, spec.Model)
		}
		return &anthropicClient{baseURL: base, apiKey: apiKey, spec: spec, http: defaultHTTP()}, nil
	default:
		return nil, fmt.Errorf("unknown provider %q", spec.Provider)
	}
}

func defaultHTTP() *http.Client {
	return &http.Client{Timeout: 120 * time.Second}
}

// ---------- OpenAI ----------

type openAIClient struct {
	baseURL string
	apiKey  string
	spec    config.ModelSpec
	http    *http.Client
	label   string
}

func (c *openAIClient) Name() string {
	label := c.label
	if label == "" {
		label = "openai"
	}
	return label + "/" + c.spec.Model
}

type oaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type oaRequest struct {
	Model          string         `json:"model"`
	Messages       []oaMessage    `json:"messages"`
	Temperature    float64        `json:"temperature"`
	MaxTokens      int            `json:"max_tokens,omitempty"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
}
type oaResponse struct {
	Choices []struct {
		Message oaMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *openAIClient) Complete(ctx context.Context, req Request) (Response, error) {
	msgs := make([]oaMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, oaMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, oaMessage{Role: m.Role, Content: m.Content})
	}
	body := oaRequest{
		Model:       c.spec.Model,
		Messages:    msgs,
		Temperature: c.spec.Temperature,
		MaxTokens:   c.spec.MaxTokens,
	}
	if req.TemperatureOverride != nil {
		body.Temperature = *req.TemperatureOverride
	}
	if req.JSON {
		if req.Schema != nil {
			name := req.SchemaName
			if name == "" {
				name = "response"
			}
			body.ResponseFormat = map[string]any{
				"type": "json_schema",
				"json_schema": map[string]any{
					"name":   name,
					"schema": req.Schema,
					"strict": true,
				},
			}
		} else {
			body.ResponseFormat = map[string]any{"type": "json_object"}
		}
	}
	buf, _ := json.Marshal(body)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(buf))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("openai http: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("openai http %d: %s", resp.StatusCode, string(raw))
	}
	var out oaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("openai decode: %w; body=%s", err, string(raw))
	}
	if out.Error != nil {
		return Response{}, errors.New("openai: " + out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return Response{}, errors.New("openai: empty choices")
	}
	return Response{
		Text:       out.Choices[0].Message.Content,
		TokensIn:   out.Usage.PromptTokens,
		TokensOut:  out.Usage.CompletionTokens,
		Provider:   "openai",
		Model:      c.spec.Model,
		FinishedAt: time.Now(),
	}, nil
}

// ---------- Anthropic ----------

type anthropicClient struct {
	baseURL string
	apiKey  string
	spec    config.ModelSpec
	http    *http.Client
}

func (c *anthropicClient) Name() string { return "anthropic/" + c.spec.Model }

type antContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type antMessage struct {
	Role    string            `json:"role"`
	Content []antContentBlock `json:"content"`
}
type antRequest struct {
	Model       string       `json:"model"`
	System      string       `json:"system,omitempty"`
	Messages    []antMessage `json:"messages"`
	MaxTokens   int          `json:"max_tokens"`
	Temperature float64      `json:"temperature"`
}
type antResponse struct {
	Content []antContentBlock `json:"content"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *anthropicClient) Complete(ctx context.Context, req Request) (Response, error) {
	msgs := make([]antMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "system" {
			// merged into top-level system below
			continue
		}
		msgs = append(msgs, antMessage{
			Role:    role,
			Content: []antContentBlock{{Type: "text", Text: m.Content}},
		})
	}
	system := req.System
	if req.JSON {
		system += "\n\nIMPORTANT: respond with a single JSON object. No prose, no markdown fences."
		if req.Schema != nil {
			schemaJSON, _ := json.Marshal(req.Schema)
			system += "\nMust conform to schema: " + string(schemaJSON)
		}
	}
	temp := c.spec.Temperature
	if req.TemperatureOverride != nil {
		temp = *req.TemperatureOverride
	}
	body := antRequest{
		Model:       c.spec.Model,
		System:      system,
		Messages:    msgs,
		MaxTokens:   c.spec.MaxTokens,
		Temperature: temp,
	}
	buf, _ := json.Marshal(body)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(buf))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic http: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("anthropic http %d: %s", resp.StatusCode, string(raw))
	}
	var out antResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("anthropic decode: %w; body=%s", err, string(raw))
	}
	if out.Error != nil {
		return Response{}, errors.New("anthropic: " + out.Error.Message)
	}
	var text strings.Builder
	for _, b := range out.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	return Response{
		Text:       text.String(),
		TokensIn:   out.Usage.InputTokens,
		TokensOut:  out.Usage.OutputTokens,
		Provider:   "anthropic",
		Model:      c.spec.Model,
		FinishedAt: time.Now(),
	}, nil
}

// CompleteJSON runs Complete with JSON-mode and validates that the response is
// parseable JSON. On invalid JSON it retries up to `retries` times, feeding the
// previous error back to the model as an assistant/user correction pair.
func CompleteJSON(ctx context.Context, c Client, req Request, retries int) (Response, []byte, error) {
	req.JSON = true
	lastErr := error(nil)
	for i := 0; i <= retries; i++ {
		resp, err := c.Complete(ctx, req)
		if err != nil {
			return resp, nil, err
		}
		js := ExtractJSON(resp.Text)
		var probe any
		if err := json.Unmarshal([]byte(js), &probe); err == nil {
			return resp, []byte(js), nil
		} else {
			lastErr = err
			req.Messages = append(req.Messages,
				Message{Role: "assistant", Content: resp.Text},
				Message{Role: "user", Content: fmt.Sprintf(
					"Your previous response was not valid JSON (%v). Return ONLY a JSON object, no prose, no markdown.",
					err)},
			)
		}
	}
	return Response{}, nil, fmt.Errorf("llm: invalid JSON after %d retries: %w", retries, lastErr)
}

// ExtractJSON pulls a JSON object out of a possibly noisy LLM response (handles markdown fences).
func ExtractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// strip first fence line
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[i+1:]
		}
		if j := strings.LastIndex(s, "```"); j >= 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(s)
	}
	// fall back to first '{' .. last '}'
	if !strings.HasPrefix(s, "{") {
		if i := strings.Index(s, "{"); i >= 0 {
			if j := strings.LastIndex(s, "}"); j > i {
				s = s[i : j+1]
			}
		}
	}
	return s
}
