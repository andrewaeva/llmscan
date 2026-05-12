package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/config"
)

type openAIClient struct {
	baseURL string
	apiKey  string
	spec    config.ModelSpec
	http    *http.Client
	label   string // "openai" | "opencode"
}

func newOpenAIClient(spec config.ModelSpec, label string) (*openAIClient, error) {
	var (
		base    string
		apiKey  string
		envName string
	)
	switch label {
	case "opencode":
		base = resolveBaseURL(spec.BaseURL, "https://api.opencode.ai/v1",
			"OPENCODE_BASE_URL", "OPENAI_BASE_URL")
		apiKey, envName = envFirstNonEmpty(spec.APIKeyEnv, "OPENCODE_API_KEY", "OPENAI_API_KEY")
	default: // "openai"
		base = resolveBaseURL(spec.BaseURL, "https://api.openai.com/v1",
			"OPENAI_BASE_URL")
		apiKey, envName = envFirstNonEmpty(spec.APIKeyEnv, "OPENAI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("missing API key for %s model %s (tried env: %s)",
			label, spec.Model, joinEnvNames(spec.APIKeyEnv, label))
	}
	if envName != "" && spec.APIKeyEnv == "" {
		spec.APIKeyEnv = envName
	}
	defaultBase := "https://api.openai.com/v1"
	if label == "opencode" {
		defaultBase = "https://api.opencode.ai/v1"
	}
	logEndpointOnce(label, spec.Model, base, defaultBase, spec.APIKeyEnv, "auth=bearer")
	return &openAIClient{baseURL: base, apiKey: apiKey, spec: spec, http: defaultHTTP(), label: label}, nil
}

func joinEnvNames(specEnv, label string) string {
	switch label {
	case "opencode":
		if specEnv != "" {
			return specEnv + ", OPENCODE_API_KEY, OPENAI_API_KEY"
		}
		return "OPENCODE_API_KEY, OPENAI_API_KEY"
	default:
		if specEnv != "" {
			return specEnv + ", OPENAI_API_KEY"
		}
		return "OPENAI_API_KEY"
	}
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
	Model               string         `json:"model"`
	Messages            []oaMessage    `json:"messages"`
	Temperature         *float64       `json:"temperature,omitempty"`
	MaxTokens           int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens int            `json:"max_completion_tokens,omitempty"`
	ResponseFormat      map[string]any `json:"response_format,omitempty"`
}

// modelUsesMaxCompletionTokens reports whether the given model family rejects
// the legacy `max_tokens` field and requires `max_completion_tokens` instead
// (GPT-5 family, o1/o3/o4 reasoning models).
func modelUsesMaxCompletionTokens(model string) bool {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "gpt-5"),
		strings.HasPrefix(m, "o1"),
		strings.HasPrefix(m, "o3"),
		strings.HasPrefix(m, "o4"),
		strings.HasPrefix(m, "chat-latest"):
		return true
	}
	return false
}
type oaResponse struct {
	Choices []struct {
		Message      oaMessage `json:"message"`
		FinishReason string    `json:"finish_reason"`
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
		msgs = append(msgs, oaMessage(m))
	}
	body := oaRequest{
		Model:    c.spec.Model,
		Messages: msgs,
	}
	reasoning := modelUsesMaxCompletionTokens(c.spec.Model)
	if reasoning {
		// Reasoning models (GPT-5/o1/o3/o4) consume a significant portion of
		// their token budget on hidden reasoning tokens before emitting any
		// content. A budget of <8000 frequently yields empty responses.
		// Bump the effective ceiling so the visible content has room to land.
		budget := c.spec.MaxTokens
		if budget < 16000 {
			budget *= 4
		}
		if budget < 8000 {
			budget = 8000
		}
		body.MaxCompletionTokens = budget
	} else {
		body.MaxTokens = c.spec.MaxTokens
	}
	// GPT-5 / o1 / o3 / o4 reasoning models only accept the default temperature (1)
	// and reject any explicit value. Omit the field for those models.
	if !reasoning {
		temp := c.spec.Temperature
		if req.TemperatureOverride != nil {
			temp = *req.TemperatureOverride
		}
		body.Temperature = &temp
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
		return Response{}, fmt.Errorf("%s http: %w", c.label, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return Response{}, fmt.Errorf("%s http %d: %s", c.label, resp.StatusCode, string(raw))
	}
	var out oaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("%s decode: %w; body=%s", c.label, err, string(raw))
	}
	if out.Error != nil {
		return Response{}, errors.New(c.label + ": " + out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return Response{}, errors.New(c.label + ": empty choices")
	}
	if out.Choices[0].Message.Content == "" && out.Choices[0].FinishReason == "length" {
		return Response{}, fmt.Errorf("%s: empty content (finish_reason=length); model spent all %d tokens on reasoning, increase agent max_tokens in config",
			c.label, out.Usage.CompletionTokens)
	}
	provider := c.label
	if provider == "" {
		provider = "openai"
	}
	return Response{
		Text:       out.Choices[0].Message.Content,
		TokensIn:   out.Usage.PromptTokens,
		TokensOut:  out.Usage.CompletionTokens,
		Provider:   provider,
		Model:      c.spec.Model,
		FinishedAt: time.Now(),
	}, nil
}
