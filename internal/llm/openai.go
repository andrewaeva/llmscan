package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	body := c.buildChatCompletionRequest(req)
	raw, err := c.postChatCompletion(ctx, body)
	if err != nil {
		return Response{}, err
	}
	return c.parseChatCompletionResponse(raw)
}

func (c *openAIClient) buildChatCompletionRequest(req Request) oaRequest {
	body := oaRequest{
		Model:    c.spec.Model,
		Messages: buildOpenAIMessages(req),
	}
	reasoning := modelUsesMaxCompletionTokens(c.spec.Model)
	c.applyCompletionBudget(&body, reasoning)
	c.applyTemperature(&body, req, reasoning)
	body.ResponseFormat = buildOpenAIResponseFormat(req)
	return body
}

func buildOpenAIMessages(req Request) []oaMessage {
	msgs := make([]oaMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, oaMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, oaMessage(m))
	}
	return msgs
}

func (c *openAIClient) applyCompletionBudget(body *oaRequest, reasoning bool) {
	if reasoning {
		body.MaxCompletionTokens = reasoningCompletionBudget(c.spec.MaxTokens)
		return
	}
	body.MaxTokens = c.spec.MaxTokens
}

func reasoningCompletionBudget(maxTokens int) int {
	// Reasoning models (GPT-5/o1/o3/o4) consume a significant portion of
	// their token budget on hidden reasoning tokens before emitting any
	// content. A budget of <8000 frequently yields empty responses.
	// Bump the effective ceiling so the visible content has room to land.
	budget := maxTokens
	if budget < 16000 {
		budget *= 4
	}
	if budget < 8000 {
		budget = 8000
	}
	return budget
}

func (c *openAIClient) applyTemperature(body *oaRequest, req Request, reasoning bool) {
	// GPT-5 / o1 / o3 / o4 reasoning models only accept the default
	// temperature (1) and reject any explicit value. Omit the field there.
	if reasoning {
		return
	}
	temp := c.spec.Temperature
	if req.TemperatureOverride != nil {
		temp = *req.TemperatureOverride
	}
	body.Temperature = &temp
}

func buildOpenAIResponseFormat(req Request) map[string]any {
	if !req.JSON {
		return nil
	}
	if req.Schema == nil {
		return map[string]any{"type": "json_object"}
	}
	name := req.SchemaName
	if name == "" {
		name = "response"
	}
	return map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   name,
			"schema": req.Schema,
			"strict": true,
		},
	}
}

func (c *openAIClient) postChatCompletion(ctx context.Context, body oaRequest) ([]byte, error) {
	buf, _ := json.Marshal(body)
	res, err := doHTTP(ctx, c.http, c.label, func(ctx context.Context) (*http.Request, error) {
		return c.newChatCompletionRequest(ctx, buf)
	})
	if err != nil {
		return nil, err
	}
	return res.body, nil
}

func (c *openAIClient) newChatCompletionRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	return req, nil
}

func (c *openAIClient) parseChatCompletionResponse(raw []byte) (Response, error) {
	out, err := decodeOpenAIResponse(c.label, raw)
	if err != nil {
		return Response{}, err
	}
	return c.responseFromOpenAI(out)
}

func decodeOpenAIResponse(label string, raw []byte) (oaResponse, error) {
	var out oaResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return oaResponse{}, fmt.Errorf("%s decode: %w; body=%s", label, err, string(raw))
	}
	if out.Error != nil {
		return oaResponse{}, errors.New(label + ": " + out.Error.Message)
	}
	return out, nil
}

func (c *openAIClient) responseFromOpenAI(out oaResponse) (Response, error) {
	if len(out.Choices) == 0 {
		return Response{}, fmt.Errorf("%s: empty choices: %w", c.label, ErrEmptyResponse)
	}
	if out.Choices[0].Message.Content == "" && out.Choices[0].FinishReason == "length" {
		return Response{}, fmt.Errorf("%s: empty content (finish_reason=length); model spent all %d tokens on reasoning, increase agent max_tokens in config: %w",
			c.label, out.Usage.CompletionTokens, ErrEmptyResponse)
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
