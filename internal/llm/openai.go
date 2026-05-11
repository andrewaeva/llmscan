package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
