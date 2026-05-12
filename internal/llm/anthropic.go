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

// anthropicClient talks to either the official Anthropic Messages API or any
// compatible proxy (e.g. OpenRouter, LiteLLM, Bedrock-proxies, internal
// gateways) configured via ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN.
//
// Auth resolution (in order):
//  1. spec.APIKeyEnv (if set in config)
//  2. ANTHROPIC_API_KEY     -> sent as "x-api-key"
//  3. ANTHROPIC_AUTH_TOKEN  -> sent as "Authorization: Bearer ..." (proxy mode)
//
// Base URL resolution:
//  1. spec.BaseURL
//  2. ANTHROPIC_BASE_URL
//  3. https://api.anthropic.com
type anthropicClient struct {
	baseURL string
	apiKey  string
	spec    config.ModelSpec
	http    *http.Client

	// useBearer makes the client send "Authorization: Bearer <token>" instead
	// of the native "x-api-key" header. Enabled when ANTHROPIC_AUTH_TOKEN is
	// used (typical for proxies) or when the user explicitly sets
	// APIKeyEnv=ANTHROPIC_AUTH_TOKEN.
	useBearer bool

	// anthropicVersion header; configurable for proxies that pin a version.
	anthropicVersion string
}

func newAnthropicClient(spec config.ModelSpec) (*anthropicClient, error) {
	base := resolveBaseURL(spec.BaseURL, "https://api.anthropic.com", "ANTHROPIC_BASE_URL")

	// Auth resolution.
	var (
		apiKey    string
		usedEnv   string
		useBearer bool
	)
	// 1) explicit env from config.
	if spec.APIKeyEnv != "" {
		apiKey, usedEnv = envFirstNonEmpty(spec.APIKeyEnv)
		if strings.EqualFold(spec.APIKeyEnv, "ANTHROPIC_AUTH_TOKEN") {
			useBearer = true
		}
	}
	// 2) standard ANTHROPIC_API_KEY (native x-api-key).
	if apiKey == "" {
		apiKey, usedEnv = envFirstNonEmpty("ANTHROPIC_API_KEY")
	}
	// 3) ANTHROPIC_AUTH_TOKEN (proxy / Bearer mode).
	if apiKey == "" {
		if v, name := envFirstNonEmpty("ANTHROPIC_AUTH_TOKEN"); v != "" {
			apiKey = v
			usedEnv = name
			useBearer = true
		}
	}
	if apiKey == "" {
		return nil, fmt.Errorf("missing API key for anthropic model %s (tried env: %s)",
			spec.Model, anthropicEnvHint(spec.APIKeyEnv))
	}
	if spec.APIKeyEnv == "" {
		spec.APIKeyEnv = usedEnv
	}

	version := strings.TrimSpace(os.Getenv("ANTHROPIC_VERSION"))
	if version == "" {
		version = "2023-06-01"
	}

	authHeader := "x-api-key"
	if useBearer {
		authHeader = "bearer"
	}
	logEndpointOnce("anthropic", spec.Model, base, "https://api.anthropic.com", spec.APIKeyEnv,
		"auth="+authHeader, "version="+version)

	return &anthropicClient{
		baseURL:          base,
		apiKey:           apiKey,
		spec:             spec,
		http:             defaultHTTP(),
		useBearer:        useBearer,
		anthropicVersion: version,
	}, nil
}

func anthropicEnvHint(specEnv string) string {
	parts := []string{}
	if specEnv != "" {
		parts = append(parts, specEnv)
	}
	parts = append(parts, "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
	return strings.Join(parts, ", ")
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
		if m.Role == "system" {
			// merged into top-level system below
			continue
		}
		msgs = append(msgs, antMessage{
			Role:    m.Role,
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
	raw, err := c.postMessages(ctx, body)
	if err != nil {
		return Response{}, err
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

// ---- Tool-use loop (CompleteWithTools) ----

type antToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type antToolBlock struct {
	Type      string          `json:"type"` // "text" | "tool_use" | "tool_result"
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`          // for tool_use
	Name      string          `json:"name,omitempty"`        // for tool_use
	Input     json.RawMessage `json:"input,omitempty"`       // for tool_use
	ToolUseID string          `json:"tool_use_id,omitempty"` // for tool_result
	Content   string          `json:"content,omitempty"`     // for tool_result (string form)
	IsError   bool            `json:"is_error,omitempty"`    // for tool_result
}

type antToolMessage struct {
	Role    string         `json:"role"`
	Content []antToolBlock `json:"content"`
}

type antToolRequest struct {
	Model       string           `json:"model"`
	System      string           `json:"system,omitempty"`
	Messages    []antToolMessage `json:"messages"`
	Tools       []antToolDef     `json:"tools,omitempty"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature float64          `json:"temperature"`
}

type antToolResponse struct {
	Content    []antToolBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// CompleteWithTools drives the multi-turn tool-use loop on top of the
// Anthropic Messages API. The loop runs until the model returns
// stop_reason="end_turn" (final text) or MaxSteps is exhausted.
func (c *anthropicClient) CompleteWithTools(ctx context.Context, req ToolRequest) (ToolResponse, error) {
	if req.Handler == nil {
		return ToolResponse{}, errors.New("anthropic: nil tool handler")
	}
	if req.MaxSteps <= 0 {
		req.MaxSteps = 20
	}

	tools := make([]antToolDef, 0, len(req.Tools))
	for _, t := range req.Tools {
		tools = append(tools, antToolDef(t))
	}

	// Seed message history with the caller's messages (skipping any "system"
	// entries; Anthropic carries system separately).
	msgs := make([]antToolMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" {
			continue
		}
		msgs = append(msgs, antToolMessage{
			Role:    m.Role,
			Content: []antToolBlock{{Type: "text", Text: m.Content}},
		})
	}

	temp := c.spec.Temperature
	if req.TemperatureOverride != nil {
		temp = *req.TemperatureOverride
	}

	var (
		steps     []ToolStep
		tokensIn  int
		tokensOut int
		finalText string
	)

	for step := 0; step < req.MaxSteps; step++ {
		body := antToolRequest{
			Model:       c.spec.Model,
			System:      req.System,
			Messages:    msgs,
			Tools:       tools,
			MaxTokens:   c.spec.MaxTokens,
			Temperature: temp,
		}
		raw, err := c.postMessages(ctx, body)
		if err != nil {
			return ToolResponse{}, err
		}
		var out antToolResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return ToolResponse{}, fmt.Errorf("anthropic decode: %w; body=%s", err, string(raw))
		}
		if out.Error != nil {
			return ToolResponse{}, errors.New("anthropic: " + out.Error.Message)
		}
		tokensIn += out.Usage.InputTokens
		tokensOut += out.Usage.OutputTokens

		// Append the assistant turn to the history.
		msgs = append(msgs, antToolMessage{Role: "assistant", Content: out.Content})

		// Collect tool_use blocks; emit a single user turn with all results.
		var (
			toolResults []antToolBlock
			textBuf     strings.Builder
			anyToolUse  bool
		)
		for _, b := range out.Content {
			switch b.Type {
			case "text":
				textBuf.WriteString(b.Text)
			case "tool_use":
				anyToolUse = true
				call := ToolCall{ID: b.ID, Name: b.Name, Input: b.Input}
				res := req.Handler(ctx, call)
				steps = append(steps, ToolStep{Call: call, Result: res})
				toolResults = append(toolResults, antToolBlock{
					Type:      "tool_result",
					ToolUseID: res.ID,
					Content:   res.Content,
					IsError:   res.IsError,
				})
			}
		}

		if !anyToolUse {
			finalText = textBuf.String()
			break
		}
		msgs = append(msgs, antToolMessage{Role: "user", Content: toolResults})
	}

	return ToolResponse{
		FinalText: finalText,
		Steps:     steps,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
		Provider:  "anthropic",
		Model:     c.spec.Model,
	}, nil
}

// postMessages sends the body to /v1/messages and returns the raw response body.
func (c *anthropicClient) postMessages(ctx context.Context, body any) ([]byte, error) {
	buf, _ := json.Marshal(body)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(buf))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("anthropic-version", c.anthropicVersion)
	if c.useBearer {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	} else {
		httpReq.Header.Set("x-api-key", c.apiKey)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic http: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		if sentinel := classifyHTTP(resp.StatusCode); sentinel != nil {
			return nil, fmt.Errorf("anthropic http %d: %s: %w", resp.StatusCode, string(raw), sentinel)
		}
		return nil, fmt.Errorf("anthropic http %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}
