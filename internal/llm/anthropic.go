package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	body := c.buildCompleteRequest(req)
	raw, err := c.postMessages(ctx, body)
	if err != nil {
		return Response{}, err
	}
	out, err := decodeAnthropicResponse(raw)
	if err != nil {
		return Response{}, err
	}
	return c.responseFromComplete(out), nil
}

func (c *anthropicClient) buildCompleteRequest(req Request) antRequest {
	return antRequest{
		Model:       c.spec.Model,
		System:      buildCompleteSystemPrompt(req),
		Messages:    buildCompleteMessages(req.Messages),
		MaxTokens:   c.spec.MaxTokens,
		Temperature: resolveAnthropicTemperature(c.spec.Temperature, req.TemperatureOverride),
	}
}

func buildCompleteMessages(messages []Message) []antMessage {
	msgs := make([]antMessage, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			// merged into top-level system.
			continue
		}
		msgs = append(msgs, antMessage{
			Role:    m.Role,
			Content: []antContentBlock{{Type: "text", Text: m.Content}},
		})
	}
	return msgs
}

func buildCompleteSystemPrompt(req Request) string {
	system := req.System
	if !req.JSON {
		return system
	}
	system += "\n\nIMPORTANT: respond with a single JSON object. No prose, no markdown fences."
	if req.Schema != nil {
		schemaJSON, _ := json.Marshal(req.Schema)
		system += "\nMust conform to schema: " + string(schemaJSON)
	}
	return system
}

func resolveAnthropicTemperature(temp float64, override *float64) float64 {
	if override != nil {
		return *override
	}
	return temp
}

func decodeAnthropicResponse(raw []byte) (antResponse, error) {
	var out antResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return antResponse{}, fmt.Errorf("anthropic decode: %w; body=%s", err, string(raw))
	}
	if out.Error != nil {
		return antResponse{}, errors.New("anthropic: " + out.Error.Message)
	}
	return out, nil
}

func extractAnthropicText(content []antContentBlock) string {
	var text strings.Builder
	for _, block := range content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	return text.String()
}

func (c *anthropicClient) responseFromComplete(out antResponse) Response {
	return Response{
		Text:       extractAnthropicText(out.Content),
		TokensIn:   out.Usage.InputTokens,
		TokensOut:  out.Usage.OutputTokens,
		Provider:   "anthropic",
		Model:      c.spec.Model,
		FinishedAt: time.Now(),
	}
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

type antToolLoop struct {
	system   string
	tools    []antToolDef
	messages []antToolMessage
	temp     float64

	steps     []ToolStep
	tokensIn  int
	tokensOut int
	finalText string
}

// CompleteWithTools drives the multi-turn tool-use loop on top of the
// Anthropic Messages API. The loop runs until the model returns
// stop_reason="end_turn" (final text) or MaxSteps is exhausted.
func (c *anthropicClient) CompleteWithTools(ctx context.Context, req ToolRequest) (ToolResponse, error) {
	if err := validateAnthropicToolRequest(&req); err != nil {
		return ToolResponse{}, err
	}
	loop := newAnthropicToolLoop(c, req)
	for step := 0; step < req.MaxSteps; step++ {
		out, err := c.runToolLoopRound(ctx, loop)
		if err != nil {
			return ToolResponse{}, err
		}
		loop.recordRound(out)
		if loop.processAssistantBlocks(ctx, req.Handler, out.Content) {
			break
		}
	}
	return loop.response(c.spec.Model), nil
}

func validateAnthropicToolRequest(req *ToolRequest) error {
	if req.Handler == nil {
		return errors.New("anthropic: nil tool handler")
	}
	if req.MaxSteps <= 0 {
		req.MaxSteps = 20
	}
	return nil
}

func newAnthropicToolLoop(c *anthropicClient, req ToolRequest) *antToolLoop {
	return &antToolLoop{
		system:   req.System,
		tools:    toAnthropicToolDefs(req.Tools),
		messages: seedAnthropicToolMessages(req.Messages),
		temp:     resolveAnthropicTemperature(c.spec.Temperature, req.TemperatureOverride),
	}
}

func toAnthropicToolDefs(tools []ToolDef) []antToolDef {
	out := make([]antToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, antToolDef(t))
	}
	return out
}

func seedAnthropicToolMessages(messages []Message) []antToolMessage {
	msgs := make([]antToolMessage, 0, len(messages))
	for _, m := range messages {
		if m.Role == "system" {
			continue
		}
		msgs = append(msgs, antToolMessage{
			Role:    m.Role,
			Content: []antToolBlock{{Type: "text", Text: m.Content}},
		})
	}
	return msgs
}

func (c *anthropicClient) runToolLoopRound(ctx context.Context, loop *antToolLoop) (antToolResponse, error) {
	body := antToolRequest{
		Model:       c.spec.Model,
		System:      loop.system,
		Messages:    loop.messages,
		Tools:       loop.tools,
		MaxTokens:   c.spec.MaxTokens,
		Temperature: loop.temp,
	}
	raw, err := c.postMessages(ctx, body)
	if err != nil {
		return antToolResponse{}, err
	}
	return decodeAnthropicToolResponse(raw)
}

func decodeAnthropicToolResponse(raw []byte) (antToolResponse, error) {
	var out antToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return antToolResponse{}, fmt.Errorf("anthropic decode: %w; body=%s", err, string(raw))
	}
	if out.Error != nil {
		return antToolResponse{}, errors.New("anthropic: " + out.Error.Message)
	}
	return out, nil
}

func (l *antToolLoop) recordRound(out antToolResponse) {
	l.tokensIn += out.Usage.InputTokens
	l.tokensOut += out.Usage.OutputTokens
	// Keep the assistant turn in history so the next round has full context.
	l.messages = append(l.messages, antToolMessage{Role: "assistant", Content: out.Content})
}

func (l *antToolLoop) processAssistantBlocks(
	ctx context.Context,
	handler func(context.Context, ToolCall) ToolResult,
	content []antToolBlock,
) bool {
	toolResults, text, hasToolUse := l.collectToolResults(ctx, handler, content)
	if !hasToolUse {
		l.finalText = text
		return true
	}
	l.messages = append(l.messages, antToolMessage{Role: "user", Content: toolResults})
	return false
}

func (l *antToolLoop) collectToolResults(
	ctx context.Context,
	handler func(context.Context, ToolCall) ToolResult,
	content []antToolBlock,
) ([]antToolBlock, string, bool) {
	var (
		toolResults []antToolBlock
		textBuf     strings.Builder
		anyToolUse  bool
	)
	for _, block := range content {
		switch block.Type {
		case "text":
			textBuf.WriteString(block.Text)
		case "tool_use":
			anyToolUse = true
			call := ToolCall{ID: block.ID, Name: block.Name, Input: block.Input}
			res := handler(ctx, call)
			l.steps = append(l.steps, ToolStep{Call: call, Result: res})
			toolResults = append(toolResults, antToolBlock{
				Type:      "tool_result",
				ToolUseID: res.ID,
				Content:   res.Content,
				IsError:   res.IsError,
			})
		}
	}
	return toolResults, textBuf.String(), anyToolUse
}

func (l *antToolLoop) response(model string) ToolResponse {
	return ToolResponse{
		FinalText: l.finalText,
		Steps:     l.steps,
		TokensIn:  l.tokensIn,
		TokensOut: l.tokensOut,
		Provider:  "anthropic",
		Model:     model,
	}
}

// postMessages sends the body to /v1/messages and returns the raw response body.
// Goes through the shared inflight semaphore + retry loop (429 / 5xx with
// exponential backoff, honors Retry-After).
func (c *anthropicClient) postMessages(ctx context.Context, body any) ([]byte, error) {
	buf, _ := json.Marshal(body)
	res, err := doHTTP(ctx, c.http, "anthropic", func(ctx context.Context) (*http.Request, error) {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(buf))
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", c.anthropicVersion)
		if c.useBearer {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		} else {
			req.Header.Set("x-api-key", c.apiKey)
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	return res.body, nil
}
