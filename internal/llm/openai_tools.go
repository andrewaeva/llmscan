package llm

// OpenAI tool-use loop.
//
// Two transports are supported, chosen automatically from the model name:
//
//   - Responses API (POST /responses) for GPT-5 / o1 / o3 / o4 reasoning
//     families. Input is a list of items (`message`, `function_call`,
//     `function_call_output`); tool calls come back as items of type
//     `function_call` with `call_id`, `name`, `arguments`.
//   - Chat Completions (POST /chat/completions) for everything else. Tools
//     are declared with `type: "function"`, tool calls appear in
//     `message.tool_calls[].function.{name, arguments}`, and results are
//     submitted as `role: "tool"` messages with `tool_call_id`.
//
// If the configured proxy doesn't implement /responses (HTTP 404), the
// reasoning-model path transparently falls back to Chat Completions on the
// first request and stays there for the rest of the loop.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type openAIToolLoop struct {
	useResponses bool
	tools        []ToolDef
	temp         float64
	reasoning    bool
	chatMsgs     []oaToolMessage
	respInput    []oaInputItem
	steps        []ToolStep
	tokensIn     int
	tokensOut    int
	finalText    string
}

type openAIToolRound struct {
	text      string
	calls     []ToolCall
	tokensIn  int
	tokensOut int
}

// CompleteWithTools drives the OpenAI tool-use loop until the model returns
// a final assistant message with no tool calls, or MaxSteps is exhausted.
func (c *openAIClient) CompleteWithTools(ctx context.Context, req ToolRequest) (ToolResponse, error) {
	if err := validateToolRequest(c.label, &req); err != nil {
		return ToolResponse{}, err
	}
	loop := newOpenAIToolLoop(c, req)
	for step := 0; step < req.MaxSteps; step++ {
		round, err := c.runToolRound(ctx, req.System, &loop)
		if err != nil {
			return ToolResponse{}, err
		}
		loop.recordRound(round)
		if loop.finishIfDone(round) {
			break
		}
		loop.executeToolCalls(ctx, req.Handler, round.calls)
	}
	return loop.response(c.label, c.spec.Model), nil
}

func validateToolRequest(label string, req *ToolRequest) error {
	if req.Handler == nil {
		return errors.New(label + ": nil tool handler")
	}
	if req.MaxSteps <= 0 {
		req.MaxSteps = 20
	}
	return nil
}

func newOpenAIToolLoop(c *openAIClient, req ToolRequest) openAIToolLoop {
	reasoning := modelUsesMaxCompletionTokens(c.spec.Model)
	return openAIToolLoop{
		useResponses: reasoning,
		tools:        req.Tools,
		temp:         resolveToolRequestTemperature(c.spec.Temperature, req.TemperatureOverride),
		reasoning:    reasoning,
		chatMsgs:     seedChatToolMessages(req),
		respInput:    seedResponsesToolInput(req.Messages),
	}
}

func resolveToolRequestTemperature(temp float64, override *float64) float64 {
	if override != nil {
		return *override
	}
	return temp
}

func seedChatToolMessages(req ToolRequest) []oaToolMessage {
	msgs := make([]oaToolMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, oaToolMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		if m.Role == "" {
			continue
		}
		msgs = append(msgs, oaToolMessage{Role: m.Role, Content: m.Content})
	}
	return msgs
}

func seedResponsesToolInput(msgs []Message) []oaInputItem {
	input := make([]oaInputItem, 0, len(msgs))
	for _, m := range msgs {
		if m.Role == "system" || m.Role == "" {
			continue
		}
		input = append(input, oaInputItem{
			Type:    "message",
			Role:    m.Role,
			Content: m.Content,
		})
	}
	return input
}

func (c *openAIClient) runToolRound(ctx context.Context, system string, loop *openAIToolLoop) (openAIToolRound, error) {
	if loop.useResponses {
		text, calls, inTok, outTok, fellBack, err := c.doResponsesRound(ctx, system, loop.respInput, loop.tools, loop.temp, loop.reasoning)
		if err != nil {
			return openAIToolRound{}, err
		}
		if fellBack {
			loop.useResponses = false
			text, calls, inTok, outTok, err = c.doChatRound(ctx, loop.chatMsgs, loop.tools, loop.temp, loop.reasoning)
			if err != nil {
				return openAIToolRound{}, err
			}
		}
		return openAIToolRound{text: text, calls: calls, tokensIn: inTok, tokensOut: outTok}, nil
	}
	text, calls, inTok, outTok, err := c.doChatRound(ctx, loop.chatMsgs, loop.tools, loop.temp, loop.reasoning)
	if err != nil {
		return openAIToolRound{}, err
	}
	return openAIToolRound{text: text, calls: calls, tokensIn: inTok, tokensOut: outTok}, nil
}

func (l *openAIToolLoop) recordRound(round openAIToolRound) {
	l.tokensIn += round.tokensIn
	l.tokensOut += round.tokensOut
	l.recordAssistantTurn(round.text, round.calls)
}

func (l *openAIToolLoop) recordAssistantTurn(text string, calls []ToolCall) {
	if l.useResponses {
		if text != "" {
			l.respInput = append(l.respInput, oaInputItem{
				Type: "message", Role: "assistant", Content: text,
			})
		}
		for _, call := range calls {
			l.respInput = append(l.respInput, oaInputItem{
				Type:      "function_call",
				CallID:    call.ID,
				Name:      call.Name,
				Arguments: string(call.Input),
			})
		}
		return
	}
	msg := oaToolMessage{Role: "assistant", Content: text}
	for _, call := range calls {
		msg.ToolCalls = append(msg.ToolCalls, oaToolCall{
			ID:   call.ID,
			Type: "function",
			Function: oaToolCallFn{
				Name:      call.Name,
				Arguments: string(call.Input),
			},
		})
	}
	l.chatMsgs = append(l.chatMsgs, msg)
}

func (l *openAIToolLoop) finishIfDone(round openAIToolRound) bool {
	if len(round.calls) != 0 {
		return false
	}
	l.finalText = round.text
	return true
}

func (l *openAIToolLoop) executeToolCalls(ctx context.Context, handler func(context.Context, ToolCall) ToolResult, calls []ToolCall) {
	for _, call := range calls {
		res := normalizeToolResult(call, handler(ctx, call))
		l.steps = append(l.steps, ToolStep{Call: call, Result: res})
		l.recordToolResult(res)
	}
}

func normalizeToolResult(call ToolCall, res ToolResult) ToolResult {
	if res.ID == "" {
		res.ID = call.ID
	}
	return res
}

func (l *openAIToolLoop) recordToolResult(res ToolResult) {
	content := toolResultContent(res)
	if l.useResponses {
		l.respInput = append(l.respInput, oaInputItem{
			Type:   "function_call_output",
			CallID: res.ID,
			Output: content,
		})
		return
	}
	l.chatMsgs = append(l.chatMsgs, oaToolMessage{
		Role:       "tool",
		Content:    content,
		ToolCallID: res.ID,
	})
}

func toolResultContent(res ToolResult) string {
	if res.IsError && !strings.HasPrefix(res.Content, "error:") {
		return "error: " + res.Content
	}
	return res.Content
}

func (l *openAIToolLoop) response(label, model string) ToolResponse {
	provider := label
	if provider == "" {
		provider = "openai"
	}
	return ToolResponse{
		FinalText: l.finalText,
		Steps:     l.steps,
		TokensIn:  l.tokensIn,
		TokensOut: l.tokensOut,
		Provider:  provider,
		Model:     model,
	}
}

// ---- Chat Completions transport ----

type oaToolCallFn struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type oaToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // always "function"
	Function oaToolCallFn `json:"function"`
}

type oaToolMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content,omitempty"`
	Name       string       `json:"name,omitempty"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolDecl struct {
	Type     string         `json:"type"` // "function"
	Function oaFunctionDecl `json:"function"`
}

type oaFunctionDecl struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

type oaChatToolRequest struct {
	Model               string          `json:"model"`
	Messages            []oaToolMessage `json:"messages"`
	Tools               []oaToolDecl    `json:"tools,omitempty"`
	ToolChoice          string          `json:"tool_choice,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	MaxTokens           int             `json:"max_tokens,omitempty"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
}

type oaChatToolResponse struct {
	Choices []struct {
		Message      oaToolMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (c *openAIClient) doChatRound(
	ctx context.Context,
	msgs []oaToolMessage,
	tools []ToolDef,
	temp float64,
	reasoning bool,
) (text string, calls []ToolCall, in, out int, err error) {
	body := c.buildChatToolRequest(msgs, tools, temp, reasoning)
	buf, _ := json.Marshal(body)
	raw, status, herr := c.postJSON(ctx, c.baseURL+"/chat/completions", buf)
	if herr != nil {
		return "", nil, 0, 0, herr
	}
	if status >= 300 {
		return "", nil, 0, 0, openAIHTTPStatusError(c.label, status, raw)
	}
	resp, err := decodeChatToolResponse(c.label, raw)
	if err != nil {
		return "", nil, 0, 0, err
	}
	choice, err := firstChatToolChoice(c.label, resp)
	if err != nil {
		return "", nil, 0, 0, err
	}
	calls = parseChatToolCalls(choice.Message)
	return choice.Message.Content, calls, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, nil
}

func (c *openAIClient) buildChatToolRequest(
	msgs []oaToolMessage,
	tools []ToolDef,
	temp float64,
	reasoning bool,
) oaChatToolRequest {
	body := oaChatToolRequest{
		Model:    c.spec.Model,
		Messages: msgs,
		Tools:    toOAToolDecls(tools),
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = "auto"
	}
	if reasoning {
		body.MaxCompletionTokens = c.spec.MaxTokens
	} else {
		body.MaxTokens = c.spec.MaxTokens
		body.Temperature = &temp
	}
	return body
}

func decodeChatToolResponse(label string, raw []byte) (oaChatToolResponse, error) {
	var resp oaChatToolResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return oaChatToolResponse{}, fmt.Errorf("%s decode: %w; body=%s", label, err, string(raw))
	}
	if resp.Error != nil {
		return oaChatToolResponse{}, errors.New(label + ": " + resp.Error.Message)
	}
	return resp, nil
}

func firstChatToolChoice(label string, resp oaChatToolResponse) (struct {
	Message      oaToolMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}, error) {
	if len(resp.Choices) == 0 {
		return struct {
			Message      oaToolMessage `json:"message"`
			FinishReason string        `json:"finish_reason"`
		}{}, errors.New(label + ": empty choices")
	}
	return resp.Choices[0], nil
}

func parseChatToolCalls(msg oaToolMessage) []ToolCall {
	calls := make([]ToolCall, 0, len(msg.ToolCalls))
	for _, tc := range msg.ToolCalls {
		args := tc.Function.Arguments
		if args == "" {
			args = "{}"
		}
		calls = append(calls, ToolCall{
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: json.RawMessage(args),
		})
	}
	return calls
}

// ---- Responses API transport ----

type oaInputItem struct {
	Type string `json:"type"` // "message" | "function_call" | "function_call_output"
	// "message"
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
	// "function_call"
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
	// "function_call_output"
	Output string `json:"output,omitempty"`
}

type oaResponsesRequest struct {
	Model           string        `json:"model"`
	Instructions    string        `json:"instructions,omitempty"`
	Input           []oaInputItem `json:"input"`
	Tools           []oaToolDecl  `json:"tools,omitempty"`
	ToolChoice      string        `json:"tool_choice,omitempty"`
	Temperature     *float64      `json:"temperature,omitempty"`
	MaxOutputTokens int           `json:"max_output_tokens,omitempty"`
}

// oaResponsesOutputItem covers the union shape returned by /responses.
// We model only the fields we consume.
type oaResponsesOutputItem struct {
	Type string `json:"type"` // "message" | "function_call" | "reasoning" | ...
	// message
	Role    string `json:"role,omitempty"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content,omitempty"`
	// function_call
	CallID    string `json:"call_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type oaResponsesResponse struct {
	Output     []oaResponsesOutputItem `json:"output"`
	OutputText string                  `json:"output_text,omitempty"` // convenience field
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (c *openAIClient) doResponsesRound(
	ctx context.Context,
	system string,
	input []oaInputItem,
	tools []ToolDef,
	temp float64,
	reasoning bool,
) (text string, calls []ToolCall, in, out int, fellBack bool, err error) {
	body := c.buildResponsesRequest(system, input, tools, temp, reasoning)
	buf, _ := json.Marshal(body)
	raw, status, herr := c.postJSON(ctx, c.baseURL+"/responses", buf)
	if herr != nil {
		return "", nil, 0, 0, false, herr
	}
	if status == http.StatusNotFound {
		return "", nil, 0, 0, true, nil
	}
	if status >= 300 {
		return "", nil, 0, 0, false, openAIHTTPStatusError(c.label, status, raw)
	}
	resp, err := decodeResponsesToolResponse(c.label, raw)
	if err != nil {
		return "", nil, 0, 0, false, err
	}
	text, calls = parseResponsesRound(resp)
	return text, calls, resp.Usage.InputTokens, resp.Usage.OutputTokens, false, nil
}

func (c *openAIClient) buildResponsesRequest(
	system string,
	input []oaInputItem,
	tools []ToolDef,
	temp float64,
	reasoning bool,
) oaResponsesRequest {
	body := oaResponsesRequest{
		Model:           c.spec.Model,
		Instructions:    system,
		Input:           input,
		Tools:           toOAToolDecls(tools),
		MaxOutputTokens: c.spec.MaxTokens,
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = "auto"
	}
	if !reasoning {
		body.Temperature = &temp
	}
	return body
}

func decodeResponsesToolResponse(label string, raw []byte) (oaResponsesResponse, error) {
	var resp oaResponsesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return oaResponsesResponse{}, fmt.Errorf("%s decode: %w; body=%s", label, err, string(raw))
	}
	if resp.Error != nil {
		return oaResponsesResponse{}, errors.New(label + ": " + resp.Error.Message)
	}
	return resp, nil
}

func parseResponsesRound(resp oaResponsesResponse) (string, []ToolCall) {
	var (
		textBuf strings.Builder
		calls   []ToolCall
	)
	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			for _, block := range item.Content {
				// "output_text" is the documented type; some proxies use
				// "text" or just dump strings — accept both.
				if block.Type == "output_text" || block.Type == "text" || block.Text != "" {
					textBuf.WriteString(block.Text)
				}
			}
		case "function_call":
			args := item.Arguments
			if args == "" {
				args = "{}"
			}
			calls = append(calls, ToolCall{
				ID:    item.CallID,
				Name:  item.Name,
				Input: json.RawMessage(args),
			})
		}
	}
	text := textBuf.String()
	if text == "" && resp.OutputText != "" {
		text = resp.OutputText
	}
	return text, calls
}

// ---- helpers ----

func openAIHTTPStatusError(label string, status int, raw []byte) error {
	if sentinel := classifyHTTP(status); sentinel != nil {
		return fmt.Errorf("%s http %d: %s: %w", label, status, string(raw), sentinel)
	}
	return fmt.Errorf("%s http %d: %s", label, status, string(raw))
}

func toOAToolDecls(tools []ToolDef) []oaToolDecl {
	if len(tools) == 0 {
		return nil
	}
	out := make([]oaToolDecl, 0, len(tools))
	for _, t := range tools {
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, oaToolDecl{
			Type: "function",
			Function: oaFunctionDecl{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  schema,
			},
		})
	}
	return out
}

// postJSON sends a POST with the openAI client's bearer auth and returns
// raw body + status. Goes through the shared inflight semaphore + retry
// loop (retries on 429 / 5xx with backoff; honors Retry-After). The
// returned status is propagated so the caller can still fall back to
// Chat Completions on a 404 from the Responses API.
func (c *openAIClient) postJSON(ctx context.Context, url string, body []byte) ([]byte, int, error) {
	res, err := doHTTP(ctx, c.http, c.label, func(ctx context.Context) (*http.Request, error) {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if rerr != nil {
			return nil, rerr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		return req, nil
	})
	// doHTTP returns an error for non-2xx that classifyHTTP recognised.
	// For 404 we want the caller to inspect status and fall back, so a
	// 404 returns an ErrBadRequest-wrapped error; convert it back to a
	// status-only return so the existing Responses-fallback path works.
	if err != nil && res.status != 0 && !isRetryable(err) {
		// non-retryable HTTP error: propagate status, swallow the error
		// (caller checks `status >= 300` itself).
		return res.body, res.status, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return res.body, res.status, nil
}
