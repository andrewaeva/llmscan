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

// CompleteWithTools drives the OpenAI tool-use loop until the model returns
// a final assistant message with no tool calls, or MaxSteps is exhausted.
//
//nolint:gocyclo // single-method state machine; splitting hurts readability
func (c *openAIClient) CompleteWithTools(ctx context.Context, req ToolRequest) (ToolResponse, error) {
	if req.Handler == nil {
		return ToolResponse{}, errors.New(c.label + ": nil tool handler")
	}
	if req.MaxSteps <= 0 {
		req.MaxSteps = 20
	}

	useResponses := modelUsesMaxCompletionTokens(c.spec.Model)

	// Seed conversation. For Chat Completions we keep oaToolMessage; for
	// Responses we keep oaInputItem. Only one path is active at a time but
	// fallback may flip from Responses to Chat mid-loop, so we maintain a
	// minimal lossless source of truth (the original messages + the
	// accumulated tool round trips) and re-materialize for each transport.
	chatMsgs := make([]oaToolMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		chatMsgs = append(chatMsgs, oaToolMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		if m.Role == "" {
			continue
		}
		chatMsgs = append(chatMsgs, oaToolMessage{Role: m.Role, Content: m.Content})
	}

	// Responses input mirrors chatMsgs but each item is wrapped in
	// {type:"message", role, content}. The system prompt is carried in the
	// dedicated `instructions` field, not inside `input`.
	respInput := make([]oaInputItem, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" || m.Role == "" {
			continue
		}
		respInput = append(respInput, oaInputItem{
			Type:    "message",
			Role:    m.Role,
			Content: m.Content,
		})
	}

	tools := req.Tools
	temp := c.spec.Temperature
	if req.TemperatureOverride != nil {
		temp = *req.TemperatureOverride
	}
	reasoning := modelUsesMaxCompletionTokens(c.spec.Model)

	var (
		steps     []ToolStep
		tokensIn  int
		tokensOut int
		finalText string
	)

	for step := 0; step < req.MaxSteps; step++ {
		var (
			text       string
			calls      []ToolCall
			inTok      int
			outTok     int
			fellBack   bool
			finishedOK bool
			err        error
		)

		if useResponses {
			text, calls, inTok, outTok, fellBack, err = c.doResponsesRound(ctx, req.System, respInput, tools, temp, reasoning)
			if err != nil {
				return ToolResponse{}, err
			}
			if fellBack {
				// Permanent flip for the remainder of the loop.
				useResponses = false
				text, calls, inTok, outTok, err = c.doChatRound(ctx, chatMsgs, tools, temp, reasoning)
				if err != nil {
					return ToolResponse{}, err
				}
			}
			finishedOK = true
		} else {
			text, calls, inTok, outTok, err = c.doChatRound(ctx, chatMsgs, tools, temp, reasoning)
			if err != nil {
				return ToolResponse{}, err
			}
			finishedOK = true
		}
		_ = finishedOK
		tokensIn += inTok
		tokensOut += outTok

		// Record the assistant turn so the next round sees it.
		if useResponses {
			if text != "" {
				respInput = append(respInput, oaInputItem{
					Type: "message", Role: "assistant", Content: text,
				})
			}
			for _, call := range calls {
				respInput = append(respInput, oaInputItem{
					Type:      "function_call",
					CallID:    call.ID,
					Name:      call.Name,
					Arguments: string(call.Input),
				})
			}
		} else {
			am := oaToolMessage{Role: "assistant", Content: text}
			for _, call := range calls {
				am.ToolCalls = append(am.ToolCalls, oaToolCall{
					ID:   call.ID,
					Type: "function",
					Function: oaToolCallFn{
						Name:      call.Name,
						Arguments: string(call.Input),
					},
				})
			}
			chatMsgs = append(chatMsgs, am)
		}

		if len(calls) == 0 {
			finalText = text
			break
		}

		// Execute each tool and record the result on both transcripts
		// (so a mid-loop Responses→Chat fallback can still recover state).
		for _, call := range calls {
			res := req.Handler(ctx, call)
			if res.ID == "" {
				res.ID = call.ID
			}
			steps = append(steps, ToolStep{Call: call, Result: res})

			content := res.Content
			if res.IsError && !strings.HasPrefix(content, "error:") {
				content = "error: " + content
			}
			if useResponses {
				respInput = append(respInput, oaInputItem{
					Type:   "function_call_output",
					CallID: res.ID,
					Output: content,
				})
			} else {
				chatMsgs = append(chatMsgs, oaToolMessage{
					Role:       "tool",
					Content:    content,
					ToolCallID: res.ID,
				})
			}
		}
	}

	provider := c.label
	if provider == "" {
		provider = "openai"
	}
	return ToolResponse{
		FinalText: finalText,
		Steps:     steps,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
		Provider:  provider,
		Model:     c.spec.Model,
	}, nil
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
	Model               string         `json:"model"`
	Messages            []oaToolMessage `json:"messages"`
	Tools               []oaToolDecl   `json:"tools,omitempty"`
	ToolChoice          string         `json:"tool_choice,omitempty"`
	Temperature         *float64       `json:"temperature,omitempty"`
	MaxTokens           int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens int            `json:"max_completion_tokens,omitempty"`
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
	buf, _ := json.Marshal(body)
	raw, status, herr := c.postJSON(ctx, c.baseURL+"/chat/completions", buf)
	if herr != nil {
		return "", nil, 0, 0, herr
	}
	if status >= 300 {
		if sentinel := classifyHTTP(status); sentinel != nil {
			return "", nil, 0, 0, fmt.Errorf("%s http %d: %s: %w", c.label, status, string(raw), sentinel)
		}
		return "", nil, 0, 0, fmt.Errorf("%s http %d: %s", c.label, status, string(raw))
	}
	var resp oaChatToolResponse
	if jerr := json.Unmarshal(raw, &resp); jerr != nil {
		return "", nil, 0, 0, fmt.Errorf("%s decode: %w; body=%s", c.label, jerr, string(raw))
	}
	if resp.Error != nil {
		return "", nil, 0, 0, errors.New(c.label + ": " + resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return "", nil, 0, 0, errors.New(c.label + ": empty choices")
	}
	choice := resp.Choices[0]
	for _, tc := range choice.Message.ToolCalls {
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
	return choice.Message.Content, calls, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, nil
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
	Model               string         `json:"model"`
	Instructions        string         `json:"instructions,omitempty"`
	Input               []oaInputItem  `json:"input"`
	Tools               []oaToolDecl   `json:"tools,omitempty"`
	ToolChoice          string         `json:"tool_choice,omitempty"`
	Temperature         *float64       `json:"temperature,omitempty"`
	MaxOutputTokens     int            `json:"max_output_tokens,omitempty"`
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
	buf, _ := json.Marshal(body)
	raw, status, herr := c.postJSON(ctx, c.baseURL+"/responses", buf)
	if herr != nil {
		return "", nil, 0, 0, false, herr
	}
	if status == http.StatusNotFound {
		return "", nil, 0, 0, true, nil
	}
	if status >= 300 {
		if sentinel := classifyHTTP(status); sentinel != nil {
			return "", nil, 0, 0, false, fmt.Errorf("%s http %d: %s: %w", c.label, status, string(raw), sentinel)
		}
		return "", nil, 0, 0, false, fmt.Errorf("%s http %d: %s", c.label, status, string(raw))
	}
	var resp oaResponsesResponse
	if jerr := json.Unmarshal(raw, &resp); jerr != nil {
		return "", nil, 0, 0, false, fmt.Errorf("%s decode: %w; body=%s", c.label, jerr, string(raw))
	}
	if resp.Error != nil {
		return "", nil, 0, 0, false, errors.New(c.label + ": " + resp.Error.Message)
	}

	var textBuf strings.Builder
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
	text = textBuf.String()
	if text == "" && resp.OutputText != "" {
		text = resp.OutputText
	}
	return text, calls, resp.Usage.InputTokens, resp.Usage.OutputTokens, false, nil
}

// ---- helpers ----

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
