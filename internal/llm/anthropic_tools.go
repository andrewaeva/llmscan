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
)

// anthropic tool-use wire types.

type antToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type antToolBlock struct {
	Type      string          `json:"type"`                 // "text" | "tool_use" | "tool_result"
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`         // for tool_use
	Name      string          `json:"name,omitempty"`       // for tool_use
	Input     json.RawMessage `json:"input,omitempty"`      // for tool_use
	ToolUseID string          `json:"tool_use_id,omitempty"` // for tool_result
	Content   string          `json:"content,omitempty"`    // for tool_result (string form)
	IsError   bool            `json:"is_error,omitempty"`   // for tool_result
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
		tools = append(tools, antToolDef{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
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
		steps       []ToolStep
		tokensIn    int
		tokensOut   int
		finalText   string
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
			// Model produced its final answer.
			finalText = textBuf.String()
			break
		}

		// Otherwise feed all tool results back in one user turn and loop.
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
		return nil, fmt.Errorf("anthropic http %d: %s", resp.StatusCode, string(raw))
	}
	return raw, nil
}

