package llm

import (
	"context"
	"encoding/json"
	"errors"
)

// ToolDef describes a tool exposed to the model in the messages API.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// ToolCall is a single invocation produced by the model.
type ToolCall struct {
	ID    string          // provider-specific call id
	Name  string          // tool name
	Input json.RawMessage // raw arguments as JSON object
}

// ToolResult is the response back to the model for a ToolCall.
type ToolResult struct {
	ID      string // must match ToolCall.ID
	Content string // textual result (truncated by caller as needed)
	IsError bool
}

// ToolStep is one round-trip of the tool-loop, captured for tracing.
type ToolStep struct {
	Call   ToolCall
	Result ToolResult
}

// ToolHandler executes a single ToolCall and returns its ToolResult.
// Implementations should never panic; they should set IsError=true with a
// short error message instead.
type ToolHandler func(ctx context.Context, call ToolCall) ToolResult

// ToolRequest mirrors Request but carries tools, a handler, and a step budget.
type ToolRequest struct {
	System              string
	Messages            []Message
	Tools               []ToolDef
	Handler             ToolHandler
	MaxSteps            int
	TemperatureOverride *float64
}

// ToolResponse is what the loop returns on completion.
type ToolResponse struct {
	FinalText string
	Steps     []ToolStep
	TokensIn  int
	TokensOut int
	Provider  string
	Model     string
}

// ErrToolsUnsupported is returned by clients that don't (yet) implement the
// tool-calling loop. Currently only the Anthropic client supports it.
var ErrToolsUnsupported = errors.New("llm: tool-calling not supported by this provider")

// ToolClient is implemented by clients that can drive a tool-use loop.
type ToolClient interface {
	Client
	CompleteWithTools(ctx context.Context, req ToolRequest) (ToolResponse, error)
}
