package agents

import (
	"context"
	"errors"
	"os"
	"sync/atomic"

	"github.com/andrewaeva/llmscan/internal/llm"
)

func writeFileAtomic(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644)
}

// stubClient is a minimal llm.Client used by every agent test.
// It scripts a sequence of textual responses (or errors) and remembers
// the last Request received for assertions.
type stubClient struct {
	name      string
	responses []string
	errs      []error
	calls     int32
	last      llm.Request
}

func (s *stubClient) Name() string {
	if s.name == "" {
		return "stub"
	}
	return s.name
}

func (s *stubClient) Complete(_ context.Context, req llm.Request) (llm.Response, error) {
	i := int(atomic.AddInt32(&s.calls, 1)) - 1
	s.last = req
	if i < len(s.errs) && s.errs[i] != nil {
		return llm.Response{}, s.errs[i]
	}
	if i >= len(s.responses) {
		if len(s.responses) == 0 {
			return llm.Response{}, errors.New("stubClient: no responses scripted")
		}
		return llm.Response{Text: s.responses[len(s.responses)-1], Model: "stub-model"}, nil
	}
	return llm.Response{Text: s.responses[i], Model: "stub-model"}, nil
}

// stubToolClient extends stubClient and implements ToolClient.
// CompleteWithTools always returns the scripted ToolResponse.
type stubToolClient struct {
	stubClient
	toolResp   llm.ToolResponse
	toolErr    error
	gotRequest llm.ToolRequest
}

func (s *stubToolClient) CompleteWithTools(ctx context.Context, req llm.ToolRequest) (llm.ToolResponse, error) {
	s.gotRequest = req
	if s.toolErr != nil {
		return llm.ToolResponse{}, s.toolErr
	}
	// Optionally invoke the handler so we observe at least one tool step.
	return s.toolResp, nil
}
