package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Scanner is a single specialized vulnerability hunter.
type Scanner struct {
	Name   string
	Client llm.Client
	// PromptOverride: if non-empty, replaces the system prompt template entirely.
	// Used when a Scanner is loaded from a SKILL.md.
	PromptOverride string
	// Scope: free-form description used when no prompt override is given.
	Scope string
}

// Scan analyzes a single file (chunk). `extraContext` is optional retrieved code
// (from RAG + ContextFilter) that gets appended to the prompt.
func (s *Scanner) Scan(ctx context.Context, f types.FileTarget, extraContext string) ([]types.Finding, error) {
	var system string
	if s.PromptOverride != "" {
		system = s.PromptOverride
	} else {
		scope := s.Scope
		if scope == "" {
			scope = scopeForAgent(s.Name)
		}
		system = fmt.Sprintf(scannerSystemTemplate, s.Name, scope)
	}
	user := fmt.Sprintf("File: %s\nLanguage: %s\nChunk: %d/%d (line offset %d)\n\n```%s\n%s\n```",
		f.Path, f.Language, f.ChunkIdx+1, max(1, f.ChunkTotal), f.LineOffset, f.Language, f.Content)
	if extraContext != "" {
		user += "\n\n" + extraContext
	}
	resp, err := s.Client.Complete(ctx, llm.Request{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Findings []types.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &parsed); err != nil {
		return nil, fmt.Errorf("%s: decode: %w; raw=%q", s.Name, err, truncate(resp.Text, 300))
	}
	now := time.Now()
	out := make([]types.Finding, 0, len(parsed.Findings))
	for i, fnd := range parsed.Findings {
		fnd.Agent = s.Name
		fnd.File = f.Path
		fnd.StartLine += f.LineOffset
		fnd.EndLine += f.LineOffset
		if fnd.ID == "" {
			fnd.ID = fmt.Sprintf("%s-%s-%d-%d", s.Name, hash6(f.Path), fnd.StartLine, i)
		}
		fnd.CreatedAt = now
		if fnd.Severity == "" {
			fnd.Severity = types.SevMedium
		}
		if fnd.Confidence == "" {
			fnd.Confidence = types.ConfMedium
		}
		out = append(out, fnd)
	}
	return out, nil
}
