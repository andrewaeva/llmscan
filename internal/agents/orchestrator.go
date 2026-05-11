package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Orchestrator builds a high-level scan plan from a tree of file paths.
type Orchestrator struct {
	Client llm.Client
}

func (o *Orchestrator) Plan(ctx context.Context, target string, files []types.FileTarget, projectContext string) (types.ScanPlan, error) {
	if o.Client == nil {
		return fallbackPlan(files), nil
	}
	// Build a compact tree listing (path + size in lines).
	var b strings.Builder
	for i, f := range files {
		if i >= 600 { // cap to keep prompt small
			fmt.Fprintf(&b, "... (%d more files)\n", len(files)-i)
			break
		}
		fmt.Fprintf(&b, "- %s [%s, %d lines]\n", f.Path, f.Language, f.Lines)
	}
	user := fmt.Sprintf("Target: %s\nProject context: %s\n\nFiles:\n%s",
		target,
		emptyIf(projectContext, "(none)"),
		b.String())
	resp, err := o.Client.Complete(ctx, llm.Request{
		System:   orchestratorSystem,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return fallbackPlan(files), err
	}
	var plan types.ScanPlan
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &plan); err != nil {
		return fallbackPlan(files), fmt.Errorf("decode plan: %w", err)
	}
	if len(plan.Priority) == 0 {
		plan = fallbackPlan(files)
	}
	if len(plan.Focus) == 0 {
		plan.Focus = append(plan.Focus, ScannerNames...)
	}
	return plan, nil
}

func fallbackPlan(files []types.FileTarget) types.ScanPlan {
	pri := make([]string, 0, len(files))
	for _, f := range files {
		pri = append(pri, f.Path)
	}
	return types.ScanPlan{
		Reasoning: "fallback: orchestrator unavailable, scanning all discovered files",
		Priority:  pri,
		Focus:     append([]string{}, ScannerNames...),
	}
}
