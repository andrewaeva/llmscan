package pipeline

import (
	"context"
	"strings"

	"github.com/andrewaeva/llmscan/internal/knowledge"
	"github.com/andrewaeva/llmscan/internal/llm"
)

// stageLoadKnowledge reads .llmscan/knowledge.md (if any) and PREPENDS it to
// Cfg.ProjectContext so the orchestrator and downstream prompts see the
// distilled architecture / stack / patterns from prior scans.
//
// We mutate Cfg in-place for this run. This is safe because the Engine value
// is per-scan and not shared. The original ProjectContext is preserved at the
// end of the merged string so user-supplied context still wins.
func stageLoadKnowledge(_ context.Context, e *Engine, s *runState) error {
	body, err := knowledge.Load(s.target)
	if err != nil {
		e.logf("knowledge: load failed: %v (continuing without)", err)
		return nil
	}
	if body == "" {
		e.logf("knowledge: no prior file (first scan)")
		return nil
	}
	header := "Project knowledge (distilled from prior scans):\n"
	merged := header + body
	if strings.TrimSpace(e.Cfg.ProjectContext) != "" {
		merged += "\n\nUser-supplied context:\n" + e.Cfg.ProjectContext
	}
	e.Cfg.ProjectContext = merged
	e.logf("knowledge: loaded %d bytes into project context", len(body))
	return nil
}

// stageWriteKnowledge regenerates .llmscan/knowledge.md from the current
// findings, file layout, and previous knowledge. Runs at the very end so it
// can use the final (post-deep, post-FP) finding list.
//
// On any failure (LLM unavailable, write error) we leave the existing file
// untouched.
func stageWriteKnowledge(ctx context.Context, e *Engine, s *runState) error {
	spec := e.Cfg.ResolveModel("verifier")
	client, err := llm.New(spec)
	if err != nil {
		e.logf("knowledge: writer disabled: %v", err)
		return nil
	}
	client = llm.Tag(client, "knowledge")
	prev, _ := knowledge.Load(s.target)
	layout, lerr := knowledge.CollectLayout(s.target, 60)
	if lerr != nil {
		e.logf("knowledge: layout: %v", lerr)
	}
	out, sumErr := knowledge.Summarize(ctx, client, prev, layout, s.final)
	if sumErr != nil {
		e.logf("knowledge: summarize: %v (keeping previous file)", sumErr)
		return nil
	}
	if err := knowledge.Save(s.target, out); err != nil {
		e.logf("knowledge: save: %v", err)
		return nil
	}
	e.logf("knowledge: wrote %d bytes to .llmscan/%s", len(out), knowledge.FileName)
	return nil
}
