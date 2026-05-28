package pipeline

import (
	"context"
	"strings"

	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/recon"
)

// stageRecon builds (or reuses) an architecture document for the target
// repository and folds it into the project context so downstream agents
// share scope. Disabled by default — opt-in via recon.enabled: true.
//
// Sampling uses already-parsed files (s.files) and, when available, the
// entry-point list derived from s.astList; we do not require taint or
// inter-procedural analysis to be enabled.
func stageRecon(ctx context.Context, e *Engine, s *runState) error {
	cfg := e.Cfg.Recon
	if cfg.Reuse {
		if existing, err := recon.Load(s.target); err == nil && existing != "" {
			e.logf("recon: reusing existing %s (%d bytes)", recon.FileName, len(existing))
			injectArchitecture(e, existing)
			return nil
		}
	}

	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 40
	}
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 60_000
	}

	var entries []callgraph.Info
	if len(s.astList) > 0 {
		entries = callgraph.Detect(s.astList)
	}

	sample := recon.Sample(s.files, entries, maxFiles)
	if len(sample) == 0 {
		e.logf("recon: nothing to sample, skipping")
		return nil
	}

	agentKey := cfg.Agent
	if agentKey == "" {
		agentKey = "recon"
	}
	spec := e.Cfg.ResolveModel(agentKey)
	client, err := llm.New(spec)
	if err != nil {
		e.logf("recon: llm new: %v (skipping recon)", err)
		return nil
	}

	doc, err := recon.Summarize(ctx, client, sample, entries, maxBytes)
	if err != nil {
		e.logf("recon: summarize: %v (continuing without architecture doc)", err)
		return nil
	}
	if err := recon.Save(s.target, doc); err != nil {
		e.logf("recon: save: %v", err)
	} else {
		e.logf("recon: wrote %d bytes to .llmscan/%s (sampled %d files, %d entry points)",
			len(doc), recon.FileName, len(sample), len(entries))
	}
	injectArchitecture(e, doc)
	return nil
}

// injectArchitecture prepends the architecture document to ProjectContext so
// every agent that consumes ProjectContext receives it.
func injectArchitecture(e *Engine, doc string) {
	if strings.TrimSpace(doc) == "" {
		return
	}
	header := "Repository architecture (recon — read first, scope your reasoning to this):\n"
	if e.Cfg.ProjectContext != "" {
		e.Cfg.ProjectContext = header + doc + "\n\n---\n\n" + e.Cfg.ProjectContext
	} else {
		e.Cfg.ProjectContext = header + doc
	}
}
