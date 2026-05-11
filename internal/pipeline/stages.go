package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andrewaeva/llmscan/internal/agents"
	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/gitdiff"
	"github.com/andrewaeva/llmscan/internal/iac"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/secrets"
	"github.com/andrewaeva/llmscan/internal/skills"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// ---- AST parsing & skills loading ----

// parseASTs concurrently parses files into per-language ASTs.
func (e *Engine) parseASTs(ctx context.Context, files []types.FileTarget) (map[string]*myast.FileAST, []*myast.FileAST) {
	out := make(map[string]*myast.FileAST, len(files))
	var mu sync.Mutex
	var wg sync.WaitGroup
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	for _, f := range files {
		if myast.Detect(f.Path) == myast.LangUnknown {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(f types.FileTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			a, err := myast.Parse(ctx, f.Path, []byte(f.Content))
			if err != nil {
				e.logf("ast %s: %v", f.Path, err)
				return
			}
			mu.Lock()
			out[f.Path] = a
			mu.Unlock()
		}(f)
	}
	wg.Wait()
	list := make([]*myast.FileAST, 0, len(out))
	for _, a := range out {
		list = append(list, a)
	}
	return out, list
}

// loadSkills loads all enabled skills from configured directories.
func (e *Engine) loadSkills() map[string]*skills.Skill {
	out := map[string]*skills.Skill{}
	for _, dir := range e.Cfg.Skills.Dirs {
		s, errs := skills.LoadDir(dir)
		for _, err := range errs {
			e.logf("skill: %v", err)
		}
		for _, sk := range s {
			out[sk.Name] = sk
		}
	}
	return out
}

// ---- Pre-filters and lightweight static analyses ----

// applyDiffFilter narrows files to those changed in the configured diff range.
func (e *Engine) applyDiffFilter(files []types.FileTarget, target string) []types.FileTarget {
	if !gitdiff.IsRepo(target) {
		e.logf("diff: %s is not a git repo, ignoring", target)
		return files
	}
	changed, err := gitdiff.ChangedFiles(target, e.Cfg.Diff.Range)
	if err != nil {
		e.logf("diff: %v", err)
		return files
	}
	set := map[string]bool{}
	for _, p := range changed {
		set[p] = true
	}
	var out []types.FileTarget
	for _, f := range files {
		if set[f.Path] {
			out = append(out, f)
		}
	}
	return out
}

// applyWatchlistPreFilter drops files unlikely to contain taint sources/sinks.
func (e *Engine) applyWatchlistPreFilter(files []types.FileTarget, astByPath map[string]*myast.FileAST) []types.FileTarget {
	var out []types.FileTarget
	for _, f := range files {
		// Always keep IaC and unknown languages (no watchlist coverage).
		if iac.Detect(f.Path, f.Content) != iac.KindNone {
			out = append(out, f)
			continue
		}
		if _, ok := astByPath[f.Path]; !ok {
			out = append(out, f)
			continue
		}
		if watchlist.HasHit(f.Language, f.Content, watchlist.KindSource, watchlist.KindSink) {
			out = append(out, f)
		}
	}
	return out
}

// collectSuppressions extracts all // llmscan:ignore directives from source.
func (e *Engine) collectSuppressions(files []types.FileTarget) []suppress.Suppression {
	var all []suppress.Suppression
	for _, f := range files {
		all = append(all, suppress.Parse(f.Path, f.Content)...)
	}
	return all
}

// runSecretsPreFilter performs deterministic secret detection before any LLM call.
func (e *Engine) runSecretsPreFilter(files []types.FileTarget) []types.Finding {
	var out []types.Finding
	for _, f := range files {
		for _, m := range secrets.ScanText(f.Path, f.Content) {
			out = append(out, types.Finding{
				ID:          fmt.Sprintf("secrets-%s-%s:%d", m.RuleID, f.Path, m.Line),
				RuleID:      m.RuleID,
				Title:       m.Title,
				Description: fmt.Sprintf("Pre-filter match (entropy=%.2f, snippet=%s)", m.Entropy, m.Snippet),
				Severity:    types.Severity(m.Severity),
				Confidence:  types.ConfHigh,
				Score:       0.95,
				CWE:         m.CWE,
				File:        f.Path,
				StartLine:   m.Line,
				EndLine:     m.Line,
				CodeSample:  m.Snippet,
				Agent:       "secrets-prefilter",
				Verified:    true,
				Tags:        []string{"secrets", "deterministic"},
				CreatedAt:   time.Now(),
			})
		}
	}
	return out
}

// ---- Orchestrator plan + RAG index ----

// planStep asks the orchestrator agent for a scan plan, with graph-derived fallback.
func (e *Engine) planStep(ctx context.Context, target string, files []types.FileTarget, g *depgraph.Graph) (types.ScanPlan, error) {
	if !e.Cfg.IsAgentEnabled("orchestrator") {
		return fallbackPlan(files, g), nil
	}
	client, err := llm.New(e.Cfg.ResolveModel("orchestrator"))
	if err != nil {
		return fallbackPlan(files, g), err
	}
	orch := &agents.Orchestrator{Client: client}
	plan, err := orch.Plan(ctx, target, files, e.Cfg.ProjectContext)
	if err != nil {
		return fallbackPlan(files, g), err
	}
	// Augment plan: prepend top fan-in files so high-blast-radius modules get scanned first.
	topByFanIn := g.TopRankedByFanIn()
	if len(topByFanIn) > 0 {
		seen := map[string]bool{}
		merged := make([]string, 0, len(plan.Priority)+len(topByFanIn))
		for _, p := range topByFanIn[:min(15, len(topByFanIn))] {
			if !seen[p] {
				merged = append(merged, p)
				seen[p] = true
			}
		}
		for _, p := range plan.Priority {
			if !seen[p] {
				merged = append(merged, p)
				seen[p] = true
			}
		}
		plan.Priority = merged
	}
	return plan, nil
}

// fallbackPlan builds a graph-based priority when the orchestrator is unavailable.
func fallbackPlan(files []types.FileTarget, g *depgraph.Graph) types.ScanPlan {
	pri := g.TopRankedByFanIn()
	if len(pri) == 0 {
		pri = make([]string, 0, len(files))
		for _, f := range files {
			pri = append(pri, f.Path)
		}
	}
	return types.ScanPlan{Reasoning: "fallback: orchestrator unavailable", Priority: pri, Focus: agents.ScannerNames}
}

// buildRAG initializes the RAG index, falling back to keyword search if no embedder available.
func (e *Engine) buildRAG(ctx context.Context, files []types.FileTarget, astByPath map[string]*myast.FileAST) *rag.Index {
	emb, err := rag.NewEmbedder(rag.EmbedderSpec{
		Provider:  e.Cfg.RAG.Provider,
		Model:     e.Cfg.RAG.Model,
		BaseURL:   e.Cfg.RAG.BaseURL,
		APIKeyEnv: e.Cfg.RAG.APIKeyEnv,
	})
	if err != nil {
		e.logf("rag embedder disabled: %v (RAG falls back to keyword search)", err)
	}
	srcs := map[string][]byte{}
	for _, f := range files {
		srcs[f.Path] = []byte(f.Content)
	}
	chunks := rag.ChunkFiles(srcs, astByPath, e.Cfg.RAG.ChunkLines)
	idx := rag.New(emb)
	if err := idx.Index(ctx, chunks, e.Cfg.RAG.BatchSize); err != nil {
		e.logf("rag index: %v", err)
	}
	e.logf("rag indexed %d chunks (embedder=%v)", idx.Size(), embedderName(emb))
	return idx
}

func embedderName(e rag.Embedder) string {
	if e == nil {
		return "keyword-only"
	}
	return e.Name()
}
