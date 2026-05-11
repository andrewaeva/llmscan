package pipeline

import (
	"context"

	"github.com/andrewaeva/llmscan/internal/agents"
	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/types"
)

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
