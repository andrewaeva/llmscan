package pipeline

import (
	"context"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// runRefinePass groups findings by file and, for files that produced >=
// RefineThreshold chunks (i.e. were split by the adaptive chunker), invokes
// the Refiner to consolidate duplicates / boilerplate across chunks. On any
// configuration or LLM error the input is returned unchanged.
func (e *Engine) runRefinePass(ctx context.Context, findings []types.Finding, chunks []types.FileTarget) []types.Finding {
	threshold := e.Cfg.Precision.RefineThreshold
	if threshold <= 0 || len(findings) < 2 {
		return findings
	}

	// Count chunks per file: only split files are interesting.
	chunksByFile := make(map[string]int, len(chunks))
	for _, c := range chunks {
		chunksByFile[c.Path]++
	}

	// Group findings by file, preserving order.
	type group struct {
		idx     []int
		split   bool
		entries []types.Finding
	}
	groups := make(map[string]*group)
	for i, f := range findings {
		g := groups[f.File]
		if g == nil {
			g = &group{split: chunksByFile[f.File] >= threshold}
			groups[f.File] = g
		}
		g.idx = append(g.idx, i)
		g.entries = append(g.entries, f)
	}

	// Anything to do?
	var any bool
	for _, g := range groups {
		if g.split && len(g.entries) >= 2 {
			any = true
			break
		}
	}
	if !any {
		return findings
	}

	cl, err := llm.New(e.Cfg.ResolveModel("verifier"))
	if err != nil {
		e.logf("refine: verifier client unavailable: %v (skipping)", err)
		return findings
	}
	refiner := &agents.Refiner{
		Client:      cl,
		MaxFindings: e.Cfg.Precision.RefineMaxFindings,
		Verbose:     e.Verbose,
		Logf:        e.logf,
	}

	out := make([]types.Finding, 0, len(findings))
	processed := make(map[string]struct{}, len(groups))

	// Walk the original slice to preserve order for files we don't touch.
	for i, f := range findings {
		if _, done := processed[f.File]; done {
			continue
		}
		g := groups[f.File]
		if g == nil || !g.split || len(g.entries) < 2 {
			// Pass-through: emit this finding only when we reach its
			// original position.
			if g != nil && g.idx[0] == i {
				out = append(out, g.entries...)
				processed[f.File] = struct{}{}
			}
			continue
		}
		// Refine this group.
		refined, rerr := refiner.Refine(ctx, f.File, g.entries)
		if rerr != nil {
			e.logf("refine[%s]: %v (keeping originals)", f.File, rerr)
			refined = g.entries
		}
		out = append(out, refined...)
		processed[f.File] = struct{}{}
	}
	return out
}
