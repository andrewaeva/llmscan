package pipeline

import (
	"context"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

type refineGroup struct {
	idx     []int
	split   bool
	entries []types.Finding
}

// runRefinePass groups findings by file and, for files that produced >=
// RefineThreshold chunks (i.e. were split by the adaptive chunker), invokes
// the Refiner to consolidate duplicates / boilerplate across chunks. On any
// configuration or LLM error the input is returned unchanged.
func (e *Engine) runRefinePass(ctx context.Context, findings []types.Finding, chunks []types.FileTarget) []types.Finding {
	threshold := e.Cfg.Precision.RefineThreshold
	if threshold <= 0 || len(findings) < 2 {
		return findings
	}

	groups := buildRefineGroups(findings, chunks, threshold)
	if !hasRefinableGroups(groups) {
		return findings
	}

	refiner, ok := e.newRefiner()
	if !ok {
		return findings
	}

	out := make([]types.Finding, 0, len(findings))
	processed := make(map[string]struct{}, len(groups))
	for i, f := range findings {
		if _, done := processed[f.File]; done {
			continue
		}
		out = e.appendRefineGroup(ctx, out, processed, groups, refiner, i, f)
	}
	return out
}

func buildRefineGroups(findings []types.Finding, chunks []types.FileTarget, threshold int) map[string]*refineGroup {
	chunksByFile := make(map[string]int, len(chunks))
	for _, c := range chunks {
		chunksByFile[c.Path]++
	}

	groups := make(map[string]*refineGroup)
	for i, f := range findings {
		g := groups[f.File]
		if g == nil {
			g = &refineGroup{split: chunksByFile[f.File] >= threshold}
			groups[f.File] = g
		}
		g.idx = append(g.idx, i)
		g.entries = append(g.entries, f)
	}
	return groups
}

func hasRefinableGroups(groups map[string]*refineGroup) bool {
	for _, g := range groups {
		if shouldRefineGroup(g) {
			return true
		}
	}
	return false
}

func shouldRefineGroup(g *refineGroup) bool {
	return g != nil && g.split && len(g.entries) >= 2
}

func (e *Engine) newRefiner() (*agents.Refiner, bool) {
	cl, err := llm.New(e.Cfg.ResolveModel("verifier"))
	if err != nil {
		e.logf("refine: verifier client unavailable: %v (skipping)", err)
		return nil, false
	}
	return &agents.Refiner{
		Client:      cl,
		MaxFindings: e.Cfg.Precision.RefineMaxFindings,
		Verbose:     e.Verbose,
		Logf:        e.logf,
	}, true
}

func (e *Engine) appendRefineGroup(
	ctx context.Context,
	out []types.Finding,
	processed map[string]struct{},
	groups map[string]*refineGroup,
	refiner *agents.Refiner,
	i int,
	f types.Finding,
) []types.Finding {
	g := groups[f.File]
	if !shouldRefineGroup(g) {
		return appendPassThroughGroup(out, processed, g, i, f.File)
	}

	refined, err := refiner.Refine(ctx, f.File, g.entries)
	if err != nil {
		e.logf("refine[%s]: %v (keeping originals)", f.File, err)
		refined = g.entries
	}
	processed[f.File] = struct{}{}
	return append(out, refined...)
}

func appendPassThroughGroup(out []types.Finding, processed map[string]struct{}, g *refineGroup, i int, file string) []types.Finding {
	if g == nil || g.idx[0] != i {
		return out
	}
	processed[file] = struct{}{}
	return append(out, g.entries...)
}
