package pipeline

import (
	"fmt"
	"sort"

	"github.com/andrewaeva/llmscan/internal/types"
)

// applyPlan reorders files: prioritized first (in plan order), then the rest.
func applyPlan(files []types.FileTarget, plan types.ScanPlan) []types.FileTarget {
	if len(plan.Priority) == 0 {
		return files
	}
	priorityIdx := map[string]int{}
	for i, p := range plan.Priority {
		priorityIdx[p] = i
	}
	type pair struct {
		idx int
		f   types.FileTarget
	}
	prio := make([]pair, 0, len(files))
	rest := make([]types.FileTarget, 0)
	for _, f := range files {
		if i, ok := priorityIdx[f.Path]; ok {
			prio = append(prio, pair{i, f})
		} else {
			rest = append(rest, f)
		}
	}
	sort.Slice(prio, func(i, j int) bool { return prio[i].idx < prio[j].idx })
	out := make([]types.FileTarget, 0, len(files))
	for _, p := range prio {
		out = append(out, p.f)
	}
	out = append(out, rest...)
	return out
}

// dedupAndCount removes findings with identical (agent, file, span, title) keys.
func dedupAndCount(in []types.Finding) []types.Finding {
	seen := map[string]bool{}
	out := make([]types.Finding, 0, len(in))
	for _, f := range in {
		key := fmt.Sprintf("%s|%s|%d|%d|%s", f.Agent, f.File, f.StartLine, f.EndLine, f.Title)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
