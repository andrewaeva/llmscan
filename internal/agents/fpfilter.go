package agents

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// FPFilter performs a final pass over the verified findings to dedup/merge/drop.
type FPFilter struct {
	Client llm.Client
}

type filterJSON struct {
	Kept    []string `json:"kept"`
	Dropped []struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	} `json:"dropped"`
	Merges []struct {
		Keep  string   `json:"keep"`
		Merge []string `json:"merge"`
	} `json:"merges"`
}

// Apply drops/merges findings; returns the filtered slice.
func (f *FPFilter) Apply(ctx context.Context, findings []types.Finding) ([]types.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}
	// First: deterministic pass.
	findings = dedupDeterministic(findings)

	// Then: LLM pass (only if client available).
	if f.Client == nil {
		return findings, nil
	}
	// Build a compact summary for the LLM.
	type item struct {
		ID         string `json:"id"`
		Agent      string `json:"agent"`
		File       string `json:"file"`
		Line       int    `json:"line"`
		Title      string `json:"title"`
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		FP         bool   `json:"false_positive"`
	}
	items := make([]item, 0, len(findings))
	for _, fnd := range findings {
		items = append(items, item{
			ID: fnd.ID, Agent: fnd.Agent, File: fnd.File, Line: fnd.StartLine,
			Title: fnd.Title, Severity: string(fnd.Severity),
			Confidence: string(fnd.Confidence), FP: fnd.FalsePositive,
		})
	}
	resp, err := f.Client.Complete(ctx, llm.Request{
		System:   fpFilterSystem,
		Messages: []llm.Message{{Role: "user", Content: mustJSON(items)}},
		JSON:     true,
	})
	if err != nil {
		return findings, err
	}
	var fj filterJSON
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &fj); err != nil {
		return findings, fmt.Errorf("fp_filter decode: %w; raw=%q", err, truncate(resp.Text, 300))
	}
	kept := make(map[string]bool, len(fj.Kept))
	for _, id := range fj.Kept {
		kept[id] = true
	}
	droppedReasons := make(map[string]string, len(fj.Dropped))
	for _, d := range fj.Dropped {
		droppedReasons[d.ID] = d.Reason
	}
	// If kept is empty, treat as "keep all not explicitly dropped".
	useDropOnly := len(kept) == 0
	out := make([]types.Finding, 0, len(findings))
	for _, fnd := range findings {
		drop := false
		if useDropOnly {
			if _, ok := droppedReasons[fnd.ID]; ok {
				drop = true
			}
		} else {
			drop = !kept[fnd.ID]
		}
		if drop {
			fnd.FalsePositive = true
			if fnd.FPReason == "" {
				fnd.FPReason = droppedReasons[fnd.ID]
				if fnd.FPReason == "" {
					fnd.FPReason = "fp_filter dropped"
				}
			}
		}
		out = append(out, fnd)
	}
	return out, nil
}

func dedupDeterministic(in []types.Finding) []types.Finding {
	seen := map[string]int{} // key -> index in out
	var out []types.Finding
	for _, f := range in {
		key := fmt.Sprintf("%s|%s|%d|%d|%s", f.Agent, f.File, f.StartLine, f.EndLine, f.RuleID)
		if i, ok := seen[key]; ok {
			// keep higher-confidence/severity
			if rank(f.Severity, f.Confidence) > rank(out[i].Severity, out[i].Confidence) {
				out[i] = f
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	return out
}

func rank(s types.Severity, c types.Confidence) int {
	sv := map[types.Severity]int{types.SevCritical: 5, types.SevHigh: 4, types.SevMedium: 3, types.SevLow: 2, types.SevInfo: 1}[s]
	cv := map[types.Confidence]int{types.ConfHigh: 3, types.ConfMedium: 2, types.ConfLow: 1}[c]
	return sv*10 + cv
}
