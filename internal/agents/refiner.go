// refiner.go implements a map-reduce style refine pass over the findings
// emitted by a single file split into multiple chunks.
//
// Why: when an oversized file is split via chunker.SplitInHalf, each sub-chunk
// is scanned independently and its findings are simply concatenated. That
// loses cross-chunk consistency:
//
//   - the same defect can be reported twice with slightly different rationales
//     (e.g. taint source in chunk A, sink in chunk B);
//   - one chunk can mark a finding "high" while a neighbour marks the same
//     pattern "medium" because the neighbour saw the sanitizer the first
//     didn't;
//   - very long files generate redundant boilerplate findings (logging,
//     error-handling) that look distinct line-by-line but describe one issue.
//
// Refiner does a single LLM "reduce" pass per file once all chunks have been
// scanned, asking the model to consolidate the partial finding lists into a
// canonical one. The reducer never invents new findings — it only merges,
// deduplicates and adjusts severity/confidence based on cross-chunk evidence.
package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Refiner consolidates the per-chunk findings of a single file.
type Refiner struct {
	Client llm.Client
	// MaxFindings caps how many findings we hand to the reducer. Above this
	// the prompt becomes large and the model loses focus. Default 20.
	MaxFindings int
	// PromptOverride replaces refinerSystem when set.
	PromptOverride string
	// Verbose enables Logf diagnostic messages.
	Verbose bool
	Logf    func(format string, args ...any)
}

func (r *Refiner) logf(format string, args ...any) {
	if !r.Verbose || r.Logf == nil {
		return
	}
	r.Logf(format, args...)
}

// refinerDecision is the structured reduce-pass output. Each entry references
// the input findings it consolidates by their ID and carries the final
// severity / confidence / rationale.
type refinerDecision struct {
	Findings []refinerEntry `json:"findings"`
}

type refinerEntry struct {
	// MergedIDs lists IDs from the input list that this entry consolidates.
	// If only one ID is listed, the entry is a pass-through (possibly with
	// adjusted severity/confidence).
	MergedIDs []string `json:"merged_ids"`
	// Drop is true when the reducer believes the listed IDs should be
	// removed entirely (e.g. boilerplate that was already covered by another
	// finding, or duplicate report of the same defect).
	Drop bool `json:"drop"`
	// Final fields override the original values when non-empty.
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Title      string `json:"title,omitempty"`
	Rationale  string `json:"rationale,omitempty"`
}

// Refine consolidates a single file's findings. On any error it returns the
// input unchanged — the refine pass must never regress baseline output.
func (r *Refiner) Refine(ctx context.Context, file string, findings []types.Finding) ([]types.Finding, error) {
	if r == nil || r.Client == nil || len(findings) < 2 {
		return findings, nil
	}
	maxFindings := r.MaxFindings
	if maxFindings <= 0 {
		maxFindings = 20
	}
	if len(findings) > maxFindings {
		// Refine only the head; tail is passed through. Sorting by score is
		// the caller's job — we trust the order given.
		r.logf("refine[%s]: %d findings exceed cap %d, refining head only", file, len(findings), maxFindings)
		head, _ := findings[:maxFindings], findings[maxFindings:]
		refinedHead, err := r.Refine(ctx, file, head)
		if err != nil {
			return findings, err
		}
		return append(refinedHead, findings[maxFindings:]...), nil
	}

	decision, err := r.askReducer(ctx, file, findings)
	if err != nil {
		r.logf("refine[%s]: reducer error: %v (keeping originals)", file, err)
		return findings, nil
	}
	out := applyDecision(findings, decision)
	r.logf("refine[%s]: %d -> %d findings", file, len(findings), len(out))
	return out, nil
}

func (r *Refiner) askReducer(ctx context.Context, file string, findings []types.Finding) (refinerDecision, error) {
	system := r.PromptOverride
	if system == "" {
		system = refinerSystem
	}
	// Compact view — the reducer only needs enough to dedupe and weigh.
	view := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		view = append(view, map[string]any{
			"id":          f.ID,
			"rule_id":     f.RuleID,
			"title":       f.Title,
			"severity":    f.Severity,
			"confidence":  f.Confidence,
			"start_line":  f.StartLine,
			"end_line":    f.EndLine,
			"description": oneLine(f.Description),
			"agent":       f.Agent,
		})
	}
	viewJSON, _ := json.Marshal(view)

	user := fmt.Sprintf(`File: %s
Per-chunk findings emitted by independent scanner passes (JSON):
%s

Consolidate. Output a JSON object:
{
  "findings": [
    {
      "merged_ids": ["id-from-input", "..."],
      "drop": false,
      "severity":   "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "title":     "optional override",
      "rationale": "one short sentence on why merged or kept"
    }
  ]
}

Rules:
  - Every input ID MUST appear in exactly one merged_ids list (no orphans,
    no duplicates).
  - "drop": true removes the listed IDs entirely.
  - When IDs describe the same defect (same rule, overlapping or adjacent
    line range, same root cause), merge them: prefer the highest severity
    and confidence from the inputs unless evidence justifies a downgrade.
  - Do NOT invent new findings. The output is a partition of the input set.
  - When unsure, keep the original as a pass-through (single-element
    merged_ids, no overrides).`, file, string(viewJSON))

	resp, err := r.Client.Complete(ctx, llm.Request{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return refinerDecision{}, err
	}
	var d refinerDecision
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &d); err != nil {
		return refinerDecision{}, fmt.Errorf("refiner: decode: %w; raw=%q", err, truncate(resp.Text, 200))
	}
	return d, nil
}

// applyDecision produces the consolidated finding slice based on the reducer's
// decision. Inputs not referenced in any merged_ids list are kept as-is
// (defensive: never lose data on a malformed decision).
func applyDecision(findings []types.Finding, d refinerDecision) []types.Finding {
	byID := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	seen := make(map[string]struct{}, len(findings))
	out := make([]types.Finding, 0, len(findings))

	for _, entry := range d.Findings {
		ids := uniqueStrings(entry.MergedIDs)
		if len(ids) == 0 {
			continue
		}
		// Mark inputs as seen even when dropped.
		for _, id := range ids {
			seen[id] = struct{}{}
		}
		if entry.Drop {
			continue
		}

		// Pick the strongest input as the base (highest severity, then
		// highest confidence, then earliest line). This preserves trace,
		// gates and all other metadata we cannot reconstruct.
		base, ok := pickBase(ids, byID)
		if !ok {
			continue
		}
		// Apply overrides.
		if s := normSeverity(entry.Severity); s != "" {
			base.Severity = s
		}
		if c := normConfidence(entry.Confidence); c != "" {
			base.Confidence = c
		}
		if t := strings.TrimSpace(entry.Title); t != "" {
			base.Title = t
		}
		if len(ids) > 1 {
			// Merge marker so downstream knows this finding was consolidated.
			base.Tags = appendUnique(base.Tags, "refined")
			if r := strings.TrimSpace(entry.Rationale); r != "" {
				base.VerifierComment = strings.TrimSpace(base.VerifierComment + " | refine: " + r)
			}
		}
		out = append(out, base)
	}

	// Pass-through for any ID the reducer forgot to reference.
	for _, f := range findings {
		if _, ok := seen[f.ID]; !ok {
			out = append(out, f)
		}
	}
	return out
}

func pickBase(ids []string, byID map[string]types.Finding) (types.Finding, bool) {
	sevRank := map[types.Severity]int{
		types.SevCritical: 5,
		types.SevHigh:     4,
		types.SevMedium:   3,
		types.SevLow:      2,
		types.SevInfo:     1,
	}
	confRank := map[types.Confidence]int{
		types.ConfHigh:   3,
		types.ConfMedium: 2,
		types.ConfLow:    1,
	}
	var best types.Finding
	have := false
	for _, id := range ids {
		f, ok := byID[id]
		if !ok {
			continue
		}
		if !have {
			best = f
			have = true
			continue
		}
		if sevRank[f.Severity] > sevRank[best.Severity] {
			best = f
			continue
		}
		if sevRank[f.Severity] == sevRank[best.Severity] && confRank[f.Confidence] > confRank[best.Confidence] {
			best = f
			continue
		}
		if sevRank[f.Severity] == sevRank[best.Severity] && confRank[f.Confidence] == confRank[best.Confidence] && f.StartLine < best.StartLine {
			best = f
		}
	}
	return best, have
}

func normSeverity(s string) types.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SevCritical
	case "high":
		return types.SevHigh
	case "medium":
		return types.SevMedium
	case "low":
		return types.SevLow
	case "info", "informational":
		return types.SevInfo
	}
	return ""
}

func normConfidence(s string) types.Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return types.ConfHigh
	case "medium":
		return types.ConfMedium
	case "low":
		return types.ConfLow
	}
	return ""
}

func uniqueStrings(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

const refinerSystem = `You are a senior application security lead consolidating the output of
multiple scanner passes that each saw a different chunk of one source file.

Your job is reduce-only:
  - Merge findings that describe the SAME defect across chunks (same rule,
    overlapping or adjacent line range, same data-flow).
  - Drop entries that are pure duplicates or boilerplate already covered by
    a stronger finding.
  - Adjust severity/confidence when neighbouring chunks provide evidence
    (e.g. a sanitizer in chunk B downgrades a taint flag in chunk A).
  - NEVER invent new findings. Output must be a partition of the input set.

When in doubt, keep the original entry as a single-element merged_ids
pass-through. Precision over creativity.`
