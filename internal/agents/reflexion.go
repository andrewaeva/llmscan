// reflexion.go implements a Reflexion loop wrapper around Scanner.
//
// The pattern (from the Reflexion paper, adapted to security scanning):
//
//  1. Generate: Scanner.Scan produces an initial finding list.
//  2. Critique: a critic LLM reviews the findings against the original code
//     and flags spurious / weak / missed items.
//  3. Revise: the same scanner re-scans the chunk with the critique injected
//     into its extra context, producing a refined finding list.
//
// Useful for "noisy" skills (e.g. business-logic / error-handling / generic)
// where naive prompts over-flag. Disabled by default; enabled per-skill via
// precision.reflexion + precision.reflexion_skills.
package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// ReflexionScanner wraps a Scanner with a critique-and-revise loop.
// It satisfies the same interface the pipeline expects (Scan method).
type ReflexionScanner struct {
	// Inner is the base scanner that does the actual generation.
	Inner *Scanner
	// Critic is the LLM used to critique the inner scanner's output. It is
	// typically the same model as Inner.Client but a separate value lets
	// callers downgrade to a cheaper model.
	Critic llm.Client
	// MaxIters caps the critique-revise rounds. 0 -> 1 (single revision).
	// Values >2 rarely help and burn tokens.
	MaxIters int
	// CritiquePromptOverride replaces reflexionCriticSystem when set.
	CritiquePromptOverride string
	// Verbose enables per-chunk diagnostic logs via Logf.
	Verbose bool
	Logf    func(format string, args ...any)
}

func (r *ReflexionScanner) logf(format string, args ...any) {
	if !r.Verbose || r.Logf == nil {
		return
	}
	r.Logf(format, args...)
}

// Scan runs the generate → critique → revise loop and returns the revised
// findings. Falls back to the inner scanner's output on critic / revise
// errors, so reflexion never makes a chunk worse than baseline.
func (r *ReflexionScanner) Scan(ctx context.Context, f types.FileTarget, extraContext string) ([]types.Finding, error) {
	if r.Inner == nil {
		return nil, fmt.Errorf("reflexion: nil inner scanner")
	}
	iters := r.MaxIters
	if iters <= 0 {
		iters = 1
	}

	// Phase 1: generate.
	initial, err := r.Inner.Scan(ctx, f, extraContext)
	if err != nil {
		return nil, err
	}
	current := initial
	for i := 0; i < iters; i++ {
		critique, cerr := r.critique(ctx, f, current)
		if cerr != nil {
			r.logf("reflexion[%s] critic iter=%d: %v (keeping current findings)", r.Inner.Name, i, cerr)
			return current, nil
		}
		// If the critic has nothing material to add, stop early.
		if !critique.HasFeedback() {
			r.logf("reflexion[%s] critic iter=%d: no actionable feedback, stopping", r.Inner.Name, i)
			return current, nil
		}

		// Phase 3: revise — re-run scanner with critique injected.
		extra := extraContext + "\n\n" + critique.Render()
		revised, rerr := r.Inner.Scan(ctx, f, extra)
		if rerr != nil {
			r.logf("reflexion[%s] revise iter=%d: %v (keeping current findings)", r.Inner.Name, i, rerr)
			return current, nil
		}
		r.logf("reflexion[%s] iter=%d: %d -> %d findings", r.Inner.Name, i, len(current), len(revised))
		current = revised
	}
	return current, nil
}

// Critique is the structured critic output. Each field is optional; we apply
// only what's present.
type Critique struct {
	// SpuriousIDs lists IDs that the critic believes are false positives.
	SpuriousIDs []string `json:"spurious_ids"`
	// MissedPatterns is a free-text list of bug patterns the inner scanner
	// failed to flag. The revise step asks the scanner to re-check them.
	MissedPatterns []string `json:"missed_patterns"`
	// WeakFindings is a list of IDs whose evidence is thin (the scanner
	// should either tighten the rationale or drop them).
	WeakFindings []string `json:"weak_findings"`
	// Notes is short free-form prose the revise step should consider.
	Notes string `json:"notes"`
}

// HasFeedback returns true when at least one field carries content. Used to
// short-circuit the revise step when the critic is satisfied.
func (c Critique) HasFeedback() bool {
	return len(c.SpuriousIDs) > 0 || len(c.MissedPatterns) > 0 || len(c.WeakFindings) > 0 || strings.TrimSpace(c.Notes) != ""
}

// Render produces a compact human-readable block that the revise step can
// prepend to extra context. Stays under a few hundred bytes by design.
func (c Critique) Render() string {
	var b strings.Builder
	b.WriteString("Critique from a second-pass reviewer of your previous output:\n")
	if len(c.SpuriousIDs) > 0 {
		fmt.Fprintf(&b, "- Likely false positives (drop or downgrade): %s\n", strings.Join(c.SpuriousIDs, ", "))
	}
	if len(c.WeakFindings) > 0 {
		fmt.Fprintf(&b, "- Findings with thin evidence (tighten or drop): %s\n", strings.Join(c.WeakFindings, ", "))
	}
	if len(c.MissedPatterns) > 0 {
		fmt.Fprintf(&b, "- Patterns possibly missed (re-check the file for these):\n")
		for _, p := range c.MissedPatterns {
			fmt.Fprintf(&b, "    * %s\n", oneLine(p))
		}
	}
	if n := strings.TrimSpace(c.Notes); n != "" {
		fmt.Fprintf(&b, "- Notes: %s\n", oneLine(n))
	}
	b.WriteString("Re-emit the full findings list applying the critique; do not just add the new items.")
	return b.String()
}

func (r *ReflexionScanner) critique(ctx context.Context, f types.FileTarget, findings []types.Finding) (Critique, error) {
	if r.Critic == nil {
		return Critique{}, fmt.Errorf("reflexion: nil critic")
	}
	system := r.CritiquePromptOverride
	if system == "" {
		system = reflexionCriticSystem
	}
	// Inline the findings as compact JSON so the critic can address them
	// by ID. Cap to ~50 items to keep prompts bounded.
	view := findings
	if len(view) > 50 {
		view = view[:50]
	}
	findingsJSON, _ := json.Marshal(view)

	user := fmt.Sprintf(`Skill: %s
File: %s (lang=%s, lines=%d..%d)
Code being scanned (line-numbered for reference):
%s

Findings emitted by the first pass (JSON):
%s

Critique them. Output a JSON object with optional fields:
{
  "spurious_ids": ["..."],
  "weak_findings": ["..."],
  "missed_patterns": ["pattern description", "..."],
  "notes": "short prose"
}
If everything looks correct and complete, return {}.`,
		r.Inner.Name, f.Path, f.Language, f.LineOffset+1, f.LineOffset+f.Lines,
		f.Content, string(findingsJSON))

	resp, err := r.Critic.Complete(ctx, llm.Request{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return Critique{}, err
	}
	var c Critique
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &c); err != nil {
		return Critique{}, fmt.Errorf("reflexion: critic decode: %w; raw=%q", err, truncate(resp.Text, 200))
	}
	return c, nil
}

const reflexionCriticSystem = `You are a senior application security reviewer auditing the output of a
specialized scanner on ONE code chunk. You have the same code the scanner
saw plus its emitted findings.

Apply two lenses:
  1. Precision — flag findings that look spurious (no real attacker control,
     framework auto-defends, dead code, demo/example file, ...).
  2. Recall — flag bug PATTERNS in the chunk the scanner did NOT report.
     Focus on patterns within the skill's domain (e.g. SSRF for an SSRF skill).

Output a single JSON object:
  {
    "spurious_ids":   ["id1","id2"],   // findings that should be dropped
    "weak_findings":  ["id3"],         // findings whose rationale is thin
    "missed_patterns":["short description of a missed pattern", "..."],
    "notes":          "brief free-text guidance for the rewriter"
  }

Rules:
  - Be conservative. Do NOT invent missed patterns just to look thorough.
  - If the first pass looks correct, return {}.
  - Keep "missed_patterns" entries to ONE sentence each, max 5 entries.
  - Reference findings by their "id" field as printed in the input JSON.`
