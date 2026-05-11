// Package agents implements the multi-agent hierarchy:
//
//	Orchestrator -> Scanner agents (per vulnerability class) -> Verifier -> FP Filter.
//
// Every agent is just an LLM call with a focused prompt and strict JSON output.
package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// ScannerNames is the canonical, ordered list of specialized scanner agents.
var ScannerNames = []string{
	"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic",
}

// Orchestrator builds a high-level scan plan from a tree of file paths.
type Orchestrator struct {
	Client llm.Client
}

func (o *Orchestrator) Plan(ctx context.Context, target string, files []types.FileTarget, projectContext string) (types.ScanPlan, error) {
	if o.Client == nil {
		return fallbackPlan(files), nil
	}
	// Build a compact tree listing (path + size in lines).
	var b strings.Builder
	for i, f := range files {
		if i >= 600 { // cap to keep prompt small
			fmt.Fprintf(&b, "... (%d more files)\n", len(files)-i)
			break
		}
		fmt.Fprintf(&b, "- %s [%s, %d lines]\n", f.Path, f.Language, f.Lines)
	}
	user := fmt.Sprintf("Target: %s\nProject context: %s\n\nFiles:\n%s",
		target,
		emptyIf(projectContext, "(none)"),
		b.String())
	resp, err := o.Client.Complete(ctx, llm.Request{
		System:   orchestratorSystem,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return fallbackPlan(files), err
	}
	var plan types.ScanPlan
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &plan); err != nil {
		return fallbackPlan(files), fmt.Errorf("decode plan: %w", err)
	}
	if len(plan.Priority) == 0 {
		plan = fallbackPlan(files)
	}
	if len(plan.Focus) == 0 {
		plan.Focus = append(plan.Focus, ScannerNames...)
	}
	return plan, nil
}

func fallbackPlan(files []types.FileTarget) types.ScanPlan {
	pri := make([]string, 0, len(files))
	for _, f := range files {
		pri = append(pri, f.Path)
	}
	return types.ScanPlan{
		Reasoning: "fallback: orchestrator unavailable, scanning all discovered files",
		Priority:  pri,
		Focus:     append([]string{}, ScannerNames...),
	}
}

// Scanner is a single specialized vulnerability hunter.
type Scanner struct {
	Name   string
	Client llm.Client
	// PromptOverride: if non-empty, replaces the system prompt template entirely.
	// Used when a Scanner is loaded from a SKILL.md.
	PromptOverride string
	// Scope: free-form description used when no prompt override is given.
	Scope string
}

// Scan analyzes a single file (chunk). `extraContext` is optional retrieved code
// (from RAG + ContextFilter) that gets appended to the prompt.
func (s *Scanner) Scan(ctx context.Context, f types.FileTarget, extraContext string) ([]types.Finding, error) {
	var system string
	if s.PromptOverride != "" {
		system = s.PromptOverride
	} else {
		scope := s.Scope
		if scope == "" {
			scope = scopeForAgent(s.Name)
		}
		system = fmt.Sprintf(scannerSystemTemplate, s.Name, scope)
	}
	user := fmt.Sprintf("File: %s\nLanguage: %s\nChunk: %d/%d (line offset %d)\n\n```%s\n%s\n```",
		f.Path, f.Language, f.ChunkIdx+1, max(1, f.ChunkTotal), f.LineOffset, f.Language, f.Content)
	if extraContext != "" {
		user += "\n\n" + extraContext
	}
	resp, err := s.Client.Complete(ctx, llm.Request{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Findings []types.Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &parsed); err != nil {
		return nil, fmt.Errorf("%s: decode: %w; raw=%q", s.Name, err, truncate(resp.Text, 300))
	}
	now := time.Now()
	out := make([]types.Finding, 0, len(parsed.Findings))
	for i, fnd := range parsed.Findings {
		fnd.Agent = s.Name
		fnd.File = f.Path
		fnd.StartLine = fnd.StartLine + f.LineOffset
		fnd.EndLine = fnd.EndLine + f.LineOffset
		if fnd.ID == "" {
			fnd.ID = fmt.Sprintf("%s-%s-%d-%d", s.Name, hash6(f.Path), fnd.StartLine, i)
		}
		fnd.CreatedAt = now
		if fnd.Severity == "" {
			fnd.Severity = types.SevMedium
		}
		if fnd.Confidence == "" {
			fnd.Confidence = types.ConfMedium
		}
		out = append(out, fnd)
	}
	return out, nil
}

// Verifier re-evaluates a finding with broader context and decides true/false positive.
type Verifier struct {
	Client llm.Client
}

type verifierJSON struct {
	Verdict       string `json:"verdict"`
	Comment       string `json:"comment"`
	FalsePositive bool   `json:"false_positive"`
	FPReason      string `json:"fp_reason"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"`
	SuggestedFix  string `json:"suggested_fix"`
}

func (v *Verifier) Verify(ctx context.Context, f types.Finding, contextSnippet string) (types.Finding, error) {
	user := fmt.Sprintf(`Finding:
%s

Surrounding code (with line numbers):
%s`, mustJSON(f), contextSnippet)

	resp, err := v.Client.Complete(ctx, llm.Request{
		System:   verifierSystem,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return f, err
	}
	var vj verifierJSON
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &vj); err != nil {
		return f, fmt.Errorf("verifier decode: %w; raw=%q", err, truncate(resp.Text, 300))
	}
	f.Verified = true
	f.VerifierVerdict = vj.Verdict
	f.VerifierComment = vj.Comment
	f.VerifierModel = resp.Model
	f.FalsePositive = vj.FalsePositive || vj.Verdict == "false_positive"
	f.FPReason = vj.FPReason
	if vj.Severity != "" {
		f.Severity = types.Severity(vj.Severity)
	}
	if vj.Confidence != "" {
		f.Confidence = types.Confidence(vj.Confidence)
	}
	if vj.SuggestedFix != "" {
		f.SuggestedFix = vj.SuggestedFix
	}
	return f, nil
}

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

// ---------- helpers ----------

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func emptyIf(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func hash6(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 6)
	for i := range out {
		out[i] = abc[h%uint32(len(abc))]
		h /= uint32(len(abc))
		if h == 0 {
			h = 2166136261 ^ uint32(i)
		}
	}
	return string(out)
}
