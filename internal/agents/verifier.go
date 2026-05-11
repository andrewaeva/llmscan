package agents

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Verifier re-evaluates a finding with broader context and decides
// true / false positive using the Trail-of-Bits six-gate methodology
// (see verifierSystem in agents.go).
type Verifier struct {
	Client llm.Client
	// PromptOverride, if non-empty, replaces verifierSystem. Used to swap
	// in a skill-supplied prompt (e.g. skills/fpcheck-verifier/SKILL.md)
	// without touching the wiring.
	PromptOverride string
}

// verifierGatesJSON mirrors the GateReview shape but keeps gate values as
// strings — the LLM may emit "PASS" / "n/a " / etc., which NormalizeGate
// will fold to canonical values.
type verifierGatesJSON struct {
	Control      string `json:"control"`
	Reachability string `json:"reachability"`
	Validation   string `json:"validation"`
	APIContract  string `json:"api_contract"`
	Environment  string `json:"environment"`
	Impact       string `json:"impact"`

	ControlReason      string `json:"control_reason"`
	ReachabilityReason string `json:"reachability_reason"`
	ValidationReason   string `json:"validation_reason"`
	APIContractReason  string `json:"api_contract_reason"`
	EnvironmentReason  string `json:"environment_reason"`
	ImpactReason       string `json:"impact_reason"`
}

type verifierJSON struct {
	Verdict        string             `json:"verdict"`
	Comment        string             `json:"comment"`
	FalsePositive  bool               `json:"false_positive"`
	FPReason       string             `json:"fp_reason"`
	Severity       string             `json:"severity"`
	Confidence     string             `json:"confidence"`
	SuggestedFix   string             `json:"suggested_fix"`
	DefenseInDepth bool               `json:"defense_in_depth"`
	Gates          *verifierGatesJSON `json:"gates,omitempty"`
	DevilsAdvocate []string           `json:"devils_advocate,omitempty"`
}

// systemPrompt picks the override if present.
func (v *Verifier) systemPrompt() string {
	if v.PromptOverride != "" {
		return v.PromptOverride
	}
	return verifierSystem
}

//nolint:gocyclo // sequential merge of gate outcome with legacy verifier fields
func (v *Verifier) Verify(ctx context.Context, f types.Finding, contextSnippet string) (types.Finding, error) {
	user := fmt.Sprintf(`Finding:
%s

Surrounding code (with line numbers):
%s`, mustJSON(f), contextSnippet)

	resp, err := v.Client.Complete(ctx, llm.Request{
		System:   v.systemPrompt(),
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

	// Stash baseline verifier metadata before gates may overwrite things.
	f.Verified = true
	f.VerifierVerdict = vj.Verdict
	f.VerifierComment = vj.Comment
	f.VerifierModel = resp.Model

	// Apply gate outcome BEFORE legacy FP fields so explicit gate signals
	// take precedence over flat boolean toggles emitted by older prompts.
	gateReview := buildGateReview(vj.Gates, vj.DevilsAdvocate)
	outcome := types.ApplyGates(&f, gateReview)

	// Severity and confidence overrides still respected when provided.
	if vj.Severity != "" && outcome != types.GateOutcomeDefenseInDepth {
		// Defense-in-depth already forced severity to low; do not let the
		// LLM override its own downgrade.
		f.Severity = types.Severity(vj.Severity)
	}
	if vj.Confidence != "" {
		f.Confidence = types.Confidence(vj.Confidence)
	}
	if vj.SuggestedFix != "" {
		f.SuggestedFix = vj.SuggestedFix
	}

	// Honor explicit false_positive/verdict flags when gates were not
	// evaluated (legacy prompt or partial fill-in).
	if outcome == types.GateOutcomeUnknown {
		f.FalsePositive = vj.FalsePositive || vj.Verdict == "false_positive"
		if f.FalsePositive && vj.FPReason != "" {
			f.FPReason = vj.FPReason
		}
	} else if outcome == types.GateOutcomeInconclusive && (vj.FalsePositive || vj.Verdict == "false_positive") {
		// Gates inconclusive but model still asserted FP — respect it but
		// keep gates attached for transparency.
		f.FalsePositive = true
		if vj.FPReason != "" {
			f.FPReason = vj.FPReason
		}
	}

	// "defense_in_depth=true" set explicitly even without Gate 6 FAIL.
	if vj.DefenseInDepth && !f.DefenseInDepth {
		f.DefenseInDepth = true
		if f.Severity != types.SevInfo {
			f.Severity = types.SevLow
		}
	}

	return f, nil
}

// buildGateReview converts the LLM-emitted gate strings into a normalized
// GateReview. Returns nil when no gate field was set, so callers can decide
// whether to attach the review at all.
func buildGateReview(in *verifierGatesJSON, devils []string) *types.GateReview {
	if in == nil &&
		len(devils) == 0 {
		return nil
	}
	g := &types.GateReview{DevilsAdvocate: devils}
	if in != nil {
		g.Control = types.NormalizeGate(in.Control)
		g.Reachability = types.NormalizeGate(in.Reachability)
		g.Validation = types.NormalizeGate(in.Validation)
		g.APIContract = types.NormalizeGate(in.APIContract)
		g.Environment = types.NormalizeGate(in.Environment)
		g.Impact = types.NormalizeGate(in.Impact)
		g.ControlReason = in.ControlReason
		g.ReachabilityReason = in.ReachabilityReason
		g.ValidationReason = in.ValidationReason
		g.APIContractReason = in.APIContractReason
		g.EnvironmentReason = in.EnvironmentReason
		g.ImpactReason = in.ImpactReason
	}
	if !g.AnyEvaluated() && len(devils) == 0 {
		return nil
	}
	return g
}
