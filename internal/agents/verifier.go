package agents

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

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
