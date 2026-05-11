package agents

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func sampleFinding() types.Finding {
	return types.Finding{
		ID: "x", RuleID: "r", Title: "t",
		Severity: types.SevHigh, Confidence: types.ConfMedium,
		File: "a.go", StartLine: 5, EndLine: 7,
	}
}

func TestVerifierTruePositive(t *testing.T) {
	cli := &stubClient{responses: []string{`{"verdict":"true_positive","comment":"definitely real","severity":"critical","confidence":"high","suggested_fix":"sanitize"}`}}
	v := &Verifier{Client: cli}
	got, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified || got.FalsePositive {
		t.Errorf("verified/FP: %+v", got)
	}
	if got.Severity != types.SevCritical || got.Confidence != types.ConfHigh {
		t.Errorf("severity/confidence not upgraded: %+v", got)
	}
	if got.VerifierVerdict != "true_positive" || got.VerifierComment != "definitely real" {
		t.Errorf("verifier fields: %+v", got)
	}
	if got.SuggestedFix != "sanitize" {
		t.Errorf("fix=%q", got.SuggestedFix)
	}
}

func TestVerifierFalsePositive(t *testing.T) {
	cli := &stubClient{responses: []string{`{"verdict":"false_positive","comment":"test code","false_positive":true,"fp_reason":"test-code"}`}}
	v := &Verifier{Client: cli}
	got, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.FalsePositive {
		t.Errorf("expected false_positive=true; got %+v", got)
	}
	if got.FPReason != "test-code" {
		t.Errorf("fp_reason=%q", got.FPReason)
	}
}

func TestVerifierFalsePositiveImpliedByVerdict(t *testing.T) {
	// Even if false_positive=false, verdict="false_positive" should mark FP.
	cli := &stubClient{responses: []string{`{"verdict":"false_positive","comment":"x"}`}}
	v := &Verifier{Client: cli}
	got, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.FalsePositive {
		t.Error("FP flag should be set from verdict alone")
	}
}

func TestVerifierLLMError(t *testing.T) {
	cli := &stubClient{errs: []error{errors.New("bad")}, responses: []string{""}}
	v := &Verifier{Client: cli}
	in := sampleFinding()
	got, err := v.Verify(context.Background(), in, "code")
	if err == nil {
		t.Error("expected propagated error")
	}
	// Returns the input finding unchanged on error.
	if got.Verified {
		t.Error("should not mark Verified on error")
	}
}

func TestVerifierBadJSON(t *testing.T) {
	cli := &stubClient{responses: []string{`not-json`}}
	v := &Verifier{Client: cli}
	_, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode err, got %v", err)
	}
}

func TestVerifierKeepsOriginalWhenEmptySeverity(t *testing.T) {
	cli := &stubClient{responses: []string{`{"verdict":"true_positive","comment":"x"}`}}
	v := &Verifier{Client: cli}
	in := sampleFinding()
	got, err := v.Verify(context.Background(), in, "code")
	if err != nil {
		t.Fatal(err)
	}
	if got.Severity != in.Severity || got.Confidence != in.Confidence {
		t.Errorf("severity/confidence should be preserved when verifier omits them; got %+v", got)
	}
}
