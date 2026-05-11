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

// ---- Six-gate verifier tests ----

func gatesAllPassJSON() string {
	return `{
  "verdict":"true_positive",
  "comment":"all gates pass",
  "gates":{
    "control":"pass","control_reason":"http body",
    "reachability":"pass","reachability_reason":"POST /api",
    "validation":"pass","validation_reason":"no validator",
    "api_contract":"pass","api_contract_reason":"raw Exec",
    "environment":"pass","environment_reason":"none",
    "impact":"pass","impact_reason":"RCE"
  },
  "devils_advocate":["pattern bias? no","hallucination? no"]
}`
}

func TestVerifierGatesAllPassConfirms(t *testing.T) {
	cli := &stubClient{responses: []string{gatesAllPassJSON()}}
	v := &Verifier{Client: cli}
	got, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified || got.FalsePositive {
		t.Errorf("expected confirmed TP; got %+v", got)
	}
	if got.Gates == nil || got.Gates.Control != types.GatePass {
		t.Errorf("Gates not attached: %+v", got.Gates)
	}
	if len(got.Gates.DevilsAdvocate) != 2 {
		t.Errorf("devils=%v", got.Gates.DevilsAdvocate)
	}
}

func TestVerifierGatesAPIContractFailMarksFP(t *testing.T) {
	resp := `{
  "verdict":"false_positive",
  "comment":"prepared stmt used",
  "gates":{
    "control":"pass","reachability":"pass",
    "validation":"pass",
    "api_contract":"fail","api_contract_reason":"prepared statement",
    "environment":"pass","impact":"pass"
  }
}`
	cli := &stubClient{responses: []string{resp}}
	v := &Verifier{Client: cli}
	got, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.FalsePositive {
		t.Errorf("expected FP; got %+v", got)
	}
	if got.FPReason != "prepared statement" {
		t.Errorf("FPReason=%q", got.FPReason)
	}
	if got.Gates == nil || got.Gates.APIContract != types.GateFail {
		t.Errorf("Gates not attached: %+v", got.Gates)
	}
}

func TestVerifierGatesImpactOnlyFailIsDefenseInDepth(t *testing.T) {
	resp := `{
  "verdict":"true_positive",
  "comment":"real bug but only robustness",
  "gates":{
    "control":"pass","reachability":"pass",
    "validation":"pass","api_contract":"pass","environment":"pass",
    "impact":"fail","impact_reason":"panic only"
  }
}`
	cli := &stubClient{responses: []string{resp}}
	v := &Verifier{Client: cli}
	in := sampleFinding()
	in.Severity = types.SevCritical
	got, err := v.Verify(context.Background(), in, "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.DefenseInDepth {
		t.Errorf("expected DefenseInDepth=true; got %+v", got)
	}
	if got.Severity != types.SevLow {
		t.Errorf("severity should downgrade to low; got %s", got.Severity)
	}
	if got.FalsePositive {
		t.Error("defense-in-depth must NOT be marked false_positive")
	}
}

func TestVerifierGatesInconclusiveDoesNotMutate(t *testing.T) {
	resp := `{
  "verdict":"inconclusive",
  "comment":"need cross-file info",
  "gates":{
    "control":"pass","reachability":"pass"
  }
}`
	cli := &stubClient{responses: []string{resp}}
	v := &Verifier{Client: cli}
	in := sampleFinding()
	got, err := v.Verify(context.Background(), in, "code")
	if err != nil {
		t.Fatal(err)
	}
	if got.FalsePositive {
		t.Error("inconclusive must not flip to FP")
	}
	if got.Severity != in.Severity {
		t.Errorf("severity changed: %s", got.Severity)
	}
	if got.VerifierVerdict != "inconclusive" {
		t.Errorf("verifier_verdict=%q", got.VerifierVerdict)
	}
}

func TestVerifierGatesControlFailMarksFP(t *testing.T) {
	resp := `{
  "verdict":"false_positive",
  "comment":"hard-coded const",
  "gates":{
    "control":"fail","control_reason":"value is a hard-coded const",
    "reachability":"pass","validation":"pass",
    "api_contract":"pass","environment":"pass","impact":"pass"
  }
}`
	cli := &stubClient{responses: []string{resp}}
	v := &Verifier{Client: cli}
	got, err := v.Verify(context.Background(), sampleFinding(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.FalsePositive {
		t.Errorf("expected FP from control=fail; got %+v", got)
	}
	if got.FPReason != "value is a hard-coded const" {
		t.Errorf("FPReason=%q", got.FPReason)
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
