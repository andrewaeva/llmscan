package types

import (
	"encoding/json"
	"testing"
)

func TestNormalizeGate(t *testing.T) {
	cases := map[string]Gate{
		"pass": GatePass, "PASS": GatePass, " ok ": GatePass, "yes": GatePass,
		"fail": GateFail, "FAIL": GateFail, "blocked": GateFail, "no": GateFail,
		"n/a": GateNotApp, "NA": GateNotApp, " not applicable ": GateNotApp,
		"":         GateUnknown,
		"whatever": GateUnknown,
	}
	for in, want := range cases {
		if got := NormalizeGate(in); got != want {
			t.Errorf("NormalizeGate(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGateReviewAnyEvaluated(t *testing.T) {
	var nilGR *GateReview
	if nilGR.AnyEvaluated() {
		t.Error("nil should be AnyEvaluated=false")
	}
	if (&GateReview{}).AnyEvaluated() {
		t.Error("empty should be false")
	}
	if !(&GateReview{Control: GatePass}).AnyEvaluated() {
		t.Error("control=pass should be true")
	}
}

func TestClassifyConfirmed(t *testing.T) {
	g := &GateReview{
		Control: GatePass, Reachability: GatePass, Validation: GatePass,
		APIContract: GatePass, Environment: GatePass, Impact: GatePass,
	}
	if got := g.Classify(); got != GateOutcomeConfirmed {
		t.Errorf("all-pass classify=%d want confirmed", got)
	}
}

func TestClassifyRefutedDefended(t *testing.T) {
	g := &GateReview{
		Control: GatePass, Reachability: GatePass,
		APIContract: GateFail, APIContractReason: "parameterized query",
		Impact: GatePass,
	}
	if g.Classify() != GateOutcomeRefutedDefended {
		t.Error("API contract FAIL should classify as RefutedDefended")
	}
	if r := g.FirstFailingReason(); r != "parameterized query" {
		t.Errorf("reason=%q", r)
	}
}

func TestClassifyRefutedNoControl(t *testing.T) {
	g := &GateReview{
		Control:       GateFail,
		ControlReason: "value comes from a hard-coded const",
		Reachability:  GatePass,
		Validation:    GatePass,
		APIContract:   GatePass,
		Environment:   GatePass,
		Impact:        GatePass,
	}
	if g.Classify() != GateOutcomeRefutedNoControl {
		t.Error("Control FAIL alone should classify as RefutedNoControl")
	}
}

func TestClassifyDefenseInDepth(t *testing.T) {
	g := &GateReview{
		Control: GatePass, Reachability: GatePass, Validation: GatePass,
		APIContract: GatePass, Environment: GatePass,
		Impact: GateFail, ImpactReason: "panic only; no exploit",
	}
	if g.Classify() != GateOutcomeDefenseInDepth {
		t.Error("Impact-only FAIL should classify as DefenseInDepth")
	}
}

func TestClassifyInconclusive(t *testing.T) {
	g := &GateReview{Control: GatePass, Reachability: GatePass}
	if g.Classify() != GateOutcomeInconclusive {
		t.Error("partial review should be inconclusive")
	}
	allNA := &GateReview{
		Control: GateNotApp, Reachability: GateNotApp, Validation: GateNotApp,
		APIContract: GateNotApp, Environment: GateNotApp, Impact: GateNotApp,
	}
	if allNA.Classify() != GateOutcomeInconclusive {
		t.Error("all-N/A should not be 'confirmed'; expected inconclusive")
	}
}

func TestApplyGatesNilFinding(t *testing.T) {
	if got := ApplyGates(nil, &GateReview{Control: GatePass}); got != GateOutcomeUnknown {
		t.Errorf("nil finding should return Unknown; got %d", got)
	}
}

func TestApplyGatesConfirmed(t *testing.T) {
	f := &Finding{Severity: SevHigh}
	gr := &GateReview{
		Control: GatePass, Reachability: GatePass, Validation: GatePass,
		APIContract: GatePass, Environment: GatePass, Impact: GatePass,
	}
	out := ApplyGates(f, gr)
	if out != GateOutcomeConfirmed || !f.Verified || f.FalsePositive {
		t.Errorf("confirmed: %+v outcome=%d", f, out)
	}
	if f.Gates == nil {
		t.Error("Gates should be attached")
	}
}

func TestApplyGatesRefutedDefended(t *testing.T) {
	f := &Finding{Severity: SevCritical}
	gr := &GateReview{
		Validation: GateFail, ValidationReason: "sanitized upstream",
	}
	if got := ApplyGates(f, gr); got != GateOutcomeRefutedDefended {
		t.Errorf("got %d", got)
	}
	if !f.FalsePositive {
		t.Error("expected FalsePositive=true")
	}
	if f.FPReason != "sanitized upstream" {
		t.Errorf("FPReason=%q", f.FPReason)
	}
}

func TestApplyGatesDefenseInDepth(t *testing.T) {
	f := &Finding{Severity: SevHigh}
	gr := &GateReview{
		Control: GatePass, Reachability: GatePass, Validation: GatePass,
		APIContract: GatePass, Environment: GatePass,
		Impact: GateFail, ImpactReason: "robustness only",
	}
	if got := ApplyGates(f, gr); got != GateOutcomeDefenseInDepth {
		t.Errorf("got %d", got)
	}
	if !f.DefenseInDepth {
		t.Error("DefenseInDepth flag should be set")
	}
	if f.Severity != SevLow {
		t.Errorf("severity not downgraded: %s", f.Severity)
	}
}

func TestApplyGatesInconclusive(t *testing.T) {
	f := &Finding{Severity: SevMedium, Confidence: ConfMedium}
	orig := *f
	out := ApplyGates(f, &GateReview{Control: GatePass}) // partial
	if out != GateOutcomeInconclusive {
		t.Errorf("outcome=%d want Inconclusive", out)
	}
	// No mutation expected on severity / FP.
	if f.Severity != orig.Severity || f.FalsePositive != orig.FalsePositive || f.Verified {
		t.Errorf("inconclusive should not mutate finding: %+v", f)
	}
}

func TestGateReviewJSONRoundTrip(t *testing.T) {
	g := &GateReview{
		Control: GatePass, ControlReason: "header",
		Reachability: GatePass, Validation: GateFail, ValidationReason: "blocked",
		Impact:         GateNotApp,
		DevilsAdvocate: []string{"pattern bias? no", "trust assumption? no"},
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var back GateReview
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Control != GatePass || back.Validation != GateFail {
		t.Errorf("round trip lost data: %+v", back)
	}
	if len(back.DevilsAdvocate) != 2 {
		t.Errorf("devils=%v", back.DevilsAdvocate)
	}
}

func TestFindingJSONOmitGatesWhenNil(t *testing.T) {
	f := Finding{ID: "x"}
	b, _ := json.Marshal(f)
	if want := `"gates"`; contains(string(b), want) {
		t.Errorf("nil gates should be omitted; got %s", b)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
