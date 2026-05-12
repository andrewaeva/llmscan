package agents

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func mkFinding(id string, sev types.Severity, conf types.Confidence, line int) types.Finding {
	return types.Finding{
		ID:         id,
		RuleID:     "rule-x",
		Title:      "issue " + id,
		Severity:   sev,
		Confidence: conf,
		StartLine:  line,
		EndLine:    line + 5,
		File:       "app/handler.go",
		Agent:      "scan:test",
	}
}

func TestRefiner_NilClientPassthrough(t *testing.T) {
	in := []types.Finding{mkFinding("a", types.SevHigh, types.ConfHigh, 10), mkFinding("b", types.SevLow, types.ConfLow, 20)}
	r := &Refiner{}
	out, err := r.Refine(context.Background(), "f.go", in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("expected passthrough %d, got %d", len(in), len(out))
	}
}

func TestRefiner_SingleFindingPassthrough(t *testing.T) {
	in := []types.Finding{mkFinding("a", types.SevHigh, types.ConfHigh, 10)}
	r := &Refiner{Client: &stubClient{}}
	out, err := r.Refine(context.Background(), "f.go", in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 1 || out[0].ID != "a" {
		t.Fatalf("expected single passthrough, got %+v", out)
	}
}

func TestRefiner_MergesAndOverrides(t *testing.T) {
	in := []types.Finding{
		mkFinding("a", types.SevMedium, types.ConfMedium, 10),
		mkFinding("b", types.SevHigh, types.ConfHigh, 12),
		mkFinding("c", types.SevLow, types.ConfLow, 50),
	}
	// Reducer says: merge a+b into one (b wins as base, override severity to
	// critical), drop c.
	resp := `{
        "findings": [
          {"merged_ids": ["a","b"], "severity": "critical", "rationale": "same SQLi"},
          {"merged_ids": ["c"], "drop": true}
        ]
    }`
	r := &Refiner{Client: &stubClient{responses: []string{resp}}}
	out, err := r.Refine(context.Background(), "f.go", in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(out), out)
	}
	got := out[0]
	if got.ID != "b" {
		t.Fatalf("expected base 'b' (stronger), got %q", got.ID)
	}
	if got.Severity != types.SevCritical {
		t.Fatalf("expected severity override critical, got %q", got.Severity)
	}
	if !containsString(got.Tags, "refined") {
		t.Fatalf("expected 'refined' tag, got %v", got.Tags)
	}
	if !strings.Contains(got.VerifierComment, "same SQLi") {
		t.Fatalf("expected rationale in VerifierComment, got %q", got.VerifierComment)
	}
}

func TestRefiner_OrphansPreserved(t *testing.T) {
	in := []types.Finding{
		mkFinding("a", types.SevHigh, types.ConfHigh, 10),
		mkFinding("b", types.SevLow, types.ConfLow, 20),
	}
	// Reducer only mentions "a" — "b" must survive as passthrough.
	resp := `{"findings":[{"merged_ids":["a"]}]}`
	r := &Refiner{Client: &stubClient{responses: []string{resp}}}
	out, err := r.Refine(context.Background(), "f.go", in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (a + orphan b), got %d", len(out))
	}
	var sawB bool
	for _, f := range out {
		if f.ID == "b" {
			sawB = true
		}
	}
	if !sawB {
		t.Fatalf("orphan 'b' must be preserved")
	}
}

func TestRefiner_ErrorFallsBackToInput(t *testing.T) {
	in := []types.Finding{
		mkFinding("a", types.SevHigh, types.ConfHigh, 10),
		mkFinding("b", types.SevLow, types.ConfLow, 20),
	}
	r := &Refiner{Client: &stubClient{responses: []string{"not json at all"}}}
	out, err := r.Refine(context.Background(), "f.go", in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("on decode error must passthrough; got %d", len(out))
	}
}

func TestPickBase_StrongerWins(t *testing.T) {
	byID := map[string]types.Finding{
		"a": mkFinding("a", types.SevMedium, types.ConfHigh, 10),
		"b": mkFinding("b", types.SevHigh, types.ConfLow, 12),
	}
	base, ok := pickBase([]string{"a", "b"}, byID)
	if !ok {
		t.Fatalf("expected ok")
	}
	if base.ID != "b" {
		t.Fatalf("severity rules: expected 'b' (high) > 'a' (medium); got %q", base.ID)
	}
}

func containsString(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
