package agents

import (
	"context"
	"errors"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestFPFilterEmptyShortCircuit(t *testing.T) {
	f := &FPFilter{}
	out, err := f.Apply(context.Background(), nil)
	if err != nil || len(out) != 0 {
		t.Errorf("expected empty, got out=%v err=%v", out, err)
	}
}

func TestFPFilterDeterministicDedup(t *testing.T) {
	f := &FPFilter{Client: nil}
	in := []types.Finding{
		{ID: "a", Agent: "injection", File: "a.go", StartLine: 10, EndLine: 12, RuleID: "sql", Severity: types.SevHigh, Confidence: types.ConfMedium},
		{ID: "b", Agent: "injection", File: "a.go", StartLine: 10, EndLine: 12, RuleID: "sql", Severity: types.SevCritical, Confidence: types.ConfHigh},
		{ID: "c", Agent: "crypto", File: "b.go", StartLine: 1, EndLine: 1, RuleID: "kv", Severity: types.SevLow, Confidence: types.ConfLow},
	}
	out, err := f.Apply(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected dedup to 2 findings, got %d", len(out))
	}
	// Higher rank survives.
	if out[0].Severity != types.SevCritical {
		t.Errorf("expected critical to win dedup; got %+v", out[0])
	}
}

func TestFPFilterLLMKeptList(t *testing.T) {
	cli := &stubClient{responses: []string{`{"kept":["f1"],"dropped":[]}`}}
	f := &FPFilter{Client: cli}
	in := []types.Finding{
		{ID: "f1", File: "a.go", Title: "k"},
		{ID: "f2", File: "b.go", Title: "drop"},
	}
	out, err := f.Apply(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings retained (one marked FP), got %d", len(out))
	}
	var f2 *types.Finding
	for i := range out {
		if out[i].ID == "f2" {
			f2 = &out[i]
		}
	}
	if f2 == nil || !f2.FalsePositive {
		t.Errorf("expected f2 marked FP; out=%+v", out)
	}
	if f2.FPReason == "" {
		t.Errorf("FPReason should be set; got %+v", f2)
	}
}

func TestFPFilterLLMDropOnly(t *testing.T) {
	cli := &stubClient{responses: []string{`{"kept":[],"dropped":[{"id":"f2","reason":"no-evidence"}]}`}}
	f := &FPFilter{Client: cli}
	in := []types.Finding{
		{ID: "f1", File: "a.go"},
		{ID: "f2", File: "b.go"},
	}
	out, err := f.Apply(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d", len(out))
	}
	for _, f := range out {
		if f.ID == "f1" && f.FalsePositive {
			t.Errorf("f1 should not be FP, got %+v", f)
		}
		if f.ID == "f2" {
			if !f.FalsePositive || f.FPReason != "no-evidence" {
				t.Errorf("f2: expected FP+no-evidence; got %+v", f)
			}
		}
	}
}

func TestFPFilterLLMErrorReturnsDedupedFindings(t *testing.T) {
	cli := &stubClient{errs: []error{errors.New("rate")}, responses: []string{""}}
	f := &FPFilter{Client: cli}
	in := []types.Finding{{ID: "x", File: "a.go", Severity: types.SevHigh}}
	out, err := f.Apply(context.Background(), in)
	if err == nil {
		t.Error("expected error propagation")
	}
	if len(out) != 1 {
		t.Errorf("findings should still be returned on error; got %+v", out)
	}
}

func TestFPFilterLLMBadJSON(t *testing.T) {
	cli := &stubClient{responses: []string{`not-json`}}
	f := &FPFilter{Client: cli}
	in := []types.Finding{{ID: "x", File: "a.go"}}
	_, err := f.Apply(context.Background(), in)
	if err == nil {
		t.Error("expected decode error")
	}
}

func TestRankOrdering(t *testing.T) {
	r1 := rank(types.SevCritical, types.ConfHigh)
	r2 := rank(types.SevHigh, types.ConfHigh)
	r3 := rank(types.SevHigh, types.ConfLow)
	if r1 <= r2 || r2 <= r3 {
		t.Errorf("rank order broken: %d %d %d", r1, r2, r3)
	}
}
