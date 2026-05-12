package agents

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func mkDebFinding() types.Finding {
	return types.Finding{
		ID: "f-1", RuleID: "sql-injection", Title: "SQLi",
		Severity: types.SevHigh, Confidence: types.ConfHigh,
		File: "app/h.go", StartLine: 10, EndLine: 14, Agent: "scan:injection",
		Description: "user input flows into Query()", CodeSample: "db.Query(req.URL.Query().Get(\"q\"))",
	}
}

func TestDebate_NilClientInconclusive(t *testing.T) {
	d := &Debater{}
	r := d.Debate(context.Background(), mkDebFinding(), "")
	if r.Verdict != "inconclusive" {
		t.Fatalf("expected inconclusive on nil client, got %q", r.Verdict)
	}
}

func TestDebate_ConsensusFirstRound(t *testing.T) {
	// Both sides agree → 1 round, no split penalty.
	resp := `{"verdict":"tp","rationale":"unsanitized query string flows to Query()","concede":false}`
	d := &Debater{Client: &stubClient{responses: []string{resp, resp}}}
	r := d.Debate(context.Background(), mkDebFinding(), "")
	if r.Verdict != "tp" {
		t.Fatalf("expected tp consensus, got %q", r.Verdict)
	}
	if r.Rounds != 1 {
		t.Fatalf("expected 1 round, got %d", r.Rounds)
	}
	if r.SplitPenalty != 1.0 {
		t.Fatalf("expected no penalty on consensus, got %v", r.SplitPenalty)
	}
}

func TestDebate_OpponentConcedes(t *testing.T) {
	prop := `{"verdict":"tp","rationale":"taint reaches db.Query","concede":false}`
	opp := `{"verdict":"tp","rationale":"agreed, the input is unsanitized","concede":true}`
	d := &Debater{Client: &stubClient{responses: []string{prop, opp}}}
	r := d.Debate(context.Background(), mkDebFinding(), "")
	if r.Verdict != "tp" {
		t.Fatalf("expected tp on concede, got %q", r.Verdict)
	}
}

func TestDebate_SplitAfterMaxRounds(t *testing.T) {
	prop := `{"verdict":"tp","rationale":"unsanitized input","concede":false}`
	opp := `{"verdict":"fp","rationale":"middleware sanitizes earlier","concede":false}`
	// Same disagreement every round.
	resps := []string{prop, opp, prop, opp}
	d := &Debater{Client: &stubClient{responses: resps}, MaxRounds: 2}
	r := d.Debate(context.Background(), mkDebFinding(), "")
	if r.Verdict != "split" {
		t.Fatalf("expected split, got %q", r.Verdict)
	}
	if r.Rounds != 2 {
		t.Fatalf("expected 2 rounds, got %d", r.Rounds)
	}
	if r.SplitPenalty >= 1.0 || r.SplitPenalty <= 0 {
		t.Fatalf("expected penalty in (0,1), got %v", r.SplitPenalty)
	}
	if !strings.Contains(r.Rationale, "split") {
		t.Fatalf("rationale should be marked split, got %q", r.Rationale)
	}
}

func TestDebate_DecodeErrorInconclusive(t *testing.T) {
	d := &Debater{Client: &stubClient{responses: []string{"not json"}}}
	r := d.Debate(context.Background(), mkDebFinding(), "")
	if r.Verdict != "inconclusive" {
		t.Fatalf("expected inconclusive on decode err, got %q", r.Verdict)
	}
}

func TestNormVerdict(t *testing.T) {
	cases := map[string]string{
		"TP":             "tp",
		"true positive":  "tp",
		"confirmed":      "tp",
		"FP":             "fp",
		"false-positive": "fp",
		"refuted":        "fp",
		"inconclusive":   "inconclusive",
		"":               "",
		"weird":          "",
	}
	for in, want := range cases {
		if got := normVerdict(in); got != want {
			t.Errorf("normVerdict(%q) = %q, want %q", in, got, want)
		}
	}
}
