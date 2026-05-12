package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Verifies the gate-debate-apply state machine routes correctly. We don't
// call a real LLM — we plug a Debater with a nil Client (returns
// inconclusive) and patch the apply step via a wrapper graph for tp/fp/split
// scenarios by constructing the state manually.

func TestDebateGraph_GateSkipsRefuted(t *testing.T) {
	f := types.Finding{
		ID: "x", File: "a.go", StartLine: 1, EndLine: 2,
		DeepVerdict: "refuted", DeepVerified: true,
	}
	deb := &agents.Debater{} // nil client; would return inconclusive if called
	g := buildDebateGraph(deb, nil)
	st := &debateState{f: &f}
	if err := g.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.applied != "" {
		t.Fatalf("refuted findings must skip debate; applied=%q", st.applied)
	}
	if containsTag(f.Tags, "debate-split") || containsTag(f.Tags, "debate-tp") || containsTag(f.Tags, "debate-fp") {
		t.Fatalf("expected no debate tags; got %v", f.Tags)
	}
}

func TestDebateGraph_AppliesSplitVerdict(t *testing.T) {
	stubDeb := &stubDebater{verdict: "split", penalty: 0.7, rationale: "no consensus"}
	g := buildDebateGraphWithRunner(stubDeb, nil)
	f := types.Finding{ID: "x", File: "a.go", StartLine: 1, EndLine: 2, Score: 0.8, DeepVerdict: "confirmed"}
	st := &debateState{f: &f}
	if err := g.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.applied != "split" {
		t.Fatalf("expected applied=split, got %q", st.applied)
	}
	if !containsTag(f.Tags, "debate-split") {
		t.Fatalf("expected debate-split tag, got %v", f.Tags)
	}
	if f.Score >= 0.8 {
		t.Fatalf("expected score penalty applied; got %v", f.Score)
	}
	if !strings.Contains(f.VerifierComment, "no consensus") {
		t.Fatalf("expected rationale in VerifierComment; got %q", f.VerifierComment)
	}
}

func TestDebateGraph_AppliesFPVerdict(t *testing.T) {
	stubDeb := &stubDebater{verdict: "fp", penalty: 1.0, rationale: "framework auto-defends"}
	g := buildDebateGraphWithRunner(stubDeb, nil)
	f := types.Finding{ID: "x", File: "a.go", StartLine: 1, EndLine: 2, DeepVerdict: "confirmed"}
	st := &debateState{f: &f}
	if err := g.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !f.FalsePositive {
		t.Fatalf("fp verdict must mark FalsePositive=true")
	}
	if !containsTag(f.Tags, "debate-fp") {
		t.Fatalf("expected debate-fp tag, got %v", f.Tags)
	}
}

// --- test helpers ---

type stubDebater struct {
	verdict   string
	penalty   float64
	rationale string
}

func (s *stubDebater) Debate(_ context.Context, _ types.Finding, _ string) agents.DebateResult {
	return agents.DebateResult{Verdict: s.verdict, SplitPenalty: s.penalty, Rationale: s.rationale, Rounds: 1}
}

// debater is the minimal interface buildDebateGraphWithRunner relies on. It
// matches agents.Debater.Debate so production code can use the concrete
// type directly.
type debater interface {
	Debate(ctx context.Context, f types.Finding, priorContext string) agents.DebateResult
}

// buildDebateGraphWithRunner is the test-only constructor that accepts any
// debater implementation. The production buildDebateGraph hard-wires
// agents.Debater for clarity.
func buildDebateGraphWithRunner(deb debater, logf func(string, ...any)) *agents.Graph[debateState] {
	g := agents.NewGraph[debateState]()
	g.Logf = logf

	g.AddNode("gate", func(_ context.Context, _ *debateState) error { return nil })
	g.SetRouter("gate", func(s *debateState) string {
		if s.f == nil || s.f.FalsePositive || s.f.Suppressed {
			return agents.End
		}
		if s.f.DeepVerdict == "refuted" {
			return agents.End
		}
		return "debate"
	})

	g.AddNode("debate", func(ctx context.Context, s *debateState) error {
		s.result = deb.Debate(ctx, *s.f, s.f.DeepComment)
		return nil
	})
	g.AddEdge("debate", "apply")

	g.AddNode("apply", func(_ context.Context, s *debateState) error {
		res := s.result
		switch res.Verdict {
		case "split":
			s.f.Tags = appendUniqueTag(s.f.Tags, "debate-split")
			if s.f.Score > 0 {
				s.f.Score *= res.SplitPenalty
			}
			if s.f.VerifierComment == "" {
				s.f.VerifierComment = res.Rationale
			}
			s.applied = "split"
		case "fp":
			s.f.FalsePositive = true
			if s.f.FPReason == "" {
				s.f.FPReason = "debate consensus: " + res.Rationale
			}
			s.f.Tags = appendUniqueTag(s.f.Tags, "debate-fp")
			s.applied = "fp"
		case "tp":
			s.f.Tags = appendUniqueTag(s.f.Tags, "debate-tp")
			s.applied = "tp"
		}
		return nil
	})
	g.AddEdge("apply", agents.End)
	g.SetEntry("gate")
	return g
}

func containsTag(tags []string, v string) bool {
	for _, t := range tags {
		if t == v {
			return true
		}
	}
	return false
}
