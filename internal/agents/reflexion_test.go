package agents

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestReflexionScannerEarlyStopWhenCriticEmpty(t *testing.T) {
	// Inner returns one finding. Critic returns "{}" → no feedback → stop.
	inner := &Scanner{
		Name: "x",
		Client: &stubClient{responses: []string{
			`{"findings":[{"rule_id":"X-1","title":"sql injection","severity":"high"}]}`,
		}},
	}
	critic := &stubClient{responses: []string{`{}`}}
	r := &ReflexionScanner{Inner: inner, Critic: critic, MaxIters: 2}

	got, err := r.Scan(context.Background(), types.FileTarget{Path: "a.go", Language: "go", Content: "foo"}, "")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "X-1" {
		t.Fatalf("expected 1 finding from initial pass, got %+v", got)
	}
	// Inner was called once (initial); reviser must NOT have been invoked
	// because critic returned no feedback. Inner has only 1 scripted resp.
}

func TestReflexionScannerReviseAppliesCritique(t *testing.T) {
	// Inner returns 2 findings on first call, 1 on second (revised).
	inner := &Scanner{
		Name: "x",
		Client: &stubClient{responses: []string{
			`{"findings":[{"rule_id":"X-1","title":"a","severity":"high"},{"rule_id":"X-2","title":"b","severity":"low"}]}`,
			`{"findings":[{"rule_id":"X-1","title":"a","severity":"high"}]}`,
		}},
	}
	critic := &stubClient{responses: []string{
		`{"spurious_ids":["X-2"], "notes":"X-2 is in a test file"}`,
	}}
	r := &ReflexionScanner{Inner: inner, Critic: critic, MaxIters: 1}

	got, err := r.Scan(context.Background(), types.FileTarget{Path: "a.go", Language: "go", Content: "foo"}, "ctx")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "X-1" {
		t.Fatalf("expected revised single finding, got %+v", got)
	}
	if !strings.Contains(critic.last.Messages[0].Content, "X-1") {
		t.Errorf("critic user prompt missing findings JSON: %q", critic.last.Messages[0].Content)
	}
}

func TestReflexionScannerInnerErrorPropagates(t *testing.T) {
	inner := &Scanner{Name: "x", Client: &stubClient{}}
	r := &ReflexionScanner{Inner: inner, Critic: &stubClient{responses: []string{"{}"}}}
	_, err := r.Scan(context.Background(), types.FileTarget{}, "")
	if err == nil {
		t.Fatalf("expected error from inner with no scripted response")
	}
}

func TestCritiqueRenderShape(t *testing.T) {
	c := Critique{
		SpuriousIDs:    []string{"a", "b"},
		WeakFindings:   []string{"c"},
		MissedPatterns: []string{"unchecked redirect target", "raw SQL via fmt.Sprintf"},
		Notes:          "consider context.WithTimeout",
	}
	out := c.Render()
	for _, want := range []string{"false positives", "thin evidence", "unchecked redirect", "WithTimeout", "Re-emit"} {
		if !strings.Contains(out, want) {
			t.Errorf("Render missing %q: %s", want, out)
		}
	}
}

func TestCritiqueHasFeedback(t *testing.T) {
	if (Critique{}).HasFeedback() {
		t.Error("empty critique should not have feedback")
	}
	if !(Critique{Notes: "x"}).HasFeedback() {
		t.Error("notes should count as feedback")
	}
	if !(Critique{SpuriousIDs: []string{"a"}}).HasFeedback() {
		t.Error("spurious_ids should count as feedback")
	}
}
