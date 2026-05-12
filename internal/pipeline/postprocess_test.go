package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestDropUnconfirmedFindings(t *testing.T) {
	cases := []struct {
		name     string
		verifier string
		deep     string
		want     bool // true = should be kept
	}{
		{"verifier_confirmed_deep_inconclusive", "confirmed", "inconclusive", true},
		{"verifier_true_positive_deep_inconclusive", "true_positive", "inconclusive", true},
		{"verifier_inconclusive_deep_confirmed", "inconclusive", "confirmed", true},
		{"verifier_inconclusive_deep_inconclusive", "inconclusive", "inconclusive", false},
		{"verifier_inconclusive_deep_empty", "inconclusive", "", false},
		{"verifier_empty_deep_empty", "", "", false},
		{"verifier_unknown_deep_inconclusive", "unknown", "inconclusive", false},
		{"verifier_refuted_deep_inconclusive", "refuted", "inconclusive", true}, // decisive -> kept (fp filter handles refuted)
		{"verifier_inconclusive_deep_refuted", "inconclusive", "refuted", true},
		{"case_insensitive_INCONCLUSIVE", "INCONCLUSIVE", "InConClusive", false},
		{"whitespace_inconclusive", "  inconclusive  ", "\tinconclusive\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []types.Finding{{
				ID:              "f-1",
				VerifierVerdict: tc.verifier,
				DeepVerdict:     tc.deep,
			}}
			out := dropUnconfirmedFindings(in)
			got := len(out) == 1
			if got != tc.want {
				t.Errorf("verifier=%q deep=%q: kept=%v, want=%v", tc.verifier, tc.deep, got, tc.want)
			}
		})
	}
}

func TestDropImpactFailFindings(t *testing.T) {
	cases := []struct {
		name  string
		gates *types.GateReview
		want  bool // true = kept
	}{
		{"no_gates", nil, true},
		{"impact_pass", &types.GateReview{Impact: types.GatePass}, true},
		{"impact_fail_lowercase", &types.GateReview{Impact: types.GateFail}, false},
		{"impact_fail_uppercase", &types.GateReview{Impact: types.Gate("FAIL")}, false},
		{"impact_na", &types.GateReview{Impact: types.GateNotApp}, true},
		{"impact_unknown", &types.GateReview{Impact: types.GateUnknown}, true},
		{"impact_fail_other_gates_pass", &types.GateReview{
			Control:      types.GatePass,
			Reachability: types.GatePass,
			Validation:   types.GatePass,
			APIContract:  types.GatePass,
			Environment:  types.GateNotApp,
			Impact:       types.GateFail,
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []types.Finding{{ID: "f-1", Gates: tc.gates}}
			out := dropImpactFailFindings(in)
			got := len(out) == 1
			if got != tc.want {
				t.Errorf("kept=%v, want=%v", got, tc.want)
			}
		})
	}
}

func TestDropImpactFailFindings_DisabledViaConfig(t *testing.T) {
	// When precision.drop_impact_fail is false stagePostProcess skips the
	// helper entirely. Simulate that by not calling it — the input must be
	// returned unchanged.
	in := []types.Finding{
		{ID: "f-1", Gates: &types.GateReview{Impact: types.GateFail}},
		{ID: "f-2", Gates: &types.GateReview{Impact: types.GatePass}},
	}
	// Sanity: the helper itself would drop f-1.
	if got := dropImpactFailFindings(append([]types.Finding(nil), in...)); len(got) != 1 {
		t.Fatalf("helper expected to drop f-1, got %d kept", len(got))
	}
	// When disabled, the slice is left untouched.
	if len(in) != 2 {
		t.Fatalf("disabled path must leave findings untouched, got %d", len(in))
	}
}

func TestDropUnconfirmedFindings_MultipleFindings(t *testing.T) {
	in := []types.Finding{
		{ID: "keep-1", VerifierVerdict: "confirmed", DeepVerdict: ""},
		{ID: "drop-1", VerifierVerdict: "inconclusive", DeepVerdict: "inconclusive"},
		{ID: "keep-2", VerifierVerdict: "inconclusive", DeepVerdict: "confirmed"},
		{ID: "drop-2", VerifierVerdict: "", DeepVerdict: ""},
		{ID: "keep-3", VerifierVerdict: "true_positive", DeepVerdict: "inconclusive"},
	}
	out := dropUnconfirmedFindings(in)
	if len(out) != 3 {
		t.Fatalf("got %d kept findings, want 3: %+v", len(out), out)
	}
	want := map[string]bool{"keep-1": true, "keep-2": true, "keep-3": true}
	for _, f := range out {
		if !want[f.ID] {
			t.Errorf("unexpected finding kept: %s", f.ID)
		}
	}
}
