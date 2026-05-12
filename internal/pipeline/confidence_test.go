package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestResolveConfidence(t *testing.T) {
	cases := []struct {
		name string
		in   types.Finding
		want types.Confidence
	}{
		{
			name: "verifier_only_true_positive",
			in: types.Finding{
				Severity: types.SevHigh, Confidence: types.ConfLow,
				Verified: true, VerifierVerdict: "true_positive",
			},
			want: types.ConfHigh,
		},
		{
			name: "deep_only_confirmed",
			in: types.Finding{
				Severity: types.SevCritical, Confidence: types.ConfLow,
				DeepVerified: true, DeepVerdict: "confirmed",
			},
			want: types.ConfHigh,
		},
		{
			name: "verifier_and_deep_both",
			in: types.Finding{
				Severity: types.SevCritical, Confidence: types.ConfLow,
				Verified: true, VerifierVerdict: "true_positive",
				DeepVerified: true, DeepVerdict: "confirmed",
			},
			want: types.ConfHigh,
		},
		{
			name: "deep_inconclusive_keeps_current",
			in: types.Finding{
				Severity: types.SevMedium, Confidence: types.ConfMedium,
				DeepVerified: true, DeepVerdict: "inconclusive",
			},
			want: types.ConfMedium,
		},
		{
			name: "taint_trace_lifts_low_to_medium",
			in: types.Finding{
				Severity: types.SevMedium, Confidence: types.ConfLow,
				Trace: []types.TraceHop{{File: "a.go", Line: 1, Kind: "source"}, {Kind: "sink"}},
			},
			want: types.ConfMedium,
		},
		{
			name: "in_test_code_downgrades_one_step",
			in: types.Finding{
				Severity: types.SevHigh, Confidence: types.ConfHigh,
				File: "internal/foo/foo_test.go",
			},
			want: types.ConfMedium,
		},
		{
			name: "reach_downgrade_does_not_drop_below_medium_when_verifier_confirms",
			in: types.Finding{
				Severity: types.SevHigh, Confidence: types.ConfLow,
				File:     "internal/foo/foo_test.go",
				FPReason: "reachability: test fixture file",
				Verified: true, VerifierVerdict: "true_positive",
			},
			want: types.ConfMedium,
		},
		{
			name: "reach_downgrade_keeps_high_when_verifier_and_deep_both_confirm",
			in: types.Finding{
				Severity:        types.SevCritical,
				Confidence:      types.ConfLow,
				File:            "internal/foo/bar.go",
				FPReason:        "reachability: no incoming calls (likely dead module)",
				Verified:        true,
				VerifierVerdict: "true_positive",
				DeepVerified:    true,
				DeepVerdict:     "confirmed",
			},
			want: types.ConfHigh,
		},
		{
			name: "critical_severity_floors_at_medium",
			in: types.Finding{
				Severity: types.SevCritical, Confidence: types.ConfLow,
			},
			want: types.ConfMedium,
		},
		{
			name: "low_severity_no_signals_stays_low",
			in: types.Finding{
				Severity: types.SevLow, Confidence: types.ConfLow,
			},
			want: types.ConfLow,
		},
		{
			name: "false_positive_blocks_verifier_boost",
			in: types.Finding{
				Severity: types.SevHigh, Confidence: types.ConfLow,
				Verified: true, VerifierVerdict: "true_positive",
				FalsePositive: true,
			},
			// Floor from severity only (medium), no high boost.
			want: types.ConfMedium,
		},
		{
			name: "empty_confidence_with_no_signals_resolves_to_low",
			in: types.Finding{
				Severity: types.SevInfo,
			},
			want: types.ConfLow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveConfidence(tc.in)
			if got != tc.want {
				t.Fatalf("resolveConfidence: got %q, want %q (finding=%+v)", got, tc.want, tc.in)
			}
		})
	}
}

func TestApplyConfidence_CountsChanges(t *testing.T) {
	fs := []types.Finding{
		{Severity: types.SevCritical, Confidence: types.ConfLow,
			Verified: true, VerifierVerdict: "true_positive"},
		{Severity: types.SevLow, Confidence: types.ConfLow},
	}
	n := applyConfidence(fs)
	if n != 1 {
		t.Fatalf("expected 1 change, got %d", n)
	}
	if fs[0].Confidence != types.ConfHigh {
		t.Fatalf("first finding should be high, got %q", fs[0].Confidence)
	}
	if fs[1].Confidence != types.ConfLow {
		t.Fatalf("second finding should remain low, got %q", fs[1].Confidence)
	}
}
