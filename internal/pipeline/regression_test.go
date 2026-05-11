package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

// TestReachDowngradeDoesNotClobberVerifiedConfidence is a regression for the
// bug where reach.Apply forced verified/deep-confirmed findings down to "low",
// undoing the strong-evidence floor. After the fix, resolveConfidence (called
// after the deep pass) must restore the appropriate floor.
func TestReachDowngradeDoesNotClobberVerifiedConfidence(t *testing.T) {
	// Verifier confirmed + deep confirmed; reach tried to downgrade.
	in := types.Finding{
		Severity:        types.SevCritical,
		Confidence:      types.ConfLow, // reach forced this
		File:            "internal/foo/bar.go",
		FPReason:        "reachability: no incoming calls",
		Verified:        true,
		VerifierVerdict: "true_positive",
		DeepVerified:    true,
		DeepVerdict:     "confirmed",
	}
	out := resolveConfidence(in)
	if out != types.ConfHigh {
		t.Errorf("verified+deep-confirmed must stay high, got %q", out)
	}

	// Only verifier confirmed → reach drops by one step but cannot go below medium.
	in2 := types.Finding{
		Severity:        types.SevHigh,
		Confidence:      types.ConfLow,
		File:            "internal/foo/foo_test.go",
		FPReason:        "reachability: test fixture",
		Verified:        true,
		VerifierVerdict: "true_positive",
	}
	if got := resolveConfidence(in2); got != types.ConfMedium {
		t.Errorf("verified+test-path must stay ≥medium, got %q", got)
	}

	// Secrets-prefilter with reach downgrade keeps high.
	in3 := types.Finding{
		Severity:   types.SevCritical,
		Confidence: types.ConfLow,
		File:       "tests/fixtures/secrets.py",
		Agent:      "secrets-prefilter",
	}
	if got := resolveConfidence(in3); got != types.ConfHigh {
		t.Errorf("secrets-prefilter must remain high even in test path, got %q", got)
	}
}

// TestDedupAndCountWithIdenticalKeysReducesToOne ensures the pipeline's
// dedupAndCount removes exact duplicates inside the same run.
func TestDedupAndCountIdempotent(t *testing.T) {
	in := []types.Finding{
		{Agent: "a", File: "x.go", StartLine: 1, EndLine: 1, Title: "T"},
		{Agent: "a", File: "x.go", StartLine: 1, EndLine: 1, Title: "T"},
		{Agent: "a", File: "x.go", StartLine: 1, EndLine: 1, Title: "T"},
	}
	out := dedupAndCount(in)
	if len(out) != 1 {
		t.Errorf("expected 1 after dedup; got %d", len(out))
	}
}
