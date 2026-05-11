package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
)

// attachTraces must downgrade severity/confidence and PASS Gate 3 when
// the matched Trace carries a SanitizerID or Guarded flag.
func TestAttachTraces_GuardDowngrade(t *testing.T) {
	trGuarded := taint.Trace{
		Category:  "sql",
		Hops:      []types.TraceHop{{File: "a.go", Line: 1, Kind: "source"}, {File: "a.go", Line: 5, Kind: "sink"}},
		Guarded:   true,
		GuardKind: "validation_pass",
	}
	trSanitizer := taint.Trace{
		Category:    "sql",
		Hops:        []types.TraceHop{{File: "b.go", Line: 1, Kind: "source"}, {File: "b.go", Line: 5, Kind: "sink"}},
		SanitizerID: "java-prepared-statement-setstring",
	}
	traces := map[string][]taint.Trace{
		"a.go": {trGuarded},
		"b.go": {trSanitizer},
	}
	findings := []types.Finding{
		{File: "a.go", StartLine: 4, EndLine: 6, Severity: types.SevCritical, Confidence: types.ConfHigh},
		{File: "b.go", StartLine: 4, EndLine: 6, Severity: types.SevHigh, Confidence: types.ConfHigh},
	}
	attachTraces(findings, traces)

	if findings[0].Severity != types.SevHigh {
		t.Errorf("guarded finding severity: want high, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != types.ConfMedium {
		t.Errorf("guarded finding confidence: want medium, got %s", findings[0].Confidence)
	}
	if !hasTag(findings[0].Tags, "taint-guarded") {
		t.Errorf("expected taint-guarded tag, got %v", findings[0].Tags)
	}

	// Sanitizer match auto-passes Gate 3.
	if findings[1].Gates == nil || findings[1].Gates.Validation != types.GatePass {
		t.Errorf("expected Gate 3 PASS for sanitizer match, got gates=%+v", findings[1].Gates)
	}
	if findings[1].Sanitizer == "" {
		t.Errorf("expected Sanitizer field populated")
	}
	if findings[1].Severity != types.SevMedium {
		t.Errorf("expected severity downgrade high->medium, got %s", findings[1].Severity)
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
