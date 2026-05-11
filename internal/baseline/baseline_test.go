package baseline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestFingerprintStable(t *testing.T) {
	f := types.Finding{RuleID: "sql", Agent: "scan:injection", File: "a.go", CodeSample: "db.Exec(query)"}
	fp1 := Fingerprint(f)
	fp2 := Fingerprint(f)
	if fp1 != fp2 || len(fp1) != 16 {
		t.Fatalf("not stable or wrong length: %q vs %q", fp1, fp2)
	}
}

func TestFingerprintCollapsesWhitespace(t *testing.T) {
	a := types.Finding{RuleID: "sql", Agent: "x", File: "a.go", CodeSample: "db .Exec   (query)"}
	b := types.Finding{RuleID: "sql", Agent: "x", File: "a.go", CodeSample: "db .Exec (query)"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("whitespace must be collapsed: %q != %q", Fingerprint(a), Fingerprint(b))
	}
}

func TestFingerprintHandlesCarriageReturns(t *testing.T) {
	a := types.Finding{RuleID: "r", File: "f", CodeSample: "x\r\ny"}
	b := types.Finding{RuleID: "r", File: "f", CodeSample: "x\ny"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("\\r should be stripped")
	}
}

func TestFingerprintFallbackToDescription(t *testing.T) {
	a := types.Finding{RuleID: "r", Agent: "g", File: "f", Description: "Some description"}
	b := types.Finding{RuleID: "r", Agent: "g", File: "f", Description: "Some description"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("should match by description when CodeSample empty")
	}
}

func TestFingerprintDifferentRules(t *testing.T) {
	a := types.Finding{RuleID: "sql", File: "a.go", CodeSample: "x"}
	b := types.Finding{RuleID: "xss", File: "a.go", CodeSample: "x"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Error("different rule_id must produce different fingerprint")
	}
}

func TestFilterNewKeepsUnknown(t *testing.T) {
	fs := []types.Finding{
		{RuleID: "sql", File: "a.go", CodeSample: "x"},
		{RuleID: "xss", File: "b.go", CodeSample: "y"},
	}
	known := map[string]struct{}{Fingerprint(fs[0]): {}}
	out := FilterNew(fs, known)
	if len(out) != 1 || out[0].RuleID != "xss" {
		t.Errorf("expected only xss to remain, got %+v", out)
	}
}

func TestFilterNewEmptyKnown(t *testing.T) {
	fs := []types.Finding{{RuleID: "a"}, {RuleID: "b"}}
	if got := FilterNew(fs, nil); len(got) != 2 {
		t.Errorf("nil known must return all findings, got %d", len(got))
	}
}

func TestAsMapRoundTrip(t *testing.T) {
	fs := []types.Finding{
		{RuleID: "sql", Agent: "scan:injection", File: "a.go", CodeSample: "x", StartLine: 12},
	}
	m := AsMap(fs)
	if len(m) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(m))
	}
	fp := Fingerprint(fs[0])
	if _, ok := m[fp]; !ok {
		t.Errorf("fingerprint %q missing from map: %+v", fp, m)
	}
}

func BenchmarkFingerprint(b *testing.B) {
	f := types.Finding{RuleID: "sql-injection", Agent: "scan:injection",
		File: "internal/handlers/user.go", CodeSample: "db.Exec(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id))"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Fingerprint(f)
	}
}
