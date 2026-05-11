package eval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadLabelsUnknownAdapter(t *testing.T) {
	_, err := LoadLabels("nope", "x")
	if err == nil {
		t.Error("expected error for unknown adapter")
	}
}

func TestLoadGenericLabels(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "labels.json", `[
		{"file":"a.go","cwe":"CWE-89","line":12},
		{"file":"b.py","cwe":"CWE-78"}
	]`)
	got, err := LoadLabels("generic", p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 || got[0].CWE != "CWE-89" || got[1].File != "b.py" {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestLoadGenericBadFile(t *testing.T) {
	if _, err := LoadLabels("generic", "/no/such/path"); err == nil {
		t.Error("expected error")
	}
}

func TestLoadSecurityEval(t *testing.T) {
	dir := t.TempDir()
	jsonl := `{"path":"a.py","cwe":"CWE-79","label":1}
{"path":"b.py","cwe":"CWE-78","label":0}
{"path":"","cwe":"CWE-89","label":1}

{"path":"c.py","cwe":"CWE-89","label":1}`
	p := writeFile(t, dir, "data.jsonl", jsonl)
	got, err := LoadLabels("securityeval", p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d labels, want 2: %+v", len(got), got)
	}
}

func TestLoadOwasp(t *testing.T) {
	dir := t.TempDir()
	csvData := `# test name, category, real vuln, cwe
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,xss,false,79
BenchmarkTest00003,path,true,22
`
	p := writeFile(t, dir, "expected.csv", csvData)
	got, err := LoadLabels("owasp-benchmark", p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d want 2: %+v", len(got), got)
	}
	if got[0].File != "BenchmarkTest00001.java" || got[0].CWE != "CWE-89" {
		t.Errorf("unexpected first: %+v", got[0])
	}
}

func TestLoadJuliet(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "CWE89_SQL_Injection_basic_01.java", "// stub")
	writeFile(t, dir, "CWE78_OS_Command_basic_01.java", "// stub")
	writeFile(t, dir, "README.md", "ignore me")
	got, err := LoadLabels("juliet", dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d want 2: %+v", len(got), got)
	}
	cwes := map[string]bool{}
	for _, l := range got {
		cwes[l.CWE] = true
	}
	if !cwes["CWE-89"] || !cwes["CWE-78"] {
		t.Errorf("missing CWE: %v", cwes)
	}
}

func TestComparePerfect(t *testing.T) {
	preds := []types.Finding{
		{File: "a.go", CWE: "CWE-89"},
		{File: "b.go", CWE: "CWE-78"},
	}
	labels := []Label{
		{File: "a.go", CWE: "CWE-89"},
		{File: "b.go", CWE: "CWE-78"},
	}
	m := Compare(preds, labels)
	if m.TP != 2 || m.FP != 0 || m.FN != 0 {
		t.Errorf("got TP=%d FP=%d FN=%d", m.TP, m.FP, m.FN)
	}
	if m.Precision != 1 || m.Recall != 1 || m.F1 != 1 {
		t.Errorf("perfect P/R/F1 expected, got %+v", m)
	}
}

func TestCompareMixed(t *testing.T) {
	preds := []types.Finding{
		{File: "a.go", CWE: "CWE-89"}, // TP
		{File: "x.go", CWE: "CWE-22"}, // FP
	}
	labels := []Label{
		{File: "a.go", CWE: "CWE-89"},
		{File: "b.go", CWE: "CWE-78"}, // FN
	}
	m := Compare(preds, labels)
	if m.TP != 1 || m.FP != 1 || m.FN != 1 {
		t.Errorf("got TP=%d FP=%d FN=%d", m.TP, m.FP, m.FN)
	}
	if got := m.Precision; got != 0.5 {
		t.Errorf("P=%v want 0.5", got)
	}
	if got := m.Recall; got != 0.5 {
		t.Errorf("R=%v want 0.5", got)
	}
	if got := m.F1; got != 0.5 {
		t.Errorf("F1=%v want 0.5", got)
	}
}

func TestCompareEmptyBoth(t *testing.T) {
	m := Compare(nil, nil)
	if m.TP != 0 || m.FP != 0 || m.FN != 0 {
		t.Errorf("expected zeros, got %+v", m)
	}
	if m.Precision != 0 || m.Recall != 0 || m.F1 != 0 {
		t.Errorf("expected zero rates")
	}
}

func TestCompareCaseInsensitiveCWE(t *testing.T) {
	preds := []types.Finding{{File: "a.go", CWE: "cwe-89"}}
	labels := []Label{{File: "a.go", CWE: "CWE-89"}}
	m := Compare(preds, labels)
	if m.TP != 1 {
		t.Errorf("expected case-insensitive match, got TP=%d", m.TP)
	}
}

func TestPrintReportDoesNotPanic(t *testing.T) {
	m := Compare([]types.Finding{{File: "a.go", CWE: "CWE-89"}}, []Label{{File: "a.go", CWE: "CWE-89"}})
	PrintReport(m) // shouldn't panic
}

func BenchmarkCompare(b *testing.B) {
	var preds []types.Finding
	var labels []Label
	for i := 0; i < 500; i++ {
		fn := "f" + string(rune('A'+(i%26))) + ".go"
		labels = append(labels, Label{File: fn, CWE: "CWE-89"})
		if i%2 == 0 {
			preds = append(preds, types.Finding{File: fn, CWE: "CWE-89"})
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Compare(preds, labels)
	}
}
