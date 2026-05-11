package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/andrewaeva/llmscan/internal/types"
)

func sampleReport() types.Report {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	return types.Report{
		Target:       "/repo",
		StartedAt:    now,
		FinishedAt:   now.Add(2 * time.Second),
		FilesScanned: 3,
		Plan:         types.ScanPlan{Reasoning: "test plan", Priority: []string{"a.go"}, Focus: []string{"injection"}},
		Stats: types.Stats{
			Raw:         5,
			AfterDedup:  4,
			AfterVerify: 3,
			FalsePos:    1,
			BySeverity:  map[string]int{"critical": 1, "high": 1, "medium": 0, "low": 1},
			ByAgent:     map[string]int{"injection": 2, "secrets": 1},
		},
		Findings: []types.Finding{
			{
				ID: "f1", RuleID: "sql-inj", Title: "SQL Injection",
				Description: "concatenation reaches Exec", Severity: types.SevCritical, Confidence: types.ConfHigh,
				CWE: "CWE-89", OWASP: "A03:2021",
				File: "a.go", StartLine: 10, EndLine: 12,
				CodeSample:      "db.Exec(\"SELECT \" + s)",
				Agent:           "injection",
				Verified:        true,
				VerifierVerdict: "true_positive",
				VerifierComment: "confirmed",
				DeepVerified:    true,
				DeepVerdict:     "confirmed",
				DeepComment:     "tainted path",
				DeepTrace:       []types.DeepToolCall{{Step: 1, Tool: "read_file", Args: "{}", Ms: 12}},
				SuggestedFix:    "use prepared statements",
				References:      []string{"https://example/owasp"},
			},
			{
				ID: "f2", Title: "Hardcoded secret",
				Severity: types.SevHigh, Confidence: types.ConfMedium,
				Agent: "secrets", File: "b.go", StartLine: 5, EndLine: 5,
			},
			{
				ID: "f3", Title: "Low risk",
				Severity: types.SevLow, Confidence: types.ConfLow,
				Agent: "generic", File: "c.go", StartLine: 1, EndLine: 1,
				FalsePositive: true,
			},
		},
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	if err := WriteJSON(&buf, r); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var back types.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if back.Target != r.Target {
		t.Errorf("target=%s", back.Target)
	}
	if len(back.Findings) != 3 {
		t.Errorf("findings=%d", len(back.Findings))
	}
	if back.Findings[0].DeepVerified != true {
		t.Error("DeepVerified not preserved")
	}
	if len(back.Findings[0].DeepTrace) != 1 || back.Findings[0].DeepTrace[0].Tool != "read_file" {
		t.Errorf("DeepTrace: %+v", back.Findings[0].DeepTrace)
	}
}

func TestWriteTextNoColor(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTextWith(&buf, sampleReport(), ColorNever); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("unexpected ANSI in plain output: %q", out[:120])
	}
	for _, want := range []string{
		"llmscan report",
		"target:",
		"files scanned:",
		"raw=5",
		"dedup=4",
		"verified=3",
		"fp=1",
		"by severity:",
		"by agent:",
		"[CRITICAL]",
		"[HIGH]",
		"SQL Injection",
		"agent:",
		"location:",
		"a.go:10-12",
		"cwe:",
		"owasp:",
		"why:",
		"verifier:",
		"deep:",
		"fix:",
		"sample:",
		"injection",
		"secrets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing substring %q in text output", want)
		}
	}
}

func TestWriteTextAlwaysColor(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTextWith(&buf, sampleReport(), ColorAlways); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Errorf("expected ANSI escapes when color forced on")
	}
}

func TestWriteTextEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	r := sampleReport()
	r.Findings = nil
	r.Stats.BySeverity = nil
	r.Stats.ByAgent = nil
	if err := WriteTextWith(&buf, r, ColorNever); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(none — clean run)") {
		t.Errorf("expected clean run message; got %q", buf.String())
	}
}

func TestWriteTextDefaultAuto(t *testing.T) {
	// auto + non-TTY writer should disable color
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Error("expected no ANSI when writing to bytes.Buffer with auto mode")
	}
}

func TestSARIFOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("parse SARIF: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version=%v", doc["version"])
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs=%d", len(runs))
	}
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)["driver"].(map[string]any)
	if tool["name"] != "llmscan" {
		t.Errorf("driver=%v", tool["name"])
	}
	results, _ := run["results"].([]any)
	if len(results) != 2 { // FP excluded
		t.Fatalf("expected 2 results (FP excluded), got %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["ruleId"] != "sql-inj" {
		t.Errorf("ruleId=%v", first["ruleId"])
	}
	if first["level"] != "error" {
		t.Errorf("level for critical=%v", first["level"])
	}
	loc := first["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	uri := loc["artifactLocation"].(map[string]any)["uri"]
	if uri != "a.go" {
		t.Errorf("uri=%v", uri)
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	cases := []struct {
		sev  types.Severity
		want string
	}{
		{types.SevCritical, "error"},
		{types.SevHigh, "error"},
		{types.SevMedium, "warning"},
		{types.SevLow, "note"},
		{types.SevInfo, "note"},
		{types.Severity("xx"), "none"},
	}
	for _, tc := range cases {
		if got := sevToSARIF(tc.sev); got != tc.want {
			t.Errorf("sevToSARIF(%q)=%q want %q", tc.sev, got, tc.want)
		}
	}
}

func TestSARIFRuleIDFallback(t *testing.T) {
	r := types.Report{
		Findings: []types.Finding{
			{Title: "Some Issue", Agent: "generic", File: "a.go", StartLine: 1, EndLine: 1, Severity: types.SevMedium},
		},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\"generic/some-issue\"") {
		t.Errorf("ruleId fallback missing: %s", buf.String())
	}
}

func TestParseColorMode(t *testing.T) {
	cases := map[string]ColorMode{
		"always": ColorAlways,
		"YES":    ColorAlways,
		"on":     ColorAlways,
		"never":  ColorNever,
		"off":    ColorNever,
		"0":      ColorNever,
		"auto":   ColorAuto,
		"":       ColorAuto,
		"weird":  ColorAuto,
	}
	for in, want := range cases {
		if got := ParseColorMode(in); got != want {
			t.Errorf("ParseColorMode(%q)=%v want %v", in, got, want)
		}
	}
}

func TestPaletteOff(t *testing.T) {
	p := palette{on: false}
	if got := p.bold("x"); got != "x" {
		t.Errorf("bold off: %q", got)
	}
	if got := p.red("x"); got != "x" {
		t.Errorf("red off: %q", got)
	}
	if got := p.confColor("high"); got != "high" {
		t.Errorf("confColor off: %q", got)
	}
	if got := p.sevBadge(types.SevHigh); got != "[HIGH]" {
		t.Errorf("badge off: %q", got)
	}
}

func TestPaletteOn(t *testing.T) {
	p := palette{on: true}
	if !strings.Contains(p.bold("x"), "\x1b[1m") {
		t.Error("bold should emit ANSI")
	}
	if !strings.Contains(p.confColor("high"), "\x1b[32m") {
		t.Error("high confidence should be green")
	}
	if !strings.Contains(p.confColor("medium"), "\x1b[33m") {
		t.Error("medium should be yellow")
	}
	if !strings.Contains(p.confColor("low"), "\x1b[90m") {
		t.Error("low should be gray")
	}
	if p.confColor("weird") != "weird" {
		t.Error("unknown confidence echoed verbatim")
	}
	if !strings.Contains(p.sevBadge(types.SevCritical), "\x1b[41m") {
		t.Error("critical badge should use red bg")
	}
	if !strings.Contains(p.sevBadge(types.SevHigh), "\x1b[31m") {
		t.Error("high badge should be red")
	}
	if !strings.Contains(p.sevBadge(types.SevMedium), "\x1b[33m") {
		t.Error("medium should be yellow")
	}
	if !strings.Contains(p.sevBadge(types.SevLow), "\x1b[34m") {
		t.Error("low should be blue")
	}
	if !strings.Contains(p.sevBadge(types.SevInfo), "\x1b[2m") {
		t.Error("info should be dim")
	}
}

func TestPaletteEmptyArg(t *testing.T) {
	p := palette{on: true}
	if got := p.bold(""); got != "" {
		t.Errorf("bold of empty returned %q", got)
	}
}

func TestSevBadgeUnknown(t *testing.T) {
	p := palette{on: false}
	if got := p.sevBadge(types.Severity("")); got != "[UNKNOWN]" {
		t.Errorf("got %q", got)
	}
}

func TestOneLineTruncates(t *testing.T) {
	long := strings.Repeat("ab cd ", 80)
	if got := oneLine(long); len(got) <= 200 {
		// expected: trimmed below ~243 chars total including marker
	} else if !strings.HasSuffix(got, "...") {
		t.Errorf("expected trailing ellipsis on truncation; got %q", got[len(got)-5:])
	}
	if got := oneLine("a\nb\n  c"); got != "a b c" {
		t.Errorf("newline collapse: %q", got)
	}
}

func TestSevRank(t *testing.T) {
	if sevRank(types.SevCritical) <= sevRank(types.SevHigh) {
		t.Error("rank ordering")
	}
	if sevRank(types.SevHigh) <= sevRank(types.SevMedium) {
		t.Error("rank ordering")
	}
	if sevRank(types.SevInfo) <= 0 {
		t.Error("info rank >0")
	}
	if sevRank(types.Severity("garbage")) != 0 {
		t.Error("unknown rank = 0")
	}
}

func TestResolveColorEnv(t *testing.T) {
	var buf bytes.Buffer
	t.Setenv("NO_COLOR", "1")
	if resolveColor(&buf, ColorAuto) {
		t.Error("NO_COLOR should disable")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")
	if !resolveColor(&buf, ColorAuto) {
		t.Error("CLICOLOR_FORCE=1 should enable")
	}
	t.Setenv("CLICOLOR_FORCE", "")
	if resolveColor(&buf, ColorAuto) {
		t.Error("non-TTY writer should be disabled")
	}
	if !resolveColor(&buf, ColorAlways) {
		t.Error("ColorAlways always returns true")
	}
	if resolveColor(&buf, ColorNever) {
		t.Error("ColorNever always returns false")
	}
}
