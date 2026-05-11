package agents

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/tools"
	"github.com/andrewaeva/llmscan/internal/types"
)

// ---- parseGateVerdict tests ----

func TestParseGateVerdictWithGates(t *testing.T) {
	in := `Analysis...
{"verdict":"refuted","reason":"sanitized","fix":"",
 "gates":{
   "control":"pass","reachability":"pass",
   "validation":"fail","validation_reason":"upstream allowlist",
   "api_contract":"pass","environment":"pass","impact":"pass"
 }}`
	v, r, _, g, did := parseGateVerdict(in)
	if v != "refuted" {
		t.Errorf("verdict=%q", v)
	}
	if r != "sanitized" {
		t.Errorf("reason=%q", r)
	}
	if g == nil || g.Validation != types.GateFail {
		t.Errorf("gates=%+v", g)
	}
	if did {
		t.Error("defense_in_depth should be false")
	}
}

func TestParseGateVerdictWithFencesAndDefenseInDepth(t *testing.T) {
	in := "Scratch.\n" +
		"```json\n" +
		`{"verdict":"confirmed","reason":"real but robustness","defense_in_depth":true,` +
		`"gates":{"control":"pass","reachability":"pass","validation":"pass",` +
		`"api_contract":"pass","environment":"pass","impact":"fail","impact_reason":"panic only"}}` +
		"\n```"
	v, _, _, g, did := parseGateVerdict(in)
	if v != "confirmed" {
		t.Errorf("verdict=%q", v)
	}
	if !did {
		t.Error("defense_in_depth should be true")
	}
	if g == nil || g.Impact != types.GateFail {
		t.Errorf("gates=%+v", g)
	}
}

func TestParseGateVerdictNoGates(t *testing.T) {
	in := `{"verdict":"confirmed","reason":"x"}`
	v, _, _, g, did := parseGateVerdict(in)
	if v != "confirmed" {
		t.Errorf("verdict=%q", v)
	}
	if g != nil {
		t.Errorf("expected nil gates; got %+v", g)
	}
	if did {
		t.Error("defense_in_depth should default false")
	}
}

func TestParseGateVerdictJSONWithEmbeddedBrace(t *testing.T) {
	// Reason contains a literal '{' inside a string — should not throw off
	// the brace matcher.
	in := `{"verdict":"confirmed","reason":"saw '{' in source"}`
	v, r, _, _, _ := parseGateVerdict(in)
	if v != "confirmed" {
		t.Errorf("verdict=%q", v)
	}
	if r != "saw '{' in source" {
		t.Errorf("reason=%q", r)
	}
}

func TestParseGateVerdictMultipleJSONObjects(t *testing.T) {
	// First a draft, then the real one. Last balanced block wins.
	in := `{"verdict":"draft"} more text {"verdict":"refuted","reason":"final"}`
	v, r, _, _, _ := parseGateVerdict(in)
	if v != "refuted" {
		t.Errorf("verdict=%q", v)
	}
	if r != "final" {
		t.Errorf("reason=%q", r)
	}
}

func TestDeepAgentReconcilesVerdictWithGates(t *testing.T) {
	// Even if the model put verdict="confirmed" in JSON, an API-contract
	// FAIL should override that into "refuted".
	sandbox, _ := tools.NewSandbox(t.TempDir())
	final := `{
		"verdict":"confirmed",
		"reason":"draft conclusion",
		"gates":{
			"control":"pass","reachability":"pass",
			"validation":"pass","api_contract":"fail","api_contract_reason":"prepared stmt",
			"environment":"pass","impact":"pass"
		}
	}`
	tc := &stubToolClient{toolResp: llm.ToolResponse{FinalText: final, Model: "m"}}
	a := &DeepAgent{Client: tc, Sandbox: sandbox, Budget: 5, ModelName: "m"}
	res := a.Verify(context.Background(), types.Finding{File: "x.go", StartLine: 1})
	if res.Verdict != "refuted" {
		t.Errorf("verdict reconciliation failed: %q", res.Verdict)
	}
	if res.Gates == nil || res.Gates.APIContract != types.GateFail {
		t.Errorf("gates: %+v", res.Gates)
	}
}

func TestDeepAgentDefenseInDepthFlagFromGates(t *testing.T) {
	sandbox, _ := tools.NewSandbox(t.TempDir())
	final := `{
		"verdict":"confirmed",
		"reason":"real but no impact",
		"gates":{
			"control":"pass","reachability":"pass","validation":"pass",
			"api_contract":"pass","environment":"pass",
			"impact":"fail","impact_reason":"panic only"
		}
	}`
	tc := &stubToolClient{toolResp: llm.ToolResponse{FinalText: final, Model: "m"}}
	a := &DeepAgent{Client: tc, Sandbox: sandbox, Budget: 5, ModelName: "m"}
	res := a.Verify(context.Background(), types.Finding{File: "x.go", StartLine: 1})
	if !res.DefenseInDepth {
		t.Errorf("expected DefenseInDepth=true; got %+v", res)
	}
	if res.Verdict != "confirmed" {
		t.Errorf("verdict=%q", res.Verdict)
	}
}

func TestDeepSystemPromptHasGatesContract(t *testing.T) {
	p := deepSystemPrompt()
	for _, want := range []string{
		"Control", "Reachability", "Validation", "APIContract", "Environment", "Impact",
		"devils_advocate", "defense_in_depth",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("deep system prompt missing %q", want)
		}
	}
}

func TestParseVerdictTrailingJSON(t *testing.T) {
	in := "Some prose explaining stuff.\n" +
		`{"verdict":"confirmed","reason":"clear taint chain","fix":"escape input"}`
	v, r, f := parseVerdict(in)
	if v != "confirmed" || r != "clear taint chain" || f != "escape input" {
		t.Errorf("parsed=%q/%q/%q", v, r, f)
	}
}

func TestParseVerdictWrappedInFence(t *testing.T) {
	in := "Analysis...\n```json\n{\"verdict\":\"refuted\",\"reason\":\"sanitized\"}\n```"
	v, r, _ := parseVerdict(in)
	if v != "refuted" || r != "sanitized" {
		t.Errorf("parsed=%q reason=%q", v, r)
	}
}

func TestParseVerdictInvalidUnknown(t *testing.T) {
	v, _, _ := parseVerdict(`{"verdict":"yes","reason":"x"}`)
	if v != "inconclusive" {
		t.Errorf("unknown verdict should become inconclusive; got %q", v)
	}
}

func TestParseVerdictNoBrace(t *testing.T) {
	v, r, _ := parseVerdict("nothing here")
	if v != "inconclusive" || !strings.Contains(r, "nothing") {
		t.Errorf("got %q/%q", v, r)
	}
}

func TestParseVerdictBadJSON(t *testing.T) {
	v, r, _ := parseVerdict("{not really json}")
	if v != "inconclusive" {
		t.Errorf("expected inconclusive, got %q reason=%q", v, r)
	}
}

func TestParseVerdictLowercases(t *testing.T) {
	v, _, _ := parseVerdict(`{"verdict":"CONFIRMED","reason":"x"}`)
	if v != "confirmed" {
		t.Errorf("expected confirmed (lowercased), got %q", v)
	}
}

func TestCompactJSON(t *testing.T) {
	out := compactJSON([]byte(`{"a":  1, "b":2}`))
	if !strings.Contains(out, `"a":1`) || !strings.Contains(out, `"b":2`) {
		t.Errorf("compactJSON: %q", out)
	}
	if compactJSON(nil) != "{}" {
		t.Errorf("nil input should produce {}")
	}
	if compactJSON([]byte("not-json")) != "not-json" {
		t.Errorf("non-json passthrough")
	}
}

func TestShortFile(t *testing.T) {
	if shortFile("a/b/c.go") != "c.go" {
		t.Errorf("shortFile: %s", shortFile("a/b/c.go"))
	}
	if shortFile("just.go") != "just.go" {
		t.Errorf("no slash: %s", shortFile("just.go"))
	}
}

func TestOneLineDeep(t *testing.T) {
	in := strings.Repeat("ab cd ", 80) // > 200 chars
	got := oneLine(in)
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncation; got tail %q", got[len(got)-10:])
	}
	if got := oneLine("a\nb"); got != "a b" {
		t.Errorf("newline collapse: %q", got)
	}
}

func TestDeepUserPromptIncludesKeyFields(t *testing.T) {
	f := types.Finding{
		Agent: "injection", Severity: types.SevHigh, Confidence: types.ConfMedium,
		RuleID: "sql-inj", CWE: "CWE-89", File: "a.go", StartLine: 10, EndLine: 12,
		Title: "SQL", Description: "concat reaches Exec", CodeSample: "db.Exec(x)",
	}
	out := deepUserPrompt(f)
	for _, want := range []string{"injection", "high", "sql-inj", "CWE-89", "a.go:10-12", "SQL", "db.Exec(x)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in prompt: %q", want, out)
		}
	}
}

func TestDeepSystemPromptHasContract(t *testing.T) {
	p := deepSystemPrompt()
	for _, want := range []string{"read_file", "grep", "confirmed", "refuted", "inconclusive", "verdict"} {
		if !strings.Contains(p, want) {
			t.Errorf("system prompt missing %q", want)
		}
	}
}

func TestDeepToolDefsShape(t *testing.T) {
	defs := deepToolDefs()
	names := map[string]bool{}
	for _, d := range defs {
		names[d.Name] = true
		if d.InputSchema == nil {
			t.Errorf("tool %s missing schema", d.Name)
		}
	}
	for _, want := range []string{"read_file", "grep", "list_dir", "git_blame"} {
		if !names[want] {
			t.Errorf("missing tool def %s", want)
		}
	}
}

func TestDeepAgentVerifyNoConfig(t *testing.T) {
	a := &DeepAgent{}
	res := a.Verify(context.Background(), types.Finding{})
	if res.Verdict != "inconclusive" {
		t.Errorf("expected inconclusive when unconfigured, got %q", res.Verdict)
	}
}

func TestDeepAgentVerifyConfirmed(t *testing.T) {
	sandboxRoot := t.TempDir()
	sandbox, err := tools.NewSandbox(sandboxRoot)
	if err != nil {
		t.Fatal(err)
	}
	tc := &stubToolClient{
		toolResp: llm.ToolResponse{
			FinalText: "Looks bad.\n" + `{"verdict":"confirmed","reason":"taint reaches sink","fix":"escape"}`,
			Steps:     nil,
			Model:     "claude-deep",
		},
	}
	a := &DeepAgent{
		Client:    tc,
		Sandbox:   sandbox,
		Budget:    5,
		ModelName: "claude-deep",
	}
	res := a.Verify(context.Background(), types.Finding{File: "x.go", StartLine: 1})
	if res.Verdict != "confirmed" {
		t.Errorf("verdict=%q", res.Verdict)
	}
	if res.Reason != "taint reaches sink" {
		t.Errorf("reason=%q", res.Reason)
	}
	if res.Fix != "escape" {
		t.Errorf("fix=%q", res.Fix)
	}
}

func TestDeepAgentVerifyLLMErrorIsInconclusive(t *testing.T) {
	sandbox, _ := tools.NewSandbox(t.TempDir())
	tc := &stubToolClient{toolErr: errors.New("boom")}
	a := &DeepAgent{Client: tc, Sandbox: sandbox, Budget: 5, ModelName: "m"}
	res := a.Verify(context.Background(), types.Finding{File: "x.go"})
	if res.Verdict != "inconclusive" {
		t.Errorf("verdict=%q", res.Verdict)
	}
	if !strings.Contains(res.Reason, "boom") {
		t.Errorf("reason should include llm error, got %q", res.Reason)
	}
	if res.Model != "m" {
		t.Errorf("model=%q", res.Model)
	}
}

func TestDeepAgentDispatchTools(t *testing.T) {
	root := t.TempDir()
	if err := writeFile(filepath.Join(root, "a.go"), "line1\nline2\nline3\n"); err != nil {
		t.Fatal(err)
	}
	sandbox, _ := tools.NewSandbox(root)
	a := &DeepAgent{Sandbox: sandbox}

	// read_file
	out, err := a.dispatch(context.Background(), llm.ToolCall{
		Name: "read_file", Input: []byte(`{"path":"a.go","start_line":1,"end_line":3}`),
	})
	if err != nil || !strings.Contains(out, "line1") {
		t.Errorf("read_file: out=%q err=%v", out, err)
	}

	// grep
	_, err = a.dispatch(context.Background(), llm.ToolCall{
		Name: "grep", Input: []byte(`{"pattern":"line2","max_matches":10}`),
	})
	if err != nil {
		t.Errorf("grep: %v", err)
	}

	// list_dir
	out, err = a.dispatch(context.Background(), llm.ToolCall{
		Name: "list_dir", Input: []byte(`{"path":"."}`),
	})
	if err != nil || !strings.Contains(out, "a.go") {
		t.Errorf("list_dir: out=%q err=%v", out, err)
	}

	// unknown tool
	_, err = a.dispatch(context.Background(), llm.ToolCall{Name: "evil"})
	if err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("expected unknown-tool error, got %v", err)
	}

	// bad args
	_, err = a.dispatch(context.Background(), llm.ToolCall{Name: "read_file", Input: []byte("not-json")})
	if err == nil || !strings.Contains(err.Error(), "bad args") {
		t.Errorf("expected bad args err, got %v", err)
	}
}

func TestDeepAgentLogfNoop(t *testing.T) {
	// Just exercise the branch where Logf is nil or Verbose=false.
	a := &DeepAgent{}
	a.logf("anything %d", 1)
	called := false
	a.Logf = func(format string, args ...any) { called = true }
	a.logf("test")
	if called {
		t.Error("logf should be no-op when Verbose=false")
	}
	a.Verbose = true
	a.logf("test")
	if !called {
		t.Error("logf should call Logf when Verbose=true")
	}
}

func TestContextFilterFallsBackWhenNilClient(t *testing.T) {
	cf := &ContextFilter{}
	out, err := cf.Filter(context.Background(), nil, nil, "injection", 3)
	if err != nil || len(out) != 0 {
		t.Errorf("nil candidates: out=%v err=%v", out, err)
	}
}

func TestFormatChunksAsContextEmpty(t *testing.T) {
	if FormatChunksAsContext(nil) != "" {
		t.Error("empty chunks should produce empty string")
	}
}

// writeFile is a tiny helper used by deep tests above.
func writeFile(path, content string) error {
	return writeFileAtomic(path, []byte(content))
}
