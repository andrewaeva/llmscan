package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
)

func TestApplyPlanReordersByPriority(t *testing.T) {
	files := []types.FileTarget{
		{Path: "a.go"}, {Path: "b.go"}, {Path: "c.go"}, {Path: "d.go"},
	}
	plan := types.ScanPlan{Priority: []string{"c.go", "a.go"}}
	out := applyPlan(files, plan)
	if out[0].Path != "c.go" || out[1].Path != "a.go" {
		t.Errorf("priority order: %v", paths(out))
	}
	// Remaining files come after, in original order.
	if out[2].Path != "b.go" || out[3].Path != "d.go" {
		t.Errorf("rest order: %v", paths(out))
	}
}

func TestApplyPlanEmptyPriorityIsNoop(t *testing.T) {
	files := []types.FileTarget{{Path: "a"}, {Path: "b"}}
	out := applyPlan(files, types.ScanPlan{})
	if len(out) != 2 || out[0].Path != "a" {
		t.Errorf("noop expected, got %v", paths(out))
	}
}

func TestDedupAndCount(t *testing.T) {
	in := []types.Finding{
		{Agent: "a", File: "x.go", StartLine: 1, EndLine: 2, Title: "T1"},
		{Agent: "a", File: "x.go", StartLine: 1, EndLine: 2, Title: "T1"}, // dup
		{Agent: "a", File: "x.go", StartLine: 3, EndLine: 4, Title: "T2"},
		{Agent: "b", File: "x.go", StartLine: 1, EndLine: 2, Title: "T1"}, // different agent
	}
	out := dedupAndCount(in)
	if len(out) != 3 {
		t.Errorf("expected 3 unique, got %d", len(out))
	}
}

func TestMatchTraceNearestSink(t *testing.T) {
	traces := []taint.Trace{
		{Hops: []types.TraceHop{{Line: 1, Kind: "source"}, {Line: 10, Kind: "sink"}}},
		{Hops: []types.TraceHop{{Line: 20, Kind: "source"}, {Line: 25, Kind: "sink"}}},
		{Hops: nil}, // empty -> skipped
	}
	if got := matchTrace(traces, 9, 12); got == nil || got.Hops[len(got.Hops)-1].Line != 10 {
		t.Errorf("expected first trace match, got %+v", got)
	}
	if got := matchTrace(traces, 100, 110); got != nil {
		t.Errorf("expected nil for far line, got %+v", got)
	}
}

func TestPickFinalFindingsPrefersFPFilter(t *testing.T) {
	report := &types.Report{Stats: types.Stats{}}
	outputs := map[string]any{
		"scan_aggregate": []types.Finding{{ID: "1"}, {ID: "2"}, {ID: "3"}},
		"dedup":          []types.Finding{{ID: "1"}, {ID: "2"}},
		"verifier":       []types.Finding{{ID: "v1"}},
		"fp_filter":      []types.Finding{{ID: "f1"}},
	}
	final := pickFinalFindings(outputs, report)
	if len(final) != 1 || final[0].ID != "f1" {
		t.Errorf("fp_filter should win, got %+v", final)
	}
	if report.Stats.Raw != 3 || report.Stats.AfterDedup != 2 || report.Stats.AfterVerify != 1 {
		t.Errorf("stats wrong: %+v", report.Stats)
	}
}

func TestPickFinalFindingsFallsBackToVerifier(t *testing.T) {
	report := &types.Report{Stats: types.Stats{}}
	outputs := map[string]any{
		"verifier": []types.Finding{{ID: "v"}},
	}
	final := pickFinalFindings(outputs, report)
	if len(final) != 1 || final[0].ID != "v" {
		t.Errorf("verifier fallback failed: %+v", final)
	}
}

func TestApplySuppressionsMarksFinding(t *testing.T) {
	e := New(config.Default())
	final := []types.Finding{
		{File: "a.go", StartLine: 10, RuleID: "rule1", Agent: "injection"},
	}
	sups := []suppress.Suppression{
		{File: "a.go", Line: 10, Rule: "*", Reason: "intentional"},
	}
	e.applySuppressions(final, sups)
	if !final[0].Suppressed {
		t.Errorf("expected Suppressed=true; got %+v", final[0])
	}
}

func TestApplySuppressionsEmpty(t *testing.T) {
	e := New(config.Default())
	final := []types.Finding{{File: "a.go", StartLine: 1}}
	e.applySuppressions(final, nil)
	if final[0].Suppressed {
		t.Error("should not mark suppressed when no entries")
	}
}

func TestAttachTraces(t *testing.T) {
	tr := taint.Trace{
		Hops:      []types.TraceHop{{Line: 1, Kind: "source"}, {Line: 5, Kind: "sink"}},
		Sanitizer: "html.EscapeString",
	}
	traces := map[string][]taint.Trace{"x.go": {tr}}
	fnds := []types.Finding{{File: "x.go", StartLine: 5, EndLine: 5}}
	attachTraces(fnds, traces)
	if len(fnds[0].Trace) == 0 {
		t.Errorf("trace not attached: %+v", fnds[0])
	}
	if fnds[0].Sanitizer != "html.EscapeString" {
		t.Errorf("sanitizer not propagated: %q", fnds[0].Sanitizer)
	}

	// Empty map → no-op.
	attachTraces(fnds, nil)
}

func TestDropByPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.DropFalsePositives = true
	cfg.Precision.MinScore = 0.5
	e := New(cfg)
	report := &types.Report{Stats: types.Stats{}}
	in := []types.Finding{
		{ID: "1", FalsePositive: true},
		{ID: "2", Suppressed: true},
		{ID: "3", Score: 0.2},
		{ID: "4", Score: 0.9},
		{ID: "5"},
	}
	out := e.dropByPolicy(in, report)
	if report.Stats.FalsePos != 1 {
		t.Errorf("FalsePos count=%d", report.Stats.FalsePos)
	}
	var ids []string
	for _, f := range out {
		ids = append(ids, f.ID)
	}
	if !contains(ids, "4") || !contains(ids, "5") {
		t.Errorf("kept set unexpected: %v", ids)
	}
	if contains(ids, "1") || contains(ids, "2") || contains(ids, "3") {
		t.Errorf("dropped findings not removed: %v", ids)
	}
}

func TestDropByPolicyKeepsFPWhenFlagDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.DropFalsePositives = false
	e := New(cfg)
	report := &types.Report{Stats: types.Stats{}}
	in := []types.Finding{{ID: "x", FalsePositive: true}}
	out := e.dropByPolicy(in, report)
	if len(out) != 1 {
		t.Errorf("expected to keep FP; got %v", out)
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank("critical") <= severityRank("high") {
		t.Error("critical>high")
	}
	if severityRank("high") <= severityRank("medium") {
		t.Error("high>medium")
	}
	if severityRank("medium") <= severityRank("low") {
		t.Error("medium>low")
	}
	if severityRank("low") <= severityRank("info") {
		t.Error("low>info")
	}
	if severityRank("garbage") != 0 {
		t.Errorf("unknown=%d", severityRank("garbage"))
	}
}

func TestDeepBudgetDefault(t *testing.T) {
	if deepBudget(config.DeepConfig{}) != 40 {
		t.Error("expected default 40")
	}
	if deepBudget(config.DeepConfig{Budget: 12}) != 12 {
		t.Error("budget override")
	}
}

func TestRunDeepPassDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Deep.Enabled = false
	e := New(cfg)
	in := []types.Finding{{File: "a.go", Severity: types.SevHigh}}
	out := e.runDeepPass(nil, ".", nil, in)
	if len(out) != 1 || out[0].DeepVerified {
		t.Errorf("disabled pass should be no-op; got %+v", out)
	}
}

func TestRunDeepPassNoFindings(t *testing.T) {
	cfg := config.Default()
	cfg.Deep.Enabled = true
	e := New(cfg)
	out := e.runDeepPass(nil, ".", nil, nil)
	if len(out) != 0 {
		t.Error("empty input should remain empty")
	}
}

func TestOpenCacheDBDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Cache.Enabled = false
	e := New(cfg)
	if cdb := e.openCacheDB(); cdb != nil {
		t.Error("expected nil cache when disabled")
		cdb.Close()
	}
}

func TestOpenCacheDBOpensAndCloses(t *testing.T) {
	cfg := config.Default()
	cfg.Cache.Enabled = true
	cfg.Cache.Path = filepath.Join(t.TempDir(), "cache.db")
	e := New(cfg)
	cdb := e.openCacheDB()
	if cdb == nil {
		t.Fatal("expected cache to open")
	}
	cdb.Close()
}

func TestDiscoverFilesDirectory(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "a.go"), []byte("package a\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "b.py"), []byte("print('hi')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Scan.MaxFileBytes = 1 << 20
	e := New(cfg)
	files, err := e.discoverFiles(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Errorf("expected ≥2 files, got %d", len(files))
	}
}

func TestDiscoverFilesSingleFileFallback(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "single.go")
	if err := os.WriteFile(p, []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	// Force exclude * so walk turns up nothing
	cfg.Scan.Include = []string{"*.never-matches"}
	e := New(cfg)
	files, err := e.discoverFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != p {
		t.Errorf("fallback expected, got %+v", files)
	}
}

func TestLooksLikeTestPath(t *testing.T) {
	cases := map[string]bool{
		"foo/bar_test.go":   true,
		"foo/test/x.go":     true,
		"foo/tests/x.py":    true,
		"foo/fixtures/x.go": true,
		"x.test.js":         true,
		"x.test.ts":         true,
		"x.spec.js":         true,
		"x.spec.ts":         true,
		"tests/__tests__/x.go": true,
		"app/test_foo.py":   true,
		"src/main.go":       false,
		"src/foo.py":        false,
	}
	for p, want := range cases {
		if got := looksLikeTestPath(p); got != want {
			t.Errorf("looksLikeTestPath(%q)=%v want %v", p, got, want)
		}
	}
}

func TestMinConf(t *testing.T) {
	if got := minConf(types.ConfHigh, types.ConfLow); got != types.ConfLow {
		t.Errorf("min=%q", got)
	}
	if got := minConf(types.ConfLow, types.ConfHigh); got != types.ConfLow {
		t.Errorf("min=%q", got)
	}
}

func TestDowngradeAll(t *testing.T) {
	if downgrade(types.ConfHigh) != types.ConfMedium {
		t.Error("high→medium")
	}
	if downgrade(types.ConfMedium) != types.ConfLow {
		t.Error("medium→low")
	}
	if downgrade(types.ConfLow) != types.ConfLow {
		t.Error("low→low")
	}
}

func TestIsTruePositiveVerdictVariants(t *testing.T) {
	for _, v := range []string{"true_positive", "TP", "Confirmed", "true", "  true_positive  "} {
		if !isTruePositiveVerdict(v) {
			t.Errorf("%q should be TP", v)
		}
	}
	for _, v := range []string{"", "false_positive", "needs_more_context", "nope"} {
		if isTruePositiveVerdict(v) {
			t.Errorf("%q should NOT be TP", v)
		}
	}
}

func TestEngineLogf(t *testing.T) {
	e := New(config.Default())
	e.logf("hello %s", "world") // just ensure no panic
}

func TestSnippetWithLines(t *testing.T) {
	content := "a\nb\nc\nd\ne\n"
	out := snippetWithLines(content, 2, 3, 1)
	if !strings.Contains(out, "a") || !strings.Contains(out, "b") || !strings.Contains(out, "d") {
		t.Errorf("snippet=%q", out)
	}
	if snippetWithLines("", 1, 1, 1) != "" {
		t.Error("empty content")
	}
}

// helpers ----

func paths(fs []types.FileTarget) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Path
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
