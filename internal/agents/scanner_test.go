package agents

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestScannerScanParsesAndRebasesLines(t *testing.T) {
	resp := `{"findings":[
		{"rule_id":"sql","title":"SQL Injection","severity":"high","confidence":"high","start_line":3,"end_line":5,"code_sample":"db.Exec(x)"},
		{"rule_id":"weak","title":"weak crypto","start_line":8,"end_line":8}
	]}`
	cli := &stubClient{responses: []string{resp}}
	s := &Scanner{Name: "injection", Client: cli}
	ft := types.FileTarget{
		Path: "src/main.go", Language: "go", Content: "package main",
		ChunkIdx: 0, ChunkTotal: 1, LineOffset: 100,
	}
	fnds, err := s.Scan(context.Background(), ft, "")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(fnds) != 2 {
		t.Fatalf("findings=%d", len(fnds))
	}
	if fnds[0].Agent != "injection" || fnds[0].File != "src/main.go" {
		t.Errorf("agent/file: %+v", fnds[0])
	}
	if fnds[0].StartLine != 103 || fnds[0].EndLine != 105 {
		t.Errorf("line rebase: %+v", fnds[0])
	}
	if fnds[0].Severity != types.SevHigh || fnds[0].Confidence != types.ConfHigh {
		t.Errorf("severity/confidence: %+v", fnds[0])
	}
	// defaults filled in
	if fnds[1].Severity != types.SevMedium || fnds[1].Confidence != types.ConfMedium {
		t.Errorf("defaults not applied: %+v", fnds[1])
	}
	if fnds[1].ID == "" {
		t.Error("ID should be auto-assigned")
	}
	if fnds[0].CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

func TestScannerScanEmptyFindings(t *testing.T) {
	cli := &stubClient{responses: []string{`{"findings":[]}`}}
	s := &Scanner{Name: "secrets", Client: cli, Scope: "secrets stuff"}
	fnds, err := s.Scan(context.Background(), types.FileTarget{Path: "a.go"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fnds) != 0 {
		t.Errorf("expected 0 findings, got %d", len(fnds))
	}
	// Scope is used when no override
	if !strings.Contains(cli.last.System, "secrets stuff") {
		t.Errorf("scope not in system prompt: %q", cli.last.System)
	}
}

func TestScannerPromptOverrideWins(t *testing.T) {
	cli := &stubClient{responses: []string{`{"findings":[]}`}}
	s := &Scanner{Name: "custom", Client: cli, PromptOverride: "CUSTOM_PROMPT"}
	_, err := s.Scan(context.Background(), types.FileTarget{Path: "a.go"}, "extra context here")
	if err != nil {
		t.Fatal(err)
	}
	if cli.last.System != "CUSTOM_PROMPT" {
		t.Errorf("expected override; got %q", cli.last.System)
	}
	if !strings.Contains(cli.last.Messages[0].Content, "extra context here") {
		t.Errorf("extra context dropped: %q", cli.last.Messages[0].Content)
	}
}

func TestScannerScanLLMError(t *testing.T) {
	cli := &stubClient{errs: []error{errors.New("boom")}, responses: []string{""}}
	s := &Scanner{Name: "x", Client: cli}
	_, err := s.Scan(context.Background(), types.FileTarget{Path: "a.go"}, "")
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected boom, got %v", err)
	}
}

func TestScannerScanBadJSON(t *testing.T) {
	cli := &stubClient{responses: []string{`{not-json`}}
	s := &Scanner{Name: "x", Client: cli}
	_, err := s.Scan(context.Background(), types.FileTarget{Path: "a.go"}, "")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected decode err, got %v", err)
	}
}

func TestScannerScanWithMarkdownFence(t *testing.T) {
	resp := "```json\n{\"findings\":[{\"rule_id\":\"r\",\"title\":\"t\",\"start_line\":1}]}\n```"
	cli := &stubClient{responses: []string{resp}}
	s := &Scanner{Name: "x", Client: cli}
	fnds, err := s.Scan(context.Background(), types.FileTarget{Path: "a.go"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fnds) != 1 {
		t.Fatalf("findings=%d", len(fnds))
	}
}

func TestScopeForAgentKnown(t *testing.T) {
	for _, name := range []string{"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic"} {
		if scopeForAgent(name) == "" {
			t.Errorf("scope empty for %s", name)
		}
	}
	if scopeForAgent("unknown") == "" {
		t.Error("unknown should still return non-empty fallback")
	}
}

func TestHash6Stable(t *testing.T) {
	a := hash6("foo/bar.go")
	b := hash6("foo/bar.go")
	c := hash6("foo/baz.go")
	if a != b {
		t.Errorf("not deterministic: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("different inputs collided: %s", a)
	}
	if len(a) != 6 {
		t.Errorf("length=%d", len(a))
	}
}

func TestEmptyIfAndTruncate(t *testing.T) {
	if emptyIf("", "def") != "def" {
		t.Error("emptyIf default")
	}
	if emptyIf(" ", "def") != "def" {
		t.Error("emptyIf whitespace")
	}
	if emptyIf("x", "def") != "x" {
		t.Error("emptyIf passthrough")
	}
	if truncate("abc", 10) != "abc" {
		t.Error("truncate short string")
	}
	if got := truncate("abcdef", 3); got != "abc..." {
		t.Errorf("truncate: %q", got)
	}
	if got := truncateRunes("héllo wörld", 5); !strings.HasSuffix(got, "...") {
		t.Errorf("truncateRunes: %q", got)
	}
	if truncateRunes("abc", 10) != "abc" {
		t.Error("truncateRunes short")
	}
}

func TestMustJSON(t *testing.T) {
	out := mustJSON(map[string]any{"k": "v"})
	if !strings.Contains(out, "\"k\"") || !strings.Contains(out, "\"v\"") {
		t.Errorf("mustJSON output: %q", out)
	}
}
