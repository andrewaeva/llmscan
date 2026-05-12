package knowledge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty content, got %q", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	body := "## Stack\n  - go\n  - gin"
	if err := Save(dir, body); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Make sure the file landed at the expected path.
	p := filepath.Join(dir, DirName, FileName)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b) != body {
		t.Errorf("on-disk content mismatch: %q", string(b))
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != body {
		t.Errorf("Load=%q want %q", got, body)
	}
}

func TestSaveTruncatesOversize(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", MaxBytes+100)
	if err := Save(dir, big); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, _ := Load(dir)
	if len(got) > MaxBytes {
		t.Errorf("Load returned %d bytes, expected <= %d", len(got), MaxBytes)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("expected truncation marker, got tail %q", got[len(got)-40:])
	}
}

func TestCollectLayoutSkipsHidden(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.go"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), nil, 0o644)
	_ = os.Mkdir(filepath.Join(dir, "internal"), 0o755)
	_ = os.Mkdir(filepath.Join(dir, ".llmscan"), 0o755)
	_ = os.Mkdir(filepath.Join(dir, ".github"), 0o755)

	out, err := CollectLayout(dir, 10)
	if err != nil {
		t.Fatalf("CollectLayout: %v", err)
	}
	got := strings.Join(out, ",")
	if !strings.Contains(got, "main.go") || !strings.Contains(got, "internal/") {
		t.Errorf("missing expected entries: %v", out)
	}
	if strings.Contains(got, ".llmscan") {
		t.Errorf("dotdir leaked: %v", out)
	}
	if !strings.Contains(got, ".github/") {
		t.Errorf("expected .github/ to be kept: %v", out)
	}
}

// fakeClient is a tiny llm.Client used only here so we don't depend on agents.
type fakeClient struct {
	resp string
	err  error
	last llm.Request
}

func (f *fakeClient) Name() string { return "fake" }
func (f *fakeClient) Complete(_ context.Context, req llm.Request) (llm.Response, error) {
	f.last = req
	if f.err != nil {
		return llm.Response{}, f.err
	}
	return llm.Response{Text: f.resp, Model: "fake-m"}, nil
}

func TestSummarizeBuildsPromptAndReturnsTrimmed(t *testing.T) {
	cl := &fakeClient{resp: "```markdown\n## Stack\n  - go\n```\n"}
	findings := []types.Finding{
		{Severity: types.SevHigh, RuleID: "INJ-1", File: "x.go", StartLine: 10, Title: "sql injection"},
		{Severity: types.SevLow, RuleID: "ERR-1", File: "y.go", StartLine: 20, Title: "ignored error"},
	}
	got, err := Summarize(context.Background(), cl, "## Old\n- foo", []string{"main.go", "internal/"}, findings)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if !strings.Contains(got, "## Stack") || strings.Contains(got, "```") {
		t.Errorf("expected cleaned markdown, got %q", got)
	}
	if !strings.Contains(cl.last.Messages[0].Content, "Previous knowledge.md:") {
		t.Errorf("missing previous section in user prompt: %q", cl.last.Messages[0].Content)
	}
	if !strings.Contains(cl.last.Messages[0].Content, "INJ-1") {
		t.Errorf("missing top finding in user prompt")
	}
}
