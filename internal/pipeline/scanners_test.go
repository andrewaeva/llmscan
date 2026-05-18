package pipeline

import (
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/contextpack"
	"github.com/andrewaeva/llmscan/internal/fewshot"
	"github.com/andrewaeva/llmscan/internal/types"
)

func TestEffectiveFewShotTopK(t *testing.T) {
	if got := effectiveFewShotTopK(0); got != 3 {
		t.Fatalf("topK(0)=%d want 3", got)
	}
	if got := effectiveFewShotTopK(-1); got != 3 {
		t.Fatalf("topK(-1)=%d want 3", got)
	}
	if got := effectiveFewShotTopK(7); got != 7 {
		t.Fatalf("topK(7)=%d want 7", got)
	}
}

func TestConcurrencyHelpers(t *testing.T) {
	if got := scannerConcurrency(0); got != 8 {
		t.Fatalf("scannerConcurrency(0)=%d want 8", got)
	}
	if got := scannerConcurrency(12); got != 12 {
		t.Fatalf("scannerConcurrency(12)=%d want 12", got)
	}
	if got := verifierConcurrency(0); got != 4 {
		t.Fatalf("verifierConcurrency(0)=%d want 4", got)
	}
	if got := verifierConcurrency(6); got != 6 {
		t.Fatalf("verifierConcurrency(6)=%d want 6", got)
	}
	if got := planVerifierConcurrency(0); got != 4 {
		t.Fatalf("planVerifierConcurrency(0)=%d want 4", got)
	}
	if got := planVerifierConcurrency(3); got != 3 {
		t.Fatalf("planVerifierConcurrency(3)=%d want 3", got)
	}
	if got := planVerifierConcurrency(10); got != 4 {
		t.Fatalf("planVerifierConcurrency(10)=%d want 4", got)
	}
}

func TestShouldLogScannerProgress(t *testing.T) {
	if shouldLogScannerProgress(false, 100, 25) {
		t.Fatal("verbose=false must never log")
	}
	if shouldLogScannerProgress(true, 10, 10) {
		t.Fatal("total<20 must not log")
	}
	if !shouldLogScannerProgress(true, 100, 25) {
		t.Fatal("expected log on 25-step boundary")
	}
	if !shouldLogScannerProgress(true, 100, 100) {
		t.Fatal("expected log on completion")
	}
	if shouldLogScannerProgress(true, 100, 26) {
		t.Fatal("unexpected log at non-boundary")
	}
}

func TestBuildChunkExtraContextFromPackAndFewShot(t *testing.T) {
	chunk := types.FileTarget{
		Path:       "svc/a.go",
		ChunkIdx:   2,
		LineOffset: 10,
		Language:   "go",
		Content:    "dangerous_call(userInput)",
	}
	pack := &contextpack.Pack{
		Chunk: contextpack.Fragment{
			File:  "svc/a.go",
			Start: 11,
			End:   11,
			Code:  "dangerous_call(userInput)\n",
		},
	}
	bank := &fewshot.Bank{
		SkillName: "injection",
		Examples: []fewshot.Example{{
			Title:    "dangerous call pattern",
			Verdict:  "vuln",
			Language: "go",
			Code:     "dangerous_call(userInput)",
		}},
	}

	extra := buildChunkExtraContext(
		chunk,
		map[string]*contextpack.Pack{chunkPackKey(chunk): pack},
		bank,
		1,
	)
	if !strings.Contains(extra, "<<<MAIN CHUNK svc/a.go:11-11>>>") {
		t.Fatalf("missing context pack render: %q", extra)
	}
	if !strings.Contains(extra, "In-context examples") {
		t.Fatalf("missing few-shot render: %q", extra)
	}
}

func TestBuildChunkExtraContextHandlesMissingData(t *testing.T) {
	chunk := types.FileTarget{Path: "x.go", ChunkIdx: 1, LineOffset: 0, Content: "x"}
	if got := buildChunkExtraContext(chunk, nil, nil, 3); got != "" {
		t.Fatalf("expected empty extra context, got %q", got)
	}
}
