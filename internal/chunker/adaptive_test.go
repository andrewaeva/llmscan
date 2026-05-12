package chunker

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/tokens"
	"github.com/andrewaeva/llmscan/internal/types"
)

func parseGoAdaptive(t *testing.T, src string) *ast.FileAST {
	t.Helper()
	f, err := ast.Parse(context.Background(), "x.go", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func TestDefaultAdaptiveOptions(t *testing.T) {
	o := DefaultAdaptiveOptions()
	if o.TargetTokens != 8000 || o.MaxTokens != 16000 || o.MinTokens != 500 {
		t.Fatalf("unexpected defaults: %+v", o)
	}
}

func TestChunkAdaptiveSmallFile(t *testing.T) {
	src := "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n"
	f := parseGoAdaptive(t, src)
	got := ChunkAdaptive(f, DefaultAdaptiveOptions())
	if len(got) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(got))
	}
	if got[0].ChunkIdx != 0 || got[0].ChunkTotal != 1 {
		t.Errorf("bad indices: %+v", got[0])
	}
}

func TestChunkAdaptiveSymbolGrouping(t *testing.T) {
	// Build a file with ~10 small functions; expect a single chunk because
	// each func is tiny and they fit under Target.
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	for i := 0; i < 10; i++ {
		sb.WriteString("func F")
		sb.WriteByte(byte('A' + i))
		sb.WriteString("() {\n\tprintln(1)\n}\n\n")
	}
	f := parseGoAdaptive(t, sb.String())
	got := ChunkAdaptive(f, AdaptiveOptions{TargetTokens: 8000, MaxTokens: 16000, MinTokens: 500})
	if len(got) != 1 {
		t.Fatalf("expected 1 packed chunk, got %d", len(got))
	}
}

func TestChunkAdaptiveCutsAtTarget(t *testing.T) {
	// Build a file with funcs whose combined token cost forces a split.
	// Each func is ~200 lines of arithmetic.
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	for i := 0; i < 6; i++ {
		sb.WriteString("func F")
		sb.WriteByte(byte('A' + i))
		sb.WriteString("(x int) int {\n")
		for j := 0; j < 200; j++ {
			sb.WriteString("\tx = x*2 + 1\n")
		}
		sb.WriteString("\treturn x\n}\n\n")
	}
	f := parseGoAdaptive(t, sb.String())
	// Target small so we are guaranteed to split.
	got := ChunkAdaptive(f, AdaptiveOptions{TargetTokens: 800, MaxTokens: 1600, MinTokens: 50})
	if len(got) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(got))
	}
	// Each chunk should be at most ~max tokens.
	for i, c := range got {
		if got := tokens.Estimate(c.Content); got > 2000 {
			t.Errorf("chunk[%d] too big: %d tokens (lines=%d)", i, got, c.Lines)
		}
		if c.ChunkTotal != len(got) {
			t.Errorf("chunk[%d] total mismatch: %d vs %d", i, c.ChunkTotal, len(got))
		}
	}
}

func TestChunkAdaptiveNoSymbolsFallback(t *testing.T) {
	// Go file with only package + imports + vars (no functions/types).
	var sb strings.Builder
	sb.WriteString("package main\n\n")
	for i := 0; i < 1200; i++ {
		sb.WriteString("var _v")
		sb.WriteByte(byte('a' + (i % 26)))
		sb.WriteString(" = 1\n")
	}
	f := parseGoAdaptive(t, sb.String())
	// Force the fallback by stripping symbols (Go parser will produce var
	// symbols, which packSymbols ignores via kind filter; that is exactly
	// the path we want to exercise).
	got := ChunkAdaptive(f, AdaptiveOptions{TargetTokens: 800, MaxTokens: 1600, MinTokens: 100, FallbackLines: 200})
	if len(got) < 2 {
		t.Fatalf("expected sliding fallback, got %d", len(got))
	}
}

func TestChunkAdaptiveNil(t *testing.T) {
	if got := ChunkAdaptive(nil, DefaultAdaptiveOptions()); got != nil {
		t.Errorf("expected nil for nil input, got %+v", got)
	}
}

func TestSplitInHalf(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("line\n")
	}
	c := types.FileTarget{
		Path: "test.go", Language: "go",
		Content: sb.String(), Lines: 100, LineOffset: 10,
	}
	left, right := SplitInHalf(c)
	if left.Lines == 0 || right.Lines == 0 {
		t.Fatalf("empty split: left=%+v right=%+v", left, right)
	}
	if left.LineOffset+left.Lines != right.LineOffset {
		t.Errorf("non-contiguous halves: left end=%d right start=%d",
			left.LineOffset+left.Lines, right.LineOffset)
	}
	if left.Lines+right.Lines < 99 || left.Lines+right.Lines > 101 {
		t.Errorf("lost lines: %d + %d", left.Lines, right.Lines)
	}
}

func TestSplitInHalfTooSmall(t *testing.T) {
	c := types.FileTarget{Path: "test.go", Content: "a\nb\n", Lines: 2}
	left, right := SplitInHalf(c)
	if left.Lines != 2 || right.Lines != 0 {
		t.Errorf("expected no-op split for tiny chunk, got %+v / %+v", left, right)
	}
}
