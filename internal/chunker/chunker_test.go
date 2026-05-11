package chunker

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
)

func parseGo(t *testing.T, src string) *ast.FileAST {
	t.Helper()
	_ = ast.NewParser()
	f, err := ast.Parse(context.Background(), "x.go", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func TestDefaultOptions(t *testing.T) {
	o := Default()
	if o.MaxLines <= 0 || o.MapReduceLOC <= 0 {
		t.Errorf("invalid defaults: %+v", o)
	}
}

func TestChunkSmallFileSingleTarget(t *testing.T) {
	src := "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n"
	f := parseGo(t, src)
	got := Chunk(f, Options{MaxLines: 100, MapReduceLOC: 2000})
	if len(got) != 1 {
		t.Fatalf("expected single chunk, got %d", len(got))
	}
	if got[0].Path != "x.go" || got[0].Language != "go" {
		t.Errorf("metadata wrong: %+v", got[0])
	}
}

func TestChunkSlidingWindow(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("package main\n")
	for i := 0; i < 600; i++ {
		sb.WriteString("var _ = 1\n")
	}
	f := parseGo(t, sb.String())
	got := Chunk(f, Options{MaxLines: 200, OverlapLines: 20, MapReduceLOC: 100000})
	if len(got) < 2 {
		t.Fatalf("expected sliding chunks, got %d", len(got))
	}
	for i, c := range got {
		if c.ChunkIdx != i || c.ChunkTotal != len(got) {
			t.Errorf("chunk[%d] indices = (%d,%d)", i, c.ChunkIdx, c.ChunkTotal)
		}
	}
}

func TestChunkHierarchicalAddsSummary(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("package main\n")
	for i := 0; i < 3000; i++ {
		sb.WriteString("var _ = 1\n")
	}
	f := parseGo(t, sb.String())
	got := Chunk(f, Options{MaxLines: 250, OverlapLines: 20, MapReduceLOC: 2000})
	if len(got) < 2 {
		t.Fatalf("expected summary+chunks, got %d", len(got))
	}
	if got[0].ChunkIdx != -1 {
		t.Errorf("first chunk must be summary (ChunkIdx=-1), got %d", got[0].ChunkIdx)
	}
}

func TestChunkNilFile(t *testing.T) {
	if got := Chunk(nil, Default()); got != nil {
		t.Errorf("nil file → nil result, got %+v", got)
	}
}

func BenchmarkChunkLarge(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("package main\n")
	for i := 0; i < 2500; i++ {
		sb.WriteString("var _ = 1\n")
	}
	f, err := ast.Parse(context.Background(), "x.go", []byte(sb.String()))
	if err != nil {
		b.Fatal(err)
	}
	opts := Default()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Chunk(f, opts)
	}
}
