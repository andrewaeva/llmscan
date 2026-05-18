package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/contextpack"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/knowledge"
	"github.com/andrewaeva/llmscan/internal/types"
)

type stubPackCache struct {
	payloads map[string][]byte
	puts     int
}

func (s *stubPackCache) GetContextPack(key string) ([]byte, bool) {
	if s.payloads == nil {
		return nil, false
	}
	raw, ok := s.payloads[key]
	return raw, ok
}

func (s *stubPackCache) PutContextPack(key string, raw []byte) error {
	if s.payloads == nil {
		s.payloads = map[string][]byte{}
	}
	s.payloads[key] = append([]byte(nil), raw...)
	s.puts++
	return nil
}

func buildContextPackBuilder(t *testing.T, src string) (*contextpack.Builder, types.FileTarget) {
	t.Helper()
	f, err := ast.Parse(context.Background(), "x.go", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	astByPath := map[string]*ast.FileAST{"x.go": f}
	g := depgraph.New(".", []*ast.FileAST{f})
	cg := callgraph.Build([]*ast.FileAST{f}, g)
	cfg := contextpack.DefaultConfig()
	cfg.BudgetTokens = 8000
	cfg.OverflowRatio = 0.6
	b := contextpack.New(cfg, astByPath, cg, g)
	chunk := types.FileTarget{
		Path:       "x.go",
		Language:   "go",
		Content:    src,
		Lines:      strings.Count(src, "\n") + 1,
		LineOffset: 0,
	}
	return b, chunk
}

func TestWholeFileChunkFillsMissingLines(t *testing.T) {
	out := wholeFileChunk(types.FileTarget{Path: "x.go", Content: "a\nb"})
	if out.ChunkIdx != 0 || out.LineOffset != 0 {
		t.Fatalf("unexpected chunk coordinates: %+v", out)
	}
	if out.Lines != 2 {
		t.Fatalf("lines=%d want 2", out.Lines)
	}
}

func TestStageLoadKnowledgePrependsExistingFile(t *testing.T) {
	dir := t.TempDir()
	if err := knowledge.Save(dir, "## Stack\n- Go"); err != nil {
		t.Fatalf("knowledge.Save: %v", err)
	}
	cfg := config.Default()
	cfg.ProjectContext = "user context"
	e := New(cfg)
	st := &runState{target: dir}
	if err := stageLoadKnowledge(context.Background(), e, st); err != nil {
		t.Fatalf("stageLoadKnowledge: %v", err)
	}
	if !strings.Contains(e.Cfg.ProjectContext, "Project knowledge") {
		t.Fatalf("missing knowledge header: %q", e.Cfg.ProjectContext)
	}
	if !strings.Contains(e.Cfg.ProjectContext, "## Stack") || !strings.Contains(e.Cfg.ProjectContext, "user context") {
		t.Fatalf("project context not merged: %q", e.Cfg.ProjectContext)
	}
}

func TestLookupPackFromCacheHandlesHitAndDecodeFailure(t *testing.T) {
	builder, chunk := buildContextPackBuilder(t, "package main\n\nfunc main() {}\n")
	want := builder.Build(context.Background(), chunk)
	payload, err := contextpack.EncodePack(want)
	if err != nil {
		t.Fatalf("EncodePack: %v", err)
	}

	cache := &stubPackCache{payloads: map[string][]byte{builder.CacheKeyFor(chunk): payload}}
	got, ok := lookupPackFromCache(builder, cache, true, chunk)
	if !ok || got.CacheKey != want.CacheKey {
		t.Fatalf("cache hit mismatch: ok=%v got=%+v want=%+v", ok, got, want)
	}

	cache.payloads[builder.CacheKeyFor(chunk)] = []byte("not-json")
	if _, ok := lookupPackFromCache(builder, cache, true, chunk); ok {
		t.Fatal("expected corrupt cached payload to be ignored")
	}
}

func TestLoadOrBuildContextPackStoresOnlyNonOverflowingPacks(t *testing.T) {
	builder, chunk := buildContextPackBuilder(t, "package main\n\nfunc main() {}\n")
	cache := &stubPackCache{}

	pack, hit := loadOrBuildContextPack(context.Background(), builder, cache, true, chunk)
	if hit || pack.CacheKey == "" {
		t.Fatalf("unexpected cache result: hit=%v pack=%+v", hit, pack)
	}
	if cache.puts != 1 {
		t.Fatalf("expected one cache store, got %d", cache.puts)
	}

	var sb strings.Builder
	sb.WriteString("package main\n\nfunc big() {\n")
	for i := 0; i < 5000; i++ {
		sb.WriteString("\tprintln(42)\n")
	}
	sb.WriteString("}\n")
	overflowBuilder, overflowChunk := buildContextPackBuilder(t, sb.String())
	overflowBuilder.Cfg.BudgetTokens = 200
	overflowCache := &stubPackCache{}

	pack, hit = loadOrBuildContextPack(context.Background(), overflowBuilder, overflowCache, true, overflowChunk)
	if hit || !pack.Overflow {
		t.Fatalf("expected overflow build on cache miss: hit=%v pack=%+v", hit, pack)
	}
	if overflowCache.puts != 0 {
		t.Fatalf("overflowing pack should not be cached, puts=%d", overflowCache.puts)
	}
}
