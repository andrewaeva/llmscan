package contextpack

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/tokens"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Minimal helper that builds Builder state from a single in-memory Go file.
func buildSingleFile(t *testing.T, src string) (*Builder, types.FileTarget) {
	t.Helper()
	f, err := ast.Parse(context.Background(), "x.go", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	astByPath := map[string]*ast.FileAST{"x.go": f}
	g := depgraph.New(".", []*ast.FileAST{f})
	cg := callgraph.Build([]*ast.FileAST{f}, g)
	cfg := DefaultConfig()
	cfg.BudgetTokens = 8000
	cfg.OverflowRatio = 0.6
	b := New(cfg, astByPath, cg, g)
	chunk := types.FileTarget{
		Path: "x.go", Language: "go",
		Content: src, Lines: strings.Count(src, "\n") + 1, LineOffset: 0,
	}
	return b, chunk
}

func TestDefaultConfigValidates(t *testing.T) {
	for _, c := range []Config{DefaultConfig(), MinimalConfig(), AggressiveConfig(), ExtremeConfig()} {
		if err := c.Validate(); err != nil {
			t.Errorf("preset %q invalid: %v", c.Level, err)
		}
	}
}

func TestConfigValidateRejectsBadInputs(t *testing.T) {
	bad := []Config{
		{BudgetTokens: 100, SqueezeHeadLines: 10, SqueezeTailLines: 10, OverflowRatio: 0.5}, // too small budget
		{BudgetTokens: 8000, CalleesHops: -1, SqueezeHeadLines: 10, SqueezeTailLines: 10, OverflowRatio: 0.5},
		{BudgetTokens: 8000, SqueezeHeadLines: 1, SqueezeTailLines: 10, OverflowRatio: 0.5}, // squeeze too small
		{BudgetTokens: 8000, SqueezeHeadLines: 10, SqueezeTailLines: 10, OverflowRatio: 2},  // ratio > 1
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestConfigHashStableAndDistinct(t *testing.T) {
	a := DefaultConfig()
	b := DefaultConfig()
	if a.hash() != b.hash() {
		t.Fatalf("identical configs produced different hashes")
	}
	c := AggressiveConfig()
	if a.hash() == c.hash() {
		t.Fatalf("different configs collided")
	}
}

func TestBuildSmallChunkFits(t *testing.T) {
	src := "package main\n\nfunc main() {\n\tprintln(1)\n}\n"
	b, chunk := buildSingleFile(t, src)
	pack := b.Build(context.Background(), chunk)
	if pack.Overflow {
		t.Errorf("small chunk should not overflow: %s", pack.OverflowReason)
	}
	if pack.Chunk.Code == "" {
		t.Errorf("chunk fragment missing")
	}
	if pack.UsedTokens != pack.Chunk.Tokens && pack.UsedTokens == 0 {
		t.Errorf("used tokens not populated: %d", pack.UsedTokens)
	}
	if got := pack.Render(); !strings.Contains(got, "MAIN CHUNK") {
		t.Errorf("Render() missing chunk header")
	}
	if pack.CacheKey == "" {
		t.Errorf("cache key empty")
	}
}

func TestBuildOverflowSignal(t *testing.T) {
	// Chunk that uses ~12K tokens with a 8K budget * 0.6 = 4.8K threshold.
	var sb strings.Builder
	sb.WriteString("package main\n\nfunc Big() {\n")
	for i := 0; i < 4000; i++ {
		sb.WriteString("\t_ = 42 + 17 - 9 * 3 / 2\n")
	}
	sb.WriteString("}\n")
	src := sb.String()
	b, chunk := buildSingleFile(t, src)
	pack := b.Build(context.Background(), chunk)
	if !pack.Overflow {
		t.Errorf("expected overflow, got %+v (chunkTokens=%d, budget=%d)",
			pack.OverflowReason, pack.Chunk.Tokens, pack.Budget)
	}
	if pack.OverflowReason == "" {
		t.Errorf("missing overflow reason")
	}
	if pack.ChunkShareOfBudget < 0.6 {
		t.Errorf("unexpected share: %.2f", pack.ChunkShareOfBudget)
	}
}

func TestRenderDeterministic(t *testing.T) {
	src := "package main\n\nfunc A() { B() }\n\nfunc B() { println(1) }\n"
	b, chunk := buildSingleFile(t, src)
	p1 := b.Build(context.Background(), chunk).Render()
	p2 := b.Build(context.Background(), chunk).Render()
	if p1 != p2 {
		t.Errorf("Render() is non-deterministic")
	}
}

func TestDedupeMergesOverlappingRanges(t *testing.T) {
	chunk := Fragment{File: "main.go", Start: 100, End: 200}
	in := []Fragment{
		{File: "a.go", Start: 10, End: 20, Kind: KindCallee, Reason: "callee F", Priority: 1, Code: "a", Tokens: 5},
		{File: "a.go", Start: 15, End: 25, Kind: KindType, Reason: "type T", Priority: 2, Code: "ab", Tokens: 8},
		{File: "b.go", Start: 5, End: 10, Kind: KindRAG, Reason: "rag", Priority: 3, Code: "x", Tokens: 4},
	}
	out := dedupe(in, chunk)
	if len(out) != 2 {
		t.Fatalf("expected 2 merged groups, got %d: %+v", len(out), out)
	}
	// First group (a.go) keeps lowest priority and combined reason.
	g := out[0]
	if g.File != "a.go" || g.Start != 10 || g.End != 25 {
		t.Errorf("bad merged range: %+v", g)
	}
	if g.Priority != 1 {
		t.Errorf("expected priority=1 (most important wins), got %d", g.Priority)
	}
	if !strings.Contains(g.Reason, "callee F") || !strings.Contains(g.Reason, "type T") {
		t.Errorf("reasons not joined: %q", g.Reason)
	}
}

func TestDedupeDropsChunkOverlaps(t *testing.T) {
	chunk := Fragment{File: "main.go", Start: 10, End: 50}
	in := []Fragment{
		{File: "main.go", Start: 20, End: 30, Kind: KindCallee, Code: "x"},
		{File: "other.go", Start: 1, End: 5, Kind: KindCallee, Code: "y"},
	}
	out := dedupe(in, chunk)
	if len(out) != 1 || out[0].File != "other.go" {
		t.Errorf("expected only other.go to survive, got %+v", out)
	}
}

func TestSqueezeShrinksLargeFragment(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString("a long line of code that is repeated many times to inflate tokens\n")
	}
	code := sb.String()
	b := &Builder{Cfg: Config{SqueezeHeadLines: 20, SqueezeTailLines: 10}}
	f := Fragment{Code: code, Tokens: tokens.Estimate(code), Kind: KindCallee}
	sq := b.squeeze(f, 500)
	if !sq.Squeezed {
		t.Errorf("Squeezed flag not set")
	}
	if sq.Tokens > 600 {
		t.Errorf("squeezed fragment still too big: %d", sq.Tokens)
	}
	if !strings.Contains(sq.Code, "lines elided") {
		t.Errorf("squeeze marker missing")
	}
}

func TestPackCacheKeyDependsOnContentAndConfig(t *testing.T) {
	src := "package main\n\nfunc main() {}\n"
	b, chunk := buildSingleFile(t, src)
	k1 := b.Build(context.Background(), chunk).CacheKey

	// Same content + same cfg → same key.
	b2, chunk2 := buildSingleFile(t, src)
	k2 := b2.Build(context.Background(), chunk2).CacheKey
	if k1 != k2 {
		t.Errorf("cache key not stable across builds: %s vs %s", k1, k2)
	}

	// Different content → different key.
	b3, chunk3 := buildSingleFile(t, "package main\n\nfunc other() {}\n")
	if k3 := b3.Build(context.Background(), chunk3).CacheKey; k3 == k1 {
		t.Errorf("cache key did not change with content")
	}
}
