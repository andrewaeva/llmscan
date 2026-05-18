package contextpack

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/tokens"
	"github.com/andrewaeva/llmscan/internal/types"
)

type stubSanitizerMatcher struct {
	names map[string]bool
}

func (s stubSanitizerMatcher) IsSanitizer(_ string, name string) bool {
	return s.names[name]
}

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

func buildFiles(t *testing.T, files map[string]string) *Builder {
	t.Helper()
	astByPath := make(map[string]*ast.FileAST, len(files))
	astList := make([]*ast.FileAST, 0, len(files))
	for path, src := range files {
		f, err := ast.Parse(context.Background(), path, []byte(src))
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		astByPath[path] = f
		astList = append(astList, f)
	}
	g := depgraph.New(".", astList)
	cg := callgraph.Build(astList, g)
	cfg := DefaultConfig()
	cfg.BudgetTokens = 8000
	cfg.OverflowRatio = 0.6
	return New(cfg, astByPath, cg, g)
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

func TestFromConfigAppliesPresetAndOverrides(t *testing.T) {
	cfg := config.Default()
	cfg.Scan.Context.Level = "minimal"
	cfg.Scan.Context.BudgetTokens = 12345
	cfg.Scan.Context.CalleesHops = 4
	cfg.Scan.Context.CallersMax = 7
	cfg.Scan.Context.RAGTopK = 5
	cfg.Scan.Context.SqueezeHeadLines = 12
	cfg.Scan.Context.OverflowRatio = 0.75
	includeTypes := false
	includeSanitizers := false
	includeSiblings := true
	includeConsts := true
	cfg.Scan.Context.IncludeTypes = &includeTypes
	cfg.Scan.Context.IncludeSanitizers = &includeSanitizers
	cfg.Scan.Context.IncludeSiblings = &includeSiblings
	cfg.Scan.Context.IncludeConsts = &includeConsts

	got := FromConfig(cfg)
	if got.Level != "minimal" {
		t.Fatalf("level=%q", got.Level)
	}
	if got.BudgetTokens != 12345 || got.CalleesHops != 4 || got.CallersMax != 7 {
		t.Fatalf("unexpected numeric overrides: %+v", got)
	}
	if got.RAGTopK != 5 || got.SqueezeHeadLines != 12 || got.OverflowRatio != 0.75 {
		t.Fatalf("unexpected secondary overrides: %+v", got)
	}
	if got.IncludeTypes || got.IncludeSanitizers || !got.IncludeSiblings || !got.IncludeConsts {
		t.Fatalf("unexpected bool overrides: %+v", got)
	}
}

func TestRenderIncludesFragmentsAndSummary(t *testing.T) {
	p := Pack{
		Chunk: Fragment{File: "main.go", Start: 10, End: 12, Code: "func main() {}\n"},
		Fragments: []Fragment{
			{Kind: KindCallee, File: "dep.go", Symbol: "helper", Start: 1, End: 3, Code: "func helper() {}\n", Reason: "callee", Tokens: 10},
			{Kind: KindRAG, File: "sim.go", Start: 4, End: 6, Code: "match\n", Reason: "similar", Tokens: 5, Squeezed: true},
		},
		Budget:     100,
		UsedTokens: 25,
		Dropped:    1,
		Squeezed:   1,
	}

	got := p.Render()
	if !strings.Contains(got, "MAIN CHUNK main.go:10-12") {
		t.Fatalf("missing main chunk header:\n%s", got)
	}
	if !strings.Contains(got, "// ---- callee (1) ----") || !strings.Contains(got, "// ---- rag (1) ----") {
		t.Fatalf("missing grouped fragment sections:\n%s", got)
	}
	if !strings.Contains(got, "helper @ dep.go:1-3") || !strings.Contains(got, "(anonymous) @ sim.go:4-6") {
		t.Fatalf("missing fragment labels:\n%s", got)
	}
	if !strings.Contains(got, "[squeezed]") || !strings.Contains(got, "[pack: 1 fragments squeezed, 1 dropped") {
		t.Fatalf("missing squeeze/summary markers:\n%s", got)
	}
}

func TestEncodeDecodePackRoundTrip(t *testing.T) {
	in := Pack{
		Chunk:      Fragment{Kind: KindChunk, File: "x.go", Start: 1, End: 2, Code: "package main", Tokens: 3},
		Fragments:  []Fragment{{Kind: KindConst, File: "x.go", Symbol: "API_KEY", Start: 3, End: 3, Code: "const API_KEY = 1", Tokens: 5}},
		Budget:     100,
		UsedTokens: 8,
		CacheKey:   "abc",
		Truncated:  true,
	}
	raw, err := EncodePack(in)
	if err != nil {
		t.Fatalf("EncodePack: %v", err)
	}
	out, err := DecodePack(raw)
	if err != nil {
		t.Fatalf("DecodePack: %v", err)
	}
	if out.CacheKey != in.CacheKey || out.UsedTokens != in.UsedTokens || len(out.Fragments) != 1 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestCollectorsFindTypesConstsSiblingsSanitizersAndRAG(t *testing.T) {
	src := strings.Join([]string{
		"package main",
		"",
		"const API_KEY = \"secret\"",
		"",
		"type Config struct{}",
		"",
		"func helper() {",
		"\tprintln(\"h\")",
		"}",
		"",
		"func main() {",
		"\t_ = API_KEY",
		"\t_ = Config{}",
		"\thelper()",
		"}",
		"",
	}, "\n")
	b := buildFiles(t, map[string]string{"x.go": src})
	b.ASTByPath["x.go"].Symbols = append(b.ASTByPath["x.go"].Symbols,
		ast.Symbol{Kind: "const", Name: "API_KEY", StartLine: 3, EndLine: 3},
		ast.Symbol{Kind: "class", Name: "Config", StartLine: 5, EndLine: 5},
	)
	b.Sanitizers = stubSanitizerMatcher{names: map[string]bool{"helper": true}}
	b.RAG = rag.New(nil)
	if err := b.RAG.Index(context.Background(), []*rag.Chunk{
		{File: "other.go", StartLine: 1, EndLine: 3, Symbol: "other", Text: "API_KEY Config helper"},
		{File: "x.go", StartLine: 11, EndLine: 14, Symbol: "main", Text: "API_KEY Config helper"},
	}, 0); err != nil {
		t.Fatalf("rag index: %v", err)
	}
	b.Cfg.RAGTopK = 2
	b.Cfg.IncludeConsts = true
	b.Cfg.IncludeSiblings = true

	lines := strings.Split(src, "\n")
	chunk := types.FileTarget{
		Path:       "x.go",
		Language:   "go",
		Content:    strings.Join(lines[10:15], "\n"),
		Lines:      5,
		LineOffset: 10,
	}

	typeFrags := b.collectTypes(chunk)
	if len(typeFrags) != 1 || typeFrags[0].Symbol != "Config" {
		t.Fatalf("type fragments=%+v", typeFrags)
	}

	constFrags := b.collectConsts(chunk)
	if len(constFrags) != 1 || constFrags[0].Symbol != "API_KEY" {
		t.Fatalf("const fragments=%+v", constFrags)
	}

	siblingFrags := b.collectSiblings(chunk)
	if len(siblingFrags) != 1 || siblingFrags[0].Symbol != "helper" {
		t.Fatalf("sibling fragments=%+v", siblingFrags)
	}

	sanitizerFrags := b.collectSanitizers(chunk)
	if len(sanitizerFrags) != 1 || sanitizerFrags[0].Symbol != "helper" {
		t.Fatalf("sanitizer fragments=%+v", sanitizerFrags)
	}

	ragFrags := b.collectRAG(context.Background(), chunk)
	if len(ragFrags) != 1 || ragFrags[0].File != "other.go" {
		t.Fatalf("rag fragments=%+v", ragFrags)
	}
}

func TestCacheKeyForAndCap(t *testing.T) {
	src := "package main\n\nfunc main() {}\n"
	b, chunk := buildSingleFile(t, src)
	if got := b.CacheKeyFor(chunk); got == "" {
		t.Fatal("CacheKeyFor returned empty key")
	}

	frags := []Fragment{
		{Symbol: "slow", Priority: 3, Tokens: 30},
		{Symbol: "fast", Priority: 1, Tokens: 20},
		{Symbol: "small", Priority: 1, Tokens: 10},
	}
	capped := b.cap(frags, 2)
	if len(capped) != 2 || capped[0].Symbol != "small" || capped[1].Symbol != "fast" {
		t.Fatalf("cap ordering mismatch: %+v", capped)
	}
}
