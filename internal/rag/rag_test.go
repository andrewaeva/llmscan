package rag

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
)

// detEmbedder is a deterministic, tiny embedder used for tests.
// Each text -> 4-dim vector: counts of letters a/b/c/d.
// This gives us controllable cosine similarity without any randomness.
type detEmbedder struct {
	dim       int
	failBatch int // 1-based: if >0, the n-th Embed call returns an error
	calls     int
	override  func([]string) ([][]float32, error) // optional hook
}

func (e *detEmbedder) Name() string { return "det" }
func (e *detEmbedder) Dim() int {
	if e.dim == 0 {
		return 4
	}
	return e.dim
}
func (e *detEmbedder) Embed(_ context.Context, batch []string) ([][]float32, error) {
	e.calls++
	if e.override != nil {
		return e.override(batch)
	}
	if e.failBatch > 0 && e.calls == e.failBatch {
		return nil, errors.New("synthetic embed failure")
	}
	out := make([][]float32, len(batch))
	for i, t := range batch {
		v := make([]float32, e.Dim())
		low := strings.ToLower(t)
		for _, r := range low {
			switch r {
			case 'a':
				v[0]++
			case 'b':
				v[1]++
			case 'c':
				v[2]++
			case 'd':
				if e.Dim() > 3 {
					v[3]++
				}
			}
		}
		out[i] = v
	}
	return out, nil
}

func TestCosine_OrthogonalAndAligned(t *testing.T) {
	x := []float32{1, 0, 0, 0}
	y := []float32{0, 1, 0, 0}
	if c := cosine(x, y); c != 0 {
		t.Errorf("orthogonal vectors: cosine=%v, want 0", c)
	}
	if c := cosine(x, x); c < 0.999 || c > 1.001 {
		t.Errorf("identical vectors: cosine=%v, want ~1", c)
	}
}

func TestCosine_DimensionMismatch(t *testing.T) {
	if c := cosine([]float32{1, 0}, []float32{1, 0, 0}); c != 0 {
		t.Errorf("mismatched dims must return 0, got %v", c)
	}
}

func TestCosine_ZeroNorm(t *testing.T) {
	if c := cosine([]float32{0, 0, 0, 0}, []float32{1, 1, 1, 1}); c != 0 {
		t.Errorf("zero-norm input must return 0, got %v", c)
	}
}

func TestNew_EmptyIndex(t *testing.T) {
	idx := New(&detEmbedder{})
	if got := idx.Size(); got != 0 {
		t.Errorf("fresh index Size=%d, want 0", got)
	}
	// SearchByVector on empty should not panic and return empty slice.
	got := idx.SearchByVector([]float32{1, 0, 0, 0}, 5)
	if len(got) != 0 {
		t.Errorf("empty index SearchByVector returned %d, want 0", len(got))
	}
}

func TestIndexAndSearch_CosineOrdering(t *testing.T) {
	emb := &detEmbedder{}
	idx := New(emb)
	chunks := []*Chunk{
		{ID: "c-aaa", File: "a.go", StartLine: 1, EndLine: 1, Text: "aaaaa"}, // [5,0,0,0]
		{ID: "c-bbb", File: "b.go", StartLine: 1, EndLine: 1, Text: "bbbbb"}, // [0,5,0,0]
		{ID: "c-mix", File: "m.go", StartLine: 1, EndLine: 1, Text: "aabbb"}, // [2,3,0,0]
	}
	if err := idx.Index(context.Background(), chunks, 2); err != nil {
		t.Fatalf("Index: %v", err)
	}
	if idx.Size() != 3 {
		t.Fatalf("Size=%d, want 3", idx.Size())
	}
	// Query close to "a"-cluster.
	got, err := idx.Search(context.Background(), "aaaa", 2)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("top-k=%d, want 2", len(got))
	}
	if got[0].ID != "c-aaa" {
		t.Errorf("top hit=%s, want c-aaa", got[0].ID)
	}
	// c-bbb should be last (orthogonal to query).
	if got[1].ID == "c-bbb" {
		t.Errorf("c-bbb should not beat c-mix; got order: %s,%s", got[0].ID, got[1].ID)
	}
}

func TestSearch_TopKExceedsSize(t *testing.T) {
	idx := New(&detEmbedder{})
	chunks := []*Chunk{
		{ID: "x", Text: "abc"},
		{ID: "y", Text: "bcd"},
	}
	if err := idx.Index(context.Background(), chunks, 8); err != nil {
		t.Fatal(err)
	}
	got, err := idx.Search(context.Background(), "abc", 100)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("Search returned %d, want 2 (capped by size)", len(got))
	}
}

func TestSearch_DefaultKWhenZero(t *testing.T) {
	idx := New(&detEmbedder{})
	chunks := make([]*Chunk, 20)
	for i := range chunks {
		chunks[i] = &Chunk{ID: "c", Text: "abc"}
	}
	if err := idx.Index(context.Background(), chunks, 0); err != nil {
		t.Fatal(err)
	}
	got, err := idx.Search(context.Background(), "abc", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 8 {
		t.Errorf("k=0 should default to 8; got %d", len(got))
	}
}

func TestSearch_NoEmbedder_KeywordFallback(t *testing.T) {
	idx := New(nil) // no embedder
	chunks := []*Chunk{
		{ID: "alpha", Text: "the quick brown fox"},
		{ID: "beta", Text: "fox fox fox jumps"},
		{ID: "gamma", Text: "lazy dog under the moon"},
	}
	if err := idx.Index(context.Background(), chunks, 4); err != nil {
		t.Fatal(err)
	}
	got, err := idx.Search(context.Background(), "fox", 2)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) == 0 || got[0].ID != "beta" {
		t.Errorf("expected 'beta' first (3 matches); got %+v", idsOf(got))
	}
}

func TestSearch_EmbedderError_FallsBackToKeyword(t *testing.T) {
	emb := &detEmbedder{}
	idx := New(emb)
	chunks := []*Chunk{
		{ID: "k1", Text: "needle in haystack"},
		{ID: "k2", Text: "nothing here"},
	}
	if err := idx.Index(context.Background(), chunks, 8); err != nil {
		t.Fatal(err)
	}
	// Make the *next* Embed call (the query embed) fail.
	emb.failBatch = emb.calls + 1
	got, err := idx.Search(context.Background(), "needle", 2)
	if err == nil {
		t.Errorf("want non-nil error returned alongside fallback results, got nil")
	}
	if len(got) == 0 || got[0].ID != "k1" {
		t.Errorf("fallback expected 'k1' first; got %v", idsOf(got))
	}
}

func TestKeywordSearch_EmptyQuery(t *testing.T) {
	got := keywordSearch([]*Chunk{{Text: "anything"}}, "   ", 5)
	if got != nil {
		t.Errorf("empty query must yield nil; got %v", got)
	}
}

func TestIndex_BatchErrorPropagates(t *testing.T) {
	emb := &detEmbedder{failBatch: 2} // fail on the 2nd batch
	idx := New(emb)
	chunks := make([]*Chunk, 5)
	for i := range chunks {
		chunks[i] = &Chunk{ID: "x", Text: "aaa"}
	}
	err := idx.Index(context.Background(), chunks, 2) // batches of 2 -> 3 batches
	if err == nil {
		t.Fatal("want error from failing batch")
	}
	if !strings.Contains(err.Error(), "embed batch") {
		t.Errorf("error should mention 'embed batch'; got %v", err)
	}
}

func TestIndex_WrongVecCount(t *testing.T) {
	emb := &detEmbedder{}
	emb.override = func(batch []string) ([][]float32, error) {
		// Return one fewer vector than asked.
		return make([][]float32, len(batch)-1), nil
	}
	idx := New(emb)
	chunks := []*Chunk{{Text: "a"}, {Text: "b"}}
	err := idx.Index(context.Background(), chunks, 8)
	if err == nil || !strings.Contains(err.Error(), "embedder returned") {
		t.Errorf("want vec-count mismatch error; got %v", err)
	}
}

func TestIndex_NilEmbedderStoresChunksOnly(t *testing.T) {
	idx := New(nil)
	chunks := []*Chunk{{ID: "z", Text: "abc"}}
	if err := idx.Index(context.Background(), chunks, 8); err != nil {
		t.Fatal(err)
	}
	if idx.Size() != 1 {
		t.Errorf("Size=%d, want 1", idx.Size())
	}
	// SearchByVector returns nothing (no vec stored), but doesn't panic.
	got := idx.SearchByVector([]float32{1}, 5)
	if len(got) != 0 {
		t.Errorf("SearchByVector without vecs returned %d, want 0", len(got))
	}
}

func TestChunkFiles_WithAST_SymbolAware(t *testing.T) {
	src := []byte("line1\nline2\nfunc A {}\nbody\nbody\nfunc B {}\nbody\n")
	files := map[string][]byte{"f.go": src}
	asts := map[string]*ast.FileAST{
		"f.go": {
			Path:     "f.go",
			Language: ast.LangGo,
			Symbols: []ast.Symbol{
				{Kind: "function", Name: "A", StartLine: 3, EndLine: 5},
				{Kind: "function", Name: "B", StartLine: 6, EndLine: 7},
			},
		},
	}
	got := ChunkFiles(files, asts, 120)
	if len(got) != 2 {
		t.Fatalf("want 2 symbol chunks, got %d", len(got))
	}
	if got[0].Symbol != "A" || got[1].Symbol != "B" {
		t.Errorf("symbol order: got %s,%s want A,B", got[0].Symbol, got[1].Symbol)
	}
	if got[0].Language != "go" {
		t.Errorf("language not propagated: %q", got[0].Language)
	}
	if !strings.Contains(got[0].Text, "func A") {
		t.Errorf("chunk text missing func A; got %q", got[0].Text)
	}
}

func TestChunkFiles_NoAST_SlidingWindow(t *testing.T) {
	var sb strings.Builder
	// Build exactly 250 lines (no trailing newline) so strings.Split(.., "\n")
	// yields 250 elements.
	for i := 0; i < 250; i++ {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString("line")
	}
	files := map[string][]byte{"big.txt": []byte(sb.String())}
	got := ChunkFiles(files, nil, 100)
	// 250 lines, window 100 -> 3 chunks (0-99, 100-199, 200-249)
	if len(got) != 3 {
		t.Fatalf("want 3 sliding chunks, got %d", len(got))
	}
	if got[0].StartLine != 1 || got[0].EndLine != 100 {
		t.Errorf("first chunk lines: got [%d,%d] want [1,100]", got[0].StartLine, got[0].EndLine)
	}
	if got[2].StartLine != 201 || got[2].EndLine != 250 {
		t.Errorf("last chunk lines: got [%d,%d] want [201,250]", got[2].StartLine, got[2].EndLine)
	}
}

func TestChunkFiles_DefaultMaxLines(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 121; i++ {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteByte('x')
	}
	files := map[string][]byte{"f": []byte(sb.String())}
	// maxLines<=0 -> defaults to 120
	got := ChunkFiles(files, nil, 0)
	if len(got) != 2 {
		t.Fatalf("want 2 chunks at default window, got %d", len(got))
	}
}

func TestChunkFiles_SkipsEmptyAndWhitespace(t *testing.T) {
	files := map[string][]byte{"empty.txt": []byte("\n\n   \n\n")}
	got := ChunkFiles(files, nil, 100)
	if len(got) != 0 {
		t.Errorf("whitespace-only file produced %d chunks, want 0", len(got))
	}
}

func TestChunkFiles_ASTWithoutSymbols_FallsBackToWindow(t *testing.T) {
	src := []byte("a\nb\nc\n")
	files := map[string][]byte{"f.go": src}
	asts := map[string]*ast.FileAST{
		"f.go": {Path: "f.go", Language: ast.LangGo, Symbols: nil},
	}
	got := ChunkFiles(files, asts, 100)
	if len(got) != 1 {
		t.Fatalf("want 1 fallback chunk, got %d", len(got))
	}
	if got[0].Symbol != "" {
		t.Errorf("fallback chunk should have empty Symbol; got %q", got[0].Symbol)
	}
}

func idsOf(cs []*Chunk) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.ID
	}
	return out
}
