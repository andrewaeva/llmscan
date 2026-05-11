// Package rag is an in-memory retrieval-augmented context store.
//
// Pipeline:
//   1. Index() splits source files into symbol-aware chunks, computes embeddings,
//      keeps everything in RAM (vectors + chunk metadata + raw text).
//   2. Search(query, k) returns top-k chunks by cosine similarity.
//   3. SearchByVector() is exposed for callers that already have an embedding.
//
// No persistence. The index is built per scan.
package rag

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/andrewaeva/llmscan/internal/ast"
)

// Chunk is one indexed code fragment.
type Chunk struct {
	ID         string  `json:"id"`
	File       string  `json:"file"`
	StartLine  int     `json:"start_line"`
	EndLine    int     `json:"end_line"`
	Symbol     string  `json:"symbol,omitempty"`
	SymbolKind string  `json:"symbol_kind,omitempty"`
	Language   string  `json:"language"`
	Text       string  `json:"text"`
	vec        []float32
}

// Embedder produces a fixed-length vector for one or many texts.
type Embedder interface {
	Embed(ctx context.Context, batch []string) ([][]float32, error)
	Dim() int
	Name() string
}

// Index is the in-memory store.
type Index struct {
	mu       sync.RWMutex
	chunks   []*Chunk
	embedder Embedder
}

// New creates an empty index.
func New(e Embedder) *Index { return &Index{embedder: e} }

// ChunkFiles splits the given files into chunks. If `asts` is provided we cut
// along function/class boundaries (much better signal than fixed-line windows).
// Files without an AST entry fall back to a 120-line sliding window.
func ChunkFiles(files map[string][]byte, asts map[string]*ast.FileAST, maxLines int) []*Chunk {
	if maxLines <= 0 {
		maxLines = 120
	}
	var out []*Chunk
	for path, src := range files {
		txt := string(src)
		lines := strings.Split(txt, "\n")
		a := asts[path]
		if a != nil && len(a.Symbols) > 0 {
			// symbol-level chunks; gap chunks between symbols are skipped.
			syms := append([]ast.Symbol(nil), a.Symbols...)
			sort.Slice(syms, func(i, j int) bool { return syms[i].StartLine < syms[j].StartLine })
			for i, s := range syms {
				body := strings.Join(lines[max0(s.StartLine-1):min1(s.EndLine, len(lines))], "\n")
				if len(body) < 2 {
					continue
				}
				out = append(out, &Chunk{
					ID:         fmt.Sprintf("%s#%d:%s", path, i, s.Name),
					File:       path,
					StartLine:  s.StartLine,
					EndLine:    s.EndLine,
					Symbol:     s.Name,
					SymbolKind: s.Kind,
					Language:   string(a.Language),
					Text:       body,
				})
			}
			continue
		}
		// Sliding-window fallback.
		for start := 0; start < len(lines); start += maxLines {
			end := start + maxLines
			if end > len(lines) {
				end = len(lines)
			}
			body := strings.Join(lines[start:end], "\n")
			if strings.TrimSpace(body) == "" {
				continue
			}
			out = append(out, &Chunk{
				ID:        fmt.Sprintf("%s#%d", path, start),
				File:      path,
				StartLine: start + 1,
				EndLine:   end,
				Text:      body,
			})
		}
	}
	return out
}

// Index embeds the chunks and stores them. Safe to call once per scan.
// Batched to avoid huge requests.
func (i *Index) Index(ctx context.Context, chunks []*Chunk, batchSize int) error {
	if i.embedder == nil {
		// No embedder: keep chunks for keyword-only search.
		i.mu.Lock()
		i.chunks = chunks
		i.mu.Unlock()
		return nil
	}
	if batchSize <= 0 {
		batchSize = 64
	}
	for start := 0; start < len(chunks); start += batchSize {
		end := start + batchSize
		if end > len(chunks) {
			end = len(chunks)
		}
		texts := make([]string, end-start)
		for j, c := range chunks[start:end] {
			t := c.Text
			if len(t) > 6000 {
				t = t[:6000]
			}
			texts[j] = t
		}
		vecs, err := i.embedder.Embed(ctx, texts)
		if err != nil {
			return fmt.Errorf("embed batch [%d:%d]: %w", start, end, err)
		}
		if len(vecs) != end-start {
			return fmt.Errorf("embedder returned %d vecs for %d inputs", len(vecs), end-start)
		}
		for j, v := range vecs {
			chunks[start+j].vec = v
		}
	}
	i.mu.Lock()
	i.chunks = chunks
	i.mu.Unlock()
	return nil
}

// Search returns the top-k chunks most similar to the query. If no embedder is
// configured it falls back to keyword scoring (very rough but useful for tests).
func (i *Index) Search(ctx context.Context, query string, k int) ([]*Chunk, error) {
	if k <= 0 {
		k = 8
	}
	i.mu.RLock()
	chunks := i.chunks
	i.mu.RUnlock()
	if i.embedder == nil {
		return keywordSearch(chunks, query, k), nil
	}
	vec, err := i.embedder.Embed(ctx, []string{query})
	if err != nil || len(vec) == 0 {
		return keywordSearch(chunks, query, k), err
	}
	return i.SearchByVector(vec[0], k), nil
}

// SearchByVector returns top-k by cosine similarity.
func (i *Index) SearchByVector(v []float32, k int) []*Chunk {
	i.mu.RLock()
	defer i.mu.RUnlock()
	type scored struct {
		c *Chunk
		s float32
	}
	scoredItems := make([]scored, 0, len(i.chunks))
	for _, c := range i.chunks {
		if c.vec == nil {
			continue
		}
		scoredItems = append(scoredItems, scored{c, cosine(v, c.vec)})
	}
	sort.Slice(scoredItems, func(a, b int) bool { return scoredItems[a].s > scoredItems[b].s })
	if k > len(scoredItems) {
		k = len(scoredItems)
	}
	out := make([]*Chunk, k)
	for j := 0; j < k; j++ {
		out[j] = scoredItems[j].c
	}
	return out
}

// Size returns the number of indexed chunks.
func (i *Index) Size() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.chunks)
}

// keywordSearch is a very cheap fallback.
func keywordSearch(chunks []*Chunk, q string, k int) []*Chunk {
	terms := strings.Fields(strings.ToLower(q))
	if len(terms) == 0 {
		return nil
	}
	type scored struct {
		c *Chunk
		s int
	}
	res := make([]scored, 0, len(chunks))
	for _, c := range chunks {
		txt := strings.ToLower(c.Text)
		score := 0
		for _, t := range terms {
			score += strings.Count(txt, t)
		}
		if score > 0 {
			res = append(res, scored{c, score})
		}
	}
	sort.Slice(res, func(a, b int) bool { return res[a].s > res[b].s })
	if k > len(res) {
		k = len(res)
	}
	out := make([]*Chunk, k)
	for j := 0; j < k; j++ {
		out[j] = res[j].c
	}
	return out
}

func cosine(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return float32(dot / (math.Sqrt(na) * math.Sqrt(nb)))
}

func max0(a int) int {
	if a < 0 {
		return 0
	}
	return a
}
func min1(a, b int) int {
	if a < b {
		return a
	}
	return b
}
