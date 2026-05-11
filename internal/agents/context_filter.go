package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
)

// ContextFilter is an LLM-backed reranker. It receives a primary chunk (the one
// being scanned) plus candidate chunks from RAG and returns a small set of
// chunks that are actually relevant for the scanner about to run.
//
// The point is precision: scanner agents work much better when their input
// excludes unrelated code with similar keywords (e.g. unrelated SQL helpers
// when the scanner is hunting for SSRF).
type ContextFilter struct {
	Client llm.Client
}

const contextFilterSystem = `You are the Context Filter agent of a multi-agent code scanner.

You receive:
  - "primary": one focused code fragment a scanner is about to analyze
  - "candidates": other fragments from the repo retrieved by similarity search
  - "scope": the vulnerability class the scanner cares about (e.g. "injection")

Your job: pick at most K candidate fragments that are TRULY relevant to analyzing
the primary fragment under the given scope. Drop everything else.

Examples of relevant context:
  - definition of a function called from the primary
  - sanitizer/validator that wraps user input on the way in
  - sink helper (db query, exec, http request) that primary delegates to
  - configuration constants that determine if the code path is reachable

Examples of NOT relevant:
  - unrelated business logic with similar variable names
  - tests, examples, fixtures
  - the primary itself

Return JSON: {"keep": ["<chunk_id>", ...], "reason": "1 sentence"}
No prose outside JSON.`

// Filter ranks candidates and returns the ones the LLM judged relevant.
// If the LLM call fails or the client is nil, it falls back to top-N similarity.
func (cf *ContextFilter) Filter(ctx context.Context, primary *rag.Chunk, candidates []*rag.Chunk, scope string, k int) ([]*rag.Chunk, error) {
	if k <= 0 || k > len(candidates) {
		k = len(candidates)
	}
	if cf == nil || cf.Client == nil || len(candidates) == 0 {
		if k > len(candidates) {
			k = len(candidates)
		}
		return candidates[:k], nil
	}
	type chunkLite struct {
		ID    string `json:"id"`
		File  string `json:"file"`
		Lines string `json:"lines"`
		Text  string `json:"text"`
	}
	cands := make([]chunkLite, 0, len(candidates))
	for _, c := range candidates {
		cands = append(cands, chunkLite{
			ID:    c.ID,
			File:  c.File,
			Lines: fmt.Sprintf("%d-%d", c.StartLine, c.EndLine),
			Text:  truncateRunes(c.Text, 1200),
		})
	}
	payload := map[string]any{
		"scope": scope,
		"k":     k,
		"primary": chunkLite{
			ID: primary.ID, File: primary.File,
			Lines: fmt.Sprintf("%d-%d", primary.StartLine, primary.EndLine),
			Text:  truncateRunes(primary.Text, 2000),
		},
		"candidates": cands,
	}
	buf, _ := json.Marshal(payload)
	resp, err := cf.Client.Complete(ctx, llm.Request{
		System:   contextFilterSystem,
		Messages: []llm.Message{{Role: "user", Content: string(buf)}},
		JSON:     true,
	})
	if err != nil {
		return candidates[:k], err
	}
	var parsed struct {
		Keep   []string `json:"keep"`
		Reason string   `json:"reason"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &parsed); err != nil {
		return candidates[:k], fmt.Errorf("context_filter decode: %w", err)
	}
	keep := map[string]bool{}
	for _, id := range parsed.Keep {
		keep[id] = true
	}
	out := make([]*rag.Chunk, 0, len(parsed.Keep))
	for _, c := range candidates {
		if keep[c.ID] {
			out = append(out, c)
		}
	}
	return out, nil
}

func truncateRunes(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}

// FormatChunksAsContext renders chunks for inclusion into a scanner prompt.
func FormatChunksAsContext(chunks []*rag.Chunk) string {
	if len(chunks) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Additional repo context (retrieved):\n")
	for _, c := range chunks {
		fmt.Fprintf(&b, "\n--- %s (%d-%d, %s) ---\n", c.File, c.StartLine, c.EndLine, c.Symbol)
		b.WriteString(c.Text)
		b.WriteString("\n")
	}
	return b.String()
}
