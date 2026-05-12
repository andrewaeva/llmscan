package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/voting"
)

// runScanner runs one scanner agent over every chunk in parallel, optionally
// enriching each prompt with RAG-retrieved + context-filtered context.
//
//nolint:gocyclo // per-chunk scan with multiple optional enrichments
func (e *Engine) runScanner(ctx context.Context, name string, client llm.Client, promptOverride string, chunks []types.FileTarget, index *rag.Index, cfilter *agents.ContextFilter, sc scanContext) []types.Finding {
	scanner := &agents.Scanner{Name: name, Client: client, PromptOverride: promptOverride}
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []types.Finding
	var done int64
	total := len(chunks)
	start := time.Now()

	for _, c := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c types.FileTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			extra := ""

			// Preferred path: ContextPack assembled by stageBuildContextPacks.
			// When present, it supersedes the legacy extra-context sources because
			// it already deduplicates callees, callers, types, sanitizers, and RAG
			// neighbours inside a hard token budget.
			if sc.packsByChunkKey != nil {
				if p, ok := sc.packsByChunkKey[chunkPackKey(c)]; ok && p != nil {
					extra = p.Render()
					fnds := e.scanOneChunk(ctx, scanner, c, extra)
					if fnds != nil {
						mu.Lock()
						out = append(out, fnds...)
						mu.Unlock()
					}
					n := atomic.AddInt64(&done, 1)
					e.prog().Inc("scanners", 1)
					if e.Verbose && total >= 20 && (n%25 == 0 || n == int64(total)) {
						e.logf("scan:%s progress %d/%d (%.0fs)", name, n, total, time.Since(start).Seconds())
					}
					return
				}
			}

			// Legacy fallback: symbol-expansion / taint traces / RAG.
			// Symbol-expansion: append referenced definitions for high precision.
			if sc.expander != nil {
				defs := sc.expander.Expand(c.Content, c.Path, sc.deps, symexpand.Options{
					Hops:     e.Cfg.Precision.SymExpandHops,
					Max:      e.Cfg.Precision.SymExpandMax,
					MaxLines: 30,
				})
				if len(defs) > 0 {
					var b strings.Builder
					b.WriteString("\n// --- Referenced definitions (symbol-expansion) ---\n")
					for _, d := range defs {
						fmt.Fprintf(&b, "// %s @ %s:%d-%d\n%s\n\n", d.Name, d.File, d.StartLine, d.EndLine, d.Code)
					}
					extra += b.String()
				}
			}
			// Taint traces relevant to this chunk.
			if trs := sc.taintTraces[c.Path]; len(trs) > 0 {
				var b strings.Builder
				b.WriteString("\n// --- Taint traces in this file ---\n")
				for _, t := range trs {
					for _, h := range t.Hops {
						fmt.Fprintf(&b, "//   %s @ %s:%d: %s\n", h.Kind, h.File, h.Line, h.Code)
					}
					b.WriteString("//   ---\n")
				}
				extra += b.String()
			}
			if index != nil {
				// query = first 4 lines of the chunk + the scanner scope
				lines := strings.SplitN(c.Content, "\n", 5)
				head := strings.Join(lines[:min(len(lines), 4)], "\n")
				query := head + "\n\nlooking for: " + name
				cands, err := index.Search(ctx, query, e.Cfg.RAG.TopK)
				if err == nil && len(cands) > 0 {
					// Drop candidates that point to the same chunk we're already analyzing.
					filtered := cands[:0]
					for _, cand := range cands {
						if cand.File == c.Path && cand.StartLine == c.LineOffset+1 {
							continue
						}
						filtered = append(filtered, cand)
					}
					primary := &rag.Chunk{
						ID: c.Path + "#primary", File: c.Path, Text: c.Content,
						StartLine: c.LineOffset + 1, EndLine: c.LineOffset + c.Lines,
					}
					if cfilter != nil {
						filtered, _ = cfilter.Filter(ctx, primary, filtered, name, e.Cfg.RAG.FilterKeep)
					} else if len(filtered) > e.Cfg.RAG.FilterKeep {
						filtered = filtered[:e.Cfg.RAG.FilterKeep]
					}
					extra += agents.FormatChunksAsContext(filtered)
				}
			}

			var fnds []types.Finding
			var err error
			if e.Cfg.Precision.VoteN > 1 {
				runs := make([][]types.Finding, 0, e.Cfg.Precision.VoteN)
				for i := 0; i < e.Cfg.Precision.VoteN; i++ {
					r, rerr := scanner.Scan(ctx, c, extra)
					if rerr != nil {
						e.logf("scan:%s vote%d on %s: %v", name, i, c.Path, rerr)
						continue
					}
					runs = append(runs, r)
				}
				k := e.Cfg.Precision.VoteK
				if k <= 0 {
					k = (e.Cfg.Precision.VoteN / 2) + 1
				}
				fnds = voting.Aggregate(runs, k)
			} else {
				fnds, err = scanner.Scan(ctx, c, extra)
				if err != nil {
					e.logf("scan:%s on %s: %v", name, c.Path, err)
					return
				}
			}
			mu.Lock()
			out = append(out, fnds...)
			mu.Unlock()

			n := atomic.AddInt64(&done, 1)
			e.prog().Inc("scanners", 1)
			if e.Verbose && total >= 20 && (n%25 == 0 || n == int64(total)) {
				e.logf("scan:%s progress %d/%d (%.0fs)", name, n, total, time.Since(start).Seconds())
			}
		}(c)
	}
	wg.Wait()
	return out
}

// ---- Verifier pass ----

// verifyAll re-checks each finding against an expanded code snippet.
func (e *Engine) verifyAll(ctx context.Context, v *agents.Verifier, findings []types.Finding, contentByPath map[string]string) []types.Finding {
	if v == nil || v.Client == nil {
		return findings
	}
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	out := make([]types.Finding, len(findings))
	for i, f := range findings {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, f types.Finding) {
			defer wg.Done()
			defer func() { <-sem }()
			snippet := snippetWithLines(contentByPath[f.File], f.StartLine, f.EndLine, 25)
			vf, err := v.Verify(ctx, f, snippet)
			if err != nil {
				e.logf("verifier on %s:%d: %v", f.File, f.StartLine, err)
				out[i] = f
				return
			}
			out[i] = vf
		}(i, f)
	}
	wg.Wait()
	return out
}

// scanOneChunk runs one scan request (with optional self-consistency voting)
// and returns the resulting findings. Logs and swallows errors; nil result
// means "nothing to add".
func (e *Engine) scanOneChunk(ctx context.Context, scanner *agents.Scanner, c types.FileTarget, extra string) []types.Finding {
	if e.Cfg.Precision.VoteN > 1 {
		runs := make([][]types.Finding, 0, e.Cfg.Precision.VoteN)
		for i := 0; i < e.Cfg.Precision.VoteN; i++ {
			r, rerr := scanner.Scan(ctx, c, extra)
			if rerr != nil {
				e.logf("scan:%s vote%d on %s: %v", scanner.Name, i, c.Path, rerr)
				continue
			}
			runs = append(runs, r)
		}
		k := e.Cfg.Precision.VoteK
		if k <= 0 {
			k = (e.Cfg.Precision.VoteN / 2) + 1
		}
		return voting.Aggregate(runs, k)
	}
	fnds, err := scanner.Scan(ctx, c, extra)
	if err != nil {
		e.logf("scan:%s on %s: %v", scanner.Name, c.Path, err)
		return nil
	}
	return fnds
}

// snippetWithLines returns content lines [start-pad, end+pad] formatted with line numbers.
func snippetWithLines(content string, start, end, pad int) string {
	if content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	from := start - pad - 1
	to := end + pad
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	var b strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "%5d | %s\n", i+1, lines[i])
	}
	return b.String()
}
