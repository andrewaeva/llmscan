package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/voting"
)

// runScanner runs one scanner agent over every chunk in parallel, optionally
// enriching each prompt with RAG-retrieved + context-filtered context.
func (e *Engine) runScanner(ctx context.Context, name string, client llm.Client, promptOverride string, chunks []types.FileTarget, index *rag.Index, cfilter *agents.ContextFilter, sc scanContext) []types.Finding {
	scanner := &agents.Scanner{Name: name, Client: client, PromptOverride: promptOverride}
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []types.Finding

	for _, c := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c types.FileTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			extra := ""
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
					extra = agents.FormatChunksAsContext(filtered)
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
		}(c)
	}
	wg.Wait()
	return out
}
