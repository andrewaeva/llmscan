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
	"github.com/andrewaeva/llmscan/internal/types"
)

// runScanner runs one scanner agent over every chunk in parallel.
//
// Per-chunk extra context comes from scanContext.packsByChunkKey (assembled by
// stageBuildContextPacks). When a chunk has no pack, the scanner runs against
// the raw chunk without extra context.
func (e *Engine) runScanner(ctx context.Context, name string, client llm.Client, promptOverride string, chunks []types.FileTarget, _ *rag.Index, _ *agents.ContextFilter, sc scanContext) []types.Finding {
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
			if sc.packsByChunkKey != nil {
				if p, ok := sc.packsByChunkKey[chunkPackKey(c)]; ok && p != nil {
					extra = p.Render()
				}
			}

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
		return voteAggregate(runs, k)
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
