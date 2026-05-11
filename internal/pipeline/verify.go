package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/types"
)

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
