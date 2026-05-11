package pipeline

import (
	"fmt"
	"time"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/gitdiff"
	"github.com/andrewaeva/llmscan/internal/iac"
	"github.com/andrewaeva/llmscan/internal/secrets"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// applyDiffFilter narrows files to those changed in the configured diff range.
func (e *Engine) applyDiffFilter(files []types.FileTarget, target string) []types.FileTarget {
	if !gitdiff.IsRepo(target) {
		e.logf("diff: %s is not a git repo, ignoring", target)
		return files
	}
	changed, err := gitdiff.ChangedFiles(target, e.Cfg.Diff.Range)
	if err != nil {
		e.logf("diff: %v", err)
		return files
	}
	set := map[string]bool{}
	for _, p := range changed {
		set[p] = true
	}
	var out []types.FileTarget
	for _, f := range files {
		if set[f.Path] {
			out = append(out, f)
		}
	}
	return out
}

// applyWatchlistPreFilter drops files unlikely to contain taint sources/sinks.
func (e *Engine) applyWatchlistPreFilter(files []types.FileTarget, astByPath map[string]*myast.FileAST) []types.FileTarget {
	var out []types.FileTarget
	for _, f := range files {
		// Always keep IaC and unknown languages (no watchlist coverage).
		if iac.Detect(f.Path, f.Content) != iac.KindNone {
			out = append(out, f)
			continue
		}
		if _, ok := astByPath[f.Path]; !ok {
			out = append(out, f)
			continue
		}
		if watchlist.HasHit(f.Language, f.Content, watchlist.KindSource, watchlist.KindSink) {
			out = append(out, f)
		}
	}
	return out
}

// collectSuppressions extracts all // llmscan:ignore directives from source.
func (e *Engine) collectSuppressions(files []types.FileTarget) []suppress.Suppression {
	var all []suppress.Suppression
	for _, f := range files {
		all = append(all, suppress.Parse(f.Path, f.Content)...)
	}
	return all
}

// runSecretsPreFilter performs deterministic secret detection before any LLM call.
func (e *Engine) runSecretsPreFilter(files []types.FileTarget) []types.Finding {
	var out []types.Finding
	for _, f := range files {
		for _, m := range secrets.ScanText(f.Path, f.Content) {
			out = append(out, types.Finding{
				ID:          fmt.Sprintf("secrets-%s-%s:%d", m.RuleID, f.Path, m.Line),
				RuleID:      m.RuleID,
				Title:       m.Title,
				Description: fmt.Sprintf("Pre-filter match (entropy=%.2f, snippet=%s)", m.Entropy, m.Snippet),
				Severity:    types.Severity(m.Severity),
				Confidence:  types.ConfHigh,
				Score:       0.95,
				CWE:         m.CWE,
				File:        f.Path,
				StartLine:   m.Line,
				EndLine:     m.Line,
				CodeSample:  m.Snippet,
				Agent:       "secrets-prefilter",
				Verified:    true,
				Tags:        []string{"secrets", "deterministic"},
				CreatedAt:   time.Now(),
			})
		}
	}
	return out
}
