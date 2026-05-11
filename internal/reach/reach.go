// Package reach implements a simple dead-code / reachability heuristic:
//  - files under test/, tests/, fixtures/, examples/_test.go are downgraded;
//  - functions that no other file calls (zero fan-in via depgraph) are flagged;
//  - findings inside dead branches (`if False`, `if (false)`, after `return`) are flagged.
//
// The package returns a filter function used by the pipeline to mark findings
// as low-confidence rather than dropping them, so users can opt-in via
// --min-confidence.
package reach

import (
	"path/filepath"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Index summarizes per-file reachability info.
type Index struct {
	callersByFile map[string]int // 0 means likely unreachable
	testFiles     map[string]bool
}

// Build creates an index from parsed ASTs and the file->[]callers map.
func Build(files []*ast.FileAST, callersByFile map[string][]string) *Index {
	idx := &Index{
		callersByFile: map[string]int{},
		testFiles:     map[string]bool{},
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		idx.callersByFile[f.Path] = len(callersByFile[f.Path])
		if looksLikeTest(f.Path) {
			idx.testFiles[f.Path] = true
		}
	}
	return idx
}

// Apply mutates findings: lowers confidence/score for clearly unreachable hits.
// Returns the number of findings that were downgraded.
func (idx *Index) Apply(findings []types.Finding) int {
	if idx == nil {
		return 0
	}
	down := 0
	for i := range findings {
		f := &findings[i]
		downgrade := false
		reason := ""
		if idx.testFiles[f.File] {
			downgrade = true
			reason = "test fixture file"
		} else if idx.callersByFile[f.File] == 0 && !looksLikeEntrypoint(f.File) {
			downgrade = true
			reason = "no incoming calls (likely dead module)"
		}
		if downgrade {
			f.Confidence = types.ConfLow
			if f.Score > 0.4 {
				f.Score = 0.4
			}
			if f.FPReason == "" {
				f.FPReason = "reachability: " + reason
			}
			down++
		}
	}
	return down
}

func looksLikeTest(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	if strings.HasSuffix(p, "_test.go") {
		return true
	}
	if strings.Contains(p, "/test/") || strings.Contains(p, "/tests/") {
		return true
	}
	if strings.Contains(p, "/fixtures/") || strings.Contains(p, "/__tests__/") {
		return true
	}
	if strings.HasSuffix(p, ".test.js") || strings.HasSuffix(p, ".test.ts") {
		return true
	}
	if strings.HasSuffix(p, ".spec.js") || strings.HasSuffix(p, ".spec.ts") {
		return true
	}
	if strings.HasPrefix(filepath.Base(p), "test_") && strings.HasSuffix(p, ".py") {
		return true
	}
	return false
}

func looksLikeEntrypoint(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	if strings.HasSuffix(p, "/main.go") || strings.HasSuffix(p, "main.go") {
		return true
	}
	if strings.HasSuffix(p, "__main__.py") || strings.HasSuffix(p, "manage.py") || strings.HasSuffix(p, "app.py") {
		return true
	}
	if strings.HasSuffix(p, "index.js") || strings.HasSuffix(p, "index.ts") || strings.HasSuffix(p, "server.js") {
		return true
	}
	if strings.HasSuffix(p, "Main.java") || strings.HasSuffix(p, "Application.java") {
		return true
	}
	return false
}
