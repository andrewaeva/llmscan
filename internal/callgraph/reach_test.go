package callgraph

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/types"
)

func TestBuildAndApplyTestFile(t *testing.T) {
	files := []*ast.FileAST{
		{Path: "internal/foo/foo_test.go"},
		{Path: "internal/foo/foo.go"},
	}
	idx := BuildReach(files, map[string][]string{
		"internal/foo/foo.go": {"caller.go"},
	})
	findings := []types.Finding{
		{File: "internal/foo/foo_test.go", RuleID: "x", Score: 0.9, Confidence: types.ConfHigh},
		{File: "internal/foo/foo.go", RuleID: "y", Score: 0.9, Confidence: types.ConfHigh},
	}
	down := idx.Apply(findings)
	if down != 1 {
		t.Fatalf("expected 1 downgrade (the _test.go), got %d", down)
	}
	if findings[0].Confidence != types.ConfLow || findings[0].Score > 0.4 {
		t.Errorf("test-file finding not downgraded: %+v", findings[0])
	}
	if findings[1].Score != 0.9 {
		t.Errorf("non-test file should be untouched, got %+v", findings[1])
	}
}

func TestApplyDeadModule(t *testing.T) {
	files := []*ast.FileAST{{Path: "pkg/unused.go"}}
	idx := BuildReach(files, map[string][]string{}) // no callers anywhere
	findings := []types.Finding{
		{File: "pkg/unused.go", Score: 0.95, Confidence: types.ConfHigh},
	}
	if down := idx.Apply(findings); down != 1 {
		t.Fatalf("expected 1 downgrade for dead module, got %d", down)
	}
	if findings[0].FPReason == "" {
		t.Error("FPReason should be set")
	}
}

func TestApplyNilIndex(t *testing.T) {
	var idx *ReachIndex
	if got := idx.Apply([]types.Finding{{}}); got != 0 {
		t.Errorf("nil index must return 0, got %d", got)
	}
}

func TestLooksLikeTestPaths(t *testing.T) {
	cases := map[string]bool{
		"a/b_test.go":           true,
		"src/tests/conftest.py": true,
		"src/test/Foo.java":     true,
		"a/fixtures/data.go":    true,
		"x/__tests__/foo.js":    true,
		"a/foo.spec.ts":         true,
		"a/foo.test.js":         true,
		"pytests/test_x.py":     true,
		"internal/foo/foo.go":   false,
		"cmd/llmscan/main.go":   false,
	}
	for p, want := range cases {
		if got := looksLikeTest(p); got != want {
			t.Errorf("looksLikeTest(%q) = %v, want %v", p, got, want)
		}
	}
}

func BenchmarkApply(b *testing.B) {
	files := make([]*ast.FileAST, 100)
	callers := map[string][]string{}
	findings := make([]types.Finding, 100)
	for i := 0; i < 100; i++ {
		path := "pkg/file.go"
		files[i] = &ast.FileAST{Path: path}
		callers[path] = []string{"main.go"}
		findings[i] = types.Finding{File: path, Score: 0.8, Confidence: types.ConfHigh}
	}
	idx := BuildReach(files, callers)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.Apply(findings)
	}
}
