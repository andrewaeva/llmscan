package callgraph

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/depgraph"
)

// synthGoProject creates N files, each with K functions calling neighbors.
// Used to stress-test call-graph construction at realistic project sizes.
func synthGoProject(b *testing.B, n int) ([]*ast.FileAST, *depgraph.Graph) {
	b.Helper()
	dir := b.TempDir()
	files := make([]*ast.FileAST, 0, n)
	for i := 0; i < n; i++ {
		var sb strings.Builder
		fmt.Fprintf(&sb, "package p%d\n", i)
		for j := 0; j < 10; j++ {
			fmt.Fprintf(&sb, `func F%d_%d(x string) {
	G%d_%d(x)
	exec.Command(x)
}
func G%d_%d(y string) {}
`, i, j, i, j, i, j)
		}
		path := filepath.Join(dir, fmt.Sprintf("f%d.go", i))
		a, err := ast.Parse(context.Background(), path, []byte(sb.String()))
		if err != nil {
			b.Fatal(err)
		}
		files = append(files, a)
	}
	g := depgraph.New(dir, files)
	return files, g
}

func benchBuild(b *testing.B, n int) {
	files, g := synthGoProject(b, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Build(files, g)
	}
}

func BenchmarkBuild100(b *testing.B)  { benchBuild(b, 100) }
func BenchmarkBuild1000(b *testing.B) { benchBuild(b, 1000) }
