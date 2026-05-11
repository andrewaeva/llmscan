package taint

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/entrypoints"
)

func synthProject(b *testing.B, n int) (files []*ast.FileAST, cg *callgraph.CallGraph, eps []entrypoints.Info) {
	b.Helper()
	dir := b.TempDir()
	for i := 0; i < n; i++ {
		var sb strings.Builder
		fmt.Fprintf(&sb, "package p%d\n", i)
		// One http handler per file plus a chain of 3 helper functions.
		fmt.Fprintf(&sb, `func Handle%d(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	A%d(q)
}
func A%d(s string) { B%d(s) }
func B%d(s string) { C%d(s) }
func C%d(s string) { db.Exec(s) }
`, i, i, i, i, i, i, i)
		path := filepath.Join(dir, fmt.Sprintf("f%d.go", i))
		a, err := ast.Parse(context.Background(), path, []byte(sb.String()))
		if err != nil {
			b.Fatal(err)
		}
		files = append(files, a)
	}
	g := depgraph.New(dir, files)
	cg = callgraph.Build(files, g)
	eps = entrypoints.Detect(files)
	return files, cg, eps
}

func benchInterProc(b *testing.B, n int) {
	files, cg, eps := synthProject(b, n)
	g := depgraph.New(b.TempDir(), files)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeInterProc(files, cg, g, eps, Options{MaxDepth: 6})
	}
}

func BenchmarkAnalyzeInterProc100(b *testing.B)  { benchInterProc(b, 100) }
func BenchmarkAnalyzeInterProc1000(b *testing.B) { benchInterProc(b, 1000) }
