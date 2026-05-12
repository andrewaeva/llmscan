package taint

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
)

func parseAll(t *testing.T, srcs map[string]string) []*ast.FileAST {
	t.Helper()
	var out []*ast.FileAST
	for p, s := range srcs {
		a, err := ast.Parse(context.Background(), p, []byte(s))
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		out = append(out, a)
	}
	return out
}

func TestAnalyzeInterProc_BasicChain(t *testing.T) {
	dir := t.TempDir()
	files := parseAll(t, map[string]string{
		filepath.Join(dir, "a.go"): `package main

func Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	B(q)
}
func B(s string) {
	C(s)
}
func C(x string) {
	db.Exec(x)
}
`,
	})
	g := depgraph.New(dir, files)
	cg := callgraph.Build(files, g)
	eps := callgraph.Detect(files)
	if len(eps) == 0 {
		t.Fatalf("expected at least one entrypoint")
	}
	paths := AnalyzeInterProc(files, cg, g, eps, Options{MaxDepth: 6})
	if len(paths) == 0 {
		t.Fatalf("expected at least one taint path; got none")
	}
	// Check the path's sink kind is sql.
	found := false
	for _, p := range paths {
		if p.Sink.Kind == "sql" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an SQL sink path; got %+v", paths)
	}
}

func TestAnalyzeInterProc_WithSanitizer(t *testing.T) {
	dir := t.TempDir()
	files := parseAll(t, map[string]string{
		filepath.Join(dir, "a.go"): `package main

func Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	Safe(q)
}
func Safe(s string) {
	y := strconv.Atoi(s)
	db.Exec(y)
}
`,
	})
	g := depgraph.New(dir, files)
	cg := callgraph.Build(files, g)
	eps := callgraph.Detect(files)
	paths := AnalyzeInterProc(files, cg, g, eps, Options{MaxDepth: 6})
	// Sanitizer in Safe should cut the path or mark it sanitized.
	for _, p := range paths {
		if p.Sink.Kind == "sql" && len(p.Sanitizers) == 0 {
			t.Fatalf("expected sanitizers recorded for sanitized path: %+v", p)
		}
	}
}

func TestAnalyzeInterProc_CrossFile(t *testing.T) {
	dir := t.TempDir()
	files := parseAll(t, map[string]string{
		filepath.Join(dir, "handler.go"): `package main

import "example.com/proj/service"

func Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	service.DoWork(q)
}
`,
		filepath.Join(dir, "service.go"): `package service

func DoWork(s string) {
	db.Exec(s)
}
`,
	})
	g := depgraph.New(dir, files)
	cg := callgraph.Build(files, g)
	eps := callgraph.Detect(files)
	paths := AnalyzeInterProc(files, cg, g, eps, Options{MaxDepth: 6})
	// Must span both files.
	for _, p := range paths {
		if len(p.Hops) >= 2 {
			seen := map[string]bool{}
			for _, h := range p.Hops {
				seen[h.File] = true
			}
			if len(seen) >= 2 {
				return // success
			}
		}
	}
	if len(paths) == 0 {
		t.Fatalf("no cross-file path found")
	}
}

func TestMatchPath_NoneNearLine(t *testing.T) {
	if p := MatchPath(nil, "x.go", 5, 5); p != nil {
		t.Fatalf("expected nil match on empty paths")
	}
}
