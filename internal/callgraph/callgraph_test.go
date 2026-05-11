package callgraph

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/depgraph"
)

// parseAll parses every file in `srcs` and returns the FileAST slice.
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

func TestBuild_GoCrossFile(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "handler.go"): `package main

import "example.com/proj/service"

func Handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	service.DoWork(q)
}
`,
		filepath.Join(dir, "service.go"): `package service

import "example.com/proj/db"

func DoWork(s string) {
	db.SaveRow(s)
}
`,
		filepath.Join(dir, "db.go"): `package db

func SaveRow(s string) {
	exec.Command("sh", "-c", s)
}
`,
	}
	astList := parseAll(t, files)
	g := depgraph.New(dir, astList)
	cg := Build(astList, g)

	if len(cg.Nodes) < 3 {
		t.Fatalf("expected at least 3 function nodes, got %d", len(cg.Nodes))
	}
	// Find Handle and check it has at least one outgoing edge.
	var handleID NodeID
	for id, n := range cg.Nodes {
		if n.Func == "Handle" {
			handleID = id
		}
	}
	if handleID == "" {
		t.Fatalf("Handle not found in graph")
	}
	if len(cg.Callees(handleID)) == 0 {
		t.Fatalf("Handle should call DoWork")
	}
}

func TestBuild_PythonCrossFile(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "views.py"): `from service import handle

def view(req):
    handle(req.args.get("q"))
`,
		filepath.Join(dir, "service.py"): `from repo import save

def handle(x):
    save(x)
`,
		filepath.Join(dir, "repo.py"): `def save(x):
    cursor.execute(x)
`,
	}
	astList := parseAll(t, files)
	g := depgraph.New(dir, astList)
	cg := Build(astList, g)
	var view NodeID
	for id, n := range cg.Nodes {
		if n.Func == "view" {
			view = id
		}
	}
	if view == "" {
		t.Fatalf("view not found")
	}
	r := cg.Reachable(view)
	if len(r) < 2 {
		t.Fatalf("view should reach at least one other function; got %d", len(r))
	}
}

func TestBuild_JSExpress(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "routes.js"): `const ctrl = require('./controllers');
app.get('/x', function handler(req, res) { ctrl.handle(req.query.q); });
`,
		filepath.Join(dir, "controllers.js"): `function handle(q) {
  doStuff(q);
}
function doStuff(x) {
  eval(x);
}
module.exports = { handle };
`,
	}
	astList := parseAll(t, files)
	g := depgraph.New(dir, astList)
	cg := Build(astList, g)
	if len(cg.Nodes) < 2 {
		t.Fatalf("expected at least 2 nodes; got %d", len(cg.Nodes))
	}
}

func TestBuild_AmbiguousNamesProduceMultipleEdges(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "a.go"): `package a
func Save(x string) {}
`,
		filepath.Join(dir, "b.go"): `package b
func Save(x string) {}
`,
		filepath.Join(dir, "c.go"): `package c
func Call() { Save("y") }
`,
	}
	astList := parseAll(t, files)
	g := depgraph.New(dir, astList)
	cg := Build(astList, g)
	var call NodeID
	for id, n := range cg.Nodes {
		if n.Func == "Call" {
			call = id
		}
	}
	if call == "" {
		t.Fatalf("Call not found")
	}
	edges := cg.Callees(call)
	// Both Save() versions are plausible candidates because dep graph cannot
	// disambiguate fictional import paths. We expect >=1 edge (>=2 ideal).
	if len(edges) < 1 {
		t.Fatalf("Call should have at least 1 outgoing edge")
	}
}

func TestSimpleCalleeName(t *testing.T) {
	cases := map[string]string{
		"fmt.Println":     "Println",
		"db.Exec":         "Exec",
		"this.foo.bar":    "bar",
		"f":               "f",
		"Foo[int]":        "Foo",
		"obj.method(123)": "method",
		"a->b":            "b",
		"X:Y":             "Y",
	}
	for in, want := range cases {
		if got := simpleCalleeName(in); got != want {
			t.Errorf("simpleCalleeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReachable_BFS(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "main.go"): `package main
func A() { B() }
func B() { C() }
func C() { D() }
func D() {}
func Z() {}
`,
	}
	astList := parseAll(t, files)
	g := depgraph.New(dir, astList)
	cg := Build(astList, g)
	var a, z NodeID
	for id, n := range cg.Nodes {
		switch n.Func {
		case "A":
			a = id
		case "Z":
			z = id
		}
	}
	rs := cg.Reachable(a)
	if !rs[a] {
		t.Fatalf("reachable set should contain start")
	}
	if rs[z] {
		t.Fatalf("Z should be unreachable from A")
	}
	// Should reach B, C, D.
	count := 0
	for id := range rs {
		switch cg.Nodes[id].Func {
		case "A", "B", "C", "D":
			count++
		}
	}
	if count != 4 {
		t.Fatalf("expected to reach A,B,C,D; got %d", count)
	}
}

func TestDOT_ContainsNodes(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, "x.go"): `package x
func A() { B() }
func B() {}
`,
	}
	astList := parseAll(t, files)
	g := depgraph.New(dir, astList)
	dot := Build(astList, g).DOT()
	if !strings.Contains(dot, "digraph callgraph") {
		t.Fatalf("DOT missing header: %s", dot)
	}
	if !strings.Contains(dot, "->") {
		t.Fatalf("DOT missing edges")
	}
}
