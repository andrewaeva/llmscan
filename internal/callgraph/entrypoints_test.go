package callgraph

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
)

func parse(t *testing.T, p, src string) *ast.FileAST {
	t.Helper()
	a, err := ast.Parse(context.Background(), p, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", p, err)
	}
	return a
}

func findKind(eps []Info, fn string) (Kind, bool) {
	for _, e := range eps {
		if e.Func == fn {
			return e.Kind, true
		}
	}
	return "", false
}

func TestDetect_GoHTTP(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "h.go"), `package main
import "net/http"
func Index(w http.ResponseWriter, r *http.Request) {
    _ = r.URL.Query()
}
`)
	eps := Detect([]*ast.FileAST{a})
	k, ok := findKind(eps, "Index")
	if !ok || k != KindHTTP {
		t.Fatalf("expected Index to be HTTP entry; got %v %v", k, ok)
	}
}

func TestDetect_GoGin(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "h.go"), `package main
func PingHandler(c *gin.Context) {
	c.Query("name")
}
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "PingHandler"); !ok || k != KindHTTP {
		t.Fatalf("gin handler not detected: %v %v", k, ok)
	}
}

func TestDetect_GoCobraMain(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "main.go"), `package main
func main() {
    cobra.Command{Use: "x"}
}
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "main"); !ok || k != KindCLI {
		t.Fatalf("main not detected as CLI: %v %v", k, ok)
	}
}

func TestDetect_PythonFlask(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "v.py"), `from flask import Flask
app = Flask(__name__)
@app.route("/x")
def view():
    return "ok"
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "view"); !ok || k != KindHTTP {
		t.Fatalf("flask view not detected: %v %v", k, ok)
	}
}

func TestDetect_PythonFastAPI(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "v.py"), `from fastapi import FastAPI
app = FastAPI()
@app.get("/items/{id}")
def get_item(id):
    return id
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "get_item"); !ok || k != KindHTTP {
		t.Fatalf("fastapi route not detected: %v %v", k, ok)
	}
}

func TestDetect_JSExpress(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "v.js"), `app.get('/x', handler);
function handler(req, res) {
  res.send(req.query.q);
}
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "handler"); !ok || k != KindHTTP {
		t.Fatalf("express handler not detected: %v %v", k, ok)
	}
}

func TestDetect_JavaSpring(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "C.java"), `@RestController
public class C {
    @GetMapping("/x")
    public String get(@RequestParam String q) { return q; }
}
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "get"); !ok || k != KindHTTP {
		t.Fatalf("spring handler not detected: %v %v", k, ok)
	}
}

func TestDetect_JavaMain(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "A.java"), `public class A {
    public static void main(String[] args) { }
}
`)
	eps := Detect([]*ast.FileAST{a})
	if k, ok := findKind(eps, "main"); !ok || k != KindCLI {
		t.Fatalf("java main not detected: %v %v", k, ok)
	}
}

func TestIDs_Stable(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "h.go"), `package main
func Handle(w http.ResponseWriter, r *http.Request) {}
`)
	eps := Detect([]*ast.FileAST{a})
	ids := IDs(eps)
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("expected one entrypoint node id; got %v", ids)
	}
}
