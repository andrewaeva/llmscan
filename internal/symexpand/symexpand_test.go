package symexpand

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
)

func parse(t testing.TB, path, src string) *ast.FileAST {
	t.Helper()
	f, err := ast.Parse(context.Background(), path, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

func TestUniqueNamesDedupsAndFiltersKeywords(t *testing.T) {
	src := `if cond { foo() }
bar(x)
foo()
return baz()`
	got := uniqueNames(src)
	want := map[string]bool{"foo": true, "bar": true, "baz": true}
	if len(got) != len(want) {
		t.Errorf("got %v want keys %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected name %q", n)
		}
	}
}

func TestIsKeyword(t *testing.T) {
	for _, k := range []string{"if", "for", "func", "class", "return", "new"} {
		if !isKeyword(k) {
			t.Errorf("isKeyword(%q)=false", k)
		}
	}
	if isKeyword("foobar") {
		t.Error("foobar should not be keyword")
	}
}

func TestExpandFindsDefinition(t *testing.T) {
	defSrc := `package main
func helper(x int) int {
	return x + 1
}
`
	caller := parse(t, "caller.go", `package main
func main() {
	v := helper(42)
	_ = v
}
`)
	def := parse(t, "def.go", defSrc)

	e := New([]*ast.FileAST{caller, def})
	defs := e.Expand("v := helper(42)", "caller.go", map[string][]string{"caller.go": {"def.go"}}, Options{Max: 4, MaxLines: 10})
	if len(defs) == 0 {
		t.Fatal("no definitions returned")
	}
	found := false
	for _, d := range defs {
		if d.Name == "helper" && d.File == "def.go" {
			found = true
			if !strings.Contains(d.Code, "helper") {
				t.Errorf("def code missing name: %q", d.Code)
			}
		}
	}
	if !found {
		t.Errorf("expected helper definition, got %+v", defs)
	}
}

func TestExpandRespectsMax(t *testing.T) {
	files := []*ast.FileAST{
		parse(t, "a.go", "package a\nfunc aa() {}\nfunc bb() {}\nfunc cc() {}\nfunc dd() {}\n"),
	}
	e := New(files)
	chunk := "aa(); bb(); cc(); dd()"
	defs := e.Expand(chunk, "x.go", nil, Options{Max: 2})
	if len(defs) > 2 {
		t.Errorf("Max=2 violated: got %d", len(defs))
	}
}

func TestExpandEmptyChunk(t *testing.T) {
	e := New(nil)
	if got := e.Expand("", "x.go", nil, Options{}); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestExpandPrefersDepFiles(t *testing.T) {
	dep := parse(t, "dep.go", "package p\nfunc target() {}\n")
	other := parse(t, "other.go", "package p\nfunc target() {}\n")
	e := New([]*ast.FileAST{other, dep})
	defs := e.Expand("target()", "main.go", map[string][]string{"main.go": {"dep.go"}}, Options{Max: 1})
	if len(defs) != 1 {
		t.Fatalf("got %d defs", len(defs))
	}
	if defs[0].File != "dep.go" {
		t.Errorf("preferred file=%q want dep.go", defs[0].File)
	}
}

func TestNewSkipsNilFiles(t *testing.T) {
	e := New([]*ast.FileAST{nil, nil})
	if len(e.byName) != 0 {
		t.Errorf("expected empty byName, got %v", e.byName)
	}
}

func BenchmarkUniqueNames(b *testing.B) {
	src := `foo(); bar(); baz(); foo(); helper(x); bar(y, z)`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = uniqueNames(src)
	}
}

func BenchmarkExpand(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("package p\n")
	for i := 0; i < 50; i++ {
		sb.WriteString("func fn")
		sb.WriteString(string(rune('A' + (i % 26))))
		sb.WriteString("() {}\n")
	}
	f := parse(b, "f.go", sb.String())
	e := New([]*ast.FileAST{f})
	chunk := "fnA(); fnB(); fnC(); fnD()"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Expand(chunk, "x.go", nil, Options{Max: 4})
	}
}
