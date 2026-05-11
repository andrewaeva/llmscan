package taint

import (
	"context"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
)

func TestAnalyzeNilFiles(t *testing.T) {
	got := Analyze(nil)
	if got == nil {
		t.Fatal("nil map")
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestAnalyzeSkipsNilFile(t *testing.T) {
	got := Analyze([]*ast.FileAST{nil})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestAnalyzeParsedGoFile(t *testing.T) {
	src := `package main
import (
	"net/http"
	"os/exec"
)
func handler(r *http.Request) {
	q := r.URL.Query().Get("cmd")
	_ = exec.Command("sh", "-c", q)
}
`
	f, err := ast.Parse(context.Background(), "h.go", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := Analyze([]*ast.FileAST{f})
	if _, ok := got["h.go"]; !ok {
		t.Errorf("missing entry for h.go: %v", got)
	}
}

func TestLinkIsIdentity(t *testing.T) {
	in := map[string][]Trace{"a.go": {{Category: "sql"}}}
	got := Link(in, map[string][]string{"a.go": {"b.go"}})
	if len(got) != 1 || got["a.go"][0].Category != "sql" {
		t.Errorf("Link mutated input: %v", got)
	}
}

func TestCaptureLHS(t *testing.T) {
	cases := map[string]string{
		"x := 1":          "x",
		"  q = r.Query()": "q",
		"  if x > 0":      "",
		"":                "",
		"return x":        "",
		"db.Exec(q)":      "",
	}
	for in, want := range cases {
		if got := captureLHS(in); got != want {
			t.Errorf("captureLHS(%q)=%q want %q", in, got, want)
		}
	}
}

func TestContainsWord(t *testing.T) {
	if !containsWord("db.Exec(query)", "query") {
		t.Error("should contain word query")
	}
	if containsWord("db.Exec(myquery)", "query") {
		t.Error("must not match substring inside identifier")
	}
	if containsWord("anything", "") {
		t.Error("empty word must be false")
	}
	if !containsWord("x = 1", "x") {
		t.Error("should match single-char identifier")
	}
}

func TestIsIdent(t *testing.T) {
	for _, b := range []byte("abcXYZ_09") {
		if !isIdent(b) {
			t.Errorf("isIdent(%q)=false", b)
		}
	}
	for _, b := range []byte(" .(){};,") {
		if isIdent(b) {
			t.Errorf("isIdent(%q)=true", b)
		}
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 1: "1", 42: "42", 12345: "12345"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d)=%q want %q", in, got, want)
		}
	}
}

func BenchmarkContainsWord(b *testing.B) {
	s := "the quick brown fox jumps over the lazy dog and queries"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = containsWord(s, "queries")
	}
}

func BenchmarkAnalyzeFile(b *testing.B) {
	src := `package main
func h(r *http.Request) {
	x := r.FormValue("y")
	_ = exec.Command("sh", x)
}
`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzeFile("h.go", "go", src)
	}
}
