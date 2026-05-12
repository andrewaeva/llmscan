package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
)

func newSandboxAt(t *testing.T, files map[string]string) *Sandbox {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewSandbox(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReadSymbolWithIndex(t *testing.T) {
	src := "package main\n\nfunc helper() int { return 1 }\n\nfunc Login(u string) bool {\n\treturn helper() == 1\n}\n"
	s := newSandboxAt(t, map[string]string{"x.go": src})
	a := &ast.FileAST{
		Path:     "x.go",
		Language: ast.LangGo,
		Symbols: []ast.Symbol{
			{Kind: "function", Name: "helper", StartLine: 3, EndLine: 3},
			{Kind: "function", Name: "Login", StartLine: 5, EndLine: 7},
		},
	}
	s.SetIndex(&SymbolIndex{ASTs: map[string]*ast.FileAST{"x.go": a}})
	out, err := s.ReadSymbol("x.go", "Login")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "func Login(u string) bool") {
		t.Errorf("ReadSymbol missed body: %q", out)
	}
	if !strings.Contains(out, "symbol Login") {
		t.Errorf("ReadSymbol missing header: %q", out)
	}
}

func TestReadSymbolFallback(t *testing.T) {
	src := "package main\n\nfunc Login() {}\n"
	s := newSandboxAt(t, map[string]string{"x.go": src})
	out, err := s.ReadSymbol("x.go", "Login")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Login") {
		t.Errorf("fallback should at least cite Login: %q", out)
	}
}

func TestFindCallersWithGraph(t *testing.T) {
	// Two files: caller.go calls Target() defined in target.go.
	files := []*ast.FileAST{
		{
			Path:     "target.go",
			Language: ast.LangGo,
			Symbols:  []ast.Symbol{{Kind: "function", Name: "Target", StartLine: 1, EndLine: 3}},
		},
		{
			Path:     "caller.go",
			Language: ast.LangGo,
			Symbols:  []ast.Symbol{{Kind: "function", Name: "Caller", StartLine: 1, EndLine: 5}},
			Calls:    []ast.Call{{Callee: "Target", Line: 3}},
		},
	}
	cg := callgraph.Build(files, &depgraph.Graph{})

	s := newSandboxAt(t, map[string]string{"target.go": "x", "caller.go": "x"})
	s.SetIndex(&SymbolIndex{CallGraph: cg})

	out, err := s.FindCallers("Target", 10)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	callers, _ := parsed["callers"].([]any)
	if len(callers) == 0 {
		t.Fatalf("expected at least one caller of Target, got %s", out)
	}
}

func TestFindCalleesFallbackGrep(t *testing.T) {
	src := "package main\n\nfunc main() {\n  helper()\n  helper2()\n}\n"
	s := newSandboxAt(t, map[string]string{"x.go": src})
	out, err := s.FindCallees("main", 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "fallback") {
		t.Errorf("expected grep fallback marker, got: %q", out)
	}
}

func TestListImportsWithAST(t *testing.T) {
	src := "package main\n\nimport \"fmt\"\nimport \"os\"\n"
	a := &ast.FileAST{
		Path:     "x.go",
		Language: ast.LangGo,
		Imports: []ast.Import{
			{Path: "fmt", Line: 3},
			{Path: "os", Line: 4},
		},
	}
	s := newSandboxAt(t, map[string]string{"x.go": src})
	s.SetIndex(&SymbolIndex{ASTs: map[string]*ast.FileAST{"x.go": a}})
	out, err := s.ListImports("x.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "fmt") || !strings.Contains(out, "os") {
		t.Errorf("missing imports: %q", out)
	}
}
