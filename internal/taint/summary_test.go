package taint

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
)

func parse(t *testing.T, p, src string) *ast.FileAST {
	t.Helper()
	a, err := ast.Parse(context.Background(), p, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", p, err)
	}
	return a
}

func TestExtractParams(t *testing.T) {
	cases := []struct {
		lang string
		sig  string
		want []string
	}{
		{"go", "func A(x string, y int)", []string{"x", "y"}},
		{"go", "func (s *Service) Do(ctx context.Context, q string) error", []string{"ctx", "q"}},
		{"python", "def view(req, id):", []string{"req", "id"}},
		{"python", "def get_item(id: int = 0):", []string{"id"}},
		{"javascript", "function handler(req, res)", []string{"req", "res"}},
		{"typescript", "function handler(req: Request, res: Response)", []string{"req", "res"}},
		{"java", "public String get(@RequestParam String q, int id)", []string{"q", "id"}},
	}
	for _, c := range cases {
		got := extractParams(c.lang, c.sig)
		if len(got) != len(c.want) {
			t.Errorf("extractParams(%q, %q) = %v, want %v", c.lang, c.sig, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("extractParams(%q, %q)[%d] = %q, want %q", c.lang, c.sig, i, got[i], c.want[i])
			}
		}
	}
}

func TestBuildSummaries_DirectSink(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "a.go"), `package x

func A(x string) {
	db.Exec(x)
}
`)
	g := depgraph.New(dir, []*ast.FileAST{a})
	cg := callgraph.Build([]*ast.FileAST{a}, g)
	sums := BuildSummaries([]*ast.FileAST{a}, cg)
	if len(sums) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(sums))
	}
	for _, s := range sums {
		if len(s.Params) != 1 || s.Params[0].ParamName != "x" {
			t.Fatalf("params not extracted: %+v", s.Params)
		}
		if len(s.Params[0].FlowsTo) == 0 {
			t.Fatalf("expected x -> db.Exec FlowsTo, got %+v", s.Params[0])
		}
		if s.Params[0].FlowsTo[0].Kind != "sql" {
			t.Fatalf("expected sql category, got %s", s.Params[0].FlowsTo[0].Kind)
		}
	}
}

func TestBuildSummaries_Sanitized(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "a.go"), `package x

func B(x string) {
	y := strconv.Atoi(x)
	db.Exec(y)
}
`)
	g := depgraph.New(dir, []*ast.FileAST{a})
	cg := callgraph.Build([]*ast.FileAST{a}, g)
	sums := BuildSummaries([]*ast.FileAST{a}, cg)
	for _, s := range sums {
		if len(s.Params[0].Sanitized) == 0 {
			t.Fatalf("expected Sanitized non-empty: %+v", s.Params[0])
		}
	}
}

func TestBuildSummaries_ReturnTaint(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "a.go"), `package x

func C(x string) string {
	return x
}
`)
	g := depgraph.New(dir, []*ast.FileAST{a})
	cg := callgraph.Build([]*ast.FileAST{a}, g)
	sums := BuildSummaries([]*ast.FileAST{a}, cg)
	for _, s := range sums {
		if !s.Params[0].ReturnedTaint {
			t.Fatalf("expected ReturnedTaint=true")
		}
	}
}

func TestBuildSummaries_CallSiteFlow(t *testing.T) {
	dir := t.TempDir()
	a := parse(t, filepath.Join(dir, "a.go"), `package x

func D(x string) {
	helper(x)
}
func helper(s string) {
	exec.Command(s)
}
`)
	g := depgraph.New(dir, []*ast.FileAST{a})
	cg := callgraph.Build([]*ast.FileAST{a}, g)
	sums := BuildSummaries([]*ast.FileAST{a}, cg)
	var d *FunctionSummary
	for _, s := range sums {
		if s.Func == "D" {
			d = s
		}
	}
	if d == nil {
		t.Fatalf("D summary missing")
	}
	if len(d.InterCalls) == 0 {
		t.Fatalf("expected at least one inter-call from D")
	}
	found := false
	for _, c := range d.InterCalls {
		for _, idx := range c.ArgParamIdx {
			if idx == 0 {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected D's call to forward param 0; got %+v", d.InterCalls)
	}
}
