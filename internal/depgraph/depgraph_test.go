package depgraph

import (
	"sort"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/ast"
)

// mkFile is a tiny helper to construct ast.FileAST without invoking the
// real parser. depgraph only reads Path/Language/Imports — Symbols/Calls
// are not used for graph building.
func mkFile(path, lang string, imports ...string) *ast.FileAST {
	imps := make([]ast.Import, 0, len(imports))
	for _, p := range imports {
		imps = append(imps, ast.Import{Path: p, Line: 1})
	}
	return &ast.FileAST{
		Path:     path,
		Language: ast.Language(lang),
		Imports:  imps,
	}
}

func TestNew_EmptyProject(t *testing.T) {
	g := New("/proj", nil)
	if g == nil {
		t.Fatal("nil graph")
	}
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Errorf("empty project should have no nodes/edges, got %d/%d",
			len(g.Nodes), len(g.Edges))
	}
}

func TestNew_FilesBecomeNodes(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go"),
		mkFile("/proj/b.go", "go"),
	})
	if len(g.Nodes) < 2 {
		t.Errorf("got %d nodes, want at least 2", len(g.Nodes))
	}
	// Both files should appear as file nodes.
	gotFiles := 0
	for _, n := range g.Nodes {
		if n.IsFile {
			gotFiles++
		}
	}
	if gotFiles != 2 {
		t.Errorf("got %d file nodes, want 2", gotFiles)
	}
}

func TestRelativeImportResolves(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/main.py", "python", "./util"),
		mkFile("/proj/util.py", "python"),
	})
	// main.py → util.py edge should exist.
	found := false
	for _, e := range g.Edges {
		if strings.HasSuffix(e.From, "main.py") && strings.HasSuffix(e.To, "util.py") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected main.py -> util.py edge, got edges: %v", g.Edges)
	}
}

func TestExternalImportBecomesExtNode(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/app.js", "javascript", "lodash", "express"),
	})
	hasExt := false
	for id, n := range g.Nodes {
		if strings.HasPrefix(id, "ext:") {
			hasExt = true
			if n.IsFile {
				t.Errorf("ext node %q marked IsFile=true", id)
			}
		}
	}
	if !hasExt {
		t.Error("expected at least one ext: node for unresolved imports")
	}
}

func TestHasCycle_Acyclic(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./b"),
		mkFile("/proj/b.go", "go", "./c"),
		mkFile("/proj/c.go", "go"),
	})
	if g.HasCycle() {
		t.Error("acyclic graph reported cycle")
	}
}

func TestHasCycle_TwoNodeCycle(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./b"),
		mkFile("/proj/b.go", "go", "./a"),
	})
	if !g.HasCycle() {
		t.Error("a↔b cycle not detected")
	}
}

func TestHasCycle_LongerCycle(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./b"),
		mkFile("/proj/b.go", "go", "./c"),
		mkFile("/proj/c.go", "go", "./a"),
	})
	if !g.HasCycle() {
		t.Error("a→b→c→a cycle not detected")
	}
}

func TestNeighbors_DepthLimit(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./b"),
		mkFile("/proj/b.go", "go", "./c"),
		mkFile("/proj/c.go", "go", "./d"),
		mkFile("/proj/d.go", "go"),
	})
	// Find a's id.
	var aID string
	for id, n := range g.Nodes {
		if n.IsFile && strings.HasSuffix(id, "a.go") {
			aID = id
			break
		}
	}
	if aID == "" {
		t.Fatal("a.go node not found")
	}
	n1 := g.Neighbors(aID, 1)
	n2 := g.Neighbors(aID, 2)
	if len(n1) > len(n2) {
		t.Errorf("depth=1 returned more than depth=2: %d vs %d", len(n1), len(n2))
	}
	if len(n2) == 0 {
		t.Error("depth=2 should reach at least one node")
	}
}

func TestTopRankedByFanIn(t *testing.T) {
	// b is imported by a, c, d → highest fan-in.
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./b"),
		mkFile("/proj/c.go", "go", "./b"),
		mkFile("/proj/d.go", "go", "./b"),
		mkFile("/proj/b.go", "go"),
	})
	top := g.TopRankedByFanIn()
	if len(top) == 0 {
		t.Fatal("expected at least one node")
	}
	if !strings.HasSuffix(top[0], "b.go") {
		t.Errorf("top-ranked = %q, want b.go", top[0])
	}
}

func TestAsFileMap(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./b"),
		mkFile("/proj/b.go", "go"),
	})
	m := g.AsFileMap()
	if len(m) == 0 {
		t.Fatal("AsFileMap empty")
	}
	// Look for a.go and verify it lists b.go.
	for path, deps := range m {
		if strings.HasSuffix(path, "a.go") {
			ok := false
			for _, d := range deps {
				if strings.HasSuffix(d, "b.go") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("a.go deps should include b.go, got %v", deps)
			}
		}
	}
}

func TestCallersByFile(t *testing.T) {
	g := New("/proj", []*ast.FileAST{
		mkFile("/proj/a.go", "go", "./util"),
		mkFile("/proj/b.go", "go", "./util"),
		mkFile("/proj/util.go", "go"),
	})
	m := g.CallersByFile()
	for path, callers := range m {
		if strings.HasSuffix(path, "util.go") {
			sort.Strings(callers)
			if len(callers) != 2 {
				t.Errorf("util.go should have 2 callers, got %v", callers)
			}
			return
		}
	}
	t.Error("util.go not in CallersByFile")
}

func TestNew_DoesNotPanicOnNilFileAST(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("New panicked on nil file: %v", r)
		}
	}()
	_ = New("/proj", []*ast.FileAST{nil})
}
