// Package depgraph builds a module/file dependency graph from parsed ASTs.
//
// Edges are best-effort: imports are resolved to real files when possible
// (relative paths and shared roots), otherwise we keep an external module node.
package depgraph

import (
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
)

// Node is a file or an external module.
type Node struct {
	ID       string `json:"id"`      // canonical id: file path (relative to root) or "ext:lodash"
	IsFile   bool   `json:"is_file"` // true if it is a file in the project
	Language string `json:"language,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Edge: A -> B means "A imports B".
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Symbol string `json:"symbol,omitempty"` // unused for now; placeholder for symbol-level edges
}

// Graph is the dependency graph for a project.
type Graph struct {
	Root  string           `json:"root"`
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge           `json:"edges"`

	out map[string][]string // adjacency: from -> []to
	in  map[string][]string // reverse adjacency
}

// New builds the graph from a slice of parsed ASTs and a project root.
func New(root string, files []*ast.FileAST) *Graph {
	g := &Graph{
		Root:  root,
		Nodes: map[string]*Node{},
		out:   map[string][]string{},
		in:    map[string][]string{},
	}
	// Index files: relpath -> *FileAST. Skip nil entries — callers may pass
	// a parsed slice that contains nil for files whose parse failed.
	byRel := map[string]*ast.FileAST{}
	for _, f := range files {
		if f == nil {
			continue
		}
		rel := relTo(root, f.Path)
		byRel[rel] = f
		g.Nodes[rel] = &Node{ID: rel, IsFile: true, Language: string(f.Language), Path: f.Path}
	}
	// Index by basename and module-like keys to resolve non-relative imports.
	byBase := map[string][]string{}
	byNoExt := map[string]string{}
	for rel := range byRel {
		base := strings.ToLower(filepath.Base(rel))
		byBase[base] = append(byBase[base], rel)
		noExt := strings.ToLower(strings.TrimSuffix(rel, filepath.Ext(rel)))
		byNoExt[noExt] = rel
	}
	for rel, f := range byRel {
		for _, imp := range f.Imports {
			target, isFile := g.resolveImport(rel, imp.Path, byRel, byBase, byNoExt)
			if target == "" {
				continue
			}
			if !isFile {
				if _, ok := g.Nodes[target]; !ok {
					g.Nodes[target] = &Node{ID: target, IsFile: false}
				}
			}
			g.Edges = append(g.Edges, Edge{From: rel, To: target})
			g.out[rel] = append(g.out[rel], target)
			g.in[target] = append(g.in[target], rel)
		}
	}
	return g
}

func relTo(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(p)
}

// resolveImport attempts to map an import path to a project file. Returns (id, isFile).
func (g *Graph) resolveImport(fromRel, imp string, byRel map[string]*ast.FileAST, byBase map[string][]string, byNoExt map[string]string) (string, bool) {
	imp = strings.TrimSpace(imp)
	if imp == "" {
		return "", false
	}
	// Relative import: ./foo, ../bar/baz
	if strings.HasPrefix(imp, ".") {
		dir := path.Dir(fromRel)
		cand := path.Clean(path.Join(dir, imp))
		// try with several extensions and as a directory index
		for _, ext := range []string{"", ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".java"} {
			key := strings.ToLower(cand + ext)
			if rel, ok := byNoExt[key]; ok {
				return rel, true
			}
		}
		for _, idx := range []string{"index.js", "index.ts", "__init__.py"} {
			if _, ok := byRel[path.Join(cand, idx)]; ok {
				return path.Join(cand, idx), true
			}
		}
		// no luck — leave as external for visibility
		return "ext:" + imp, false
	}
	// Absolute import paths: try as a project path first.
	for _, ext := range []string{"", ".go", ".py", ".js", ".ts", ".java"} {
		key := strings.ToLower(strings.ReplaceAll(imp, ".", "/") + ext)
		if rel, ok := byNoExt[key]; ok {
			return rel, true
		}
		key2 := strings.ToLower(imp + ext)
		if rel, ok := byNoExt[key2]; ok {
			return rel, true
		}
	}
	// Fallback by last segment.
	last := imp
	if i := strings.LastIndexAny(imp, "/."); i >= 0 {
		last = imp[i+1:]
	}
	if cands := byBase[strings.ToLower(last+".py")]; len(cands) == 1 {
		return cands[0], true
	}
	if cands := byBase[strings.ToLower(last+".go")]; len(cands) == 1 {
		return cands[0], true
	}
	return "ext:" + imp, false
}

// Out returns IDs imported by `id`.
func (g *Graph) Out(id string) []string {
	return append([]string(nil), g.out[id]...)
}

// In returns IDs that import `id`.
func (g *Graph) In(id string) []string {
	return append([]string(nil), g.in[id]...)
}

// Neighbors returns out-neighbors up to `depth` hops, deduplicated.
func (g *Graph) Neighbors(id string, depth int) []string {
	seen := map[string]bool{id: true}
	frontier := []string{id}
	for d := 0; d < depth && len(frontier) > 0; d++ {
		next := []string{}
		for _, n := range frontier {
			for _, m := range g.out[n] {
				if !seen[m] {
					seen[m] = true
					next = append(next, m)
				}
			}
		}
		frontier = next
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		if k != id {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TopRankedByFanIn returns IDs ordered by number of incoming edges (most-depended-on first).
// Useful for prioritization: code many things import has the largest blast radius.
func (g *Graph) TopRankedByFanIn() []string {
	type kv struct {
		id    string
		score int
	}
	items := make([]kv, 0, len(g.Nodes))
	for id, n := range g.Nodes {
		if !n.IsFile {
			continue
		}
		items = append(items, kv{id, len(g.in[id])})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].score > items[j].score })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.id
	}
	return out
}

// HasCycle reports whether the file-induced subgraph contains a cycle. External
// nodes are ignored. The DAG validator uses this on the agent layer graph, but
// the same primitive is useful for sanity checks on the code graph.
// AsFileMap returns absolute path -> []absolute paths of direct dependencies.
func (g *Graph) AsFileMap() map[string][]string {
	out := map[string][]string{}
	for from, tos := range g.out {
		fromAbs := g.absOf(from)
		for _, to := range tos {
			toAbs := g.absOf(to)
			if fromAbs == "" || toAbs == "" {
				continue
			}
			out[fromAbs] = append(out[fromAbs], toAbs)
		}
	}
	return out
}

// CallersByFile returns abs path -> []abs paths of files that import it.
func (g *Graph) CallersByFile() map[string][]string {
	out := map[string][]string{}
	for to, froms := range g.in {
		toAbs := g.absOf(to)
		for _, from := range froms {
			fromAbs := g.absOf(from)
			if fromAbs == "" || toAbs == "" {
				continue
			}
			out[toAbs] = append(out[toAbs], fromAbs)
		}
	}
	return out
}

func (g *Graph) absOf(id string) string {
	if n, ok := g.Nodes[id]; ok && n.IsFile {
		return n.Path
	}
	return ""
}

func (g *Graph) HasCycle() bool {
	color := map[string]int{} // 0=white, 1=gray, 2=black
	var dfs func(string) bool
	dfs = func(n string) bool {
		switch color[n] {
		case 1:
			return true
		case 2:
			return false
		}
		color[n] = 1
		for _, m := range g.out[n] {
			if !g.Nodes[m].IsFile {
				continue
			}
			if dfs(m) {
				return true
			}
		}
		color[n] = 2
		return false
	}
	for id, n := range g.Nodes {
		if !n.IsFile {
			continue
		}
		if dfs(id) {
			return true
		}
	}
	return false
}
