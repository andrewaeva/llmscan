// Package callgraph builds a best-effort, language-agnostic call graph from
// parsed file ASTs and a file-level dependency graph.
//
// The graph operates at the granularity of (file, symbol) — each declared
// function/method becomes a Node. Edges connect a caller node to a callee node
// at a specific source line. Resolution is best-effort: when a call name is
// ambiguous we add edges to every plausible candidate (we prefer false-positive
// edges over missing them for downstream taint propagation).
//
// This package never inspects file contents beyond what is already extracted
// in ast.FileAST. It is pure-Go and CGO-free.
package callgraph

import (
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/depgraph"
)

// NodeID is a stable identifier for a function/method node in the graph.
// Format: "<file>::<name>" (no receiver in id; receiver kept on the Node).
type NodeID string

// Node is one function/method in one file.
type Node struct {
	ID     NodeID      `json:"id"`
	File   string      `json:"file"`
	Func   string      `json:"func"`
	Symbol *ast.Symbol `json:"-"`
}

// Edge is a call from caller to callee at a specific line in the caller's body.
type Edge struct {
	From NodeID `json:"from"`
	To   NodeID `json:"to"`
	Line int    `json:"line"`
}

// CallGraph holds every node and every edge.
type CallGraph struct {
	Nodes map[NodeID]*Node
	// adjacency lists, both directions
	out map[NodeID][]Edge
	in  map[NodeID][]Edge
	// auxiliary indices for resolution
	byName  map[string][]NodeID // function name -> nodes
	byFile  map[string][]NodeID // file -> nodes
	byPath  map[string]*Node    // "<file>::<name>" lookup
	allEdge []Edge
}

// IDOf returns the canonical NodeID for a function inside file.
func IDOf(file, fn string) NodeID {
	return NodeID(file + "::" + fn)
}

// Build constructs the call graph from parsed ASTs and the depgraph.
//
// Resolution strategy for a call site c in file F:
//  1. Try same-file match (priority): a Symbol with Name == c.Callee.
//  2. If c.Callee looks like "pkg.Name" or "obj.Name", strip the prefix and
//     look in imported files (per the depgraph), then everywhere as a fallback.
//  3. If still ambiguous, edges to all candidates are added.
func Build(files []*ast.FileAST, deps *depgraph.Graph) *CallGraph {
	g := &CallGraph{
		Nodes:  map[NodeID]*Node{},
		out:    map[NodeID][]Edge{},
		in:     map[NodeID][]Edge{},
		byName: map[string][]NodeID{},
		byFile: map[string][]NodeID{},
		byPath: map[string]*Node{},
	}
	// 1) Add all symbols as nodes.
	for _, f := range files {
		if f == nil {
			continue
		}
		for i := range f.Symbols {
			s := &f.Symbols[i]
			if s.Kind != "function" && s.Kind != "method" {
				continue
			}
			id := IDOf(f.Path, s.Name)
			n := &Node{ID: id, File: f.Path, Func: s.Name, Symbol: s}
			// If the same id already exists (overloads, methods with same name on
			// different receivers within one file), keep the first; build a
			// secondary entry under a receiver-qualified id so we don't lose it.
			if _, ok := g.Nodes[id]; ok {
				if s.Receiver != "" {
					altID := IDOf(f.Path, recvShort(s.Receiver)+"."+s.Name)
					n.ID = altID
					g.Nodes[altID] = n
					g.byPath[string(altID)] = n
					g.byName[s.Name] = append(g.byName[s.Name], altID)
					g.byFile[f.Path] = append(g.byFile[f.Path], altID)
				}
				continue
			}
			g.Nodes[id] = n
			g.byPath[string(id)] = n
			g.byName[s.Name] = append(g.byName[s.Name], id)
			g.byFile[f.Path] = append(g.byFile[f.Path], id)
		}
	}

	// 2) Resolve calls. For each call in a file, find its caller node by line
	// containment and add an edge to every plausible callee.
	for _, f := range files {
		if f == nil {
			continue
		}
		callerNodes := g.byFile[f.Path]
		for _, c := range f.Calls {
			caller := findContainingNode(f, callerNodes, g, c.Line)
			if caller == "" {
				continue
			}
			candidates := g.resolveCall(f, deps, c.Callee)
			for _, callee := range candidates {
				if callee == caller {
					continue // self-recursion is fine; keep it but bound dedup
				}
				e := Edge{From: caller, To: callee, Line: c.Line}
				g.out[caller] = append(g.out[caller], e)
				g.in[callee] = append(g.in[callee], e)
				g.allEdge = append(g.allEdge, e)
			}
		}
	}
	return g
}

// recvShort returns a short receiver type name for "(s *Service)" -> "Service".
func recvShort(r string) string {
	r = strings.TrimSpace(r)
	r = strings.Trim(r, "()")
	parts := strings.Fields(r)
	if len(parts) == 0 {
		return ""
	}
	t := parts[len(parts)-1]
	t = strings.TrimPrefix(t, "*")
	if dot := strings.LastIndex(t, "."); dot >= 0 {
		t = t[dot+1:]
	}
	return t
}

func findContainingNode(f *ast.FileAST, nodeIDs []NodeID, g *CallGraph, line int) NodeID {
	var best NodeID
	bestLen := 0
	for _, id := range nodeIDs {
		n := g.Nodes[id]
		if n == nil || n.Symbol == nil {
			continue
		}
		s := n.Symbol
		if s.StartLine <= line && line <= s.EndLine {
			l := s.EndLine - s.StartLine
			if best == "" || l < bestLen {
				best = id
				bestLen = l
			}
		}
	}
	_ = f
	return best
}

// resolveCall returns plausible callee NodeIDs for a textual callee expression.
//
//nolint:gocyclo // straight-line resolver with several fallback strategies
func (g *CallGraph) resolveCall(from *ast.FileAST, deps *depgraph.Graph, callee string) []NodeID {
	name := simpleCalleeName(callee)
	if name == "" {
		return nil
	}
	var out []NodeID
	seen := map[NodeID]bool{}
	add := func(ids []NodeID) {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}

	// 1) Same-file candidates have priority.
	if from != nil {
		for _, id := range g.byFile[from.Path] {
			n := g.Nodes[id]
			if n != nil && n.Func == name {
				add([]NodeID{id})
			}
		}
	}

	// 2) Cross-file via depgraph (imported files).
	if deps != nil && from != nil {
		for _, imp := range deps.Out(relTo(deps, from.Path)) {
			// imp can be a file id (rel path) or "ext:...".
			if strings.HasPrefix(imp, "ext:") {
				continue
			}
			absImp := absOf(deps, imp)
			if absImp == "" {
				continue
			}
			for _, id := range g.byFile[absImp] {
				n := g.Nodes[id]
				if n != nil && n.Func == name {
					add([]NodeID{id})
				}
			}
		}
	}

	// 3) Global fallback by name.
	if len(out) == 0 {
		add(g.byName[name])
	}
	return out
}

// relTo replays depgraph's relTo without importing internals (best-effort).
func relTo(g *depgraph.Graph, p string) string {
	if g == nil {
		return p
	}
	// Reverse search: depgraph.Nodes has IDs that are rel paths and Path == absolute.
	for id, n := range g.Nodes {
		if n.IsFile && n.Path == p {
			return id
		}
	}
	return p
}

func absOf(g *depgraph.Graph, id string) string {
	if g == nil {
		return ""
	}
	if n, ok := g.Nodes[id]; ok && n.IsFile {
		return n.Path
	}
	return ""
}

// SimpleCalleeName is the exported variant of simpleCalleeName.
func SimpleCalleeName(callee string) string { return simpleCalleeName(callee) }

// LookupByName returns plausible NodeIDs for a function name, preferring nodes
// in `fromFile` first and then nodes anywhere else with that name.
func (g *CallGraph) LookupByName(fromFile, name string) []NodeID {
	seen := map[NodeID]bool{}
	var out []NodeID
	for _, id := range g.byFile[fromFile] {
		n := g.Nodes[id]
		if n != nil && n.Func == name && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range g.byName[name] {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// simpleCalleeName strips package/receiver prefixes from a callee expression
// and returns the trailing identifier. "fmt.Println" -> "Println";
// "db.Exec" -> "Exec"; "this.foo.bar" -> "bar"; "f" -> "f".
func simpleCalleeName(callee string) string {
	callee = strings.TrimSpace(callee)
	// remove generic instantiations: "Foo[int]" -> "Foo"
	if i := strings.IndexByte(callee, '['); i >= 0 {
		callee = callee[:i]
	}
	// trailing parens (shouldn't be present but be safe)
	if i := strings.IndexByte(callee, '('); i >= 0 {
		callee = callee[:i]
	}
	if i := strings.LastIndexAny(callee, ".:->"); i >= 0 {
		callee = callee[i+1:]
	}
	return callee
}

// Callers returns incoming edges (who calls id).
func (g *CallGraph) Callers(id NodeID) []Edge {
	return append([]Edge(nil), g.in[id]...)
}

// Callees returns outgoing edges (who id calls).
func (g *CallGraph) Callees(id NodeID) []Edge {
	return append([]Edge(nil), g.out[id]...)
}

// Edges returns a copy of all edges.
func (g *CallGraph) Edges() []Edge {
	return append([]Edge(nil), g.allEdge...)
}

// Entrypoints heuristically returns nodes with no incoming edges. Real entry
// detection (HTTP/CLI/gRPC) lives in the entrypoints package.
func (g *CallGraph) Entrypoints() []NodeID {
	var out []NodeID
	for id := range g.Nodes {
		if len(g.in[id]) == 0 {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Reachable returns the set of nodes reachable from `from` via forward BFS
// over outgoing edges.
func (g *CallGraph) Reachable(from NodeID) map[NodeID]bool {
	seen := map[NodeID]bool{from: true}
	q := []NodeID{from}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		for _, e := range g.out[cur] {
			if !seen[e.To] {
				seen[e.To] = true
				q = append(q, e.To)
			}
		}
	}
	return seen
}

// ReachableFromAny unions Reachable over a set of starting nodes.
func (g *CallGraph) ReachableFromAny(set []NodeID) map[NodeID]bool {
	out := map[NodeID]bool{}
	for _, s := range set {
		for k := range g.Reachable(s) {
			out[k] = true
		}
	}
	return out
}

// FindNodeAtLine returns the most specific node enclosing (file, line).
func (g *CallGraph) FindNodeAtLine(file string, line int) *Node {
	var best *Node
	bestLen := 0
	for _, id := range g.byFile[file] {
		n := g.Nodes[id]
		if n == nil || n.Symbol == nil {
			continue
		}
		if n.Symbol.StartLine <= line && line <= n.Symbol.EndLine {
			l := n.Symbol.EndLine - n.Symbol.StartLine
			if best == nil || l < bestLen {
				best = n
				bestLen = l
			}
		}
	}
	return best
}

// DOT returns a Graphviz-friendly textual representation. Useful for --show-callgraph.
func (g *CallGraph) DOT() string {
	var sb strings.Builder
	sb.WriteString("digraph callgraph {\n")
	sb.WriteString("  rankdir=LR;\n  node [shape=box,fontsize=10];\n")
	ids := make([]NodeID, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		n := g.Nodes[id]
		label := strings.ReplaceAll(string(id), `"`, `\"`)
		sb.WriteString(`  "` + label + `" [label="` + n.Func + `\n` + n.File + `"];` + "\n")
	}
	for _, e := range g.allEdge {
		sb.WriteString(`  "` + string(e.From) + `" -> "` + string(e.To) + `";` + "\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}
