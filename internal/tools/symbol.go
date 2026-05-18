// symbol.go adds higher-level inspection tools on top of the file sandbox:
//
//	read_symbol(file, name)  -> function/method body extracted via the AST index
//	find_callers(symbol)     -> incoming edges from the call graph
//	find_callees(symbol)     -> outgoing edges from the call graph
//	list_imports(file)       -> imports declared in a file
//
// These rely on optional indices wired by the host (Sandbox.SetIndex). When an
// index is not configured the tools degrade gracefully to a structured error so
// the deep agent can fall back to read_file/grep.
package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
)

// SymbolIndex bundles the read-only project indices the symbol tools need.
// Each field is optional; callers may set only what they have.
type SymbolIndex struct {
	// ASTs maps project-relative file paths to parsed ASTs.
	ASTs map[string]*ast.FileAST
	// CallGraph is the project-wide call graph (Symbol == byName key).
	CallGraph *callgraph.CallGraph
}

// SetIndex wires read-only indices into the sandbox. Safe to call once during
// pipeline setup. Subsequent calls replace the previous index.
func (s *Sandbox) SetIndex(idx *SymbolIndex) { s.Index = idx }

// Index lives on the Sandbox so dispatchers can reach it. Declared on the
// Sandbox in sandbox.go (Index field).

// ReadSymbol returns the source of a named function/method in `path`, with a
// short header listing receiver, kind, and line range. Falls back to ReadFile
// when the AST index isn't available or the symbol is not found.
func (s *Sandbox) ReadSymbol(path, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty symbol name")
	}
	abs, err := s.resolve(path)
	if err != nil {
		return "", err
	}
	rel := absRel(s.Root, abs)
	if s.Index == nil || s.Index.ASTs == nil {
		// Best-effort grep+read fallback.
		return s.symbolFallback(rel, name)
	}
	a := s.Index.ASTs[rel]
	if a == nil {
		// Some indexers store absolute paths.
		a = s.Index.ASTs[abs]
	}
	if a == nil {
		return s.symbolFallback(rel, name)
	}
	// Find the best matching symbol — exact name match wins; otherwise the
	// last symbol whose name suffix-matches (covers "Receiver.Method").
	bare := name
	if i := strings.LastIndexAny(name, ".:"); i >= 0 {
		bare = name[i+1:]
	}
	var matched *ast.Symbol
	for i := range a.Symbols {
		sym := &a.Symbols[i]
		if sym.Kind != "function" && sym.Kind != "method" {
			continue
		}
		if sym.Name == bare || sym.Name == name {
			matched = sym
			break
		}
	}
	if matched == nil {
		return s.symbolFallback(rel, name)
	}
	body, err := s.ReadFile(rel, matched.StartLine, matched.EndLine)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "// symbol %s (%s) in %s lines %d-%d\n",
		matched.Name, kindWithReceiver(matched), rel, matched.StartLine, matched.EndLine)
	buf.WriteString(body)
	return buf.String(), nil
}

// symbolFallback uses grep to find a line that looks like the definition, then
// returns ±60 lines. Always succeeds with text — never bubbles a grep error
// since the agent can decide based on the returned content.
func (s *Sandbox) symbolFallback(rel, name string) (string, error) {
	bare := name
	if i := strings.LastIndexAny(name, ".:"); i >= 0 {
		bare = name[i+1:]
	}
	// Try the file the agent asked for first.
	if rel != "" {
		pattern := fmt.Sprintf(`\b(func|def|fn|function)\b[^\n]*\b%s\b`, escapeRegex(bare))
		hits, _ := s.Grep(pattern, rel, 5)
		if line := firstHitLine(hits); line > 0 {
			start := line - 5
			if start < 1 {
				start = 1
			}
			body, _ := s.ReadFile(rel, start, line+80)
			return "// symbol fallback (no AST index)\n" + body, nil
		}
	}
	// Cross-repo fallback.
	pattern := fmt.Sprintf(`\b(func|def|fn|function)\b[^\n]*\b%s\b`, escapeRegex(bare))
	hits, _ := s.Grep(pattern, "", 5)
	if hits == "" {
		return "", fmt.Errorf("symbol %q not found", name)
	}
	return "// symbol candidates (no AST index)\n" + hits, nil
}

// FindCallers returns the call sites that invoke `name` (any matching node).
// Output is a small JSON document; when no call graph is wired the call falls
// back to grep for "name(" so the agent always gets something useful.
func (s *Sandbox) FindCallers(name string, maxHits int) (string, error) {
	if maxHits <= 0 {
		maxHits = 50
	}
	if name == "" {
		return "", fmt.Errorf("empty symbol name")
	}
	if s.Index == nil || s.Index.CallGraph == nil {
		return s.callsiteGrep(name, maxHits, "callers")
	}
	g := s.Index.CallGraph
	bare := lastSegment(name)
	type hit struct {
		Caller string `json:"caller"`
		File   string `json:"file"`
		Line   int    `json:"line"`
		To     string `json:"to"`
	}
	var hits []hit
	for _, id := range g.NodesByName(bare) {
		for _, e := range g.Callers(id) {
			fromNode := g.Nodes[e.From]
			if fromNode == nil {
				continue
			}
			toNode := g.Nodes[e.To]
			toName := bare
			if toNode != nil {
				toName = toNode.Func
			}
			hits = append(hits, hit{
				Caller: fromNode.Func,
				File:   fromNode.File,
				Line:   e.Line,
				To:     toName,
			})
			if len(hits) >= maxHits {
				break
			}
		}
		if len(hits) >= maxHits {
			break
		}
	}
	if len(hits) == 0 {
		// Symbol may live in a file we didn't parse; fall back.
		return s.callsiteGrep(name, maxHits, "callers")
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Line < hits[j].Line
	})
	out, _ := json.MarshalIndent(map[string]any{"symbol": name, "callers": hits}, "", "  ")
	return string(out), nil
}

// FindCallees returns the outgoing call edges from `name` — every function
// the symbol invokes, with file:line of the call site.
func (s *Sandbox) FindCallees(name string, maxHits int) (string, error) {
	if maxHits <= 0 {
		maxHits = 50
	}
	if name == "" {
		return "", fmt.Errorf("empty symbol name")
	}
	if s.Index == nil || s.Index.CallGraph == nil {
		return s.callsiteGrep(name, maxHits, "callees")
	}
	g := s.Index.CallGraph
	bare := lastSegment(name)
	type hit struct {
		From string `json:"from"`
		File string `json:"file"`
		Line int    `json:"line"`
		To   string `json:"to"`
	}
	var hits []hit
	for _, id := range g.NodesByName(bare) {
		fromNode := g.Nodes[id]
		fromName := bare
		if fromNode != nil {
			fromName = fromNode.Func
		}
		for _, e := range g.Callees(id) {
			toNode := g.Nodes[e.To]
			toName := ""
			fileName := ""
			if toNode != nil {
				toName = toNode.Func
				fileName = toNode.File
			}
			hits = append(hits, hit{
				From: fromName,
				File: fileName,
				Line: e.Line,
				To:   toName,
			})
			if len(hits) >= maxHits {
				break
			}
		}
		if len(hits) >= maxHits {
			break
		}
	}
	if len(hits) == 0 {
		return s.callsiteGrep(name, maxHits, "callees")
	}
	out, _ := json.MarshalIndent(map[string]any{"symbol": name, "callees": hits}, "", "  ")
	return string(out), nil
}

// ListImports returns the imports declared in `path` (one per line).
func (s *Sandbox) ListImports(path string) (string, error) {
	abs, err := s.resolve(path)
	if err != nil {
		return "", err
	}
	rel := absRel(s.Root, abs)
	if s.Index != nil && s.Index.ASTs != nil {
		a := s.Index.ASTs[rel]
		if a == nil {
			a = s.Index.ASTs[abs]
		}
		if a != nil {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "// imports of %s (%d)\n", rel, len(a.Imports))
			for _, im := range a.Imports {
				if im.Alias != "" {
					fmt.Fprintf(&buf, "  %s  %s as %s\n", padInt(im.Line, 4), im.Path, im.Alias)
				} else {
					fmt.Fprintf(&buf, "  %s  %s\n", padInt(im.Line, 4), im.Path)
				}
			}
			return buf.String(), nil
		}
	}
	// Fallback: regex grep first 200 lines.
	body, err := s.ReadFile(rel, 1, 200)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "// imports fallback (no AST index)\n")
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "from ") ||
			strings.HasPrefix(t, "use ") || strings.HasPrefix(t, "require ") ||
			strings.HasPrefix(t, "#include ") {
			buf.WriteString(ln + "\n")
		}
	}
	return buf.String(), nil
}

// callsiteGrep is the call-graph-less fallback for FindCallers / FindCallees.
func (s *Sandbox) callsiteGrep(name string, maxHits int, mode string) (string, error) {
	bare := lastSegment(name)
	pattern := fmt.Sprintf(`\b%s\s*\(`, escapeRegex(bare))
	hits, err := s.Grep(pattern, "", maxHits)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("// %s fallback (no call graph) for %q\n%s", mode, name, hits), nil
}

// ---- helpers ----

func absRel(root, abs string) string {
	if !strings.HasPrefix(abs, root) {
		return abs
	}
	r := strings.TrimPrefix(abs, root)
	r = strings.TrimPrefix(r, "/")
	return r
}

func kindWithReceiver(s *ast.Symbol) string {
	if s.Receiver != "" {
		return s.Kind + " on " + s.Receiver
	}
	return s.Kind
}

func lastSegment(s string) string {
	if i := strings.LastIndexAny(s, ".:->"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func escapeRegex(s string) string {
	const special = `\.+*?()|[]{}^$`
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(special, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func firstHitLine(grepOutput string) int {
	for _, ln := range strings.Split(grepOutput, "\n") {
		if strings.HasPrefix(ln, "//") || ln == "" {
			continue
		}
		// "path:line:  text" — extract the middle integer.
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) < 2 {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(parts[1], "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func padInt(n, w int) string {
	s := fmt.Sprintf("%d", n)
	for len(s) < w {
		s = " " + s
	}
	return s
}
