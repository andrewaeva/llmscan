package contextpack

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/tokens"
	"github.com/andrewaeva/llmscan/internal/types"
)

// rag.Index is used via the embedded Builder.RAG field; the type itself is
// referenced through that field so an explicit import is unnecessary here.

// -- callees ----------------------------------------------------------------

// collectCallees walks the call graph outward from every function in chunk up
// to CalleesHops, returning each unique callee as a Fragment with priority
// proportional to its hop distance.
func (b *Builder) collectCallees(c types.FileTarget) []Fragment {
	if b.CG == nil || b.Cfg.CalleesHops == 0 {
		return nil
	}
	seeds := b.nodesInChunk(c)
	if len(seeds) == 0 {
		return nil
	}
	type item struct {
		id   callgraph.NodeID
		dist int
	}
	visited := map[callgraph.NodeID]int{}
	for _, s := range seeds {
		visited[s] = 0
	}
	q := make([]item, 0, len(seeds))
	for _, s := range seeds {
		q = append(q, item{s, 0})
	}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.dist >= b.Cfg.CalleesHops {
			continue
		}
		for _, e := range b.CG.Callees(cur.id) {
			if _, ok := visited[e.To]; ok {
				continue
			}
			visited[e.To] = cur.dist + 1
			q = append(q, item{e.To, cur.dist + 1})
		}
	}
	out := make([]Fragment, 0, len(visited))
	for id, dist := range visited {
		if dist == 0 {
			continue // seeds are inside the chunk
		}
		n := b.CG.Nodes[id]
		if n == nil || n.Symbol == nil {
			continue
		}
		frag, ok := b.symbolFragment(n.File, *n.Symbol, KindCallee,
			fmt.Sprintf("called %d hop(s) from chunk", dist), dist)
		if !ok {
			continue
		}
		out = append(out, frag)
	}
	return b.cap(out, b.Cfg.CalleesMax)
}

// -- callers ----------------------------------------------------------------

func (b *Builder) collectCallers(c types.FileTarget) []Fragment {
	if b.CG == nil || b.Cfg.CallersHops == 0 {
		return nil
	}
	seeds := b.nodesInChunk(c)
	if len(seeds) == 0 {
		return nil
	}
	type item struct {
		id   callgraph.NodeID
		dist int
	}
	visited := map[callgraph.NodeID]int{}
	for _, s := range seeds {
		visited[s] = 0
	}
	q := make([]item, 0, len(seeds))
	for _, s := range seeds {
		q = append(q, item{s, 0})
	}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.dist >= b.Cfg.CallersHops {
			continue
		}
		for _, e := range b.CG.Callers(cur.id) {
			if _, ok := visited[e.From]; ok {
				continue
			}
			visited[e.From] = cur.dist + 1
			q = append(q, item{e.From, cur.dist + 1})
		}
	}
	out := make([]Fragment, 0, len(visited))
	for id, dist := range visited {
		if dist == 0 {
			continue
		}
		n := b.CG.Nodes[id]
		if n == nil || n.Symbol == nil {
			continue
		}
		frag, ok := b.symbolFragment(n.File, *n.Symbol, KindCaller,
			fmt.Sprintf("calls into chunk (%d hop)", dist), dist)
		if !ok {
			continue
		}
		out = append(out, frag)
	}
	return b.cap(out, b.Cfg.CallersMax)
}

// -- types ------------------------------------------------------------------

// typeIdentRe matches Go-style PascalCase identifiers (also fits Python class
// names, Java types, JS classes). Conservative but effective.
var typeIdentRe = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]{2,})\b`)

func (b *Builder) collectTypes(c types.FileTarget) []Fragment {
	if b.Cfg.TypesMax == 0 {
		return nil
	}
	names := b.uniqueIdentsByRegex(c.Content, typeIdentRe)
	if len(names) == 0 {
		return nil
	}
	out := make([]Fragment, 0, b.Cfg.TypesMax)
	// Look in the chunk's own file first, then in imported files.
	files := b.candidateFilesForChunk(c)
	for _, name := range names {
		if len(out) >= b.Cfg.TypesMax {
			break
		}
		for _, fpath := range files {
			fast := b.ASTByPath[fpath]
			if fast == nil {
				continue
			}
			for i := range fast.Symbols {
				s := &fast.Symbols[i]
				if s.Name != name {
					continue
				}
				if s.Kind != "class" && s.Kind != "struct" && s.Kind != "interface" {
					continue
				}
				if c.Path == fpath && s.StartLine >= c.LineOffset+1 && s.EndLine <= c.LineOffset+c.Lines {
					continue // already in chunk
				}
				frag, ok := b.symbolFragment(fpath, *s, KindType,
					"type referenced in chunk", 2)
				if !ok {
					continue
				}
				out = append(out, frag)
				break // one definition per name
			}
			if len(out) >= b.Cfg.TypesMax {
				break
			}
		}
	}
	return out
}

// -- sanitizers -------------------------------------------------------------

func (b *Builder) collectSanitizers(c types.FileTarget) []Fragment {
	if b.Sanitizers == nil || b.Cfg.SanitizersMax == 0 {
		return nil
	}
	lang := c.Language
	if lang == "" && b.ASTByPath[c.Path] != nil {
		lang = string(b.ASTByPath[c.Path].Language)
	}
	out := make([]Fragment, 0, b.Cfg.SanitizersMax)
	files := b.candidateFilesForChunk(c)
	seen := map[string]bool{}
	for _, fpath := range files {
		fast := b.ASTByPath[fpath]
		if fast == nil {
			continue
		}
		for i := range fast.Symbols {
			s := &fast.Symbols[i]
			if s.Kind != "function" && s.Kind != "method" {
				continue
			}
			if !b.Sanitizers.IsSanitizer(lang, s.Name) {
				continue
			}
			key := fpath + "::" + s.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			frag, ok := b.symbolFragment(fpath, *s, KindSanitizer,
				"sanitizer-like name in scope", 3)
			if !ok {
				continue
			}
			out = append(out, frag)
			if len(out) >= b.Cfg.SanitizersMax {
				return out
			}
		}
	}
	return out
}

// -- siblings ---------------------------------------------------------------

func (b *Builder) collectSiblings(c types.FileTarget) []Fragment {
	if b.Cfg.SiblingsMax == 0 {
		return nil
	}
	fast := b.ASTByPath[c.Path]
	if fast == nil {
		return nil
	}
	chunkLo := c.LineOffset + 1
	chunkHi := c.LineOffset + c.Lines
	type ranked struct {
		s    *ast.Symbol
		dist int
	}
	var pool []ranked
	for i := range fast.Symbols {
		s := &fast.Symbols[i]
		if s.Kind != "function" && s.Kind != "method" {
			continue
		}
		if s.StartLine >= chunkLo && s.EndLine <= chunkHi {
			continue // already inside chunk
		}
		dist := 0
		if s.EndLine < chunkLo {
			dist = chunkLo - s.EndLine
		} else if s.StartLine > chunkHi {
			dist = s.StartLine - chunkHi
		}
		pool = append(pool, ranked{s, dist})
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i].dist < pool[j].dist })
	out := make([]Fragment, 0, b.Cfg.SiblingsMax)
	for _, r := range pool {
		if len(out) >= b.Cfg.SiblingsMax {
			break
		}
		frag, ok := b.symbolFragment(c.Path, *r.s, KindSibling,
			fmt.Sprintf("sibling symbol (Δ=%d lines)", r.dist), 4)
		if !ok {
			continue
		}
		out = append(out, frag)
	}
	return out
}

// -- RAG --------------------------------------------------------------------

func (b *Builder) collectRAG(ctx context.Context, c types.FileTarget) []Fragment {
	if b.RAG == nil || b.Cfg.RAGTopK == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Use the first ~1200 chars of chunk as query. Avoids over-specific
	// embeddings; the embedder's own truncation handles longer inputs.
	query := c.Content
	if len(query) > 1200 {
		query = query[:1200]
	}
	hits, err := b.RAG.Search(ctx, query, b.Cfg.RAGTopK)
	if err != nil {
		return nil
	}
	out := make([]Fragment, 0, len(hits))
	chunkLo := c.LineOffset + 1
	chunkHi := c.LineOffset + c.Lines
	for _, h := range hits {
		if h.File == c.Path && h.StartLine >= chunkLo && h.EndLine <= chunkHi {
			continue
		}
		f := Fragment{
			Kind:     KindRAG,
			Reason:   "semantically similar code",
			File:     h.File,
			Symbol:   h.Symbol,
			Start:    h.StartLine,
			End:      h.EndLine,
			Code:     h.Text,
			Priority: 3,
			Tokens:   tokens.Estimate(h.Text),
		}
		out = append(out, f)
	}
	return out
}

// -- consts -----------------------------------------------------------------

var allCapsRe = regexp.MustCompile(`\b([A-Z][A-Z0-9_]{3,})\b`)

func (b *Builder) collectConsts(c types.FileTarget) []Fragment {
	if b.Cfg.ConstsMax == 0 {
		return nil
	}
	names := b.uniqueIdentsByRegex(c.Content, allCapsRe)
	if len(names) == 0 {
		return nil
	}
	out := make([]Fragment, 0, b.Cfg.ConstsMax)
	files := b.candidateFilesForChunk(c)
	for _, name := range names {
		if len(out) >= b.Cfg.ConstsMax {
			break
		}
		for _, fpath := range files {
			fast := b.ASTByPath[fpath]
			if fast == nil {
				continue
			}
			for i := range fast.Symbols {
				s := &fast.Symbols[i]
				if s.Name != name {
					continue
				}
				if s.Kind != "const" && s.Kind != "var" {
					continue
				}
				frag, ok := b.symbolFragment(fpath, *s, KindConst,
					"constant referenced in chunk", 4)
				if !ok {
					continue
				}
				out = append(out, frag)
				break
			}
			if len(out) >= b.Cfg.ConstsMax {
				break
			}
		}
	}
	return out
}

// -- helpers ----------------------------------------------------------------

// nodesInChunk returns call-graph nodes whose source body lies inside chunk.
func (b *Builder) nodesInChunk(c types.FileTarget) []callgraph.NodeID {
	if b.CG == nil {
		return nil
	}
	chunkLo := c.LineOffset + 1
	chunkHi := c.LineOffset + c.Lines
	var ids []callgraph.NodeID
	// Iterate via CG.Nodes; callgraph does not expose a per-file index publicly,
	// but FindNodeAtLine + per-line scan is the supported path.
	// To avoid O(N*lines), we just check every node's file and overlap.
	for id, n := range b.CG.Nodes {
		if n == nil || n.Symbol == nil || n.File != c.Path {
			continue
		}
		if n.Symbol.EndLine < chunkLo || n.Symbol.StartLine > chunkHi {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// candidateFilesForChunk returns the chunk's file followed by every file
// imported by it (per depgraph), then everything else in the project. Used
// when chasing type/const definitions.
func (b *Builder) candidateFilesForChunk(c types.FileTarget) []string {
	seen := map[string]bool{}
	out := []string{c.Path}
	seen[c.Path] = true
	if b.Deps != nil {
		for _, dep := range b.Deps.Neighbors(c.Path, 1) {
			if dep == c.Path || seen[dep] {
				continue
			}
			seen[dep] = true
			out = append(out, dep)
		}
	}
	// Limit unbounded fallback search to the same directory.
	dir := filepath.Dir(c.Path)
	for p := range b.ASTByPath {
		if seen[p] {
			continue
		}
		if filepath.Dir(p) == dir {
			out = append(out, p)
			seen[p] = true
		}
	}
	return out
}

// symbolFragment renders a symbol's body from the file source. Returns ok=false
// if the source is unavailable or the range is empty.
func (b *Builder) symbolFragment(file string, s ast.Symbol, kind FragmentKind, reason string, priority int) (Fragment, bool) {
	fast := b.ASTByPath[file]
	if fast == nil {
		return Fragment{}, false
	}
	src := ast.FileSource(fast)
	if len(src) == 0 {
		return Fragment{}, false
	}
	lines := strings.Split(string(src), "\n")
	lo := s.StartLine - 1
	hi := s.EndLine
	if lo < 0 {
		lo = 0
	}
	if hi > len(lines) {
		hi = len(lines)
	}
	if hi <= lo {
		return Fragment{}, false
	}
	body := strings.Join(lines[lo:hi], "\n")
	return Fragment{
		Kind:     kind,
		Reason:   reason,
		File:     file,
		Symbol:   s.Name,
		Start:    s.StartLine,
		End:      s.EndLine,
		Code:     body,
		Priority: priority,
		Tokens:   tokens.Estimate(body),
	}, true
}

// uniqueIdentsByRegex returns identifiers matching re, preserving first-seen
// order. Helpful for type/const lookup queries.
func (b *Builder) uniqueIdentsByRegex(s string, re *regexp.Regexp) []string {
	matches := re.FindAllStringSubmatch(s, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// cap truncates a fragment slice to maxN, keeping the lowest-priority items.
func (b *Builder) cap(in []Fragment, maxN int) []Fragment {
	if maxN <= 0 || len(in) <= maxN {
		return in
	}
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Priority != in[j].Priority {
			return in[i].Priority < in[j].Priority
		}
		return in[i].Tokens < in[j].Tokens
	})
	return in[:maxN]
}
