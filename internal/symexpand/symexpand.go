// Package symexpand pulls function/method definitions referenced by a given
// chunk and returns them as extra context for the scanner.
//
// Heuristic — language-agnostic:
//  1. Extract identifiers that look like calls inside the chunk (foo.bar(, baz(...).
//  2. Look up Symbol definitions across the whole indexed AST set.
//  3. Prefer definitions from files that are direct deps (depgraph 1-hop).
//  4. Return up to `Max` definition snippets, each truncated to `MaxLines` lines.
package symexpand

import (
	"regexp"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
)

// Definition is a returned snippet.
type Definition struct {
	Name      string
	File      string
	StartLine int
	EndLine   int
	Code      string
}

// Options controls expansion.
type Options struct {
	Max      int // max definitions per call
	MaxLines int // max lines per definition snippet
	Hops     int // 0 = all files, 1 = direct deps only, 2 = deps of deps
}

// Expander indexes AST results and exposes Expand.
type Expander struct {
	// name -> []Definition
	byName map[string][]Definition
	// path -> AST (kept to slice source on demand)
	byPath map[string]*ast.FileAST
}

// New builds an expander from parsed ASTs.
func New(files []*ast.FileAST) *Expander {
	e := &Expander{
		byName: map[string][]Definition{},
		byPath: map[string]*ast.FileAST{},
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		e.byPath[f.Path] = f
		for _, s := range f.Symbols {
			if s.Kind != "function" && s.Kind != "method" && s.Kind != "class" {
				continue
			}
			e.byName[s.Name] = append(e.byName[s.Name], Definition{
				Name:      s.Name,
				File:      f.Path,
				StartLine: s.StartLine,
				EndLine:   s.EndLine,
			})
		}
	}
	return e
}

var callRE = regexp.MustCompile(`(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]{2,})\s*\(`)

// Expand returns up to opts.Max definitions referenced from `chunk`.
// `chunkFile` is used to prefer same-package / direct-dep definitions.
// `deps` maps file -> direct dependency files (from depgraph).
func (e *Expander) Expand(chunk, chunkFile string, deps map[string][]string, opts Options) []Definition {
	if opts.Max == 0 {
		opts.Max = 4
	}
	if opts.MaxLines == 0 {
		opts.MaxLines = 30
	}
	names := uniqueNames(chunk)
	if len(names) == 0 {
		return nil
	}
	depSet := map[string]bool{chunkFile: true}
	for _, d := range deps[chunkFile] {
		depSet[d] = true
	}
	if opts.Hops > 1 {
		for d := range depSet {
			for _, dd := range deps[d] {
				depSet[dd] = true
			}
		}
	}

	var hits []Definition
	for _, name := range names {
		candidates := e.byName[name]
		if len(candidates) == 0 {
			continue
		}
		// Prefer deps first
		sort.SliceStable(candidates, func(i, j int) bool {
			ai := depSet[candidates[i].File]
			aj := depSet[candidates[j].File]
			if ai != aj {
				return ai
			}
			return candidates[i].File < candidates[j].File
		})
		def := candidates[0]
		def.Code = e.slice(def.File, def.StartLine, def.EndLine, opts.MaxLines)
		hits = append(hits, def)
		if len(hits) >= opts.Max {
			break
		}
	}
	return hits
}

func uniqueNames(src string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range callRE.FindAllStringSubmatch(src, -1) {
		name := m[1]
		if isKeyword(name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func isKeyword(s string) bool {
	switch s {
	case "if", "for", "while", "return", "func", "def", "class", "import",
		"new", "var", "let", "const", "switch", "case", "try", "catch",
		"print", "println", "log", "true", "false", "nil", "None":
		return true
	}
	return false
}

func (e *Expander) slice(path string, start, end, maxLines int) string {
	f, ok := e.byPath[path]
	if !ok || f == nil {
		return ""
	}
	src := string(astSource(f))
	lines := strings.Split(src, "\n")
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	if end > len(lines) {
		end = len(lines)
	}
	if end-start+1 > maxLines {
		end = start + maxLines - 1
	}
	return strings.Join(lines[start-1:end], "\n")
}

// astSource is a tiny helper that pulls the source bytes from a FileAST.
// The exported FileAST does not expose them — keep a same-package adapter.
var astSource = ast.FileSource
