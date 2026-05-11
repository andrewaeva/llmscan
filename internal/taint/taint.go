// Package taint performs a lightweight, language-agnostic, line-level taint
// analysis. It does NOT do real data-flow; instead it uses the watchlist plus
// simple identifier propagation to suggest plausible source->sink chains.
//
// The output is fed to scanners as additional context and attached to
// findings as Finding.Trace — concrete evidence that drives down false
// positives (and lets the verifier confirm/reject quickly).
package taint

import (
	"regexp"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// Hop is one location in a trace.
type Hop = types.TraceHop

// Trace is an ordered list of hops.
type Trace struct {
	Hops      []Hop
	Category  string // sql/command/...
	Sanitizer string // if any sanitizer of same category sits between source and sink
}

// Analyze runs intra-file taint on each parsed AST and returns traces grouped
// per file. Cross-file linking is handled by Link().
func Analyze(files []*ast.FileAST) map[string][]Trace {
	out := map[string][]Trace{}
	for _, f := range files {
		if f == nil {
			continue
		}
		src := string(ast.FileSource(f))
		out[f.Path] = analyzeFile(f.Path, string(f.Language), src)
	}
	return out
}

// Link merges intra-file traces across the depgraph: if file A taints a
// parameter that is consumed by a sink in file B, traces are concatenated.
// This is intentionally simple: it joins file-level chains whenever a callee
// name matches a sink-reaching parameter in the deps graph.
func Link(traces map[string][]Trace, deps map[string][]string) map[string][]Trace {
	// Simplification: we don't yet have parameter-level taint, so Link is a
	// no-op placeholder for future expansion. Kept to preserve API stability.
	_ = deps
	return traces
}

// assignRE captures lhs = rhs patterns across languages.
var assignRE = regexp.MustCompile(`^\s*(?:[A-Za-z_][\w.]*\s*[,]?\s*)*([A-Za-z_]\w*)\s*[:=]=?\s*(.+)$`)

func analyzeFile(path, lang, src string) []Trace {
	lines := strings.Split(src, "\n")
	type taintedVar struct {
		name     string
		line     int
		category string
		source   Hop
	}
	tainted := map[string]taintedVar{}
	var traces []Trace

	for i, line := range lines {
		lineNo := i + 1

		// Detect new sources.
		for _, e := range watchlist.FindMatches(lang, line, watchlist.KindSource) {
			lhs := captureLHS(line)
			source := Hop{File: path, Line: lineNo, Kind: "source", Code: strings.TrimSpace(line)}
			if lhs != "" {
				tainted[lhs] = taintedVar{name: lhs, line: lineNo, category: e.Category, source: source}
			} else {
				// orphan source — still keep as anchor (e.g. inline use)
				tainted["_inline_"+itoa(lineNo)] = taintedVar{name: "_inline", line: lineNo, category: e.Category, source: source}
			}
		}

		// Propagation: rhs uses a tainted variable -> lhs becomes tainted.
		if m := assignRE.FindStringSubmatch(line); m != nil {
			lhs := m[1]
			rhs := m[2]
			for v, tv := range tainted {
				if v == lhs {
					continue
				}
				if containsWord(rhs, v) {
					tainted[lhs] = taintedVar{name: lhs, line: lineNo, category: tv.category, source: tv.source}
				}
			}
		}

		// Sanitizers wipe taint of matching category for identifiers on this line.
		for _, e := range watchlist.FindMatches(lang, line, watchlist.KindSanitizer) {
			for v, tv := range tainted {
				if tv.category == e.Category && containsWord(line, v) {
					delete(tainted, v)
				}
			}
		}

		// Sinks: if any tainted variable of the same category appears here -> trace.
		for _, sink := range watchlist.FindMatches(lang, line, watchlist.KindSink) {
			for _, tv := range tainted {
				if tv.category != sink.Category {
					continue
				}
				if !containsWord(line, tv.name) && tv.name != "_inline" {
					continue
				}
				tr := Trace{
					Category: sink.Category,
					Hops: []Hop{
						tv.source,
						{File: path, Line: lineNo, Kind: "sink", Code: strings.TrimSpace(line)},
					},
				}
				traces = append(traces, tr)
			}
		}
	}

	sort.SliceStable(traces, func(i, j int) bool {
		return traces[i].Hops[len(traces[i].Hops)-1].Line < traces[j].Hops[len(traces[j].Hops)-1].Line
	})
	return traces
}

var lhsRE = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*[:=]=?`)

func captureLHS(line string) string {
	m := lhsRE.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[1]
}

func containsWord(s, w string) bool {
	if w == "" {
		return false
	}
	idx := 0
	for {
		i := strings.Index(s[idx:], w)
		if i < 0 {
			return false
		}
		j := idx + i
		left := j == 0 || !isIdent(s[j-1])
		right := j+len(w) == len(s) || !isIdent(s[j+len(w)])
		if left && right {
			return true
		}
		idx = j + len(w)
		if idx >= len(s) {
			return false
		}
	}
}

func isIdent(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
