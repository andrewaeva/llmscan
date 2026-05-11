// Package taint performs a lightweight, language-agnostic, line-level taint
// analysis. It does NOT do real data-flow; instead it uses the watchlist plus
// simple identifier propagation to suggest plausible source->sink chains.
//
// Path-sensitive extension: the analyzer tracks if/guard scopes and marks
// any sink that lives inside a known validation guard as Trace.Guarded.
// When a sanitizer from the framework-aware database is invoked on the
// tainted variable, Trace.SanitizerID is set so downstream gates can
// confirm Gate 3 (Validation) automatically.
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
	"github.com/andrewaeva/llmscan/internal/sanitizers"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// Hop is one location in a trace.
type Hop = types.TraceHop

// Trace is an ordered list of hops.
type Trace struct {
	Hops      []Hop
	Category  string // sql/command/...
	Sanitizer string // legacy: name of a watchlist sanitizer of matching category between source and sink

	// Guarded is true when the sink resides inside an if/guard scope whose
	// condition looked like a validator. The trace is kept (it may still
	// be a real flow) but downstream pipelines should lower confidence
	// and severity.
	Guarded   bool   `json:"guarded,omitempty"`
	GuardKind string `json:"guard_kind,omitempty"` // e.g. "validation_pass"

	// SanitizerID is the id from the framework-aware sanitizer database
	// that cleared this taint flow (if any). When set, Gate 3 (Validation)
	// is treated as PASS automatically.
	SanitizerID string `json:"sanitizer_id,omitempty"`
}

// Analyze runs intra-file taint on each parsed AST and returns traces grouped
// per file. Cross-file linking is handled by Link().
func Analyze(files []*ast.FileAST) map[string][]Trace {
	out := map[string][]Trace{}
	db, _ := sanitizers.LoadDefault()
	for _, f := range files {
		if f == nil {
			continue
		}
		src := string(ast.FileSource(f))
		out[f.Path] = analyzeFileDB(f.Path, string(f.Language), src, db)
	}
	return out
}

// AnalyzeWithDB is like Analyze but uses a caller-supplied sanitizer DB.
func AnalyzeWithDB(files []*ast.FileAST, db *sanitizers.DB) map[string][]Trace {
	out := map[string][]Trace{}
	for _, f := range files {
		if f == nil {
			continue
		}
		src := string(ast.FileSource(f))
		out[f.Path] = analyzeFileDB(f.Path, string(f.Language), src, db)
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

// guardKeywordRE detects validator-style call shapes inside an if/guard
// expression. Falls back to the curated set when the sanitizer DB has no
// matching language.
var guardKeywordRE = regexp.MustCompile(`\b(isValid|isAlphanumeric|isInt|isNumeric|isEmail|isURL|isUUID|validate|sanitize|verify|matches|in\s+ALLOWED|in\s+WHITELIST|in\s+SAFE_)`)

// guardScope describes a textual scope inside which sinks should be
// flagged as guard-protected (i.e. potentially a false positive).
type guardScope struct {
	startLine  int
	endLine    int // exclusive close; 0 when still open
	indent     int // for indent-based languages (python)
	braceDepth int // depth at which the guard opened; close when depth returns here
	kind       string
}

// analyzeFile is kept for backwards compatibility (used by benchmarks).
// It runs without a sanitizer DB.
func analyzeFile(path, lang, src string) []Trace {
	return analyzeFileDB(path, lang, src, nil)
}

//nolint:gocyclo // taint + guard scope tracking across many source/sink/sanitizer patterns
func analyzeFileDB(path, lang, src string, db *sanitizers.DB) []Trace {
	lines := strings.Split(src, "\n")
	type taintedVar struct {
		name     string
		line     int
		category string
		source   Hop
	}
	tainted := map[string]taintedVar{}
	var traces []Trace

	braced := isBracedLang(lang)
	scopes := []guardScope{} // active guard scopes only

	braceDepth := 0

	for i, line := range lines {
		lineNo := i + 1
		indent := leadingIndent(line)

		// Close indent-based scopes that have ended (Python). We close when
		// a non-blank line appears with indent <= scope.indent.
		if !braced {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				scopes = closePythonScopes(scopes, indent)
			}
		}

		// Detect guard openings (if / elif / when) BEFORE updating brace
		// depth so the opening brace is recognized as part of the guard.
		if isGuardHeader(line) {
			kind := detectGuardKind(lang, line, db)
			if kind != "" {
				sc := guardScope{startLine: lineNo, indent: indent, kind: kind, braceDepth: braceDepth}
				scopes = append(scopes, sc)
			}
		}

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

		// Sanitizers from watchlist wipe taint of matching category for
		// identifiers on this line. We also consult the sanitizer DB so
		// framework-aware rules can mark a taint flow as cleared.
		var matchedSanitizerID string
		for _, e := range watchlist.FindMatches(lang, line, watchlist.KindSanitizer) {
			for v, tv := range tainted {
				if tv.category == e.Category && containsWord(line, v) {
					delete(tainted, v)
				}
			}
		}
		if db != nil && !isGuardHeader(line) {
			// Match-by-pattern across ALL categories so a Java prepared
			// statement (sql) cleans only sql taint, etc. Guard headers
			// (`if isValid(x)`) are skipped so the protected variable stays
			// tainted inside the block — useful for downstream pipelines
			// that want to flag the trace as guarded rather than clean.
			dbHits := db.Match(lang, line, nil)
			for _, s := range dbHits {
				if s.Negative {
					continue
				}
				matched := false
				for v, tv := range tainted {
					if !containsWord(line, v) {
						continue
					}
					if !categoryIn(s.Categories, tv.category) {
						continue
					}
					delete(tainted, v)
					matched = true
				}
				if matched {
					matchedSanitizerID = s.ID
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
				sinkHop := Hop{File: path, Line: lineNo, Kind: "sink", Code: strings.TrimSpace(line)}
				tr := Trace{
					Category: sink.Category,
					Hops:     []Hop{tv.source, sinkHop},
				}
				if g := activeGuardFor(scopes); g != nil {
					tr.Guarded = true
					tr.GuardKind = g.kind
					tr.Hops[len(tr.Hops)-1].Note = "inside guard:" + g.kind
				}
				if matchedSanitizerID != "" {
					tr.SanitizerID = matchedSanitizerID
					tr.Hops[len(tr.Hops)-1].Note = strings.TrimSpace(tr.Hops[len(tr.Hops)-1].Note + " sanitizer:" + matchedSanitizerID)
				}
				traces = append(traces, tr)
			}
		}

		// Update brace depth for braced languages AFTER guard-open detection
		// so the `if (...) {` line itself opens its scope at the same
		// braceDepth it lives in.
		if braced {
			braceDepth += countBraces(line)
			scopes = closeBracedScopes(scopes, braceDepth)
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

// ---- guard / scope helpers ----

func isBracedLang(lang string) bool {
	switch lang {
	case "go", "java", "javascript", "typescript", "c", "cpp", "csharp", "rust":
		return true
	}
	return false
}

func countBraces(s string) int {
	d := 0
	inStr := byte(0)
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case inStr != 0:
			if b == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if b == inStr {
				inStr = 0
			}
		case b == '"' || b == '\'' || b == '`':
			inStr = b
		case b == '{':
			d++
		case b == '}':
			d--
		}
	}
	return d
}

func leadingIndent(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			n++
		case '\t':
			n += 4
		default:
			return n
		}
	}
	return n
}

var ifHeaderRE = regexp.MustCompile(`^\s*(if\b|else\s+if\b|elif\b|when\b|case\b)`)

func isGuardHeader(line string) bool {
	return ifHeaderRE.MatchString(line)
}

// detectGuardKind inspects the `if (...)` condition and returns a guard
// kind label when it looks like a validator. Returns "" for unrelated
// conditionals such as `if err != nil`, `if x == 0`, etc.
func detectGuardKind(lang, line string, db *sanitizers.DB) string {
	// Extract condition text — everything after the keyword up to the
	// trailing `{` or `:`.
	cond := line
	for _, kw := range []string{"else if", "elif", "if"} {
		if i := strings.Index(line, kw); i >= 0 {
			cond = line[i+len(kw):]
			break
		}
	}
	cond = strings.TrimSpace(cond)
	cond = strings.TrimSuffix(strings.TrimRight(cond, " \t{:"), ")")
	cond = strings.TrimPrefix(cond, "(")

	if cond == "" {
		return ""
	}
	if guardKeywordRE.MatchString(cond) {
		return "validation_pass"
	}
	if db != nil {
		hits := db.Match(lang, cond, nil)
		for _, s := range hits {
			if !s.Negative {
				return "validation_pass"
			}
		}
	}
	// Python idiom: `if x in ALLOWED_LIST:` or `if x in (`a`, `b`)`.
	if strings.Contains(cond, " in ") {
		if strings.Contains(cond, "ALLOWED") ||
			strings.Contains(cond, "WHITELIST") ||
			strings.Contains(cond, "VALID") ||
			strings.Contains(cond, "PERMITTED") ||
			strings.Contains(cond, "SAFE") {
			return "validation_pass"
		}
	}
	return ""
}

// activeGuardFor returns the innermost open guard scope, or nil if none.
func activeGuardFor(scopes []guardScope) *guardScope {
	for i := len(scopes) - 1; i >= 0; i-- {
		if scopes[i].endLine == 0 {
			return &scopes[i]
		}
	}
	return nil
}

func closeBracedScopes(scopes []guardScope, curDepth int) []guardScope {
	out := scopes[:0]
	for _, sc := range scopes {
		if curDepth <= sc.braceDepth {
			// closed
			continue
		}
		out = append(out, sc)
	}
	return out
}

func closePythonScopes(scopes []guardScope, curIndent int) []guardScope {
	out := scopes[:0]
	for _, sc := range scopes {
		if curIndent <= sc.indent {
			continue
		}
		out = append(out, sc)
	}
	return out
}

func categoryIn(cats []string, want string) bool {
	if want == "" {
		return len(cats) > 0
	}
	for _, c := range cats {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}
