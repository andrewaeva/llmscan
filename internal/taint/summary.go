// Function summaries: per-function param flow descriptions used to drive
// inter-procedural taint propagation. See interproc.go for the fixed-point
// algorithm that consumes these summaries.
package taint

import (
	"regexp"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/sanitizers"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// SinkRef is a sink reached inside a function body.
type SinkRef struct {
	Kind     string // watchlist category: sql / command / xss / ...
	Match    string // raw watchlist matcher that fired (for traceability)
	Line     int
	CalleeID callgraph.NodeID // populated when the sink is itself a function we have a summary for
}

// SanitizerRef records a sanitizer match in a function body.
type SanitizerRef struct {
	Kind  string
	Match string
	Line  int
	// ID is the framework-aware sanitizer database id when the match
	// originated from internal/sanitizers (empty for watchlist matches).
	ID string `json:"id,omitempty"`
}

// ParamFlow describes how one parameter of a function flows through its body.
type ParamFlow struct {
	ParamIdx      int    `json:"param_idx"`
	ParamName     string `json:"param_name"`
	FlowsTo       []SinkRef
	Sanitized     []SanitizerRef
	ReturnedTaint bool // true if a tainted param value leaves the function via `return`

	// GuardedFlowsTo are sinks reached only along paths that go through a
	// validator/guard scope. Callers should treat these as low-confidence
	// signals (severity / confidence downgrade) rather than as canonical
	// taint flows.
	GuardedFlowsTo []SinkRef `json:"guarded_flows_to,omitempty"`
	// GuardSanitizers records sanitizers from the framework-aware database
	// that were active on the guarded sub-path.
	GuardSanitizers []SanitizerRef `json:"guard_sanitizers,omitempty"`
}

// CallSiteFlow records a call from this function to another, with the indices
// of the *current* function's params that are passed through.
type CallSiteFlow struct {
	CalleeName string           // textual callee name (resolved by call graph)
	CalleeID   callgraph.NodeID // first resolved candidate (best effort)
	Line       int
	// ArgParamIdx[i] is the index in the current function's params that flows
	// to argument position i of the callee, or -1 if not param-derived.
	ArgParamIdx []int
}

// FunctionSummary is the compiled per-function dataflow signature.
type FunctionSummary struct {
	NodeID      callgraph.NodeID
	File        string
	Func        string
	ParamNames  []string
	Params      []ParamFlow
	SinksInBody []SinkRef
	Sanitizers  []SanitizerRef
	InterCalls  []CallSiteFlow
	// IsSink: every parameter that reaches the function unsanitized is treated
	// as flowing to a sink-like category (callers should propagate taint
	// regardless of body content).
	IsSink bool
	// IsSanitizer: callers should clear taint of matching kind when this is invoked.
	IsSanitizer bool
	// IsSource: entry-point — all params are tainted at function entry.
	IsSource bool
	// SourceCategories: categories assigned by the source classifier (e.g. http).
	SourceCategories []string
}

// BuildSummaries scans every parsed file and returns a summary per declared
// function/method node. The keys are callgraph NodeIDs.
func BuildSummaries(files []*ast.FileAST, cg *callgraph.CallGraph) map[callgraph.NodeID]*FunctionSummary {
	db, _ := sanitizers.LoadDefault()
	return BuildSummariesWithDB(files, cg, db)
}

// BuildSummariesWithDB is BuildSummaries with an explicit sanitizer DB.
func BuildSummariesWithDB(files []*ast.FileAST, cg *callgraph.CallGraph, db *sanitizers.DB) map[callgraph.NodeID]*FunctionSummary {
	out := map[callgraph.NodeID]*FunctionSummary{}
	for _, f := range files {
		if f == nil {
			continue
		}
		src := string(ast.FileSource(f))
		lines := strings.Split(src, "\n")
		for i := range f.Symbols {
			s := &f.Symbols[i]
			if s.Kind != "function" && s.Kind != "method" {
				continue
			}
			sm := buildFunctionSummary(f, lines, s, cg, db)
			if sm == nil {
				continue
			}
			out[sm.NodeID] = sm
		}
	}
	return out
}

// buildFunctionSummary does a single linear pass over function body lines and
// builds a coarse parameter-flow description.
//
// Algorithm (intra-procedural, no CFG):
//  1. Extract param names from the signature line.
//  2. Initialize tainted := set(params).
//  3. For each line in body:
//     - If assignment `lhs = expr` and rhs references any tainted ident -> add lhs.
//     - If a watchlist sanitizer matches and references a tainted ident -> remove it.
//     - If a watchlist sink matches and a tainted ident appears -> record a SinkRef
//     (and link it back to the param via the original taint source).
//     - For every call expression, record CallSiteFlow with the indices of
//     params that appear inside the call's argument span.
//     - If `return <expr>` and expr references a tainted param -> mark ReturnedTaint.
//
//nolint:gocyclo // single-pass dataflow summary; intentionally flat
func buildFunctionSummary(f *ast.FileAST, lines []string, s *ast.Symbol, cg *callgraph.CallGraph, db *sanitizers.DB) *FunctionSummary {
	id := callgraph.IDOf(f.Path, s.Name)
	if cg != nil {
		if _, ok := cg.Nodes[id]; !ok {
			// duplicate-name function — try receiver-qualified id
			altID := callgraph.IDOf(f.Path, recvShortName(s.Receiver)+"."+s.Name)
			if _, ok := cg.Nodes[altID]; ok {
				id = altID
			}
		}
	}
	sm := &FunctionSummary{NodeID: id, File: f.Path, Func: s.Name}
	if s.StartLine < 1 || s.EndLine > len(lines) || s.StartLine > s.EndLine {
		return sm
	}
	// 1) param names
	sig := strings.Join(lines[s.StartLine-1:min(s.StartLine+3, s.EndLine)], "\n")
	params := extractParams(string(f.Language), sig)
	sm.ParamNames = params
	paramIdx := map[string]int{}
	for i, p := range params {
		paramIdx[p] = i
	}
	// init param flows
	sm.Params = make([]ParamFlow, len(params))
	for i, p := range params {
		sm.Params[i] = ParamFlow{ParamIdx: i, ParamName: p}
	}
	// 2) initial taint set: param name -> origin param idx
	tainted := map[string]int{}
	for i, p := range params {
		tainted[p] = i
	}

	lang := string(f.Language)
	// guard scope tracking for path-sensitive summaries
	braced := isBracedLang(lang)
	var scopes []guardScope
	braceDepth := 0
	// 3) scan body
	for ln := s.StartLine + 1; ln <= s.EndLine; ln++ {
		line := lines[ln-1]
		indent := leadingIndent(line)
		if !braced && strings.TrimSpace(line) != "" {
			scopes = closePythonScopes(scopes, indent)
		}
		if isGuardHeader(line) {
			if kind := detectGuardKind(lang, line, db); kind != "" {
				scopes = append(scopes, guardScope{startLine: ln, indent: indent, kind: kind, braceDepth: braceDepth})
			}
		}
		inGuard := activeGuardFor(scopes) != nil
		// detect new sources (these are also tracked separately for IsSource decisions)
		for _, e := range watchlist.FindMatches(lang, line, watchlist.KindSource) {
			lhs := captureLHS(line)
			if lhs != "" {
				// not a param, but propagates as a "synthetic" param idx -1
				tainted[lhs] = -1
				_ = e
			}
		}

		// propagation: lhs = ... rhs ... -> lhs becomes tainted
		if m := assignRE.FindStringSubmatch(line); m != nil {
			lhs := strings.TrimSpace(m[1])
			rhs := m[2]
			for v, origin := range tainted {
				if v == lhs {
					continue
				}
				if containsWord(rhs, v) {
					tainted[lhs] = origin
				}
			}
		}

		// sanitizers wipe taint of matching category
		for _, e := range watchlist.FindMatches(lang, line, watchlist.KindSanitizer) {
			sm.Sanitizers = append(sm.Sanitizers, SanitizerRef{Kind: e.Category, Match: e.Match, Line: ln})
			for v, origin := range tainted {
				if !containsWord(line, v) {
					continue
				}
				if origin >= 0 && origin < len(sm.Params) {
					sm.Params[origin].Sanitized = append(sm.Params[origin].Sanitized,
						SanitizerRef{Kind: e.Category, Match: e.Match, Line: ln})
				}
				delete(tainted, v)
			}
		}

		// framework-aware sanitizer DB hits — skip on guard headers so that
		// `if isValid(x) { sink(x) }` keeps x tainted into the block.
		if db != nil && !isGuardHeader(line) {
			for _, sd := range db.Match(lang, line, nil) {
				if sd.Negative {
					continue
				}
				ref := SanitizerRef{Kind: firstCat(sd.Categories), Match: sd.ID, Line: ln, ID: sd.ID}
				sm.Sanitizers = append(sm.Sanitizers, ref)
				for v, origin := range tainted {
					if !containsWord(line, v) {
						continue
					}
					if origin >= 0 && origin < len(sm.Params) {
						if inGuard {
							sm.Params[origin].GuardSanitizers = append(sm.Params[origin].GuardSanitizers, ref)
						} else {
							sm.Params[origin].Sanitized = append(sm.Params[origin].Sanitized, ref)
						}
					}
					delete(tainted, v)
				}
			}
		}

		// sinks
		for _, e := range watchlist.FindMatches(lang, line, watchlist.KindSink) {
			sr := SinkRef{Kind: e.Category, Match: e.Match, Line: ln}
			sm.SinksInBody = append(sm.SinksInBody, sr)
			for v, origin := range tainted {
				if !containsWord(line, v) {
					continue
				}
				if origin >= 0 && origin < len(sm.Params) {
					if inGuard {
						sm.Params[origin].GuardedFlowsTo = append(sm.Params[origin].GuardedFlowsTo, sr)
					} else {
						sm.Params[origin].FlowsTo = append(sm.Params[origin].FlowsTo, sr)
					}
				}
			}
		}

		// call sites with tainted args
		for _, call := range f.Calls {
			if call.Line != ln {
				continue
			}
			args := callArgsOn(line)
			ai := make([]int, len(args))
			anyTainted := false
			for i, a := range args {
				ai[i] = -1
				a = strings.TrimSpace(a)
				if idx, ok := tainted[a]; ok {
					ai[i] = idx
					if idx >= 0 {
						anyTainted = true
					}
				} else {
					// e.g. "foo.Bar(x)" — split idents and check membership
					for v, origin := range tainted {
						if containsWord(a, v) {
							ai[i] = origin
							if origin >= 0 {
								anyTainted = true
							}
							break
						}
					}
				}
			}
			if anyTainted || hasResolvableCallee(call.Callee) {
				cf := CallSiteFlow{
					CalleeName:  call.Callee,
					Line:        ln,
					ArgParamIdx: ai,
				}
				if cg != nil {
					if cands := resolveCalleeNodes(cg, f, call.Callee); len(cands) > 0 {
						cf.CalleeID = cands[0]
					}
				}
				sm.InterCalls = append(sm.InterCalls, cf)
			}
		}

		// return statements
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "return") {
			rest := strings.TrimPrefix(t, "return")
			for v, origin := range tainted {
				if origin < 0 || origin >= len(sm.Params) {
					continue
				}
				if containsWord(rest, v) {
					sm.Params[origin].ReturnedTaint = true
				}
			}
		}

		if braced {
			braceDepth += countBraces(line)
			scopes = closeBracedScopes(scopes, braceDepth)
		}
	}
	return sm
}

// recvShortName is a copy of callgraph.recvShort kept private here to avoid
// re-exporting the helper.
func recvShortName(r string) string {
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

// extractParams returns parameter identifier names for a function/method
// signature snippet across supported languages.
//
// Goal is precision over completeness: it understands the common shapes used
// by HTTP handlers, gRPC methods, Python defs, JS/TS arrow and named
// functions, Java methods. Falls back to all identifiers inside the first
// (...) group.
//
//nolint:gocyclo // language-aware parameter extraction has many small branches
func extractParams(lang, sig string) []string {
	// For Go methods the first "(...)" is the receiver — skip it. Detect by
	// "func (" pattern.
	if lang == "go" {
		idx := strings.Index(sig, "func ")
		if idx >= 0 && idx+5 < len(sig) && sig[idx+5] == '(' {
			// Skip the receiver group.
			depth := 0
			for i := idx + 5; i < len(sig); i++ {
				switch sig[i] {
				case '(':
					depth++
				case ')':
					depth--
					if depth == 0 {
						sig = sig[i+1:]
						break
					}
				}
				if depth == 0 && i > idx+5 {
					break
				}
			}
		}
	}
	open := strings.IndexByte(sig, '(')
	if open < 0 {
		return nil
	}
	// Find matching close paren, respecting nested parens (Go: func(x map[string]int))
	depth := 0
	end := -1
	for i := open; i < len(sig); i++ {
		switch sig[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= open {
		return nil
	}
	inside := sig[open+1 : end]
	// Split top-level commas (ignore commas inside generic/type brackets).
	parts := splitTopLevel(inside, ',')
	var names []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "..." || p == "self" || p == "cls" {
			continue
		}
		// Strip default values: name=42 -> name
		if i := strings.IndexByte(p, '='); i >= 0 {
			p = p[:i]
		}
		// Strip annotations: name: type -> name
		if i := strings.IndexByte(p, ':'); i >= 0 {
			p = p[:i]
		}
		// Spread / rest: ...name or *name
		p = strings.TrimPrefix(p, "...")
		p = strings.TrimPrefix(p, "*")
		// In Go you may have "x, y int" — could not be told apart from a single param.
		// Take last identifier of each space-separated chunk.
		flds := strings.Fields(p)
		if len(flds) == 0 {
			continue
		}
		switch lang {
		case "go":
			// "ctx context.Context" -> "ctx"
			names = append(names, identOnly(flds[0]))
		case "java":
			// "String name" -> "name"
			names = append(names, identOnly(flds[len(flds)-1]))
		default:
			// python/js/ts: first token is the name
			names = append(names, identOnly(flds[0]))
		}
	}
	// Filter out empties / pure types.
	out := names[:0]
	for _, n := range names {
		if n == "" {
			continue
		}
		if !isIdentStart(n[0]) {
			continue
		}
		out = append(out, n)
	}
	return out
}

func identOnly(s string) string {
	for i := 0; i < len(s); i++ {
		if !isIdent(s[i]) {
			return s[:i]
		}
	}
	return s
}

func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	last := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

// hasResolvableCallee returns true for callees that look like a normal name
// (so even when no current-fn taint is passed, we still record the call for
// reachability purposes).
func hasResolvableCallee(callee string) bool {
	c := strings.TrimSpace(callee)
	if c == "" {
		return false
	}
	if strings.ContainsAny(c, "() ") {
		return false
	}
	return true
}

// resolveCalleeNodes is a thin wrapper that mirrors callgraph.resolveCall but
// works with the public API only.
func resolveCalleeNodes(cg *callgraph.CallGraph, from *ast.FileAST, callee string) []callgraph.NodeID {
	name := callgraph.SimpleCalleeName(callee)
	if name == "" || cg == nil || from == nil {
		return nil
	}
	out := cg.LookupByName(from.Path, name)
	return out
}

// callArgsOn extracts the argument list (top-level comma split) from the first
// top-level call expression on a single source line. Returns the raw textual
// args. Best-effort: nested calls' inner arguments are returned as a single
// blob for the outer call.
func callArgsOn(line string) []string {
	open := strings.IndexByte(line, '(')
	if open < 0 {
		return nil
	}
	depth := 0
	end := -1
	for i := open; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end <= open {
		return nil
	}
	return splitTopLevel(line[open+1:end], ',')
}

// captureLHS exists in taint.go (analyzeFile). We keep this file in the same
// package so we can reuse it; assignRE is also from taint.go.
var _ = regexp.MustCompile // ensure regexp stays imported

func firstCat(cs []string) string {
	if len(cs) == 0 {
		return ""
	}
	return cs[0]
}
