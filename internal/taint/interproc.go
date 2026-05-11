// Inter-procedural taint analysis using a worklist fixed-point algorithm over
// per-function summaries and a call graph.
//
// High-level design: each entry point seeds a per-parameter "tainted bit". We
// propagate that bit through the call graph: when a tainted parameter is
// passed to another function at argument position i, we mark callee.Params[i]
// as tainted in our intermediate state. When tainted reaches a SinkRef inside
// a function body, we record a TaintPath that reconstructs the chain via the
// recorded hops.
package taint

import (
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/entrypoints"
	"github.com/andrewaeva/llmscan/internal/types"
)

// TaintPath is one source-to-sink data-flow chain across files/functions.
type TaintPath struct {
	Source     entrypoints.Info `json:"source"`
	Hops       []types.TraceHop `json:"hops"`
	Sink       SinkRef          `json:"sink"`
	Sanitizers []SanitizerRef   `json:"sanitizers,omitempty"`
	Confidence float64          `json:"confidence"`

	// Guarded marks a path that reaches a sink only through a
	// validator/guard scope (ParamFlow.GuardedFlowsTo). Downstream
	// pipelines should downgrade confidence and severity instead of
	// treating these as canonical taint flows.
	Guarded bool `json:"guarded,omitempty"`
	// SanitizerID records the framework-aware sanitizer that fired on
	// the path (if any).
	SanitizerID string `json:"sanitizer_id,omitempty"`
}

// Options control the inter-procedural walk.
type Options struct {
	MaxDepth int // hop limit; 0 -> default 6
}

// AnalyzeInterProc computes inter-procedural taint paths.
//
// The algorithm:
//  1. Seed: for each entry-point node, every parameter is tainted at entry.
//  2. Worklist of (nodeID, paramIdx, path-so-far). Pop until empty.
//  3. For each popped item, look at the function's summary:
//     - emit TaintPath for every direct SinkRef in paramFlow.FlowsTo,
//     - if returnedTaint is true, push the caller's resulting variable too
//     (handled implicitly through caller's recorded CallSiteFlow),
//     - for every CallSiteFlow that uses this param, push (callee, argIdx).
//  4. Bound by MaxDepth to keep the loop finite even on deeply recursive
//     real-world code.
//
//nolint:gocyclo // worklist + dedup + per-call propagation; flat is intentional
func AnalyzeInterProc(
	files []*ast.FileAST,
	cg *callgraph.CallGraph,
	_ *depgraph.Graph,
	entries []entrypoints.Info,
	opts Options,
) []TaintPath {
	if cg == nil {
		return nil
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 6
	}
	summaries := BuildSummaries(files, cg)

	// Worklist state. Key prevents re-visiting the same (node, param) pair
	// from the same starting entry, which is the standard IFDS-light de-dup.
	type item struct {
		node    callgraph.NodeID
		param   int
		entry   entrypoints.Info
		hops    []types.TraceHop
		san     []SanitizerRef
		visited map[string]bool
	}
	var paths []TaintPath

	// stable, deterministic ordering of entry points
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].File != entries[j].File {
			return entries[i].File < entries[j].File
		}
		return entries[i].Func < entries[j].Func
	})

	for _, ep := range entries {
		sm := summaries[ep.Node]
		if sm == nil {
			continue
		}
		// Seed one work item per parameter; the entry-point's parameters are
		// the attacker-controlled inputs.
		for pi := range sm.Params {
			seed := item{
				node:  ep.Node,
				param: pi,
				entry: ep,
				hops: []types.TraceHop{
					{File: ep.File, Line: lineOfNode(cg, ep.Node), Kind: "source", Code: "entry:" + string(ep.Kind) + " " + ep.Func + "(" + sm.Params[pi].ParamName + ")"},
				},
				visited: map[string]bool{visitKey(ep.Node, pi): true},
			}
			queue := []item{seed}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				if len(cur.hops) > opts.MaxDepth+1 {
					continue
				}
				csum := summaries[cur.node]
				if csum == nil || cur.param < 0 || cur.param >= len(csum.Params) {
					continue
				}
				pf := csum.Params[cur.param]

				// 1) Record sanitizers we pass through.
				localSan := append([]SanitizerRef(nil), cur.san...)
				localSan = append(localSan, pf.Sanitized...)

				// 2) Emit a TaintPath for every direct sink the param reaches.
				for _, sr := range pf.FlowsTo {
					if sanitized(localSan, sr.Kind) {
						continue
					}
					hops := append([]types.TraceHop(nil), cur.hops...)
					hops = append(hops, types.TraceHop{
						File: csum.File, Line: sr.Line, Kind: "sink",
						Code: sr.Match,
					})
					paths = append(paths, TaintPath{
						Source:     cur.entry,
						Hops:       hops,
						Sink:       sr,
						Sanitizers: localSan,
						Confidence: scoreConfidence(len(hops), len(localSan), false),
					})
				}

				// 2b) Path-sensitive: sinks reached only under a guard are
				// emitted as Guarded paths (severity/confidence downgrade).
				for _, sr := range pf.GuardedFlowsTo {
					if sanitized(localSan, sr.Kind) {
						continue
					}
					hops := append([]types.TraceHop(nil), cur.hops...)
					hops = append(hops, types.TraceHop{
						File: csum.File, Line: sr.Line, Kind: "sink",
						Code: sr.Match, Note: "guarded",
					})
					sanID := ""
					for _, gs := range pf.GuardSanitizers {
						if gs.ID != "" {
							sanID = gs.ID
							break
						}
					}
					paths = append(paths, TaintPath{
						Source:      cur.entry,
						Hops:        hops,
						Sink:        sr,
						Sanitizers:  append(append([]SanitizerRef(nil), localSan...), pf.GuardSanitizers...),
						Confidence:  scoreConfidence(len(hops), len(localSan)+1, false),
						Guarded:     true,
						SanitizerID: sanID,
					})
				}

				// 3) Explore call sites that pass this param onward.
				for _, cs := range csum.InterCalls {
					// Does any arg index correspond to our current param?
					for argPos, originParam := range cs.ArgParamIdx {
						if originParam != cur.param {
							continue
						}
						// Resolve callee candidate(s).
						candidates := resolveCallee(cg, csum.File, cs.CalleeName, cs.CalleeID)
						for _, cand := range candidates {
							// Avoid revisits along this entry's trace.
							vk := visitKey(cand, argPos)
							if cur.visited[vk] {
								continue
							}
							nv := copyVisits(cur.visited)
							nv[vk] = true
							nextHops := append([]types.TraceHop(nil), cur.hops...)
							nextHops = append(nextHops, types.TraceHop{
								File: csum.File, Line: cs.Line, Kind: "propagator",
								Code: cs.CalleeName,
							})
							queue = append(queue, item{
								node:    cand,
								param:   argPos,
								entry:   cur.entry,
								hops:    nextHops,
								san:     localSan,
								visited: nv,
							})
						}
					}
				}
				_ = pf // (kept for clarity)
			}
		}
	}

	// Stable sort: source file/line then sink line.
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Source.File != paths[j].Source.File {
			return paths[i].Source.File < paths[j].Source.File
		}
		if paths[i].Sink.Line != paths[j].Sink.Line {
			return paths[i].Sink.Line < paths[j].Sink.Line
		}
		return len(paths[i].Hops) < len(paths[j].Hops)
	})
	return paths
}

func sanitized(sans []SanitizerRef, kind string) bool {
	for _, s := range sans {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func visitKey(n callgraph.NodeID, p int) string {
	return string(n) + ":" + itoa(p)
}

func copyVisits(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func lineOfNode(cg *callgraph.CallGraph, id callgraph.NodeID) int {
	if cg == nil {
		return 0
	}
	n := cg.Nodes[id]
	if n == nil || n.Symbol == nil {
		return 0
	}
	return n.Symbol.StartLine
}

func resolveCallee(cg *callgraph.CallGraph, fromFile, callee string, hint callgraph.NodeID) []callgraph.NodeID {
	if hint != "" {
		if _, ok := cg.Nodes[hint]; ok {
			return []callgraph.NodeID{hint}
		}
	}
	name := callgraph.SimpleCalleeName(callee)
	if name == "" {
		return nil
	}
	return cg.LookupByName(fromFile, name)
}

// scoreConfidence assigns a confidence in [0,1] based on path length and the
// number of sanitizers crossed. Shorter, sanitizer-free paths score higher.
func scoreConfidence(hops, sanitizers int, returnFlow bool) bool2float {
	base := 0.85
	if hops >= 3 {
		base -= 0.05 * float64(hops-2)
	}
	if sanitizers > 0 {
		base -= 0.20
	}
	if returnFlow {
		base += 0.02
	}
	if base < 0.20 {
		base = 0.20
	}
	if base > 0.99 {
		base = 0.99
	}
	return bool2float(base)
}

// bool2float exists only to keep scoreConfidence visually compact.
type bool2float = float64

// AsTrace returns a TaintPath as a flat hop list, ready to attach to
// Finding.Trace.
func (tp TaintPath) AsTrace() []types.TraceHop {
	return append([]types.TraceHop(nil), tp.Hops...)
}

// MatchPath finds an inter-procedural path whose sink lies within the line
// range [start..end] of the given file. Returns nil when none matches.
//
// Matching is tolerant: we first try a tight line-window match, then fall
// back to (a) any sink in the same function and (b) any sink in the same
// file. Tolerance helps when a finding is reported on the call line while
// the sink (db.Exec, exec.Command) lives a few lines below inside the same
// callee.
//
//nolint:gocyclo // 3-pass tolerant matcher
func MatchPath(paths []TaintPath, file string, start, end int) *TaintPath {
	// Pass 1: tight window — sink within +/-2 of the finding span.
	for i := range paths {
		p := &paths[i]
		if p.Sink.Line == 0 || len(p.Hops) == 0 {
			continue
		}
		last := p.Hops[len(p.Hops)-1]
		if last.File != file {
			continue
		}
		if last.Line >= start-2 && last.Line <= end+2 {
			return p
		}
	}
	// Pass 2: relaxed window — any sink whose source file matches and whose
	// sink line is within 50 lines of the finding span. This catches cases
	// where the LLM reports the call site line while the sink is at the
	// inside of the callee.
	for i := range paths {
		p := &paths[i]
		if p.Sink.Line == 0 || len(p.Hops) == 0 {
			continue
		}
		last := p.Hops[len(p.Hops)-1]
		if last.File != file {
			continue
		}
		if last.Line >= start-50 && last.Line <= end+50 {
			return p
		}
	}
	// Pass 3: any path that touches the finding's file as one of its hops.
	for i := range paths {
		p := &paths[i]
		for _, h := range p.Hops {
			if h.File == file {
				return p
			}
		}
	}
	return nil
}

// CategoriesIn returns the set of sink categories present in the path list.
func CategoriesIn(paths []TaintPath) []string {
	m := map[string]bool{}
	for _, p := range paths {
		m[p.Sink.Kind] = true
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FormatHops renders hops as "file:line" strings for debug output.
func FormatHops(hops []types.TraceHop) string {
	parts := make([]string, 0, len(hops))
	for _, h := range hops {
		parts = append(parts, h.File+":"+itoa(h.Line))
	}
	return strings.Join(parts, " -> ")
}
