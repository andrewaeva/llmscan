package pipeline

import (
	"strings"

	"github.com/andrewaeva/llmscan/internal/baseline"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Post-processing helpers: trace/interproc attachment, guard-downgrade,
// suppressions, policy drop, baseline, reachable-file set. All operate on
// the final []Finding slice produced by stagePostProcess.

func (e *Engine) applySuppressions(final []types.Finding, suppressions []suppress.Suppression) {
	if len(suppressions) == 0 {
		return
	}
	count := 0
	for i := range final {
		if m, ok := suppress.MatchAt(suppressions, final[i].File, final[i].StartLine, final[i].RuleID, final[i].Agent); ok {
			final[i].Suppressed = true
			final[i].SuppressedReason = m.Reason
			count++
		}
	}
	if count > 0 {
		e.logf("suppressed %d findings via in-source markers", count)
	}
}

// attachTraces walks each finding and, when a taint trace ends near its span,
// attaches the trace and applies guard-downgrade if the trace was guarded or
// matched a sanitizer.
func attachTraces(final []types.Finding, taintTraces map[string][]taint.Trace) {
	if len(taintTraces) == 0 {
		return
	}
	for i := range final {
		if tr := matchTrace(taintTraces[final[i].File], final[i].StartLine, final[i].EndLine); tr != nil {
			final[i].Trace = tr.Hops
			if tr.Sanitizer != "" {
				final[i].Sanitizer = tr.Sanitizer
			}
			if tr.SanitizerID != "" && final[i].Sanitizer == "" {
				final[i].Sanitizer = tr.SanitizerID
			}
			applyGuardDowngrade(&final[i], tr.Guarded, tr.GuardKind, tr.SanitizerID)
		}
	}
}

// attachInterProc attaches matching inter-procedural TaintPath info to findings.
// When a path's sink line is near a finding's span, the finding gets the path's
// Hops as Trace, the interproc-taint tag, and a small confidence bump.
func attachInterProc(final []types.Finding, paths []taint.TaintPath) {
	if len(paths) == 0 {
		return
	}
	for i := range final {
		f := &final[i]
		tp := taint.MatchPath(paths, f.File, f.StartLine, f.EndLine)
		if tp == nil {
			continue
		}
		// Only overwrite trace if the interproc path is longer than what's
		// already attached (more context wins).
		if len(tp.Hops) > len(f.Trace) {
			f.Trace = tp.AsTrace()
		}
		f.Tags = appendUnique(f.Tags, "interproc-taint")
		if len(tp.Sanitizers) > 0 {
			f.Tags = appendUnique(f.Tags, "interproc-sanitized")
			if f.Sanitizer == "" {
				f.Sanitizer = tp.Sanitizers[0].Match
			}
		}
		applyGuardDowngrade(f, tp.Guarded, "validation_pass", tp.SanitizerID)
		// Confidence bump for cross-function chains; bounded at 0.99.
		if f.Score > 0 {
			f.Score = minFloat(0.99, f.Score+0.05)
		} else {
			f.Score = tp.Confidence
		}
	}
}

// applyGuardDowngrade lowers severity and confidence one notch when a
// taint trace landed inside a validator/guard scope or matched a
// framework-aware sanitizer. Gate 3 (Validation) is auto-PASSed when a
// SanitizerID is recorded.
func applyGuardDowngrade(f *types.Finding, guarded bool, guardKind, sanitizerID string) {
	if !guarded && sanitizerID == "" {
		return
	}
	if guarded {
		f.Tags = appendUnique(f.Tags, "taint-guarded")
		if guardKind != "" {
			f.Tags = appendUnique(f.Tags, "guard:"+guardKind)
		}
	}
	if sanitizerID != "" {
		f.Tags = appendUnique(f.Tags, "sanitizer:"+sanitizerID)
		if f.Sanitizer == "" {
			f.Sanitizer = sanitizerID
		}
		if f.Gates == nil {
			f.Gates = &types.GateReview{}
		}
		if f.Gates.Validation == types.GateUnknown {
			f.Gates.Validation = types.GatePass
			f.Gates.ValidationReason = "sanitizer database match: " + sanitizerID
		}
	}
	// Severity downgrade by one step.
	switch f.Severity {
	case types.SevCritical:
		f.Severity = types.SevHigh
	case types.SevHigh:
		f.Severity = types.SevMedium
	case types.SevMedium:
		f.Severity = types.SevLow
	}
	// Confidence downgrade: cap below high.
	if normConf(f.Confidence) == types.ConfHigh {
		f.Confidence = types.ConfMedium
	} else if f.Confidence == "" {
		f.Confidence = types.ConfMedium
	}
}

// dropUnconfirmedFindings discards findings where both the verifier and the
// deep agent returned an inconclusive verdict (or never ran). When neither
// LLM could confirm or refute exploitability, the finding is noise. Findings
// that received any decisive verdict from either agent — confirmed,
// true_positive, refuted, false_positive — pass through unchanged
// (refuted/fp are handled by the existing false-positive filter).
func dropUnconfirmedFindings(in []types.Finding) []types.Finding {
	out := in[:0]
	for _, f := range in {
		if isUnconfirmed(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func isUnconfirmed(f types.Finding) bool {
	return isUnclearVerdict(f.VerifierVerdict) && isUnclearVerdict(f.DeepVerdict)
}

// dropImpactFailFindings discards findings whose Impact gate (Gate 6 in the
// Trail of Bits fp-check methodology) is FAIL. A failing impact gate means
// the verifier explicitly concluded the bug has no security impact —
// defense-in-depth at best, not an actionable security finding. Findings
// without a gate review attached are left untouched: there is no evidence to
// act on, so downstream filters decide.
func dropImpactFailFindings(in []types.Finding) []types.Finding {
	out := in[:0]
	for _, f := range in {
		if hasImpactGateFail(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func hasImpactGateFail(f types.Finding) bool {
	if f.Gates == nil {
		return false
	}
	return types.NormalizeGate(string(f.Gates.Impact)) == types.GateFail
}

func isUnclearVerdict(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "inconclusive", "unknown":
		return true
	default:
		return false
	}
}

// dropByPolicy removes suppressed, false-positive, and below-min-score findings.
func (e *Engine) dropByPolicy(final []types.Finding, report *types.Report) []types.Finding {
	minScore := e.Cfg.Precision.MinScore
	kept := final[:0]
	for _, f := range final {
		if f.Suppressed {
			continue
		}
		if e.Cfg.DropFalsePositives && f.FalsePositive {
			report.Stats.FalsePos++
			continue
		}
		if minScore > 0 && f.Score > 0 && f.Score < minScore {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// applyBaseline filters out previously-known findings and optionally writes
// the current set as the new baseline.
func (e *Engine) applyBaseline(cdb cache.Cache, final []types.Finding) []types.Finding {
	if cdb == nil || e.Cfg.Baseline.Path == "" {
		return final
	}
	known, _ := cdb.LoadBaseline()
	if !e.Cfg.Baseline.Write && len(known) > 0 {
		before := len(final)
		final = baseline.FilterNew(final, known)
		e.logf("baseline: %d -> %d findings (%d known)", before, len(final), len(known))
	}
	if e.Cfg.Baseline.Write {
		if err := cdb.SaveBaseline(baseline.AsMap(final)); err != nil {
			e.logf("baseline save: %v", err)
		} else {
			e.logf("baseline written: %d fingerprints", len(final))
		}
	}
	return final
}

// reachableFileSet collects the set of files containing any node reachable
// from the union of all entry points.
func reachableFileSet(cg *callgraph.CallGraph, eps []callgraph.Info) map[string]bool {
	if cg == nil || len(eps) == 0 {
		return nil
	}
	ids := make([]callgraph.NodeID, 0, len(eps))
	for _, e := range eps {
		ids = append(ids, e.Node)
	}
	rs := cg.ReachableFromAny(ids)
	out := map[string]bool{}
	for id := range rs {
		if n := cg.Nodes[id]; n != nil {
			out[n.File] = true
		}
	}
	return out
}

func matchTrace(traces []taint.Trace, line, endLine int) *taint.Trace {
	for i := range traces {
		t := &traces[i]
		if len(t.Hops) == 0 {
			continue
		}
		sink := t.Hops[len(t.Hops)-1].Line
		if sink >= line-2 && sink <= endLine+2 {
			return t
		}
	}
	return nil
}

func appendUnique(in []string, v string) []string {
	for _, s := range in {
		if s == v {
			return in
		}
	}
	return append(in, v)
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
