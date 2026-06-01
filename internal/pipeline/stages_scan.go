package pipeline

import (
	"context"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/tools"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Scan-phase stages: DAG build, DAG run, post-process. These stages drive
// the LLM scanner pass and finalise the report.

func stageBuildDAG(_ context.Context, e *Engine, s *runState) error {
	s.enabledScanners = e.enabledScanners(s.plan, s.skillByName, s.files)
	sc := scanContext{
		chunks:          s.chunks,
		contentByPath:   map[string]string{},
		index:           s.index,
		suppress:        s.suppressions,
		packsByChunkKey: s.scanCtx.packsByChunkKey,
		fewshotBanks:    s.scanCtx.fewshotBanks,
		target:          s.target,
		astByPath:       s.astByPath,
		callGraph:       s.cg,
	}
	for _, f := range s.prioritized {
		sc.contentByPath[f.Path] = f.Content
	}
	s.scanCtx = sc
	d, err := e.buildDAG(s.enabledScanners, s.skillByName, sc)
	if err != nil {
		return fmt.Errorf("dag build: %w", err)
	}
	s.dag = d
	e.logf("DAG layers: %v", d.Layers())
	return nil
}

func stageRunDAG(ctx context.Context, e *Engine, s *runState) error {
	agentPar := e.Cfg.Scan.AgentParallel
	if agentPar <= 0 {
		agentPar = max(len(s.enabledScanners), 4)
	}
	// Honest total: each enabled scanner agent runs over every chunk.
	// runScanner increments "scanners" by 1 per chunk; verifier/fp/deep are
	// reported in post-process.
	total := len(s.chunks) * len(s.enabledScanners)
	e.prog().Stage("scanners", total)
	s.outputs, s.dagErrs = s.dag.Run(ctx, agentPar)
	e.prog().Done("scanners")
	for name, err := range s.dagErrs {
		e.logf("dag node %s: %v", name, err)
	}
	return nil
}

func stagePostProcess(ctx context.Context, e *Engine, s *runState) error {
	e.prog().Stage("post-process", 0)
	final := pickFinalFindings(s.outputs, s.report)

	// Snapshot: state of findings at each gate of the funnel. Captured here
	// (post-dedup, pre-secret-drop) to feed .llmscan/stages/*.json renderers.
	if verified, ok := s.outputs["verifier"].([]types.Finding); ok {
		s.snapVerified = cloneFindings(verified)
	}
	// snapRaw is the dedup output (pre-verifier).
	if dedup, ok := s.outputs["dedup"].([]types.Finding); ok {
		s.snapRaw = cloneFindings(dedup)
	} else if raw, ok := s.outputs["scan_aggregate"].([]types.Finding); ok {
		s.snapRaw = cloneFindings(raw)
	}
	s.stageCounts["raw"] = s.report.Stats.Raw
	s.stageCounts["dedup"] = s.report.Stats.AfterDedup
	s.stageCounts["verified"] = s.report.Stats.AfterVerify

	preSecret := byID(final)
	final = dropSecretFindings(final)
	markDropped(s, preSecret, final, "drop_secret")

	preSuppress := byID(final)
	e.applySuppressions(final, s.suppressions)
	markDropped(s, preSuppress, final, "suppressed")

	// At this point 'final' is the fp_filter output minus secret/suppressed.
	// That's our 'confirmed' snapshot — before refine/deep/debate/drop policies
	// have had a chance to remove anything.
	s.snapConfirmed = cloneFindings(final)
	s.stageCounts["confirmed"] = len(final)

	preRefine := byID(final)
	final = e.runRefinePass(ctx, final, s.chunks)
	markDropped(s, preRefine, final, "refine")
	if e.Cfg.Precision.Reachability {
		idx := callgraph.BuildReach(s.astList, s.graph.CallersByFile())
		if s.reachableFiles != nil {
			idx.SetCallGraphReachable(s.reachableFiles)
		}
		if down := idx.Apply(final); down > 0 {
			e.logf("reachability: downgraded %d findings", down)
		}
	}
	attachTraces(final, s.taintTraces)
	attachInterProc(final, s.interProcPaths)
	final = e.runDeepPass(ctx, s.target, s.cacheDB, final, &tools.SymbolIndex{
		ASTs:      s.astByPath,
		CallGraph: s.cg,
	})
	if e.Cfg.Precision.DropUnconfirmed {
		before := len(final)
		pre := byID(final)
		final = dropUnconfirmedFindings(final)
		markDropped(s, pre, final, "drop_unconfirmed")
		if dropped := before - len(final); dropped > 0 {
			e.logf("dropped %d unconfirmed findings (verifier=inconclusive && deep=inconclusive)", dropped)
		}
	}
	if e.Cfg.Precision.DropImpactFail {
		before := len(final)
		pre := byID(final)
		final = dropImpactFailFindings(final)
		markDropped(s, pre, final, "drop_impact_fail")
		if dropped := before - len(final); dropped > 0 {
			e.logf("dropped %d findings (impact gate = fail)", dropped)
		}
	}
	if n := applyConfidence(final); n > 0 {
		e.logf("confidence: updated %d findings", n)
	}
	if n := e.applyCalibration(final); n > 0 {
		e.logf("calibration: remapped %d scores", n)
	}
	prePolicy := byID(final)
	final = e.dropByPolicy(final, s.report)
	markDropped(s, prePolicy, final, "policy")

	preBaseline := byID(final)
	final = e.applyBaseline(s.cacheDB, final)
	markDropped(s, preBaseline, final, "baseline")
	e.prog().Done("post-process")

	for _, f := range final {
		s.report.Stats.BySeverity[string(f.Severity)]++
		s.report.Stats.ByAgent[f.Agent]++
	}
	types.SortFindings(final)
	s.report.Groups = buildFindingGroups(final)
	s.report.Stats.RootCauses = len(s.report.Groups)
	s.report.Findings = final
	s.final = final
	s.snapFinal = cloneFindings(final)
	s.stageCounts["final"] = len(final)
	return nil
}

func cloneFindings(in []types.Finding) []types.Finding {
	if len(in) == 0 {
		return nil
	}
	out := make([]types.Finding, len(in))
	copy(out, in)
	return out
}

// byID indexes findings by stable id (file:line:rule:agent) so we can compute
// the set difference after a filter pass — that's how we attribute drops.
func byID(in []types.Finding) map[string]types.Finding {
	m := make(map[string]types.Finding, len(in))
	for _, f := range in {
		m[findingKey(f)] = f
	}
	return m
}

func findingKey(f types.Finding) string {
	if f.ID != "" {
		return f.ID
	}
	return fmt.Sprintf("%s:%d:%s:%s", f.File, f.StartLine, f.RuleID, f.Agent)
}

// markDropped records the stage that removed each finding present in 'before'
// but missing from 'after'. First-write-wins: a finding's drop reason is the
// earliest stage that dropped it (in case downstream stages also exclude it).
func markDropped(s *runState, before map[string]types.Finding, after []types.Finding, stage string) {
	if s.dropReasons == nil {
		return
	}
	kept := make(map[string]struct{}, len(after))
	for _, f := range after {
		kept[findingKey(f)] = struct{}{}
	}
	for id := range before {
		if _, ok := kept[id]; ok {
			continue
		}
		if _, already := s.dropReasons[id]; already {
			continue
		}
		s.dropReasons[id] = stage
	}
}

// dropSecretFindings discards any finding whose rule_id or agent identifies
// it as secret-detection output. Secrets detection was removed from llmscan;
// this filter is the safety net catching anything a dynamic skill or generic
// scanner might still produce under that label.
func dropSecretFindings(in []types.Finding) []types.Finding {
	out := in[:0]
	for _, f := range in {
		if isSecretFinding(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func isSecretFinding(f types.Finding) bool {
	if strings.Contains(strings.ToLower(f.RuleID), "secret") {
		return true
	}
	if strings.Contains(strings.ToLower(f.Agent), "secret") {
		return true
	}
	return false
}

// pickFinalFindings extracts the canonical final-findings slice from DAG
// outputs, falling back from fp_filter → verifier when the former is absent.
func pickFinalFindings(outputs map[string]any, report *types.Report) []types.Finding {
	final, _ := outputs["fp_filter"].([]types.Finding)
	if final == nil {
		final, _ = outputs["verifier"].([]types.Finding)
	}
	if raw, ok := outputs["scan_aggregate"].([]types.Finding); ok {
		report.Stats.Raw = len(raw)
	}
	if dedup, ok := outputs["dedup"].([]types.Finding); ok {
		report.Stats.AfterDedup = len(dedup)
	}
	if verified, ok := outputs["verifier"].([]types.Finding); ok {
		report.Stats.AfterVerify = len(verified)
	}
	return final
}
