package pipeline

import (
	"context"
	"fmt"

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
	final = append(final, s.prefilterFindings...)
	e.applySuppressions(final, s.suppressions)
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
	if n := applyConfidence(final); n > 0 {
		e.logf("confidence: updated %d findings", n)
	}
	if n := e.applyCalibration(final); n > 0 {
		e.logf("calibration: remapped %d scores", n)
	}
	final = e.dropByPolicy(final, s.report)
	final = e.applyBaseline(s.cacheDB, final)
	e.prog().Done("post-process")

	for _, f := range final {
		s.report.Stats.BySeverity[string(f.Severity)]++
		s.report.Stats.ByAgent[f.Agent]++
	}
	types.SortFindings(final)
	s.report.Findings = final
	s.final = final
	return nil
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
