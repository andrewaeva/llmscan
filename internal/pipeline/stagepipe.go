package pipeline

import (
	"context"
	"errors"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/contextpack"
	"github.com/andrewaeva/llmscan/internal/dag"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/skills"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
)

// runState carries everything a pipeline stage needs to read or mutate.
//
// The state is mutable on purpose: each stage either populates a field or
// transforms an existing one. The fields document the data flow:
//
//	discover      → Files, Report.FilesScanned
//	parseAST      → ASTByPath, ASTList, Graph
//	prefilters    → Files (filtered), Suppressions, TaintTraces,
//	                CG, Entrypoints, InterProcPaths, ReachableFiles,
//	                PrefilterFindings
//	plan          → SkillByName, Plan, Report.Plan
//	rag+cache     → Index, CacheDB
//	chunk+DAG     → Chunks, Prioritized, EnabledScanners, ScanCtx, DAG
//	scan          → Outputs, DAGErrs
//	postprocess   → Final, Report.Findings, Report.Stats
//
// Stage helpers stay free to read any earlier field. A nil field means the
// corresponding stage was skipped (e.g. taint disabled).
type runState struct {
	target string
	report *types.Report

	// Inputs / lightweight state.
	files []types.FileTarget

	// AST + dep graph.
	astByPath map[string]*myast.FileAST
	astList   []*myast.FileAST
	graph     *depgraph.Graph

	// Pre-filter / static-analysis artifacts.
	suppressions      []suppress.Suppression
	taintTraces       map[string][]taint.Trace
	cg                *callgraph.CallGraph
	entryPoints       []callgraph.Info
	interProcPaths    []taint.TaintPath
	reachableFiles    map[string]bool
	prefilterFindings []types.Finding

	// Skills + plan.
	skillByName map[string]*skills.Skill
	plan        types.ScanPlan

	// RAG + caches.
	index   *rag.Index
	cacheDB cache.Cache

	// Chunk queue + DAG.
	chunks          []types.FileTarget
	prioritized     []types.FileTarget
	enabledScanners []string
	scanCtx         scanContext
	dag             *dag.DAG

	// Scan outputs.
	outputs map[string]any
	dagErrs map[string]error

	// Final findings.
	final []types.Finding

	// ContextPack telemetry (populated by stageBuildContextPacks when
	// scan.context.enabled = true).
	cpStats   types.ContextPackStats
	cpBuilder *contextpack.Builder
}

// stage is one named step in the pipeline. Stages are executed in order; the
// first non-nil error aborts the run.
//
// Skip allows a stage to opt out at runtime (e.g. taint stage when taint is
// disabled) so that progress reporting doesn't print a "skipped" event for
// every disabled feature.
type stage struct {
	name string
	skip func(e *Engine, s *runState) bool
	run  func(ctx context.Context, e *Engine, s *runState) error
}

// errPipelineAbort is returned by stages that want to stop the pipeline with
// the current report (e.g. discovery returning zero files is not an error,
// but there's no point in proceeding). Run() unwraps this and returns nil
// alongside the partially-populated report.
var errPipelineAbort = errors.New("pipeline: graceful abort")
