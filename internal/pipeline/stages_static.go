package pipeline

import (
	"context"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/taint"
)

// Static-analysis stages: discover, parse, prefilters (taint, interproc,
// secrets, watchlist), orchestrator plan, RAG, cache opening. These stages
// only touch deterministic analyzers (no scanner LLM calls).

func stageOpenASTCache(_ context.Context, e *Engine, _ *runState) error {
	if !e.Cfg.ASTCache.Enabled {
		return nil
	}
	path := e.Cfg.ASTCache.Path
	if path == "" {
		path = ".llmscan/ast-cache.db"
	}
	c, err := myast.OpenCache(path)
	if err != nil {
		e.logf("ast cache: %v (continuing without cache)", err)
		return nil
	}
	e.astCache = c
	if e.Cfg.ASTCache.Clear {
		if err := c.Clear(); err != nil {
			e.logf("ast cache clear: %v", err)
		}
	}
	return nil
}

func stageDiscover(ctx context.Context, e *Engine, s *runState) error {
	e.prog().Stage("discover", 0)
	files, err := e.discoverFiles(s.target)
	if err != nil {
		return err
	}
	if e.Cfg.Diff.Range != "" {
		files = e.applyDiffFilter(ctx, files, s.target)
		e.logf("diff %q: %d files in scope", e.Cfg.Diff.Range, len(files))
	}
	s.files = files
	s.report.FilesScanned = len(files)
	e.prog().SetTotal("discover", len(files))
	e.prog().Inc("discover", len(files))
	e.prog().Done("discover")
	e.logf("discovered %d files", len(files))
	return nil
}

func stageParseAST(ctx context.Context, e *Engine, s *runState) error {
	e.prog().Stage("parse-ast", len(s.files))
	s.astByPath, s.astList = e.parseASTs(ctx, s.files)
	e.prog().Inc("parse-ast", len(s.astList))
	e.prog().Done("parse-ast")
	e.logf("parsed AST for %d files", len(s.astList))
	s.graph = depgraph.New(s.target, s.astList)
	if s.graph.HasCycle() {
		e.logf("note: dependency graph contains cycles")
	}
	return nil
}

func stageWatchlist(_ context.Context, e *Engine, s *runState) error {
	e.prog().Stage("watchlist", 0)
	before := len(s.files)
	s.files = e.applyWatchlistPreFilter(s.files, s.astByPath)
	e.prog().SetTotal("watchlist", before)
	e.prog().Inc("watchlist", before)
	e.prog().Done("watchlist")
	e.logf("watchlist pre-filter: %d -> %d files", before, len(s.files))
	return nil
}

func stageSuppressions(_ context.Context, e *Engine, s *runState) error {
	s.suppressions = e.collectSuppressions(s.files)
	return nil
}

func stageTaint(_ context.Context, e *Engine, s *runState) error {
	e.prog().Stage("taint", len(s.astList))
	s.taintTraces = taint.Analyze(s.astList)
	e.prog().Inc("taint", len(s.taintTraces))
	e.prog().Done("taint")
	e.logf("taint: %d files analyzed", len(s.taintTraces))
	return nil
}

func stageInterproc(_ context.Context, e *Engine, s *runState) error {
	e.prog().Stage("interproc", 0)
	s.cg = callgraph.Build(s.astList, s.graph)
	s.entryPoints = callgraph.Detect(s.astList)
	s.interProcPaths = taint.AnalyzeInterProc(s.astList, s.cg, s.graph, s.entryPoints,
		taint.Options{MaxDepth: e.Cfg.Precision.InterProcMaxDepth})
	s.reachableFiles = reachableFileSet(s.cg, s.entryPoints)
	e.prog().Done("interproc")
	e.logf("interproc: %d entrypoints, %d nodes, %d edges, %d taint paths",
		len(s.entryPoints), len(s.cg.Nodes), len(s.cg.Edges()), len(s.interProcPaths))
	return nil
}

func stageSecretsPrefilter(_ context.Context, e *Engine, s *runState) error {
	e.prog().Stage("secrets-prefilter", len(s.files))
	s.prefilterFindings = e.runSecretsPreFilter(s.files)
	e.prog().Inc("secrets-prefilter", len(s.files))
	e.prog().Done("secrets-prefilter")
	e.logf("secrets pre-filter: %d deterministic findings", len(s.prefilterFindings))
	return nil
}

func stageOrchestrator(ctx context.Context, e *Engine, s *runState) error {
	s.skillByName = e.loadSkills()
	s.scanCtx.fewshotBanks = e.loadFewShotBanks()
	e.prog().Stage("orchestrator", 0)
	plan, perr := e.planStep(ctx, s.target, s.files, s.graph)
	e.prog().Done("orchestrator")
	if perr != nil {
		e.logf("orchestrator: %v (using fallback plan)", perr)
	}
	s.plan = plan
	s.report.Plan = plan
	return nil
}

func stageRAG(ctx context.Context, e *Engine, s *runState) error {
	s.index = e.buildRAG(ctx, s.files, s.astByPath)
	return nil
}

func stageOpenCache(_ context.Context, e *Engine, s *runState) error {
	s.cacheDB = e.openCacheDB()
	return nil
}
