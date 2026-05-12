package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/baseline"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/chunker"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/contextpack"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/entrypoints"
	"github.com/andrewaeva/llmscan/internal/reach"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/util"
)

// stages returns the ordered pipeline. Adding a step here is the only place
// callers need to touch; runtime gating is handled by each stage's skip().
func (e *Engine) stages() []stage {
	return []stage{
		{name: "ast-cache", run: stageOpenASTCache},
		{name: "discover", run: stageDiscover},
		{name: "parse-ast", run: stageParseAST},
		{name: "watchlist",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Precision.PreFilterWatchlist },
			run:  stageWatchlist},
		{name: "suppressions", run: stageSuppressions},
		{name: "taint",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Precision.Taint },
			run:  stageTaint},
		{name: "interproc",
			skip: func(e *Engine, _ *runState) bool { return !(e.Cfg.Precision.Taint && e.Cfg.Precision.InterProc) },
			run:  stageInterproc},
		{name: "symexpand",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Precision.SymbolExpansion },
			run:  stageSymExpand},
		{name: "secrets-prefilter",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Precision.SecretsPreFilter },
			run:  stageSecretsPrefilter},
		{name: "orchestrator", run: stageOrchestrator},
		{name: "rag",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.RAG.Enabled },
			run:  stageRAG},
		{name: "cache", run: stageOpenCache},
		{name: "chunk", run: stageChunk},
		{name: "context-pack",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Scan.Context.Enabled },
			run:  stageBuildContextPacks},
		{name: "dag-build", run: stageBuildDAG},
		{name: "scanners", run: stageRunDAG},
		{name: "post-process", run: stagePostProcess},
	}
}

// Run executes the full pipeline on `target` (file or directory).
func (e *Engine) Run(ctx context.Context, target string) (types.Report, error) {
	report := types.Report{
		Target:    target,
		StartedAt: time.Now(),
		Stats:     types.Stats{BySeverity: map[string]int{}, ByAgent: map[string]int{}},
	}
	st := &runState{target: target, report: &report}

	// astCache is opened in stageOpenASTCache and must be closed last, before
	// the cache DB (which is opened in stageOpenCache).
	defer e.closeASTCache()
	defer st.closeCacheDB()

	for _, s := range e.stages() {
		if s.skip != nil && s.skip(e, st) {
			continue
		}
		if err := s.run(ctx, e, st); err != nil {
			if errors.Is(err, errPipelineAbort) {
				break
			}
			return report, fmt.Errorf("stage %s: %w", s.name, err)
		}
	}

	report.FinishedAt = time.Now()
	return report, nil
}

func (e *Engine) closeASTCache() {
	if e.astCache == nil {
		return
	}
	st := e.astCache.Stats()
	e.logf("ast cache: hits=%d misses=%d stores=%d errors=%d", st.Hits, st.Misses, st.Stores, st.Errors)
	_ = e.astCache.Close()
	e.astCache = nil
}

func (s *runState) closeCacheDB() {
	if s.cacheDB == nil {
		return
	}
	_ = s.cacheDB.Close()
	s.cacheDB = nil
}

// --- Stage implementations -------------------------------------------------

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
	s.entryPoints = entrypoints.Detect(s.astList)
	s.interProcPaths = taint.AnalyzeInterProc(s.astList, s.cg, s.graph, s.entryPoints,
		taint.Options{MaxDepth: e.Cfg.Precision.InterProcMaxDepth})
	s.reachableFiles = reachableFileSet(s.cg, s.entryPoints)
	e.prog().Done("interproc")
	e.logf("interproc: %d entrypoints, %d nodes, %d edges, %d taint paths",
		len(s.entryPoints), len(s.cg.Nodes), len(s.cg.Edges()), len(s.interProcPaths))
	return nil
}

func stageSymExpand(_ context.Context, _ *Engine, s *runState) error {
	s.expander = symexpand.New(s.astList)
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

func stageChunk(_ context.Context, e *Engine, s *runState) error {
	s.prioritized = applyPlan(s.files, s.plan)
	var chunks []types.FileTarget
	if e.Cfg.Scan.Chunk.Enabled {
		opts := chunker.AdaptiveOptions{
			TargetTokens:  e.Cfg.Scan.Chunk.TargetTokens,
			MaxTokens:     e.Cfg.Scan.Chunk.MaxTokens,
			MinTokens:     e.Cfg.Scan.Chunk.MinTokens,
			FallbackLines: e.Cfg.Scan.Chunk.FallbackLines,
		}
		for _, f := range s.prioritized {
			fa := s.astByPath[f.Path]
			if fa == nil {
				// Fallback to legacy chunker when AST is missing (binary, parse fail).
				chunks = append(chunks, util.ChunkFile(f, e.Cfg.Scan.ChunkLines, e.Cfg.Scan.ChunkOverlap)...)
				continue
			}
			adaptive := chunker.ChunkAdaptive(fa, opts)
			if len(adaptive) == 0 {
				chunks = append(chunks, util.ChunkFile(f, e.Cfg.Scan.ChunkLines, e.Cfg.Scan.ChunkOverlap)...)
				continue
			}
			chunks = append(chunks, adaptive...)
		}
		e.logf("chunker: adaptive (target=%d max=%d min=%d) → %d chunks across %d files",
			opts.TargetTokens, opts.MaxTokens, opts.MinTokens, len(chunks), len(s.prioritized))
	} else {
		for _, f := range s.prioritized {
			chunks = append(chunks, util.ChunkFile(f, e.Cfg.Scan.ChunkLines, e.Cfg.Scan.ChunkOverlap)...)
		}
		e.logf("scanning %d chunks across %d files", len(chunks), len(s.prioritized))
	}
	s.chunks = chunks
	return nil
}

// stageBuildContextPacks assembles a contextpack.Pack for each chunk and
// implements the overflow feedback loop: when a chunk's pack signals
// Overflow=true (chunk_tokens > budget * OverflowRatio), the chunk is split
// in half and packs are rebuilt for each half. The loop is bounded to avoid
// pathological re-splitting (max 4 rounds).
func stageBuildContextPacks(ctx context.Context, e *Engine, s *runState) error {
	cfg := buildContextpackConfig(e.Cfg)
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("context-pack: invalid config: %w", err)
	}
	builder := contextpack.New(cfg, s.astByPath, s.cg, s.graph)
	if s.index != nil && cfg.RAGTopK > 0 {
		builder.RAG = s.index
	}
	s.cpBuilder = builder

	e.prog().Stage("context-pack", len(s.chunks))

	const maxRounds = 4
	cacheDB := s.cacheDB
	cacheEnabled := e.Cfg.Scan.Context.Cache && cacheDB != nil

	type work struct {
		chunks []types.FileTarget // queue
	}
	q := work{chunks: append([]types.FileTarget(nil), s.chunks...)}

	outChunks := make([]types.FileTarget, 0, len(q.chunks))
	outPacks := make(map[string]*contextpack.Pack, len(q.chunks))

	var (
		totalFragments  int
		totalTokensSent int
		tokenSamples    []int
		overflowCount   int
		rechunks        int
		cacheHits       int
		totalSqueezed   int
		totalDropped    int
	)

	for round := 0; round < maxRounds && len(q.chunks) > 0; round++ {
		next := q.chunks[:0]
		for _, c := range q.chunks {
			var pack contextpack.Pack
			hit := false
			key := chunkPackKey(c)
			if cacheEnabled {
				if payload, ok := cacheDB.GetContextPack(builder.CacheKeyFor(c)); ok {
					if p, err := contextpack.DecodePack(payload); err == nil {
						pack = p
						hit = true
						cacheHits++
					}
				}
			}
			if !hit {
				pack = builder.Build(ctx, c)
				if cacheEnabled && !pack.Overflow {
					if payload, err := contextpack.EncodePack(pack); err == nil {
						_ = cacheDB.PutContextPack(builder.CacheKeyFor(c), payload)
					}
				}
			}

			if pack.Overflow && round+1 < maxRounds && c.Lines > 4 {
				// Split chunk and re-queue for next round.
				overflowCount++
				rechunks++
				left, right := chunker.SplitInHalf(c)
				next = append(next, left, right)
				e.logf("context-pack: overflow on %s:%d-%d (%s) → split",
					c.Path, c.LineOffset+1, c.LineOffset+c.Lines, pack.OverflowReason)
				continue
			}
			if pack.Overflow {
				overflowCount++
				e.logf("context-pack: overflow on %s:%d-%d (kept, max splits reached)",
					c.Path, c.LineOffset+1, c.LineOffset+c.Lines)
			}
			outChunks = append(outChunks, c)
			p := pack
			outPacks[key] = &p
			totalFragments += len(pack.Fragments)
			totalTokensSent += pack.UsedTokens
			tokenSamples = append(tokenSamples, pack.UsedTokens)
			totalSqueezed += pack.Squeezed
			totalDropped += pack.Dropped
			e.prog().Inc("context-pack", 1)
		}
		q.chunks = next
	}

	// Anything left in the queue after maxRounds: emit as-is, packs assembled
	// with overflow flag preserved so the operator sees in logs/stats.
	for _, c := range q.chunks {
		pack := builder.Build(ctx, c)
		outChunks = append(outChunks, c)
		k := chunkPackKey(c)
		p := pack
		outPacks[k] = &p
		totalFragments += len(pack.Fragments)
		totalTokensSent += pack.UsedTokens
		tokenSamples = append(tokenSamples, pack.UsedTokens)
		totalSqueezed += pack.Squeezed
		totalDropped += pack.Dropped
	}

	s.chunks = outChunks
	s.cpStats = types.ContextPackStats{
		Packs:            len(outChunks),
		SqueezedChunks:   totalSqueezed,
		DroppedFragments: totalDropped,
		Rechunks:         rechunks,
		CacheHits:        cacheHits,
	}
	if n := len(outChunks); n > 0 {
		s.cpStats.AvgFragments = float64(totalFragments) / float64(n)
		s.cpStats.AvgTokensSent = float64(totalTokensSent) / float64(n)
		s.cpStats.OverflowRate = float64(overflowCount) / float64(n+overflowCount)
		s.cpStats.P95TokensSent = percentileInt(tokenSamples, 95)
	}
	s.report.Stats.ContextPack = &s.cpStats

	// Stash on scanContext (will be set during dag-build).
	s.scanCtx.packsByChunkKey = outPacks

	e.prog().Done("context-pack")
	e.logf("context-pack: %d packs, avg frags=%.1f avg tokens=%.0f overflow=%d rechunks=%d cache_hits=%d",
		len(outChunks), s.cpStats.AvgFragments, s.cpStats.AvgTokensSent,
		overflowCount, rechunks, cacheHits)
	return nil
}

func buildContextpackConfig(c config.Config) contextpack.Config {
	var base contextpack.Config
	switch strings.ToLower(c.Scan.Context.Level) {
	case "minimal":
		base = contextpack.MinimalConfig()
	case "aggressive":
		base = contextpack.AggressiveConfig()
	case "extreme":
		base = contextpack.ExtremeConfig()
	default:
		base = contextpack.DefaultConfig()
	}
	if b := c.AutoContextBudget(""); b > 0 {
		base.BudgetTokens = b
	}
	cc := c.Scan.Context
	if cc.CalleesHops > 0 {
		base.CalleesHops = cc.CalleesHops
	}
	if cc.CalleesMax > 0 {
		base.CalleesMax = cc.CalleesMax
	}
	if cc.CallersHops > 0 {
		base.CallersHops = cc.CallersHops
	}
	if cc.CallersMax > 0 {
		base.CallersMax = cc.CallersMax
	}
	if cc.IncludeTypes != nil {
		base.IncludeTypes = *cc.IncludeTypes
	}
	if cc.TypesMax > 0 {
		base.TypesMax = cc.TypesMax
	}
	if cc.IncludeSanitizers != nil {
		base.IncludeSanitizers = *cc.IncludeSanitizers
	}
	if cc.SanitizersMax > 0 {
		base.SanitizersMax = cc.SanitizersMax
	}
	if cc.IncludeSiblings != nil {
		base.IncludeSiblings = *cc.IncludeSiblings
	}
	if cc.SiblingsMax > 0 {
		base.SiblingsMax = cc.SiblingsMax
	}
	if cc.RAGTopK > 0 {
		base.RAGTopK = cc.RAGTopK
	}
	if cc.IncludeConsts != nil {
		base.IncludeConsts = *cc.IncludeConsts
	}
	if cc.ConstsMax > 0 {
		base.ConstsMax = cc.ConstsMax
	}
	if cc.SqueezeHeadLines > 0 {
		base.SqueezeHeadLines = cc.SqueezeHeadLines
	}
	if cc.SqueezeTailLines > 0 {
		base.SqueezeTailLines = cc.SqueezeTailLines
	}
	if cc.OverflowRatio > 0 {
		base.OverflowRatio = cc.OverflowRatio
	}
	return base
}

// percentileInt returns the (approximate) p-th percentile of xs (0<p<100).
func percentileInt(xs []int, p int) int {
	if len(xs) == 0 {
		return 0
	}
	copyXs := append([]int(nil), xs...)
	sort.Ints(copyXs)
	idx := (p * (len(copyXs) - 1)) / 100
	if idx < 0 {
		idx = 0
	}
	if idx >= len(copyXs) {
		idx = len(copyXs) - 1
	}
	return copyXs[idx]
}

func stageBuildDAG(_ context.Context, e *Engine, s *runState) error {
	s.enabledScanners = e.enabledScanners(s.plan, s.skillByName, s.files)
	sc := scanContext{
		chunks:          s.chunks,
		contentByPath:   map[string]string{},
		index:           s.index,
		expander:        s.expander,
		taintTraces:     s.taintTraces,
		interProcPaths:  s.interProcPaths,
		deps:            s.graph.AsFileMap(),
		suppress:        s.suppressions,
		packsByChunkKey: s.scanCtx.packsByChunkKey,
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
		idx := reach.Build(s.astList, s.graph.CallersByFile())
		if s.reachableFiles != nil {
			idx.SetCallGraphReachable(s.reachableFiles)
		}
		if down := idx.Apply(final); down > 0 {
			e.logf("reachability: downgraded %d findings", down)
		}
	}
	attachTraces(final, s.taintTraces)
	attachInterProc(final, s.interProcPaths)
	final = e.runDeepPass(ctx, s.target, s.cacheDB, final)
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

func (e *Engine) discoverFiles(target string) ([]types.FileTarget, error) {
	opts := util.WalkOptions{
		ScopeRoots:     e.Cfg.Scan.ScopeRoots,
		MaxFiles:       e.Cfg.Scan.MaxFiles,
		Include:        e.Cfg.Scan.Include,
		Exclude:        e.Cfg.Scan.Exclude,
		MaxBytes:       e.Cfg.Scan.MaxFileBytes,
		FollowSymlinks: e.Cfg.Scan.FollowSymlinks,
	}
	files, err := util.WalkScoped(target, opts)
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	if len(files) > 0 {
		return files, nil
	}
	// Single-file fallback when walk turned up nothing.
	info, ierr := os.Stat(target)
	if ierr != nil || info.IsDir() {
		return files, nil
	}
	lang := util.LanguageOf(target)
	if lang == "" {
		lang = "text"
	}
	b, _ := os.ReadFile(target)
	return []types.FileTarget{{
		Path: target, Language: lang, Content: string(b),
		Lines: strings.Count(string(b), "\n") + 1,
	}}, nil
}

func (e *Engine) openCacheDB() cache.Cache {
	if !e.Cfg.Cache.Enabled {
		return nil
	}
	path := e.Cfg.Cache.Path
	if path == "" {
		path = ".llmscan/cache.db"
	}
	c, err := cache.Open(path)
	if err != nil {
		e.logf("cache disabled: %v", err)
		return nil
	}
	return c
}

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

// applyPlan reorders files: prioritized first (in plan order), then the rest.
func applyPlan(files []types.FileTarget, plan types.ScanPlan) []types.FileTarget {
	if len(plan.Priority) == 0 {
		return files
	}
	priorityIdx := map[string]int{}
	for i, p := range plan.Priority {
		priorityIdx[p] = i
	}
	type pair struct {
		idx int
		f   types.FileTarget
	}
	prio := make([]pair, 0, len(files))
	rest := make([]types.FileTarget, 0)
	for _, f := range files {
		if i, ok := priorityIdx[f.Path]; ok {
			prio = append(prio, pair{i, f})
		} else {
			rest = append(rest, f)
		}
	}
	sort.Slice(prio, func(i, j int) bool { return prio[i].idx < prio[j].idx })
	out := make([]types.FileTarget, 0, len(files))
	for _, p := range prio {
		out = append(out, p.f)
	}
	out = append(out, rest...)
	return out
}

// dedupAndCount removes findings with identical (agent, file, span, title) keys.
func dedupAndCount(in []types.Finding) []types.Finding {
	seen := map[string]bool{}
	out := make([]types.Finding, 0, len(in))
	for _, f := range in {
		key := fmt.Sprintf("%s|%s|%d|%d|%s", f.Agent, f.File, f.StartLine, f.EndLine, f.Title)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// reachableFileSet collects the set of files containing any node reachable
// from the union of all entry points.
func reachableFileSet(cg *callgraph.CallGraph, eps []entrypoints.Info) map[string]bool {
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

// attachInterProc attaches matching inter-procedural TaintPath info to findings.
// When a path's sink line is near a finding's span, the finding gets the path's
// Hops as Trace, the interproc-taint tag, and a small confidence bump.
func attachInterProc(final []types.Finding, paths []taint.TaintPath) {
	if len(paths) == 0 {
		return
	}
	for i := range final {
		f := &final[i]
		if tp := taint.MatchPath(paths, f.File, f.StartLine, f.EndLine); tp != nil {
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
