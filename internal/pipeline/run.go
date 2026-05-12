package pipeline

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/baseline"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/entrypoints"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/reach"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/util"
)

// Run executes the full pipeline on `target` (file or directory).
//
//nolint:gocyclo // sequential pipeline stages; flat is intentional
func (e *Engine) Run(ctx context.Context, target string) (types.Report, error) {
	report := types.Report{
		Target:    target,
		StartedAt: time.Now(),
		Stats:     types.Stats{BySeverity: map[string]int{}, ByAgent: map[string]int{}},
	}

	// 0) Open AST cache (best-effort; falls back to nil = no cache).
	if e.Cfg.ASTCache.Enabled {
		path := e.Cfg.ASTCache.Path
		if path == "" {
			path = ".llmscan/ast-cache.db"
		}
		if c, err := myast.OpenCache(path); err != nil {
			e.logf("ast cache: %v (continuing without cache)", err)
		} else {
			e.astCache = c
			if e.Cfg.ASTCache.Clear {
				if err := c.Clear(); err != nil {
					e.logf("ast cache clear: %v", err)
				}
			}
			defer func() {
				st := c.Stats()
				e.logf("ast cache: hits=%d misses=%d stores=%d errors=%d", st.Hits, st.Misses, st.Stores, st.Errors)
				_ = c.Close()
			}()
		}
	}

	// 1) Discover files.
	files, err := e.discoverFiles(target)
	if err != nil {
		return report, err
	}
	if e.Cfg.Diff.Range != "" {
		files = e.applyDiffFilter(ctx, files, target)
		e.logf("diff %q: %d files in scope", e.Cfg.Diff.Range, len(files))
	}
	report.FilesScanned = len(files)
	e.logf("discovered %d files", len(files))

	// 2) Parse ASTs and build dependency graph.
	astByPath, astList := e.parseASTs(ctx, files)
	e.logf("parsed AST for %d files", len(astList))
	graph := depgraph.New(target, astList)
	if graph.HasCycle() {
		e.logf("note: dependency graph contains cycles")
	}

	// 3) Pre-filters and lightweight static analyses.
	if e.Cfg.Precision.PreFilterWatchlist {
		before := len(files)
		files = e.applyWatchlistPreFilter(files, astByPath)
		e.logf("watchlist pre-filter: %d -> %d files", before, len(files))
	}
	suppressions := e.collectSuppressions(files)
	var taintTraces map[string][]taint.Trace
	if e.Cfg.Precision.Taint {
		taintTraces = taint.Analyze(astList)
		e.logf("taint: %d files analyzed", len(taintTraces))
	}

	// 3a) Inter-procedural taint (call-graph + function summaries + IFDS-light).
	var (
		cg             *callgraph.CallGraph
		entryPoints    []entrypoints.Info
		interProcPaths []taint.TaintPath
		reachableFiles map[string]bool
	)
	if e.Cfg.Precision.Taint && e.Cfg.Precision.InterProc {
		cg = callgraph.Build(astList, graph)
		entryPoints = entrypoints.Detect(astList)
		interProcPaths = taint.AnalyzeInterProc(astList, cg, graph, entryPoints,
			taint.Options{MaxDepth: e.Cfg.Precision.InterProcMaxDepth})
		reachableFiles = reachableFileSet(cg, entryPoints)
		e.logf("interproc: %d entrypoints, %d nodes, %d edges, %d taint paths",
			len(entryPoints), len(cg.Nodes), len(cg.Edges()), len(interProcPaths))
	}
	var expander *symexpand.Expander
	if e.Cfg.Precision.SymbolExpansion {
		expander = symexpand.New(astList)
	}
	var prefilterFindings []types.Finding
	if e.Cfg.Precision.SecretsPreFilter {
		prefilterFindings = e.runSecretsPreFilter(files)
		e.logf("secrets pre-filter: %d deterministic findings", len(prefilterFindings))
	}

	// 4) Skills + orchestrator plan.
	skillByName := e.loadSkills()
	plan, perr := e.planStep(ctx, target, files, graph)
	if perr != nil {
		e.logf("orchestrator: %v (using fallback plan)", perr)
	}
	report.Plan = plan

	// 5) Optional RAG + cache.
	var index *rag.Index
	if e.Cfg.RAG.Enabled {
		index = e.buildRAG(ctx, files, astByPath)
	}
	cdb := e.openCacheDB()
	if cdb != nil {
		defer cdb.Close()
	}

	// 6) Build chunk queue.
	prioritized := applyPlan(files, plan)
	var chunks []types.FileTarget
	for _, f := range prioritized {
		chunks = append(chunks, util.ChunkFile(f, e.Cfg.Scan.ChunkLines, e.Cfg.Scan.ChunkOverlap)...)
	}
	e.logf("scanning %d chunks across %d files", len(chunks), len(prioritized))

	// 7) Assemble DAG.
	enabledScanners := e.enabledScanners(plan, skillByName, files)
	sc := scanContext{
		chunks:         chunks,
		contentByPath:  map[string]string{},
		index:          index,
		expander:       expander,
		taintTraces:    taintTraces,
		interProcPaths: interProcPaths,
		deps:           graph.AsFileMap(),
		suppress:       suppressions,
	}
	for _, f := range prioritized {
		sc.contentByPath[f.Path] = f.Content
	}
	d, err := e.buildDAG(enabledScanners, skillByName, sc)
	if err != nil {
		return report, fmt.Errorf("dag build: %w", err)
	}
	e.logf("DAG layers: %v", d.Layers())

	// 8) Execute. DAG-level parallelism gates the number of scanner *agents*
	// running concurrently; per-chunk parallelism is gated separately inside
	// each scanner node via Scan.Concurrency.
	agentPar := e.Cfg.Scan.AgentParallel
	if agentPar <= 0 {
		agentPar = max(len(enabledScanners), 4)
	}
	outputs, dagErrs := d.Run(ctx, agentPar)
	for name, err := range dagErrs {
		e.logf("dag node %s: %v", name, err)
	}

	// 9) Collect final findings + post-processing.
	final := pickFinalFindings(outputs, &report)
	final = append(final, prefilterFindings...)
	e.applySuppressions(final, suppressions)
	if e.Cfg.Precision.Reachability {
		idx := reach.Build(astList, graph.CallersByFile())
		if reachableFiles != nil {
			idx.SetCallGraphReachable(reachableFiles)
		}
		if down := idx.Apply(final); down > 0 {
			e.logf("reachability: downgraded %d findings", down)
		}
	}
	attachTraces(final, taintTraces)
	attachInterProc(final, interProcPaths)
	// Optional sub-agent deep pass runs BEFORE dropByPolicy so that findings
	// the deep agent refutes are filtered out via the standard FP path.
	final = e.runDeepPass(ctx, target, cdb, final)
	// Resolve final Confidence from all collected signals (scanner, verifier,
	// deep, taint, secrets, reach). This must run AFTER deep so that confirmed
	// hotspots are not stuck at the value reach.Apply forced earlier.
	if n := applyConfidence(final); n > 0 {
		e.logf("confidence: updated %d findings", n)
	}
	final = e.dropByPolicy(final, &report)
	final = e.applyBaseline(cdb, final)

	for _, f := range final {
		report.Stats.BySeverity[string(f.Severity)]++
		report.Stats.ByAgent[f.Agent]++
	}
	types.SortFindings(final)
	report.Findings = final
	report.FinishedAt = time.Now()
	return report, nil
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

func (e *Engine) openCacheDB() *cache.DB {
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

func (e *Engine) applyBaseline(cdb *cache.DB, final []types.Finding) []types.Finding {
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
