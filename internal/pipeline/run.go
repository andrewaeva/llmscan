package pipeline

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/baseline"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/reach"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/util"
)

// Run executes the full pipeline on `target` (file or directory).
func (e *Engine) Run(ctx context.Context, target string) (types.Report, error) {
	report := types.Report{
		Target:    target,
		StartedAt: time.Now(),
		Stats:     types.Stats{BySeverity: map[string]int{}, ByAgent: map[string]int{}},
	}

	// 1) Discover files.
	files, err := e.discoverFiles(target)
	if err != nil {
		return report, err
	}
	if e.Cfg.Diff.Range != "" {
		files = e.applyDiffFilter(files, target)
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
		chunks:        chunks,
		contentByPath: map[string]string{},
		index:         index,
		expander:      expander,
		taintTraces:   taintTraces,
		deps:          graph.AsFileMap(),
		suppress:      suppressions,
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
		if down := reach.Build(astList, graph.CallersByFile()).Apply(final); down > 0 {
			e.logf("reachability: downgraded %d findings", down)
		}
	}
	attachTraces(final, taintTraces)
	// Optional sub-agent deep pass runs BEFORE dropByPolicy so that findings
	// the deep agent refutes are filtered out via the standard FP path.
	final = e.runDeepPass(ctx, target, cdb, final)
	final = e.dropByPolicy(final, &report)
	final = e.applyBaseline(cdb, final)

	for _, f := range final {
		report.Stats.BySeverity[string(f.Severity)]++
		report.Stats.ByAgent[f.Agent]++
	}
	report.Findings = final
	report.FinishedAt = time.Now()
	return report, nil
}

func (e *Engine) discoverFiles(target string) ([]types.FileTarget, error) {
	files, err := util.Walk(target, e.Cfg.Scan.Include, e.Cfg.Scan.Exclude, e.Cfg.Scan.MaxFileBytes, e.Cfg.Scan.FollowSymlinks)
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
			final[i].Sanitizer = tr.Sanitizer
		}
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
