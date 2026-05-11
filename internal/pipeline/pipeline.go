// Package pipeline runs the full multi-agent scan as a validated DAG.
//
// High-level flow:
//
//	discover -> parse AST -> build depgraph -> orchestrator plan
//	          -> build RAG index (optional) -> chunk targets
//	          -> DAG: [context_filter] -> [scanner agents in parallel]
//	                  -> [dedup] -> [verifier] -> [fp_filter] -> report
//
// Every cross-agent dependency is expressed in the DAG so layers can run in
// parallel safely. The DAG is validated for cycles/missing deps before run.
package pipeline

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andrewaeva/llmscan/internal/agents"
	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/baseline"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/dag"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/gitdiff"
	"github.com/andrewaeva/llmscan/internal/iac"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/reach"
	"github.com/andrewaeva/llmscan/internal/secrets"
	"github.com/andrewaeva/llmscan/internal/skills"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/util"
	"github.com/andrewaeva/llmscan/internal/voting"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// Engine drives a single scan.
type Engine struct {
	Cfg     config.Config
	Logger  *log.Logger
	Verbose bool
}

// New returns an engine wired with a default logger.
func New(cfg config.Config) *Engine {
	return &Engine{Cfg: cfg, Logger: log.New(os.Stderr, "[llmscan] ", log.LstdFlags)}
}

// Run executes the full pipeline on `target` (file or directory).
func (e *Engine) Run(ctx context.Context, target string) (types.Report, error) {
	report := types.Report{
		Target:    target,
		StartedAt: time.Now(),
		Stats:     types.Stats{BySeverity: map[string]int{}, ByAgent: map[string]int{}},
	}

	// 1) Discover files.
	files, err := util.Walk(target, e.Cfg.Scan.Include, e.Cfg.Scan.Exclude, e.Cfg.Scan.MaxFileBytes, e.Cfg.Scan.FollowSymlinks)
	if err != nil {
		return report, fmt.Errorf("walk: %w", err)
	}
	if len(files) == 0 {
		if info, ierr := os.Stat(target); ierr == nil && !info.IsDir() {
			lang := util.LanguageOf(target)
			if lang == "" {
				lang = "text"
			}
			b, _ := os.ReadFile(target)
			files = []types.FileTarget{{
				Path: target, Language: lang, Content: string(b),
				Lines: strings.Count(string(b), "\n") + 1,
			}}
		}
	}
	// 1b) Apply --diff filter (PR mode) BEFORE AST parsing.
	if e.Cfg.Diff.Range != "" {
		files = e.applyDiffFilter(files, target)
		e.logf("diff %q: %d files in scope", e.Cfg.Diff.Range, len(files))
	}
	report.FilesScanned = len(files)
	e.logf("discovered %d files", len(files))

	// 2) Parse ASTs in parallel.
	astByPath, astList := e.parseASTs(ctx, files)
	e.logf("parsed AST for %d files", len(astList))

	// 3) Build dependency graph from imports.
	graph := depgraph.New(target, astList)
	if graph.HasCycle() {
		e.logf("note: dependency graph contains cycles")
	}

	// 3a) Watchlist pre-filter: drop files with zero source/sink hits (huge token saver).
	if e.Cfg.Precision.PreFilterWatchlist {
		before := len(files)
		files = e.applyWatchlistPreFilter(files, astByPath)
		e.logf("watchlist pre-filter: %d -> %d files", before, len(files))
	}

	// 3b) Suppression markers across all files.
	suppressions := e.collectSuppressions(files)

	// 3c) Lightweight taint traces (per-file).
	var taintTraces map[string][]taint.Trace
	if e.Cfg.Precision.Taint {
		taintTraces = taint.Analyze(astList)
		e.logf("taint: %d files analyzed", len(taintTraces))
	}

	// 3d) Symbol-expansion index.
	var expander *symexpand.Expander
	if e.Cfg.Precision.SymbolExpansion {
		expander = symexpand.New(astList)
	}

	// 3e) Deterministic secrets pre-filter.
	var prefilterFindings []types.Finding
	if e.Cfg.Precision.SecretsPreFilter {
		prefilterFindings = e.runSecretsPreFilter(files)
		e.logf("secrets pre-filter: %d deterministic findings", len(prefilterFindings))
	}

	// 4) Skills: load SKILL.md from configured dirs (if any) and merge with built-ins.
	skillByName := e.loadSkills()

	// 5) Orchestrator plan.
	plan, perr := e.planStep(ctx, target, files, graph)
	if perr != nil {
		e.logf("orchestrator: %v (using fallback plan)", perr)
	}
	report.Plan = plan

	// 6) Build RAG index (optional).
	var index *rag.Index
	if e.Cfg.RAG.Enabled {
		index = e.buildRAG(ctx, files, astByPath)
	}

	// 6a) Open cache (sqlite) for embeddings + baseline if enabled.
	var cdb *cache.DB
	if e.Cfg.Cache.Enabled {
		path := e.Cfg.Cache.Path
		if path == "" {
			path = ".llmscan/cache.db"
		}
		if c2, err := cache.Open(path); err == nil {
			cdb = c2
			defer cdb.Close()
		} else {
			e.logf("cache disabled: %v", err)
		}
	}

	// 7) Build prioritized chunk queue.
	prioritized := applyPlan(files, plan)
	var chunks []types.FileTarget
	for _, f := range prioritized {
		chunks = append(chunks, util.ChunkFile(f, e.Cfg.Scan.ChunkLines, e.Cfg.Scan.ChunkOverlap)...)
	}
	e.logf("scanning %d chunks across %d files", len(chunks), len(prioritized))

	// 8) Build the agent DAG.
	enabledScanners := e.enabledScanners(plan, skillByName, files)
	depsMap := graph.AsFileMap()
	scanCtx := scanContext{
		chunks:       chunks,
		contentByPath: map[string]string{},
		index:        index,
		expander:     expander,
		taintTraces:  taintTraces,
		deps:         depsMap,
		suppress:     suppressions,
	}
	for _, f := range prioritized {
		scanCtx.contentByPath[f.Path] = f.Content
	}
	d, err := e.buildDAG(enabledScanners, skillByName, scanCtx)
	if err != nil {
		return report, fmt.Errorf("dag build: %w", err)
	}
	e.logf("DAG layers: %v", d.Layers())

	// 9) Execute.
	outputs, dagErrs := d.Run(ctx, e.Cfg.Scan.Concurrency)
	for name, err := range dagErrs {
		e.logf("dag node %s: %v", name, err)
	}

	// 10) Collect final findings from the fp_filter node.
	final, _ := outputs["fp_filter"].([]types.Finding)
	if final == nil {
		// fall back to verifier output if fp_filter failed
		final, _ = outputs["verifier"].([]types.Finding)
	}
	rawTotal := 0
	if raw, ok := outputs["scan_aggregate"].([]types.Finding); ok {
		rawTotal = len(raw)
		report.Stats.Raw = rawTotal
	}
	if dedup, ok := outputs["dedup"].([]types.Finding); ok {
		report.Stats.AfterDedup = len(dedup)
	}
	if verified, ok := outputs["verifier"].([]types.Finding); ok {
		report.Stats.AfterVerify = len(verified)
	}

	// Merge deterministic pre-filter findings into the final set.
	final = append(final, prefilterFindings...)

	// Apply suppression markers across all findings.
	if len(suppressions) > 0 {
		suppCount := 0
		for i := range final {
			if m, ok := suppress.MatchAt(suppressions, final[i].File, final[i].StartLine, final[i].RuleID, final[i].Agent); ok {
				final[i].Suppressed = true
				final[i].SuppressedReason = m.Reason
				suppCount++
			}
		}
		if suppCount > 0 {
			e.logf("suppressed %d findings via in-source markers", suppCount)
		}
	}

	// Reachability downgrade.
	if e.Cfg.Precision.Reachability {
		callersByFile := graph.CallersByFile()
		down := reach.Build(astList, callersByFile).Apply(final)
		if down > 0 {
			e.logf("reachability: downgraded %d findings", down)
		}
	}

	// Attach taint traces to findings on matching file/line.
	if len(taintTraces) > 0 {
		for i := range final {
			if tr := matchTrace(taintTraces[final[i].File], final[i].StartLine, final[i].EndLine); tr != nil {
				final[i].Trace = tr.Hops
				final[i].Sanitizer = tr.Sanitizer
			}
		}
	}

	// Filter by score threshold and FP/suppressed flags.
	minScore := e.Cfg.Precision.MinScore
	drop := func(f types.Finding) bool {
		if f.Suppressed {
			return true
		}
		if e.Cfg.DropFalsePositives && f.FalsePositive {
			report.Stats.FalsePos++
			return true
		}
		if minScore > 0 && f.Score > 0 && f.Score < minScore {
			return true
		}
		return false
	}
	kept := final[:0]
	for _, f := range final {
		if drop(f) {
			continue
		}
		kept = append(kept, f)
	}
	final = kept

	// Baseline diff: drop findings already in baseline, optionally write fresh baseline.
	if cdb != nil && e.Cfg.Baseline.Path != "" {
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
	}

	for _, f := range final {
		report.Stats.BySeverity[string(f.Severity)]++
		report.Stats.ByAgent[f.Agent]++
	}
	report.Findings = final
	report.FinishedAt = time.Now()
	return report, nil
}

// scanContext aggregates per-scan data the DAG nodes need.
type scanContext struct {
	chunks        []types.FileTarget
	contentByPath map[string]string
	index         *rag.Index
	expander      *symexpand.Expander
	taintTraces   map[string][]taint.Trace
	deps          map[string][]string
	suppress      []suppress.Suppression
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

func (e *Engine) applyDiffFilter(files []types.FileTarget, target string) []types.FileTarget {
	if !gitdiff.IsRepo(target) {
		e.logf("diff: %s is not a git repo, ignoring", target)
		return files
	}
	changed, err := gitdiff.ChangedFiles(target, e.Cfg.Diff.Range)
	if err != nil {
		e.logf("diff: %v", err)
		return files
	}
	set := map[string]bool{}
	for _, p := range changed {
		set[p] = true
	}
	var out []types.FileTarget
	for _, f := range files {
		if set[f.Path] {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) applyWatchlistPreFilter(files []types.FileTarget, astByPath map[string]*myast.FileAST) []types.FileTarget {
	var out []types.FileTarget
	for _, f := range files {
		// Always keep IaC and unknown languages (no watchlist coverage).
		if iac.Detect(f.Path, f.Content) != iac.KindNone {
			out = append(out, f)
			continue
		}
		if _, ok := astByPath[f.Path]; !ok {
			out = append(out, f)
			continue
		}
		if watchlist.HasHit(f.Language, f.Content, watchlist.KindSource, watchlist.KindSink) {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) collectSuppressions(files []types.FileTarget) []suppress.Suppression {
	var all []suppress.Suppression
	for _, f := range files {
		all = append(all, suppress.Parse(f.Path, f.Content)...)
	}
	return all
}

func (e *Engine) runSecretsPreFilter(files []types.FileTarget) []types.Finding {
	var out []types.Finding
	for _, f := range files {
		for _, m := range secrets.ScanText(f.Path, f.Content) {
			out = append(out, types.Finding{
				ID:          fmt.Sprintf("secrets-%s-%s:%d", m.RuleID, f.Path, m.Line),
				RuleID:      m.RuleID,
				Title:       m.Title,
				Description: fmt.Sprintf("Pre-filter match (entropy=%.2f, snippet=%s)", m.Entropy, m.Snippet),
				Severity:    types.Severity(m.Severity),
				Confidence:  types.ConfHigh,
				Score:       0.95,
				CWE:         m.CWE,
				File:        f.Path,
				StartLine:   m.Line,
				EndLine:     m.Line,
				CodeSample:  m.Snippet,
				Agent:       "secrets-prefilter",
				Verified:    true,
				Tags:        []string{"secrets", "deterministic"},
				CreatedAt:   time.Now(),
			})
		}
	}
	return out
}

// -------------------------------------------------------------------------------------------------
// Steps
// -------------------------------------------------------------------------------------------------

func (e *Engine) parseASTs(ctx context.Context, files []types.FileTarget) (map[string]*myast.FileAST, []*myast.FileAST) {
	out := make(map[string]*myast.FileAST, len(files))
	var mu sync.Mutex
	var wg sync.WaitGroup
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	for _, f := range files {
		if myast.Detect(f.Path) == myast.LangUnknown {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(f types.FileTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			a, err := myast.Parse(ctx, f.Path, []byte(f.Content))
			if err != nil {
				e.logf("ast %s: %v", f.Path, err)
				return
			}
			mu.Lock()
			out[f.Path] = a
			mu.Unlock()
		}(f)
	}
	wg.Wait()
	list := make([]*myast.FileAST, 0, len(out))
	for _, a := range out {
		list = append(list, a)
	}
	return out, list
}

func (e *Engine) loadSkills() map[string]*skills.Skill {
	out := map[string]*skills.Skill{}
	for _, dir := range e.Cfg.Skills.Dirs {
		s, errs := skills.LoadDir(dir)
		for _, err := range errs {
			e.logf("skill: %v", err)
		}
		for _, sk := range s {
			out[sk.Name] = sk
		}
	}
	return out
}

func (e *Engine) planStep(ctx context.Context, target string, files []types.FileTarget, g *depgraph.Graph) (types.ScanPlan, error) {
	if !e.Cfg.IsAgentEnabled("orchestrator") {
		return fallbackPlan(files, g), nil
	}
	client, err := llm.New(e.Cfg.ResolveModel("orchestrator"))
	if err != nil {
		return fallbackPlan(files, g), err
	}
	orch := &agents.Orchestrator{Client: client}
	plan, err := orch.Plan(ctx, target, files, e.Cfg.ProjectContext)
	if err != nil {
		return fallbackPlan(files, g), err
	}
	// Augment plan: prepend top fan-in files so high-blast-radius modules get scanned first.
	topByFanIn := g.TopRankedByFanIn()
	if len(topByFanIn) > 0 {
		seen := map[string]bool{}
		merged := make([]string, 0, len(plan.Priority)+len(topByFanIn))
		for _, p := range topByFanIn[:min(15, len(topByFanIn))] {
			if !seen[p] {
				merged = append(merged, p)
				seen[p] = true
			}
		}
		for _, p := range plan.Priority {
			if !seen[p] {
				merged = append(merged, p)
				seen[p] = true
			}
		}
		plan.Priority = merged
	}
	return plan, nil
}

func fallbackPlan(files []types.FileTarget, g *depgraph.Graph) types.ScanPlan {
	pri := g.TopRankedByFanIn()
	if len(pri) == 0 {
		pri = make([]string, 0, len(files))
		for _, f := range files {
			pri = append(pri, f.Path)
		}
	}
	return types.ScanPlan{Reasoning: "fallback: orchestrator unavailable", Priority: pri, Focus: agents.ScannerNames}
}

func (e *Engine) buildRAG(ctx context.Context, files []types.FileTarget, astByPath map[string]*myast.FileAST) *rag.Index {
	emb, err := rag.NewEmbedder(rag.EmbedderSpec{
		Provider:  e.Cfg.RAG.Provider,
		Model:     e.Cfg.RAG.Model,
		BaseURL:   e.Cfg.RAG.BaseURL,
		APIKeyEnv: e.Cfg.RAG.APIKeyEnv,
	})
	if err != nil {
		e.logf("rag embedder disabled: %v (RAG falls back to keyword search)", err)
	}
	srcs := map[string][]byte{}
	for _, f := range files {
		srcs[f.Path] = []byte(f.Content)
	}
	chunks := rag.ChunkFiles(srcs, astByPath, e.Cfg.RAG.ChunkLines)
	idx := rag.New(emb)
	if err := idx.Index(ctx, chunks, e.Cfg.RAG.BatchSize); err != nil {
		e.logf("rag index: %v", err)
	}
	e.logf("rag indexed %d chunks (embedder=%v)", idx.Size(), embedderName(emb))
	return idx
}

func embedderName(e rag.Embedder) string {
	if e == nil {
		return "keyword-only"
	}
	return e.Name()
}

// -------------------------------------------------------------------------------------------------
// DAG assembly
// -------------------------------------------------------------------------------------------------

func (e *Engine) enabledScanners(plan types.ScanPlan, skillByName map[string]*skills.Skill, files []types.FileTarget) []string {
	focus := map[string]bool{}
	for _, f := range plan.Focus {
		focus[f] = true
	}
	// Names known to us: built-in scanner names ∪ skills with kind==scanner.
	names := map[string]bool{}
	for _, n := range agents.ScannerNames {
		names[n] = true
	}
	for name, sk := range skillByName {
		if sk.Kind == skills.KindScanner {
			names[name] = true
		}
	}
	// Enable IaC scanners when matching files are present.
	iacAgents := map[string]bool{}
	for _, f := range files {
		if k := iac.Detect(f.Path, f.Content); k != iac.KindNone {
			if a := iac.AgentName(k); a != "" {
				iacAgents[a] = true
			}
		}
	}
	for a := range iacAgents {
		names[a] = true
	}
	var out []string
	for name := range names {
		if !e.Cfg.IsAgentEnabled(name) {
			continue
		}
		if sk, ok := skillByName[name]; ok && !sk.IsEnabled() {
			continue
		}
		if len(focus) > 0 && !focus[name] {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		out = []string{"generic"}
	}
	return out
}

func (e *Engine) buildDAG(scannerNames []string, skillByName map[string]*skills.Skill, sc scanContext) (*dag.DAG, error) {
	chunks := sc.chunks
	contentByPath := sc.contentByPath
	index := sc.index

	// Build LLM clients for each scanner / verifier / fp_filter / context_filter once.
	scannerClients := map[string]llm.Client{}
	scannerPrompts := map[string]string{}
	for _, name := range scannerNames {
		client, err := llm.New(e.Cfg.ResolveModel(name))
		if err != nil {
			e.logf("scanner %s disabled: %v", name, err)
			continue
		}
		scannerClients[name] = client
		if sk, ok := skillByName[name]; ok && sk.Prompt != "" {
			scannerPrompts[name] = sk.Prompt
		}
	}
	if len(scannerClients) == 0 {
		return nil, fmt.Errorf("no scanner agents could be initialized")
	}

	// context_filter (optional)
	var cfilter *agents.ContextFilter
	if e.Cfg.IsAgentEnabled("context_filter") && index != nil {
		if cl, err := llm.New(e.Cfg.ResolveModel("context_filter")); err == nil {
			cfilter = &agents.ContextFilter{Client: cl}
		} else {
			e.logf("context_filter disabled: %v", err)
		}
	}

	// verifier
	var verifier *agents.Verifier
	if e.Cfg.IsAgentEnabled("verifier") {
		if cl, err := llm.New(e.Cfg.ResolveModel("verifier")); err == nil {
			verifier = &agents.Verifier{Client: cl}
		} else {
			e.logf("verifier disabled: %v", err)
		}
	}

	// fp_filter
	var fpFilter *agents.FPFilter
	if e.Cfg.IsAgentEnabled("fp_filter") {
		if cl, err := llm.New(e.Cfg.ResolveModel("fp_filter")); err == nil {
			fpFilter = &agents.FPFilter{Client: cl}
		} else {
			e.logf("fp_filter disabled: %v", err)
			fpFilter = &agents.FPFilter{}
		}
	} else {
		fpFilter = &agents.FPFilter{}
	}

	// ---- Nodes ----

	nodes := []*dag.Node{}

	// One scanner node per agent. Each runs over ALL chunks in parallel internally.
	for _, name := range scannerNames {
		client, ok := scannerClients[name]
		if !ok {
			continue
		}
		nm := name
		cl := client
		promptOverride := scannerPrompts[nm]
		nodes = append(nodes, &dag.Node{
			Name:      "scan:" + nm,
			DependsOn: nil,
			Run: func(ctx context.Context, _ map[string]any) (any, error) {
				return e.runScanner(ctx, nm, cl, promptOverride, chunks, index, cfilter, sc), nil
			},
		})
	}

	// Aggregator collects from every scanner.
	scanDeps := make([]string, 0, len(scannerClients))
	for _, name := range scannerNames {
		if _, ok := scannerClients[name]; ok {
			scanDeps = append(scanDeps, "scan:"+name)
		}
	}
	nodes = append(nodes, &dag.Node{
		Name:      "scan_aggregate",
		DependsOn: scanDeps,
		Run: func(_ context.Context, inputs map[string]any) (any, error) {
			var all []types.Finding
			for _, v := range inputs {
				if fs, ok := v.([]types.Finding); ok {
					all = append(all, fs...)
				}
			}
			return all, nil
		},
	})

	// Deterministic dedup.
	nodes = append(nodes, &dag.Node{
		Name:      "dedup",
		DependsOn: []string{"scan_aggregate"},
		Run: func(_ context.Context, inputs map[string]any) (any, error) {
			fs, _ := inputs["scan_aggregate"].([]types.Finding)
			return dedupAndCount(fs), nil
		},
	})

	// Verifier (per-finding, parallel).
	nodes = append(nodes, &dag.Node{
		Name:      "verifier",
		DependsOn: []string{"dedup"},
		Run: func(ctx context.Context, inputs map[string]any) (any, error) {
			fs, _ := inputs["dedup"].([]types.Finding)
			if verifier == nil {
				return fs, nil
			}
			return e.verifyAll(ctx, verifier, fs, contentByPath), nil
		},
	})

	// FP filter (LLM-judge + deterministic dedup).
	nodes = append(nodes, &dag.Node{
		Name:      "fp_filter",
		DependsOn: []string{"verifier"},
		Run: func(ctx context.Context, inputs map[string]any) (any, error) {
			fs, _ := inputs["verifier"].([]types.Finding)
			out, err := fpFilter.Apply(ctx, fs)
			if err != nil {
				e.logf("fp_filter: %v", err)
				return fs, nil
			}
			return out, nil
		},
	})

	return dag.Build(nodes)
}

// runScanner runs one scanner agent over every chunk in parallel, optionally
// enriching each prompt with RAG-retrieved + context-filtered context.
func (e *Engine) runScanner(ctx context.Context, name string, client llm.Client, promptOverride string, chunks []types.FileTarget, index *rag.Index, cfilter *agents.ContextFilter, sc scanContext) []types.Finding {
	scanner := &agents.Scanner{Name: name, Client: client, PromptOverride: promptOverride}
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []types.Finding

	for _, c := range chunks {
		wg.Add(1)
		sem <- struct{}{}
		go func(c types.FileTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			extra := ""
			// Symbol-expansion: append referenced definitions for high precision.
			if sc.expander != nil {
				defs := sc.expander.Expand(c.Content, c.Path, sc.deps, symexpand.Options{
					Hops:     e.Cfg.Precision.SymExpandHops,
					Max:      e.Cfg.Precision.SymExpandMax,
					MaxLines: 30,
				})
				if len(defs) > 0 {
					var b strings.Builder
					b.WriteString("\n// --- Referenced definitions (symbol-expansion) ---\n")
					for _, d := range defs {
						fmt.Fprintf(&b, "// %s @ %s:%d-%d\n%s\n\n", d.Name, d.File, d.StartLine, d.EndLine, d.Code)
					}
					extra += b.String()
				}
			}
			// Taint traces relevant to this chunk.
			if trs := sc.taintTraces[c.Path]; len(trs) > 0 {
				var b strings.Builder
				b.WriteString("\n// --- Taint traces in this file ---\n")
				for _, t := range trs {
					for _, h := range t.Hops {
						fmt.Fprintf(&b, "//   %s @ %s:%d: %s\n", h.Kind, h.File, h.Line, h.Code)
					}
					b.WriteString("//   ---\n")
				}
				extra += b.String()
			}
			if index != nil {
				// query = first 4 lines of the chunk + the scanner scope
				lines := strings.SplitN(c.Content, "\n", 5)
				head := strings.Join(lines[:min(len(lines), 4)], "\n")
				query := head + "\n\nlooking for: " + name
				cands, err := index.Search(ctx, query, e.Cfg.RAG.TopK)
				if err == nil && len(cands) > 0 {
					// Drop candidates that point to the same chunk we're already analyzing.
					filtered := cands[:0]
					for _, cand := range cands {
						if cand.File == c.Path && cand.StartLine == c.LineOffset+1 {
							continue
						}
						filtered = append(filtered, cand)
					}
					primary := &rag.Chunk{
						ID: c.Path + "#primary", File: c.Path, Text: c.Content,
						StartLine: c.LineOffset + 1, EndLine: c.LineOffset + c.Lines,
					}
					if cfilter != nil {
						filtered, _ = cfilter.Filter(ctx, primary, filtered, name, e.Cfg.RAG.FilterKeep)
					} else if len(filtered) > e.Cfg.RAG.FilterKeep {
						filtered = filtered[:e.Cfg.RAG.FilterKeep]
					}
					extra = agents.FormatChunksAsContext(filtered)
				}
			}

			var fnds []types.Finding
			var err error
			if e.Cfg.Precision.VoteN > 1 {
				runs := make([][]types.Finding, 0, e.Cfg.Precision.VoteN)
				for i := 0; i < e.Cfg.Precision.VoteN; i++ {
					r, rerr := scanner.Scan(ctx, c, extra)
					if rerr != nil {
						e.logf("scan:%s vote%d on %s: %v", name, i, c.Path, rerr)
						continue
					}
					runs = append(runs, r)
				}
				k := e.Cfg.Precision.VoteK
				if k <= 0 {
					k = (e.Cfg.Precision.VoteN / 2) + 1
				}
				fnds = voting.Aggregate(runs, k)
			} else {
				fnds, err = scanner.Scan(ctx, c, extra)
				if err != nil {
					e.logf("scan:%s on %s: %v", name, c.Path, err)
					return
				}
			}
			mu.Lock()
			out = append(out, fnds...)
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return out
}

func (e *Engine) verifyAll(ctx context.Context, v *agents.Verifier, findings []types.Finding, contentByPath map[string]string) []types.Finding {
	if v == nil || v.Client == nil {
		return findings
	}
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	out := make([]types.Finding, len(findings))
	for i, f := range findings {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, f types.Finding) {
			defer wg.Done()
			defer func() { <-sem }()
			snippet := snippetWithLines(contentByPath[f.File], f.StartLine, f.EndLine, 25)
			vf, err := v.Verify(ctx, f, snippet)
			if err != nil {
				e.logf("verifier on %s:%d: %v", f.File, f.StartLine, err)
				out[i] = f
				return
			}
			out[i] = vf
		}(i, f)
	}
	wg.Wait()
	return out
}

func snippetWithLines(content string, start, end, pad int) string {
	if content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	from := start - pad - 1
	to := end + pad
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	var b strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "%5d | %s\n", i+1, lines[i])
	}
	return b.String()
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

func (e *Engine) logf(format string, args ...any) {
	if e.Logger != nil {
		e.Logger.Printf(format, args...)
	}
}
