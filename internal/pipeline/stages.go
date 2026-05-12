package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/andrewaeva/llmscan/internal/agents"
	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/fewshot"
	"github.com/andrewaeva/llmscan/internal/iac"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/secrets"
	"github.com/andrewaeva/llmscan/internal/skills"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/vcs"
	"github.com/andrewaeva/llmscan/internal/watchlist"
)

// ---- AST parsing & skills loading ----

// parseASTs concurrently parses files into per-language ASTs.
// Hits the on-disk AST cache (when enabled) keyed by content sha256+lang.
func (e *Engine) parseASTs(ctx context.Context, files []types.FileTarget) (map[string]*myast.FileAST, []*myast.FileAST) {
	out := make(map[string]*myast.FileAST, len(files))
	var mu sync.Mutex
	var wg sync.WaitGroup
	conc := e.Cfg.Scan.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	cache := e.astCache // may be nil → no-op
	for _, f := range files {
		lang := myast.Detect(f.Path)
		if lang == myast.LangUnknown {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(f types.FileTarget, lang myast.Language) {
			defer wg.Done()
			defer func() { <-sem }()
			src := []byte(f.Content)
			if cached, ok, _ := cache.Lookup(f.Path, src, lang); ok && cached != nil {
				mu.Lock()
				out[f.Path] = cached
				mu.Unlock()
				return
			}
			a, err := myast.Parse(ctx, f.Path, src)
			if err != nil {
				e.logf("ast %s: %v", f.Path, err)
				return
			}
			if err := cache.Store(a); err != nil {
				e.logf("ast cache store %s: %v", f.Path, err)
			}
			mu.Lock()
			out[f.Path] = a
			mu.Unlock()
		}(f, lang)
	}
	wg.Wait()
	list := make([]*myast.FileAST, 0, len(out))
	for _, a := range out {
		list = append(list, a)
	}
	return out, list
}

// loadSkills loads all enabled scanner skills from configured directories.
// Special-purpose skills (folders prefixed with "_") are intentionally
// excluded — fetch them with loadSpecialSkill.
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

// loadFewShotBanks builds the per-skill few-shot example registry by scanning
// skills/<name>/examples/*.json across every configured skills dir.
// Returns a non-nil Banks even if no examples were found, so callers can
// safely call .Bank() without nil checks.
func (e *Engine) loadFewShotBanks() *fewshot.Banks {
	b := fewshot.New()
	errs := b.LoadFromSkillDirs(e.Cfg.Skills.Dirs)
	for _, err := range errs {
		e.logf("fewshot: %v", err)
	}
	if names := b.SkillNames(); len(names) > 0 && e.Verbose {
		e.logf("fewshot: loaded banks for %d skill(s): %v", len(names), names)
	}
	return b
}

// loadSpecialSkill resolves a special skill (folder starts with "_") across
// every configured skills dir and returns the first prompt body it finds.
// Returns "" when no skill is present, so callers can fall back to the
// built-in default prompt.
func (e *Engine) loadSpecialSkill(dirName string) string {
	for _, dir := range e.Cfg.Skills.Dirs {
		sk, err := skills.LoadSpecial(dir, dirName)
		if err != nil {
			e.logf("special skill %s in %s: %v", dirName, dir, err)
			continue
		}
		if sk != nil && sk.Prompt != "" {
			return sk.Prompt
		}
	}
	return ""
}

// ---- Pre-filters and lightweight static analyses ----

// applyDiffFilter narrows files to those changed in the configured diff range.
// VCS is selected automatically (git/arc) based on filesystem markers; the
// range may carry an explicit "git:" / "arc:" prefix to force a backend.
func (e *Engine) applyDiffFilter(ctx context.Context, files []types.FileTarget, target string) []types.FileTarget {
	rangeSpec, forced := vcs.SplitRange(e.Cfg.Diff.Range)
	// An explicit --vcs flag overrides auto-detection.
	if forced == vcs.KindNone {
		switch e.Cfg.Scan.VCS {
		case "git":
			forced = vcs.KindGit
		case "arc":
			forced = vcs.KindArc
		case "none":
			forced = vcs.KindNone
		}
	}
	var (
		v   vcs.VCS
		err error
	)
	switch {
	case e.Cfg.Scan.VCS == "none" && forced == vcs.KindNone:
		e.logf("diff: --vcs=none, skipping")
		return files
	case forced != vcs.KindNone:
		// Honor the prefix even if auto-detection would have chosen something
		// else (e.g. a repo with both .git and .arc, or scanning a sub-tree).
		detected, _ := vcs.Detect(target)
		root := target
		if detected != nil && detected.Kind() == forced {
			root = detected.Root()
		}
		v, err = vcs.Open(forced, root)
	default:
		v, err = vcs.Detect(target)
	}
	if err != nil || v == nil || v.Kind() == vcs.KindNone {
		e.logf("diff: no VCS detected at %s, ignoring --diff", target)
		return files
	}
	changed, err := v.ChangedFiles(ctx, rangeSpec)
	if err != nil {
		e.logf("diff (%s): %v", v.Kind(), err)
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

// applyWatchlistPreFilter drops files unlikely to contain taint sources/sinks.
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

// collectSuppressions extracts all // llmscan:ignore directives from source.
func (e *Engine) collectSuppressions(files []types.FileTarget) []suppress.Suppression {
	all := make([]suppress.Suppression, 0, len(files))
	for _, f := range files {
		all = append(all, suppress.Parse(f.Path, f.Content)...)
	}
	return all
}

// runSecretsPreFilter performs deterministic secret detection before any LLM call.
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

// ---- Orchestrator plan + RAG index ----

// planStep asks the orchestrator agent for a scan plan, with graph-derived fallback.
func (e *Engine) planStep(ctx context.Context, target string, files []types.FileTarget, g *depgraph.Graph) (types.ScanPlan, error) {
	if !e.Cfg.IsAgentEnabled("orchestrator") {
		fp := fallbackPlan(files, g)
		e.logf("orchestrator: disabled, focus=all (%d agents)", len(fp.Focus))
		return fp, nil
	}
	client, err := llm.New(e.Cfg.ResolveModel("orchestrator"))
	if err != nil {
		fp := fallbackPlan(files, g)
		e.logf("orchestrator: %v (using fallback plan, focus=all %d agents)", err, len(fp.Focus))
		return fp, err
	}
	orch := &agents.Orchestrator{Client: client}
	plan, err := orch.Plan(ctx, target, files, e.Cfg.ProjectContext)
	if err != nil {
		fp := fallbackPlan(files, g)
		e.logf("orchestrator: %v (using fallback plan, focus=all %d agents)", err, len(fp.Focus))
		return fp, err
	}
	// Safety net: if planner narrowed focus too aggressively for a non-trivial
	// project, expand to the full scanner list. The planner sees only file
	// paths and can miss vulnerability classes that are obvious from content
	// (e.g. deserialization, race conditions, supply-chain).
	minFocus := 3
	if len(files) >= 50 && len(plan.Focus) > 0 && len(plan.Focus) < minFocus {
		e.logf("orchestrator: focus too narrow (%d agents on %d files) -> expanding to all %d",
			len(plan.Focus), len(files), len(agents.ScannerNames))
		plan.Focus = append([]string{}, agents.ScannerNames...)
	} else {
		e.logf("orchestrator: focus=%v (%d/%d agents)", plan.Focus, len(plan.Focus), len(agents.ScannerNames))
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

// fallbackPlan builds a graph-based priority when the orchestrator is unavailable.
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

// buildRAG initializes the RAG index, falling back to keyword search if no embedder available.
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

// skillUsesReflexion reports whether the given scanner name is listed in
// precision.reflexion_skills. An empty list means "apply to all enabled
// scanners".
func (e *Engine) skillUsesReflexion(name string) bool {
	list := e.Cfg.Precision.ReflexionSkills
	if len(list) == 0 {
		return true
	}
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}
