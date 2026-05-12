package pipeline

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/util"
)

// stages returns the ordered pipeline. Adding a step here is the only place
// callers need to touch; runtime gating is handled by each stage's skip().
//
// Stage implementations live in stages_static.go (deterministic analysers),
// stages_chunk.go (chunking + context-pack assembly), and stages_scan.go
// (LLM DAG build / run / post-process).
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
		{name: "secrets-prefilter",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Precision.SecretsPreFilter },
			run:  stageSecretsPrefilter},
		{name: "orchestrator", run: stageOrchestrator},
		{name: "rag",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.RAG.Enabled },
			run:  stageRAG},
		{name: "cache", run: stageOpenCache},
		{name: "chunk", run: stageChunk},
		{name: "context-pack", run: stageBuildContextPacks},
		{name: "dag-build", run: stageBuildDAG},
		{name: "scanners", run: stageRunDAG},
		{name: "post-process", run: stagePostProcess},
		{name: "write-knowledge",
			skip: func(e *Engine, _ *runState) bool { return !e.Cfg.Precision.KnowledgeMemory },
			run:  stageWriteKnowledge},
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

// discoverFiles walks the target with the configured scope and falls back to
// reading the target as a single file when the walk produces nothing.
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

// openCacheDB opens the persistent SQLite cache or returns nil when disabled
// or unreachable.
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
