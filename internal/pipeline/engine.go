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
	"log"
	"os"
	"strconv"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/calibration"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/contextpack"
	"github.com/andrewaeva/llmscan/internal/fewshot"
	"github.com/andrewaeva/llmscan/internal/progress"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Engine drives a single scan.
type Engine struct {
	Cfg     config.Config
	Logger  *log.Logger
	Verbose bool

	// astCache is opened lazily on first use and closed by Run via defer.
	// A nil value is a valid no-op cache, so callers don't need to nil-check.
	astCache *myast.Cache

	// Lazily-loaded isotonic calibration model (see Precision.CalibrationPath).
	calModel         *calibration.Model
	calLoadAttempted bool

	// progress reports stage/chunk events to a UI surface; defaults to no-op.
	progress progress.Reporter
}

// SetProgress installs a progress reporter. Pass nil to silence (no-op).
// Engine takes ownership: callers should not call r.Stop() themselves; that's
// the caller's responsibility because Stop is intentionally not invoked from
// Run so a single reporter can span multiple Engine.Run calls if desired.
func (e *Engine) SetProgress(r progress.Reporter) {
	if r == nil {
		e.progress = &progress.NoopReporter{}
		return
	}
	e.progress = r
}

// prog returns the active reporter, lazily defaulting to Noop.
func (e *Engine) prog() progress.Reporter {
	if e.progress == nil {
		e.progress = &progress.NoopReporter{}
	}
	return e.progress
}

// New returns an engine wired with a default logger.
func New(cfg config.Config) *Engine {
	return &Engine{Cfg: cfg, Logger: log.New(os.Stderr, "[llmscan] ", log.LstdFlags)}
}

// scanContext aggregates per-scan data the DAG nodes need. Per-chunk extra
// context lives in packsByChunkKey (assembled by stageBuildContextPacks).
type scanContext struct {
	chunks          []types.FileTarget
	contentByPath   map[string]string
	index           *rag.Index
	suppress        []suppress.Suppression
	packsByChunkKey map[string]*contextpack.Pack
	// fewshotBanks is the per-skill bank registry. When nil or the skill has
	// no bank, runScanner skips in-context examples. Populated by
	// stageLoadFewShot.
	fewshotBanks *fewshot.Banks
}

// chunkPackKey is the per-chunk key used to look up its ContextPack from
// scanContext.packsByChunkKey. Must match what stageBuildContextPacks writes.
func chunkPackKey(c types.FileTarget) string {
	return c.Path + "#" + strconv.Itoa(c.ChunkIdx) + "@" + strconv.Itoa(c.LineOffset)
}

func (e *Engine) logf(format string, args ...any) {
	if e.Logger != nil {
		e.Logger.Printf(format, args...)
	}
}
