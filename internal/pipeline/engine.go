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

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/rag"
	"github.com/andrewaeva/llmscan/internal/suppress"
	"github.com/andrewaeva/llmscan/internal/symexpand"
	"github.com/andrewaeva/llmscan/internal/taint"
	"github.com/andrewaeva/llmscan/internal/types"
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

// scanContext aggregates per-scan data the DAG nodes need.
type scanContext struct {
	chunks         []types.FileTarget
	contentByPath  map[string]string
	index          *rag.Index
	expander       *symexpand.Expander
	taintTraces    map[string][]taint.Trace
	interProcPaths []taint.TaintPath
	deps           map[string][]string
	suppress       []suppress.Suppression
}

func (e *Engine) logf(format string, args ...any) {
	if e.Logger != nil {
		e.Logger.Printf(format, args...)
	}
}
