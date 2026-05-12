package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	myast "github.com/andrewaeva/llmscan/internal/ast"
	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/depgraph"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/pipeline"
	"github.com/andrewaeva/llmscan/internal/progress"
	"github.com/andrewaeva/llmscan/internal/report"
	"github.com/andrewaeva/llmscan/internal/types"
	"github.com/andrewaeva/llmscan/internal/util"
)

// scanFlags groups CLI flags for the scan command (kept compact to avoid 20-arg functions).
type scanFlags struct {
	cfgPath, outPath, format             string
	model, provider, verifModel, fpModel string
	concurrency                          int
	keepFP, verbose                      bool
	include, exclude, focus              []string
	failOn, projectCtx                   string
	ragEnabled                           bool
	ragProvider, ragModel                string
	skillsDirs                           []string

	// v3
	diffRange, baseline, baselineWrite           string
	noWatchlist, noTaint, noReach                bool
	noOrchestrator, noVerifier, noFPFilter, fast bool
	minScore                                     float64
	calibrationPath                              string
	voteN, voteK                                 int
	jsonRetries                                  int
	cachePath                                    string
	noCache                                      bool
	color                                        string
	progressMode                                 string
	noTUI                                        bool
	reportFile                                   string

	// inter-procedural taint
	noInterproc       bool
	interprocMaxDepth int
	showCallGraph     bool

	// --deep sub-agent verification pass.
	deep                                  bool
	deepSeverity                          string
	deepMaxHotspots, deepBudget, deepConc int
	deepModel, deepProvider               string
	deepNoCache                           bool

	// monorepo support
	vcsKind      string
	scopeRoots   []string
	maxFiles     int
	astCachePath string
	noASTCache   bool
	astCacheClr  bool

	// LLM transport (global inflight cap + retry)
	inflightLimit int
}

func scanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a file or directory",
		Args:  cobra.ExactArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runScan(args[0], f) },
	}
	bindScanFlags(cmd, f)
	return cmd
}

func runScan(target string, f *scanFlags) error {
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target not accessible: %w", err)
	}
	cfg, err := config.Load(f.cfgPath)
	if err != nil {
		return err
	}
	applyFlagOverrides(&cfg, f)
	configureLLMTransport(cfg)
	if f.showCallGraph {
		return runShowCallGraph(target, cfg)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	eng := pipeline.New(cfg)
	eng.Verbose = f.verbose

	// Progress UI (TUI on TTY, plain lines in CI/pipes).
	pmode, err := progress.ParseMode(f.progressMode)
	if err != nil {
		return err
	}
	if f.noTUI && pmode != progress.ModeNone {
		pmode = progress.ModePlain
	}
	// Treat stderr OR stdout being non-TTY as "no TUI": stderr is where the
	// TUI draws, but if stdout (where the report lands) is a pipe / file the
	// final report would race the TUI's cursor-up sequences. Plain output is
	// safe in both cases.
	isTTY := progress.IsTerminal(os.Stderr) && progress.IsTerminal(os.Stdout)
	reporter := progress.NewAuto(pmode, os.Stderr, isTTY)
	eng.SetProgress(reporter)

	rep, err := eng.Run(ctx, target)
	// Stop the reporter BEFORE printing the final report so the TUI clears
	// its painted region first. Doing this in a deferred call would let the
	// TUI's cursor-up sequences (lastLines clear) eat the top of the report.
	reporter.Stop()
	if err != nil {
		return err
	}

	out, closeOut, err := openOutput(f.outPath)
	if err != nil {
		return err
	}

	if err := writeReport(out, rep, f.format, f.color); err != nil {
		_ = closeOut()
		return err
	}
	if cerr := closeOut(); cerr != nil {
		return cerr
	}

	// Always persist a copy of the report under <target>/.llmscan/ so the user
	// has a reliable fallback if the terminal scroll-back is clobbered.
	if err := writePersistedReports(target, rep, f.reportFile); err != nil {
		// Persistence is best-effort: log and continue rather than failing
		// the scan over an unwritable directory.
		fmt.Fprintf(os.Stderr, "[llmscan] report: persist failed: %v\n", err)
	}

	if f.failOn != "" && shouldFail(rep, f.failOn) {
		cancel()
		os.Exit(2) //nolint:gocritic // process is exiting; remaining defers (signal ctx cancel) are released above
	}
	return nil
}

// configureLLMTransport installs the process-wide LLM transport policy
// (inflight cap + retry tuning) from config. Idempotent: only the first
// call has effect, so re-runs from tests do not flip the cap.
func configureLLMTransport(cfg config.Config) {
	base := time.Duration(cfg.LLM.RetryBaseDelayMS) * time.Millisecond
	maxD := time.Duration(cfg.LLM.RetryMaxDelayMS) * time.Millisecond
	llm.ConfigureTransport(cfg.LLM.InflightLimit, cfg.LLM.MaxRetries, base, maxD)
}

// writePersistedReports always writes <target>/.llmscan/last-report.{txt,json}
// and, if reportFile is non-empty, also writes the text rendering there.
// All writes are best-effort; a failure on one path does not prevent the
// others from being attempted.
func writePersistedReports(target string, rep types.Report, reportFile string) error {
	dir := filepath.Join(target, ".llmscan")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	txtPath := filepath.Join(dir, "last-report.txt")
	jsonPath := filepath.Join(dir, "last-report.json")

	var txtBuf, jsonBuf bytes.Buffer
	// .llmscan/last-report.txt is read by humans in a plain editor — disable
	// ANSI color escapes so it is grep-friendly and diff-friendly.
	if err := report.WriteTextWith(&txtBuf, rep, report.ColorNever); err != nil {
		return fmt.Errorf("render text: %w", err)
	}
	if err := report.WriteJSON(&jsonBuf, rep); err != nil {
		return fmt.Errorf("render json: %w", err)
	}

	var firstErr error
	writeIf := func(path string, data []byte) {
		if err := os.WriteFile(path, data, 0o644); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("write %s: %w", path, err)
		}
	}
	writeIf(txtPath, txtBuf.Bytes())
	writeIf(jsonPath, jsonBuf.Bytes())

	fmt.Fprintf(os.Stderr, "[llmscan] report: wrote %s (%d KB), %s (%d KB)\n",
		txtPath, (txtBuf.Len()+1023)/1024, jsonPath, (jsonBuf.Len()+1023)/1024)

	if reportFile != "" {
		if err := os.WriteFile(reportFile, txtBuf.Bytes(), 0o644); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("write %s: %w", reportFile, err)
		} else if err == nil {
			fmt.Fprintf(os.Stderr, "[llmscan] report: wrote %s (%d KB)\n",
				reportFile, (txtBuf.Len()+1023)/1024)
		}
	}

	return firstErr
}

// runShowCallGraph parses the target, builds the call graph, and prints it as
// DOT to stdout. Used by the --show-callgraph debug flag.
func runShowCallGraph(target string, cfg config.Config) error {
	files, err := util.Walk(target, cfg.Scan.Include, cfg.Scan.Exclude, cfg.Scan.MaxFileBytes, cfg.Scan.FollowSymlinks)
	if err != nil {
		return fmt.Errorf("walk: %w", err)
	}
	var astList []*myast.FileAST
	for _, f := range files {
		if myast.Detect(f.Path) == myast.LangUnknown {
			continue
		}
		a, perr := myast.Parse(context.Background(), f.Path, []byte(f.Content))
		if perr != nil {
			continue
		}
		astList = append(astList, a)
	}
	graph := depgraph.New(target, astList)
	cg := callgraph.Build(astList, graph)
	fmt.Print(cg.DOT())
	return nil
}

func writeReport(out *os.File, rep types.Report, format, color string) error {
	switch strings.ToLower(format) {
	case "json":
		return report.WriteJSON(out, rep)
	case "sarif":
		return report.WriteSARIF(out, rep)
	default:
		return report.WriteTextWith(out, rep, report.ParseColorMode(color))
	}
}

func bindScanFlags(cmd *cobra.Command, f *scanFlags) {
	// Base flags (v1/v2).
	cmd.Flags().StringVarP(&f.cfgPath, "config", "c", "", "Path to YAML config")
	cmd.Flags().StringVarP(&f.outPath, "output", "o", "", "Output file (default stdout)")
	cmd.Flags().StringVarP(&f.format, "format", "f", "text", "Output format: text | json | sarif")
	cmd.Flags().StringVar(&f.model, "model", "", "Default LLM model (overrides config)")
	cmd.Flags().StringVar(&f.provider, "provider", "", "Default LLM provider: openai | anthropic")
	cmd.Flags().StringVar(&f.verifModel, "verifier-model", "", "Override model for verifier agent")
	cmd.Flags().StringVar(&f.fpModel, "fp-model", "", "Override model for FP-filter agent")
	cmd.Flags().IntVarP(&f.concurrency, "concurrency", "j", 0, "Parallel LLM calls (default 8)")
	cmd.Flags().BoolVar(&f.keepFP, "keep-fp", false, "Keep findings marked as false positives in the output")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Verbose logging")
	cmd.Flags().StringSliceVar(&f.include, "include", nil, "Include filename globs (e.g. '*.go')")
	cmd.Flags().StringSliceVar(&f.exclude, "exclude", nil, "Exclude patterns (substring match)")
	cmd.Flags().StringSliceVar(&f.focus, "focus", nil, "Limit scanner agents (subset of: injection,auth,crypto,deserialization,ssrf,generic)")
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "Exit with code 2 if any finding meets this severity threshold (critical|high|medium|low)")
	cmd.Flags().StringVar(&f.projectCtx, "project-context", "", "Free-form project context passed to the orchestrator")
	cmd.Flags().BoolVar(&f.ragEnabled, "rag", false, "Enable RAG index for context retrieval (sqlite-backed cache by default)")
	cmd.Flags().StringVar(&f.ragProvider, "rag-provider", "", "Embeddings provider: openai | opencode | voyage")
	cmd.Flags().StringVar(&f.ragModel, "rag-model", "", "Embeddings model (e.g. text-embedding-3-small)")
	cmd.Flags().StringSliceVar(&f.skillsDirs, "skills-dir", nil, "Directory with SKILL.md files (repeatable)")

	// v3 flags.
	cmd.Flags().StringVar(&f.diffRange, "diff", "", "Incremental scan: only files changed in git range (e.g. 'origin/main...HEAD')")
	cmd.Flags().StringVar(&f.baseline, "baseline", "", "Path to baseline sqlite DB; suppress findings already present")
	cmd.Flags().StringVar(&f.baselineWrite, "baseline-write", "", "Write current findings to this baseline sqlite DB (e.g. .llmscan/baseline.db)")
	cmd.Flags().BoolVar(&f.noWatchlist, "no-watchlist", false, "Disable per-language source/sink watchlist pre-filter")
	cmd.Flags().BoolVar(&f.noTaint, "no-taint", false, "Disable taint analysis (source -> sanitizer -> sink chains)")
	cmd.Flags().BoolVar(&f.noReach, "no-reachability", false, "Disable reachability downgrade (test/dead code)")
	cmd.Flags().BoolVar(&f.noInterproc, "no-interproc", false, "Disable inter-procedural cross-file taint (fall back to intra-file taint only)")
	cmd.Flags().IntVar(&f.interprocMaxDepth, "interproc-max-depth", 0, "Max hops for inter-procedural taint paths (default 6)")
	cmd.Flags().BoolVar(&f.showCallGraph, "show-callgraph", false, "Print the inter-procedural call graph as DOT and exit (debug)")
	cmd.Flags().Float64Var(&f.minScore, "min-score", 0.0, "Drop findings with Score below threshold (0..1)")
	cmd.Flags().StringVar(&f.calibrationPath, "calibration", "", "Path to isotonic calibration model (from `llmscan eval --calibrate-out`); remaps every Score to empirical TP probability")
	cmd.Flags().StringVar(&f.progressMode, "progress", "auto", "Progress UI: auto | tty | plain | none")
	cmd.Flags().BoolVar(&f.noTUI, "no-tui", false, "Disable the progress TUI (equivalent to --progress=plain); useful for CI and clean logs")
	cmd.Flags().StringVar(&f.reportFile, "report-file", "", "Write the text report to this path in addition to stdout (always written to .llmscan/last-report.txt)")
	cmd.Flags().IntVar(&f.voteN, "vote-n", 0, "Self-consistency voting: run scanners N times (0 disables)")
	cmd.Flags().IntVar(&f.voteK, "vote-k", 0, "Self-consistency voting: keep findings present in K of N runs (default ceil(N/2))")
	cmd.Flags().IntVar(&f.jsonRetries, "json-retries", -1, "Structured-output retries on schema failure (default 2)")
	cmd.Flags().StringVar(&f.cachePath, "cache-path", "", "Override sqlite cache path (default .llmscan/cache.db)")
	cmd.Flags().BoolVar(&f.noCache, "no-cache", false, "Disable sqlite cache entirely")

	// Speed knobs.
	cmd.Flags().BoolVar(&f.noOrchestrator, "no-orchestrator", false, "Skip the LLM planner; use graph-based fallback plan (saves 1 LLM call)")
	cmd.Flags().BoolVar(&f.noVerifier, "no-verifier", false, "Skip the per-finding verifier pass (saves N LLM calls)")
	cmd.Flags().BoolVar(&f.noFPFilter, "no-fp-filter", false, "Skip the LLM false-positive filter (deterministic dedup still runs)")
	cmd.Flags().BoolVar(&f.fast, "fast", false, "Speed preset: no-orchestrator + no-verifier + no-fp-filter + concurrency=16")
	cmd.Flags().StringVar(&f.color, "color", "auto", "Color output for text format: auto | always | never (honors NO_COLOR, CLICOLOR_FORCE)")

	// --deep sub-agent verification (Anthropic + OpenAI Responses API).
	cmd.Flags().BoolVar(&f.deep, "deep", false, "Run a sub-agent verification pass over high-severity findings (supports Anthropic and OpenAI tool-loop)")
	cmd.Flags().StringVar(&f.deepSeverity, "deep-severity", "", "Min severity that triggers deep verification: critical | high | medium (default: high)")
	cmd.Flags().IntVar(&f.deepMaxHotspots, "deep-max-hotspots", 0, "Cap on findings inspected by the sub-agent (default 20)")
	cmd.Flags().IntVar(&f.deepBudget, "deep-budget", 0, "Max tool calls per hotspot (default 40)")
	cmd.Flags().IntVar(&f.deepConc, "deep-concurrency", 0, "Parallel sub-agents (default 4)")
	cmd.Flags().StringVar(&f.deepModel, "deep-model", "", "Override model id for the sub-agent (default: --model)")
	cmd.Flags().StringVar(&f.deepProvider, "deep-provider", "", "Override provider for the sub-agent (default: --provider; supports anthropic and openai)")
	cmd.Flags().BoolVar(&f.deepNoCache, "deep-no-cache", false, "Disable sqlite caching of sub-agent tool outputs (cached by default)")

	// Monorepo flags.
	cmd.Flags().StringVar(&f.vcsKind, "vcs", "", "VCS backend: auto | git | arc | none (default: auto-detect via .git/.arc)")
	cmd.Flags().StringSliceVar(&f.scopeRoots, "scope-root", nil, "Restrict traversal to these sub-paths (repeatable). Absolute or relative to target.")
	cmd.Flags().IntVar(&f.maxFiles, "max-files", 0, "Abort with error if the post-filter file count exceeds this (default 100000; 0 = unlimited)")
	cmd.Flags().StringVar(&f.astCachePath, "ast-cache-path", "", "Override AST cache path (default .llmscan/ast-cache.db)")
	cmd.Flags().BoolVar(&f.noASTCache, "no-ast-cache", false, "Disable the AST parse cache for this run")
	cmd.Flags().BoolVar(&f.astCacheClr, "ast-cache-clear", false, "Wipe the AST cache before scanning")

	// LLM transport.
	cmd.Flags().IntVar(&f.inflightLimit, "inflight-limit", -1, "Max concurrent LLM HTTP requests across all agents (0=unlimited; overrides config). Use when scanning through a rate-limited proxy.")
}
