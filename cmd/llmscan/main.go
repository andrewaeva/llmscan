// Command llmscan is the CLI entrypoint for the LLM-based multi-agent code security scanner.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/eval"
	"github.com/andrewaeva/llmscan/internal/harness"
	"github.com/andrewaeva/llmscan/internal/pipeline"
	"github.com/andrewaeva/llmscan/internal/report"
	"github.com/andrewaeva/llmscan/internal/types"
)

var version = "0.3.0"

func main() {
	root := &cobra.Command{
		Use:           "llmscan",
		Short:         "LLM-based multi-agent code security scanner",
		Long:          "llmscan inspects a codebase with a hierarchy of specialized LLM agents: Orchestrator -> Scanner agents (DAG) -> Verifier -> FP-filter. v3 adds watchlist pre-filter, secrets pre-filter, taint analysis, reachability, structured JSON output, sqlite cache, baseline/diff mode, IaC scanners, voting, and evaluation harness.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(scanCmd())
	root.AddCommand(initConfigCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(harnessCmd())
	root.AddCommand(evalCmd())
	root.AddCommand(benchCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("llmscan", version)
		},
	}
}

// scanFlags groups CLI flags for the scan command (kept compact to avoid 20-arg functions).
type scanFlags struct {
	cfgPath, outPath, format                    string
	model, provider, verifModel, fpModel        string
	concurrency                                 int
	keepFP, verbose                             bool
	include, exclude, focus                     []string
	failOn, projectCtx                          string
	ragEnabled                                  bool
	ragProvider, ragModel                       string
	skillsDirs                                  []string

	// v3
	diffRange, baseline, baselineWrite          string
	noWatchlist, noSymexpand, noTaint, noReach  bool
	noSecretsPF                                 bool
	minScore                                    float64
	voteN, voteK                                int
	jsonRetries                                 int
	cachePath                                   string
	noCache                                     bool
}

func scanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if _, err := os.Stat(target); err != nil {
				return fmt.Errorf("target not accessible: %w", err)
			}
			cfg, err := config.Load(f.cfgPath)
			if err != nil {
				return err
			}
			applyFlagOverrides(&cfg, f)

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			eng := pipeline.New(cfg)
			eng.Verbose = f.verbose
			rep, err := eng.Run(ctx, target)
			if err != nil {
				return err
			}

			out := os.Stdout
			if f.outPath != "" {
				fh, ferr := os.Create(f.outPath)
				if ferr != nil {
					return ferr
				}
				defer fh.Close()
				out = fh
			}

			switch strings.ToLower(f.format) {
			case "json":
				if err := report.WriteJSON(out, rep); err != nil {
					return err
				}
			case "sarif":
				if err := report.WriteSARIF(out, rep); err != nil {
					return err
				}
			default:
				if err := report.WriteText(out, rep); err != nil {
					return err
				}
			}

			if f.failOn != "" {
				if shouldFail(rep, f.failOn) {
					os.Exit(2)
				}
			}
			return nil
		},
	}

	// Base flags (v1/v2).
	cmd.Flags().StringVarP(&f.cfgPath, "config", "c", "", "Path to YAML config")
	cmd.Flags().StringVarP(&f.outPath, "output", "o", "", "Output file (default stdout)")
	cmd.Flags().StringVarP(&f.format, "format", "f", "text", "Output format: text | json | sarif")
	cmd.Flags().StringVar(&f.model, "model", "", "Default LLM model (overrides config)")
	cmd.Flags().StringVar(&f.provider, "provider", "", "Default LLM provider: openai | anthropic")
	cmd.Flags().StringVar(&f.verifModel, "verifier-model", "", "Override model for verifier agent")
	cmd.Flags().StringVar(&f.fpModel, "fp-model", "", "Override model for FP-filter agent")
	cmd.Flags().IntVarP(&f.concurrency, "concurrency", "j", 0, "Parallel LLM calls (default 4)")
	cmd.Flags().BoolVar(&f.keepFP, "keep-fp", false, "Keep findings marked as false positives in the output")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Verbose logging")
	cmd.Flags().StringSliceVar(&f.include, "include", nil, "Include filename globs (e.g. '*.go')")
	cmd.Flags().StringSliceVar(&f.exclude, "exclude", nil, "Exclude patterns (substring match)")
	cmd.Flags().StringSliceVar(&f.focus, "focus", nil, "Limit scanner agents (subset of: injection,secrets,auth,crypto,deserialization,ssrf,generic)")
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
	cmd.Flags().BoolVar(&f.noSymexpand, "no-symexpand", false, "Disable symbol expansion (cross-function context via depgraph)")
	cmd.Flags().BoolVar(&f.noTaint, "no-taint", false, "Disable taint analysis (source -> sanitizer -> sink chains)")
	cmd.Flags().BoolVar(&f.noReach, "no-reachability", false, "Disable reachability downgrade (test/dead code)")
	cmd.Flags().BoolVar(&f.noSecretsPF, "no-secrets-prefilter", false, "Disable regex+entropy secrets pre-filter")
	cmd.Flags().Float64Var(&f.minScore, "min-score", 0.0, "Drop findings with Score below threshold (0..1)")
	cmd.Flags().IntVar(&f.voteN, "vote-n", 0, "Self-consistency voting: run scanners N times (0 disables)")
	cmd.Flags().IntVar(&f.voteK, "vote-k", 0, "Self-consistency voting: keep findings present in K of N runs (default ceil(N/2))")
	cmd.Flags().IntVar(&f.jsonRetries, "json-retries", -1, "Structured-output retries on schema failure (default 2)")
	cmd.Flags().StringVar(&f.cachePath, "cache-path", "", "Override sqlite cache path (default .llmscan/cache.db)")
	cmd.Flags().BoolVar(&f.noCache, "no-cache", false, "Disable sqlite cache entirely")
	return cmd
}

func harnessCmd() *cobra.Command {
	var (
		out, id, name, image, target, cfg, failOn string
	)
	cmd := &cobra.Command{
		Use:   "harness-step",
		Short: "Emit a Harness CI/STO pipeline step that runs llmscan and ingests SARIF",
		RunE: func(cmd *cobra.Command, args []string) error {
			w := os.Stdout
			if out != "" {
				fh, err := os.Create(out)
				if err != nil {
					return err
				}
				defer fh.Close()
				w = fh
			}
			return harness.WriteStepYAML(w, harness.StepOptions{
				Identifier: id, Name: name, Image: image,
				TargetPath: target, ConfigPath: cfg, FailOn: failOn,
			})
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "Output file (default stdout)")
	cmd.Flags().StringVar(&id, "id", "llmscan_sast", "Harness step identifier")
	cmd.Flags().StringVar(&name, "name", "LLM SAST", "Display name")
	cmd.Flags().StringVar(&image, "image", "ghcr.io/andrewaeva/llmscan:latest", "Container image with llmscan")
	cmd.Flags().StringVar(&target, "target", ".", "Target path inside the workspace")
	cmd.Flags().StringVar(&cfg, "config", "", "Optional llmscan.yaml path inside the container")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Severity threshold for failing the pipeline")
	return cmd
}

func evalCmd() *cobra.Command {
	var (
		adapter, datasetPath, target, cfgPath, outPath, format string
		verbose                                                bool
	)
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Run llmscan against a labeled dataset and compute precision/recall/F1",
		Long: "eval loads ground-truth labels via a local adapter and runs the scanner against the target codebase. " +
			"Adapters: owasp-benchmark, securityeval, juliet, generic. No network downloads are performed.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if adapter == "" || datasetPath == "" || target == "" {
				return fmt.Errorf("eval requires --adapter, --dataset-path, and --target")
			}
			labels, err := eval.LoadLabels(adapter, datasetPath)
			if err != nil {
				return fmt.Errorf("load labels: %w", err)
			}
			if len(labels) == 0 {
				return fmt.Errorf("dataset %q yielded zero labels", datasetPath)
			}

			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			eng := pipeline.New(cfg)
			eng.Verbose = verbose
			rep, err := eng.Run(ctx, target)
			if err != nil {
				return err
			}
			metrics := eval.Compare(rep.Findings, labels)

			out := os.Stdout
			if outPath != "" {
				fh, ferr := os.Create(outPath)
				if ferr != nil {
					return ferr
				}
				defer fh.Close()
				out = fh
			}
			switch strings.ToLower(format) {
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(metrics)
			default:
				eval.PrintReport(metrics)
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&adapter, "adapter", "", "Dataset adapter: owasp-benchmark | securityeval | juliet | generic")
	cmd.Flags().StringVar(&datasetPath, "dataset-path", "", "Local path to dataset (file or directory)")
	cmd.Flags().StringVar(&target, "target", "", "Codebase path to scan (usually the dataset code root)")
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "", "Path to llmscan.yaml")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "Output file (default stdout)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | json")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	return cmd
}

func initConfigCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a sample llmscan.yaml to the current directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				path = "llmscan.yaml"
			}
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists", path)
			}
			return os.WriteFile(path, []byte(sampleConfig), 0o644)
		},
	}
	cmd.Flags().StringVarP(&path, "path", "p", "llmscan.yaml", "Where to write the sample config")
	return cmd
}

func applyFlagOverrides(cfg *config.Config, f *scanFlags) {
	if f.model != "" {
		cfg.DefaultModel.Model = f.model
	}
	if f.provider != "" {
		cfg.DefaultModel.Provider = f.provider
		cfg.DefaultModel.APIKeyEnv = "" // re-derive in ResolveModel
	}
	if f.verifModel != "" {
		ac := cfg.Agents["verifier"]
		ac.Enabled = true
		ac.Model.Model = f.verifModel
		if f.provider != "" {
			ac.Model.Provider = f.provider
		}
		cfg.Agents["verifier"] = ac
	}
	if f.fpModel != "" {
		ac := cfg.Agents["fp_filter"]
		ac.Enabled = true
		ac.Model.Model = f.fpModel
		if f.provider != "" {
			ac.Model.Provider = f.provider
		}
		cfg.Agents["fp_filter"] = ac
	}
	if f.concurrency > 0 {
		cfg.Scan.Concurrency = f.concurrency
	}
	if f.keepFP {
		cfg.DropFalsePositives = false
	}
	if len(f.include) > 0 {
		cfg.Scan.Include = f.include
	}
	if len(f.exclude) > 0 {
		cfg.Scan.Exclude = append(cfg.Scan.Exclude, f.exclude...)
	}
	if f.projectCtx != "" {
		cfg.ProjectContext = f.projectCtx
	}
	if f.ragEnabled {
		cfg.RAG.Enabled = true
	}
	if f.ragProvider != "" {
		cfg.RAG.Provider = f.ragProvider
		cfg.RAG.Enabled = true
	}
	if f.ragModel != "" {
		cfg.RAG.Model = f.ragModel
	}
	if len(f.skillsDirs) > 0 {
		cfg.Skills.Dirs = append(cfg.Skills.Dirs, f.skillsDirs...)
	}
	if len(f.focus) > 0 {
		set := map[string]bool{}
		for _, x := range f.focus {
			set[strings.TrimSpace(x)] = true
		}
		for _, name := range []string{"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic"} {
			ac := cfg.Agents[name]
			ac.Enabled = set[name]
			if ac.Model.Model == "" {
				ac.Model = config.ModelSpec{}
			}
			cfg.Agents[name] = ac
		}
	}

	// v3 overrides.
	if f.diffRange != "" {
		cfg.Diff.Range = f.diffRange
	}
	if f.baseline != "" {
		cfg.Baseline.Path = f.baseline
	}
	if f.baselineWrite != "" {
		cfg.Baseline.Path = f.baselineWrite
		cfg.Baseline.Write = true
	}
	if f.noWatchlist {
		cfg.Precision.PreFilterWatchlist = false
	}
	if f.noSymexpand {
		cfg.Precision.SymbolExpansion = false
	}
	if f.noTaint {
		cfg.Precision.Taint = false
	}
	if f.noReach {
		cfg.Precision.Reachability = false
	}
	if f.noSecretsPF {
		cfg.Precision.SecretsPreFilter = false
	}
	if f.minScore > 0 {
		cfg.Precision.MinScore = f.minScore
	}
	if f.voteN > 0 {
		cfg.Precision.VoteN = f.voteN
	}
	if f.voteK > 0 {
		cfg.Precision.VoteK = f.voteK
	}
	if f.jsonRetries >= 0 {
		cfg.Precision.JSONRetries = f.jsonRetries
	}
	if f.cachePath != "" {
		cfg.Cache.Path = f.cachePath
		cfg.Cache.Enabled = true
	}
	if f.noCache {
		cfg.Cache.Enabled = false
	}
}

// shouldFail returns true if the report contains at least one finding with severity >= threshold.
func shouldFail(rep types.Report, threshold string) bool {
	rank := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	t, ok := rank[strings.ToLower(threshold)]
	if !ok {
		return false
	}
	for _, fnd := range rep.Findings {
		if fnd.FalsePositive {
			continue
		}
		if rank[strings.ToLower(string(fnd.Severity))] >= t {
			return true
		}
	}
	return false
}

const sampleConfig = `# llmscan sample configuration (v3)
default_model:
  provider: openai          # openai | anthropic
  model: gpt-4o-mini
  temperature: 0.1
  max_tokens: 4096
  # base_url: https://api.openai.com/v1   # optional, e.g. for OpenAI-compatible endpoints
  # api_key_env: OPENAI_API_KEY

agents:
  orchestrator:
    enabled: true
    # model: { provider: anthropic, model: claude-3-5-sonnet-latest }
  injection:       { enabled: true }
  secrets:         { enabled: true }
  auth:            { enabled: true }
  crypto:          { enabled: true }
  deserialization: { enabled: true }
  ssrf:            { enabled: true }
  generic:         { enabled: true }

  verifier:
    enabled: true
    # Use a stronger model for verification.
    model:
      provider: anthropic
      model: claude-3-5-sonnet-latest
      api_key_env: ANTHROPIC_API_KEY

  fp_filter:
    enabled: true

drop_false_positives: true

scan:
  max_file_bytes: 262144
  chunk_lines: 350
  chunk_overlap: 30
  concurrency: 4
  exclude:
    - .git/
    - node_modules/
    - vendor/
    - dist/
    - build/
    - target/
    - "*.min.js"
    - "*.lock"

# v3: precision controls. All on by default except voting.
precision:
  pre_filter_watchlist: true   # per-language sources/sinks gate; files with zero hits skip LLM
  symbol_expansion:    true    # attach 1-2 hop function definitions to scanner context
  sym_expand_hops:     1
  sym_expand_max:      4
  taint:               true    # source -> sanitizer -> sink chain detection (5 languages)
  reachability:        true    # downgrade findings in test/dead code
  secrets_pre_filter:  true    # regex + Shannon entropy secrets detector
  json_retries:        2       # structured-output retry loop on schema validation failures
  vote_n:              0       # self-consistency voting (>=2 to enable)
  vote_k:              0       # majority threshold (default ceil(N/2))
  min_score:           0.0     # drop findings below score threshold (0..1)

# v3: incremental scanning via git.
# diff:
#   range: "origin/main...HEAD"
#   include_rev_deps: false

# v3: sqlite-backed cache (embeddings + RAG chunks + baseline). Pure-Go (modernc.org/sqlite).
cache:
  enabled: true
  path: .llmscan/cache.db

# v3: baseline mode — suppress findings already in baseline.db.
# baseline:
#   path: .llmscan/baseline.db
#   write: false               # set true to refresh baseline with current run

project_context: |
  Internal microservice. Prefer high signal: only report exploitable issues with a real taint source.
`
