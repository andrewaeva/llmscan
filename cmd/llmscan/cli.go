package main

import (
	"os"
	"strings"

	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/types"
)

// openOutput returns either os.Stdout (with a no-op closer) or a freshly-created
// file. The caller must defer the returned close function.
func openOutput(path string) (*os.File, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	fh, err := os.Create(path)
	if err != nil {
		return nil, func() error { return nil }, err
	}
	return fh, fh.Close, nil
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

// applyFlagOverrides merges scanFlags into cfg. Split by concern for readability:
// model selection -> scan -> RAG/skills -> precision -> v3 IO (diff/baseline/cache).
func applyFlagOverrides(cfg *config.Config, f *scanFlags) {
	applyModelOverrides(cfg, f)
	applyScanOverrides(cfg, f)
	applyRAGAndSkillsOverrides(cfg, f)
	applyFocusOverrides(cfg, f)
	applyPrecisionOverrides(cfg, f)
	applyIOOverrides(cfg, f)
	applySpeedOverrides(cfg, f)
	applyDeepOverrides(cfg, f)
}

func applyDeepOverrides(cfg *config.Config, f *scanFlags) {
	if f.deep {
		cfg.Deep.Enabled = true
	}
	if f.deepSeverity != "" {
		cfg.Deep.MinSeverity = strings.ToLower(f.deepSeverity)
	}
	if f.deepMaxHotspots > 0 {
		cfg.Deep.MaxHotspots = f.deepMaxHotspots
	}
	if f.deepBudget > 0 {
		cfg.Deep.Budget = f.deepBudget
	}
	if f.deepConc > 0 {
		cfg.Deep.Concurrency = f.deepConc
	}
	if f.deepModel != "" {
		cfg.Deep.Model = f.deepModel
	}
	if f.deepProvider != "" {
		cfg.Deep.Provider = f.deepProvider
	}
	if f.deepNoCache {
		cfg.Deep.Cache = false
	}
}

func applyModelOverrides(cfg *config.Config, f *scanFlags) {
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
}

func applyScanOverrides(cfg *config.Config, f *scanFlags) {
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
}

func applyRAGAndSkillsOverrides(cfg *config.Config, f *scanFlags) {
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
}

var scannerAgentNames = []string{"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic"}

func applyFocusOverrides(cfg *config.Config, f *scanFlags) {
	if len(f.focus) == 0 {
		return
	}
	set := map[string]bool{}
	for _, x := range f.focus {
		set[strings.TrimSpace(x)] = true
	}
	for _, name := range scannerAgentNames {
		ac := cfg.Agents[name]
		ac.Enabled = set[name]
		if ac.Model.Model == "" {
			ac.Model = config.ModelSpec{}
		}
		cfg.Agents[name] = ac
	}
}

func applySpeedOverrides(cfg *config.Config, f *scanFlags) {
	if f.fast {
		f.noOrchestrator = true
		f.noVerifier = true
		f.noFPFilter = true
		if f.concurrency == 0 {
			cfg.Scan.Concurrency = 16
		}
	}
	disable := func(name string) {
		ac := cfg.Agents[name]
		ac.Enabled = false
		cfg.Agents[name] = ac
	}
	if f.noOrchestrator {
		disable("orchestrator")
	}
	if f.noVerifier {
		disable("verifier")
	}
	if f.noFPFilter {
		disable("fp_filter")
	}
}

func applyPrecisionOverrides(cfg *config.Config, f *scanFlags) {
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
	if f.noInterproc {
		cfg.Precision.InterProc = false
	}
	if f.interprocMaxDepth > 0 {
		cfg.Precision.InterProcMaxDepth = f.interprocMaxDepth
	}
	if f.minScore > 0 {
		cfg.Precision.MinScore = f.minScore
	}
	if f.calibrationPath != "" {
		cfg.Precision.CalibrationPath = f.calibrationPath
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
}

func applyIOOverrides(cfg *config.Config, f *scanFlags) {
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
	if f.cachePath != "" {
		cfg.Cache.Path = f.cachePath
		cfg.Cache.Enabled = true
	}
	if f.noCache {
		cfg.Cache.Enabled = false
	}
	applyMonorepoOverrides(cfg, f)
}

// applyMonorepoOverrides wires --vcs, --scope-root, --max-files and the
// --ast-cache-* family into the config tree.
func applyMonorepoOverrides(cfg *config.Config, f *scanFlags) {
	if f.vcsKind != "" {
		cfg.Scan.VCS = f.vcsKind
	}
	if len(f.scopeRoots) > 0 {
		cfg.Scan.ScopeRoots = append(cfg.Scan.ScopeRoots, f.scopeRoots...)
	}
	// 0 means "unlimited" on the CLI for ergonomics; only override when set >0.
	if f.maxFiles > 0 {
		cfg.Scan.MaxFiles = f.maxFiles
	}
	if f.astCachePath != "" {
		cfg.ASTCache.Path = f.astCachePath
		cfg.ASTCache.Enabled = true
	}
	if f.noASTCache {
		cfg.ASTCache.Enabled = false
	}
	if f.astCacheClr {
		cfg.ASTCache.Clear = true
	}
}
