// Package config loads scanner configuration from YAML, environment and CLI.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ModelSpec describes a single LLM model used by an agent.
type ModelSpec struct {
	Provider    string  `yaml:"provider"`              // "openai" | "anthropic"
	Model       string  `yaml:"model"`                 // e.g. "claude-sonnet-4-6", "gpt-4o-mini"
	Temperature float64 `yaml:"temperature,omitempty"` // default 0.1
	MaxTokens   int     `yaml:"max_tokens,omitempty"`  // default 4096
	BaseURL     string  `yaml:"base_url,omitempty"`    // optional override (OpenAI-compatible endpoints)
	APIKeyEnv   string  `yaml:"api_key_env,omitempty"` // env var to read the API key from
	// ContextWindow is the total input-token capacity of the model. When
	// non-zero, the ContextPack auto-budget caps at 0.7 × ContextWindow to
	// leave room for the system prompt and output. Examples: Claude Opus
	// 4.7 = 200000, GPT-5.4 = 272000, Gemini 2.5 Pro = 1000000.
	ContextWindow int `yaml:"context_window,omitempty"`
}

// AgentConfig binds an agent role to a model and a few knobs.
type AgentConfig struct {
	Model      ModelSpec `yaml:"model"`
	Enabled    bool      `yaml:"enabled"`
	MaxRetries int       `yaml:"max_retries,omitempty"`
}

// ScanConfig describes filesystem traversal options.
type ScanConfig struct {
	Include        []string `yaml:"include,omitempty"`
	Exclude        []string `yaml:"exclude,omitempty"`
	MaxFileBytes   int      `yaml:"max_file_bytes,omitempty"`
	Concurrency    int      `yaml:"concurrency,omitempty"`    // chunks in flight per single scanner agent
	AgentParallel  int      `yaml:"agent_parallel,omitempty"` // scanner agents in flight (DAG layer)
	FollowSymlinks bool     `yaml:"follow_symlinks,omitempty"`

	// Monorepo support.
	ScopeRoots []string `yaml:"scope_roots,omitempty"` // restrict traversal to these sub-paths
	MaxFiles   int      `yaml:"max_files,omitempty"`   // abort with error above this count; 0 = unlimited
	VCS        string   `yaml:"vcs,omitempty"`         // auto | git | arc | none

	// Chunk controls the adaptive (token-aware, symbol-grouped) chunker.
	// Context wires the ContextPack builder. Both always run; zero fields fall
	// back to tuned defaults inside the pipeline.
	Chunk   ChunkConfig   `yaml:"chunk,omitempty"`
	Context ContextConfig `yaml:"context,omitempty"`
}

// ChunkConfig controls the adaptive (token-aware, symbol-grouped) chunker.
//
// The pipeline groups consecutive top-level symbols up to TargetTokens,
// hard-caps at MaxTokens, and avoids emitting tail chunks smaller than
// MinTokens. Tuned defaults match 200K-context modern models:
// target = 8000 tokens ≈ 700–1000 LOC of Go.
type ChunkConfig struct {
	TargetTokens  int `yaml:"target_tokens,omitempty"`
	MaxTokens     int `yaml:"max_tokens,omitempty"`
	MinTokens     int `yaml:"min_tokens,omitempty"`
	FallbackLines int `yaml:"fallback_lines,omitempty"`
}

// ContextConfig wires the contextpack builder.
//
// Level is one of "minimal", "balanced", "aggressive", "extreme" (or empty
// for "balanced"). BudgetTokens overrides the level default; 0 = derive from
// ModelSpec.ContextWindow (cap at 0.7 × window).
type ContextConfig struct {
	Level             string  `yaml:"level,omitempty"`
	BudgetTokens      int     `yaml:"budget_tokens,omitempty"`
	CalleesHops       int     `yaml:"callees_hops,omitempty"`
	CalleesMax        int     `yaml:"callees_max,omitempty"`
	CallersHops       int     `yaml:"callers_hops,omitempty"`
	CallersMax        int     `yaml:"callers_max,omitempty"`
	IncludeTypes      *bool   `yaml:"include_types,omitempty"`
	TypesMax          int     `yaml:"types_max,omitempty"`
	IncludeSanitizers *bool   `yaml:"include_sanitizers,omitempty"`
	SanitizersMax     int     `yaml:"sanitizers_max,omitempty"`
	IncludeSiblings   *bool   `yaml:"include_siblings,omitempty"`
	SiblingsMax       int     `yaml:"siblings_max,omitempty"`
	RAGTopK           int     `yaml:"rag_top_k,omitempty"`
	IncludeConsts     *bool   `yaml:"include_consts,omitempty"`
	ConstsMax         int     `yaml:"consts_max,omitempty"`
	SqueezeHeadLines  int     `yaml:"squeeze_head_lines,omitempty"`
	SqueezeTailLines  int     `yaml:"squeeze_tail_lines,omitempty"`
	OverflowRatio     float64 `yaml:"overflow_ratio,omitempty"`
	Cache             bool    `yaml:"cache,omitempty"`
}

// RAGConfig controls the in-memory retrieval index.
type RAGConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Provider   string `yaml:"provider,omitempty"` // openai | opencode | voyage
	Model      string `yaml:"model,omitempty"`    // embedding model
	BaseURL    string `yaml:"base_url,omitempty"`
	APIKeyEnv  string `yaml:"api_key_env,omitempty"`
	TopK       int    `yaml:"top_k,omitempty"`       // candidates per scanner chunk
	FilterKeep int    `yaml:"filter_keep,omitempty"` // after context-filter
	ChunkLines int    `yaml:"chunk_lines,omitempty"` // sliding-window fallback size
	BatchSize  int    `yaml:"batch_size,omitempty"`
}

// SkillsConfig points to one or more directories with SKILL.md files.
type SkillsConfig struct {
	Dirs []string `yaml:"dirs,omitempty"`
}

// PrecisionConfig groups v3 precision/safety toggles.
type PrecisionConfig struct {
	// PreFilterWatchlist skips files with zero source/sink hits from watchlist.
	PreFilterWatchlist bool `yaml:"pre_filter_watchlist"`
	// Taint enables intra-file (and best-effort cross-file) taint tracking.
	Taint bool `yaml:"taint"`
	// Reachability downgrades findings in dead/test code.
	Reachability bool `yaml:"reachability"`
	// VoteN: self-consistency voting (N independent runs, K majority).
	VoteN int `yaml:"vote_n,omitempty"`
	VoteK int `yaml:"vote_k,omitempty"`
	// MinScore filters findings with Score below threshold (0..1).
	MinScore float64 `yaml:"min_score,omitempty"`
	// CalibrationPath points to an isotonic calibration model fitted with
	// `llmscan eval --calibrate-out`. When set, every finding's Score is
	// remapped through the model before --min-score is applied, so the
	// threshold reflects empirical true-positive probability.
	CalibrationPath string `yaml:"calibration_path,omitempty"`
	// JSONRetries for structured-output retry feedback loop.
	JSONRetries int `yaml:"json_retries,omitempty"`
	// SecretsPreFilter enables regex+entropy secret detector before LLM.
	SecretsPreFilter bool `yaml:"secrets_pre_filter"`

	// InterProc enables inter-procedural cross-file taint analysis (call graph
	// + function summaries + IFDS-light fixed-point). Disable with --no-interproc.
	InterProc bool `yaml:"interproc"`
	// InterProcMaxDepth caps TaintPath length (default 6 when zero).
	InterProcMaxDepth int `yaml:"interproc_max_depth,omitempty"`

	// FewShotEnabled appends in-context examples from skills/<name>/examples/
	// to the scanner prompt for each chunk. Off by default; enable per project
	// to lift recall on domain-specific patterns.
	FewShotEnabled bool `yaml:"fewshot,omitempty"`
	// FewShotTopK is the maximum number of examples injected per chunk; 0 -> 3.
	FewShotTopK int `yaml:"fewshot_top_k,omitempty"`

	// PlanVerify swaps the standard one-shot Verifier for a plan-and-execute
	// verifier (planner emits investigation steps; executor uses the same
	// deep-agent toolbox to discharge each step). Off by default.
	PlanVerify bool `yaml:"plan_verify,omitempty"`

	// Reflexion wraps shortlisted scanners in a generate → critique → revise
	// loop. Use ReflexionSkills to restrict the wrapping to noisy skills like
	// authz-bypass / business-state. ReflexionMaxIters caps the iterations
	// (default 1: a single critique-revise round).
	Reflexion         bool     `yaml:"reflexion,omitempty"`
	ReflexionSkills   []string `yaml:"reflexion_skills,omitempty"`
	ReflexionMaxIters int      `yaml:"reflexion_max_iters,omitempty"`

	// KnowledgeMemory enables generation of .llmscan/knowledge.md after a
	// successful scan and reuse of it as project_context on subsequent runs.
	KnowledgeMemory bool `yaml:"knowledge_memory,omitempty"`
}

// DiffConfig configures incremental scanning.
type DiffConfig struct {
	Range          string `yaml:"range,omitempty"`
	IncludeRevDeps bool   `yaml:"include_rev_deps,omitempty"`
}

// CacheConfig points to the sqlite cache file.
type CacheConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path,omitempty"`
}

// ASTCacheConfig controls the AST parse cache used to amortize tree-sitter
// parsing across repeated scans of large repos. Enabled by default; falls
// back to a no-op cache if the on-disk file cannot be created.
type ASTCacheConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path,omitempty"`
	Clear   bool   `yaml:"-"` // CLI-only: wipe before run
}

// BaselineConfig holds baseline I/O settings.
type BaselineConfig struct {
	Path  string `yaml:"path,omitempty"`
	Write bool   `yaml:"write,omitempty"` // overwrite baseline with current findings
}

// DeepConfig controls the optional sub-agent (--deep) pass that verifies and
// deepens high-severity findings via tool-driven inspection of the codebase.
//
// Disabled by default. When enabled, runs after the regular pipeline and only
// against findings at or above MinSeverity, capped at MaxHotspots.
type DeepConfig struct {
	Enabled      bool   `yaml:"enabled,omitempty"`
	MinSeverity  string `yaml:"min_severity,omitempty"`   // critical | high | medium
	MaxHotspots  int    `yaml:"max_hotspots,omitempty"`   // hard cap; default 20
	Budget       int    `yaml:"budget,omitempty"`         // max tool calls per hotspot; default 40
	Concurrency  int    `yaml:"concurrency,omitempty"`    // parallel sub-agents; default 4
	Cache        bool   `yaml:"cache,omitempty"`          // cache tool outputs in sqlite; default true
	Model        string `yaml:"model,omitempty"`          // override LLM model id (empty = use default)
	Provider     string `yaml:"provider,omitempty"`       // override provider (empty = use default)
	MaxFileBytes int    `yaml:"max_file_bytes,omitempty"` // sandbox guard; default 512 KiB
}

// Config is the full configuration tree.
type Config struct {
	// Default model used when an agent does not override it.
	DefaultModel ModelSpec `yaml:"default_model"`

	// Per-agent overrides. Keys: orchestrator, injection, secrets, auth, crypto, deserialization, ssrf, generic, verifier, fp_filter, context_filter.
	Agents map[string]AgentConfig `yaml:"agents,omitempty"`

	// Verifier behavior.
	VerifierConfidenceThreshold Confidence `yaml:"verifier_min_confidence,omitempty"`
	DropFalsePositives          bool       `yaml:"drop_false_positives,omitempty"`

	Scan      ScanConfig      `yaml:"scan"`
	RAG       RAGConfig       `yaml:"rag"`
	Skills    SkillsConfig    `yaml:"skills"`
	Precision PrecisionConfig `yaml:"precision"`
	Diff      DiffConfig      `yaml:"diff"`
	Cache     CacheConfig     `yaml:"cache"`
	ASTCache  ASTCacheConfig  `yaml:"ast_cache"`
	Baseline  BaselineConfig  `yaml:"baseline"`
	Deep      DeepConfig      `yaml:"deep"`

	// Free-form context that gets injected into agent prompts.
	ProjectContext string `yaml:"project_context,omitempty"`
}

// Confidence (string alias to avoid import cycles with types).
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// Default returns a sensible baseline configuration.
func Default() Config {
	return Config{
		DefaultModel: ModelSpec{ //nolint:gosec // APIKeyEnv holds the env var *name*, not a credential
			Provider:    "anthropic",
			Model:       "claude-sonnet-4-6",
			Temperature: 0.1,
			MaxTokens:   4096,
			APIKeyEnv:   "ANTHROPIC_API_KEY",
		},
		Agents: map[string]AgentConfig{
			"orchestrator":      {Enabled: true},
			"injection":         {Enabled: true},
			"secrets":           {Enabled: true},
			"auth":              {Enabled: true},
			"crypto":            {Enabled: true},
			"deserialization":   {Enabled: true},
			"ssrf":              {Enabled: true},
			"generic":           {Enabled: true},
			"insecure-defaults": {Enabled: true},
			"race-conditions":   {Enabled: true},
			"error-handling":    {Enabled: true},
			"supply-chain":      {Enabled: true},
			"memory-safety":     {Enabled: true},
			"context_filter":    {Enabled: true},
			"verifier":          {Enabled: true},
			"fp_filter":         {Enabled: true},
		},
		RAG: RAGConfig{
			Enabled:    false, // off by default; embeddings cost money
			TopK:       8,
			FilterKeep: 3,
			ChunkLines: 120,
			BatchSize:  64,
		},
		Skills:                      SkillsConfig{},
		VerifierConfidenceThreshold: ConfLow,
		DropFalsePositives:          true,
		Precision: PrecisionConfig{
			PreFilterWatchlist: true,
			Taint:              true,
			Reachability:       true,
			VoteN:              0,
			VoteK:              0,
			MinScore:           0.0,
			JSONRetries:        2,
			SecretsPreFilter:   true,
			InterProc:          true,
			InterProcMaxDepth:  6,
		},
		Cache: CacheConfig{
			Enabled: true,
			Path:    ".llmscan/cache.db",
		},
		ASTCache: ASTCacheConfig{
			Enabled: true,
			Path:    ".llmscan/ast-cache.db",
		},
		Deep: DeepConfig{
			Enabled:      false,
			MinSeverity:  "high",
			MaxHotspots:  20,
			Budget:       40,
			Concurrency:  4,
			Cache:        true,
			MaxFileBytes: 512 * 1024,
		},
		Scan: ScanConfig{
			MaxFileBytes:   256 * 1024,
			Concurrency:    16,
			AgentParallel:  8,
			FollowSymlinks: false,
			MaxFiles:       100000,
			VCS:            "auto",
			Exclude: []string{
				".git/", "node_modules/", "vendor/", "dist/", "build/", "target/",
				".venv/", "venv/", "__pycache__/", ".idea/", ".vscode/",
				"*.min.js", "*.lock", "*.sum", "go.sum",
			},
			Chunk: ChunkConfig{
				TargetTokens:  8000,
				MaxTokens:     16000,
				MinTokens:     500,
				FallbackLines: 400,
			},
			Context: ContextConfig{
				Level: "balanced",
				Cache: true,
			},
		},
	}
}

// Load reads YAML config from `path`. If `path` is empty, returns the default config.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the configuration for obviously-broken combinations and
// out-of-range numbers. It does NOT enforce any business logic that callers
// might intentionally override at the CLI; only invariants that would cause
// silent misbehaviour deep inside the pipeline.
func (c Config) Validate() error {
	p := c.Precision
	if p.VoteN < 0 {
		return fmt.Errorf("precision.vote_n=%d must be >= 0", p.VoteN)
	}
	if p.VoteK < 0 {
		return fmt.Errorf("precision.vote_k=%d must be >= 0", p.VoteK)
	}
	if p.VoteN > 0 && p.VoteK > p.VoteN {
		return fmt.Errorf("precision.vote_k=%d cannot exceed vote_n=%d", p.VoteK, p.VoteN)
	}
	if p.MinScore < 0 || p.MinScore > 1 {
		return fmt.Errorf("precision.min_score=%v must be in [0,1]", p.MinScore)
	}
	if p.InterProcMaxDepth < 0 {
		return fmt.Errorf("precision.interproc_max_depth=%d must be >= 0", p.InterProcMaxDepth)
	}
	if p.JSONRetries < 0 {
		return fmt.Errorf("precision.json_retries=%d must be >= 0", p.JSONRetries)
	}
	if c.Deep.MaxHotspots < 0 || c.Deep.Budget < 0 || c.Deep.Concurrency < 0 {
		return fmt.Errorf("deep.* counters must be >= 0")
	}
	cc := c.Scan.Chunk
	if cc.TargetTokens > 0 && cc.MaxTokens > 0 && cc.MaxTokens < cc.TargetTokens {
		return fmt.Errorf("scan.chunk.max_tokens=%d must be >= target_tokens=%d",
			cc.MaxTokens, cc.TargetTokens)
	}
	if cc.MinTokens < 0 || cc.TargetTokens < 0 || cc.MaxTokens < 0 {
		return fmt.Errorf("scan.chunk.* token counters must be >= 0")
	}
	ctx := c.Scan.Context
	if ctx.OverflowRatio < 0 || ctx.OverflowRatio > 1 {
		return fmt.Errorf("scan.context.overflow_ratio=%v must be in [0,1]", ctx.OverflowRatio)
	}
	if ctx.BudgetTokens < 0 {
		return fmt.Errorf("scan.context.budget_tokens=%d must be >= 0", ctx.BudgetTokens)
	}
	if ctx.CalleesHops < 0 || ctx.CallersHops < 0 {
		return fmt.Errorf("scan.context.*_hops must be >= 0")
	}
	switch strings.ToLower(ctx.Level) {
	case "", "minimal", "balanced", "aggressive", "extreme":
	default:
		return fmt.Errorf("scan.context.level=%q must be one of minimal|balanced|aggressive|extreme", ctx.Level)
	}
	return nil
}

// AutoContextBudget resolves the effective contextpack budget for the given
// agent. Precedence:
//
//	1. scan.context.budget_tokens if non-zero, capped at 0.7 × ContextWindow.
//	2. 0.7 × model.context_window if window is set.
//	3. Level default (40K minimal, 80K balanced/aggressive, 120K extreme).
func (c Config) AutoContextBudget(agent string) int {
	model := c.ResolveModel(agent)
	cap0 := 0
	if model.ContextWindow > 0 {
		cap0 = int(float64(model.ContextWindow) * 0.7)
	}
	if b := c.Scan.Context.BudgetTokens; b > 0 {
		if cap0 > 0 && b > cap0 {
			return cap0
		}
		return b
	}
	if cap0 > 0 {
		return cap0
	}
	switch strings.ToLower(c.Scan.Context.Level) {
	case "minimal":
		return 40000
	case "extreme":
		return 120000
	default: // balanced, aggressive, or empty
		return 80000
	}
}

// ResolveModel returns the model spec for an agent, falling back to DefaultModel and filling in env-derived API key info.
func (c Config) ResolveModel(agent string) ModelSpec {
	m := c.DefaultModel
	if ac, ok := c.Agents[agent]; ok && ac.Model.Model != "" {
		// Shallow-merge: agent-level overrides win, but unset fields fall back to default.
		if ac.Model.Provider != "" {
			m.Provider = ac.Model.Provider
		}
		m.Model = ac.Model.Model
		if ac.Model.Temperature != 0 {
			m.Temperature = ac.Model.Temperature
		}
		if ac.Model.MaxTokens != 0 {
			m.MaxTokens = ac.Model.MaxTokens
		}
		if ac.Model.BaseURL != "" {
			m.BaseURL = ac.Model.BaseURL
		}
		if ac.Model.APIKeyEnv != "" {
			m.APIKeyEnv = ac.Model.APIKeyEnv
		}
	}
	if m.APIKeyEnv == "" {
		switch strings.ToLower(m.Provider) {
		case "anthropic":
			m.APIKeyEnv = "ANTHROPIC_API_KEY"
		default:
			m.APIKeyEnv = "OPENAI_API_KEY"
		}
	}
	if m.Temperature == 0 {
		m.Temperature = 0.1
	}
	if m.MaxTokens == 0 {
		m.MaxTokens = 4096
	}
	return m
}

// IsAgentEnabled reports whether an agent is enabled. Defaults to true.
func (c Config) IsAgentEnabled(agent string) bool {
	if ac, ok := c.Agents[agent]; ok {
		return ac.Enabled
	}
	return true
}
