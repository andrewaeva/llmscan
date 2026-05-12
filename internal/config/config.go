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
	ChunkLines     int      `yaml:"chunk_lines,omitempty"`
	ChunkOverlap   int      `yaml:"chunk_overlap,omitempty"`
	Concurrency    int      `yaml:"concurrency,omitempty"`    // chunks in flight per single scanner agent
	AgentParallel  int      `yaml:"agent_parallel,omitempty"` // scanner agents in flight (DAG layer)
	FollowSymlinks bool     `yaml:"follow_symlinks,omitempty"`

	// Monorepo support.
	ScopeRoots []string `yaml:"scope_roots,omitempty"` // restrict traversal to these sub-paths
	MaxFiles   int      `yaml:"max_files,omitempty"`   // abort with error above this count; 0 = unlimited
	VCS        string   `yaml:"vcs,omitempty"`         // auto | git | arc | none
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
	// SymbolExpansion attaches referenced function defs (1-2 hops) to scanner context.
	SymbolExpansion bool `yaml:"symbol_expansion"`
	SymExpandHops   int  `yaml:"sym_expand_hops,omitempty"`
	SymExpandMax    int  `yaml:"sym_expand_max,omitempty"`
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
			SymbolExpansion:    true,
			SymExpandHops:      1,
			SymExpandMax:       4,
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
			ChunkLines:     350,
			ChunkOverlap:   30,
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
	return cfg, nil
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
