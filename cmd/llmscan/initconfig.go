package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

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

const sampleConfig = `# llmscan sample configuration (v3)
default_model:
  provider: anthropic       # anthropic | openai
  model: claude-sonnet-4-6
  temperature: 0.1
  max_tokens: 4096
  # base_url: https://api.anthropic.com   # optional; also picks up ANTHROPIC_BASE_URL
  # api_key_env: ANTHROPIC_API_KEY        # or ANTHROPIC_AUTH_TOKEN for Bearer proxies

agents:
  orchestrator:
    enabled: true
    # model: { provider: openai, model: gpt-4o-mini }
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
      model: claude-sonnet-4-6
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
