# Contributing to llmscan

Thanks for considering a contribution. This document covers the workflow,
expectations, and gotchas specific to llmscan.

## Quick start

```bash
git clone https://github.com/andrewaeva/llmscan
cd llmscan
make test        # go test -race -count=1 ./...
make lint        # golangci-lint
./llmscan version
```

Requires Go 1.24+. SQLite is pure-Go (`modernc.org/sqlite`) — no CGO needed.

## Development workflow

```bash
make fmt         # gofmt -s + goimports
make lint        # golangci-lint v2
make test        # race detector + coverage
make precommit   # all hooks
```

Install pre-commit hooks once:

```bash
pre-commit install
```

The hooks run `gofmt`, `goimports`, `go vet`, `go mod tidy`, and
`golangci-lint` on every commit.

## Branching and commits

- Branch from `main`. Keep PRs focused — one logical change per PR.
- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `perf:`.
- The release changelog excludes pure `docs:`, `test:`, and `chore:` commits.
- Rebase, do not merge `main` into your branch.

## What does NOT change without discussion

The following surfaces are stable and break downstream consumers. Open an
issue first before changing any of them:

- **CLI flags** (`scan`, `eval`, `harness-step`, `init`, `bench`)
- **YAML config schema** (`llmscan.yaml`)
- **JSON output schema** (`Finding`, `Report`, including `DeepTrace`,
  `DeepVerified`, etc.)
- **SARIF output**
- **Exit codes** (`--fail-on` semantics)
- **`SKILL.md` frontmatter format** (`name`, `kind`, `layer`, `cwe`,
  `severity`, `languages`, `depends_on`)

Behavior changes inside the pipeline (new agents, better confidence
heuristics, additional sandbox tools for `--deep`) are welcome.

## Adding a new vulnerability skill

1. Create `skills/<name>/SKILL.md` with the standard frontmatter:

   ```yaml
   ---
   name: <name>
   kind: scanner
   description: <one line>
   layer: 1
   depends_on: []
   languages: [go, python, javascript, typescript, java]   # or []
   cwe: [CWE-XXX]
   severity: high
   ---
   ```

2. Body must follow the established structure:
   - `# Scope`
   - `# Patterns to flag` (language-specific examples)
   - `# Patterns to NOT flag` (FP guards)
   - `# Confidence calibration` (high/medium/low)
   - `# Suggested fix patterns`
   - `# References` (OWASP/CWE/blog posts)
   - `# Output schema` (exact JSON shape — do not deviate)

3. Register the agent in `internal/config/config.go` (`ScannerNames`,
   `Default().Agents`, and `sampleConfig`).

4. Add the skill name to `internal/skills/skills_test.go`.

5. Reference any borrowed technique with a comment at the top of the body:

   ```markdown
   <!-- Inspired by Trail of Bits skills (https://github.com/trailofbits/skills, MIT). -->
   ```

   and update `NOTICE.md` if a new upstream is introduced.

6. Run `make test` — the skill parser test will pick it up.

## Adding a new pipeline stage

- New stages live in `internal/pipeline/stages.go` (or a new file if it is
  large). The pipeline is a sequence in `Engine.Run` — add the stage between
  the right two existing ones and gate it with a config flag in
  `internal/config/config.go`.
- Surface a `--<name>` CLI flag in `cmd/llmscan/cli.go`.
- Document the stage in `README.md` under the pipeline diagram.

## Testing rules

- All tests must be hermetic. No real network. Use `httptest.NewServer` for
  LLM clients.
- Race detector is mandatory: `go test -race -count=1 ./...`.
- Target coverage for new packages: ≥ 70%. Critical packages (`pipeline`,
  `agents`, `llm`) must stay above their current numbers.
- When fixing a bug, add a regression test in the same PR.
- Snapshot tests for `report` are fine if the snapshot is small and inline.

## Linting

`golangci-lint v2` runs in CI with these enablers: `errcheck`, `govet`,
`ineffassign`, `staticcheck`, `unused`, `gocyclo` (15), `gocritic`, `gosec`,
`misspell`, `unconvert`, `unparam`, `prealloc`, `bodyclose`, `noctx`,
`revive`.

If you genuinely need to bypass a rule, use a targeted directive with a
reason:

```go
//nolint:gosec // G404: non-crypto RNG is correct here, jitter only
```

PRs with broad `//nolint` directives or with `nolintlint` flagging unused
suppressions will be rejected.

## LLM costs and the `--deep` mode

The deep sub-agent pass costs real API tokens. When writing or reviewing
changes to `internal/agents/deepscanner.go`, `internal/pipeline/deep.go`, or
`internal/llm/anthropic_tools.go`:

- Keep tool-output truncation in place (≤32 KiB, ≤500 lines, ≤100 grep
  matches, ≤200 dir entries).
- Honor `--deep-budget` strictly. No "one more call" escape hatches.
- Cache key must include the scan root to avoid cross-project poisoning.

## Releases

Maintainers tag releases:

```bash
git tag v0.x.y
git push --tags
```

The `release.yml` workflow builds binaries for 5 platforms via GoReleaser,
pushes a multi-arch Docker image to `ghcr.io/andrewaeva/llmscan`, and
publishes a GitHub release with auto-generated changelog.

## Reporting bugs and asking questions

- **Bugs**: open a GitHub issue with reproduction steps, expected vs actual
  output, and the `llmscan version` output. If the bug involves a specific
  file, attach a minimal sample (with secrets redacted).
- **Questions**: GitHub Discussions are preferred over issues.
- **Security vulnerabilities**: do not file a public issue. See
  [SECURITY.md](SECURITY.md).

## Code of conduct

Be respectful. Assume good faith. We follow the
[Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
