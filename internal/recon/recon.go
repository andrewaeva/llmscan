// Package recon builds an architecture document for the target repository
// before any scanning happens. The document captures entry points, trust
// boundaries, framework / stack hints, and likely attack surface so that
// downstream scanners reason with shared context instead of guessing from
// each file in isolation.
//
// Inspired by Cloudflare's Project Glasswing "Recon" stage — the harness
// produces an architecture document and a queue of attack-class tasks
// before fanning out to hunters. Scoped prompts beat broad "find bugs"
// prompts by a wide margin.
package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/callgraph"
	"github.com/andrewaeva/llmscan/internal/knowledge"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// FileName is the markdown artefact persisted under <target>/.llmscan/.
const FileName = "architecture.md"

// Path returns the canonical on-disk location for the architecture doc.
func Path(target string) string {
	return filepath.Join(target, knowledge.DirName, FileName)
}

// Load returns the previously generated architecture document, or empty
// string if none exists.
func Load(target string) (string, error) {
	p := Path(target)
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", p, err)
	}
	return string(b), nil
}

// Save writes the architecture document to <target>/.llmscan/architecture.md.
func Save(target, content string) error {
	dir := filepath.Join(target, knowledge.DirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	p := filepath.Join(dir, FileName)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Sample picks files that are likely informative for architecture mapping:
// top-level entry points (handlers, main, routes), config files, and the
// shallowest directories. The output is capped to maxFiles paths.
func Sample(files []types.FileTarget, entries []callgraph.Info, maxFiles int) []types.FileTarget {
	if maxFiles <= 0 {
		maxFiles = 40
	}
	score := map[string]int{}
	byPath := map[string]types.FileTarget{}
	for _, f := range files {
		byPath[f.Path] = f
		score[f.Path] = baseScore(f.Path)
	}
	for _, e := range entries {
		if _, ok := byPath[e.File]; ok {
			score[e.File] += 50
		}
	}
	type kv struct {
		path string
		s    int
	}
	ranked := make([]kv, 0, len(score))
	for p, s := range score {
		ranked = append(ranked, kv{p, s})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].s != ranked[j].s {
			return ranked[i].s > ranked[j].s
		}
		return ranked[i].path < ranked[j].path
	})
	out := make([]types.FileTarget, 0, maxFiles)
	for _, r := range ranked {
		if len(out) >= maxFiles {
			break
		}
		out = append(out, byPath[r.path])
	}
	return out
}

func baseScore(p string) int {
	lp := strings.ToLower(p)
	base := strings.ToLower(filepath.Base(p))
	score := 0
	// Shallow files matter more.
	depth := strings.Count(p, string(filepath.Separator))
	score -= depth
	// Common entry-point names.
	for _, hint := range []string{
		"main.", "server.", "app.", "index.",
		"router", "routes", "handler", "controller",
		"middleware", "auth", "api/",
	} {
		if strings.Contains(lp, hint) {
			score += 8
		}
	}
	// Config / manifest files (small, high info density).
	for _, n := range []string{
		"package.json", "go.mod", "go.sum", "cargo.toml", "pyproject.toml",
		"requirements.txt", "pom.xml", "build.gradle", "dockerfile", "compose.yaml",
		"compose.yml", "docker-compose.yml", ".env.example", "config.yaml",
		"config.yml", "readme.md",
	} {
		if base == n {
			score += 20
		}
	}
	// Penalise generated / vendored.
	for _, junk := range []string{
		"vendor/", "node_modules/", "dist/", "build/", ".gen.", "_test.", "/test/",
		"/tests/", "fixtures/", "testdata/",
	} {
		if strings.Contains(lp, junk) {
			score -= 30
		}
	}
	return score
}

// Summarize calls the LLM with selected files and an entry-point list and
// returns a markdown architecture document. Caller is responsible for
// persisting the result via Save.
func Summarize(ctx context.Context, client llm.Client, files []types.FileTarget, entries []callgraph.Info, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = 60_000
	}
	var b strings.Builder
	b.WriteString("# Repository\n")
	b.WriteString("Files sampled for architecture analysis (entry points, config, top-level):\n\n")
	for _, f := range files {
		fmt.Fprintf(&b, "## %s\n```\n", f.Path)
		body := string(f.Content)
		if len(body) > 4000 {
			body = body[:4000] + "\n...[truncated]\n"
		}
		b.WriteString(body)
		b.WriteString("\n```\n\n")
		if b.Len() > maxBytes {
			b.WriteString("...[corpus truncated]\n")
			break
		}
	}
	if len(entries) > 0 {
		b.WriteString("\n# Detected entry points (call-graph)\n")
		seen := map[string]bool{}
		for _, e := range entries {
			key := e.File + ":" + e.Func
			if seen[key] {
				continue
			}
			seen[key] = true
			fmt.Fprintf(&b, "- %s :: %s (%s)\n", e.File, e.Func, e.Kind)
			if len(seen) >= 80 {
				break
			}
		}
	}

	prompt := `You are a senior application security architect. Produce a concise architecture document (markdown, ≤ 600 words) for the repository sampled below. Use the EXACT section headings:

## Stack
Language(s), framework(s), runtime(s), build system. One bullet each.

## Entry points
External-facing handlers / routes / CLI commands / cron jobs. Group by transport (HTTP, gRPC, queue, CLI). For each: route or symbol, file path.

## Trust boundaries
Where untrusted input enters the system and where authentication / authorization is enforced. Note any module that runs with elevated privileges.

## Data layer
Databases, ORMs, queues, caches, external HTTP clients. Note where queries are built (raw SQL vs parameterised).

## AuthN / AuthZ shape
How users / services authenticate, where session / token is verified, how authorisation checks are expressed (decorator / middleware / inline).

## Likely attack surface
List 5–10 high-priority areas worth deeper scanning, each as: "<area> — <attack class>". Be specific, not generic.

## Out of scope
Vendored / test / generated paths that scanners should down-weight.

Be terse. Cite file paths. Do NOT invent code that is not visible in the corpus.

CORPUS:
` + b.String()

	resp, err := client.Complete(ctx, llm.Request{
		Messages: []llm.Message{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", fmt.Errorf("llm: %w", err)
	}
	return strings.TrimSpace(resp.Text), nil
}
