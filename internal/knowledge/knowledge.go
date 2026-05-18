// Package knowledge persists a compact project memory between scans.
//
// On scan start, the engine reads .llmscan/knowledge.md (if present) and
// prepends it to Cfg.ProjectContext so the orchestrator and skills see the
// distilled architecture, tech stack, and recurring patterns from prior
// runs. On scan end, an LLM regenerates the file from the new file tree,
// top findings, and previous knowledge.
//
// The file is intentionally markdown (not JSON) so humans can read and
// hand-edit it. It MUST stay short (<3 KB) so it fits comfortably into every
// prompt without dominating the context budget.
package knowledge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// FileName is the markdown file persisted under <target>/.llmscan/.
const FileName = "knowledge.md"

// DirName is the project-local directory under which knowledge.md lives.
const DirName = ".llmscan"

// MaxBytes caps the size of the loaded/written knowledge file. Anything
// larger is truncated; the writer keeps the head + a "[...]" marker.
const MaxBytes = 8 * 1024

// Path returns the absolute path of the knowledge file under target.
func Path(target string) string {
	return filepath.Join(target, DirName, FileName)
}

// Load reads .llmscan/knowledge.md and returns its content. Returns ("", nil)
// when the file does not exist — a missing file is a normal first-run state,
// not an error.
func Load(target string) (string, error) {
	if target == "" {
		return "", nil
	}
	b, err := os.ReadFile(Path(target))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if len(b) > MaxBytes {
		b = b[:MaxBytes]
	}
	return strings.TrimSpace(string(b)), nil
}

// Save writes content to .llmscan/knowledge.md atomically. Creates the
// directory if missing. Truncates to MaxBytes.
func Save(target, content string) error {
	if target == "" {
		return errors.New("knowledge.Save: empty target")
	}
	dir := filepath.Join(target, DirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("knowledge: mkdir %s: %w", dir, err)
	}
	const marker = "\n[...truncated]"
	if len(content) > MaxBytes {
		content = content[:MaxBytes-len(marker)] + marker
	}
	tmp := filepath.Join(dir, FileName+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, FileName))
}

// Summarize asks an LLM to (re)generate the knowledge file from:
//   - the previous knowledge (to preserve continuity)
//   - the project's top-level file/dir layout
//   - a compact list of top findings
//
// On LLM error it returns previous unchanged so the caller can keep the
// existing file. The result is always trimmed to MaxBytes.
func Summarize(ctx context.Context, client llm.Client, previous string, layout []string, findings []types.Finding) (string, error) {
	if client == nil {
		return previous, errors.New("knowledge.Summarize: nil client")
	}
	user := buildSummaryPrompt(previous, layout, findings)
	resp, err := client.Complete(ctx, llm.Request{
		System:   summarizerSystem,
		Messages: []llm.Message{{Role: "user", Content: user}},
	})
	if err != nil {
		return previous, err
	}
	out := strings.TrimSpace(resp.Text)
	out = stripCodeFence(out)
	if out == "" {
		return previous, errors.New("knowledge.Summarize: empty response")
	}
	if len(out) > MaxBytes {
		out = out[:MaxBytes]
	}
	return out, nil
}

// CollectLayout returns up to maxEntries top-level directories and notable
// files from target. Used as compact project context for the summarizer.
func CollectLayout(target string, maxEntries int) ([]string, error) {
	if maxEntries <= 0 {
		maxEntries = 60
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") && name != ".github" {
			continue
		}
		if e.IsDir() {
			out = append(out, name+"/")
		} else {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) > maxEntries {
		out = out[:maxEntries]
	}
	return out, nil
}

// ---- internals ----

const summarizerSystem = `You maintain a compact, evolving knowledge file for a security scanner.
The file MUST stay under 3000 characters of plain markdown. No code fences.

Sections (use these exact markdown headers, omit if empty):
  ## Stack and frameworks
  ## Architecture overview
  ## Trust boundaries
  ## Known recurring patterns
  ## Notes for future scans

Rules:
  - Preserve facts from the previous knowledge unless contradicted by new evidence.
  - Add NEW facts learned from the latest findings (e.g. "uses gin web framework",
    "JWT auth via internal/auth", "tenant_id in URL path").
  - Drop entries that are now wrong.
  - Be terse: bullet points, no prose paragraphs.
  - Do NOT enumerate every file or every finding. Pick the load-bearing ones.
  - Output JUST the markdown — no preamble, no closing remarks.`

func buildSummaryPrompt(previous string, layout []string, findings []types.Finding) string {
	var b strings.Builder
	if previous != "" {
		b.WriteString("Previous knowledge.md:\n")
		b.WriteString(previous)
		b.WriteString("\n\n")
	} else {
		b.WriteString("Previous knowledge.md: (empty, first scan)\n\n")
	}
	b.WriteString("Top-level project layout:\n")
	for _, l := range layout {
		fmt.Fprintf(&b, "  - %s\n", l)
	}
	b.WriteString("\nTop findings from the latest scan (up to 30, highest-severity first):\n")
	top := pickTopFindings(findings, 30)
	if len(top) == 0 {
		b.WriteString("  (no findings)\n")
	} else {
		for _, f := range top {
			fmt.Fprintf(&b, "  - [%s] %s — %s:%d (%s)\n", f.Severity, f.RuleID, f.File, f.StartLine, oneLine(f.Title, 80))
		}
	}
	b.WriteString("\nWrite the new knowledge.md.")
	return b.String()
}

// pickTopFindings returns at most n findings, prioritising by severity rank,
// then by confidence and rule id for stability.
func pickTopFindings(in []types.Finding, n int) []types.Finding {
	if n <= 0 || len(in) == 0 {
		return nil
	}
	cp := make([]types.Finding, len(in))
	copy(cp, in)
	sort.SliceStable(cp, func(i, j int) bool {
		ri, rj := sevRank(cp[i].Severity), sevRank(cp[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return cp[i].RuleID < cp[j].RuleID
	})
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func sevRank(s types.Severity) int {
	switch s {
	case types.SevCritical:
		return 5
	case types.SevHigh:
		return 4
	case types.SevMedium:
		return 3
	case types.SevLow:
		return 2
	case types.SevInfo:
		return 1
	}
	return 0
}

func oneLine(s string, limit int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}

func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// strip first line (e.g. ```markdown)
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
		s = strings.TrimSpace(s)
	}
	return s
}
