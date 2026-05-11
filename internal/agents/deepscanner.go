// deepscanner.go implements the optional sub-agent ("--deep") pass.
//
// Unlike regular scanners which receive a fixed code chunk + symexpand
// context, a DeepAgent gets only a starting hotspot (file:line) and a
// toolbox (read_file, grep, list_dir, git_blame). It drives a multi-turn
// tool-use loop until it decides whether the finding is real, and produces
// a structured verdict that is merged into the original Finding.
package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/tools"
	"github.com/andrewaeva/llmscan/internal/types"
)

// DeepResult is what the agent returns for a single hotspot.
type DeepResult struct {
	Verdict string // "confirmed" | "refuted" | "inconclusive"
	Reason  string
	Fix     string
	Trace   []types.DeepToolCall
	Model   string
}

// DeepAgent verifies a single finding by giving an LLM access to read-only
// inspection tools rooted at Root.
type DeepAgent struct {
	Client    llm.ToolClient
	Sandbox   *tools.Sandbox
	Cache     *cache.DB // optional; if non-nil, tool outputs are memoized
	UseCache  bool
	Budget    int  // max tool calls; 0 -> default
	Verbose   bool // log every tool call
	Logf      func(format string, args ...any)
	ModelName string // for trace + reporting
}

func (a *DeepAgent) logf(format string, args ...any) {
	if a.Logf == nil || !a.Verbose {
		return
	}
	a.Logf(format, args...)
}

// Verify investigates one finding and returns a DeepResult.
// Network and tool errors do NOT make Verify return an error — they result
// in Verdict="inconclusive" so the caller can keep the original finding.
func (a *DeepAgent) Verify(ctx context.Context, f types.Finding) DeepResult {
	if a.Client == nil || a.Sandbox == nil {
		return DeepResult{Verdict: "inconclusive", Reason: "deep agent not configured"}
	}
	budget := a.Budget
	if budget <= 0 {
		budget = 40
	}

	system := deepSystemPrompt()
	user := deepUserPrompt(f)

	var trace []types.DeepToolCall
	step := 0

	handler := func(ctx context.Context, call llm.ToolCall) llm.ToolResult {
		step++
		t0 := time.Now()
		out, ferr := a.dispatch(ctx, call)
		elapsed := time.Since(t0).Milliseconds()

		args := compactJSON(call.Input)
		argShort := args
		if len(argShort) > 200 {
			argShort = argShort[:200] + "..."
		}
		resultShort := out
		if len(resultShort) > 512 {
			resultShort = resultShort[:512] + "..."
		}
		errStr := ""
		if ferr != nil {
			errStr = ferr.Error()
		}
		trace = append(trace, types.DeepToolCall{
			Step:   step,
			Tool:   call.Name,
			Args:   args,
			Result: resultShort,
			Error:  errStr,
			Ms:     elapsed,
		})
		a.logf("deep[%s:%d] tool %s %s -> %dms err=%q",
			shortFile(f.File), f.StartLine, call.Name, argShort, elapsed, errStr)

		if ferr != nil {
			return llm.ToolResult{ID: call.ID, Content: "error: " + ferr.Error(), IsError: true}
		}
		return llm.ToolResult{ID: call.ID, Content: out}
	}

	resp, err := a.Client.CompleteWithTools(ctx, llm.ToolRequest{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		Tools:    deepToolDefs(),
		Handler:  handler,
		MaxSteps: budget,
	})
	if err != nil {
		a.logf("deep[%s:%d] llm error: %v", shortFile(f.File), f.StartLine, err)
		return DeepResult{Verdict: "inconclusive", Reason: "llm error: " + err.Error(), Trace: trace, Model: a.ModelName}
	}

	verdict, reason, fix := parseVerdict(resp.FinalText)
	return DeepResult{
		Verdict: verdict,
		Reason:  reason,
		Fix:     fix,
		Trace:   trace,
		Model:   resp.Model,
	}
}

// dispatch routes one ToolCall to the sandbox; result strings are truncated
// at the sandbox layer.
func (a *DeepAgent) dispatch(ctx context.Context, call llm.ToolCall) (string, error) {
	_ = ctx
	// Memoize if cache is configured.
	var key string
	if a.UseCache && a.Cache != nil {
		h := sha256.Sum256([]byte(call.Name + "|" + string(call.Input) + "|" + a.Sandbox.Root))
		key = hex.EncodeToString(h[:])
		if blob, ok := a.Cache.GetDeepTool(key); ok {
			return string(blob), nil
		}
	}

	var (
		out string
		err error
	)
	switch call.Name {
	case "read_file":
		var args struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		}
		if e := json.Unmarshal(call.Input, &args); e != nil {
			return "", fmt.Errorf("bad args: %w", e)
		}
		out, err = a.Sandbox.ReadFile(args.Path, args.StartLine, args.EndLine)
	case "grep":
		var args struct {
			Pattern    string `json:"pattern"`
			PathGlob   string `json:"path_glob"`
			MaxMatches int    `json:"max_matches"`
		}
		if e := json.Unmarshal(call.Input, &args); e != nil {
			return "", fmt.Errorf("bad args: %w", e)
		}
		out, err = a.Sandbox.Grep(args.Pattern, args.PathGlob, args.MaxMatches)
	case "list_dir":
		var args struct {
			Path string `json:"path"`
		}
		if e := json.Unmarshal(call.Input, &args); e != nil {
			return "", fmt.Errorf("bad args: %w", e)
		}
		out, err = a.Sandbox.ListDir(args.Path)
	case "git_blame":
		var args struct {
			Path string `json:"path"`
			Line int    `json:"line"`
		}
		if e := json.Unmarshal(call.Input, &args); e != nil {
			return "", fmt.Errorf("bad args: %w", e)
		}
		out, err = a.Sandbox.GitBlame(args.Path, args.Line)
	default:
		return "", fmt.Errorf("unknown tool: %s", call.Name)
	}

	if err == nil && key != "" {
		_ = a.Cache.PutDeepTool(key, []byte(out))
	}
	return out, err
}

// ---- prompts & tool schemas ----

func deepSystemPrompt() string {
	return `You are a senior application security engineer verifying a candidate finding
reported by a static-analysis sub-agent. You have read-only tools to inspect
the codebase. Use them aggressively.

Workflow:
  1. Read the cited range with read_file to see the surrounding context.
  2. Use grep to follow tainted variables, sanitizers, helpers, and callers.
  3. Open related files with read_file as needed to confirm or refute the
     vulnerability end-to-end.
  4. Be skeptical: if the finding is fenced by a sanitizer, framework
     protection, dead code, or test scaffolding, REFUTE it.
  5. Stop calling tools once you can decide. Do not over-investigate.

Output policy: when you are done, return a SINGLE JSON object on the LAST
line of your reply with this exact shape (no markdown fences, no other text
after it):

  {"verdict":"confirmed|refuted|inconclusive",
   "reason":"<1-3 sentence rationale grounded in code you read>",
   "fix":"<optional concrete remediation hint, may be empty>"}

You may include a brief plain-text rationale above the JSON if you wish, but
the JSON object on the final line is mandatory and parsed automatically.`
}

func deepUserPrompt(f types.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Candidate finding:\n")
	fmt.Fprintf(&b, "  agent:     %s\n", f.Agent)
	fmt.Fprintf(&b, "  severity:  %s (confidence %s)\n", f.Severity, f.Confidence)
	fmt.Fprintf(&b, "  rule:      %s\n", f.RuleID)
	if f.CWE != "" {
		fmt.Fprintf(&b, "  cwe:       %s\n", f.CWE)
	}
	fmt.Fprintf(&b, "  location:  %s:%d-%d\n", f.File, f.StartLine, f.EndLine)
	fmt.Fprintf(&b, "  title:     %s\n", f.Title)
	if f.Description != "" {
		fmt.Fprintf(&b, "  why:       %s\n", oneLine(f.Description))
	}
	if f.CodeSample != "" {
		fmt.Fprintf(&b, "\nReported snippet:\n```\n%s\n```\n", f.CodeSample)
	}
	fmt.Fprintf(&b, "\nUse the tools to verify or refute this. Start by reading the cited range.\n")
	return b.String()
}

func deepToolDefs() []llm.ToolDef {
	return []llm.ToolDef{
		{
			Name: "read_file",
			Description: "Read lines from a file in the project. Paths are relative to the project root. " +
				"Returns line-numbered text. Prefer narrow ranges (≤ 200 lines per call).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":       map[string]any{"type": "string", "description": "Project-relative path"},
					"start_line": map[string]any{"type": "integer", "description": "1-based start line (default 1)"},
					"end_line":   map[string]any{"type": "integer", "description": "1-based end line; 0 = start+500"},
				},
				"required": []string{"path"},
			},
		},
		{
			Name: "grep",
			Description: "Regex-search the project for a pattern. Returns up to max_matches hits with " +
				"file:line:text. Use it to follow identifiers, helpers, or sinks across files.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern":     map[string]any{"type": "string", "description": "Go (RE2) regex"},
					"path_glob":   map[string]any{"type": "string", "description": "Optional glob, e.g. 'internal/*.go' (default: whole repo)"},
					"max_matches": map[string]any{"type": "integer", "description": "Cap on hits returned (default 100)"},
				},
				"required": []string{"pattern"},
			},
		},
		{
			Name:        "list_dir",
			Description: "List the immediate children of a directory.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Project-relative directory (default '.')"},
				},
			},
		},
		{
			Name:        "git_blame",
			Description: "Run git blame for a single line. Returns commit, author, date, summary.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
					"line": map[string]any{"type": "integer"},
				},
				"required": []string{"path", "line"},
			},
		},
	}
}

// ---- helpers ----

func compactJSON(b []byte) string {
	if len(b) == 0 {
		return "{}"
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

func shortFile(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 && len(p)-i < 40 {
		return p[i+1:]
	}
	return p
}

// parseVerdict extracts the JSON verdict from the model's final message.
// It tolerates leading prose and code fences.
func parseVerdict(text string) (verdict, reason, fix string) {
	text = strings.TrimSpace(text)
	// Find the last '{' and parse until matching '}'.
	start := strings.LastIndex(text, "{")
	if start < 0 {
		return "inconclusive", strings.TrimSpace(text), ""
	}
	jsonPart := text[start:]
	// Strip trailing fences/text after the JSON.
	if end := strings.LastIndex(jsonPart, "}"); end >= 0 {
		jsonPart = jsonPart[:end+1]
	}
	var v struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
		Fix     string `json:"fix"`
	}
	if err := json.Unmarshal([]byte(jsonPart), &v); err != nil {
		return "inconclusive", strings.TrimSpace(text), ""
	}
	verdict = strings.ToLower(strings.TrimSpace(v.Verdict))
	switch verdict {
	case "confirmed", "refuted", "inconclusive":
	default:
		verdict = "inconclusive"
	}
	return verdict, strings.TrimSpace(v.Reason), strings.TrimSpace(v.Fix)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
