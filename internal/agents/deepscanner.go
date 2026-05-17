// deepscanner.go implements the optional sub-agent ("--deep") pass.
//
// Unlike regular scanners which receive a fixed code chunk + symexpand
// context, a DeepAgent gets only a starting hotspot (file:line) and a
// toolbox (read_file, grep, list_dir, blame). It drives a multi-turn
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
	// Gates is the optional six-gate review attached by the deep agent.
	// Pipeline.deep merges this onto the original Finding when present.
	Gates *types.GateReview
	// DefenseInDepth is set when only Gate 6 (Impact) failed.
	DefenseInDepth bool
}

// DeepAgent verifies a single finding by giving an LLM access to read-only
// inspection tools rooted at Root.
type DeepAgent struct {
	Client    llm.ToolClient
	Sandbox   *tools.Sandbox
	Cache     cache.Cache // optional; if non-nil, tool outputs are memoized
	UseCache  bool
	Budget    int  // max tool calls; 0 -> default
	Verbose   bool // log every tool call
	Logf      func(format string, args ...any)
	ModelName string // for trace + reporting
	// PromptOverride, if non-empty, replaces deepSystemPrompt(). Used to
	// swap in a skill-supplied prompt without rewiring the agent.
	PromptOverride string
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
//
//nolint:gocyclo // tool-loop + verdict reconciliation; flat is intentional
func (a *DeepAgent) Verify(ctx context.Context, f types.Finding) DeepResult {
	if a.Client == nil || a.Sandbox == nil {
		return DeepResult{Verdict: "inconclusive", Reason: "deep agent not configured"}
	}
	budget := a.Budget
	if budget <= 0 {
		budget = 40
	}

	system := deepSystemPrompt()
	if a.PromptOverride != "" {
		system = a.PromptOverride
	}
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

	verdict, reason, fix, gates, defenseInDepth := parseGateVerdict(resp.FinalText)
	// Reconcile verdict with gate outcome (if any). Gate signals override
	// the bare verdict string so we cannot end up with verdict=confirmed
	// while validation/api/env clearly FAIL'd.
	if gates != nil {
		switch gates.Classify() {
		case types.GateOutcomeRefutedDefended, types.GateOutcomeRefutedNoControl:
			verdict = "refuted"
			if r := gates.FirstFailingReason(); r != "" && reason == "" {
				reason = r
			}
		case types.GateOutcomeConfirmed:
			verdict = "confirmed"
		case types.GateOutcomeDefenseInDepth:
			// Real bug but lacking primary security impact. Keep verdict
			// as confirmed-with-flag so the pipeline can downgrade rather
			// than drop.
			verdict = "confirmed"
			defenseInDepth = true
		case types.GateOutcomeInconclusive, types.GateOutcomeUnknown:
			// leave verdict as parsed
		}
	}
	return DeepResult{
		Verdict:        verdict,
		Reason:         reason,
		Fix:            fix,
		Trace:          trace,
		Model:          resp.Model,
		Gates:          gates,
		DefenseInDepth: defenseInDepth,
	}
}

// dispatch routes one ToolCall to the sandbox; result strings are truncated
// at the sandbox layer.
func (a *DeepAgent) dispatch(ctx context.Context, call llm.ToolCall) (string, error) {
	_ = ctx
	key, cached := a.deepToolCacheKey(call)
	if cached != "" {
		return cached, nil
	}

	handler, ok := deepToolHandlers[call.Name]
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", call.Name)
	}

	out, err := handler(a, call.Input)
	if err == nil && key != "" {
		_ = a.Cache.PutDeepTool(key, []byte(out))
	}
	return out, err
}

type deepToolHandler func(*DeepAgent, []byte) (string, error)

var deepToolHandlers = map[string]deepToolHandler{
	"read_file":    dispatchReadFile,
	"grep":         dispatchGrep,
	"list_dir":     dispatchListDir,
	"blame":        dispatchBlame,
	"git_blame":    dispatchBlame,
	"read_symbol":  dispatchReadSymbol,
	"find_callers": dispatchFindCallers,
	"find_callees": dispatchFindCallees,
	"list_imports": dispatchListImports,
}

func (a *DeepAgent) deepToolCacheKey(call llm.ToolCall) (string, string) {
	if !a.UseCache || a.Cache == nil {
		return "", ""
	}
	h := sha256.Sum256([]byte(call.Name + "|" + string(call.Input) + "|" + a.Sandbox.Root))
	key := hex.EncodeToString(h[:])
	if blob, ok := a.Cache.GetDeepTool(key); ok {
		return key, string(blob)
	}
	return key, ""
}

func dispatchReadFile(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.ReadFile(args.Path, args.StartLine, args.EndLine)
}

func dispatchGrep(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Pattern    string `json:"pattern"`
		PathGlob   string `json:"path_glob"`
		MaxMatches int    `json:"max_matches"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.Grep(args.Pattern, args.PathGlob, args.MaxMatches)
}

func dispatchListDir(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.ListDir(args.Path)
}

func dispatchBlame(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Path string `json:"path"`
		Line int    `json:"line"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.Blame(args.Path, args.Line)
}

func dispatchReadSymbol(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.ReadSymbol(args.Path, args.Name)
}

func dispatchFindCallers(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Name    string `json:"name"`
		MaxHits int    `json:"max_hits"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.FindCallers(args.Name, args.MaxHits)
}

func dispatchFindCallees(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Name    string `json:"name"`
		MaxHits int    `json:"max_hits"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.FindCallees(args.Name, args.MaxHits)
}

func dispatchListImports(a *DeepAgent, input []byte) (string, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := unmarshalDeepToolArgs(input, &args); err != nil {
		return "", err
	}
	return a.Sandbox.ListImports(args.Path)
}

func unmarshalDeepToolArgs(input []byte, dst any) error {
	if err := json.Unmarshal(input, dst); err != nil {
		return fmt.Errorf("bad args: %w", err)
	}
	return nil
}

// ---- prompts & tool schemas ----

// deepSystemPrompt drives the optional --deep sub-agent that has read-only
// tool access. The methodology is the Trail of Bits fp-check deep path:
// Step 0 (frame the threat model) + 5 investigation phases + 13 devil's
// advocate questions + the same six gates the standard verifier uses.
func deepSystemPrompt() string {
	return `You are a senior application security engineer verifying ONE candidate
finding for llmscan via the Trail-of-Bits fp-check deep-path methodology.
You have read-only tools. Use them.
Primary toolkit:
  - read_file(path, start_line, end_line)  — narrow ranges
  - read_symbol(path, name)                — fetch a function body by name (preferred over read_file when you know the symbol)
  - find_callers(name, max_hits)           — incoming call sites from the project call graph
  - find_callees(name, max_hits)           — outgoing calls from a function (forward data-flow)
  - list_imports(path)                     — see which libraries are in scope (helps spot framework auto-escape / sanitizers)
  - grep(pattern, path_glob, max_matches)  — fallback for free-form lookup
  - list_dir(path) / blame(path, line)     — for orientation and provenance

Step 0 — Frame the threat model:
  - What is the trust boundary the input must cross?
  - Who is the attacker, and what do they control?
  - What is the consequence if the bug is real?

Five investigation phases (run only the ones that apply, stop once you can
decide; total budget is bounded by the host):
  Phase 1: Read the cited range + immediate caller(s) to confirm shape.
  Phase 2: Trace the data flow source → propagator → sink, hop by hop.
  Phase 3: Hunt for upstream validation / sanitizer / framework auto-escape.
  Phase 4: Audit the sink's contract — does the API itself defend?
  Phase 5: Consider environment mitigations (compiler, OS, runtime, CSP).

Six mandatory gates (each PASS / FAIL / N/A with a one-sentence reason):
  1. Control       — attacker really controls the source?
  2. Reachability  — sink reachable on a realistic execution path?
  3. Validation    — upstream validation blocks exploitation?
  4. APIContract   — sink API is self-defending?
  5. Environment   — runtime/compiler/OS mitigates the issue?
  6. Impact        — real security impact (RCE/exfil/privesc) vs robustness?

Verdict rules (apply in order):
  - Gate 3/4/5 = FAIL ⇒ verdict="refuted" (upstream defense).
  - Gate 1/2 = FAIL ⇒ verdict="refuted" (no control / unreachable).
  - Gate 6 = FAIL only ⇒ verdict="confirmed" but defense_in_depth=true.
  - All gates PASS (or PASS with some N/A) ⇒ verdict="confirmed".
  - Otherwise ⇒ verdict="inconclusive".

Thirteen devil's-advocate questions to consider (list the ones that fired in
"devils_advocate"; keep each item short):
  1. Pattern bias — flagging because it "looks like" a known bug?
  2. Trust assumption — assumed an unverified caller is trusted?
  3. Mathematical proof — verified bounds/sizes, not just glanced at them?
  4. Defense-in-depth vs primary control confusion?
  5. Hallucination — invented code/sanitizers/APIs not in the repo?
  6. False-negative protection — would dismissing this miss a real bug?
  7. Cross-component reach — did I follow every caller path?
  8. Race / concurrency — could the check-then-use be raced?
  9. Logic vs spec — does the code violate a documented invariant?
 10. Test scaffolding — is this dead in production?
 11. Configuration drift — does default config make this reachable?
 12. Supply-chain — does an external dep silently disable a guard?
 13. Variant — does the same antipattern repeat nearby (variant analysis)?

Rationalizations to REJECT — never use these as a reason to refute:
  - "rapid analysis", "skipping for efficiency"
  - "pattern looks dangerous, must be real"
  - "similar code was vulnerable elsewhere"
  - "this is clearly critical, no need to verify"

Output policy: return a SINGLE JSON object on the LAST line of your reply
(no markdown fences after it). You may include short plain-text scratch
above it. Required shape:

  {
    "verdict": "confirmed|refuted|inconclusive",
    "reason":  "1-3 sentences grounded in code you read",
    "fix":     "optional concrete remediation hint",
    "defense_in_depth": true|false,
    "gates": {
      "control":            "pass|fail|n/a",
      "control_reason":     "...",
      "reachability":       "pass|fail|n/a",
      "reachability_reason":"...",
      "validation":         "pass|fail|n/a",
      "validation_reason":  "...",
      "api_contract":       "pass|fail|n/a",
      "api_contract_reason":"...",
      "environment":        "pass|fail|n/a",
      "environment_reason": "...",
      "impact":             "pass|fail|n/a",
      "impact_reason":      "..."
    },
    "devils_advocate": ["...","..."]
  }`
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
			Name:        "blame",
			Description: "VCS blame for a single line (git or arc, auto-detected). Returns commit, author, date, summary.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
					"line": map[string]any{"type": "integer"},
				},
				"required": []string{"path", "line"},
			},
		},
		{
			Name: "read_symbol",
			Description: "Read the full body of a named function/method from `path` using the AST index. " +
				"More precise than read_file when you know the symbol name. Falls back to grep when no AST is available.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Project-relative file path"},
					"name": map[string]any{"type": "string", "description": "Bare symbol name (e.g. 'HandleLogin')"},
				},
				"required": []string{"path", "name"},
			},
		},
		{
			Name: "find_callers",
			Description: "List functions that call `name`, with file:line. Uses the project call graph; " +
				"falls back to grep when the graph is unavailable. Use to assess reachability of a sink.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":     map[string]any{"type": "string", "description": "Bare symbol name"},
					"max_hits": map[string]any{"type": "integer", "description": "Cap on results (default 50)"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name: "find_callees",
			Description: "List functions that `name` itself calls, with file:line. " +
				"Use to trace data-flow forward from a source.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":     map[string]any{"type": "string"},
					"max_hits": map[string]any{"type": "integer"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "list_imports",
			Description: "List the imports declared in `path`. Useful for understanding which libraries (and therefore defaults / sanitizers) are in scope.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
				},
				"required": []string{"path"},
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
// It tolerates leading prose and code fences. Retained for backwards-
// compatible callers; new code should prefer parseGateVerdict.
func parseVerdict(text string) (verdict, reason, fix string) {
	verdict, reason, fix, _, _ = parseGateVerdict(text)
	return verdict, reason, fix
}

// parseGateVerdict is parseVerdict + the optional gates payload introduced
// by the fp-check methodology. Returns (verdict, reason, fix, gates,
// defenseInDepth). gates is nil when no gate fields were emitted.
//
// The locator is tolerant of:
//   - extra prose before the JSON ("Analysis...\n{...}")
//   - markdown fences (```json … ```)
//   - the JSON appearing anywhere as long as the LAST top-level "{...}" of
//     the message decodes successfully.
func parseGateVerdict(text string) (verdict, reason, fix string, gates *types.GateReview, defenseInDepth bool) {
	text = strings.TrimSpace(text)
	jsonPart, ok := extractLastJSONObject(text)
	if !ok {
		return "inconclusive", strings.TrimSpace(text), "", nil, false
	}
	var v struct {
		Verdict        string             `json:"verdict"`
		Reason         string             `json:"reason"`
		Fix            string             `json:"fix"`
		DefenseInDepth bool               `json:"defense_in_depth"`
		Gates          *verifierGatesJSON `json:"gates,omitempty"`
		Devils         []string           `json:"devils_advocate,omitempty"`
	}
	if err := json.Unmarshal([]byte(jsonPart), &v); err != nil {
		return "inconclusive", strings.TrimSpace(text), "", nil, false
	}
	verdict = strings.ToLower(strings.TrimSpace(v.Verdict))
	switch verdict {
	case "confirmed", "refuted", "inconclusive":
	default:
		verdict = "inconclusive"
	}
	gates = buildGateReview(v.Gates, v.Devils)
	return verdict, strings.TrimSpace(v.Reason), strings.TrimSpace(v.Fix), gates, v.DefenseInDepth
}

// extractLastJSONObject finds the rightmost balanced {...} block in s. It
// scans backwards from the last '}' and pairs braces while respecting JSON
// strings (so a literal '{' inside a "..." string does not throw off the
// match). Returns ("", false) when no balanced block is found.
func extractLastJSONObject(s string) (string, bool) {
	end := strings.LastIndex(s, "}")
	if end < 0 {
		return "", false
	}
	depth := 0
	inStr := false
	escape := false
	for i := end; i >= 0; i-- {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' {
			escape = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		switch c {
		case '}':
			depth++
		case '{':
			depth--
			if depth == 0 {
				return s[i : end+1], true
			}
		}
	}
	return "", false
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
