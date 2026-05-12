// plan_verifier.go implements a Plan-and-Execute verifier — an alternative
// to the single-shot Verifier that runs in two phases:
//
//  1. Planner: an LLM produces a short, ordered list of verification steps
//     ("read the cited range", "find callers of X", "look for sanitizer Y").
//
//  2. Executor: a tool-using LLM walks those steps with the same toolbox the
//     DeepAgent uses (read_file, read_symbol, find_callers, find_callees,
//     list_imports, grep, list_dir, blame) and emits the final six-gate
//     verdict.
//
// Unlike DeepAgent it operates on every finding (not just hotspots) and
// replaces the standard Verifier when precision.plan_verify is enabled.
// Errors at any phase fall back to returning the original Finding unchanged.
package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/tools"
	"github.com/andrewaeva/llmscan/internal/types"
)

// PlanVerifier is the public configuration for the plan-and-execute verifier.
type PlanVerifier struct {
	// Planner produces the step list. A plain llm.Client is sufficient.
	Planner llm.Client
	// Executor runs the steps with tool access.
	Executor llm.ToolClient
	// Sandbox is the read-only filesystem root + symbol index the executor
	// can inspect.
	Sandbox *tools.Sandbox
	// Budget caps the number of tool calls per finding. 0 -> 30.
	Budget int
	// MaxSteps caps the number of planner-emitted steps. 0 -> 8.
	MaxSteps int
	// Verbose enables per-finding diagnostic logs via Logf.
	Verbose bool
	Logf    func(format string, args ...any)
	// ModelName is recorded onto the Finding for reporting.
	ModelName string
	// PlannerPromptOverride replaces planVerifierPlannerSystem when set.
	PlannerPromptOverride string
	// ExecutorPromptOverride replaces planVerifierExecutorSystem when set.
	ExecutorPromptOverride string
}

func (p *PlanVerifier) logf(format string, args ...any) {
	if !p.Verbose || p.Logf == nil {
		return
	}
	p.Logf(format, args...)
}

// Verify runs the plan-and-execute loop for a single finding. It mirrors the
// shape of Verifier.Verify so the pipeline can swap it in transparently.
func (p *PlanVerifier) Verify(ctx context.Context, f types.Finding, contextSnippet string) (types.Finding, error) {
	if p.Planner == nil || p.Executor == nil || p.Sandbox == nil {
		// Misconfigured: behave like no-op verifier so the pipeline keeps
		// running with the original finding.
		return f, fmt.Errorf("plan_verifier: missing planner / executor / sandbox")
	}

	// ---- Phase 1: plan ----
	plan, err := p.makePlan(ctx, f, contextSnippet)
	if err != nil {
		p.logf("plan_verifier[%s:%d] planner error: %v", shortFile(f.File), f.StartLine, err)
		return f, err
	}
	if len(plan) == 0 {
		// Empty plan still gives the executor a chance to fall back to
		// reading the cited range.
		plan = []string{"Re-read the cited range and the immediate caller; emit the six-gate verdict."}
	}
	p.logf("plan_verifier[%s:%d] plan(%d): %s", shortFile(f.File), f.StartLine, len(plan), oneLine(strings.Join(plan, " | ")))

	// ---- Phase 2: execute ----
	return p.executePlan(ctx, f, contextSnippet, plan)
}

// makePlan asks the planner LLM for a short, ordered list of verification
// steps. The planner has no tools — it works purely from the finding and the
// surrounding snippet.
func (p *PlanVerifier) makePlan(ctx context.Context, f types.Finding, contextSnippet string) ([]string, error) {
	system := p.PlannerPromptOverride
	if system == "" {
		system = planVerifierPlannerSystem
	}
	maxSteps := p.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 8
	}
	user := fmt.Sprintf(`Finding:
%s

Surrounding code (with line numbers):
%s

Produce up to %d concrete verification steps as JSON: {"steps":["...","..."]}
Each step must be one sentence and reference a tool when possible
(read_file/read_symbol/find_callers/find_callees/list_imports/grep).`,
		mustJSON(f), contextSnippet, maxSteps)

	resp, err := p.Planner.Complete(ctx, llm.Request{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		JSON:     true,
	})
	if err != nil {
		return nil, err
	}
	var pj struct {
		Steps []string `json:"steps"`
	}
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &pj); err != nil {
		return nil, fmt.Errorf("plan_verifier: planner decode: %w; raw=%q", err, truncate(resp.Text, 200))
	}
	// Trim & cap.
	out := make([]string, 0, len(pj.Steps))
	for _, s := range pj.Steps {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
		if len(out) >= maxSteps {
			break
		}
	}
	return out, nil
}

// executePlan runs the steps through a tool-using LLM identical to DeepAgent
// (same toolbox, same gate output schema) and merges the verdict onto the
// finding.
func (p *PlanVerifier) executePlan(ctx context.Context, f types.Finding, contextSnippet string, plan []string) (types.Finding, error) {
	system := p.ExecutorPromptOverride
	if system == "" {
		system = planVerifierExecutorSystem
	}
	budget := p.Budget
	if budget <= 0 {
		budget = 30
	}

	user := planExecutorUserPrompt(f, contextSnippet, plan)

	var trace []types.DeepToolCall
	step := 0
	// Reuse the same dispatcher as DeepAgent — same tools, same arg shapes.
	// We construct a thin shim DeepAgent purely for dispatch.
	shim := &DeepAgent{Sandbox: p.Sandbox}
	handler := func(ctx context.Context, call llm.ToolCall) llm.ToolResult {
		step++
		t0 := time.Now()
		out, ferr := shim.dispatch(ctx, call)
		elapsed := time.Since(t0).Milliseconds()

		args := compactJSON(call.Input)
		if len(args) > 200 {
			args = args[:200] + "..."
		}
		result := out
		if len(result) > 512 {
			result = result[:512] + "..."
		}
		errStr := ""
		if ferr != nil {
			errStr = ferr.Error()
		}
		trace = append(trace, types.DeepToolCall{
			Step:   step,
			Tool:   call.Name,
			Args:   args,
			Result: result,
			Error:  errStr,
			Ms:     elapsed,
		})
		if ferr != nil {
			return llm.ToolResult{ID: call.ID, Content: "error: " + ferr.Error(), IsError: true}
		}
		return llm.ToolResult{ID: call.ID, Content: out}
	}

	resp, err := p.Executor.CompleteWithTools(ctx, llm.ToolRequest{
		System:   system,
		Messages: []llm.Message{{Role: "user", Content: user}},
		Tools:    deepToolDefs(),
		Handler:  handler,
		MaxSteps: budget,
	})
	if err != nil {
		return f, err
	}

	verdict, reason, fix, gates, defenseInDepth := parseGateVerdict(resp.FinalText)

	// Stash baseline metadata first so gate logic below can override safely.
	f.Verified = true
	f.VerifierVerdict = verdict
	f.VerifierComment = reason
	if p.ModelName != "" {
		f.VerifierModel = p.ModelName
	} else {
		f.VerifierModel = resp.Model
	}
	if fix != "" {
		f.SuggestedFix = fix
	}

	// Apply gates (same semantics as Verifier).
	outcome := types.ApplyGates(&f, gates)
	if defenseInDepth && !f.DefenseInDepth {
		f.DefenseInDepth = true
		if f.Severity != types.SevInfo {
			f.Severity = types.SevLow
		}
	}
	if outcome == types.GateOutcomeUnknown && verdict == "refuted" {
		f.FalsePositive = true
		if reason != "" {
			f.FPReason = reason
		}
	}
	return f, nil
}

func planExecutorUserPrompt(f types.Finding, contextSnippet string, plan []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Candidate finding:\n%s\n\n", mustJSON(f))
	if contextSnippet != "" {
		fmt.Fprintf(&b, "Surrounding code (line-numbered):\n%s\n", contextSnippet)
	}
	fmt.Fprintf(&b, "\nExecute this plan, then emit the final JSON verdict on the last line.\n")
	for i, s := range plan {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
	}
	fmt.Fprintf(&b, "\nUse tools to actually check each step; do not hand-wave. Stop early if the\nverdict is already obvious — the budget is bounded.\n")
	return b.String()
}

// ---- Prompts ----

const planVerifierPlannerSystem = `You are the planner of a Plan-and-Execute verifier for security findings.
Given ONE candidate finding and its surrounding code, produce a short, ordered
plan (max 8 steps) that another agent will execute with read-only tools.

Each step must:
  - be ONE sentence
  - reference a specific tool when possible (read_file, read_symbol, find_callers,
    find_callees, list_imports, grep)
  - move toward deciding the six gates (control / reachability / validation /
    api_contract / environment / impact)

Prefer fewer high-leverage steps over many shallow ones. Do NOT include a step
that says "make the final decision" — the executor handles that.

Output a single JSON object: {"steps":["read_symbol of the handler","find_callers of the sink","..."]}`

const planVerifierExecutorSystem = `You are the executor of a Plan-and-Execute verifier. You are given:
  - the candidate finding
  - the surrounding code snippet
  - a numbered plan of verification steps produced by a planner

You have read-only tools:
  - read_file(path, start_line, end_line)
  - read_symbol(path, name)
  - find_callers(name, max_hits)
  - find_callees(name, max_hits)
  - list_imports(path)
  - grep(pattern, path_glob, max_matches)
  - list_dir(path) / blame(path, line)

Execute the plan in order. You MAY deviate (skip, reorder, or add a step) when
intermediate evidence makes a step pointless or insufficient — explain in one
sentence in your scratch text. Stop as soon as the six gates can be decided.

Apply the same six-gate methodology as the deep agent:
  1. Control       — attacker really controls the source?
  2. Reachability  — sink reachable on a realistic execution path?
  3. Validation    — upstream validation blocks exploitation?
  4. APIContract   — sink API is self-defending?
  5. Environment   — runtime/compiler/OS mitigates the issue?
  6. Impact        — real security impact (RCE/exfil/privesc) vs robustness?

Verdict rules:
  - Gate 3/4/5 FAIL ⇒ "refuted" (upstream defense)
  - Gate 1/2 FAIL   ⇒ "refuted" (no control / unreachable)
  - Gate 6 FAIL only ⇒ "confirmed" with defense_in_depth=true
  - All gates PASS (or PASS with N/A) ⇒ "confirmed"
  - Otherwise ⇒ "inconclusive"

Output a SINGLE JSON object on the LAST line of your reply. Schema:
  {
    "verdict": "confirmed|refuted|inconclusive",
    "reason":  "1-3 sentences grounded in code you read",
    "fix":     "optional concrete remediation hint",
    "defense_in_depth": true|false,
    "gates": {
      "control":"pass|fail|n/a","control_reason":"...",
      "reachability":"pass|fail|n/a","reachability_reason":"...",
      "validation":"pass|fail|n/a","validation_reason":"...",
      "api_contract":"pass|fail|n/a","api_contract_reason":"...",
      "environment":"pass|fail|n/a","environment_reason":"...",
      "impact":"pass|fail|n/a","impact_reason":"..."
    },
    "devils_advocate": ["..."]
  }`
