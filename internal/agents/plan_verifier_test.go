package agents

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/tools"
	"github.com/andrewaeva/llmscan/internal/types"
)

func TestPlanVerifierVerifyRefutedFromGates(t *testing.T) {
	sandbox, err := tools.NewSandbox(t.TempDir())
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	planner := &stubClient{responses: []string{`{"steps":["read_file path/x.go lines 10-30","find_callers HandleLogin"]}`}}
	final := `Plan executed.

{
  "verdict": "refuted",
  "reason": "framework auto-escapes the sink",
  "fix": "",
  "defense_in_depth": false,
  "gates": {
    "control":"pass","control_reason":"x",
    "reachability":"pass","reachability_reason":"x",
    "validation":"fail","validation_reason":"sanitizer runs upstream",
    "api_contract":"pass","api_contract_reason":"x",
    "environment":"n/a","environment_reason":"x",
    "impact":"pass","impact_reason":"x"
  }
}`
	executor := &stubToolClient{toolResp: llm.ToolResponse{FinalText: final, Model: "stub-model"}}

	pv := &PlanVerifier{
		Planner:   planner,
		Executor:  executor,
		Sandbox:   sandbox,
		Budget:    5,
		ModelName: "stub-model",
	}
	f := types.Finding{File: "path/x.go", StartLine: 10, EndLine: 12, Severity: types.SevHigh}
	got, err := pv.Verify(context.Background(), f, "  10 | foo\n  11 | bar\n")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Verified {
		t.Errorf("expected Verified=true, got %+v", got)
	}
	if got.VerifierVerdict != "refuted" {
		t.Errorf("verdict=%q want refuted", got.VerifierVerdict)
	}
	if !got.FalsePositive && got.Severity == types.SevHigh {
		t.Errorf("expected gate-driven downgrade or FP; got %+v", got)
	}
	if !strings.Contains(executor.gotRequest.System, "Plan-and-Execute") {
		t.Errorf("executor system prompt missing: %q", executor.gotRequest.System)
	}
}

func TestPlanVerifierPlannerErrorReturnsOriginal(t *testing.T) {
	sandbox, _ := tools.NewSandbox(t.TempDir())
	planner := &stubClient{errs: []error{errors.New("rate limited")}}
	executor := &stubToolClient{}

	pv := &PlanVerifier{Planner: planner, Executor: executor, Sandbox: sandbox}
	f := types.Finding{File: "x.go", StartLine: 1, EndLine: 2}
	got, err := pv.Verify(context.Background(), f, "")
	if err == nil {
		t.Fatalf("expected error from planner")
	}
	if got.Verified {
		t.Errorf("expected unchanged finding when planner fails, got Verified=true")
	}
}

func TestPlanVerifierMissingConfig(t *testing.T) {
	pv := &PlanVerifier{}
	_, err := pv.Verify(context.Background(), types.Finding{}, "")
	if err == nil {
		t.Fatalf("expected error for missing config")
	}
}

func TestPlanVerifierExecutorConfig(t *testing.T) {
	pv := &PlanVerifier{}
	system, budget := pv.executorConfig()
	if system != planVerifierExecutorSystem {
		t.Fatalf("system=%q want default", system)
	}
	if budget != 30 {
		t.Fatalf("budget=%d want 30", budget)
	}

	pv.ExecutorPromptOverride = "custom executor prompt"
	pv.Budget = 7
	system, budget = pv.executorConfig()
	if system != "custom executor prompt" {
		t.Fatalf("system=%q want custom override", system)
	}
	if budget != 7 {
		t.Fatalf("budget=%d want 7", budget)
	}
}

func TestPlanVerifierApplyExecutorVerdictModelSelectionAndFP(t *testing.T) {
	resp := llm.ToolResponse{
		Model: "response-model",
		FinalText: `{
			"verdict":"refuted",
			"reason":"sink is unreachable from untrusted input"
		}`,
	}

	pv := &PlanVerifier{}
	got := pv.applyExecutorVerdict(types.Finding{Severity: types.SevHigh}, resp)
	if !got.Verified {
		t.Fatalf("expected verified finding")
	}
	if got.VerifierModel != "response-model" {
		t.Fatalf("VerifierModel=%q want response-model", got.VerifierModel)
	}
	if !got.FalsePositive {
		t.Fatalf("expected false_positive=true for refuted verdict without gates")
	}
	if got.FPReason != "sink is unreachable from untrusted input" {
		t.Fatalf("FPReason=%q", got.FPReason)
	}

	pv = &PlanVerifier{ModelName: "override-model"}
	got = pv.applyExecutorVerdict(types.Finding{Severity: types.SevHigh}, resp)
	if got.VerifierModel != "override-model" {
		t.Fatalf("VerifierModel=%q want override-model", got.VerifierModel)
	}
}
