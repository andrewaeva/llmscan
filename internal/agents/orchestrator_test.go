package agents

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestOrchestratorFallbackWhenNilClient(t *testing.T) {
	o := &Orchestrator{}
	plan, err := o.Plan(context.Background(), "target", []types.FileTarget{{Path: "a.go"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Priority) != 1 || plan.Priority[0] != "a.go" {
		t.Errorf("fallback priority: %+v", plan.Priority)
	}
	if len(plan.Focus) == 0 {
		t.Errorf("focus empty: %+v", plan)
	}
}

func TestOrchestratorParsesPlan(t *testing.T) {
	resp := `{
		"reasoning": "looks injectable",
		"priority": ["a.go","b.go"],
		"focus": ["injection","auth"],
		"skip_globs": ["*.lock"],
		"agent_hints": {"injection":["b.go"]}
	}`
	cli := &stubClient{responses: []string{resp}}
	o := &Orchestrator{Client: cli}
	files := []types.FileTarget{{Path: "a.go", Lines: 50}, {Path: "b.go", Lines: 30}}
	plan, err := o.Plan(context.Background(), "/target", files, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reasoning != "looks injectable" {
		t.Errorf("reasoning=%q", plan.Reasoning)
	}
	if len(plan.Priority) != 2 || plan.Priority[0] != "a.go" {
		t.Errorf("priority=%+v", plan.Priority)
	}
	if len(plan.Focus) != 2 {
		t.Errorf("focus=%+v", plan.Focus)
	}
	if !strings.Contains(cli.last.Messages[0].Content, "/target") {
		t.Errorf("user prompt missing target: %q", cli.last.Messages[0].Content)
	}
}

func TestOrchestratorErrorFallsBack(t *testing.T) {
	cli := &stubClient{errs: []error{errors.New("rate")}, responses: []string{""}}
	o := &Orchestrator{Client: cli}
	plan, err := o.Plan(context.Background(), "/t", []types.FileTarget{{Path: "x.go"}}, "")
	if err == nil {
		t.Error("expected error propagation")
	}
	// Plan should still be the fallback
	if len(plan.Priority) != 1 {
		t.Errorf("fallback priority: %+v", plan)
	}
}

func TestOrchestratorBadJSONFallsBack(t *testing.T) {
	cli := &stubClient{responses: []string{`gibberish`}}
	o := &Orchestrator{Client: cli}
	plan, err := o.Plan(context.Background(), "/t", []types.FileTarget{{Path: "x.go"}}, "")
	if err == nil {
		t.Error("expected decode err")
	}
	if len(plan.Priority) != 1 || plan.Priority[0] != "x.go" {
		t.Errorf("fallback priority: %+v", plan)
	}
}

func TestOrchestratorEmptyPlanFallsBack(t *testing.T) {
	cli := &stubClient{responses: []string{`{"reasoning":"x"}`}}
	o := &Orchestrator{Client: cli}
	plan, err := o.Plan(context.Background(), "/t", []types.FileTarget{{Path: "x.go"}}, "ctx")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Priority) == 0 {
		t.Errorf("empty plan should fall back, got %+v", plan)
	}
	if len(plan.Focus) == 0 {
		t.Errorf("focus should be populated even after fallback: %+v", plan)
	}
}

func TestOrchestratorCapsFileListing(t *testing.T) {
	cli := &stubClient{responses: []string{`{"priority":["a.go"]}`}}
	o := &Orchestrator{Client: cli}
	files := make([]types.FileTarget, 700)
	for i := range files {
		files[i] = types.FileTarget{Path: "f.go", Lines: 1}
	}
	_, err := o.Plan(context.Background(), "/t", files, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cli.last.Messages[0].Content, "more files") {
		t.Errorf("prompt should mention cap: %q", cli.last.Messages[0].Content)
	}
}
