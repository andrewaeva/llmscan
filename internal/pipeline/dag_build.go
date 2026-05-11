package pipeline

import (
	"context"
	"fmt"
	"sort"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/dag"
	"github.com/andrewaeva/llmscan/internal/iac"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/skills"
	"github.com/andrewaeva/llmscan/internal/types"
)

// enabledScanners computes which scanner agents (built-in + skills + IaC) should run.
//
//nolint:gocyclo // routing across scanner kinds; flat dispatch
func (e *Engine) enabledScanners(plan types.ScanPlan, skillByName map[string]*skills.Skill, files []types.FileTarget) []string {
	focus := map[string]bool{}
	for _, f := range plan.Focus {
		focus[f] = true
	}
	// Names known to us: built-in scanner names ∪ skills with kind==scanner.
	names := map[string]bool{}
	for _, n := range agents.ScannerNames {
		names[n] = true
	}
	for name, sk := range skillByName {
		if sk.Kind == skills.KindScanner {
			names[name] = true
		}
	}
	// Enable IaC scanners when matching files are present.
	iacAgents := map[string]bool{}
	for _, f := range files {
		if k := iac.Detect(f.Path, f.Content); k != iac.KindNone {
			if a := iac.AgentName(k); a != "" {
				iacAgents[a] = true
			}
		}
	}
	for a := range iacAgents {
		names[a] = true
	}
	var out []string
	for name := range names {
		if !e.Cfg.IsAgentEnabled(name) {
			continue
		}
		if sk, ok := skillByName[name]; ok && !sk.IsEnabled() {
			continue
		}
		if len(focus) > 0 && !focus[name] {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		out = []string{"generic"}
	}
	return out
}

// buildDAG wires scanner / aggregate / dedup / verifier / fp_filter nodes.
//
//nolint:gocyclo // declarative graph wiring; cleaner inline than split
func (e *Engine) buildDAG(scannerNames []string, skillByName map[string]*skills.Skill, sc scanContext) (*dag.DAG, error) {
	chunks := sc.chunks
	contentByPath := sc.contentByPath
	index := sc.index

	// Build LLM clients for each scanner / verifier / fp_filter / context_filter once.
	scannerClients := map[string]llm.Client{}
	scannerPrompts := map[string]string{}
	for _, name := range scannerNames {
		client, err := llm.New(e.Cfg.ResolveModel(name))
		if err != nil {
			e.logf("scanner %s disabled: %v", name, err)
			continue
		}
		scannerClients[name] = client
		if sk, ok := skillByName[name]; ok && sk.Prompt != "" {
			scannerPrompts[name] = sk.Prompt
		}
	}
	if len(scannerClients) == 0 {
		return nil, fmt.Errorf("no scanner agents could be initialized")
	}

	// context_filter (optional)
	var cfilter *agents.ContextFilter
	if e.Cfg.IsAgentEnabled("context_filter") && index != nil {
		if cl, err := llm.New(e.Cfg.ResolveModel("context_filter")); err == nil {
			cfilter = &agents.ContextFilter{Client: cl}
		} else {
			e.logf("context_filter disabled: %v", err)
		}
	}

	// verifier
	var verifier *agents.Verifier
	if e.Cfg.IsAgentEnabled("verifier") {
		if cl, err := llm.New(e.Cfg.ResolveModel("verifier")); err == nil {
			verifier = &agents.Verifier{Client: cl}
		} else {
			e.logf("verifier disabled: %v", err)
		}
	}

	// fp_filter
	var fpFilter *agents.FPFilter
	if e.Cfg.IsAgentEnabled("fp_filter") {
		if cl, err := llm.New(e.Cfg.ResolveModel("fp_filter")); err == nil {
			fpFilter = &agents.FPFilter{Client: cl}
		} else {
			e.logf("fp_filter disabled: %v", err)
			fpFilter = &agents.FPFilter{}
		}
	} else {
		fpFilter = &agents.FPFilter{}
	}

	// ---- Nodes ----

	nodes := []*dag.Node{}

	// One scanner node per agent. Each runs over ALL chunks in parallel internally.
	for _, name := range scannerNames {
		client, ok := scannerClients[name]
		if !ok {
			continue
		}
		nm := name
		cl := client
		promptOverride := scannerPrompts[nm]
		nodes = append(nodes, &dag.Node{
			Name:      "scan:" + nm,
			DependsOn: nil,
			Run: func(ctx context.Context, _ map[string]any) (any, error) {
				return e.runScanner(ctx, nm, cl, promptOverride, chunks, index, cfilter, sc), nil
			},
		})
	}

	// Aggregator collects from every scanner.
	scanDeps := make([]string, 0, len(scannerClients))
	for _, name := range scannerNames {
		if _, ok := scannerClients[name]; ok {
			scanDeps = append(scanDeps, "scan:"+name)
		}
	}
	nodes = append(nodes, &dag.Node{
		Name:      "scan_aggregate",
		DependsOn: scanDeps,
		Run: func(_ context.Context, inputs map[string]any) (any, error) {
			var all []types.Finding
			for _, v := range inputs {
				if fs, ok := v.([]types.Finding); ok {
					all = append(all, fs...)
				}
			}
			return all, nil
		},
	})

	// Deterministic dedup.
	nodes = append(nodes, &dag.Node{
		Name:      "dedup",
		DependsOn: []string{"scan_aggregate"},
		Run: func(_ context.Context, inputs map[string]any) (any, error) {
			fs, _ := inputs["scan_aggregate"].([]types.Finding)
			return dedupAndCount(fs), nil
		},
	})

	// Verifier (per-finding, parallel).
	nodes = append(nodes, &dag.Node{
		Name:      "verifier",
		DependsOn: []string{"dedup"},
		Run: func(ctx context.Context, inputs map[string]any) (any, error) {
			fs, _ := inputs["dedup"].([]types.Finding)
			if verifier == nil {
				return fs, nil
			}
			return e.verifyAll(ctx, verifier, fs, contentByPath), nil
		},
	})

	// FP filter (LLM-judge + deterministic dedup).
	nodes = append(nodes, &dag.Node{
		Name:      "fp_filter",
		DependsOn: []string{"verifier"},
		Run: func(ctx context.Context, inputs map[string]any) (any, error) {
			fs, _ := inputs["verifier"].([]types.Finding)
			out, err := fpFilter.Apply(ctx, fs)
			if err != nil {
				e.logf("fp_filter: %v", err)
				return fs, nil
			}
			return out, nil
		},
	})

	return dag.Build(nodes)
}
