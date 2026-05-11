package pipeline

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/andrewaeva/llmscan/internal/agents"
	"github.com/andrewaeva/llmscan/internal/cache"
	"github.com/andrewaeva/llmscan/internal/config"
	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/tools"
	"github.com/andrewaeva/llmscan/internal/types"
)

// runDeepPass runs the optional sub-agent verification pass over high-severity
// findings. It mutates `findings` in place, attaching DeepVerified/Verdict/
// Comment/Trace, and returns the same slice for chaining.
//
// Errors at the per-finding level are absorbed into Verdict="inconclusive"
// so a single failed hotspot never aborts the whole scan.
//
//nolint:gocyclo // sequential pipeline stages; restructure would obscure flow
func (e *Engine) runDeepPass(ctx context.Context, target string, cdb *cache.DB, findings []types.Finding) []types.Finding {
	cfg := e.Cfg.Deep
	if !cfg.Enabled || len(findings) == 0 {
		return findings
	}

	// 1) Build sandbox rooted at the scan target.
	sandbox, err := tools.NewSandbox(target)
	if err != nil {
		e.logf("deep: sandbox init failed: %v (deep skipped)", err)
		return findings
	}
	if cfg.MaxFileBytes > 0 {
		sandbox.MaxFileBytes = cfg.MaxFileBytes
	}

	// 2) Build a tool-capable LLM client. Falls back to default model if the
	//    deep-specific model is unset.
	spec := e.Cfg.DefaultModel
	if cfg.Model != "" {
		spec.Model = cfg.Model
	}
	if cfg.Provider != "" {
		spec.Provider = cfg.Provider
	}
	rawClient, err := llm.New(spec)
	if err != nil {
		e.logf("deep: llm init failed: %v (deep skipped)", err)
		return findings
	}
	tc, ok := rawClient.(llm.ToolClient)
	if !ok {
		e.logf("deep: provider %s does not support tool-calling (deep skipped)", spec.Provider)
		return findings
	}

	// 3) Pick hotspots from final findings: severity >= threshold, not FP, not
	//    suppressed. Sort by severity (worst first), then file:line, cap.
	//
	// fp-check escalation rule: even when severity is below the threshold,
	// escalate findings the standard verifier flagged "inconclusive" so the
	// deep path can resolve them.
	threshold := severityRank(cfg.MinSeverity)
	type idxF struct {
		i int
		f types.Finding
	}
	var hotspots []idxF
	for i, f := range findings {
		if f.Suppressed || f.FalsePositive {
			continue
		}
		inconclusive := isInconclusive(f)
		if severityRank(string(f.Severity)) < threshold && !inconclusive {
			continue
		}
		hotspots = append(hotspots, idxF{i: i, f: f})
	}
	sort.SliceStable(hotspots, func(a, b int) bool {
		ra := severityRank(string(hotspots[a].f.Severity))
		rb := severityRank(string(hotspots[b].f.Severity))
		if ra != rb {
			return ra > rb
		}
		if hotspots[a].f.File != hotspots[b].f.File {
			return hotspots[a].f.File < hotspots[b].f.File
		}
		return hotspots[a].f.StartLine < hotspots[b].f.StartLine
	})
	maxH := cfg.MaxHotspots
	if maxH <= 0 {
		maxH = 20
	}
	if len(hotspots) > maxH {
		e.logf("deep: %d hotspots eligible, capping at %d", len(hotspots), maxH)
		hotspots = hotspots[:maxH]
	}
	if len(hotspots) == 0 {
		e.logf("deep: no hotspots meet severity threshold %q", cfg.MinSeverity)
		return findings
	}

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 4
	}
	e.logf("deep: verifying %d hotspots (budget=%d, conc=%d, model=%s)",
		len(hotspots), deepBudget(cfg), conc, spec.Model)

	// 4) Fan out.
	agent := &agents.DeepAgent{
		Client:         tc,
		Sandbox:        sandbox,
		Cache:          cdb,
		UseCache:       cfg.Cache,
		Budget:         deepBudget(cfg),
		Verbose:        e.Verbose,
		Logf:           e.logf,
		ModelName:      spec.Model,
		PromptOverride: e.loadSpecialSkill("_fpcheck-deep"),
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	start := time.Now()

	for _, hs := range hotspots {
		wg.Add(1)
		hs := hs
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			t0 := time.Now()
			res := agent.Verify(ctx, hs.f)
			e.logf("deep[%d] %s:%d -> %s (%dms, %d tool calls)",
				hs.i, hs.f.File, hs.f.StartLine, res.Verdict,
				time.Since(t0).Milliseconds(), len(res.Trace))

			findings[hs.i].DeepVerified = true
			findings[hs.i].DeepVerdict = res.Verdict
			findings[hs.i].DeepComment = res.Reason
			findings[hs.i].DeepModel = res.Model
			findings[hs.i].DeepTrace = res.Trace
			// Merge the deep agent's six-gate review (if any). ApplyGates
			// keeps existing gate state on a no-op and otherwise mutates
			// FalsePositive / Severity / DefenseInDepth consistently with
			// the standard verifier.
			if res.Gates != nil {
				_ = types.ApplyGates(&findings[hs.i], res.Gates)
			}
			if res.Verdict == "refuted" {
				findings[hs.i].FalsePositive = true
				if findings[hs.i].FPReason == "" {
					findings[hs.i].FPReason = "deep agent refuted: " + res.Reason
				}
			}
			if res.DefenseInDepth {
				findings[hs.i].DefenseInDepth = true
				if findings[hs.i].Severity != types.SevInfo {
					findings[hs.i].Severity = types.SevLow
				}
			}
			if res.Fix != "" && findings[hs.i].SuggestedFix == "" {
				findings[hs.i].SuggestedFix = res.Fix
			}
		}()
	}
	wg.Wait()
	e.logf("deep: pass completed in %s", time.Since(start).Round(time.Millisecond))
	return findings
}

func deepBudget(cfg config.DeepConfig) int {
	if cfg.Budget > 0 {
		return cfg.Budget
	}
	return 40
}

// isInconclusive reports whether the standard verifier left this finding
// unresolved (verdict="inconclusive" / "needs_more_context", or gates with
// an inconclusive outcome). Used by runDeepPass to decide whether to
// escalate even when severity is below the threshold.
func isInconclusive(f types.Finding) bool {
	switch f.VerifierVerdict {
	case "inconclusive", "needs_more_context":
		return true
	}
	if f.Gates != nil {
		switch f.Gates.Classify() {
		case types.GateOutcomeInconclusive, types.GateOutcomeUnknown:
			return true
		}
	}
	return false
}

// severityRank converts a severity string to a comparable number.
// Higher = more severe. Unknown values rank at 0.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}
