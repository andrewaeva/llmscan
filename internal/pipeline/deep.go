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
	"github.com/andrewaeva/llmscan/internal/vcs"
)

type deepHotspot struct {
	index   int
	finding types.Finding
}

// runDeepPass runs the optional sub-agent verification pass over high-severity
// findings. It mutates `findings` in place, attaching DeepVerified/Verdict/
// Comment/Trace, and returns the same slice for chaining.
//
// Errors at the per-finding level are absorbed into Verdict="inconclusive"
// so a single failed hotspot never aborts the whole scan.
//
//nolint:gocyclo // sequential pipeline stages; restructure would obscure flow
func (e *Engine) runDeepPass(ctx context.Context, target string, cdb cache.Cache, findings []types.Finding, idx *tools.SymbolIndex) []types.Finding {
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
	// Wire up VCS so the blame tool dispatches to the right backend (git/arc).
	if v, derr := vcs.Detect(sandbox.Root); derr == nil && v != nil && v.Kind() != vcs.KindNone {
		sandbox.VCS = v
	}
	// Wire up project indices for read_symbol / find_callers / find_callees /
	// list_imports. When idx is nil the tools degrade to grep fallbacks.
	if idx != nil {
		sandbox.SetIndex(idx)
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
	if cfg.BaseURL != "" {
		spec.BaseURL = cfg.BaseURL
	}
	if cfg.APIKeyEnv != "" {
		spec.APIKeyEnv = cfg.APIKeyEnv
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
	hotspots := collectDeepHotspots(findings, cfg.MinSeverity)
	sort.SliceStable(hotspots, func(a, b int) bool {
		ra := severityRank(string(hotspots[a].finding.Severity))
		rb := severityRank(string(hotspots[b].finding.Severity))
		if ra != rb {
			return ra > rb
		}
		if hotspots[a].finding.File != hotspots[b].finding.File {
			return hotspots[a].finding.File < hotspots[b].finding.File
		}
		return hotspots[a].finding.StartLine < hotspots[b].finding.StartLine
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

	e.prog().Stage("deep", len(hotspots))
	defer e.prog().Done("deep")

	// 4) Fan out.
	agent := &agents.DeepAgent{
		Client:    tc,
		Sandbox:   sandbox,
		Cache:     cdb,
		UseCache:  cfg.Cache,
		Budget:    deepBudget(cfg),
		Verbose:   e.Verbose,
		Logf:      e.logf,
		ModelName: spec.Model,
		// Skill override is resolved once per pass.
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
			res := agent.Verify(ctx, hs.finding)
			e.logf("deep[%d] %s:%d -> %s (%dms, %d tool calls)",
				hs.index, hs.finding.File, hs.finding.StartLine, res.Verdict,
				time.Since(t0).Milliseconds(), len(res.Trace))
			applyDeepResult(&findings[hs.index], res)
			e.prog().Inc("deep", 1)
		}()
	}
	wg.Wait()
	e.logf("deep: pass completed in %s", time.Since(start).Round(time.Millisecond))

	// Optional debate / cross-examination pass over the deep-verified
	// findings. Cheap relative to the deep tool-loop (2-4 extra LLM calls
	// per hotspot, no tools) and orthogonal: catches confirmation bias the
	// single deep pass missed.
	if cfg.Debate {
		indices := make([]int, 0, len(hotspots))
		for _, h := range hotspots {
			indices = append(indices, h.index)
		}
		e.runDebatePass(ctx, rawClient, findings, indices)
	}
	return findings
}

// runDebatePass invokes the Debater on every hotspot whose deep verdict is
// not a clear refute. Disagreement after MaxRounds applies a 0.7 score
// penalty and tags the finding "debate-split".
//
// Per-finding routing is expressed as a small LangGraph-style state machine
// (internal/agents.Graph). The nodes are:
//
//	gate    -> filter (suppressed / FP / refuted -> End)
//	debate  -> call Debater.Debate, store result in state
//	apply   -> mutate the underlying finding based on the verdict
//
// The router on "gate" picks debate or End; the router on "debate" always
// flows into apply -> End. This is small enough that a switch would also
// work, but keeping it in the graph means every routing decision shows up
// in --verbose output with a stable node name.
func (e *Engine) runDebatePass(ctx context.Context, cl llm.Client, findings []types.Finding, indices []int) {
	cfg := e.Cfg.Deep
	maxR := cfg.DebateMaxRounds
	if maxR <= 0 {
		maxR = 2
	}
	deb := &agents.Debater{
		Client:        cl,
		MaxRounds:     maxR,
		ProponentTemp: 0.3,
		OpponentTemp:  0.6,
		Verbose:       e.Verbose,
		Logf:          e.logf,
	}
	g := buildDebateGraph(deb, e.logf)
	start := time.Now()
	e.prog().Stage("debate", len(indices))
	defer e.prog().Done("debate")
	var splits, agreed int
	for _, i := range indices {
		st := &debateState{f: &findings[i]}
		if err := g.Run(ctx, st); err != nil {
			e.logf("debate graph[%d]: %v", i, err)
			continue
		}
		switch st.applied {
		case "split":
			splits++
		case "tp", "fp":
			agreed++
		}
		e.prog().Inc("debate", 1)
	}
	e.logf("debate: %d agreed, %d split (in %s)", agreed, splits, time.Since(start).Round(time.Millisecond))
}

// debateState is the state carried through buildDebateGraph. It points at
// the live finding so apply-node mutations land in the caller's slice.
type debateState struct {
	f       *types.Finding
	result  agents.DebateResult
	applied string // "tp" | "fp" | "split" | "" (skipped or inconclusive)
}

func buildDebateGraph(deb *agents.Debater, logf func(string, ...any)) *agents.Graph[debateState] {
	g := agents.NewGraph[debateState]()
	g.Logf = logf

	g.AddNode("gate", func(_ context.Context, _ *debateState) error { return nil })
	g.SetRouter("gate", func(s *debateState) string {
		if s.f == nil || s.f.FalsePositive || s.f.Suppressed {
			return agents.End
		}
		if s.f.DeepVerdict == "refuted" {
			return agents.End
		}
		return "debate"
	})

	g.AddNode("debate", func(ctx context.Context, s *debateState) error {
		s.result = deb.Debate(ctx, *s.f, s.f.DeepComment)
		return nil
	})
	g.AddEdge("debate", "apply")

	g.AddNode("apply", func(_ context.Context, s *debateState) error {
		res := s.result
		switch res.Verdict {
		case "split":
			s.f.Tags = appendUniqueTag(s.f.Tags, "debate-split")
			if s.f.Score > 0 {
				s.f.Score *= res.SplitPenalty
			}
			if s.f.VerifierComment == "" {
				s.f.VerifierComment = res.Rationale
			}
			s.applied = "split"
		case "fp":
			s.f.FalsePositive = true
			if s.f.FPReason == "" {
				s.f.FPReason = "debate consensus: " + res.Rationale
			}
			s.f.Tags = appendUniqueTag(s.f.Tags, "debate-fp")
			s.applied = "fp"
		case "tp":
			s.f.Tags = appendUniqueTag(s.f.Tags, "debate-tp")
			s.applied = "tp"
		}
		return nil
	})
	g.AddEdge("apply", agents.End)

	g.SetEntry("gate")
	return g
}

func appendUniqueTag(tags []string, v string) []string {
	for _, t := range tags {
		if t == v {
			return tags
		}
	}
	return append(tags, v)
}

func collectDeepHotspots(findings []types.Finding, minSeverity string) []deepHotspot {
	// fp-check escalation rule: even when severity is below the threshold,
	// escalate findings the standard verifier flagged inconclusive so the
	// deep path can resolve them.
	threshold := severityRank(minSeverity)
	hotspots := make([]deepHotspot, 0, len(findings))
	for i, f := range findings {
		if f.Suppressed || f.FalsePositive {
			continue
		}
		if severityRank(string(f.Severity)) < threshold && !isInconclusive(f) {
			continue
		}
		hotspots = append(hotspots, deepHotspot{index: i, finding: f})
	}
	return hotspots
}

func applyDeepResult(f *types.Finding, res agents.DeepResult) {
	f.DeepVerified = true
	f.DeepVerdict = res.Verdict
	f.DeepComment = res.Reason
	f.DeepModel = res.Model
	f.DeepTrace = res.Trace

	// Merge the deep agent's six-gate review (if any). ApplyGates keeps
	// existing gate state on a no-op and otherwise mutates FalsePositive /
	// Severity / DefenseInDepth consistently with the standard verifier.
	if res.Gates != nil {
		_ = types.ApplyGates(f, res.Gates)
	}
	if res.Verdict == "refuted" {
		f.FalsePositive = true
		if f.FPReason == "" {
			f.FPReason = "deep agent refuted: " + res.Reason
		}
	}
	if res.DefenseInDepth {
		f.DefenseInDepth = true
		if f.Severity != types.SevInfo {
			f.Severity = types.SevLow
		}
	}
	if res.Fix != "" && f.SuggestedFix == "" {
		f.SuggestedFix = res.Fix
	}
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
