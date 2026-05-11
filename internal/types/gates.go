package types

import "strings"

// NormalizeGate maps an arbitrary string (as produced by an LLM) to one of the
// four canonical Gate values. Whitespace is trimmed and case is folded so that
// "PASS", "Pass", "pass" all collapse to GatePass.
func NormalizeGate(s string) Gate {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pass", "ok", "yes", "supports", "true":
		return GatePass
	case "fail", "blocked", "no", "refutes", "false":
		return GateFail
	case "n/a", "na", "not applicable", "unknown-na":
		return GateNotApp
	}
	return GateUnknown
}

// AnyEvaluated reports whether at least one gate in the review carries a
// non-empty status. Useful to decide whether the review block is worth
// rendering at all.
func (g *GateReview) AnyEvaluated() bool {
	if g == nil {
		return false
	}
	return g.Control != GateUnknown ||
		g.Reachability != GateUnknown ||
		g.Validation != GateUnknown ||
		g.APIContract != GateUnknown ||
		g.Environment != GateUnknown ||
		g.Impact != GateUnknown
}

// GateOutcome categorizes a GateReview into one of the verdict buckets
// described in the Trail of Bits fp-check methodology. See ApplyGates.
type GateOutcome int

const (
	// GateOutcomeUnknown means the review is empty or every gate is N/A —
	// caller should leave the finding untouched.
	GateOutcomeUnknown GateOutcome = iota
	// GateOutcomeConfirmed means every evaluated gate either passed or is
	// not applicable; treat the finding as a confirmed true positive.
	GateOutcomeConfirmed
	// GateOutcomeRefutedNoControl means Gate 1 (Control) or Gate 2
	// (Reachability) failed — attacker either does not control the source
	// or cannot reach the sink.
	GateOutcomeRefutedNoControl
	// GateOutcomeRefutedDefended means Gate 3 (Validation), Gate 4 (API
	// contract), or Gate 5 (Environment) failed — there is an upstream
	// defense that blocks exploitation. Strongest FP signal.
	GateOutcomeRefutedDefended
	// GateOutcomeDefenseInDepth means the only failing gate is Gate 6
	// (Impact) — the bug is real but lacks security impact. Downgrade,
	// don't drop.
	GateOutcomeDefenseInDepth
	// GateOutcomeInconclusive means at least one gate is unknown / blank
	// while no failing gate is present. Leave the finding unchanged.
	GateOutcomeInconclusive
)

// Classify computes the GateOutcome for a review using the rules from the
// Trail of Bits fp-check methodology. The function is pure — it does not
// mutate the receiver.
func (g *GateReview) Classify() GateOutcome {
	if g == nil || !g.AnyEvaluated() {
		return GateOutcomeUnknown
	}
	// Strongest refutation: an upstream defense blocks the exploit.
	if g.anyDefenseFail() {
		return GateOutcomeRefutedDefended
	}
	// Attacker has no control or path: refuted.
	if g.Control == GateFail || g.Reachability == GateFail {
		return GateOutcomeRefutedNoControl
	}
	// Only Gate 6 failed: defense-in-depth, not a primary security bug.
	if g.Impact == GateFail {
		return GateOutcomeDefenseInDepth
	}
	// At this point no gate FAIL'd. Either everything PASS'd (or is N/A)
	// → confirmed; or some are still GateUnknown → inconclusive. Must
	// have at least one PASS to call it confirmed; pure N/A means
	// inconclusive (no positive evidence either way).
	if !g.allDecided() || !g.anyPass() {
		return GateOutcomeInconclusive
	}
	return GateOutcomeConfirmed
}

// anyDefenseFail reports whether Gate 3, 4, or 5 failed.
func (g *GateReview) anyDefenseFail() bool {
	return g.Validation == GateFail ||
		g.APIContract == GateFail ||
		g.Environment == GateFail
}

// allDecided reports whether every gate has a non-Unknown status.
func (g *GateReview) allDecided() bool {
	return g.Control != GateUnknown &&
		g.Reachability != GateUnknown &&
		g.Validation != GateUnknown &&
		g.APIContract != GateUnknown &&
		g.Environment != GateUnknown &&
		g.Impact != GateUnknown
}

// anyPass reports whether any gate has GatePass set.
func (g *GateReview) anyPass() bool {
	return g.Control == GatePass ||
		g.Reachability == GatePass ||
		g.Validation == GatePass ||
		g.APIContract == GatePass ||
		g.Environment == GatePass ||
		g.Impact == GatePass
}

// FirstFailingReason returns the reason text of the gate that drove the
// refutation. It mirrors the order Classify uses (defense → control → impact)
// so the caller can attach a meaningful FPReason.
func (g *GateReview) FirstFailingReason() string {
	if g == nil {
		return ""
	}
	if g.Validation == GateFail && g.ValidationReason != "" {
		return g.ValidationReason
	}
	if g.APIContract == GateFail && g.APIContractReason != "" {
		return g.APIContractReason
	}
	if g.Environment == GateFail && g.EnvironmentReason != "" {
		return g.EnvironmentReason
	}
	if g.Control == GateFail && g.ControlReason != "" {
		return g.ControlReason
	}
	if g.Reachability == GateFail && g.ReachabilityReason != "" {
		return g.ReachabilityReason
	}
	if g.Impact == GateFail && g.ImpactReason != "" {
		return g.ImpactReason
	}
	return ""
}

// ApplyGates merges a GateReview into a Finding using the fp-check verdict
// rules and returns the GateOutcome it chose. The function is the single
// source of truth for how gates affect Finding state — keep verifier and deep
// pipelines pointed at this helper so behavior stays consistent.
//
//   - GateOutcomeConfirmed       → Verified=true, FalsePositive=false
//   - GateOutcomeRefutedDefended → FalsePositive=true with FPReason set
//   - GateOutcomeRefutedNoControl→ FalsePositive=true with FPReason set
//   - GateOutcomeDefenseInDepth  → DefenseInDepth=true, severity downgraded to low
//   - GateOutcomeInconclusive    → no mutation (caller decides escalation)
//   - GateOutcomeUnknown         → no mutation
func ApplyGates(f *Finding, g *GateReview) GateOutcome {
	if f == nil {
		return GateOutcomeUnknown
	}
	if g != nil && g.AnyEvaluated() {
		f.Gates = g
	}
	outcome := g.Classify()
	switch outcome {
	case GateOutcomeConfirmed:
		f.Verified = true
		f.FalsePositive = false
		if f.FPReason != "" {
			f.FPReason = ""
		}
	case GateOutcomeRefutedDefended, GateOutcomeRefutedNoControl:
		f.FalsePositive = true
		if reason := g.FirstFailingReason(); reason != "" {
			f.FPReason = reason
		} else if f.FPReason == "" {
			f.FPReason = "refuted by gate review"
		}
	case GateOutcomeDefenseInDepth:
		f.DefenseInDepth = true
		// Downgrade severity but keep the finding so reviewers can act on
		// it if they care about hardening.
		f.Severity = SevLow
		if g.ImpactReason != "" && f.FPReason == "" {
			f.FPReason = "defense-in-depth: " + g.ImpactReason
		}
	}
	return outcome
}
