package pipeline

import (
	"path/filepath"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// resolveConfidence computes the final Confidence for a finding from all the
// signals collected during the pipeline (scanner self-report, verifier verdict,
// deep sub-agent verdict, taint trace presence, reach downgrade reason,
// severity).
//
// Priority rules (highest wins, then a single bounded downgrade for test/dead
// code that still cannot push below the floor set by strong evidence):
//
//   - deep "confirmed"            -> high
//   - verifier "true_positive"    -> high   (and not false_positive)
//   - taint trace present         -> at least medium
//   - critical/high severity      -> at least medium
//   - explicit value from scanner -> respected
//   - otherwise                   -> low
//
// A test/dead-code reachability downgrade lowers by one level, but never
// below medium when both verifier and deep agree, and never below the
// taint floor.
//
//nolint:gocyclo // multi-signal confidence resolution; flat by design
func resolveConfidence(f types.Finding) types.Confidence {
	// 1) Start from whatever scanner/verifier already produced.
	cur := normConf(f.Confidence)

	// 2) Strong signals that REQUIRE at least medium / high.
	floor := types.Confidence("")
	ceiling := types.Confidence("")

	// Verifier said true_positive and didn't mark FP -> boost to high.
	verifierConfirmed := !f.FalsePositive &&
		f.Verified &&
		isTruePositiveVerdict(f.VerifierVerdict)
	if verifierConfirmed {
		floor = atLeast(floor, types.ConfHigh)
	}

	// Deep agent confirmed -> high. (refuted already becomes FP and is dropped.)
	deepConfirmed := f.DeepVerified && strings.EqualFold(f.DeepVerdict, "confirmed")
	if deepConfirmed {
		floor = atLeast(floor, types.ConfHigh)
	}

	// Taint chain present -> at least medium (deterministic evidence).
	if len(f.Trace) > 0 {
		floor = atLeast(floor, types.ConfMedium)
	}

	// Severity-based default floor: critical/high findings shouldn't sit at
	// "low" unless reachability/test downgrade explicitly placed them there.
	switch f.Severity {
	case types.SevCritical, types.SevHigh:
		// Only a soft floor — overridden by reach downgrade below.
		floor = atLeast(floor, types.ConfMedium)
	}

	// 3) Reachability/test downgrade. The reach pass writes
	// FPReason = "reachability: ..." when it lowers confidence. We treat that
	// as a single one-step downgrade applied AFTER the floor, but verifier+deep
	// prevent dropping below medium.
	reachDowngrade := strings.HasPrefix(f.FPReason, "reachability:") || looksLikeTestPath(f.File)

	resolved := maxConf(cur, floor)
	if ceiling != "" {
		resolved = minConf(resolved, ceiling)
	}

	if reachDowngrade {
		// Lower one level, but respect the strong-evidence floor.
		strongFloor := types.Confidence("")
		if verifierConfirmed && deepConfirmed {
			strongFloor = types.ConfHigh
		} else if verifierConfirmed || deepConfirmed {
			strongFloor = types.ConfMedium
		}
		resolved = maxConf(downgrade(resolved), strongFloor)
	}

	if resolved == "" {
		resolved = types.ConfLow
	}
	return resolved
}

// applyConfidence walks the slice and rewrites Confidence using resolveConfidence.
// Returns the number of findings whose Confidence value changed.
func applyConfidence(findings []types.Finding) int {
	changed := 0
	for i := range findings {
		before := findings[i].Confidence
		after := resolveConfidence(findings[i])
		if after != before {
			findings[i].Confidence = after
			changed++
		}
	}
	return changed
}

func isTruePositiveVerdict(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true_positive", "tp", "confirmed", "true":
		return true
	}
	return false
}

func normConf(c types.Confidence) types.Confidence {
	switch strings.ToLower(string(c)) {
	case "high":
		return types.ConfHigh
	case "medium", "med":
		return types.ConfMedium
	case "low":
		return types.ConfLow
	}
	return ""
}

func confRank(c types.Confidence) int {
	switch normConf(c) {
	case types.ConfHigh:
		return 3
	case types.ConfMedium:
		return 2
	case types.ConfLow:
		return 1
	}
	return 0
}

func maxConf(a, b types.Confidence) types.Confidence {
	if confRank(a) >= confRank(b) {
		return a
	}
	return b
}

func minConf(a, b types.Confidence) types.Confidence {
	if confRank(a) <= confRank(b) {
		return a
	}
	return b
}

func atLeast(cur, floor types.Confidence) types.Confidence {
	if confRank(floor) > confRank(cur) {
		return floor
	}
	return cur
}

func downgrade(c types.Confidence) types.Confidence {
	switch normConf(c) {
	case types.ConfHigh:
		return types.ConfMedium
	case types.ConfMedium:
		return types.ConfLow
	}
	return types.ConfLow
}

// looksLikeTestPath mirrors the heuristic used by internal/reach so we can
// still downgrade test-code findings even when reach didn't run.
func looksLikeTestPath(p string) bool {
	q := strings.ToLower(filepath.ToSlash(p))
	if strings.HasSuffix(q, "_test.go") {
		return true
	}
	if strings.Contains(q, "/test/") || strings.Contains(q, "/tests/") {
		return true
	}
	if strings.Contains(q, "/fixtures/") || strings.Contains(q, "/__tests__/") {
		return true
	}
	if strings.HasSuffix(q, ".test.js") || strings.HasSuffix(q, ".test.ts") {
		return true
	}
	if strings.HasSuffix(q, ".spec.js") || strings.HasSuffix(q, ".spec.ts") {
		return true
	}
	if strings.HasPrefix(filepath.Base(q), "test_") && strings.HasSuffix(q, ".py") {
		return true
	}
	return false
}
