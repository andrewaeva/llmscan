package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// stageWriteStages persists per-funnel-point findings snapshots and a human
// readable summary under <target>/.llmscan/stages/. Always runs (no flag) so
// users can answer "why did 13 verified findings become 0 in the final
// report?" without rerunning the scan.
//
// Layout written:
//
//	stages/01-raw.json         []Finding after scanners + dedup (pre-verifier)
//	stages/02-verified.json    []Finding after verifier (pre fp_filter)
//	stages/03-confirmed.json   []Finding after fp_filter + suppressions (pre refine/deep)
//	stages/04-final.json       []Finding as reported (post deep/debate/drops)
//	stages/stages-summary.txt  funnel counts + per-finding drop attribution
func stageWriteStages(_ context.Context, _ *Engine, s *runState) error {
	dir := filepath.Join(s.target, ".llmscan", "stages")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir stages: %w", err)
	}
	type snap struct {
		name string
		data []types.Finding
	}
	snaps := []snap{
		{"01-raw.json", s.snapRaw},
		{"02-verified.json", s.snapVerified},
		{"03-confirmed.json", s.snapConfirmed},
		{"04-final.json", s.snapFinal},
	}
	for _, sp := range snaps {
		// Always write the file even when empty — explicit "0 findings at this
		// gate" is more useful than a missing file.
		payload := struct {
			Stage    string          `json:"stage"`
			Count    int             `json:"count"`
			Findings []types.Finding `json:"findings"`
		}{
			Stage:    strings.TrimSuffix(strings.TrimPrefix(sp.name, "0"), ".json"),
			Count:    len(sp.data),
			Findings: sp.data,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("encode %s: %w", sp.name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, sp.name), b, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", sp.name, err)
		}
	}

	summary := renderFunnelSummary(s)
	if err := os.WriteFile(filepath.Join(dir, "stages-summary.txt"), []byte(summary), 0o644); err != nil {
		return fmt.Errorf("write stages-summary.txt: %w", err)
	}
	return nil
}

// renderFunnelSummary builds the human-readable digest. Read by humans in
// plain editors — no ANSI, no colour, fixed-width columns.
func renderFunnelSummary(s *runState) string {
	var b strings.Builder
	b.WriteString("━━ llmscan pipeline funnel ━━\n")

	// Counts at each gate. Use stageCounts (filled in stagePostProcess) so
	// the numbers match the snapshot files exactly.
	rawN := s.stageCounts["raw"]
	dedupN := s.stageCounts["dedup"]
	verifiedN := s.stageCounts["verified"]
	confirmedN := s.stageCounts["confirmed"]
	finalN := s.stageCounts["final"]

	fmt.Fprintf(&b, "01 raw          : %4d  (scanners output)\n", rawN)
	fmt.Fprintf(&b, "02 dedup        : %4d  (%+d)\n", dedupN, dedupN-rawN)
	fmt.Fprintf(&b, "03 verified     : %4d  (%+d)\n", verifiedN, verifiedN-dedupN)
	fmt.Fprintf(&b, "04 confirmed    : %4d  (%+d, after fp_filter + suppressions + secret-drop)\n",
		confirmedN, confirmedN-verifiedN)
	fmt.Fprintf(&b, "05 final        : %4d  (%+d, after refine + deep + debate + drop policies)\n",
		finalN, finalN-confirmedN)

	// Drop attribution: bucket findings by the stage that removed them.
	if len(s.dropReasons) > 0 {
		buckets := map[string][]types.Finding{}
		// Index every snapshot finding by id so we can look up details for the
		// drop list (confirmed is the richest pre-drop set; fall back to raw).
		details := map[string]types.Finding{}
		for _, src := range [][]types.Finding{s.snapRaw, s.snapVerified, s.snapConfirmed} {
			for _, f := range src {
				details[findingKey(f)] = f
			}
		}
		for id, stage := range s.dropReasons {
			buckets[stage] = append(buckets[stage], details[id])
		}

		// Stable stage order matching the pipeline.
		stageOrder := []string{
			"drop_secret", "suppressed", "refine",
			"drop_unconfirmed", "drop_impact_fail",
			"policy", "baseline",
		}
		seen := map[string]bool{}
		for _, st := range stageOrder {
			seen[st] = true
		}
		// Append any other stages that appeared but aren't in the canonical list.
		extras := make([]string, 0)
		for st := range buckets {
			if !seen[st] {
				extras = append(extras, st)
			}
		}
		sort.Strings(extras)
		stageOrder = append(stageOrder, extras...)

		fmt.Fprintf(&b, "\nDropped findings by stage (%d total):\n", len(s.dropReasons))
		for _, st := range stageOrder {
			fs := buckets[st]
			if len(fs) == 0 {
				continue
			}
			fmt.Fprintf(&b, "  %s (%d):\n", st, len(fs))
			// Stable order: by file:line:rule.
			sort.Slice(fs, func(i, j int) bool {
				if fs[i].File != fs[j].File {
					return fs[i].File < fs[j].File
				}
				if fs[i].StartLine != fs[j].StartLine {
					return fs[i].StartLine < fs[j].StartLine
				}
				return fs[i].RuleID < fs[j].RuleID
			})
			for _, f := range fs {
				rule := f.RuleID
				if rule == "" {
					rule = f.Agent
				}
				fmt.Fprintf(&b, "    %s:%d  %-32s  sev=%s\n",
					trimPath(f.File), f.StartLine, rule, string(f.Severity))
			}
		}
	}
	return b.String()
}

// trimPath shortens repo-relative paths for the summary log. Bare files keep
// at most three trailing segments so summary lines stay readable.
func trimPath(p string) string {
	parts := strings.Split(p, "/")
	if len(parts) <= 3 {
		return p
	}
	return "…/" + strings.Join(parts[len(parts)-3:], "/")
}
