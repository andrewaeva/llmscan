package pipeline

import (
	"strconv"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// voteAggregate is N-of-K self-consistency voting across N independent
// scanner runs of the same chunk. A finding is retained only if it appears
// in at least K out of N runs, judged by a stable vote key
// (rule_id + agent + file + start_line bucketed by 5).
//
// Surviving findings get VoteCount/VoteTotal populated; their Score is
// multiplied by VoteCount/N.
func voteAggregate(runs [][]types.Finding, k int) []types.Finding {
	if k <= 1 || len(runs) <= 1 {
		if len(runs) == 0 {
			return nil
		}
		return runs[0]
	}
	n := len(runs)
	counts := map[string]int{}
	rep := map[string]types.Finding{}
	for _, run := range runs {
		seen := map[string]bool{}
		for _, f := range run {
			key := voteKey(f)
			if seen[key] {
				continue
			}
			seen[key] = true
			counts[key]++
			if _, ok := rep[key]; !ok {
				rep[key] = f
			}
		}
	}
	var out []types.Finding
	for key, c := range counts {
		if c < k {
			continue
		}
		f := rep[key]
		f.VoteCount = c
		f.VoteTotal = n
		if f.Score == 0 {
			f.Score = 0.5
		}
		f.Score *= float64(c) / float64(n)
		out = append(out, f)
	}
	return out
}

func voteKey(f types.Finding) string {
	// Fuzz line by /5 buckets so off-by-a-few doesn't kill consensus.
	bucket := f.StartLine / 5
	return strings.Join([]string{f.RuleID, f.Agent, f.File, strconv.Itoa(bucket)}, "|")
}
