// Package voting implements N-of-K self-consistency voting across multiple
// scanner runs of the same chunk with elevated temperature. A finding is
// retained only if it appears in at least K out of N runs, judged by a stable
// "vote key" (rule_id + file + start_line ± fuzz).
package voting

import (
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// Aggregate takes N independent finding lists for the same chunk and returns
// only those that occur in at least K of them. Surviving findings get
// VoteCount / VoteTotal populated; their Score is multiplied by VoteCount/N.
func Aggregate(runs [][]types.Finding, k int) []types.Finding {
	if k <= 1 || len(runs) <= 1 {
		// degenerate: just merge first run
		if len(runs) == 0 {
			return nil
		}
		return runs[0]
	}
	n := len(runs)
	counts := map[string]int{}
	rep := map[string]types.Finding{}
	for _, run := range runs {
		seenThisRun := map[string]bool{}
		for _, f := range run {
			key := voteKey(f)
			if seenThisRun[key] {
				continue
			}
			seenThisRun[key] = true
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
	return strings.Join([]string{f.RuleID, f.Agent, f.File, itoa(bucket)}, "|")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
