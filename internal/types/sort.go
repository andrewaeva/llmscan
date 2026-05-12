package types

import "sort"

// SeverityRank returns a higher integer for more severe levels.
// Unknown severities rank 0.
func SeverityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// ConfidenceRank returns a higher integer for higher confidence.
// Unknown values rank 0.
func ConfidenceRank(c Confidence) int {
	switch c {
	case ConfHigh:
		return 3
	case ConfMedium:
		return 2
	case ConfLow:
		return 1
	}
	return 0
}

// LessFinding is the canonical comparator: most critical and most confident
// findings come first. Tie-breakers (in order): severity, confidence,
// numeric score, false-positive flag (real positives first), file, start line.
func LessFinding(a, b Finding) bool {
	if sa, sb := SeverityRank(a.Severity), SeverityRank(b.Severity); sa != sb {
		return sa > sb
	}
	if ca, cb := ConfidenceRank(a.Confidence), ConfidenceRank(b.Confidence); ca != cb {
		return ca > cb
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.FalsePositive != b.FalsePositive {
		// keep real findings before suppressed/FP ones at the same level
		return !a.FalsePositive
	}
	if a.File != b.File {
		return a.File < b.File
	}
	return a.StartLine < b.StartLine
}

// SortFindings ranks findings in-place: most critical and most confident first.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return LessFinding(fs[i], fs[j]) })
}
