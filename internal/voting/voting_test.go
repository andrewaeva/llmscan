package voting

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func mkFinding(rule, file string, line int) types.Finding {
	return types.Finding{RuleID: rule, Agent: "scan:test", File: file, StartLine: line, Score: 0.8}
}

func TestAggregateEmpty(t *testing.T) {
	if got := Aggregate(nil, 2); got != nil {
		t.Errorf("nil runs should yield nil, got %v", got)
	}
}

func TestAggregateSingleRun(t *testing.T) {
	runs := [][]types.Finding{{mkFinding("sql", "a.go", 10)}}
	got := Aggregate(runs, 1)
	if len(got) != 1 {
		t.Fatalf("single run with k=1 must pass through, got %+v", got)
	}
}

func TestAggregateMajority(t *testing.T) {
	// 3 runs; finding A appears in all 3, B in 2, C in 1. K=2 → keep A,B.
	a := mkFinding("sql", "a.go", 10)
	b := mkFinding("xss", "b.go", 20)
	c := mkFinding("ssrf", "c.go", 30)
	runs := [][]types.Finding{
		{a, b, c},
		{a, b},
		{a},
	}
	got := Aggregate(runs, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 survivors (A,B), got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.VoteTotal != 3 {
			t.Errorf("VoteTotal = %d, want 3", f.VoteTotal)
		}
		if f.VoteCount < 2 {
			t.Errorf("VoteCount = %d, want >=2", f.VoteCount)
		}
		if f.Score == 0 {
			t.Error("Score must be populated")
		}
	}
}

func TestAggregateScoreScaling(t *testing.T) {
	a := mkFinding("sql", "a.go", 10) // score 0.8
	runs := [][]types.Finding{{a}, {a}, {a}}
	got := Aggregate(runs, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 survivor, got %d", len(got))
	}
	// score should be 0.8 * (3/3) = 0.8
	if got[0].Score < 0.79 || got[0].Score > 0.81 {
		t.Errorf("score = %v, want ≈ 0.8", got[0].Score)
	}
}

func TestAggregateLineFuzzing(t *testing.T) {
	// Same rule, line diff <5 → bucketed together.
	a := mkFinding("sql", "a.go", 10)
	b := mkFinding("sql", "a.go", 12) // bucket 12/5 = 2; 10/5 = 2 → same
	runs := [][]types.Finding{{a}, {b}}
	got := Aggregate(runs, 2)
	if len(got) != 1 {
		t.Fatalf("expected fuzzy-line collapse, got %+v", got)
	}
}

func TestAggregateDuplicateInOneRunCountsOnce(t *testing.T) {
	a := mkFinding("sql", "a.go", 10)
	runs := [][]types.Finding{{a, a, a}, {a}} // first run repeats; should still count as 1
	got := Aggregate(runs, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].VoteCount != 2 {
		t.Errorf("VoteCount = %d, want 2", got[0].VoteCount)
	}
}

func BenchmarkAggregate(b *testing.B) {
	mk := func(i int) types.Finding {
		return types.Finding{RuleID: "r", Agent: "a", File: "f.go", StartLine: i, Score: 0.5}
	}
	runs := make([][]types.Finding, 5)
	for i := range runs {
		fs := make([]types.Finding, 200)
		for j := range fs {
			fs[j] = mk(j)
		}
		runs[i] = fs
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Aggregate(runs, 3)
	}
}
