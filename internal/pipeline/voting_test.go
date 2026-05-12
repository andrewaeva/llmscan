package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func mkVoteFinding(rule, file string, line int) types.Finding {
	return types.Finding{RuleID: rule, Agent: "scan:test", File: file, StartLine: line, Score: 0.8}
}

func TestVoteAggregateEmpty(t *testing.T) {
	if got := voteAggregate(nil, 2); got != nil {
		t.Errorf("nil runs should yield nil, got %v", got)
	}
}

func TestVoteAggregateSingleRun(t *testing.T) {
	runs := [][]types.Finding{{mkVoteFinding("sql", "a.go", 10)}}
	got := voteAggregate(runs, 1)
	if len(got) != 1 {
		t.Fatalf("single run with k=1 must pass through, got %+v", got)
	}
}

func TestVoteAggregateMajority(t *testing.T) {
	a := mkVoteFinding("sql", "a.go", 10)
	b := mkVoteFinding("xss", "b.go", 20)
	c := mkVoteFinding("ssrf", "c.go", 30)
	runs := [][]types.Finding{
		{a, b, c},
		{a, b},
		{a},
	}
	got := voteAggregate(runs, 2)
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

func TestVoteAggregateScoreScaling(t *testing.T) {
	a := mkVoteFinding("sql", "a.go", 10)
	runs := [][]types.Finding{{a}, {a}, {a}}
	got := voteAggregate(runs, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 survivor, got %d", len(got))
	}
	if got[0].Score < 0.79 || got[0].Score > 0.81 {
		t.Errorf("score = %v, want ≈ 0.8", got[0].Score)
	}
}

func TestVoteAggregateLineFuzzing(t *testing.T) {
	a := mkVoteFinding("sql", "a.go", 10)
	b := mkVoteFinding("sql", "a.go", 12)
	runs := [][]types.Finding{{a}, {b}}
	got := voteAggregate(runs, 2)
	if len(got) != 1 {
		t.Fatalf("expected fuzzy-line collapse, got %+v", got)
	}
}

func TestVoteAggregateDuplicateInOneRunCountsOnce(t *testing.T) {
	a := mkVoteFinding("sql", "a.go", 10)
	runs := [][]types.Finding{{a, a, a}, {a}}
	got := voteAggregate(runs, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].VoteCount != 2 {
		t.Errorf("VoteCount = %d, want 2", got[0].VoteCount)
	}
}

func BenchmarkVoteAggregate(b *testing.B) {
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
		_ = voteAggregate(runs, 3)
	}
}
