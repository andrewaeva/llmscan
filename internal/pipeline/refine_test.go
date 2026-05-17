package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestBuildRefineGroupsMarksOnlySplitFiles(t *testing.T) {
	findings := []types.Finding{
		{File: "a.go", RuleID: "1"},
		{File: "a.go", RuleID: "2"},
		{File: "b.go", RuleID: "3"},
	}
	chunks := []types.FileTarget{
		{Path: "a.go"},
		{Path: "a.go"},
		{Path: "b.go"},
	}

	groups := buildRefineGroups(findings, chunks, 2)
	if !hasRefinableGroups(groups) {
		t.Fatal("expected at least one refinable group")
	}

	if got := groups["a.go"]; got == nil || !got.split || len(got.entries) != 2 || got.idx[0] != 0 || got.idx[1] != 1 {
		t.Fatalf("unexpected group for a.go: %+v", got)
	}
	if got := groups["b.go"]; got == nil || got.split || len(got.entries) != 1 || got.idx[0] != 2 {
		t.Fatalf("unexpected group for b.go: %+v", got)
	}
}

func TestHasRefinableGroupsRequiresSplitAndMultipleFindings(t *testing.T) {
	if hasRefinableGroups(map[string]*refineGroup{
		"a.go": {split: false, entries: []types.Finding{{File: "a.go"}, {File: "a.go"}}},
		"b.go": {split: true, entries: []types.Finding{{File: "b.go"}}},
	}) {
		t.Fatal("expected no refinable groups")
	}
}
