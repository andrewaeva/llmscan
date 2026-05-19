package pipeline

import (
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestBuildFindingGroupsByCodeSample(t *testing.T) {
	in := []types.Finding{
		{
			ID: "a", RuleID: "sql-inj", Title: "SQL Injection", Agent: "injection",
			Severity: types.SevHigh, Confidence: types.ConfHigh,
			File: "a.go", StartLine: 10, EndLine: 12, CodeSample: "db.Exec(query)",
		},
		{
			ID: "b", RuleID: "sql-inj", Title: "SQL Injection", Agent: "injection",
			Severity: types.SevHigh, Confidence: types.ConfMedium,
			File: "b.go", StartLine: 22, EndLine: 24, CodeSample: "db.Exec( query )",
		},
		{
			ID: "c", RuleID: "auth-missing", Title: "Missing auth check", Agent: "auth",
			Severity: types.SevMedium, Confidence: types.ConfMedium,
			File: "auth.go", StartLine: 5, EndLine: 5,
		},
	}

	groups := buildFindingGroups(in)
	if len(groups) != 2 {
		t.Fatalf("groups=%d want 2: %+v", len(groups), groups)
	}
	if groups[0].Title != "SQL Injection" {
		t.Fatalf("primary order wrong: %+v", groups)
	}
	if groups[0].Basis != "code_sample" {
		t.Fatalf("basis=%q want code_sample", groups[0].Basis)
	}
	if groups[0].OccurrenceCount != 2 || groups[0].FileCount != 2 {
		t.Fatalf("group counts wrong: %+v", groups[0])
	}
	if groups[0].Occurrences[0].FindingID != "a" || groups[0].Occurrences[1].FindingID != "b" {
		t.Fatalf("occurrence order wrong: %+v", groups[0].Occurrences)
	}
}

func TestBuildFindingGroupsByTraceSignature(t *testing.T) {
	in := []types.Finding{
		{
			ID: "a", RuleID: "ssrf", Title: "SSRF", Agent: "ssrf",
			Severity: types.SevCritical, Confidence: types.ConfHigh,
			File: "a.go", StartLine: 10, EndLine: 12,
			Trace: []types.TraceHop{
				{Kind: "source", Code: `req.URL.Query()["url"]`},
				{Kind: "sink", Code: "http.Get(target)"},
			},
		},
		{
			ID: "b", RuleID: "ssrf", Title: "SSRF", Agent: "ssrf",
			Severity: types.SevHigh, Confidence: types.ConfHigh,
			File: "b.go", StartLine: 30, EndLine: 31,
			Trace: []types.TraceHop{
				{Kind: "source", Code: `req.URL.Query()[ "url" ]`},
				{Kind: "sink", Code: "http.Get( target )"},
			},
		},
	}

	groups := buildFindingGroups(in)
	if len(groups) != 1 {
		t.Fatalf("groups=%d want 1: %+v", len(groups), groups)
	}
	if groups[0].Basis != "trace" {
		t.Fatalf("basis=%q want trace", groups[0].Basis)
	}
	if groups[0].Primary.ID != "a" {
		t.Fatalf("primary=%q want a", groups[0].Primary.ID)
	}
}

func TestBuildFindingGroupsFallsBackToLocation(t *testing.T) {
	in := []types.Finding{
		{
			ID: "a", RuleID: "auth-missing", Title: "Missing auth check", Agent: "auth",
			Severity: types.SevHigh, Confidence: types.ConfMedium,
			File: "a.go", StartLine: 10, EndLine: 10, Description: "missing auth",
		},
		{
			ID: "b", RuleID: "auth-missing", Title: "Missing auth check", Agent: "auth",
			Severity: types.SevHigh, Confidence: types.ConfMedium,
			File: "b.go", StartLine: 20, EndLine: 20, Description: "missing auth",
		},
	}

	groups := buildFindingGroups(in)
	if len(groups) != 2 {
		t.Fatalf("groups=%d want 2: %+v", len(groups), groups)
	}
	for _, g := range groups {
		if g.Basis != "location" {
			t.Fatalf("basis=%q want location", g.Basis)
		}
		if g.OccurrenceCount != 1 {
			t.Fatalf("unexpected collapse: %+v", g)
		}
	}
}
