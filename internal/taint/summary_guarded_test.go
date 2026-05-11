package taint

import (
	"testing"
)

// GuardedFlowsTo populated only when the sink lives inside a validator
// guard. Both FlowsTo and GuardedFlowsTo populated for mixed paths.
func TestSummary_GuardedFlowsTo_Basic(t *testing.T) {
	src := `package main
func run(q string) {
	if validate(q) {
		db.Exec(q)
	}
	db.Exec(q)
}
`
	f := parse(t, "a.go", src)
	sums := buildPathSensitiveSummaries(t, f)
	var pf ParamFlow
	for _, s := range sums {
		if s.Func == "run" {
			pf = s.Params[0]
		}
	}
	if len(pf.GuardedFlowsTo) == 0 {
		t.Fatalf("expected GuardedFlowsTo populated for guarded sink, got %+v", pf)
	}
	if len(pf.FlowsTo) == 0 {
		t.Fatalf("expected FlowsTo populated for the unguarded sink below the block, got %+v", pf)
	}
}

// Nested guards keep deeper sinks marked.
func TestSummary_GuardedFlowsTo_Python(t *testing.T) {
	src := `def run(x):
    if x in ALLOWED_LIST:
        cursor.execute(x)
    cursor.execute(x)
`
	f := parse(t, "a.py", src)
	sums := buildPathSensitiveSummaries(t, f)
	var pf ParamFlow
	for _, s := range sums {
		if s.Func == "run" {
			pf = s.Params[0]
		}
	}
	if len(pf.GuardedFlowsTo) == 0 {
		t.Fatalf("expected guarded python flow, got %+v", pf)
	}
	if len(pf.FlowsTo) == 0 {
		t.Fatalf("expected unguarded python flow after block close, got %+v", pf)
	}
}
