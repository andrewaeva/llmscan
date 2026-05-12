package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type counterState struct {
	value int
	log   []string
}

func TestGraph_LinearRun(t *testing.T) {
	g := NewGraph[counterState]()
	g.AddNode("a", func(_ context.Context, s *counterState) error { s.value++; s.log = append(s.log, "a"); return nil })
	g.AddNode("b", func(_ context.Context, s *counterState) error { s.value += 2; s.log = append(s.log, "b"); return nil })
	g.AddEdge("a", "b").AddEdge("b", End)
	g.SetEntry("a")

	st := &counterState{}
	if err := g.Run(context.Background(), st); err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.value != 3 {
		t.Fatalf("expected value 3 (a+b), got %d", st.value)
	}
	if got := strings.Join(st.log, ","); got != "a,b" {
		t.Fatalf("expected order a,b; got %s", got)
	}
}

func TestGraph_ConditionalRouter(t *testing.T) {
	g := NewGraph[counterState]()
	g.AddNode("a", func(_ context.Context, s *counterState) error { s.value++; return nil })
	g.AddNode("even", func(_ context.Context, s *counterState) error { s.log = append(s.log, "even"); return nil })
	g.AddNode("odd", func(_ context.Context, s *counterState) error { s.log = append(s.log, "odd"); return nil })
	g.SetRouter("a", func(s *counterState) string {
		if s.value%2 == 0 {
			return "even"
		}
		return "odd"
	})
	g.AddEdge("even", End).AddEdge("odd", End)
	g.SetEntry("a")

	st := &counterState{value: 0} // becomes 1 -> odd
	if err := g.Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(st.log, ","), "odd") {
		t.Fatalf("expected odd branch, got %v", st.log)
	}

	st = &counterState{value: 1} // becomes 2 -> even
	if err := g.Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(st.log, ","), "even") {
		t.Fatalf("expected even branch, got %v", st.log)
	}
}

func TestGraph_CycleWithBudget(t *testing.T) {
	g := NewGraph[counterState]()
	g.AddNode("loop", func(_ context.Context, s *counterState) error { s.value++; return nil })
	g.AddEdge("loop", "loop") // intentional infinite loop
	g.SetEntry("loop")
	g.MaxSteps = 5

	st := &counterState{}
	err := g.Run(context.Background(), st)
	if err == nil {
		t.Fatalf("expected step budget error")
	}
	if !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("expected budget error, got %v", err)
	}
	if st.value != 5 {
		t.Fatalf("expected exactly 5 executions, got %d", st.value)
	}
}

func TestGraph_NodeErrorAborts(t *testing.T) {
	g := NewGraph[counterState]()
	wantErr := errors.New("boom")
	g.AddNode("ok", func(_ context.Context, s *counterState) error { s.value++; return nil })
	g.AddNode("bad", func(_ context.Context, _ *counterState) error { return wantErr })
	g.AddEdge("ok", "bad").AddEdge("bad", End)
	g.SetEntry("ok")

	st := &counterState{}
	err := g.Run(context.Background(), st)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped wantErr, got %v", err)
	}
	if st.value != 1 {
		t.Fatalf("expected first node to have run once, value=%d", st.value)
	}
}

func TestGraph_ValidateCatchesBadEntry(t *testing.T) {
	g := NewGraph[counterState]()
	g.SetEntry("missing")
	if err := g.Validate(); err == nil {
		t.Fatalf("expected validation error for missing entry node")
	}
}

func TestGraph_LogfReceivesTransitions(t *testing.T) {
	var log []string
	g := NewGraph[counterState]()
	g.Logf = func(format string, args ...any) { log = append(log, fmt.Sprintf(format, args...)) }
	g.AddNode("a", func(_ context.Context, s *counterState) error { s.value++; return nil })
	g.AddEdge("a", End)
	g.SetEntry("a")
	if err := g.Run(context.Background(), &counterState{}); err != nil {
		t.Fatal(err)
	}
	if len(log) == 0 {
		t.Fatalf("expected at least one log line")
	}
}
