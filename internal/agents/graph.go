// graph.go is a small LangGraph-inspired state machine used for per-item
// agent pipelines with conditional branching.
//
// LangChain's LangGraph models an agent flow as a directed graph of named
// nodes plus conditional edges that pick the next node based on the current
// state. The Go equivalent we want is very small: a registry of node
// functions and an edge router that, given the state, returns the name of
// the next node (or the terminal sentinel End).
//
// Why a graph, not a switch:
//
//   - Conditional, possibly cyclic transitions (retry, refine-loop) are
//     awkward to express as inline switch cases.
//   - The transition log doubles as observability for --verbose: every hop
//     is logged with the prior/next node name and a short reason.
//   - Adding a new branch ("on-confidence-low -> extra-context") is a single
//     AddEdge call rather than another nested if.
//
// The graph operates on a single State per Run; it is NOT a parallel
// executor. Use internal/dag for parallel fan-out across many items.
package agents

import (
	"context"
	"fmt"
	"strings"
)

// End is the sentinel "terminal" node name. Returning End from an edge
// router or as the entry node stops the run.
const End = "__end__"

// Node is a single step in the graph. It mutates the provided State and
// optionally returns an error. Returning a non-nil error aborts the run.
type Node[S any] func(ctx context.Context, state *S) error

// Router decides the next node given the current state. Returning End
// terminates the run.
type Router[S any] func(state *S) string

// Edge is an unconditional transition: after `from`, go to `to`.
// Conditional routing is expressed via SetRouter; an explicit edge wins
// over the router only when the node has no router attached.
type edge struct {
	from, to string
}

// Graph is a small named-node, named-edge state machine.
type Graph[S any] struct {
	entry   string
	nodes   map[string]Node[S]
	routers map[string]Router[S]
	edges   []edge
	// MaxSteps caps the total number of node executions per Run, guarding
	// against accidental cycles. 0 -> 64.
	MaxSteps int
	// Logf, when set, receives one line per transition. Useful with
	// --verbose; safe to leave nil in production.
	Logf func(format string, args ...any)
}

// NewGraph creates an empty graph for state type S.
func NewGraph[S any]() *Graph[S] {
	return &Graph[S]{
		nodes:   map[string]Node[S]{},
		routers: map[string]Router[S]{},
	}
}

// AddNode registers a node function under a name. Re-registering replaces.
func (g *Graph[S]) AddNode(name string, fn Node[S]) *Graph[S] {
	g.nodes[name] = fn
	return g
}

// AddEdge declares an unconditional transition from -> to. Only consulted
// when the source node has no router.
func (g *Graph[S]) AddEdge(from, to string) *Graph[S] {
	g.edges = append(g.edges, edge{from: from, to: to})
	return g
}

// SetRouter attaches a router to a node. The router runs AFTER the node
// function and returns the name of the next node. End terminates.
func (g *Graph[S]) SetRouter(node string, r Router[S]) *Graph[S] {
	g.routers[node] = r
	return g
}

// SetEntry chooses the node executed first.
func (g *Graph[S]) SetEntry(name string) *Graph[S] {
	g.entry = name
	return g
}

// Validate returns an error for obvious construction mistakes. Cheap; call
// once at build time to fail fast in tests.
func (g *Graph[S]) Validate() error {
	if g.entry == "" {
		return fmt.Errorf("graph: entry node not set")
	}
	if _, ok := g.nodes[g.entry]; !ok {
		return fmt.Errorf("graph: entry node %q not registered", g.entry)
	}
	for _, e := range g.edges {
		if _, ok := g.nodes[e.from]; !ok {
			return fmt.Errorf("graph: edge from unknown node %q", e.from)
		}
		if e.to == End {
			continue
		}
		if _, ok := g.nodes[e.to]; !ok {
			return fmt.Errorf("graph: edge to unknown node %q", e.to)
		}
	}
	for name := range g.routers {
		if _, ok := g.nodes[name]; !ok {
			return fmt.Errorf("graph: router attached to unknown node %q", name)
		}
	}
	return nil
}

// Run executes the graph starting at the entry node. On End or a router
// returning End the run stops and the (mutated) state is returned. A
// per-node error aborts the run and propagates.
func (g *Graph[S]) Run(ctx context.Context, state *S) error {
	if err := g.Validate(); err != nil {
		return err
	}
	maxSteps := g.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 64
	}
	current := g.entry
	visits := make(map[string]int, len(g.nodes))

	for step := 0; step < maxSteps; step++ {
		if current == End {
			g.logf("graph: terminated at step=%d", step)
			return nil
		}
		fn, ok := g.nodes[current]
		if !ok {
			return fmt.Errorf("graph: unknown node %q at step=%d", current, step)
		}
		visits[current]++
		g.logf("graph: step=%d node=%s visit=%d", step, current, visits[current])
		if err := fn(ctx, state); err != nil {
			return fmt.Errorf("graph: node %q: %w", current, err)
		}
		next := g.nextOf(current, state)
		if next == "" {
			g.logf("graph: no transition from %q (terminating)", current)
			return nil
		}
		current = next
	}
	return fmt.Errorf("graph: step budget exhausted after %d steps (last node=%q)", maxSteps, current)
}

func (g *Graph[S]) nextOf(from string, state *S) string {
	if r, ok := g.routers[from]; ok && r != nil {
		return strings.TrimSpace(r(state))
	}
	for _, e := range g.edges {
		if e.from == from {
			return e.to
		}
	}
	return "" // no transition -> terminate
}

func (g *Graph[S]) logf(format string, args ...any) {
	if g.Logf == nil {
		return
	}
	g.Logf(format, args...)
}
