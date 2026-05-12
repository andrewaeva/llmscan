package dag

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newNode(name string, deps []string, val any) *Node {
	return &Node{
		Name:      name,
		DependsOn: deps,
		Run: func(_ context.Context, _ map[string]any) (any, error) {
			return val, nil
		},
	}
}

func TestBuild_AnonymousNode(t *testing.T) {
	_, err := Build([]*Node{{Name: ""}})
	if err == nil || !strings.Contains(err.Error(), "anonymous") {
		t.Errorf("got %v, want anonymous node error", err)
	}
}

func TestBuild_DuplicateNode(t *testing.T) {
	_, err := Build([]*Node{newNode("a", nil, 1), newNode("a", nil, 2)})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("got %v, want duplicate node error", err)
	}
}

func TestBuild_UnknownDep(t *testing.T) {
	_, err := Build([]*Node{newNode("a", []string{"missing"}, 1)})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("got %v, want unknown dep error", err)
	}
}

func TestBuild_Cycle(t *testing.T) {
	_, err := Build([]*Node{
		newNode("a", []string{"b"}, 1),
		newNode("b", []string{"a"}, 1),
	})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("got %v, want cycle error", err)
	}
}

func TestBuild_SelfCycle(t *testing.T) {
	_, err := Build([]*Node{newNode("a", []string{"a"}, 1)})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("got %v, want cycle error", err)
	}
}

func TestBuild_LongerCycle(t *testing.T) {
	_, err := Build([]*Node{
		newNode("a", []string{"c"}, 1),
		newNode("b", []string{"a"}, 1),
		newNode("c", []string{"b"}, 1),
	})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("got %v, want cycle error", err)
	}
}

func TestLayers_Diamond(t *testing.T) {
	// a → {b, c} → d
	d, err := Build([]*Node{
		newNode("a", nil, 1),
		newNode("b", []string{"a"}, 1),
		newNode("c", []string{"a"}, 1),
		newNode("d", []string{"b", "c"}, 1),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	layers := d.Layers()
	if len(layers) != 3 {
		t.Fatalf("got %d layers, want 3 (a | b,c | d): %v", len(layers), layers)
	}
	if layers[0][0] != "a" || layers[2][0] != "d" {
		t.Errorf("unexpected layering: %v", layers)
	}
	if len(layers[1]) != 2 {
		t.Errorf("middle layer should have 2 nodes, got %v", layers[1])
	}
}

func TestRun_OutputsAndInputs(t *testing.T) {
	var seenInputs map[string]any
	nodes := []*Node{
		{Name: "src", Run: func(_ context.Context, _ map[string]any) (any, error) { return 42, nil }},
		{
			Name:      "sink",
			DependsOn: []string{"src"},
			Run: func(_ context.Context, in map[string]any) (any, error) {
				seenInputs = in
				return in["src"].(int) * 2, nil
			},
		},
	}
	d, err := Build(nodes)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	out, errs := d.Run(context.Background(), 4)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if seenInputs["src"] != 42 {
		t.Errorf("sink didn't see src=42, got %v", seenInputs)
	}
	if out["sink"] != 84 {
		t.Errorf("sink output: got %v, want 84", out["sink"])
	}
}

func TestRun_PerNodeError(t *testing.T) {
	want := errors.New("boom")
	nodes := []*Node{
		newNode("ok", nil, "good"),
		{
			Name: "bad",
			Run:  func(_ context.Context, _ map[string]any) (any, error) { return nil, want },
		},
	}
	d, err := Build(nodes)
	if err != nil {
		t.Fatal(err)
	}
	out, errs := d.Run(context.Background(), 4)
	if errs["bad"] != want {
		t.Errorf("bad err: got %v, want %v", errs["bad"], want)
	}
	if _, hasOK := errs["ok"]; hasOK {
		t.Errorf("ok should not have error")
	}
	if out["ok"] != "good" {
		t.Errorf("ok output lost on sibling failure: %v", out)
	}
}

func TestRun_RespectsLayerBarrier(t *testing.T) {
	// b and c must NOT start until a finishes.
	var aDone int64
	var earlyStart int64

	mkChild := func(name string) *Node {
		return &Node{
			Name:      name,
			DependsOn: []string{"a"},
			Run: func(_ context.Context, _ map[string]any) (any, error) {
				if atomic.LoadInt64(&aDone) == 0 {
					atomic.StoreInt64(&earlyStart, 1)
				}
				return nil, nil
			},
		}
	}
	nodes := []*Node{
		{
			Name: "a",
			Run: func(_ context.Context, _ map[string]any) (any, error) {
				time.Sleep(30 * time.Millisecond)
				atomic.StoreInt64(&aDone, 1)
				return nil, nil
			},
		},
		mkChild("b"),
		mkChild("c"),
	}
	d, err := Build(nodes)
	if err != nil {
		t.Fatal(err)
	}
	d.Run(context.Background(), 4)
	if atomic.LoadInt64(&earlyStart) != 0 {
		t.Error("child started before parent finished — layer barrier violated")
	}
}

func TestRun_ConcurrencyCapped(t *testing.T) {
	// Spawn 8 sibling nodes in the same layer; limit concurrency to 2.
	var inflight int64
	var peak int64
	mk := func(i int) *Node {
		return &Node{
			Name: string(rune('a' + i)),
			Run: func(_ context.Context, _ map[string]any) (any, error) {
				n := atomic.AddInt64(&inflight, 1)
				for {
					p := atomic.LoadInt64(&peak)
					if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				atomic.AddInt64(&inflight, -1)
				return nil, nil
			},
		}
	}
	nodes := []*Node{mk(0), mk(1), mk(2), mk(3), mk(4), mk(5), mk(6), mk(7)}
	d, err := Build(nodes)
	if err != nil {
		t.Fatal(err)
	}
	d.Run(context.Background(), 2)
	if got := atomic.LoadInt64(&peak); got > 2 {
		t.Errorf("peak in-flight = %d, want <= 2", got)
	}
}

func TestRun_DefaultConcurrency(t *testing.T) {
	// Passing concurrency <= 0 must not deadlock.
	d, err := Build([]*Node{newNode("a", nil, 1)})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := d.Run(context.Background(), 0)
	if out["a"] != 1 {
		t.Errorf("got %v", out)
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	// Slow node observes ctx.Done(). After cancellation, downstream nodes
	// still run (current contract: per-node opt-in to ctx).
	ctx, cancel := context.WithCancel(context.Background())
	var canceled int64
	nodes := []*Node{
		{
			Name: "slow",
			Run: func(c context.Context, _ map[string]any) (any, error) {
				select {
				case <-c.Done():
					atomic.StoreInt64(&canceled, 1)
					return nil, c.Err()
				case <-time.After(2 * time.Second):
					return nil, nil
				}
			},
		},
	}
	d, err := Build(nodes)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, errs := d.Run(ctx, 4)
	if atomic.LoadInt64(&canceled) != 1 {
		t.Error("slow node did not observe cancellation")
	}
	if errs["slow"] == nil {
		t.Error("expected slow node to return ctx error")
	}
}

func TestRun_ConcurrentSafe(t *testing.T) {
	// Many parallel writes to outputs must not race; -race verifies this.
	const n = 30
	var nodes []*Node
	for i := 0; i < n; i++ {
		nodes = append(nodes, newNode(string(rune('A'+i)), nil, i))
	}
	d, err := Build(nodes)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for r := 0; r < 5; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Run(context.Background(), 8)
		}()
	}
	wg.Wait()
}

func TestRun_EmptyDAG(t *testing.T) {
	d, err := Build(nil)
	if err != nil {
		t.Fatal(err)
	}
	out, errs := d.Run(context.Background(), 4)
	if len(out) != 0 || len(errs) != 0 {
		t.Errorf("empty DAG: out=%v errs=%v", out, errs)
	}
}

func TestLayers_DeterministicOrder(t *testing.T) {
	// Same DAG built twice must produce the same layer ordering. Kahn's
	// algorithm picks zero-indegree nodes from a map (unordered), so we
	// sort each layer for determinism.
	mk := func() *DAG {
		d, err := Build([]*Node{
			newNode("a", nil, 1),
			newNode("b", nil, 1),
			newNode("c", nil, 1),
			newNode("z", []string{"a", "b", "c"}, 1),
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	l1 := mk().Layers()
	l2 := mk().Layers()
	if len(l1) != len(l2) {
		t.Fatalf("different layer counts: %v vs %v", l1, l2)
	}
	for i := range l1 {
		if strings.Join(l1[i], ",") != strings.Join(l2[i], ",") {
			t.Errorf("layer %d differs: %v vs %v", i, l1[i], l2[i])
		}
	}
}
