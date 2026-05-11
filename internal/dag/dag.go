// Package dag builds, validates and runs an agent DAG layer-by-layer.
//
// A "node" is an agent identified by name. Edges describe data dependencies
// (e.g. "verifier" depends on every scanner). The DAG is validated for cycles
// and undeclared dependencies before execution.
//
// Execution model:
//   - Compute layers via Kahn's algorithm.
//   - For each layer: run all nodes in parallel up to `Concurrency`.
//   - A node sees the merged outputs of every node it depends on.
package dag

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Node is a unit of work in the DAG.
type Node struct {
	Name      string
	DependsOn []string
	// Run is invoked with the merged inputs (keyed by upstream node name).
	// Whatever it returns is published under this node's name to downstream nodes.
	Run func(ctx context.Context, inputs map[string]any) (any, error)
}

// DAG is a validated set of nodes ready for layered execution.
type DAG struct {
	nodes  map[string]*Node
	layers [][]string
}

// Build constructs and validates a DAG. Returns an error on cycles or missing deps.
func Build(nodes []*Node) (*DAG, error) {
	m := make(map[string]*Node, len(nodes))
	for _, n := range nodes {
		if n.Name == "" {
			return nil, fmt.Errorf("dag: anonymous node")
		}
		if _, dup := m[n.Name]; dup {
			return nil, fmt.Errorf("dag: duplicate node %q", n.Name)
		}
		m[n.Name] = n
	}
	for _, n := range nodes {
		for _, d := range n.DependsOn {
			if _, ok := m[d]; !ok {
				return nil, fmt.Errorf("dag: node %q depends on unknown node %q", n.Name, d)
			}
		}
	}
	layers, err := topoLayers(m)
	if err != nil {
		return nil, err
	}
	return &DAG{nodes: m, layers: layers}, nil
}

// Layers returns the topological layering (each inner slice is a parallel group).
func (d *DAG) Layers() [][]string { return d.layers }

// Run executes the DAG layer by layer. `concurrency` caps parallelism within a layer.
// Errors from individual nodes are collected and returned per-node; the function
// returns the per-node outputs map and the per-node error map.
func (d *DAG) Run(ctx context.Context, concurrency int) (map[string]any, map[string]error) {
	if concurrency <= 0 {
		concurrency = 4
	}
	outputs := make(map[string]any, len(d.nodes))
	errs := make(map[string]error)
	var mu sync.Mutex

	for _, layer := range d.layers {
		// Gate concurrency within the layer.
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, name := range layer {
			n := d.nodes[name]
			wg.Add(1)
			sem <- struct{}{}
			go func(n *Node) {
				defer wg.Done()
				defer func() { <-sem }()
				inputs := make(map[string]any, len(n.DependsOn))
				mu.Lock()
				for _, d := range n.DependsOn {
					inputs[d] = outputs[d]
				}
				mu.Unlock()
				out, err := n.Run(ctx, inputs)
				mu.Lock()
				outputs[n.Name] = out
				if err != nil {
					errs[n.Name] = err
				}
				mu.Unlock()
			}(n)
		}
		wg.Wait()
	}
	return outputs, errs
}

// topoLayers returns Kahn-style layering. Returns error on cycle.
func topoLayers(m map[string]*Node) ([][]string, error) {
	indeg := make(map[string]int, len(m))
	rev := make(map[string][]string, len(m))
	for name := range m {
		indeg[name] = 0
	}
	for _, n := range m {
		for _, d := range n.DependsOn {
			indeg[n.Name]++
			rev[d] = append(rev[d], n.Name)
		}
	}
	remaining := len(m)
	var layers [][]string
	for remaining > 0 {
		var layer []string
		for name, deg := range indeg {
			if deg == 0 {
				layer = append(layer, name)
			}
		}
		if len(layer) == 0 {
			return nil, fmt.Errorf("dag: cycle detected (remaining=%d)", remaining)
		}
		sort.Strings(layer)
		for _, name := range layer {
			delete(indeg, name)
			for _, child := range rev[name] {
				indeg[child]--
			}
			remaining--
		}
		layers = append(layers, layer)
	}
	return layers, nil
}
