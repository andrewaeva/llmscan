// Package calibration implements isotonic regression (Pool Adjacent Violators)
// to map raw LLM-reported confidence scores onto an empirical true-positive
// probability learned from a labelled eval dataset.
//
// Workflow:
//
//  1. Run `llmscan eval` against a labelled corpus.
//  2. Each predicted finding is bucketed as true-positive (matched label) or
//     false-positive (no matching label). We collect (raw_score, is_tp) pairs.
//  3. PAV fits a monotonically non-decreasing step function f: [0,1] -> [0,1]
//     such that f(raw_score) ~ P(true positive | raw_score).
//  4. The fitted model is persisted as JSON and loaded on subsequent scans;
//     each finding's Score is replaced by f(raw_score) before --min-score is
//     applied. Calibrated scores have an honest probabilistic meaning.
//
// This is intentionally a tiny pure-Go implementation — no gonum / scikit
// dependency.
package calibration

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"time"
)

// Sample is one (raw_score, true_positive) observation produced by `eval`.
type Sample struct {
	Score float64 `json:"score"`
	TP    bool    `json:"tp"`
}

// SchemaVersion is the on-disk format version. Bump when the JSON layout of
// Model changes in a non-backwards-compatible way (renamed fields, changed
// knot semantics, etc.). Load() rejects files with a higher schema version
// and warns on lower versions.
const SchemaVersion = 1

// Model is a piecewise-constant non-decreasing mapping from raw score to
// empirical true-positive probability. Knots are sorted by X (raw score).
type Model struct {
	// Schema is the on-disk format version. 0 in legacy files; treated as 1.
	Schema    int       `json:"schema,omitempty"`
	Method    string    `json:"method"` // "isotonic-pav" or "platt"
	CreatedAt time.Time `json:"created_at"`
	NSamples  int       `json:"n_samples"`
	Knots     []Knot    `json:"knots"`
	// Brier score on the training set (lower is better, 0 is perfect).
	Brier float64 `json:"brier,omitempty"`
}

// ErrSchemaTooNew is returned by Load when a model file was produced by a
// newer build of llmscan and may use fields this binary doesn't understand.
var ErrSchemaTooNew = errors.New("calibration: model schema is newer than this build supports")

// Knot is one breakpoint of the fitted step function.
type Knot struct {
	X float64 `json:"x"` // raw score
	Y float64 `json:"y"` // calibrated probability in [0,1]
}

// Apply maps a raw score to its calibrated probability. For scores outside
// the training range we clamp to the boundary knot (sensible default — the
// alternative is linear extrapolation which can overshoot [0,1]).
func (m *Model) Apply(raw float64) float64 {
	if m == nil || len(m.Knots) == 0 {
		return raw
	}
	if raw <= m.Knots[0].X {
		return m.Knots[0].Y
	}
	if raw >= m.Knots[len(m.Knots)-1].X {
		return m.Knots[len(m.Knots)-1].Y
	}
	// Linear interpolation between two adjacent knots gives a continuous
	// (rather than purely step) mapping — friendlier for sorting/thresholding.
	i := sort.Search(len(m.Knots), func(i int) bool { return m.Knots[i].X >= raw })
	if i == 0 {
		return m.Knots[0].Y
	}
	lo, hi := m.Knots[i-1], m.Knots[i]
	if hi.X == lo.X {
		return hi.Y
	}
	t := (raw - lo.X) / (hi.X - lo.X)
	return lo.Y + t*(hi.Y-lo.Y)
}

// Fit runs Pool Adjacent Violators (PAV) on the given samples and returns a
// monotonically non-decreasing calibration model.
//
// PAV is the classical isotonic regression algorithm: sort by X, then
// repeatedly merge adjacent blocks whose means violate monotonicity until
// none remain. O(n) after the initial sort.
func Fit(samples []Sample) *Model {
	if len(samples) == 0 {
		return &Model{Method: "isotonic-pav", CreatedAt: time.Now()}
	}
	// Sort by raw score.
	sorted := append([]Sample(nil), samples...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Score < sorted[j].Score })

	// Initialise blocks: one sample per block.
	type block struct {
		sum   float64 // sum of y values (0 or 1)
		count int
		xmin  float64
		xmax  float64
	}
	blocks := make([]block, 0, len(sorted))
	for _, s := range sorted {
		y := 0.0
		if s.TP {
			y = 1.0
		}
		blocks = append(blocks, block{sum: y, count: 1, xmin: s.Score, xmax: s.Score})
	}

	// PAV: merge adjacent violators.
	for i := 0; i < len(blocks)-1; {
		mi := blocks[i].sum / float64(blocks[i].count)
		mj := blocks[i+1].sum / float64(blocks[i+1].count)
		if mi <= mj {
			i++
			continue
		}
		// merge i+1 into i
		blocks[i].sum += blocks[i+1].sum
		blocks[i].count += blocks[i+1].count
		if blocks[i+1].xmax > blocks[i].xmax {
			blocks[i].xmax = blocks[i+1].xmax
		}
		if blocks[i+1].xmin < blocks[i].xmin {
			blocks[i].xmin = blocks[i+1].xmin
		}
		blocks = append(blocks[:i+1], blocks[i+2:]...)
		if i > 0 {
			i-- // re-check the now-merged block against its predecessor
		}
	}

	// Materialise knots — one per block at the block's xmax with the block
	// mean as Y. We also emit a knot at the block's xmin so that scores
	// inside the block map flat to the block mean.
	knots := make([]Knot, 0, len(blocks)*2)
	for _, b := range blocks {
		y := b.sum / float64(b.count)
		knots = append(knots, Knot{X: b.xmin, Y: y})
		if b.xmax != b.xmin {
			knots = append(knots, Knot{X: b.xmax, Y: y})
		}
	}
	// Enforce strict X-monotonicity by nudging duplicates (rare).
	for i := 1; i < len(knots); i++ {
		if knots[i].X <= knots[i-1].X {
			knots[i].X = math.Nextafter(knots[i-1].X, 1)
		}
	}

	m := &Model{
		Method:    "isotonic-pav",
		CreatedAt: time.Now(),
		NSamples:  len(samples),
		Knots:     knots,
	}
	m.Brier = brier(m, samples)
	return m
}

// brier returns the mean squared error between calibrated predictions and
// the binary outcomes on the training set.
func brier(m *Model, samples []Sample) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		p := m.Apply(s.Score)
		y := 0.0
		if s.TP {
			y = 1.0
		}
		d := p - y
		sum += d * d
	}
	return sum / float64(len(samples))
}

// Save writes the model as JSON. The current SchemaVersion is stamped into
// the file regardless of the value passed in m.
func Save(path string, m *Model) error {
	if m == nil {
		return errors.New("calibration save: nil model")
	}
	modelCopy := *m
	modelCopy.Schema = SchemaVersion
	data, err := json.MarshalIndent(&modelCopy, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("calibration save: %w", err)
	}
	return nil
}

// Load reads a model from JSON. Files with Schema==0 are treated as v1 for
// backward compatibility with models produced before SchemaVersion existed.
// Files with a higher Schema return ErrSchemaTooNew so callers can decide
// whether to abort or fall back to uncalibrated scoring.
func Load(path string) (*Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("calibration load: %w", err)
	}
	if m.Schema == 0 {
		m.Schema = 1 // legacy file
	}
	if m.Schema > SchemaVersion {
		return nil, fmt.Errorf("%w: file=%d, supported=%d", ErrSchemaTooNew, m.Schema, SchemaVersion)
	}
	return &m, nil
}
