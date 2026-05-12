package calibration

import (
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestFitEmpty(t *testing.T) {
	m := Fit(nil)
	if m == nil {
		t.Fatal("nil model")
	}
	if got := m.Apply(0.5); got != 0.5 {
		t.Errorf("empty model must passthrough, got %v", got)
	}
}

func TestFitMonotonic(t *testing.T) {
	// Synthetic: higher scores correlate with TP.
	rng := rand.New(rand.NewSource(42))
	var samples []Sample
	for i := 0; i < 500; i++ {
		s := rng.Float64()
		samples = append(samples, Sample{Score: s, TP: rng.Float64() < s})
	}
	m := Fit(samples)
	if len(m.Knots) == 0 {
		t.Fatal("no knots fit")
	}
	// Y values must be non-decreasing along sorted X.
	xs := make([]float64, 0, 50)
	for x := 0.0; x <= 1.0; x += 0.02 {
		xs = append(xs, x)
	}
	prev := -1.0
	for _, x := range xs {
		y := m.Apply(x)
		if y < prev-1e-9 {
			t.Errorf("monotonicity broken at x=%.3f: y=%.4f prev=%.4f", x, y, prev)
		}
		if y < 0 || y > 1 {
			t.Errorf("y out of [0,1] at x=%.3f: %v", x, y)
		}
		prev = y
	}
}

func TestFitPerfectSeparator(t *testing.T) {
	// Below 0.5 = FP, above = TP. PAV should learn approx step function.
	var samples []Sample
	for i := 0; i < 100; i++ {
		x := float64(i) / 100
		samples = append(samples, Sample{Score: x, TP: x >= 0.5})
	}
	m := Fit(samples)
	if got := m.Apply(0.1); got > 0.05 {
		t.Errorf("low region should map low, got %v", got)
	}
	if got := m.Apply(0.9); got < 0.95 {
		t.Errorf("high region should map high, got %v", got)
	}
}

func TestFitOvercofidentLLM(t *testing.T) {
	// Realistic scenario: LLM is overconfident — claims 0.9 but really 0.5 TP.
	rng := rand.New(rand.NewSource(7))
	var samples []Sample
	for i := 0; i < 1000; i++ {
		samples = append(samples, Sample{Score: 0.9, TP: rng.Float64() < 0.5})
	}
	for i := 0; i < 200; i++ {
		samples = append(samples, Sample{Score: 0.2, TP: rng.Float64() < 0.1})
	}
	m := Fit(samples)
	cal := m.Apply(0.9)
	if math.Abs(cal-0.5) > 0.1 {
		t.Errorf("expected calibrated(0.9) ≈ 0.5 (TP rate), got %v", cal)
	}
	low := m.Apply(0.2)
	if low > 0.25 || low < 0 {
		t.Errorf("expected calibrated(0.2) ≈ 0.1, got %v", low)
	}
}

func TestApplyClampsOutOfRange(t *testing.T) {
	samples := []Sample{
		{Score: 0.3, TP: false},
		{Score: 0.4, TP: false},
		{Score: 0.7, TP: true},
		{Score: 0.8, TP: true},
	}
	m := Fit(samples)
	// Below the smallest knot must be clamped to the leftmost Y, not return 0.
	left := m.Apply(-1)
	if left != m.Knots[0].Y {
		t.Errorf("left clamp: got %v want %v", left, m.Knots[0].Y)
	}
	right := m.Apply(2)
	if right != m.Knots[len(m.Knots)-1].Y {
		t.Errorf("right clamp: got %v want %v", right, m.Knots[len(m.Knots)-1].Y)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	samples := []Sample{
		{Score: 0.1, TP: false}, {Score: 0.2, TP: false}, {Score: 0.3, TP: true},
		{Score: 0.5, TP: true}, {Score: 0.6, TP: true}, {Score: 0.8, TP: true},
	}
	m := Fit(samples)
	dir := t.TempDir()
	path := filepath.Join(dir, "cal.json")
	if err := Save(path, m); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.NSamples != m.NSamples {
		t.Errorf("nsamples mismatch")
	}
	if len(got.Knots) != len(m.Knots) {
		t.Fatalf("knot count mismatch: %d vs %d", len(got.Knots), len(m.Knots))
	}
	for i := range got.Knots {
		if math.Abs(got.Knots[i].X-m.Knots[i].X) > 1e-9 ||
			math.Abs(got.Knots[i].Y-m.Knots[i].Y) > 1e-9 {
			t.Errorf("knot %d mismatch: got %+v want %+v", i, got.Knots[i], m.Knots[i])
		}
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(os.TempDir(), "no-such-calibration.json")); err == nil {
		t.Error("expected error on missing file")
	}
}

func TestBrierBetterThanRaw(t *testing.T) {
	// Calibration must not be worse than identity on its training set.
	rng := rand.New(rand.NewSource(99))
	var samples []Sample
	for i := 0; i < 800; i++ {
		raw := rng.Float64()
		// True probability is sqrt(raw) — overconfident raw scores.
		samples = append(samples, Sample{Score: raw, TP: rng.Float64() < math.Sqrt(raw)})
	}
	m := Fit(samples)
	var rawBrier float64
	for _, s := range samples {
		y := 0.0
		if s.TP {
			y = 1.0
		}
		d := s.Score - y
		rawBrier += d * d
	}
	rawBrier /= float64(len(samples))
	if m.Brier > rawBrier {
		t.Errorf("calibrated Brier (%.4f) worse than raw (%.4f)", m.Brier, rawBrier)
	}
}

func TestKnotsSortedByX(t *testing.T) {
	samples := []Sample{
		{Score: 0.5, TP: true}, {Score: 0.1, TP: false},
		{Score: 0.9, TP: true}, {Score: 0.2, TP: false},
		{Score: 0.7, TP: true}, {Score: 0.3, TP: false},
	}
	m := Fit(samples)
	xs := make([]float64, len(m.Knots))
	for i, k := range m.Knots {
		xs[i] = k.X
	}
	if !sort.Float64sAreSorted(xs) {
		t.Errorf("knots must be sorted by X, got %v", xs)
	}
}
