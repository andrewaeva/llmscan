package pipeline

import (
	"github.com/andrewaeva/llmscan/internal/calibration"
	"github.com/andrewaeva/llmscan/internal/types"
)

// applyCalibration remaps every finding's Score through a fitted isotonic
// model (loaded once, then cached on the Engine). Findings with Score==0 are
// left alone — they have no LLM confidence signal to recalibrate.
//
// The model file is `e.Cfg.Precision.CalibrationPath`. Errors loading the
// model are logged once and the run continues uncalibrated rather than
// failing — calibration is a precision-amplifier, not a hard requirement.
func (e *Engine) applyCalibration(findings []types.Finding) int {
	path := e.Cfg.Precision.CalibrationPath
	if path == "" {
		return 0
	}
	if e.calModel == nil && !e.calLoadAttempted {
		e.calLoadAttempted = true
		m, err := calibration.Load(path)
		if err != nil {
			e.logf("calibration: load %q: %v (continuing uncalibrated)", path, err)
			return 0
		}
		e.calModel = m
		e.logf("calibration: loaded %d-knot model from %s (n=%d, brier=%.4f)",
			len(m.Knots), path, m.NSamples, m.Brier)
	}
	if e.calModel == nil {
		return 0
	}
	n := 0
	for i := range findings {
		f := &findings[i]
		if f.Score == 0 {
			continue
		}
		f.Score = e.calModel.Apply(f.Score)
		n++
	}
	return n
}
