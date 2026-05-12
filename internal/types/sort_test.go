package types

import "testing"

func TestSortFindings_SeverityFirst(t *testing.T) {
	fs := []Finding{
		{Severity: SevLow, Confidence: ConfHigh, Score: 0.9, File: "a.go", StartLine: 1},
		{Severity: SevCritical, Confidence: ConfLow, Score: 0.1, File: "z.go", StartLine: 99},
		{Severity: SevHigh, Confidence: ConfMedium, Score: 0.5, File: "m.go", StartLine: 10},
		{Severity: SevMedium, Confidence: ConfHigh, Score: 0.95, File: "b.go", StartLine: 2},
	}
	SortFindings(fs)
	want := []Severity{SevCritical, SevHigh, SevMedium, SevLow}
	for i, w := range want {
		if fs[i].Severity != w {
			t.Errorf("pos %d: got %q want %q", i, fs[i].Severity, w)
		}
	}
}

func TestSortFindings_ConfidenceThenScoreTiebreak(t *testing.T) {
	fs := []Finding{
		{Severity: SevHigh, Confidence: ConfLow, Score: 0.9, File: "a.go", StartLine: 1},
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.6, File: "b.go", StartLine: 1},
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.95, File: "c.go", StartLine: 1},
		{Severity: SevHigh, Confidence: ConfMedium, Score: 0.8, File: "d.go", StartLine: 1},
	}
	SortFindings(fs)
	if fs[0].File != "c.go" || fs[1].File != "b.go" {
		t.Errorf("confidence/score order wrong: %v", []string{fs[0].File, fs[1].File, fs[2].File, fs[3].File})
	}
	if fs[2].Confidence != ConfMedium {
		t.Errorf("medium should come before low; got %v", fs[2].Confidence)
	}
	if fs[3].Confidence != ConfLow {
		t.Errorf("low should be last; got %v", fs[3].Confidence)
	}
}

func TestSortFindings_FalsePositiveDemoted(t *testing.T) {
	fs := []Finding{
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.9, FalsePositive: true, File: "a.go", StartLine: 1},
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.9, FalsePositive: false, File: "b.go", StartLine: 1},
	}
	SortFindings(fs)
	if fs[0].FalsePositive {
		t.Errorf("real finding must come before FP at same severity/conf/score")
	}
}

func TestSortFindings_StableFileLine(t *testing.T) {
	fs := []Finding{
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.9, File: "b.go", StartLine: 10},
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.9, File: "a.go", StartLine: 20},
		{Severity: SevHigh, Confidence: ConfHigh, Score: 0.9, File: "a.go", StartLine: 5},
	}
	SortFindings(fs)
	if fs[0].File != "a.go" || fs[0].StartLine != 5 {
		t.Errorf("file/line tiebreak failed: %s:%d", fs[0].File, fs[0].StartLine)
	}
	if fs[1].File != "a.go" || fs[1].StartLine != 20 {
		t.Errorf("second pos wrong: %s:%d", fs[1].File, fs[1].StartLine)
	}
}
