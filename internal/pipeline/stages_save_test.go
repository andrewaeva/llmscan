package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewaeva/llmscan/internal/types"
)

func TestStageWriteStagesProducesAllFiles(t *testing.T) {
	target := t.TempDir()
	mkF := func(file string, line int, rule string, sev types.Severity) types.Finding {
		return types.Finding{
			ID:        rule + ":" + file,
			RuleID:    rule,
			Agent:     "test",
			File:      file,
			StartLine: line,
			Severity:  sev,
		}
	}
	raw := []types.Finding{
		mkF("a.go", 1, "r1", types.SevHigh),
		mkF("b.go", 2, "r2", types.SevMedium),
		mkF("c.go", 3, "r3", types.SevLow),
	}
	verified := []types.Finding{raw[0], raw[1]} // r3 dropped at verifier
	confirmed := []types.Finding{raw[0]}        // r2 dropped at fp_filter
	final := []types.Finding{}                  // r1 dropped at policy

	s := &runState{
		target:        target,
		snapRaw:       raw,
		snapVerified:  verified,
		snapConfirmed: confirmed,
		snapFinal:     final,
		stageCounts: map[string]int{
			"raw":       3,
			"dedup":     3,
			"verified":  2,
			"confirmed": 1,
			"final":     0,
		},
		dropReasons: map[string]string{
			"r3:c.go": "drop_unconfirmed",
			"r2:b.go": "policy",
			"r1:a.go": "policy",
		},
	}

	if err := stageWriteStages(context.Background(), nil, s); err != nil {
		t.Fatalf("stageWriteStages: %v", err)
	}

	dir := filepath.Join(target, ".llmscan", "stages")
	want := []string{"01-raw.json", "02-verified.json", "03-confirmed.json", "04-final.json", "stages-summary.txt"}
	for _, name := range want {
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if st.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}

	// Spot-check 01-raw.json has the expected count.
	b, err := os.ReadFile(filepath.Join(dir, "01-raw.json"))
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	var got struct {
		Count    int             `json:"count"`
		Findings []types.Finding `json:"findings"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if got.Count != 3 || len(got.Findings) != 3 {
		t.Fatalf("01-raw.json: want 3 findings, got count=%d len=%d", got.Count, len(got.Findings))
	}

	// Summary must enumerate the funnel and the drop buckets.
	sumB, err := os.ReadFile(filepath.Join(dir, "stages-summary.txt"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	sum := string(sumB)
	for _, needle := range []string{
		"01 raw          :    3",
		"05 final        :    0",
		"drop_unconfirmed (1)",
		"policy (2)",
		"a.go:1",
	} {
		if !strings.Contains(sum, needle) {
			t.Errorf("summary missing %q in:\n%s", needle, sum)
		}
	}
}
