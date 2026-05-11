// Package eval implements benchmark evaluation: given a labeled dataset
// (path + expected findings per file), it runs the scanner and computes
// precision / recall / F1 per CWE and overall.
//
// Supported dataset adapters (all local-path):
//   - "juliet"          (Juliet Test Suite extracted folder)
//   - "owasp-benchmark" (BenchmarkJava expectedresults-1.2.csv)
//   - "securityeval"    (SecurityEval JSONL: {code, cwe, label})
//   - "generic"         (labels.json: [{file,cwe,line}, ...])
//
// The eval command is intentionally adapter-driven and does NOT download.
package eval

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// Label is the ground truth for a single test case.
type Label struct {
	File string `json:"file"`
	CWE  string `json:"cwe"`
	Line int    `json:"line,omitempty"`
}

// LoadLabels reads the dataset and returns ground-truth labels.
func LoadLabels(adapter, path string) ([]Label, error) {
	switch adapter {
	case "owasp-benchmark":
		return loadOwasp(path)
	case "securityeval":
		return loadSecurityEval(path)
	case "juliet":
		return loadJuliet(path)
	case "generic":
		return loadGeneric(path)
	}
	return nil, fmt.Errorf("eval: unknown adapter %q", adapter)
}

// Metrics holds aggregate scores.
type Metrics struct {
	TP        int                `json:"tp"`
	FP        int                `json:"fp"`
	FN        int                `json:"fn"`
	Precision float64            `json:"precision"`
	Recall    float64            `json:"recall"`
	F1        float64            `json:"f1"`
	ByCWE     map[string]*Scores `json:"by_cwe"`
}

// Scores per category.
type Scores struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// Compare matches predicted findings against labels and produces metrics.
// A match requires same file + same CWE (line is informative only).
func Compare(predicted []types.Finding, labels []Label) Metrics {
	type key struct{ file, cwe string }
	want := map[key]bool{}
	have := map[key]bool{}
	for _, l := range labels {
		want[key{filepath.Clean(l.File), strings.ToUpper(l.CWE)}] = true
	}
	for _, f := range predicted {
		have[key{filepath.Clean(f.File), strings.ToUpper(f.CWE)}] = true
	}
	m := Metrics{ByCWE: map[string]*Scores{}}
	for k := range want {
		s, ok := m.ByCWE[k.cwe]
		if !ok {
			s = &Scores{}
			m.ByCWE[k.cwe] = s
		}
		if have[k] {
			m.TP++
			s.TP++
		} else {
			m.FN++
			s.FN++
		}
	}
	for k := range have {
		if !want[k] {
			m.FP++
			s, ok := m.ByCWE[k.cwe]
			if !ok {
				s = &Scores{}
				m.ByCWE[k.cwe] = s
			}
			s.FP++
		}
	}
	finalize := func(tp, fp, fn int) (p, r, f1 float64) {
		if tp+fp > 0 {
			p = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			r = float64(tp) / float64(tp+fn)
		}
		if p+r > 0 {
			f1 = 2 * p * r / (p + r)
		}
		return
	}
	m.Precision, m.Recall, m.F1 = finalize(m.TP, m.FP, m.FN)
	for _, s := range m.ByCWE {
		s.Precision, s.Recall, s.F1 = finalize(s.TP, s.FP, s.FN)
	}
	return m
}

// PrintReport writes a human-readable summary to stdout.
func PrintReport(m Metrics) {
	fmt.Printf("Overall: TP=%d FP=%d FN=%d  P=%.3f R=%.3f F1=%.3f\n",
		m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1)
	keys := make([]string, 0, len(m.ByCWE))
	for k := range m.ByCWE {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := m.ByCWE[k]
		fmt.Printf("  %-12s TP=%-4d FP=%-4d FN=%-4d  P=%.3f R=%.3f F1=%.3f\n",
			k, s.TP, s.FP, s.FN, s.Precision, s.Recall, s.F1)
	}
}

// ---- adapters ----

func loadGeneric(path string) ([]Label, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Label
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SecurityEval JSONL: {"code":"...","cwe":"CWE-79","label":1,"id":"...","path":"..."}.
func loadSecurityEval(path string) ([]Label, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Label
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Path  string `json:"path"`
			CWE   string `json:"cwe"`
			Label int    `json:"label"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Label != 1 || rec.Path == "" || rec.CWE == "" {
			continue
		}
		out = append(out, Label{File: rec.Path, CWE: rec.CWE})
	}
	return out, nil
}

// OWASP Benchmark: expectedresults-1.2.csv has columns:
// # test name, category, real vulnerability, cwe, ...
func loadOwasp(path string) ([]Label, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []Label
	for i, row := range rows {
		if i == 0 || len(row) < 4 {
			continue
		}
		if strings.HasPrefix(row[0], "#") {
			continue
		}
		real := strings.ToLower(strings.TrimSpace(row[2]))
		if real != "true" {
			continue
		}
		cwe := "CWE-" + strings.TrimSpace(row[3])
		out = append(out, Label{File: row[0] + ".java", CWE: cwe})
	}
	return out, nil
}

// Juliet: filename pattern CWE<NUM>_<class>_<sub>_<id>.java. Bad cases have
// "bad" suffix; good cases have "good". We treat bad cases as positive labels.
func loadJuliet(root string) ([]Label, error) {
	var out []Label
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		if !strings.HasPrefix(base, "CWE") {
			return nil
		}
		// extract CWE id up to first underscore
		us := strings.Index(base, "_")
		if us < 4 {
			return nil
		}
		cwe := base[:us] // "CWE89"
		cwe = strings.Replace(cwe, "CWE", "CWE-", 1)
		// only label files containing bad sinks (Juliet structure varies — accept all)
		out = append(out, Label{File: p, CWE: cwe})
		return nil
	})
	return out, err
}
