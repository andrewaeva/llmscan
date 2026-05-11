// Package report renders a scan report in several formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/andrewaeva/llmscan/internal/types"
)

// WriteJSON emits the full report as indented JSON.
func WriteJSON(w io.Writer, r types.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText emits a human-readable summary.
func WriteText(w io.Writer, r types.Report) error {
	fmt.Fprintf(w, "llmscan report\n")
	fmt.Fprintf(w, "target:        %s\n", r.Target)
	fmt.Fprintf(w, "duration:      %s\n", r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "files scanned: %d\n", r.FilesScanned)
	fmt.Fprintf(w, "raw=%d  dedup=%d  verified=%d  fp=%d  final=%d\n",
		r.Stats.Raw, r.Stats.AfterDedup, r.Stats.AfterVerify, r.Stats.FalsePos, len(r.Findings))

	if len(r.Stats.BySeverity) > 0 {
		fmt.Fprintf(w, "\nby severity:\n")
		keys := []string{"critical", "high", "medium", "low", "info"}
		for _, k := range keys {
			if v, ok := r.Stats.BySeverity[k]; ok && v > 0 {
				fmt.Fprintf(w, "  %-8s %d\n", k, v)
			}
		}
	}
	if len(r.Stats.ByAgent) > 0 {
		fmt.Fprintf(w, "\nby agent:\n")
		keys := make([]string, 0, len(r.Stats.ByAgent))
		for k := range r.Stats.ByAgent {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %-15s %d\n", k, r.Stats.ByAgent[k])
		}
	}

	sorted := append([]types.Finding(nil), r.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		si := sevRank(sorted[i].Severity)
		sj := sevRank(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		return sorted[i].StartLine < sorted[j].StartLine
	})

	fmt.Fprintf(w, "\nfindings:\n")
	if len(sorted) == 0 {
		fmt.Fprintf(w, "  (none)\n")
		return nil
	}
	for _, f := range sorted {
		fp := ""
		if f.FalsePositive {
			fp = " [FP]"
		}
		fmt.Fprintf(w, "\n- [%s/%s] %s%s\n", strings.ToUpper(string(f.Severity)), f.Confidence, f.Title, fp)
		fmt.Fprintf(w, "  agent:     %s\n", f.Agent)
		fmt.Fprintf(w, "  location:  %s:%d-%d\n", f.File, f.StartLine, f.EndLine)
		if f.RuleID != "" {
			fmt.Fprintf(w, "  rule_id:   %s\n", f.RuleID)
		}
		if f.CWE != "" {
			fmt.Fprintf(w, "  cwe:       %s\n", f.CWE)
		}
		if f.OWASP != "" {
			fmt.Fprintf(w, "  owasp:     %s\n", f.OWASP)
		}
		if f.Description != "" {
			fmt.Fprintf(w, "  why:       %s\n", oneLine(f.Description))
		}
		if f.VerifierComment != "" {
			fmt.Fprintf(w, "  verifier:  %s (%s)\n", oneLine(f.VerifierComment), f.VerifierVerdict)
		}
		if f.SuggestedFix != "" {
			fmt.Fprintf(w, "  fix:       %s\n", oneLine(f.SuggestedFix))
		}
		if f.CodeSample != "" {
			fmt.Fprintf(w, "  sample:\n")
			for _, l := range strings.Split(f.CodeSample, "\n") {
				fmt.Fprintf(w, "    %s\n", l)
			}
		}
	}
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}

func sevRank(s types.Severity) int {
	switch s {
	case types.SevCritical:
		return 5
	case types.SevHigh:
		return 4
	case types.SevMedium:
		return 3
	case types.SevLow:
		return 2
	case types.SevInfo:
		return 1
	}
	return 0
}

// ---------- SARIF ----------

// WriteSARIF emits a minimal SARIF 2.1.0 document.
func WriteSARIF(w io.Writer, r types.Report) error {
	type loc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string `json:"ruleId"`
		Level     string `json:"level"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []loc `json:"locations"`
	}
	type rule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
	}
	type run struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []rule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	var s sarif
	s.Schema = "https://json.schemastore.org/sarif-2.1.0.json"
	s.Version = "2.1.0"
	var r1 run
	r1.Tool.Driver.Name = "llmscan"
	r1.Tool.Driver.Version = "0.1.0"

	ruleSet := map[string]rule{}
	for _, f := range r.Findings {
		if f.FalsePositive {
			continue
		}
		id := f.RuleID
		if id == "" {
			id = f.Agent + "/" + strings.ReplaceAll(strings.ToLower(f.Title), " ", "-")
		}
		if _, ok := ruleSet[id]; !ok {
			var rl rule
			rl.ID = id
			rl.Name = f.Title
			rl.ShortDescription.Text = f.Description
			ruleSet[id] = rl
		}
		var res result
		res.RuleID = id
		res.Level = sevToSARIF(f.Severity)
		res.Message.Text = f.Description
		var l loc
		l.PhysicalLocation.ArtifactLocation.URI = f.File
		l.PhysicalLocation.Region.StartLine = max1(f.StartLine, 1)
		l.PhysicalLocation.Region.EndLine = max1(f.EndLine, f.StartLine)
		res.Locations = []loc{l}
		r1.Results = append(r1.Results, res)
	}
	for _, rl := range ruleSet {
		r1.Tool.Driver.Rules = append(r1.Tool.Driver.Rules, rl)
	}
	s.Runs = []run{r1}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

func sevToSARIF(s types.Severity) string {
	switch s {
	case types.SevCritical, types.SevHigh:
		return "error"
	case types.SevMedium:
		return "warning"
	case types.SevLow, types.SevInfo:
		return "note"
	}
	return "none"
}

func max1(a, b int) int {
	if a > b {
		return a
	}
	return b
}
