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

// WriteText emits a human-readable summary. Coloring is auto-detected from
// the writer (TTY + NO_COLOR/CLICOLOR_FORCE env). Use WriteTextWith to force
// a specific ColorMode.
func WriteText(w io.Writer, r types.Report) error {
	return WriteTextWith(w, r, ColorAuto)
}

// WriteTextWith emits a human-readable summary, with explicit color control.
func WriteTextWith(w io.Writer, r types.Report, mode ColorMode) error {
	p := palette{on: resolveColor(w, mode)}

	// Header banner.
	fmt.Fprintf(w, "%s\n", p.bold(p.cyan("━━ llmscan report ━━")))
	fmt.Fprintf(w, "%s %s\n", p.dim("target:       "), r.Target)
	fmt.Fprintf(w, "%s %s\n", p.dim("duration:     "), r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "%s %d\n", p.dim("files scanned:"), r.FilesScanned)
	fmt.Fprintf(w, "%s raw=%d dedup=%d verified=%d fp=%d %s=%d\n",
		p.dim("pipeline:     "),
		r.Stats.Raw, r.Stats.AfterDedup, r.Stats.AfterVerify, r.Stats.FalsePos,
		p.bold("final"), len(r.Findings))

	if len(r.Stats.BySeverity) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.bold("by severity:"))
		keys := []string{"critical", "high", "medium", "low", "info"}
		for _, k := range keys {
			v, ok := r.Stats.BySeverity[k]
			if !ok || v == 0 {
				continue
			}
			badge := p.sevBadge(types.Severity(k))
			fmt.Fprintf(w, "  %s %s\n", badge, p.bold(fmt.Sprintf("%d", v)))
		}
	}
	if len(r.Stats.ByAgent) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.bold("by agent:"))
		keys := make([]string, 0, len(r.Stats.ByAgent))
		for k := range r.Stats.ByAgent {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "  %s %d\n", p.cyan(fmt.Sprintf("%-15s", k)), r.Stats.ByAgent[k])
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

	fmt.Fprintf(w, "\n%s\n", p.bold(fmt.Sprintf("findings (%d):", len(sorted))))
	if len(sorted) == 0 {
		fmt.Fprintf(w, "  %s\n", p.green("(none — clean run)"))
		return nil
	}
	for i, f := range sorted {
		writeFinding(w, p, i+1, f)
	}
	return nil
}

//nolint:gocyclo // optional formatting branches per finding field
func writeFinding(w io.Writer, p palette, idx int, f types.Finding) {
	fp := ""
	if f.FalsePositive {
		fp = " " + p.gray("[FP]")
	}
	num := p.dim(fmt.Sprintf("#%d", idx))
	badge := p.sevBadge(f.Severity)
	conf := p.confColor(string(f.Confidence))
	title := p.bold(f.Title)
	fmt.Fprintf(w, "\n%s %s %s %s%s\n",
		num, badge, p.dim("conf=")+conf, title, fp)

	loc := fmt.Sprintf("%s:%d-%d", f.File, f.StartLine, f.EndLine)
	label := func(k string) string { return p.dim(fmt.Sprintf("  %-9s", k)) }

	fmt.Fprintf(w, "%s %s\n", label("agent:"), p.magenta(f.Agent))
	fmt.Fprintf(w, "%s %s\n", label("location:"), p.cyan(loc))
	if f.RuleID != "" {
		fmt.Fprintf(w, "%s %s\n", label("rule_id:"), f.RuleID)
	}
	if f.CWE != "" {
		fmt.Fprintf(w, "%s %s\n", label("cwe:"), p.yellow(f.CWE))
	}
	if f.OWASP != "" {
		fmt.Fprintf(w, "%s %s\n", label("owasp:"), p.yellow(f.OWASP))
	}
	if f.Description != "" {
		fmt.Fprintf(w, "%s %s\n", label("why:"), oneLine(f.Description))
	}
	if f.VerifierComment != "" {
		verdict := f.VerifierVerdict
		vc := p.gray(verdict)
		switch strings.ToLower(verdict) {
		case "true_positive", "tp", "confirmed":
			vc = p.red(verdict)
		case "false_positive", "fp":
			vc = p.green(verdict)
		}
		fmt.Fprintf(w, "%s %s (%s)\n", label("verifier:"), oneLine(f.VerifierComment), vc)
	}
	if f.DeepVerified {
		vc := p.gray(f.DeepVerdict)
		switch strings.ToLower(f.DeepVerdict) {
		case "confirmed":
			vc = p.red(f.DeepVerdict)
		case "refuted":
			vc = p.green(f.DeepVerdict)
		case "inconclusive":
			vc = p.yellow(f.DeepVerdict)
		}
		dc := oneLine(f.DeepComment)
		fmt.Fprintf(w, "%s %s (%s, %d tool calls)\n", label("deep:"), dc, vc, len(f.DeepTrace))
	}
	if f.SuggestedFix != "" {
		fmt.Fprintf(w, "%s %s\n", label("fix:"), p.green(oneLine(f.SuggestedFix)))
	}
	if f.CodeSample != "" {
		fmt.Fprintf(w, "%s\n", label("sample:"))
		for _, l := range strings.Split(f.CodeSample, "\n") {
			fmt.Fprintf(w, "    %s\n", p.dim("│ ")+l)
		}
	}
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
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
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
