package pipeline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

func buildFindingGroups(findings []types.Finding) []types.FindingGroup {
	if len(findings) == 0 {
		return nil
	}

	buckets := make(map[string][]types.Finding, len(findings))
	for _, f := range findings {
		key, _ := findingGroupKey(f)
		buckets[key] = append(buckets[key], f)
	}

	out := make([]types.FindingGroup, 0, len(buckets))
	for _, members := range buckets {
		out = append(out, newFindingGroup(members))
	}

	sort.SliceStable(out, func(i, j int) bool {
		return types.LessFinding(out[i].Primary, out[j].Primary)
	})
	for i := range out {
		out[i].ID = fmt.Sprintf("group-%03d", i+1)
	}
	return out
}

func newFindingGroup(findings []types.Finding) types.FindingGroup {
	members := append([]types.Finding(nil), findings...)
	types.SortFindings(members)
	primary := members[0]
	_, basis := findingGroupKey(primary)

	files := make(map[string]struct{}, len(members))
	occurrences := make([]types.FindingOccurrence, 0, len(members))
	for _, f := range members {
		files[f.File] = struct{}{}
		occurrences = append(occurrences, findingOccurrenceFrom(f))
	}

	return types.FindingGroup{
		Basis:           basis,
		RuleID:          primary.RuleID,
		Title:           primary.Title,
		Agent:           primary.Agent,
		Severity:        primary.Severity,
		Confidence:      primary.Confidence,
		Score:           primary.Score,
		CWE:             primary.CWE,
		OWASP:           primary.OWASP,
		FileCount:       len(files),
		OccurrenceCount: len(members),
		Primary:         primary,
		Occurrences:     occurrences,
	}
}

func findingOccurrenceFrom(f types.Finding) types.FindingOccurrence {
	return types.FindingOccurrence{
		FindingID:     f.ID,
		File:          f.File,
		StartLine:     f.StartLine,
		EndLine:       f.EndLine,
		Confidence:    f.Confidence,
		Score:         f.Score,
		Verified:      f.Verified,
		FalsePositive: f.FalsePositive,
		DeepVerdict:   f.DeepVerdict,
	}
}

func findingGroupKey(f types.Finding) (string, string) {
	head := groupIdentity(f)
	traceSig := findingTraceSignature(f)
	codeSig := normalizeGroupSnippet(f.CodeSample)
	descSig := specificGroupText(f.Description)
	switch {
	case traceSig != "":
		return head + "|trace|" + traceSig, "trace"
	case codeSig != "":
		return head + "|code_sample|" + codeSig, "code_sample"
	case descSig != "":
		return head + "|description|" + descSig, "description"
	default:
		return fmt.Sprintf("%s|location|%s|%d|%d", head, f.File, f.StartLine, f.EndLine), "location"
	}
}

func groupIdentity(f types.Finding) string {
	rule := normalizeGroupText(f.RuleID)
	title := normalizeGroupText(f.Title)
	agent := normalizeGroupText(f.Agent)
	if rule == "" {
		rule = title
	}
	return strings.Join([]string{rule, agent, title}, "|")
}

func findingTraceSignature(f types.Finding) string {
	if len(f.Trace) == 0 {
		return ""
	}
	source := traceHopSignature(selectTraceHop(f.Trace, "source", true))
	sink := traceHopSignature(selectTraceHop(f.Trace, "sink", false))
	sanitizer := normalizeGroupText(f.Sanitizer)
	if source == "" && sink == "" && sanitizer == "" {
		return ""
	}
	return strings.Join([]string{source, sink, sanitizer}, "|")
}

func selectTraceHop(hops []types.TraceHop, kind string, first bool) *types.TraceHop {
	if first {
		for i := range hops {
			if strings.EqualFold(hops[i].Kind, kind) {
				return &hops[i]
			}
		}
		return &hops[0]
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if strings.EqualFold(hops[i].Kind, kind) {
			return &hops[i]
		}
	}
	return &hops[len(hops)-1]
}

func traceHopSignature(h *types.TraceHop) string {
	if h == nil {
		return ""
	}
	text := normalizeGroupSnippet(h.Code)
	if text == "" {
		text = normalizeGroupText(h.Note)
	}
	if text == "" {
		return ""
	}
	kind := normalizeGroupText(h.Kind)
	if kind == "" {
		return text
	}
	return kind + ":" + text
}

func normalizeGroupText(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "\r", ""))
	return strings.Join(strings.Fields(s), " ")
}

func normalizeGroupSnippet(s string) string {
	s = normalizeGroupText(s)
	return strings.ReplaceAll(s, " ", "")
}

func specificGroupText(s string) string {
	s = normalizeGroupText(s)
	if len(s) < 32 {
		return ""
	}
	if len(strings.Fields(s)) < 4 {
		return ""
	}
	return s
}
