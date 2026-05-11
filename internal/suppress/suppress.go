// Package suppress parses in-source suppression comments.
//
// Syntax (placed on the offending line or the line above):
//
//	// llmscan:ignore[<rule>] reason: <text>
//	# llmscan:ignore[<rule>] reason: <text>
//	/* llmscan:ignore[<rule>] reason: <text> */
//
// `<rule>` is either a rule_id, agent name, or `*` for everything.
package suppress

import (
	"bufio"
	"regexp"
	"strings"
)

// Suppression is a parsed marker.
type Suppression struct {
	File   string
	Line   int    // line where the marker is placed
	Rule   string // rule_id, agent or *
	Reason string
}

var markerRE = regexp.MustCompile(`llmscan:ignore\[([^\]]+)\](?:\s+reason:\s*(.*))?`)

// Parse scans file content for suppression markers and returns them.
func Parse(file, content string) []Suppression {
	var out []Suppression
	sc := bufio.NewScanner(content2reader(content))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		m := markerRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rule := strings.TrimSpace(m[1])
		reason := ""
		if len(m) > 2 {
			reason = strings.TrimSpace(m[2])
		}
		out = append(out, Suppression{File: file, Line: lineNo, Rule: rule, Reason: reason})
	}
	return out
}

// MatchAt returns the matching suppression (if any) for (file,line,rule).
// A marker on line N suppresses findings on line N and N+1.
func MatchAt(ss []Suppression, file string, line int, rule, agent string) (Suppression, bool) {
	for _, s := range ss {
		if s.File != file {
			continue
		}
		if line < s.Line || line > s.Line+1 {
			continue
		}
		if s.Rule == "*" || s.Rule == rule || s.Rule == agent {
			return s, true
		}
	}
	return Suppression{}, false
}

// tiny reader helper to avoid importing strings.NewReader at top scope twice
func content2reader(s string) *strings.Reader { return strings.NewReader(s) }
