// Package baseline computes stable fingerprints for findings and filters out
// findings that already exist in a stored baseline. Used to gate PRs on
// *new* issues only.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/types"
)

// Fingerprint computes a stable id for a finding that is insensitive to
// line shifts (uses normalized code sample and rule_id+file).
func Fingerprint(f types.Finding) string {
	code := normalize(f.CodeSample)
	if code == "" {
		code = normalize(f.Description)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s", f.RuleID, f.Agent, f.File, code)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// FilterNew keeps only findings whose fingerprint is NOT present in known.
func FilterNew(findings []types.Finding, known map[string]struct{}) []types.Finding {
	if len(known) == 0 {
		return findings
	}
	var out []types.Finding
	for _, f := range findings {
		fp := Fingerprint(f)
		if _, ok := known[fp]; ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

// AsMap returns fingerprints->json-stringified findings for storage.
func AsMap(findings []types.Finding) map[string]string {
	out := make(map[string]string, len(findings))
	for _, f := range findings {
		out[Fingerprint(f)] = fmt.Sprintf("%s/%s @%s:%d", f.Agent, f.RuleID, f.File, f.StartLine)
	}
	return out
}

func normalize(s string) string {
	// collapse whitespace
	s = strings.ReplaceAll(s, "\r", "")
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
