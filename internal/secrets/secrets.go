// Package secrets implements a deterministic secret pre-filter used before
// the LLM secrets scanner runs. It produces high-precision findings on its
// own and routes ambiguous (entropy-positive, regex-negative) cases to the
// LLM for verification.
package secrets

import (
	"math"
	"regexp"
	"strings"
)

// Rule represents a deterministic secret pattern.
type Rule struct {
	ID       string
	Title    string
	Pattern  *regexp.Regexp
	Severity string // critical | high | medium
	CWE      string
	// MinEntropy: if >0, also require the captured token to exceed this entropy.
	MinEntropy float64
}

// Match is a single hit produced by the pre-filter.
type Match struct {
	RuleID   string
	Title    string
	Severity string
	CWE      string
	File     string
	Line     int
	Col      int
	Snippet  string // redacted (first 4 chars + ***)
	Entropy  float64
	Token    string // *full* token, only kept in-memory for verifier
}

// Rules is the curated, conservative list. Inspired by gitleaks/trufflehog.
var Rules = []Rule{
	{ID: "aws-access-key", Title: "AWS Access Key", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{ID: "aws-secret-key", Title: "AWS Secret Access Key", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?(secret|sk)["'\s:=]+([A-Za-z0-9/+=]{40})`)},
	{ID: "gcp-service-account", Title: "GCP Service Account Key", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`"type":\s*"service_account"`)},
	{ID: "google-api-key", Title: "Google API Key", Severity: "high", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{ID: "github-pat", Title: "GitHub Personal Access Token", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,255}`)},
	{ID: "github-oauth", Title: "GitHub OAuth Token", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{ID: "slack-token", Title: "Slack Token", Severity: "high", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,48}`)},
	{ID: "slack-webhook", Title: "Slack Webhook", Severity: "medium", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Z0-9/]{20,}`)},
	{ID: "stripe-live", Title: "Stripe Live Secret Key", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`)},
	{ID: "stripe-test", Title: "Stripe Test Secret Key", Severity: "high", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`)},
	{ID: "openai-key", Title: "OpenAI API Key", Severity: "high", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{ID: "anthropic-key", Title: "Anthropic API Key", Severity: "high", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`sk-ant-[A-Za-z0-9\-_]{20,}`)},
	{ID: "jwt", Title: "JSON Web Token", Severity: "medium", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{ID: "pem-private", Title: "PEM Private Key Header", Severity: "critical", CWE: "CWE-798",
		Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{ID: "generic-bearer", Title: "Bearer Token (heuristic)", Severity: "medium", CWE: "CWE-798",
		Pattern:    regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{20,}`),
		MinEntropy: 3.5},
	{ID: "generic-password", Title: "Hardcoded Password (heuristic)", Severity: "high", CWE: "CWE-798",
		Pattern:    regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']`),
		MinEntropy: 3.0},
}

// ScanText runs all rules against a single file's content.
func ScanText(path, content string) []Match {
	if content == "" {
		return nil
	}
	var out []Match
	for _, r := range Rules {
		for _, idx := range r.Pattern.FindAllStringIndex(content, -1) {
			token := content[idx[0]:idx[1]]
			ent := Shannon(token)
			if r.MinEntropy > 0 && ent < r.MinEntropy {
				continue
			}
			if isLikelyPlaceholder(token) {
				continue
			}
			line, col := offsetToLineCol(content, idx[0])
			out = append(out, Match{
				RuleID:   r.ID,
				Title:    r.Title,
				Severity: r.Severity,
				CWE:      r.CWE,
				File:     path,
				Line:     line,
				Col:      col,
				Snippet:  redact(token),
				Entropy:  ent,
				Token:    token,
			})
		}
	}
	return out
}

// HighEntropyAmbiguous returns strings that look high-entropy but matched no
// concrete rule — candidates to send to the LLM for verification.
func HighEntropyAmbiguous(content string, minEntropy float64, minLen int) []Match {
	if minEntropy == 0 {
		minEntropy = 4.5
	}
	if minLen == 0 {
		minLen = 24
	}
	re := regexp.MustCompile(`["']([A-Za-z0-9+/=_\-]{` + itoa(minLen) + `,})["']`)
	var out []Match
	for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
		token := content[m[2]:m[3]]
		ent := Shannon(token)
		if ent < minEntropy {
			continue
		}
		if isLikelyPlaceholder(token) {
			continue
		}
		line, col := offsetToLineCol(content, m[2])
		out = append(out, Match{
			RuleID:   "high-entropy",
			Title:    "High-entropy string (needs verification)",
			Severity: "medium",
			CWE:      "CWE-798",
			Line:     line,
			Col:      col,
			Snippet:  redact(token),
			Entropy:  ent,
			Token:    token,
		})
	}
	return out
}

// Shannon entropy in bits per character.
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := [256]int{}
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func isLikelyPlaceholder(s string) bool {
	low := strings.ToLower(s)
	for _, p := range []string{"example", "placeholder", "your-", "xxx", "todo", "changeme", "dummy", "sample"} {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

func redact(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:4] + "***"
}

func offsetToLineCol(s string, off int) (int, int) {
	if off > len(s) {
		off = len(s)
	}
	line := 1
	col := 1
	for i := 0; i < off; i++ {
		if s[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
