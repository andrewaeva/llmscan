// Package agents implements the multi-agent hierarchy:
//
//	Orchestrator -> Scanner agents (per vulnerability class) -> Verifier -> FP Filter.
//
// Every agent is just an LLM call with a focused prompt and strict JSON output.
package agents

import (
	"encoding/json"
	"strings"
)

// ScannerNames is the canonical, ordered list of specialized scanner agents.
// New skill names (insecure-defaults, race-conditions, error-handling,
// supply-chain, memory-safety) load dynamically via skills/*/SKILL.md and are
// auto-registered into the DAG by enabledScanners, but they're listed here so
// the orchestrator's default focus plan includes them too.
var ScannerNames = []string{
	"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic",
	"insecure-defaults", "race-conditions", "error-handling", "supply-chain", "memory-safety",
}

// ---- shared helpers ----

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func emptyIf(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func hash6(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 6)
	for i := range out {
		out[i] = abc[h%uint32(len(abc))]
		h /= uint32(len(abc))
		if h == 0 {
			h = 2166136261 ^ uint32(i)
		}
	}
	return string(out)
}

// ---- prompts ----

const orchestratorSystem = `You are the Orchestrator agent of a multi-agent code security scanner.

Goal: produce a high-level scan plan from a project file tree.
You MUST return a single JSON object with this shape:
{
  "reasoning": "1-3 sentences explaining your plan",
  "priority": ["path/to/file1", "..."],
  "focus":    ["injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic"],
  "skip_globs": ["*.lock", "vendor/", ...],
  "agent_hints": {"secrets": ["config/*.yaml"], "injection": ["api/*.go"]}
}

Pick at most 50 priority files (most likely to contain bugs / handle untrusted input / auth / secrets).
Focus must be a subset of the allowed agent names.
No prose outside JSON.`

const scannerSystemTemplate = `You are the %s security agent inside a multi-agent code scanner.

Your scope: %s

You receive ONE file (possibly chunked). Output a JSON object:
{
  "findings": [
    {
      "rule_id": "short-id",
      "title": "human title",
      "description": "what is wrong and why",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "cwe": "CWE-XXX",
      "owasp": "AXX:YYYY",
      "start_line": 12,
      "end_line": 20,
      "code_sample": "the offending lines",
      "suggested_fix": "1-3 sentences",
      "references": ["https://..."]
    }
  ]
}

Rules:
- If nothing found, return {"findings": []}.
- Line numbers refer to the CHUNK you receive (1-based). Caller will re-base them.
- Be conservative. Mark uncertain or speculative findings with confidence="low".
- Never invent code that is not in the snippet.
- Do not flag generic "input is not validated" without a concrete dangerous sink.
- No prose outside JSON.`

const verifierSystem = `You are the Verifier agent. You receive ONE raw finding plus the source code around it.

Decide whether the finding is real or a false positive, and refine its severity/confidence.

Return JSON:
{
  "verdict": "true_positive|false_positive|needs_more_context",
  "comment": "1-3 sentences explaining the verdict",
  "false_positive": true|false,
  "fp_reason": "if false_positive=true, short tag like 'test-code'|'unreachable'|'sanitized'|'no-sink'|'static-data'|'duplicate'",
  "severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "suggested_fix": "optional, improved fix proposal"
}

Heuristics:
- Code under */test*, *_test.*, examples/, fixtures/, mocks/ -> usually false_positive unless it is clearly exploitable.
- Constants used only inside tests -> false_positive 'test-code'.
- Sink dominated by a known sanitizer / parameterized call -> false_positive 'sanitized'.
- No taint source reaching the sink in the visible context -> false_positive 'no-sink'.
- Demo/example strings clearly labeled as such -> false_positive 'example'.
- When in doubt prefer 'needs_more_context' over guessing.
No prose outside JSON.`

const fpFilterSystem = `You are the False-Positive Filter agent. You receive a JSON array of VERIFIED findings.

Your job: deduplicate, merge near-duplicates, and drop residual obvious false positives.

Return JSON:
{
  "kept": [<finding ids to keep>],
  "dropped": [{"id":"...","reason":"..."}],
  "merges": [{"keep":"id_a","merge":["id_b","id_c"]}]
}

Rules:
- Two findings at the same file+line range with similar titles -> merge.
- Findings flagged false_positive=true upstream -> drop (echo reason).
- Low-confidence findings without any taint source visible -> drop with reason 'no-evidence'.
- Never drop a finding with severity in {critical,high} unless it was already marked false_positive.
No prose outside JSON.`

// scopeForAgent returns a short scope description used in the scanner prompt template.
func scopeForAgent(name string) string {
	switch name {
	case "injection":
		return "Injection vulnerabilities: SQL, NoSQL, command, LDAP, XPath, template injection; unsafe string concatenation reaching exec/query sinks."
	case "secrets":
		return "Hardcoded secrets: API keys, tokens, passwords, private keys, cloud credentials, JWT secrets, DB connection strings with passwords."
	case "auth":
		return "Authentication and authorization flaws: missing auth checks, broken access control, weak session handling, IDOR, JWT misuse."
	case "crypto":
		return "Cryptographic misuse: weak/deprecated algorithms (MD5/SHA1/DES/RC4), ECB mode, static IVs, predictable RNG for security, hardcoded keys."
	case "deserialization":
		return "Unsafe deserialization of untrusted data: pickle.loads, yaml.load, Java ObjectInputStream, eval, Function() on user input."
	case "ssrf":
		return "SSRF, open redirects, and unsafe outbound requests built from user-controlled URLs without allowlists or scheme checks."
	case "generic":
		return "Other high-impact issues: path traversal, race conditions on security checks, XXE, insecure file permissions, prototype pollution, unsafe reflection."
	}
	return "General code security issues."
}
