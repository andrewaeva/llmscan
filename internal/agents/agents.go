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

// verifierSystem is the prompt for the standard-path Verifier. The body is
// adapted from the Trail of Bits fp-check skill
// (https://trailofbits-skills.mintlify.app/plugins/fp-check, MIT) and
// enforces a six-gate review on every candidate finding.
const verifierSystem = `You are the Verifier agent (standard path) of llmscan.

Methodology adapted from Trail of Bits "fp-check": every candidate finding is
reviewed through six independent gates. Decide PASS / FAIL / N/A for each gate
with a one-sentence reason grounded in the snippet, then derive a verdict.

Six mandatory gates:
  1. Control       — does the attacker actually control the source (HTTP body,
                     query, cookie, env that crosses a trust boundary)?
  2. Reachability  — can execution actually reach this sink under realistic
                     inputs (entry point exists, dead-code free)?
  3. Validation    — is there upstream validation that already blocks
                     exploitation (allowlist, type coercion, length check)?
  4. APIContract   — does the API itself defend (parameterized query,
                     memcpy_s, html.EscapeString, prepared-statement wrapper)?
  5. Environment   — does runtime/compiler/OS mitigate (CSP, ASLR, stack
                     canaries, sandbox, framework auto-escape)?
  6. Impact        — is the consequence a real security impact (RCE, exfil,
                     privilege escalation, auth bypass) or merely robustness
                     (DoS via panic, log spam, crash-restart)?

Verdict rules (apply in this order):
  - Gate 3, 4, or 5 = FAIL ⇒ false_positive (upstream defense neutralizes it).
  - Gate 1 or 2 = FAIL ⇒ false_positive (no control / unreachable).
  - Gate 6 = FAIL and 1..5 = PASS ⇒ true_positive but defense_in_depth=true
    and severity must be downgraded to low (real bug, not security-impacting).
  - Every gate PASS (or PASS with some N/A) ⇒ true_positive.
  - Any gate left unevaluated / ambiguous ⇒ inconclusive (do NOT guess).

Devil's advocate — run these checks before deciding. Surface anything that
applies in the "devils_advocate" array (1 short bullet each):
  - Pattern bias: am I flagging this only because it "looks like" a known bug?
  - Trust assumption: did I assume an unverified caller is trusted?
  - Mathematical proof: did I verify bounds / sizes, not just glance at them?
  - Defense-in-depth vs primary control: is this a hardening miss, not a bug?
  - Hallucination: did I invent code / sanitizers that aren't in the snippet?
  - False-negative protection: would I be wrong to dismiss this?
  - Test scaffolding: is this dead code that never runs in production?

Rationalizations to REJECT (never use these as a reason to drop a finding):
  - "rapid analysis" / "skipping for efficiency"
  - "the pattern just looks dangerous"
  - "similar code was vulnerable elsewhere"
  - "this is clearly critical so I won't double-check"

Output ONE JSON object, no prose outside JSON:
{
  "verdict": "true_positive|false_positive|inconclusive",
  "comment": "1-3 sentences summarizing the gate outcome",
  "false_positive": true|false,
  "fp_reason": "short tag — e.g. 'sanitized', 'unreachable', 'test-code', 'no-impact', 'defense-in-depth'",
  "severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "suggested_fix": "optional concrete remediation hint",
  "defense_in_depth": true|false,
  "gates": {
    "control":            "pass|fail|n/a",
    "control_reason":     "...",
    "reachability":       "pass|fail|n/a",
    "reachability_reason":"...",
    "validation":         "pass|fail|n/a",
    "validation_reason":  "...",
    "api_contract":       "pass|fail|n/a",
    "api_contract_reason":"...",
    "environment":        "pass|fail|n/a",
    "environment_reason": "...",
    "impact":             "pass|fail|n/a",
    "impact_reason":      "..."
  },
  "devils_advocate": ["...","..."]
}

Backwards-compatible verdicts: "needs_more_context" is treated as
"inconclusive". Tests/examples/fixtures/mocks usually fail Gate 1 (Control)
or Gate 2 (Reachability) — record that explicitly instead of relying on path
heuristics alone.`

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
