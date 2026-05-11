// Package types contains shared data structures used across the scanner.
package types

import "time"

// Gate is the status of one of the six Trail-of-Bits fp-check gates.
//
// Each gate either supports the vulnerability (Pass), refutes it (Fail), or
// could not be evaluated (NotApp / Unknown). The Verifier and DeepAgent both
// emit a GateReview that is consumed by applyGates to derive the final
// verdict on the candidate finding.
type Gate string

const (
	GatePass    Gate = "pass" // gate supports the vulnerability
	GateFail    Gate = "fail" // gate refutes / blocks the vulnerability
	GateNotApp  Gate = "n/a"  // gate not applicable to this finding
	GateUnknown Gate = ""     // gate not evaluated (default)
)

// GateReview captures the six fp-check gates plus a short rationale per gate.
//
// Methodology adapted from Trail of Bits fp-check
// (https://trailofbits-skills.mintlify.app/plugins/fp-check, MIT):
//
//  1. Control       — attacker actually controls the source?
//  2. Reachability  — is the path to the sink reachable?
//  3. Validation    — does upstream validation block exploitation?
//  4. APIContract   — does the API itself protect (prepared stmt, memcpy_s, ...)?
//  5. Environment   — does runtime/compiler/OS mitigate (CSP, ASLR, sandbox, ...)?
//  6. Impact        — is there a real security impact, or is it robustness only?
type GateReview struct {
	Control      Gate `json:"control,omitempty"`
	Reachability Gate `json:"reachability,omitempty"`
	Validation   Gate `json:"validation,omitempty"`
	APIContract  Gate `json:"api_contract,omitempty"`
	Environment  Gate `json:"environment,omitempty"`
	Impact       Gate `json:"impact,omitempty"`

	ControlReason      string `json:"control_reason,omitempty"`
	ReachabilityReason string `json:"reachability_reason,omitempty"`
	ValidationReason   string `json:"validation_reason,omitempty"`
	APIContractReason  string `json:"api_contract_reason,omitempty"`
	EnvironmentReason  string `json:"environment_reason,omitempty"`
	ImpactReason       string `json:"impact_reason,omitempty"`

	// DevilsAdvocate captures the bias-checking questions the agent asked
	// itself before issuing the verdict (e.g. "pattern bias?", "trust
	// assumption?"). Empty when not provided.
	DevilsAdvocate []string `json:"devils_advocate,omitempty"`
}

// Severity of a finding.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Confidence reported by the agent.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// Finding describes a potential vulnerability emitted by a scanner agent.
type Finding struct {
	ID          string     `json:"id"`
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	CWE         string     `json:"cwe,omitempty"`
	OWASP       string     `json:"owasp,omitempty"`

	File       string `json:"file"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	CodeSample string `json:"code_sample,omitempty"`

	// Agent that produced the finding (e.g. "injection", "secrets", "auth").
	Agent string `json:"agent"`

	// Verification metadata. Populated by the Verifier agent.
	Verified        bool     `json:"verified"`
	VerifierVerdict string   `json:"verifier_verdict,omitempty"`
	VerifierComment string   `json:"verifier_comment,omitempty"`
	VerifierModel   string   `json:"verifier_model,omitempty"`
	FalsePositive   bool     `json:"false_positive"`
	FPReason        string   `json:"fp_reason,omitempty"`
	SuggestedFix    string   `json:"suggested_fix,omitempty"`
	References      []string `json:"references,omitempty"`

	// Numeric confidence in [0,1] (preferred over Confidence enum when present).
	Score float64 `json:"score,omitempty"`

	// Taint trace: ordered hops source -> ... -> sink (file:line entries).
	Trace []TraceHop `json:"trace,omitempty"`

	// Tags: compliance/category tags (OWASP, CWE, MITRE, IaC, etc.).
	Tags []string `json:"tags,omitempty"`

	// Sanitizer applied between source and sink (if detected).
	Sanitizer string `json:"sanitizer,omitempty"`

	// Suppressed via in-source comment.
	Suppressed       bool   `json:"suppressed,omitempty"`
	SuppressedReason string `json:"suppressed_reason,omitempty"`

	// Voting metadata when --vote-n>1.
	VoteCount int `json:"vote_count,omitempty"`
	VoteTotal int `json:"vote_total,omitempty"`

	// DeepVerified is true when a sub-agent (--deep) confirmed or refuted this
	// finding via tool-driven inspection of the codebase.
	DeepVerified bool           `json:"deep_verified,omitempty"`
	DeepVerdict  string         `json:"deep_verdict,omitempty"` // confirmed | refuted | inconclusive
	DeepComment  string         `json:"deep_comment,omitempty"`
	DeepModel    string         `json:"deep_model,omitempty"`
	DeepTrace    []DeepToolCall `json:"deep_trace,omitempty"`

	// Gates is the optional fp-check six-gate review attached by Verifier and
	// DeepAgent. Backwards compatible: when nil it is omitted from JSON.
	Gates *GateReview `json:"gates,omitempty"`

	// DefenseInDepth marks a finding whose only failed gate is Impact (Gate 6):
	// the issue is real but lacks a primary security impact, so it is reported
	// as a defense-in-depth concern rather than dropped as FP.
	DefenseInDepth bool `json:"defense_in_depth,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// DeepToolCall is one step of a sub-agent's investigation (one tool invocation
// and its result, truncated for the trace).
type DeepToolCall struct {
	Step   int    `json:"step"`
	Tool   string `json:"tool"`
	Args   string `json:"args"`             // compact JSON
	Result string `json:"result,omitempty"` // truncated to ~512 chars
	Error  string `json:"error,omitempty"`
	Ms     int64  `json:"ms"`
}

// TraceHop is one hop in a taint trace.
type TraceHop struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Kind string `json:"kind"` // source | propagator | sanitizer | sink
	Code string `json:"code,omitempty"`
}

// FileTarget represents a file (or chunk) ready to be analyzed.
type FileTarget struct {
	Path     string
	Language string
	Content  string
	Lines    int
	// Optional: chunk index when a file is split into multiple chunks.
	ChunkIdx   int
	ChunkTotal int
	// Line offset of the chunk inside the original file.
	LineOffset int
}

// ScanPlan is produced by the Orchestrator.
type ScanPlan struct {
	Reasoning  string              `json:"reasoning"`
	Priority   []string            `json:"priority"`              // ordered file paths
	Focus      []string            `json:"focus"`                 // suspected vulnerability classes
	SkipGlobs  []string            `json:"skip_globs"`            // patterns to skip (tests, vendor, ...)
	AgentHints map[string][]string `json:"agent_hints,omitempty"` // agent -> file paths
}

// Report aggregates all findings of a scan.
type Report struct {
	Target       string    `json:"target"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	FilesScanned int       `json:"files_scanned"`
	Plan         ScanPlan  `json:"plan"`
	Findings     []Finding `json:"findings"`
	Stats        Stats     `json:"stats"`
}

// Stats keeps high-level numbers for the final report.
type Stats struct {
	Raw         int            `json:"raw_findings"`
	AfterDedup  int            `json:"after_dedup"`
	AfterVerify int            `json:"after_verify"`
	FalsePos    int            `json:"false_positives"`
	BySeverity  map[string]int `json:"by_severity"`
	ByAgent     map[string]int `json:"by_agent"`
	TokensIn    int            `json:"tokens_in,omitempty"`
	TokensOut   int            `json:"tokens_out,omitempty"`
}
