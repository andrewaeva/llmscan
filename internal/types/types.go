// Package types contains shared data structures used across the scanner.
package types

import "time"

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
	Verified         bool   `json:"verified"`
	VerifierVerdict  string `json:"verifier_verdict,omitempty"`
	VerifierComment  string `json:"verifier_comment,omitempty"`
	VerifierModel    string `json:"verifier_model,omitempty"`
	FalsePositive    bool   `json:"false_positive"`
	FPReason         string `json:"fp_reason,omitempty"`
	SuggestedFix     string `json:"suggested_fix,omitempty"`
	References       []string `json:"references,omitempty"`

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

	CreatedAt time.Time `json:"created_at"`
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
	Reasoning  string   `json:"reasoning"`
	Priority   []string `json:"priority"`    // ordered file paths
	Focus      []string `json:"focus"`       // suspected vulnerability classes
	SkipGlobs  []string `json:"skip_globs"`  // patterns to skip (tests, vendor, ...)
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
