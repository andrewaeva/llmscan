// Package agents implements the multi-agent hierarchy:
//
//	Orchestrator -> Scanner agents (per vulnerability class) -> Verifier -> FP Filter.
//
// Every agent is just an LLM call with a focused prompt and strict JSON output.
//
// This file only declares package-level data shared across agents. Each agent
// lives in its own file (orchestrator.go, scanner.go, verifier.go, fpfilter.go).
package agents

// ScannerNames is the canonical, ordered list of specialized scanner agents.
var ScannerNames = []string{
	"injection", "secrets", "auth", "crypto", "deserialization", "ssrf", "generic",
}
