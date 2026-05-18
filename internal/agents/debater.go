// debater.go implements a two-agent debate / cross-examination wrapper
// for high-stakes findings (typically the --deep verification path).
//
// Single-pass verification is sensitive to confirmation bias: once a model
// commits to a verdict it tends to defend it. We mitigate this with a
// devil's-advocate setup using the SAME model run with a different
// temperature/seed:
//
//  1. Proponent (round 0): given the finding and any prior context, argue
//     whether the finding is a TRUE POSITIVE. Returns verdict + rationale.
//  2. Opponent (round 0): the same prompt but instructed to argue the
//     OPPOSITE verdict to whatever the proponent emitted.
//  3. If they agree → consensus, return the verdict with the joined
//     rationale.
//  4. If they disagree, run round 1: each side sees the other's argument
//     and is allowed to either concede or sharpen their case. After
//     MaxRounds (default 2) without consensus we return DebateResult with
//     Verdict="split" and a confidence penalty.
//
// The debater is intentionally model-agnostic; the only requirement is that
// the same llm.Client implements Complete. We expose TemperatureOverride
// so callers can run the two roles with distinct seeds.
package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/andrewaeva/llmscan/internal/llm"
	"github.com/andrewaeva/llmscan/internal/types"
)

// Debater orchestrates a proponent/opponent debate over a single finding.
type Debater struct {
	Client    llm.Client
	MaxRounds int
	// ProponentTemp / OpponentTemp let callers split the two roles by
	// sampling temperature. Both default to 0.4 if zero.
	ProponentTemp float64
	OpponentTemp  float64
	// PromptOverride replaces debaterSystem when set.
	PromptOverride string
	Verbose        bool
	Logf           func(format string, args ...any)
}

// DebateResult is the outcome of a debate over one finding.
type DebateResult struct {
	// Verdict is one of "tp" (true positive), "fp" (false positive),
	// "inconclusive", or "split" (no consensus after MaxRounds).
	Verdict string
	// Rationale is a short joined explanation from both sides.
	Rationale string
	// Rounds counts how many full proponent+opponent exchanges occurred.
	Rounds int
	// SplitPenalty is a multiplier in (0,1] applied to the finding's score
	// when verdict is "split". 1.0 = no penalty.
	SplitPenalty float64
}

func (d *Debater) logf(format string, args ...any) {
	if !d.Verbose || d.Logf == nil {
		return
	}
	d.Logf(format, args...)
}

type debateTurn struct {
	Verdict   string `json:"verdict"`
	Rationale string `json:"rationale"`
	// Concede is true when the speaker accepts the other side's position
	// after seeing their argument. Only meaningful in rounds >= 1.
	Concede bool `json:"concede,omitempty"`
}

// Debate runs the proponent/opponent loop over the given finding and returns
// the consensus verdict. On any LLM/decode error it returns
// Verdict="inconclusive" without touching the finding — the caller decides
// what to do.
func (d *Debater) Debate(ctx context.Context, f types.Finding, priorContext string) DebateResult {
	if d == nil || d.Client == nil {
		return DebateResult{Verdict: "inconclusive", SplitPenalty: 1.0}
	}
	maxR := d.MaxRounds
	if maxR <= 0 {
		maxR = 2
	}
	propTemp := d.ProponentTemp
	if propTemp == 0 {
		propTemp = 0.4
	}
	oppTemp := d.OpponentTemp
	if oppTemp == 0 {
		oppTemp = 0.4
	}

	transcript := strings.Builder{}
	var lastProp, lastOpp debateTurn

	for round := 0; round < maxR; round++ {
		// Proponent turn.
		prop, err := d.turn(ctx, f, priorContext, transcript.String(), "proponent", round, propTemp)
		if err != nil {
			d.logf("debate[%s:%d] proponent err round=%d: %v", f.File, f.StartLine, round, err)
			return DebateResult{Verdict: "inconclusive", SplitPenalty: 1.0, Rounds: round}
		}
		lastProp = prop
		fmt.Fprintf(&transcript, "[round %d / proponent] verdict=%s | %s\n", round, prop.Verdict, oneLine(prop.Rationale))

		// Opponent turn — must argue the opposite verdict unless conceding.
		opp, err := d.turn(ctx, f, priorContext, transcript.String(), "opponent", round, oppTemp)
		if err != nil {
			d.logf("debate[%s:%d] opponent err round=%d: %v", f.File, f.StartLine, round, err)
			return DebateResult{Verdict: "inconclusive", SplitPenalty: 1.0, Rounds: round}
		}
		lastOpp = opp
		fmt.Fprintf(&transcript, "[round %d / opponent ] verdict=%s | %s\n", round, opp.Verdict, oneLine(opp.Rationale))

		d.logf("debate[%s:%d] round=%d prop=%s opp=%s concede(p=%v,o=%v)",
			f.File, f.StartLine, round, prop.Verdict, opp.Verdict, prop.Concede, opp.Concede)

		// Consensus reached?
		if v, ok := consensus(prop, opp); ok {
			return DebateResult{
				Verdict:      v,
				Rationale:    joinRationales(prop.Rationale, opp.Rationale),
				Rounds:       round + 1,
				SplitPenalty: 1.0,
			}
		}
	}
	// No consensus → split.
	return DebateResult{
		Verdict:      "split",
		Rationale:    "split: " + joinRationales(lastProp.Rationale, lastOpp.Rationale),
		Rounds:       maxR,
		SplitPenalty: 0.7,
	}
}

func consensus(prop, opp debateTurn) (string, bool) {
	pv := normVerdict(prop.Verdict)
	ov := normVerdict(opp.Verdict)
	if pv == "" || ov == "" {
		return "", false
	}
	// Either side conceding counts as consensus on the OTHER side's verdict.
	if prop.Concede {
		return ov, true
	}
	if opp.Concede {
		return pv, true
	}
	if pv == ov {
		return pv, true
	}
	return "", false
}

func normVerdict(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "tp", "true_positive", "true-positive", "true positive", "confirmed":
		return "tp"
	case "fp", "false_positive", "false-positive", "false positive", "refuted":
		return "fp"
	case "inconclusive", "unknown", "needs_more_context":
		return "inconclusive"
	}
	return ""
}

func joinRationales(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch {
	case a == "" && b == "":
		return ""
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + " | " + b
}

func (d *Debater) turn(ctx context.Context, f types.Finding, priorContext, transcript, role string, round int, temp float64) (debateTurn, error) {
	system := d.PromptOverride
	if system == "" {
		system = debaterSystem
	}
	user := buildDebateUser(f, priorContext, transcript, role, round)
	tempPtr := temp
	resp, err := d.Client.Complete(ctx, llm.Request{
		System:              system,
		Messages:            []llm.Message{{Role: "user", Content: user}},
		JSON:                true,
		TemperatureOverride: &tempPtr,
	})
	if err != nil {
		return debateTurn{}, err
	}
	var t debateTurn
	if err := json.Unmarshal([]byte(llm.ExtractJSON(resp.Text)), &t); err != nil {
		return debateTurn{}, fmt.Errorf("debate %s: decode: %w; raw=%q", role, err, truncate(resp.Text, 200))
	}
	return t, nil
}

func buildDebateUser(f types.Finding, priorContext, transcript, role string, round int) string {
	var prior string
	if pc := strings.TrimSpace(priorContext); pc != "" {
		prior = "\nPrior verification context:\n" + pc + "\n"
	}
	var trans string
	if t := strings.TrimSpace(transcript); t != "" {
		trans = "\nDebate transcript so far:\n" + t + "\n"
	}
	var roleInstr string
	switch role {
	case "proponent":
		if round == 0 {
			roleInstr = "You are the PROPONENT. Argue whether this finding is a TRUE POSITIVE. Pick your honest verdict."
		} else {
			roleInstr = "You are the PROPONENT. The opponent challenged your previous position. Either sharpen your argument or concede if their reasoning is stronger."
		}
	case "opponent":
		roleInstr = "You are the OPPONENT / devil's advocate. Challenge the proponent's verdict. If you genuinely agree after considering their argument, set concede=true."
	default:
		roleInstr = "Evaluate the finding."
	}
	return fmt.Sprintf(`%s

Finding under review:
  rule_id:     %s
  title:       %s
  severity:    %s
  confidence:  %s
  file:        %s:%d-%d
  agent:       %s
  description: %s
  code_sample:
%s
%s%s
Output JSON only:
{
  "verdict":   "tp|fp|inconclusive",
  "rationale": "ONE concise sentence with the strongest reason for your verdict",
  "concede":   false
}`,
		roleInstr,
		f.RuleID, f.Title, f.Severity, f.Confidence,
		f.File, f.StartLine, f.EndLine, f.Agent,
		oneLine(f.Description),
		indent(f.CodeSample, "    "),
		prior, trans)
}

func indent(s, prefix string) string {
	if s == "" {
		return "    (no sample)"
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = prefix + ln
	}
	return strings.Join(lines, "\n")
}

const debaterSystem = `You are a senior application security reviewer participating in an
adversarial cross-examination of one scanner finding. You take a role —
PROPONENT (argue true-positive) or OPPONENT (devil's advocate) — and
defend it with concrete code-level reasoning.

Rules:
  - One sentence rationale. No filler.
  - Anchor your claim in the code sample. If the sample is insufficient,
    say so and return verdict="inconclusive".
  - When the OTHER side's argument decisively wins, set concede=true and
    return THEIR verdict.
  - Never invent code that isn't shown.
  - Output strictly a single JSON object with keys: verdict, rationale,
    concede. No prose around it.`
