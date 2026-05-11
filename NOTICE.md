# Third-Party Notices

`llmscan` borrows ideas and prompt patterns from open-source projects. This
file lists those sources and their licenses.

## Trail of Bits — Skills collection

Several scanner prompts in `skills/*/SKILL.md` are inspired by Trail of Bits'
public Skills collection: https://github.com/trailofbits/skills (MIT License).

Inspired-by examples include:

- `skills/insecure-defaults/`   — `plugins/insecure-defaults`
- `skills/supply-chain/`        — `plugins/supply-chain-risk-auditor`
- `skills/iac-ghactions/`       — `plugins/agentic-actions-auditor`
- `skills/crypto/`              — `plugins/constant-time-analysis`, `plugins/zeroize-audit`
- `skills/_fpcheck-verifier/`   — `plugins/fp-check` (six-gate methodology, standard path)
- `skills/_fpcheck-deep/`       — `plugins/fp-check` (six-gate methodology, deep path with tools)
- general taint / FP-check methodology — `plugins/static-analysis`, `plugins/fp-check`, `plugins/variant-analysis`

The fp-check methodology (six independent gates: Control / Reachability /
Validation / APIContract / Environment / Impact) is implemented in
`internal/types/gates.go` and exercised by both `Verifier` (standard path) and
`DeepAgent` (deep path). The verdict rules — defense-side gates fail ⇒ FP,
control/reachability fail ⇒ FP, impact-only fail ⇒ defense-in-depth, all-pass
⇒ TP — are taken directly from the Trail of Bits formulation. Reference:
https://trailofbits-skills.mintlify.app/plugins/fp-check.

No code or prompt text was copied verbatim; the influence is methodological
(scope rules, FP guardrails, calibration). Trail of Bits' MIT license terms
are preserved in the upstream repository.
