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
- general taint / FP-check methodology — `plugins/static-analysis`, `plugins/fp-check`, `plugins/variant-analysis`

No code or prompt text was copied verbatim; the influence is methodological
(scope rules, FP guardrails, calibration). Trail of Bits' MIT license terms
are preserved in the upstream repository.
