# llmscan

LLM-based multi-agent SAST scanner на Go. Иерархия агентов
(Orchestrator → Scanner DAG → Verifier → FP-filter) поверх детерминированных
слоёв: tree-sitter, depgraph, taint, reachability, regex+entropy для секретов,
IaC-сканеры, baseline и diff-режим.

Цель — **precision**: меньше шума, меньше токенов, воспроизводимый CI.

## Установка

```bash
# Docker (рекомендуется)
docker run --rm -e ANTHROPIC_API_KEY -v "$PWD:/work" \
  ghcr.io/andrewaeva/llmscan:latest scan /work --fail-on high

# go install
go install github.com/andrewaeva/llmscan/cmd/llmscan@latest

# Из исходников (Go 1.24+, без CGO)
git clone https://github.com/andrewaeva/llmscan && cd llmscan
go build -o llmscan ./cmd/llmscan
```

Готовые бинари (linux/macOS/windows × amd64/arm64) — на
[Releases](https://github.com/andrewaeva/llmscan/releases).

## LLM-провайдеры

| Provider | Base URL env | Key env | Auth |
|---|---|---|---|
| `openai` | `OPENAI_BASE_URL` | `OPENAI_API_KEY` | `Bearer` |
| `anthropic` (native) | `ANTHROPIC_BASE_URL` | `ANTHROPIC_API_KEY` | `x-api-key` |
| `anthropic` (proxy) | `ANTHROPIC_BASE_URL` | `ANTHROPIC_AUTH_TOKEN` | `Bearer` |

Для reasoning-моделей (`gpt-5*`, `o1/o3/o4`) клиент автоматически использует
`max_completion_tokens` и опускает `temperature`.

## Быстрый старт

```bash
./llmscan init                            # llmscan.yaml
./llmscan scan ./code                     # human-readable
./llmscan scan ./code --format sarif -o report.sarif
./llmscan scan ./code --fail-on high      # exit 2 если есть high+
./llmscan scan . --diff origin/main...HEAD --deep   # PR-ревью
```

## Pipeline

```
discover → parse-ast → depgraph → diff-filter → watchlist →
taint → symexpand → secrets-prefilter → orchestrator → RAG →
[scanners ∥ + IaC] → dedup → verifier → fp_filter →
suppress → reachability → deep (optional) → score-filter →
baseline → report (text|json|sarif)
```

## Ключевые флаги

| Флаг | Назначение |
|---|---|
| `--diff RANGE` | сканировать только diff (git/arc, см. ниже) |
| `--baseline / --baseline-write PATH` | подавление известных findings |
| `--min-score F`, `--fail-on LEVEL` | пороги для CI |
| `--vote-n N --vote-k K` | self-consistency (N прогонов, оставить ≥K) |
| `--fast` | отключает orchestrator/verifier/fp_filter |
| `--deep` | sub-agent верификация high+ через read-only tools |
| `--scope-root DIR` (repeat), `--max-files N` | подграфы монорепо |
| `--no-{watchlist,symexpand,taint,reachability,secrets-prefilter,cache,ast-cache}` | выключить слои |
| `--agent-parallel N`, `--concurrency N` | параллелизм |

Полный список — `./llmscan scan --help`.

## Deep mode

`--deep` запускает sub-agent (Anthropic или OpenAI Responses API / Chat
Completions fallback) на findings уровня `--deep-severity` (default `high`).
Read-only tools: `read_file`, `grep`, `list_dir`, `blame` — все sandbox'нуты
через `filepath.Rel` + `EvalSymlinks` в корне скана. Лимит вызовов на
hotspot — `--deep-budget` (default 40), кеш в `.llmscan/cache.db`.

Verdict через six gates (Trail of Bits fp-check): control, reachability,
validation, api, environment, impact. Если провален только impact —
`defense_in_depth=true`, severity → low.

```bash
./llmscan scan . --deep --verbose
./llmscan scan . --deep --deep-severity critical --deep-budget 60
```

## Monorepo (git / Yandex Arc)

Корень определяется по `.git/` или `.arc/`; VCS-бэкенд автоматический.

```bash
./llmscan scan ./apps/payments --diff origin/main...HEAD          # git
./llmscan scan . --diff arc:trunk..HEAD                            # arc
./llmscan scan . --scope-root apps/payments --scope-root libs/auth # подграф
```

AST-кеш sqlite (`.llmscan/ast-cache.db`) включён по умолчанию.

## Skills (scanner agents)

Каждый — `skills/<name>/SKILL.md` с YAML-фронтматтером и промптом;
подгружаются динамически.

**Code:** `injection`, `secrets`, `auth`, `crypto`, `deserialization`, `ssrf`,
`generic`, `insecure-defaults`, `race-conditions`, `error-handling`,
`supply-chain`, `memory-safety`.

**IaC** (auto-enabled по filetype): `iac-docker`, `iac-k8s`, `iac-terraform`,
`iac-ghactions`.

Промпты ряда скиллов и FP-методология заимствуют идеи из
[Trail of Bits Skills](https://github.com/trailofbits/skills) (MIT) — см.
`NOTICE.md`.

## Suppression

```go
// llmscan:ignore[generic-password] reason: test fixture
password := "fake-test-password"
```

Маркер ищется на той же строке или строкой выше. `// llmscan:ignore` без
rule-id подавляет любой rule.

## Baseline / Diff

```bash
./llmscan scan . --baseline-write .llmscan/baseline.db
./llmscan scan . --baseline .llmscan/baseline.db --fail-on high
```

Fingerprint = `sha256(rule_id|agent|file|normalized_code)[:16]`.

## Eval

```bash
./llmscan eval --adapter owasp-benchmark \
  --dataset-path ./expectedresults-1.2.csv --target ./src
```

Адаптеры: `owasp-benchmark`, `securityeval`, `juliet`, `generic`. Выводит
precision / recall / F1 общие и по CWE.

## Конфиг

`llmscan.yaml` (`./llmscan init` создаст пример) переопределяет дефолты:
`default_model`, `precision.*` (watchlist/taint/reach/voting/min_score),
`cache`, `baseline`, `diff`, `agents.<name>`, `deep`. CLI-флаги имеют приоритет.

## JSON-схема находки (сокращённо)

```json
{
  "rule_id": "sql-injection", "severity": "high", "confidence": "high",
  "cwe": "CWE-89", "file": "app/handlers.go", "start_line": 42,
  "agent": "scan:injection", "verified": true, "false_positive": false,
  "score": 0.92, "tags": ["taint", "verified"],
  "trace": [{"file":"...","line":30,"kind":"source"},
            {"file":"...","line":14,"kind":"sink"}],
  "gates": {"control":"pass","validation":"fail","impact":"pass"}
}
```

## Development

```bash
make lint test
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
pre-commit install
```

## Лицензия

MIT — см. [`LICENSE`](LICENSE).
