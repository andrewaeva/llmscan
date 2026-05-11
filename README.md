# llmscan — LLM-based multi-agent SAST scanner (v3)

`llmscan` — это CI-ready SAST-сканер на Go, который использует иерархию LLM-агентов
(Orchestrator → Scanner DAG → Verifier → FP-filter) поверх классических
детерминированных приёмов: tree-sitter parsing, depgraph, taint, reachability,
regex+entropy для секретов, IaC-сканеры, baseline и diff-режим.

Главная цель v3 — **precision**: меньше шума, меньше токенов, воспроизводимый CI.

---

## Что нового в v3

| # | Фича | Где |
|---|------|-----|
| 1 | Per-language watchlist pre-filter (sources/sinks/sanitizers) | `internal/watchlist` |
| 2 | Structured output: JSON schema + retry feedback-loop | `internal/llm`, `CompleteJSON` |
| 3 | Confidence score `(0..1)` + `--min-score` | `types.Finding.Score` |
| 4 | Secrets pre-filter — 15 regex + Shannon entropy | `internal/secrets` |
| 5 | Embedding-кэш + RAG-чанки в sqlite (pure-Go) | `internal/cache` |
| 6 | Symbol-expansion (1–2 hop по depgraph) | `internal/symexpand` |
| 7 | Sanitizer-awareness словари + LLM-проверка | `internal/watchlist` + промпты |
| 8 | Reachability-фильтр (test/dead code → confidence=low, score≤0.4) | `internal/reach` |
| 9 | Taint tracking — Go/Python/JS/TS/Java, межфайл по depgraph | `internal/taint` |
| 10 | Self-consistency voting `--vote-n=N --vote-k=K` | `internal/voting` |
| 11 | Diff-режим (`--diff origin/main...HEAD`) + baseline (sqlite) | `internal/gitdiff`, `internal/baseline` |
| 12 | Suppression-комментарии: `// llmscan:ignore[rule] reason: ...` | `internal/suppress` |
| 13 | Persistent RAG-кэш (тот же sqlite) | `internal/cache` |
| 14 | Hierarchical map-reduce для файлов ≥ 2000 LOC | `internal/chunker` |
| 15 | IaC сканеры: Dockerfile, k8s, Terraform, GitHub Actions | `skills/iac-*`, `internal/iac` |
| 16 | `llmscan eval` — оффлайн-адаптеры датасетов (OWASP/SecurityEval/Juliet/Generic) | `internal/eval` |
| 17 | Расширенный CLI: 13 новых флагов, новая команда `eval` | `cmd/llmscan` |

Все v3 фичи включены по умолчанию, кроме voting (`--vote-n=0`).

---

## Установка

```bash
git clone https://github.com/andrewaeva/llmscan
cd llmscan
go build -o llmscan ./cmd/llmscan
./llmscan version
```

Требуется Go 1.24+. SQLite — pure-Go (`modernc.org/sqlite`), CGO не нужен для кэша.
Tree-sitter подключён без CGO (через `smacker/go-tree-sitter`).

### LLM-провайдеры и env-переменные

| Provider | Base URL env | Key env (в порядке приоритета) | Auth-заголовок |
|----------|--------------|---------------------------------|----------------|
| `openai` | `OPENAI_BASE_URL` (default `https://api.openai.com/v1`) | `spec.api_key_env` → `OPENAI_API_KEY` | `Authorization: Bearer ...` |
| `opencode` | `OPENCODE_BASE_URL`, `OPENAI_BASE_URL` | `OPENCODE_API_KEY` → `OPENAI_API_KEY` | `Authorization: Bearer ...` |
| `anthropic` (native) | `ANTHROPIC_BASE_URL` (default `https://api.anthropic.com`) | `ANTHROPIC_API_KEY` | `x-api-key` |
| `anthropic` (proxy) | `ANTHROPIC_BASE_URL` | `ANTHROPIC_AUTH_TOKEN` | `Authorization: Bearer ...` |

Дополнительно: `ANTHROPIC_VERSION` переопределяет заголовок `anthropic-version`
(default `2023-06-01`).

Если в YAML задан `agents.<agent>.model.api_key_env: ANTHROPIC_AUTH_TOKEN` —
клиент автоматически переключится в Bearer-режим (для OpenRouter / LiteLLM /
внутренних gateway-ев).

```bash
# Пример: Claude через прокси, совместимый с Anthropic Messages API.
export ANTHROPIC_BASE_URL=https://your-proxy.example.com
export ANTHROPIC_AUTH_TOKEN=sk-proxy-xyz
./llmscan scan ./code --provider anthropic --model claude-3-5-sonnet-latest
```

---

## Быстрый старт

```bash
export OPENAI_API_KEY=sk-...
./llmscan init                            # положит llmscan.yaml в текущий каталог
./llmscan scan ./path/to/code             # человекочитаемый отчёт
./llmscan scan ./code --format sarif -o report.sarif
./llmscan scan ./code --format json | jq '.findings[] | select(.score >= 0.7)'
```

CI/Harness:

```bash
./llmscan harness-step --image ghcr.io/andrewaeva/llmscan:latest --fail-on high > harness-step.yaml
./llmscan scan . --fail-on high           # exit 2 если есть high+
```

---

## Pipeline (DAG)

```
discover → parse-ast → depgraph
        ↓
  diff-filter (опционально)
        ↓
  watchlist pre-filter      ← skips files with zero source/sink hits
        ↓
  taint analysis            ← intra-file + cross-file via depgraph
        ↓
  symbol expansion          ← injects called function defs into context
        ↓
  secrets pre-filter        ← regex + entropy → deterministic findings
        ↓
  orchestrator              ← LLM plan (focus, priority, skip globs)
        ↓
  RAG (опционально)         ← sqlite-cached embeddings
        ↓
  ┌────────────────────────────────────────┐
  │ DAG layers (parallel):                 │
  │  [scan:auth scan:crypto scan:deser     │
  │   scan:generic scan:injection          │
  │   scan:secrets scan:ssrf + IaC]        │
  │  → scan_aggregate                      │
  │  → dedup                               │
  │  → verifier                            │
  │  → fp_filter                           │
  └────────────────────────────────────────┘
        ↓
  suppressions ← `// llmscan:ignore[rule]`
        ↓
  reachability downgrade
        ↓
  attach taint traces
        ↓
  score filter ← --min-score
        ↓
  baseline diff/write
        ↓
  report (text | json | sarif)
```

Все слои логируются с `--verbose`.

---

## CLI

### `scan`

| Флаг | Описание |
|------|----------|
| `--diff RANGE` | Сканировать только файлы, изменённые в git range (например `origin/main...HEAD`) |
| `--baseline PATH` | Скрыть finding'и, уже присутствующие в baseline.db |
| `--baseline-write PATH` | Перезаписать baseline текущим запуском |
| `--no-watchlist` | Отключить watchlist pre-filter |
| `--no-symexpand` | Отключить symbol expansion |
| `--no-taint` | Отключить taint |
| `--no-reachability` | Отключить downgrade в test/dead code |
| `--no-secrets-prefilter` | Отключить детерминированный секрет-сканер |
| `--min-score F` | Отбрасывать finding'и с score ниже порога |
| `--vote-n N --vote-k K` | Self-consistency: запустить сканеры N раз, оставить только finding'и, появившиеся в ≥ K прогонах |
| `--json-retries N` | Сколько раз ретраить при провале JSON-schema (default 2) |
| `--cache-path PATH` | Путь к sqlite-кэшу (default `.llmscan/cache.db`) |
| `--no-cache` | Полностью отключить кэш |

Старые флаги (`--model`, `--provider`, `--focus`, `--rag`, `--skills-dir`, `--fail-on` и т.д.) сохранены.

### `eval`

```bash
./llmscan eval \
  --adapter owasp-benchmark \
  --dataset-path ./datasets/BenchmarkJava/expectedresults-1.2.csv \
  --target ./datasets/BenchmarkJava/src/main/java
```

Поддерживаемые адаптеры (только локальные пути, без сетевых загрузок):

- `owasp-benchmark` — CSV `expectedresults-*.csv` из OWASP BenchmarkJava
- `securityeval`    — JSONL вида `{code, cwe, label}`
- `juliet`          — каталог Juliet Test Suite (CWE из имени файла)
- `generic`         — `labels.json`: `[{file, cwe, line}, ...]`

Выводит **precision / recall / F1**, общие и по CWE.

### `harness-step`

```bash
./llmscan harness-step --fail-on high --image ghcr.io/andrewaeva/llmscan:latest
```

Печатает YAML-шаг Harness CI/STO, который запускает контейнер с `llmscan`,
сохраняет SARIF и сам прокидывает severity-threshold для падения пайплайна.

---

## Конфигурация (`llmscan.yaml`)

```yaml
default_model:
  provider: openai
  model: gpt-4o-mini
  temperature: 0.1
  max_tokens: 4096

precision:
  pre_filter_watchlist: true   # files без sources/sinks пропускаются
  symbol_expansion:    true
  sym_expand_hops:     1
  sym_expand_max:      4
  taint:               true
  reachability:        true
  secrets_pre_filter:  true
  json_retries:        2
  vote_n:              0        # >=2 включает voting
  vote_k:              0        # default ceil(N/2)
  min_score:           0.0

cache:
  enabled: true
  path: .llmscan/cache.db

baseline:
  path: .llmscan/baseline.db
  write: false

diff:
  range: "origin/main...HEAD"
  include_rev_deps: false

agents:
  injection:       { enabled: true }
  secrets:         { enabled: true }
  auth:            { enabled: true }
  crypto:          { enabled: true }
  deserialization: { enabled: true }
  ssrf:            { enabled: true }
  generic:         { enabled: true }
  verifier:
    enabled: true
    model: { provider: anthropic, model: claude-3-5-sonnet-latest }
  fp_filter: { enabled: true }
```

`./llmscan init` положит файл со всеми комментариями.

---

## Suppression-комментарии

Подавлять отдельные finding'и можно прямо в коде:

```go
// llmscan:ignore[generic-password] reason: test fixture
password := "fake-test-password"
```

```python
password = "fake-test-password"  # llmscan:ignore[generic-password] reason: test fixture
```

Парсер ищет маркер **на той же строке или строкой выше** finding'а.
Подавление пишется в поле `suppressed: true` и `suppressed_reason` в JSON-отчёте.

Можно подавить **любой** rule:

```go
// llmscan:ignore reason: false positive — input is validated upstream
```

---

## Baseline и Diff

Типовой воркфлоу для существующего проекта:

```bash
# 1) Зафиксировать текущее состояние как baseline.
./llmscan scan . --baseline-write .llmscan/baseline.db

# 2) В CI: показать только новые finding'и относительно baseline.
./llmscan scan . --baseline .llmscan/baseline.db --fail-on high

# 3) Только изменения относительно main:
./llmscan scan . --diff "origin/main...HEAD" --baseline .llmscan/baseline.db
```

Fingerprint баззлайна = `sha256(rule_id|agent|file|normalized_code)[:16]`,
устойчив к whitespace и большинству реформатирований.

---

## IaC

Скиллы автоматически включаются при обнаружении соответствующих файлов:

- `iac-docker`     — `Dockerfile`, `Containerfile`, `docker-compose.yml`
- `iac-k8s`        — манифесты с `apiVersion:` и `kind:`
- `iac-terraform`  — `*.tf`, `*.tfvars`
- `iac-ghactions`  — `.github/workflows/*.yml`

Каждый скилл — `SKILL.md` с YAML-фронтматтером и подробным промптом для LLM.
Watchlist pre-filter **никогда** не отбрасывает IaC-файлы.

---

## Self-consistency voting

Полезно для критичных репозиториев — снижает вариативность LLM:

```bash
./llmscan scan . --vote-n 3 --vote-k 2 --min-score 0.6
```

Каждый scanner-агент запускается 3 раза с разным seed/температурой,
finding'и кластеризуются по ключу `rule_id|agent|file|line/5` и
сохраняются только те, что появились в ≥ 2 прогонах.

Поля `vote_count` и `vote_total` пишутся в JSON-отчёт.

---

## Sqlite cache (pure-Go)

`.llmscan/cache.db` хранит:

- `embeddings(key, provider, model, dim, vec)` — закэшированные эмбеддинги для RAG (SHA256 от чанка)
- `rag_chunks(...)` — текст чанков и метаданные
- `baseline(fingerprint, finding_json, created_at)` — known findings

Cache shared между запусками, отключается через `--no-cache`.
Используется `modernc.org/sqlite` — pure-Go, без CGO/системного sqlite.

---

## Output schema (JSON)

```json
{
  "id": "...",
  "rule_id": "sql-injection",
  "title": "SQL Injection",
  "severity": "high",
  "confidence": "high",
  "cwe": "CWE-89",
  "file": "app/handlers.go",
  "start_line": 42,
  "end_line": 45,
  "agent": "scan:injection",
  "verified": true,
  "false_positive": false,
  "fp_reason": "",
  "score": 0.92,
  "tags": ["taint", "verified"],
  "trace": [
    {"file": "app/handlers.go", "line": 30, "kind": "source", "code": "r.URL.Query().Get(\"id\")"},
    {"file": "app/db.go",       "line": 14, "kind": "sink",   "code": "db.Exec(query)"}
  ],
  "suppressed": false,
  "vote_count": 3,
  "vote_total": 3
}
```

---

## Eval-результаты

После `llmscan eval` (формат `text`):

```
=== llmscan evaluation ===
overall:    tp=128  fp=22  fn=18   precision=0.853   recall=0.877   f1=0.865

by CWE:
  CWE-89   tp=42 fp=6  fn=4   P=0.875  R=0.913  F1=0.894
  CWE-78   tp=21 fp=3  fn=2   P=0.875  R=0.913  F1=0.894
  CWE-22   tp=18 fp=4  fn=3   P=0.818  R=0.857  F1=0.837
  ...
```

(Числа из примера. Реальные зависят от датасета и модели.)

---

## Архитектура (директории)

```
cmd/llmscan/           CLI
internal/
  ast/                 tree-sitter wrappers (Go/Python/JS/TS/Java)
  baseline/            sqlite-baseline fingerprints
  cache/               sqlite cache (embeddings, RAG, baseline)
  chunker/             sliding window + hierarchical map-reduce
  config/              YAML + defaults + per-agent overrides
  depgraph/            import/call graph
  eval/                dataset adapters + precision/recall/F1
  gitdiff/             `git diff --name-only`
  harness/             Harness CI/STO step generator
  iac/                 IaC file detection
  llm/                 OpenAI / Anthropic + structured JSON + retry
  pipeline/            DAG orchestrator
  reach/               reachability downgrade
  report/              text / json / sarif writers
  secrets/             15 regex + Shannon entropy
  suppress/            inline ignore-markers
  symexpand/           cross-function context expansion
  taint/               source → sanitizer → sink chains (5 langs)
  types/               Finding, Report, TraceHop
  voting/              N-of-K consensus
  watchlist/           per-language sources/sinks/sanitizers
skills/                LLM agent prompts (markdown с YAML-фронтматтером)
examples/vuln_samples/ smoke-targets
```

---

## Smoke-test

```bash
go build -o llmscan ./cmd/llmscan
OPENAI_API_KEY=sk-fake ./llmscan scan ./examples/vuln_samples --verbose
```

Ожидаемые логи:

```
discovered N files
parsed AST for N files
watchlist pre-filter: N -> M files
taint: M files analyzed
secrets pre-filter: K deterministic findings
DAG layers: [[scan:auth scan:crypto scan:deserialization scan:generic scan:injection scan:secrets scan:ssrf] [scan_aggregate] [dedup] [verifier] [fp_filter]]
reachability: downgraded X findings
```

401-ошибки от OpenAI с `sk-fake` ожидаемы — важна структура DAG и работа детерминированных слоёв.

---

## Лицензия

MIT.
