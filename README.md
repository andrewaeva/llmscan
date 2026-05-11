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
| 18 | Цветной консольный отчёт (severity-бейджи, `--color auto/always/never`) | `internal/report` |
| 19 | Параллелизм: `--agent-parallel`, per-chunk `--concurrency` + progress-логи | `internal/pipeline` |
| 20 | Speed knobs: `--fast`, `--no-orchestrator`, `--no-verifier`, `--no-fp-filter` | `cmd/llmscan` |
| 21 | One-shot endpoint-лог (`provider model base_url`) при старте LLM-клиента | `internal/llm` |
| 22 | **`--deep`**: sub-agent верификация high+ находок с тулами read_file/grep/list_dir/git_blame | `internal/agents/deepscanner.go`, `internal/tools`, `internal/llm/anthropic_tools.go` |

Все v3 фичи включены по умолчанию, кроме voting (`--vote-n=0`) и `--deep`.

---

## Установка

### Docker (рекомендуется)

```bash
# Последний релиз с GHCR.
docker run --rm -v "$PWD:/work" ghcr.io/andrewaeva/llmscan:latest scan /work

# С API-ключом для LLM-провайдера.
docker run --rm \
  -e ANTHROPIC_API_KEY \
  -v "$PWD:/work" \
  ghcr.io/andrewaeva/llmscan:latest scan /work --fail-on high
```

Образ — distroless (`gcr.io/distroless/static-debian12:nonroot`), <30 MB,
содержит бинарь и встроенные `skills/`.

### Предкомпилированные бинари

Скачайте архив для своей платформы со страницы
[Releases](https://github.com/andrewaeva/llmscan/releases) — там лежат сборки
для linux/macOS/windows на amd64/arm64 вместе с `skills/` и `checksums.txt`.

### `go install`

```bash
go install github.com/andrewaeva/llmscan/cmd/llmscan@latest
```

### Homebrew

```bash
# placeholder — tap появится с первым релизом
# brew install andrewaeva/tap/llmscan
```

### Из исходников

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
./llmscan scan ./code --provider anthropic --model claude-sonnet-4-6
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
  deep pass (опционально, --deep) ← sub-agent верификация high+
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
| `--agent-parallel N` | Сколько scanner-агентов запускать параллельно (default 8) |
| `--concurrency N` | Параллелизм внутри одного агента — чанки на файл (default 16) |
| `--fast` | Скоростной пресет: отключает orchestrator/verifier/fp_filter |
| `--no-orchestrator` | Пропустить LLM-планировщик |
| `--no-verifier` | Пропустить verifier-агент |
| `--no-fp-filter` | Пропустить fp_filter |
| `--color MODE` | `auto` (default) / `always` / `never` для текстового отчёта |
| `--deep` | Включить sub-agent верификацию high+ находок (см. ниже) |
| `--deep-severity LEVEL` | Минимальная severity для deep-пасса (default `high`) |
| `--deep-max-hotspots N` | Максимум hotspot'ов на запуск (default 20) |
| `--deep-budget N` | Лимит tool-вызовов на hotspot (default 40) |
| `--deep-concurrency N` | Параллельных deep-агентов (default 4) |
| `--deep-model NAME` | Переопределить модель deep-агента |
| `--deep-provider NAME` | Переопределить провайдера (поддерживается только `anthropic`) |
| `--deep-no-cache` | Отключить sqlite-кеш tool-вызовов (включён по умолчанию) |

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

## Deep mode (`--deep`)

Опциональный sub-agent пасс: после основной пайплайны Anthropic-агент берёт
находки уровня `--deep-severity` и выше (default `high`), сортирует по
severity и для каждой запускает tool-loop:

- `read_file(path, start, end)` — чтение фрагмента файла
- `grep(pattern, glob, max)` — поиск по проекту
- `list_dir(path)` — листинг каталога
- `git_blame(path, line)` — автор/коммит для строки

Все тулы read-only, sandbox запирает доступ внутри корня скана через
`filepath.Rel` + `EvalSymlinks` (защита от path traversal и symlink-escape).
Output тулов обрезается (≤32 KiB, ≤500 строк, ≤100 grep-матчей, ≤200 dir-записей).
Лимит tool-вызовов на hotspot — `--deep-budget` (default 40).

Агент возвращает в финальном сообщении JSON-блок с verdict'ом и шестью fp-check
gates (см. секцию «False-positive verification» ниже):

```json
{
  "verdict": "confirmed|refuted|inconclusive",
  "reason": "...",
  "fix": "...",
  "defense_in_depth": false,
  "gates": {"control":"pass","reachability":"pass","validation":"fail","...":"..."},
  "devils_advocate": ["pattern bias? no", "..."]
}
```

- `refuted` → `Finding.FalsePositive = true` (отсев в fp_filter)
- `confirmed` / `inconclusive` → остаются с полями `DeepVerified`, `DeepVerdict`,
  `DeepComment`, `DeepModel`, `DeepTrace` (все tool-вызовы со step/args/result/ms)
- Если из шести gates провален только Gate 6 (Impact) — finding помечается
  `defense_in_depth=true`, severity опускается до `low`, но не отбрасывается.

Кеш tool-вызовов лежит в той же `.llmscan/cache.db` (таблица `deep_tool_cache`,
ключ = `sha256(tool|args|root)`), включён по умолчанию, отключается через
`--deep-no-cache`.

Консольный отчёт показывает цветной бейдж: `confirmed` (red), `refuted` (green),
`inconclusive` (yellow) и число tool calls.

Типичный запуск:

```bash
./llmscan scan . --deep --verbose
./llmscan scan . --deep --deep-severity critical --deep-budget 60
./llmscan scan . --diff origin/main...HEAD --deep    # PR-ревью
```

**Ограничение**: реализован только Anthropic. Если активный провайдер не
`anthropic`, deep-пасс пропускается с предупреждением (OpenAI tools API
пока не подключён).

---

## False-positive verification (six gates)

Verifier (standard path) и DeepAgent (deep path) валидируют находки по
методологии [Trail of Bits fp-check](https://trailofbits-skills.mintlify.app/plugins/fp-check):
каждая находка проходит через шесть независимых gates.

| #  | Gate          | Что проверяет                                                                |
|----|---------------|-------------------------------------------------------------------------------|
| 1  | Control       | Атакующий действительно контролирует source?                                  |
| 2  | Reachability  | Достижим ли sink на реалистичном пути исполнения?                             |
| 3  | Validation    | Есть ли upstream validation (allowlist, schema), блокирующая эксплуатацию?    |
| 4  | APIContract   | Защищает ли сам API (parameterized query, memcpy_s, auto-escape)?             |
| 5  | Environment   | Митигирует ли runtime/compiler/OS (ASLR, sandbox, CSP, framework auto-escape)?|
| 6  | Impact        | Реальная security-импликация (RCE/exfil/privesc) или просто robustness?       |

Каждый gate возвращает `pass`, `fail` или `n/a` плюс одно-два предложения
обоснования. Финальный verdict выводится по правилам:

- Gate 3, 4 или 5 = `fail` → **false_positive** (есть upstream defense).
- Gate 1 или 2 = `fail` → **false_positive** (нет контроля / недостижимо).
- Только Gate 6 = `fail` → **true_positive + defense_in_depth** (severity → low).
- Все gates `pass` (часть может быть `n/a`) → **true_positive**.
- Иначе → **inconclusive** (если активен `--deep` — эскалируется в deep-agent).

**Standard vs Deep path:**

- *Standard*: `internal/agents/verifier.go` — один LLM-вызов без tool-use,
  для простых однокомпонентных багов с понятным data-flow. Промпт лежит в
  `skills/_fpcheck-verifier/SKILL.md` (специальные skill'ы с префиксом `_`
  не попадают в scanner-DAG).
- *Deep*: `internal/agents/deepscanner.go` с read-only tools — для
  cross-component багов, race conditions, логических багов, или когда
  standard вернул `inconclusive` (автоматическая эскалация если `--deep`
  включён). Промпт — `skills/_fpcheck-deep/SKILL.md`.

Оба промпта явно требуют **devil's advocate** проверки (pattern bias, trust
assumption, hallucination и др.) и явно отвергают rationalizations типа
«pattern looks dangerous, must be real».

`Finding.Gates` (опциональное поле, `omitempty`) сохраняется в JSON и в SARIF
(внутри `properties.gates`). В text-отчёте выводится блок:

```
gates:
  control:      pass — attacker controls Content-Length header
  reachability: pass — any HTTP POST triggers this path
  validation:   fail — no validation between atoi() and memcpy()
  api:          fail — memcpy() has no bounds protection
  environment:  fail — no compiler/OS protection
  impact:       pass — RCE
```

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
    model: { provider: anthropic, model: claude-sonnet-4-6 }
  fp_filter: { enabled: true }

deep:
  enabled: false
  min_severity: high
  max_hotspots: 20
  budget: 40
  concurrency: 4
  cache: true
  # model:    claude-sonnet-4-6
  # provider: anthropic
  max_file_bytes: 524288   # 512 KiB на одно read_file
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

## Skills (scanner agents)

Каждый скилл — `skills/<name>/SKILL.md` с YAML-фронтматтером и развёрнутым
промптом (scope, языковые паттерны, FP-фильтры, calibration, references).
Скиллы подгружаются динамически — добавление новой директории
`skills/<name>/SKILL.md` автоматически делает её доступной сканеру.

**Code (application-level):**

| Skill | Что ищет | Severity | Основные CWE |
|---|---|---|---|
| `injection` | SQL / NoSQL / cmd / template / LDAP / XPath / GraphQL injection | high | CWE-89, 78, 94, 643, 91, 943 |
| `secrets` | hardcoded API keys, tokens, private keys, DB URIs | high | CWE-798, 321, 259, 522 |
| `auth` | broken authn/authz, IDOR, JWT misuse, session/2FA flaws | high | CWE-287, 285, 639, 862, 863 |
| `crypto` | weak algos, ECB, static IV, predictable RNG, non-CT compare | medium | CWE-327, 326, 330, 338, 208 |
| `deserialization` | unsafe pickle/Marshal/ObjectInputStream/BinaryFormatter | critical | CWE-502 |
| `ssrf` | SSRF, open redirect, cloud-metadata access, DNS rebinding | high | CWE-918, 601 |
| `generic` | path traversal, XXE, XSS, CSRF, CORS, prototype pollution, ReDoS, mass assignment | medium | CWE-22, 611, 79, 352, 942, 1321, 1333 |
| `insecure-defaults` | fail-open fallbacks, default-permit ACLs, dev defaults reaching prod | high | CWE-1188, 453 |
| `race-conditions` | TOCTOU, insecure temp files, check-then-act, data races | medium | CWE-362, 367, 377 |
| `error-handling` | ignored errors, panic on user input, stack-trace leakage | low | CWE-209, 754, 755 |
| `supply-chain` | typosquatting, unpinned deps, curl\|sh, postinstall scripts | high | CWE-1357, 1104, 829, 494 |
| `memory-safety` | Go/Rust/C/C++ unsafe, integer overflow, UAF, format strings | critical | CWE-119, 787, 416, 190, 134 |

**IaC (auto-enabled by filetype):**

- `iac-docker`     — `Dockerfile`, `Containerfile`, `docker-compose.yml`
- `iac-k8s`        — манифесты с `apiVersion:` и `kind:`
- `iac-terraform`  — `*.tf`, `*.tfvars`
- `iac-ghactions`  — `.github/workflows/*.yml`

Watchlist pre-filter **никогда** не отбрасывает IaC-файлы.

### Атрибуция

Промпты ряда скиллов (особенно `insecure-defaults`, `supply-chain`,
`iac-ghactions`, паттерны constant-time / zeroize в `crypto`, методология
FP-фильтрации) черпают идеи из открытой коллекции
[Trail of Bits Skills](https://github.com/trailofbits/skills) (MIT) —
см. `NOTICE.md`.

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
  tools/               sandbox tools для deep-агента (read_file/grep/list_dir/git_blame)
  agents/              deepscanner — sub-agent верификация high+ находок
  types/               Finding, Report, TraceHop, DeepToolCall
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

## Development

Common Make targets used during local development:

```
make lint        # golangci-lint run ./...
make fmt         # gofmt -s -w + goimports -w
make test        # go test (also: make test-race, test-cover)
make precommit   # pre-commit run --all-files
```

First-time setup (optional but recommended):

```
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install golang.org/x/tools/cmd/goimports@latest
pre-commit install
```

The repo ships with `.golangci.yml` (errcheck, gosimple, govet, ineffassign,
staticcheck, unused, gocyclo, gocritic, gosec, misspell, unconvert, unparam,
prealloc, bodyclose, noctx, revive) and `.pre-commit-config.yaml` (go-fmt,
go-imports, go-mod-tidy, go-vet plus the standard pre-commit hooks). The CI
lint job runs `golangci-lint-action` on every push and PR.

---

## Releases

Релизы собираются автоматически через [GoReleaser](https://goreleaser.com/) при
пуше тэга:

```bash
git tag v0.4.0
git push origin v0.4.0
```

GitHub Actions workflow `.github/workflows/release.yml`:

- собирает кросс-компилированные бинари (linux/macOS/windows × amd64/arm64),
- упаковывает архивы (`tar.gz` / `zip`) c `skills/`, `README.md`, `LICENSE`,
- пушит multi-arch образ в `ghcr.io/andrewaeva/llmscan:<tag>` и `:latest`,
- генерирует `checksums.txt` (sha256) и changelog из git-истории.

Локальная проверка release-конфига без публикации:

```bash
goreleaser release --snapshot --clean --skip=publish
```

---

## Лицензия

MIT — см. [`LICENSE`](LICENSE).
