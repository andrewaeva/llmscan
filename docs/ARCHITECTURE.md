# llmscan Architecture

LLM-multi-agent SAST поверх детерминированных слоёв. CGO-free Go. Цель — высокая precision при контролируемом расходе токенов и воспроизводимом CI.

## Высокоуровневый вид

```
                ┌────────────────────────────────────────────┐
                │  CLI (cmd/llmscan): scan / harness-step    │
                └─────────────────────┬──────────────────────┘
                                      │
                                      ▼
                  ┌─────────────────────────────────────────┐
                  │   Engine.Run() — pipeline.go            │
                  │   фиксированный список stages           │
                  └─┬───────────────────────────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │  Static layer (no LLM)          │   Каждый stage — отдельная функция
   │  parse-AST → watchlist → taint  │   с собственным skip() и run().
   │  → interproc                    │   Добавление шага = одна строка
   └────────────────┬────────────────┘   в e.stages().
                    │
   ┌────────────────┴────────────────┐
   │  Planning + retrieval           │
   │  orchestrator (LLM) → RAG       │
   └────────────────┬────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │  Chunking + ContextPack         │
   │  chunk (adaptive) → context-pack│
   └────────────────┬────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │  LLM scanners (DAG)             │
   │  dag-build → scanners (paralle) │
   │  → verifier → fp-filter         │
   └────────────────┬────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │  Post-process                   │
   │  reach + dedupe + suppress      │
   │  → calibration → baseline       │
   │  → report (JSON/SARIF/Markdown) │
   └─────────────────────────────────┘
```

## Дерево пакетов

| Слой | Пакет | Роль |
|---|---|---|
| Точка входа | `cmd/llmscan` | cobra CLI: `scan`, `harness-step` |
| Pipeline | `internal/pipeline` | оркестрация stages, scanContext, dag-runner |
| LLM-агенты | `internal/agents` | orchestrator, scanner, verifier, fp-filter, deepscanner, context-filter |
| LLM транспорт | `internal/llm` | OpenAI/Anthropic клиенты, retry, JSON-schema |
| Конфигурация | `internal/config` | YAML loader + Validate(), AutoContextBudget |
| Знания | `internal/skills` | загрузка SKILL.md (промпт + правила scope) |
| AST | `internal/ast` | tree-sitter, детекция языка, FileAST |
| Зависимости | `internal/depgraph` | импорт-граф, TopRankedByFanIn |
| Call-graph | `internal/callgraph` | граф вызовов, reachability heuristic, entrypoints |
| Чанкер | `internal/chunker` | adaptive symbol+token chunking, SplitInHalf |
| Контекст | `internal/contextpack` | сбор callees/callers/types/sanitizers/siblings/RAG, бюджет токенов |
| Taint | `internal/taint` | intra-file + interproc (IFDS-light, summaries) |
| Watchlist | `internal/watchlist` | префильтр по sources/sinks |
| Sanitizers | `internal/sanitizers` | словарь обезвреживающих функций |
| IaC | `internal/iac` | детекция IaC файлов, доп. правила |
| RAG | `internal/rag` | embeddings + keyword fallback, индекс чанков |
| Кэш | `internal/cache` | SQLite: вердикты LLM, ContextPack, AST |
| Diff | `internal/vcs` | git/arc, ChangedFiles, --diff |
| Calibration | `internal/calibration` | изотоническая регрессия → empirical TPR |
| Baseline | `internal/baseline` | сравнение с прошлым прогоном |
| Suppress | `internal/suppress` | `// llmscan:ignore` директивы |
| Report | `internal/report` | JSON / SARIF / Markdown / Harness STO |
| Tools | `internal/tools` | sandbox для deep-агента (read_file/grep/list_dir/blame) |
| Tokens | `internal/tokens` | tokenizers для бюджетирования |
| DAG | `internal/dag` | layered parallel DAG runner |
| Progress | `internal/progress` | tty-прогресс |
| Util | `internal/util` | Walk/WalkScoped, IsExcluded, LanguageOf |
| Types | `internal/types` | Finding, Report, Stats, FileTarget, ScanPlan |

## Стадии пайплайна

Порядок и условия gating жёстко зафиксированы в `pipeline.Engine.stages()`. Каждая стадия — `func(ctx, e *Engine, s *runState) error` с опциональным `skip`. Это единственное место, куда добавляется новый шаг.

| # | Stage | Файл | Skip? | Что делает |
|---|---|---|---|---|
| 1 | `ast-cache` | `stages_static.go` | — | открывает SQLite-кэш AST |
| 2 | `discover` | `stages_static.go` | — | walk → `[]FileTarget` с учётом scope_roots, exclude, max_files, --diff |
| 3 | `parse-ast` | `stages_static.go` | — | tree-sitter в N горутин, depgraph + callgraph |
| 4 | `watchlist` | `stages_static.go` | `!PreFilterWatchlist` | отбрасывает файлы без источников/стоков |
| 5 | `suppressions` | `stages_static.go` | — | читает `// llmscan:ignore` |
| 6 | `taint` | `stages_static.go` | `!Taint` | intra-file taint трассировки |
| 7 | `interproc` | `stages_static.go` | `!Taint || !InterProc` | call-graph + function summaries + IFDS-light |
| 8 | `load-knowledge` | `stages_static.go` | — | читает `<target>/.llmscan/knowledge.md` (≤ 8 KB) для инъекции в orchestrator-промпт |
| 9 | `orchestrator` | `stages_static.go` | — | LLM-планировщик: focus агентов + priority файлов; здесь же загружаются few-shot banks |
| 10 | `rag` | `stages_static.go` | `!RAG.Enabled` | embeddings или keyword index |
| 11 | `cache` | `stages_static.go` | — | открывает SQLite-кэш вердиктов LLM |
| 12 | `chunk` | `stages_chunk.go` | — | adaptive chunker: группирует symbols до TargetTokens, hard-cap MaxTokens |
| 13 | `context-pack` | `stages_chunk.go` | — | для каждого чанка строит Pack (callees/callers/types/sanitizers/siblings/RAG/consts), overflow → split, до 4 раундов |
| 14 | `dag-build` | `stages_scan.go` | — | строит DAG агентов: scanners → verifier → fp_filter; verifier = PlanVerifier с fallback |
| 15 | `scanners` | `stages_scan.go` | — | параллельно прогоняет DAG, опционально N-of-K voting + Reflexion-обертка для белого списка скиллов |
| 16 | `post-process` | `postprocess.go` | — | dedupe, suppress, `dropSecretFindings` (safety-net: любой finding с "secret" в `RuleID`/`Agent` отбрасывается), **refine** (map-reduce reducer по file), reachability downgrade, calibration, baseline, **deep+debate** pass, stats |
| 17 | `write-knowledge` | `stages_static.go` | — | обновляет `<target>/.llmscan/knowledge.md` авто-саммари по частым rule_id × file |

`runState` (внутренний state-bag) проходит через все стадии и содержит: files, prioritized, chunks, astByPath, depgraph, callgraph, taint, suppressions, plan, scanCtx (chunks + packsByChunkKey + index), cpBuilder, cacheDB, report.

## Иерархия агентов

```
                 ┌──────────────┐
                 │ Orchestrator │  планирует focus + priority
                 └──────┬───────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
   built-in scanners:            dynamic skills (skills/*/SKILL.md):
   injection                     insecure-defaults
   auth                          race-conditions
   crypto                        error-handling
   deserialization               supply-chain
   ssrf                          memory-safety
   generic                       + custom
        │
        ▼
   ┌──────────────┐
   │  Verifier    │  читает CodeSample + ContextPack, ставит confidence
   └──────┬───────┘
        │
        ▼
   ┌──────────────┐
   │  FP-filter   │  отбрасывает явные ложноположительные
   └──────┬───────┘
        │
        ▼
   ┌──────────────┐  (опционально, по --deep)
   │ DeepScanner  │  агент с tool-loop: read_file/grep/list_dir/blame
   └──────────────┘
```

`agents.ScannerNames` — канонический список встроенных сканеров. Dynamic skills из `skills/*/SKILL.md` подхватываются `enabledScanners` и автоматически попадают в DAG. Каждый сканер получает chunk + ContextPack как extra-context.

## LangChain-паттерны (всегда включены)

Восемь паттернов работают по умолчанию, feature-flag'ов у них нет. Остались только тюнинг-поля в `precision.*` / `deep.*`.

| Паттерн | Пакет | Что делает | Тюнинг |
|---|---|---|---|
| Extended DeepAgent tools | `internal/tools` (`symbol.go`, `sandbox.go`) | поверх read_file/grep/list_dir/blame агент имеет `read_symbol`, `find_callers`, `find_callees`, `list_imports` поверх `SymbolIndex` | — |
| Few-shot retrieval | `internal/fewshot` | `Banks.LoadFromSkillDirs` читает `skills/<name>/examples/*.json`; `Bank.Retrieve` — 3-gram Jaccard с опц. языковым фильтром; top-K инжектится в scanner-промпт | `precision.fewshot_top_k` (дефолт 3) |
| Plan-and-Execute Verifier | `internal/agents/plan_verifier.go` | вместо одноразового Verifier — `Planner → Executor` tool-loop поверх sandbox-а DeepAgent. При отсутствии tool-calls / sandbox — фоллбэк на обычный Verifier | — |
| Knowledge memory | `internal/knowledge` | `<target>/.llmscan/knowledge.md` (≤8 KB) читается в `load-knowledge`, пишется в `write-knowledge` как top-N rule_id × file | — |
| Reflexion loop | `internal/agents/reflexion.go` | оборачивает scanner в `generate → critique → revise` тем же клиентом, что и сам сканер | `precision.reflexion_skills` (белый список), `precision.reflexion_max_iters` (дефолт 1) |
| Map-reduce Refine | `internal/agents/refiner.go` + `internal/pipeline/refine.go` | группирует post-verify findings по файлу; при ≥ `refine_threshold` — reducer-LLM partitionя дубли в group-base + merged ids. Reducer-промпт фиксирует: новые findings выдумывать нельзя. base = highest severity → confidence → earliest line. Мерджи получают тег `refined` и rationale в `VerifierComment`. При ошибке LLM — input passthrough | `precision.refine_threshold` (дефолт 3), `precision.refine_max_findings` (дефолт 20) |
| Multi-agent Debate | `internal/agents/debater.go` + `internal/pipeline/deep.go::runDebatePass` | после deep-pass для каждого high-severity finding: proponent (`temp=0.3`) ↔ opponent (`temp=0.6`) до `debate_max_rounds` раундов. Concede-aware: любая сторона может выставить `concede=true`. Verdict: `tp`/`fp`/`inconclusive`/`split`. FP-консенсус → `FalsePositive=true` + тег `debate-fp`; split → score × 0.7 + тег `debate-split`; inconclusive → no-op | `deep.debate` (bool, дефолт true), `deep.debate_max_rounds` (дефолт 2) |
| LangGraph state machine | `internal/agents/graph.go` | `Graph[S any]` — generic stateful DAG: `AddNode(name, fn)`, `AddEdge(from, to)`, `SetRouter(node, router)`, `SetEntry`, sentinel `End`. `MaxSteps` budget guard (дефолт 64), optional `Logf`, `Validate()`. Используется в `runDebatePass` (`gate → debate → apply`); базовый примитив для будущих per-item conditional flows | — |

## ContextPack: как формируется промпт сканера

Раньше extra-context собирался legacy-путём (symexpand callees, neighbour chunks). Теперь — единая абстракция `contextpack.Pack` со строгим бюджетом токенов.

Источники фрагментов (`Fragment`), в порядке приоритета:

1. **Сам chunk** — обязательный, всегда первым.
2. **Callees** (через call-graph, `CalleesHops` шагов) — функции, которые вызывает текущий.
3. **Callers** (`CallersHops` шагов) — функции, которые вызывают текущий.
4. **Types** — структуры/классы, используемые в chunk.
5. **Sanitizers** — обезвреживающие функции из `sanitizers.yaml`.
6. **Siblings** — соседние top-level symbols того же файла.
7. **RAG** — top-K чанков по embeddings (когда `RAG.Enabled`).
8. **Consts** — константы и enums, на которые ссылается chunk.

Сборщик ведёт бюджет: `cfg.BudgetTokens` ∈ `AutoContextBudget(agent)` = min(`scan.context.budget_tokens`, 0.7 × `model.context_window`) или дефолт по `level` (40K/80K/120K).

Когда `chunk_tokens > budget * OverflowRatio`, чанк помечается `Overflow=true` и в `stageBuildContextPacks` пересплитывается `chunker.SplitInHalf` пополам, до 4 раундов. После — `squeeze`: дроп head/tail строк фрагментов, дедуп по диапазону.

Конфиг получает `contextpack.FromConfig(cfg)`: level preset → AutoContextBudget → per-field overrides.

Кэш: `cacheKey = sha256(chunk + cfg.hash())`, хранится в SQLite. Pack без overflow заносится в кэш, при повторном прогоне берётся как есть.

## Deterministic слои (до LLM)

Они либо отбрасывают findings, либо понижают их confidence, либо сужают набор файлов:

- **Watchlist** (`internal/watchlist`): YAML словари sources/sinks/sanitizers. Файл без хоть одного хита по `Source` или `Sink` (для известного языка) выкидывается до того, как LLM его увидит.
- **Taint** (`internal/taint`): intra-file прохождение от sources к sinks через AST + sanitizers. Когда `InterProc=true` — расширяется на call-graph с function summaries.
- **Reachability** (`internal/callgraph/reach.go`, `BuildReach` + `ReachIndex`): после LLM-пасса понижает confidence для findings в test/dead-code или вне reachability set от entry points.

## DAG и параллелизм

`dag.Run` исполняет агентов слоями: на одном слое — независимые сканеры параллельно (`Scan.AgentParallel`), внутри каждого сканера — чанки тоже параллельно (`Scan.Concurrency`). `verifier` и `fp_filter` идут после.

Voting (опционально, когда `VoteN > 1`): сканер N раз запускается с повышенной температурой, результаты агрегируются `voteAggregate(runs, k)` — finding остаётся, если попал ≥ K раз; score умножается на `votes/N`.

Deep-pass (опционально, `--deep`): для high-severity findings запускается `DeepAgent` с sandbox (`internal/tools`: read_file/grep/list_dir/blame) в multi-turn tool-use loop. Вердикт сливается в исходный Finding.

## Конфиденс и калибровка

`pipeline/confidence.go` — детерминистический пересчёт confidence на основе:

1. Verifier verdict (HighConf/MediumConf/LowConf/FP).
2. Taint trace presence.
3. Reachability downgrade (FPReason starts with `reachability:`).
4. Vote consistency.
5. Calibration model (когда `CalibrationPath` задан): isotonic regression поверх Score → empirical TPR. После калибровки `--min-score` отражает реальную вероятность true-positive.

## Кэширование

Три уровня SQLite-кэша:

- **AST cache** (`.llmscan/ast-cache.db`): ключ — sha256 содержимого + язык, значение — сериализованный FileAST. Амортизирует tree-sitter на больших репо.
- **LLM cache** (`.llmscan/cache.db`): ключ — agent + chunk + extra-context hash, значение — JSON-вердикт. Идентичный пересчёт не зовёт LLM.
- **ContextPack cache** (тот же файл, namespace `cp:`): ключ — `Builder.CacheKeyFor(chunk)`, значение — сериализованный Pack без overflow.

Все кэши открываются в начальных стадиях (`ast-cache`, `cache`) и закрываются через `defer` в `Run()`.

## Конфиг

`config.Config` — корень YAML-дерева. Загрузка: `config.Load(path)` → `Default()` + YAML merge + `Validate()`.

Ключевые блоки:

- `default_model` / `agents.*.model` — LLM-провайдер, токены, context_window
- `scan.{include,exclude,scope_roots,max_files,vcs}` — границы обхода
- `scan.chunk.{target_tokens,max_tokens,min_tokens,fallback_lines}` — адаптивный чанкер
- `scan.context.{level,budget_tokens,*_hops,*_max,include_*,*_max}` — ContextPack
- `precision.{watchlist,taint,interproc,reach,vote_n,vote_k,min_score,calibration_path,interproc_max_depth,json_retries,fewshot_top_k,reflexion_skills,reflexion_max_iters,refine_threshold,refine_max_findings}` — переключатели, пороги и тюнинг LangChain-паттернов
- `rag.{enabled,provider,model,top_k,batch_size}` — retrieval
- `cache.{enabled,path}`, `ast_cache.{enabled,path}` — SQLite кэши
- `baseline.{path,write}` — сравнение с прошлым прогоном
- `deep.{enabled,min_severity,max_hotspots,budget,concurrency,debate,debate_max_rounds}` — sub-агент + debate

Валидация — единая `Config.Validate()`. Никаких deprecated-полей: legacy line-based chunker, symbol-expansion и `ChunkConfig.Enabled`/`ContextConfig.Enabled` удалены.

## Вход — выход

**Вход:**
1. Папка или файл с кодом (target).
2. `llmscan.yaml` (опционально) — переопределения дефолтов.
3. Переменные окружения с API-ключами (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …).
4. `--diff`, `--baseline`, `--fail-on`, `--format`, `-o`.

**Выход:**
1. `types.Report` со списком `[]Finding` и `Stats` (по severity, по агенту, по контекстпаку).
2. Сериализация: JSON / SARIF / Markdown / Harness-STO snippet.
3. Exit code по `--fail-on` severity threshold.

## Точки расширения

- **Новый scanner** — добавить `skills/<name>/SKILL.md` (description, scope, prompt). Подхватывается автоматически.
- **Новый stage** — функция `func(ctx, e, s) error` + одна строка в `Engine.stages()`.
- **Новый LLM-провайдер** — реализация интерфейса в `internal/llm`.
- **Новый VCS** — реализация `vcs.VCS` (kind/Root/ChangedFiles).
- **Новый формат отчёта** — функция в `internal/report` + флаг в `cmd/llmscan/scan.go`.
- **Новый источник контекста** — collector в `internal/contextpack` + поле в `Config`.
