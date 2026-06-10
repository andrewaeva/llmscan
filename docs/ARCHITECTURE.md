# llmscan Architecture

LLM-multi-agent SAST поверх детерминированных слоёв. Go + CGO (tree-sitter-грамматики в `internal/ast` — нативные). Цель — высокая precision при контролируемом расходе токенов и воспроизводимом CI.

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
| Progress | `internal/progress` | tty-прогресс (multi-stage TUI: scanners + refine + deep + debate) |
| Recon | `internal/recon` | семплирует entry-points + config + shallow-файлы, одним LLM-вызовом генерит architecture-doc для `ProjectContext` |
| LLM log | `internal/llm/log.go` | JSONL-строка на каждый Complete (stage, model, tokens, latency); Sink + `Tag(client, stage)` + `WithStage(ctx, tag)` |
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
| 8a | `recon` | `stages_recon.go` | `!Recon.Enabled` | семплирует entry-points + config + shallow-файлы (`recon.sample_files`) и одним LLM-вызовом пишет architecture-doc (≤ `recon.max_bytes`), который префиксится к `ProjectContext` — orchestrator и scanners видят высокоуровневый контекст |
| 9 | `orchestrator` | `stages_static.go` | — | LLM-планировщик: focus агентов + priority файлов; здесь же загружаются few-shot banks |
| 10 | `rag` | `stages_static.go` | `!RAG.Enabled` | embeddings или keyword index |
| 11 | `cache` | `stages_static.go` | — | открывает SQLite-кэш вердиктов LLM |
| 12 | `chunk` | `stages_chunk.go` | — | adaptive chunker: группирует symbols до TargetTokens, hard-cap MaxTokens |
| 13 | `context-pack` | `stages_chunk.go` | — | для каждого чанка строит Pack (callees/callers/types/sanitizers/siblings/RAG/consts), overflow → split, до 4 раундов |
| 14 | `dag-build` | `stages_scan.go` | — | строит DAG агентов: scanners → verifier → fp_filter; verifier = PlanVerifier с fallback |
| 15 | `scanners` | `stages_scan.go` | — | параллельно прогоняет DAG, опционально N-of-K voting + Reflexion-обертка для белого списка скиллов |
| 16 | `post-process` | `postprocess.go` | — | dedupe, suppress, `dropSecretFindings` (safety-net: любой finding с "secret" в `RuleID`/`Agent` отбрасывается), **refine** (map-reduce reducer по file, бар `refine N/M`), reachability downgrade, calibration, baseline, **deep** (`deep N/M`) + **debate** (`debate N/M`) pass, `dropUnconfirmedFindings` (отбрасывает finding, если и verifier, и deep вернули `inconclusive`/пусто), `dropImpactFailFindings` (отбрасывает finding с `impact gate = fail` — verifier явно сказал «no security impact»), stats |
| 17 | `write-stages` | `stages_save.go` | — | пишет 4 JSON-снапшота (`01-raw`, `02-verified`, `03-confirmed`, `04-final`) + `stages-summary.txt` в `<target>/.llmscan/stages/`; в summary — воронка с числами по стадиям и атрибуции дропов на базе `runState.dropReasons` |
| 18 | `write-knowledge` | `stages_static.go` | — | обновляет `<target>/.llmscan/knowledge.md` авто-саммари по частым rule_id × file |

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

## LLM transport (надёжность)

Все провайдер-клиенты (`internal/llm/openai.go`, `internal/llm/openai_tools.go`,
`internal/llm/anthropic.go`) проходят через единый chokepoint `doHTTP`
(`internal/llm/retry.go`), который:

1. **Глобальный inflight-семафор.** Один на процесс, размер берётся из
   `LLM.InflightLimit`. Каждый HTTP-запрос ждёт слота перед `http.Do` и
   освобождает его сразу после. Это ограничение общее для scanner-агентов,
   verifier, fp_filter, deep-agent и debate — суммарный inflight никогда не
   превышает заданного cap. При значении 0 семафор не создаётся (no-op fast
   path). Используется при работе через прокси с жёстким лимитом одновременных
   запросов (например 5 на Eliza-proxy).
2. **Exponential backoff retry.** На `ErrRateLimit` (HTTP 429) и
   `ErrTransient` (5xx, сетевые сбои; `ErrServer` обёрнут в `ErrTransient`,
   так что `errors.Is(err, ErrTransient)` ловит оба) выполняется до
   `LLM.MaxRetries` попыток (default 6). Базовая задержка `LLM.RetryBaseDelayMS`,
   множитель 2.0, jitter ±25%, клампом `LLM.RetryMaxDelayMS`. HTTP-заголовок
   `Retry-After` (число секунд или HTTP-date) уважается и переопределяет
   расчётную задержку. Между попытками `ctx.Done()` прерывает sleep мгновенно.
3. **Идемпотентная установка.** `llm.ConfigureTransport(...)` вызывается из
   `cmd/llmscan/scan.go` один раз после `applyFlagOverrides`. `sync.Once`
   гарантирует, что первый вызов выигрывает — повторные вызовы (в тестах /
   скриптовых сценариях) игнорируются. Для тестов есть отдельный
   `resetTransportForTest`, обходящий Once.

CLI: `--inflight-limit N` (приоритет над yaml). YAML-секция: `llm:` с полями
`inflight_limit`, `max_retries`, `retry_base_delay_ms`, `retry_max_delay_ms`.

Когда `InflightLimit > 0`, при разборе флагов `Scan.AgentParallel` урезается
до `max(2, InflightLimit)`: дальнейший fan-out агентов только увеличивает
очередь у семафора без выигрыша в пропускной способности.

## LLM call logging и cost attribution

Структурированный след всех LLM-вызовов живёт в `internal/llm/log.go`:

- `LogEntry` — одна JSONL-строка на `Complete` (и `CompleteWithTools`): `ts`,
  `stage`, `provider`, `model`, `tokens_in`, `tokens_out`, `latency_ms`, `ok`,
  `error`, `msg_count`, `json_mode`.
- `Sink` интерфейс; реализация `NewFileSink(path)` выводит JSONL в файл под
  mutex. `SetSink` / `CloseSink` управляют процесс-wide sink один раз.
- `Tag(client, stage)` — внешний wrapper над `Client`; если исходник реализует
  `ToolClient`, возвращает `loggingToolClient` с тех же capabilities.
- `WithStage(ctx, tag)` — переопределяет stage из `ctx` (бьёт статический tag).

Call-sites тэгируются один раз в момент создания клиента:

| Stage tag | Кто тэгирует |
|---|---|
| `orchestrator` | `stages.go::stageOrchestrator` |
| `recon` | `stages_recon.go::stageRecon` |
| `knowledge` | `stages_knowledge.go::stageWriteKnowledge` |
| `scanner.<agent>` | `dag_build.go::buildDAG` (по одному client на сканер) |
| `context_filter` | `dag_build.go` |
| `verifier` | `dag_build.go` (клиент расшарен между PlanVerifier и обычным Verifier) |
| `fp_filter` | `dag_build.go` |
| `refine` | `refine.go::newRefiner` |
| `deep` | `deep.go::runDeepPass` (тэг на `tc` — ToolClient для tool-loop) |
| `debate` | `deep.go::runDebatePass` (отдельный `Tag(rawClient, "debate")` чтобы не двоить запись вместе с deep) |

Агрегатор — `cmd/llmscan/cost.go` (субкоманда `llmscan cost --log calls.jsonl [--prices prices.yaml] [--json]`).
Группирует по (stage, model), считает `calls`, `errors`, `tokens_in/out`,
`avg_latency_ms` и (при наличии прайс-листа) `usd`. Сортировка: USD desc →
токены desc → stage → model. Схема прайс-листа — USD за 1M токенов; ключ
`default` работает как fallback для незнакомых моделей.

Включение: `--llm-log PATH` в `scan`. Когда флаг пуст — sink не создаётся и
оверхеда нет. Сбои sink никогда не валят реальный LLM-вызов.

## Progress reporting

`internal/progress` — multi-stage TUI. API:

- `Stage(name string, total int)` — регистрирует новый бар (`total=0` —
  indeterminate режим).
- `Inc(name, delta)` / `SetTotal(name, total)` — инкремент и переоценка.
- `Done(name)` — закрывает бар галочкой.

Стадии, которые видны пользователю:
`discover`, `parse-ast`, `watchlist`, `taint`, `interproc`, `chunk`,
`context-pack`, `scanners`, `refine`, `deep`, `debate`. Раньше post-process был
одним сплошным баром «post-process» без total — сейчас разбит на три реальных
прохода с известными счётчиками.

`--no-tui` / `--progress=plain` переключается в plain-mode (`stages_*` пишут
в stderr построчные логи) — обязательно на remote VM, в CI и когда stdout не tty.

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
- `precision.{watchlist,taint,interproc,reach,vote_n,vote_k,min_score,calibration_path,interproc_max_depth,json_retries,fewshot_top_k,reflexion_skills,reflexion_max_iters,refine_threshold,refine_max_findings,drop_unconfirmed,drop_impact_fail}` — переключатели, пороги и тюнинг LangChain-паттернов (`drop_unconfirmed` дефолт `true` — отбрасывает finding с `inconclusive` от обоих агентов; `drop_impact_fail` дефолт `true` — отбрасывает finding с `impact gate = fail`)
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

- **Новый scanner** — добавить `skills/<name>/SKILL.md` (description, scope, prompt). Подхватывается автоматически. Для дешёвых прогонов предпочтительно добавлять в один из broad skills (`web-app` / `crypto-secrets` / `runtime-safety`), а не плодить узкие — каждый дополнительный сканер умножает LLM-вызовы на чанк.
- **Новый LLM-call stage** — обернуть клиент в `llm.Tag(c, "my-stage")` в момент создания. Появится в `--llm-log` и в `llmscan cost` без других правок.
- **Новый stage** — функция `func(ctx, e, s) error` + одна строка в `Engine.stages()`.
- **Новый LLM-провайдер** — реализация интерфейса в `internal/llm`.
- **Новый VCS** — реализация `vcs.VCS` (kind/Root/ChangedFiles).
- **Новый формат отчёта** — функция в `internal/report` + флаг в `cmd/llmscan/scan.go`.
- **Новый источник контекста** — collector в `internal/contextpack` + поле в `Config`.
