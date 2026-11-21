# KruschStack (`krusch-stack`) Specification

> **Repository**: `https://github.com/kruschdev/krusch-stack.git`
> **Version**: `1.3.1`
> **Runtime**: Node.js `>=22.0.0` (Native ESM + `node:sqlite`) & Docker Compose (`pgvector/pgvector:pg16` DDL parity)
> **License**: MIT

---

## 1. Overview

**KruschStack** (`krusch-stack`) is the unified, single-install distribution of the Krusch Sovereign AI & Coding Agent Ecosystem. Instead of manually installing, configuring, and wiring separate repositories across IDEs and databases, developers can install the entire stack with a single `npx` command or `docker compose up -d`:

1. **Tier 1: Working Memory, Invariants & Git Alignment (`krusch-context-mcp` + `git-alignment`)**: `retrieve`, `remember`, `revise`, `nudge`, `health` with `INV-12` span-grounded drift detection, `git blame -w -M` hunk attribution, superseded-commit stale-code scanning, and `--when`/`--require` companion-file co-change gates.
2. **Tier 2A: Codebase AST & Git DAG (`krusch-git`)**: `list_repos`, `read_tree`, `read_blob`, `search_symbols`, `file_symbols`, `dependency_graph`, `semantic_search`.
3. **Tier 2B: OS Filesystem & Page-Anchored Memory (`krusch-fs`)**: `locate`, `search`, `page_tree`, `read_page`, `remember_on_page`, `sync` with SHA-256 page drift tracking (`VALID` vs `STALE_DRIFT`).
4. **Tier 2C: Structural Graph Context & Temporal Ontology (`hydrascope`)**: `traverseContext`, `checkAnswerable`, `compareVectorVsGraph`, `supersedeDecision`, `ingestDirectory`, and `runBenchmark` (`stack.hydrascope`, `POST /hydrascope/*`, and `--server hydrascope` 6-tool modular MCP) with `asOf` `:SUPERSEDES` replay, 10-language polyglot AST/import/`.env`/ADR compilation, auto-hydrated 4-Axis Brick Ontology, and optional live HydraDB OpenCypher sync.
5. **Tier 2D & Tier 3: 2PC Staged Execution, Turn-0 Grounded Harness & Collaborative Brick Exchange (`krusch-harness` + `grounded-harness` + `brick-exchange`)**: `run`, `task_status`, `diff`, `apply_diff`, `explain`, `reject`, `abort`, staging unified diffs and enforcing invariants alongside `stack.actionHarness` (`INV-STACK-10`), `stack.groundedHarness` (`INV-STACK-11` / `INV-GH-01..12`, `--server krusch-grounded-harness`), and `stack.brickExchange` (`INV-STACK-12` / `INV-LEGO-36`, `--server krusch-brick-exchange`).
6. **Frontend Design & Styling Engine (`krusch-frontend-mcp`)**: `generate_color_palette`, `css_to_tailwind`, `query_design_rules`, `get_canonical_template` (`16` HTML/SVG + Lego + Vercel Golden Brick templates), `list_canonical_templates`, `generate_responsive_breakpoints`.
7. **Workspace Hub & Hybrid RAG (`g-krusch`)**: `get_agent_steering`, `search_drive_rag`, `read_drive_file`, `write_drive_file`, `list_drive_workspace`, `get_workspace_status`.
8. **Cognitive Cascade Router, Sovereign ToolGraph & Polyglot Audit (`krusch-cascade-router` + `tool-graph` + `polyglot-audit`)**: `krusch_route_task` & `krusch_stack_status`, `<1ms` `CONSUMES -> PRODUCED_BY` prerequisite tool routing (`stack.toolGraph`, `POST /tool-graph/*`), and 28-rule 10-language brownfield hazard scanning (`stack.polyglotAudit`).

---

## 2. Architectural Invariants

- **`INV-STACK-01` (Zero-Setup Local `node:sqlite` Engine + 21-Table Companion PostgreSQL DDL Parity)**: Every engine in `krusch-stack` executes runtime storage locally out-of-the-box with zero external dependencies using Node 22 native `node:sqlite` (`.krusch-stack/stack.db`, `DB_PATH`, or in-memory `:memory:` when `KRUSCH_EPHEMERAL=1`), while `db/init.sql` maintains verified 21-table PostgreSQL 16 + `pgvector` schema and index DDL parity (`tests/postgres-schema-parity.test.js`) for companion Docker Compose schema provisioning.
- **`INV-STACK-02` (Universal Return Envelope)**: Every engine function and MCP tool payload returns a deterministic JSON envelope `{ ok: boolean, tool: string, summary: string, data: object }` (or `{ ok: false, tool, summary, error }` on failure) serialized as JSON text inside the MCP `content` array.
- **`INV-STACK-03` (4-Boolean MCP Tool Annotations, Memory #567)**: Every registered MCP tool in `src/mcp/server.js` MUST explicitly declare `annotations: { title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint }` as booleans and ship with a root MIT `LICENSE` file.
- **`INV-STACK-04` (Public Sanitization, Memory #594)**: Zero internal homelab hostnames, private LAN/Tailscale IPs (`192.168.x.x`, `10.10.10.x`, `100.x.x.x`), or private OS usernames in any source file, test, `docker-compose.yml`, or documentation. All defaults use `127.0.0.1` / `localhost` or environment variables.
- **`INV-STACK-05` (Progressive Profile Filtering)**: The MCP server, doctor, and IDE installer support four opinionated profiles via `normalizeStackProfile(profile)`: `memory-only` (Tier 1 `context`, 5 unified tools / 1 modular server), `coding-agent` (Tiers 1, 2A, 3A `context,git,harness`, 19 unified tools / 4 modular servers incl. `krusch-grounded-harness`), `core` (Tiers 1, 2A, 2B, 3A + Router, 27 unified tools / 8 modular servers), and `full` (39 unified tools / 10 modular servers). Programmatic APIs and `mcp`/`serve` default to `full` for backward compatibility, while interactive `npx krusch-stack init` defaults to `coding-agent` unless `--profile` or `KRUSCH_STACK_PROFILE` is explicitly supplied.
- **`INV-STACK-06` (2PC Staged Harness Safety)**: `krusch_run` stages file modifications as unified diffs in SQLite (`harness_tasks`) and evaluates active `invariant` memories via `nudge` before transitioning to `STAGED`. Working tree files are only mutated when `krusch_apply_diff` is explicitly called on a `STAGED` task.
- **`INV-STACK-07` (External-Content Porter `FTS5` & Lazy Top-K Hydration)**: `ensureStackSchemaMigrations(db)` in `src/db/sqlite.js` idempotently provisions SQLite external-content Porter `FTS5` virtual tables (`git_symbols_fts`, `fs_pages_fts`, `fs_page_memories_fts` with `tokenize='porter unicode61'`), `AFTER INSERT`/`DELETE`/`UPDATE` synchronization triggers using raw `old.<col>` and `new.<col>` column references (never `coalesce` on `'delete'`), and one-time `'rebuild'` backfill when legacy base tables contain rows with an empty `*_fts_docsize` shadow table. Tier 2A (`semanticSearch`) and Tier 2B (`search`) evaluate candidate metadata + `FTS5` `bm25(...)` ranks first and lazily hydrate full `snippet` / `page_text` payloads only for the Top-K winning rows.
- **`INV-STACK-08` (Tier 2B `.env` `KEYS_ONLY` Redaction & Pre-Write Secret Shield)**: `src/engines/fs-engine.js` redacts sensitive `.env` and `.env.*` file values (`KEY=[REDACTED]`, excluding `.env.example`, `.env.sample`, `.env.template`, `.env.schema`, `.env.dist`) via `redactEnvSecrets` before computing SHA-256 `page_hash` or storing `fs_pages.page_text`, and blocks raw API keys, tokens, PEM private keys, and inline URL passwords in `rememberOnPage` via `scanForSecretLeak(text)` before SQLite insertion while permitting `[REDACTED]` placeholders.
- **`INV-STACK-09` (Tier 2A 2-Hop `git_edges` Call-Graph Bridging & Token/Identifier Telemetry)**: `semanticSearch` in `src/engines/git-engine.js` expands Top-3 Hop-1 symbol hits across 1-hop `git_edges` callers/callees when multi-term queries (`>= 2` distinctive tokens) leave at least one query token uncovered, capping bridged symbol scores strictly at `Math.min(topHop1Score * 0.84, Math.max(0.01, topHop1Score - 0.01))` (`bridge_hop: true`, `bridge_via`), and both `krusch_git_semantic_search` and `krusch_fs_search` accept optional `limit_tokens` while reporting `unattested_query_identifiers` / `unattested_query_terms` (`string[]`) without altering `ALL_STACK_TOOLS.length === 39`.
- **`INV-STACK-10` (2PC Tool-Action Harness, Trajectory Spin-Loop Guard & Verify-on-Stop Gate)**: `src/engines/action-harness-engine.js` extends Tier 3 2PC governance beyond filesystem diffs to arbitrary external RPC/MCP tool-calling trajectories without altering `ALL_STACK_TOOLS.length === 39`. All sessions and events persist in SQLite (`action_harness_sessions`, `action_harness_events` via `ACTION_HARNESS_SCHEMA_SQL`) and return strict `INV-STACK-02` `okEnvelope` payloads exposed on `stack.actionHarness` and `POST /action-harness/{start,intercept,outcome,verify-stop,summary}`: (1) blocks duplicate `(tool_name, canonical_args)` read spin-loops (`BLOCK_SPIN_LOOP`) and runaway consecutive read streaks (`BLOCK_READ_STREAK`); (2) blocks duplicate mutating side-effects (`BLOCK_DUPLICATE_WRITE`); (3) stages mutating tool calls (`ALLOW_MUTATION`) after auditing unresolved placeholders, malformed non-ISO date placeholders, `scanForSecretLeak`, and optional `contextEngine.nudge` invariants (`HOLD_FOR_REVISION`); and (4) gates premature zero-mutation stops via `verifyStop` (`CONTINUE_VERIFY` vs. `ALLOW_STOP`) while respecting intentional policy-grounded abstentions.
- **`INV-STACK-11` (Turn-0 Grounded, Scale-Aware, Defect-Only Agent Harness, `INV-GH-01..12`)**: `src/engines/grounded-harness-engine.js` (`krusch-stack/grounded-harness`, `stack.groundedHarness`, and `POST /grounded-harness/{scale-profile,ground,ground-and-start,evaluate-turn,start,intercept,outcome,verify-stop,summary}`) provides zero-dependency SQLite (`grounded_sessions`, `grounded_events`) and PostgreSQL DDL parity with [`kruschdev/grounded-harness`](https://github.com/kruschdev/grounded-harness) while keeping `ALL_STACK_TOOLS.length === 39` strictly intact: (1) zero-LLM Turn-0 workspace schema & hazard introspection (RFC-4180 CSV literal `"NA"` `keep_default_na=False` flags, JSON `null`/`[]` wildcard flags, read-only SQLite DDL/row counts, `.env` exclusion, `256/32`-token Raw-RAG BM25 chunks, and KV-cache-stable SHA-256 `prefixHash`); (2) Gemini tool-less guard (`functionCallingConfig: { mode: 'NONE' }`); (3) monotonic scale-aware profiles (`SMALL_MODEL`, `MID_MODEL`, `FRONTIER_REASONING`) with `maxReadStreak = 0`; (4) quote-safe, Python-`//`-safe comment-normalized call hashing (`MEMOIZED_PRIOR_READ` $\rightarrow$ `BLOCK_SPIN_LOOP`) with SQLite `rowid`-ordered post-mutation verification re-read allowance; (5) staged-diff-only `FORCE_VERIFY` + zero-turn-when-healthy `inspectOutputDefects`; and (6) `execCommandWithPartialStdout` preserving partial `stdout` on subprocess timeouts.
- **`INV-STACK-12` & `INV-LEGO-36` (Collaborative Brick Exchange, Deadbolt 2-Hop Blast Radius & 4-Axis HydraScope Ontology)**: `src/engines/brick-exchange-engine.js` (`krusch-stack/brick-exchange`) and `src/engines/brick-ontology-engine.js` (`krusch-stack/brick-ontology`) ship zero-dependency `node:sqlite` execution (`brick_exchange_bricks`, `brick_exchange_grants`, `brick_exchange_adoptions`) and `db/init.sql` PostgreSQL DDL parity with `@krusch/toolkit/brick-exchange` (`krusch-sealed-brick/v1`, [Paper #29](https://krusch.dev/articles/mit-open-source-brick-exchange-common-ground-deadbolt) & [Paper #30](https://krusch.dev/articles/ontological-brick-exchange-deadbolt-common-ground-hydrascope)) while keeping `ALL_STACK_TOOLS.length === 39` intact: (1) 4-gate Node 22 `--permission` sandbox + mandatory fault-injection checks + Ed25519 lineage signatures embedding normalized `blueprint.ontology` inside `blueprintHash` (`TAMPERED_ONTOLOGY` on unsigned top-level mismatch); (2) tiered team commons + MIT-attributed Common Ground scoped cross-org grants; (3) bit-for-bit HydraScope 48-bit surrogate vertex hashing (`sha256("${ns}\0${logicalId}")` under default `'brick-ontology'`), Cypher-clean edge types (`TARGETS_STACK`, `CONSUMES_PORT`, `PRODUCES_PORT`, `BRIDGES_CHANNEL`, `ROUTES_TO_MODEL`, `SUPERSEDES`), port namespace isolation (rejecting bare non-canonical `'unscoped'` ports), and same-org cycle-safe `SUPERSEDES` lineage; (4) seal-verified `$0` hexagonal adapter synthesis (`binding.js`, `binding.ts`, `binding_adapter.py`) stripping consumed raw alias keys for `additionalProperties: false` schemas; and (5) Deadbolt 2-hop AST blast-radius mapping (`hop0 -> hop1 -> hop2`), conflict-free wave planning (`planFanOut`), and Policy Floor protection.
- **`INV-STACK-13` (Tier 2C HydraScope Structural Context, Temporal `asOf` Lineage & Modular MCP Extension Surface)**: `src/engines/hydrascope-engine.js` (`krusch-stack/hydrascope`, `stack.hydrascope`, `POST /hydrascope/{state,traverse,check-answerable,compare,benchmark,supersede,ingest}`) persists structural graph nodes (`hydrascope_nodes`) and directed edges (`hydrascope_edges`) in SQLite WAL (with 21-table `db/init.sql` PostgreSQL 16 + `pgvector` parity and optional sanitized `HYDRADB_URL` OpenCypher sync), pre-seeded with the 18-artifact FinTech benchmark corpus and 8 Proof-Over-Vectors scenarios. Supports zero-LLM `checkAnswerable`, multi-hop structural BFS + temporal `asOf` `:SUPERSEDES` replay (`traverseContext` with automatic `brick_exchange_bricks` 4-axis ontology hydration when `includeBrickOntology` or stack/channel/port filters are supplied), head-to-head dense vector vs. structural traversal comparison (`compareVectorVsGraph`), live ADR supersession (`supersedeDecision`), and symlink-contained 10-language polyglot directory compilation (`ingestDirectory`). Meanwhile, `MODULAR_EXTENSION_TOOLS` in `src/mcp/server.js` exposes `--server hydrascope` (6 tools), `--server krusch-brick-exchange` (10 tools), and `--server krusch-grounded-harness` (7 tools) without altering `ALL_STACK_TOOLS.length === 39` or `src/mcp/deferred-bridge.js`.
- **`INV-STACK-14` (Zero-LLM Git Alignment Guards, Sovereign ToolGraph Prerequisite Router & Polyglot Hazard Scanner)**: (1) `src/engines/git-alignment-engine.js` (`krusch-stack/git-alignment`) enriches `stack.context.nudge()` with `--when`/`--require` companion-file co-change rules (`INV-ALIGN-COCHANGE-03`), `git blame -w -M` hunk/snippet memory attribution (`INV-ALIGN-BLAME-01`), and `INV-LEGO-01` hand-rolled boilerplate checks, and enriches `stack.context.health()` with surviving superseded-commit stale-code detection (`INV-ALIGN-STALE-02`); (2) `src/engines/tool-graph-engine.js` (`krusch-stack/tool-graph`, `stack.toolGraph`, `POST /tool-graph/{find,describe,call,outcome,stats,reset}`) provides `<1ms` typed `CONSUMES -> PRODUCED_BY` prerequisite closure, `extractGivenTypesFromTask` entity pruning, two-pass budget allocation, and `[0, 5]` bounded-LRU `reportOutcome` gap learning; and (3) `src/engines/polyglot-audit-engine.js` (`krusch-stack/polyglot-audit`, `stack.polyglotAudit`) scans 10 languages / 14 extensions across 28 brownfield & Slop-Breaker rules while mapping findings to `@krusch/toolkit` bricks.
- **`INV-STACK-15` (Zero-Cloud 30-Second Value Demo, Decision Observability & Clean-Room Reproducer)**: (1) `src/installer/demo.js` (`krusch-stack/demo`, `runStackDemo`, `npx krusch-stack demo`) executes a deterministic 3-act walkthrough in `<1s` over an isolated temporary SQLite workspace with zero network calls; (2) `src/engines/observability-engine.js` (`krusch-stack/observability`, `stack.observability`, `npx krusch-stack explain`, `GET /telemetry`) aggregates structured decision counters and chronological `"Why did the agent do that?"` explanations across `harness_tasks`, `harness_apply_journal`, `action_harness_events`, `grounded_events`, `context_memories`, and `stack_hitl_gates` without adding new DDL tables (preserving 21-table SQLite/PostgreSQL parity and `ALL_STACK_TOOLS.length === 39`); and (3) `scripts/reproduce_clean_room.js` (`npm run bench:repro`) verifies deterministic clean-room gates and emits reproducible SHA-256 audit digests.

---

## 3. Frozen Module Contracts (Subagent Boundaries)

### Module Group A: Tiers 1 & 2 Engines (`src/engines/context-engine.js`, `src/engines/git-engine.js`, `src/engines/fs-engine.js`)
- **`src/engines/context-engine.js`**, **`src/engines/context-lexical.js`**, **`src/engines/context-epistemic.js`**, **`src/engines/context-prune.js`**:
  - Exports `createContextEngine({ db, workspaceRoot, ephemeral, embedEndpoint, embedModel, autoEmbed })` returning:
    - `retrieve({ query = "*", category, include_state = true, include_lineage = null, condense = null, include_markdown = false, limit_tokens = 4000, _embedding = null })` & `retrieveAsync(...)`
    - `remember({ category, content, provenance, _embedding = null })` & `rememberAsync(...)`
    - `revise({ action, target_id, new_content, reason, provenance, _embedding = null })` & `reviseAsync(...)`
    - `nudge({ trigger = "pre_commit", code = "" })`
    - `health()`
  - `src/engines/context-lexical.js` additionally exports shared Tier 2 lexical/identifier helpers `splitIdentifierSubtokens(token)`, `extractCodeShapeIdentifiers(queryText)`, and `buildFts5MatchQuery(queryText)`.
  - Supports optional 1024-dim dense embeddings in SQLite (`context_memories.embedding TEXT` with automatic `ALTER TABLE` migration), RM3 pseudo-relevance feedback, in-session episode kernel smoothing, 3-tier `prunePreSynthesis` (`680 / 440 / 320` char) progressive condensation, and `INV-12` span drift (`VALID`, `HEALED_LINE_SHIFT`, `STALE_DRIFT`).
- **`src/engines/git-engine.js`**:
  - Exports `createGitEngine({ db, workspaceRoot })` and `maskCodePreservingNewlines(source)` returning:
    - `listRepos()`
    - `readTree({ repo, path = "" })`
    - `readBlob({ repo, path, start_line, end_line })`
    - `searchSymbols({ repo, query, symbol_type })`
    - `fileSymbols({ repo, file_path })`
    - `dependencyGraph({ repo, symbol })`
    - `semanticSearch({ repo, query, limit = 10, limit_tokens })`
    - `indexRepo({ repoPath })`
  - Uses comment/string-masked AST brace matching (`INV-GIT-01`), external-content Porter `FTS5` (`git_symbols_fts`) + camelCase/stemmed scoring + lazy Top-K `snippet` hydration (`INV-STACK-07`), gated 2-hop `git_edges` call-graph bridging (`0.84` score cap), optional `limit_tokens` budgeting, and `unattested_query_identifiers` (`INV-STACK-09`).
- **`src/engines/fs-engine.js`**:
  - Exports `createFsEngine({ db, workspaceRoot })`, `isSensitiveEnvFile(filePath)`, `redactEnvSecrets(content)`, and `scanForSecretLeak(text)` returning:
    - `locate({ pattern = "*", category = "all", min_size_bytes = 0 })`
    - `search({ query, category = "all", limit = 10, limit_tokens })`
    - `pageTree({ path })`
    - `readPage({ path, page_number = 1 })`
    - `rememberOnPage({ path, page_number = 1, note, category = "annotation" })`
    - `sync({ paths = [] })`
  - Splits files into bounded structural pages (~80 lines/page or markdown heading boundaries), enforces `.env` `KEYS_ONLY` value redaction (`KEY=[REDACTED]`) and `scanForSecretLeak` pre-write secret shielding (`INV-STACK-08`), uses external-content Porter `FTS5` (`fs_pages_fts`, `fs_page_memories_fts`) + lazy Top-K `page_text` hydration (`INV-STACK-07`), enforces optional `limit_tokens`, and reports `unattested_query_terms` (`INV-STACK-09`).

### Module Group B: Tier 3, Frontend, Workspace & Router Engines (`src/engines/harness-engine.js`, `src/engines/frontend-engine.js`, `src/engines/workspace-engine.js`, `src/engines/router-engine.js`)
- **`src/engines/harness-engine.js`**:
  - Exports `createHarnessEngine({ db, workspaceRoot, contextEngine })` returning:
    - `run({ goal, edits = [], files = [], test_command, task_id })`
    - `taskStatus({ task_id })`
    - `diff({ task_id })`
    - `applyDiff({ task_id })`
    - `explain({ task_id })`
    - `reject({ task_id, reason })`
    - `abort({ task_id })`
- **`src/engines/frontend-engine.js`**:
  - Exports `createFrontendEngine({ db })` returning:
    - `generateColorPalette({ base_hex, harmony = "complementary" })`
    - `cssToTailwind({ css })`
    - `queryDesignRules({ query, category })`
    - `getCanonicalTemplate({ template_id })`
    - `listCanonicalTemplates()`
    - `generateResponsiveBreakpoints({ component_type = "grid" })`
- **`src/engines/workspace-engine.js`**:
  - Exports `createWorkspaceEngine({ db, workspaceRoot })` returning:
    - `getAgentSteering()`
    - `searchDriveRag({ query, limit = 10 })`
    - `readDriveFile({ path })`
    - `writeDriveFile({ path, content, mime_type })`
    - `listDriveWorkspace({ folder = "" })`
    - `getWorkspaceStatus()`
- **`src/engines/router-engine.js`**:
  - Exports `VERSION = '1.3.1'` and `createRouterEngine({ config })` returning:
    - `routeTask({ prompt, task_type, budget_tier })` (aligned with the 3-Chair Bandit fleet: `gemma4:e2b`, `qwen3-coder-30b-moe:latest`, `inkling-2-mini:ud-iq4_xs-dspark`)
    - `getStackStatus({ engines, db })` (reporting `version: '1.3.1'`, `auxiliary_engines`, `hydrascope_tables_ready`, and `brick_exchange_tables_ready`)

### Module Group C: Installer, Doctor & Docker (`src/installer/ide-config.js`, `src/installer/doctor.js`, `Dockerfile`, `docker-compose.yml`, `db/init.sql`)
- **`src/installer/ide-config.js`**:
  - Exports `generateIdeConfig({ ide = "all", mode = "unified", profile = "full", deferTools = false, includeExtended = false, workspaceRoot })` and `writeIdeConfigs({ targetDir, ide, mode, profile, deferTools, includeExtended })`.
  - Supports Claude Code (`.mcp.json`), Cursor (`.cursor/mcp.json`), Windsurf (`mcp_config.json`), and Antigravity (`mcp_config.json`).
- **`src/installer/doctor.js`**:
  - Exports `runStackDoctor({ workspaceRoot, db, profile })` verifying Node `>=22` and all 21 SQLite tables across the 10 stack pillars, returning `{ ok, tool, summary, data }`.
- **`Dockerfile`, `docker-compose.yml`, `db/init.sql`**:
  - Multi-container stack with `pgvector/pgvector:pg16` (`postgres`) and non-root `krusch-stack` gateway service bound to `127.0.0.1:3780`. `src/db/sqlite.js` (`node:sqlite`) executes active runtime storage out-of-the-box, while `db/init.sql` maintains 100% 21-table PostgreSQL DDL & index parity (`tests/postgres-schema-parity.test.js`).

### Module Group D: 2PC Tool-Action Harness Engine (`src/engines/action-harness-engine.js`, `bin/krusch-stack.js`)
- **`src/engines/action-harness-engine.js`**:
  - Exports `ACTION_HARNESS_SCHEMA_SQL`, `classifyToolMutability(toolName, explicitMutating)`, `canonicalizeToolCallKey(toolName, args)`, and `createActionHarnessEngine({ db, contextEngine })` returning:
    - `startSession({ session_id, persona, goal, anchor_date, max_identical_reads = 1, max_duplicate_writes = 1, max_read_streak = 6, max_verify_nudges = 1, enforce_context_nudge = false, reset = false })`
    - `interceptToolCall({ session_id, step = 0, tool_name, args = {}, is_mutating, is_memory_search = false })`
    - `recordToolOutcome({ session_id, event_id, status = "COMMITTED", canonical_args, result_preview = "" })`
    - `verifyStop({ session_id, step = 0, final_text = "", has_mutating_tools_available = true })`
    - `sessionSummary({ session_id })`
- **HTTP Gateway Contract (`bin/krusch-stack.js`)**:
  - Mounts `POST /action-harness/{start,intercept,outcome,verify-stop,summary}` delegating to `stack.actionHarness` while strictly preserving `ALL_STACK_TOOLS.length === 39`.

### Module Group E: Turn-0 Grounded, Scale-Aware, Defect-Only Harness Engine (`src/engines/grounded-harness-engine.js`, `bin/krusch-stack.js`)
- **`src/engines/grounded-harness-engine.js` (`krusch-stack/grounded-harness`)**:
  - Exposes `0` tools in default unified `ALL_STACK_TOOLS` (`ALL_STACK_TOOLS.length === 39` strictly preserved) while registering `7` annotated modular extension tools in `MODULAR_EXTENSION_TOOLS` (`src/mcp/server.js`, active via `--server krusch-grounded-harness`, `init --modular`, or `--include-extended`). Imports `okEnvelope` from internal package sibling `../db/sqlite.js` (`INV-STACK-01` zero external npm dependencies preserved).
  - Pure synchronous helper primitives (`inferModelScaleMetadata`, `resolveScaleProfile`, `buildScaleAwareDirective`, `buildSafeGeminiToolConfig`, `normalizeCodeSnippetForHash`, `canonicalizeGroundedToolCallKey`, `inspectOutputDefects`, `formatTimeoutWithPartialStdout`, `execCommandWithPartialStdout`, `introspectWorkspaceSchemas`) return typed domain values directly, whereas `compileTurnZeroGrounding` and all `createGroundedHarnessEngine({ db, workspaceRoot })` engine methods return `INV-STACK-02` `{ ok, tool, summary, data }` envelopes:
    - `resolveScale(params)`
    - `groundWorkspace(params)`
    - `startSession(params)`
    - `groundAndStartSession(params)`
    - `evaluateTurn({ session_id, turn_response })`
    - `interceptToolCall({ session_id, step = 0, tool_name, args = {}, mutating, suppress_turn0_reads = true, block_spin_loop = false })`
    - `recordToolOutcome({ session_id, event_id, ok = true, result_preview = "", timed_out = false, partial_stdout = "", pending_diffs_delta = 0, verification_passed })`
    - `verifyStop({ session_id, assistant_text = "", candidate_answer, finish_reason = null, truncated_tool_calls = false, tool_calls = [], expect_non_empty_answer = false, pending_diffs_count, latest_verification_passed, verification_command = "npm test" })`
    - `sessionSummary({ session_id })`
- **HTTP Gateway Contract (`bin/krusch-stack.js`)**:
  - Mounts `POST /grounded-harness/{scale-profile,ground,ground-and-start,evaluate-turn,start,intercept,outcome,verify-stop,summary}` delegating to `stack.groundedHarness` while strictly preserving `ALL_STACK_TOOLS.length === 39`.

### Module Group F: Collaborative Brick Exchange & 4-Axis Ontology Engine (`src/engines/brick-exchange-engine.js`, `src/engines/brick-ontology-engine.js`, `bin/krusch-stack.js`)
- **`src/engines/brick-exchange-engine.js` (`krusch-stack/brick-exchange`) & `src/engines/brick-ontology-engine.js` (`krusch-stack/brick-ontology`)**:
  - Exports `BRICK_EXCHANGE_SCHEMA_SQL`, `generateEd25519BrickKeys`, `verifySealedBrickBundle`, `createBrickExchangeEngine({ db, workspaceRoot })`, `CANONICAL_SHARED_TYPES`, `STACK_ONTOLOGY_STACKS`, `STACK_ONTOLOGY_PORTS`, `STACK_ONTOLOGY_CHANNELS`, `STACK_ONTOLOGY_MOE_PROFILES`, `hasForbiddenKeyRecursive`, `parsePortReference`, `isWebStandardPureBrickSource`, `areOntologyPortsCompatible`, `surrogateOntologyVertexId`, `normalizeBrickOntology`, `inspectBrickOntology`, `checkBrickOntologyCompatibility`, `composeCrossStackBricks`, `synthesizeHexagonalBinding`, and `createBrickOntologyEngine`.
  - `stack.brickExchange` exposes `keygen`, `sealBrick`, `verifyBrick`, `publishBrick`, `issueGrant`, `revokeGrant`, `listInbox`, `tryBrick`, `adoptBrick` (honoring `adapterFileName`: `binding.js`, `binding.ts`, `binding_adapter.py`), `auditBrickLocks`, `analyzeBlastRadius`, `planFanOut`, `verifyBlastRadius`, `inspectOntology`, `checkOntologyCompatibility`, `composeCrossStack`, `synthesizeBinding`, and `stats`.
- **HTTP Gateway Security Contract (`bin/krusch-stack.js` & `src/mcp/server.js`, `STATUS: FROZEN 2026-11-21T12:20:00-08:00`)**:
  - Mounts `POST /brick-exchange/{keygen,seal,verify,publish,grant,revoke,inbox,try,adopt,audit-locks,blast-radius,fanout,verify-blast-radius,ontology-inspect,ontology-check,ontology-compose,ontology-bind,stats}` while stripping internal/callback/authority keys (`viewerOrgId`, `nowMs`, `authorizedBricks`, `tryBrickFn`, `getAuthorizedBricksFn`, `invariantScript`, `repairFn`, `assertFn`, `__proto__`, `constructor`, `prototype`) on HTTP JSON payloads, stripping `nowMs`/callbacks + enforcing `assertPathWithinWorkspace` across both HTTP and MCP `dispatchStackTool`, capping `MAX_SEAL_CHECKS = 32` (`15s` aggregate wall-clock) on `sealBrick`, blocking cross-org `(brick_id, source_hash)` / `brick_id` ownership overwrites (`BRICK_ORG_CONFLICT`), checking `brick_exchange_grants` revocation on direct-bundle `adoptBrick`, sharing `src/engines/shared/js-code-scanner.js` + `src/engines/brick-exchange/seal-crypto.js` (zero circular ESM imports, single `BRICK_EXCHANGE_SCHEMA_SQL` source), requiring authenticated `viewerId` (`401`/`403`) on `POST /brick-exchange/ontology-compose`, and blocking inline `invariantScript` (`403`) on `POST /brick-exchange/verify-blast-radius` while keeping `ALL_STACK_TOOLS.length === 39` unchanged.

### Module Group G: Tier 2C HydraScope Structural Context Engine (`src/engines/hydrascope-engine.js`, `bin/krusch-stack.js`)
- **`src/engines/hydrascope-engine.js` (`krusch-stack/hydrascope`)**:
  - Exports `HYDRASCOPE_SCHEMA_SQL`, `FINTECH_BENCHMARK_CORPUS`, `HYDRASCOPE_BENCHMARK_SCENARIOS`, `compileArtifactsToHydraGraph`, `compileDirectoryToHydraGraph`, `createHydraScopeEngine({ db, workspaceRoot, brickExchange, hydraUrl, hydraToken, hydraGraphId })` returning `INV-STACK-02` envelopes:
    - `getState()`
    - `checkAnswerable({ query })`
    - `traverseContext({ query, asOf = null, tokenBudget = 900, maxHops = 3, includeBrickOntology = false, targetStack = null, targetChannel = null, requiredPorts = [] })`
    - `compareVectorVsGraph({ query, asOf = null, tokenBudget = 900, topK = 4 })`
    - `runBenchmark()`
    - `supersedeDecision({ oldId, newId, title, content, governsIds = [], effectiveAt })`
    - `ingestDirectory({ targetDir, allowExternalPaths = false })`
- **HTTP Gateway Contract (`bin/krusch-stack.js`)**:
  - Mounts `POST /hydrascope/{state,traverse,check-answerable,compare,benchmark,supersede,ingest}` (blocking external directory traversal over HTTP with `allowExternalPaths: false`) while preserving `ALL_STACK_TOOLS.length === 39`.

### Module Group H: Git Alignment, Sovereign ToolGraph & Polyglot Audit (`src/engines/git-alignment-engine.js`, `src/engines/tool-graph-engine.js`, `src/engines/polyglot-audit-engine.js`)
- **`src/engines/git-alignment-engine.js` (`krusch-stack/git-alignment`)**:
  - Exports `DEFAULT_COCHANGE_RULES`, `isUnifiedDiffText`, `parseUnifiedDiffFiles`, `parseCoChangeRuleDirective`, `extractMemoryCoChangeRules`, `evaluateCoChangeRules`, `findBlamedDiffMemories`, `scanSupersededStaleCode`, `detectLegoBoilerplateViolations`.
- **`src/engines/tool-graph-engine.js` (`krusch-stack/tool-graph`)**:
  - Exports `TOOL_GRAPH_SHARED_TYPES`, `extractGivenTypesFromTask`, `buildToolPrerequisiteGraph`, `createToolGraphEngine({ tools, pinnedToolNames, dispatcher, maxIntents })` returning `findTools`, `describeTool`, `callTool`, `reportOutcome`, `getExposedTools`, `exportState`, `importState`, `resetState`, `getStats`.
- **`src/engines/polyglot-audit-engine.js` (`krusch-stack/polyglot-audit`)**:
  - Exports `POLYGLOT_HAZARD_RULES`, `normalizeGitHubRepoInput`, `auditPolyglotSource`, `auditPolyglotRepository`, `createPolyglotAuditEngine({ workspaceRoot })`.

### Module Group I: Progressive Onboarding Demo, Decision Observability & Clean-Room Reproducer (`src/installer/demo.js`, `src/engines/observability-engine.js`, `scripts/reproduce_clean_room.js`)
- **`src/installer/demo.js` (`krusch-stack/demo`)**:
  - Exports `runStackDemo({ createStackFn } = {})` returning `{ ok: true, tool: 'krusch_stack_demo', summary: string, data: { duration_ms: number, zero_cloud_calls: true, acts: Array<{ act: number, title: string, passed: boolean, details: object }> } }`.
- **`src/engines/observability-engine.js` (`krusch-stack/observability`)**:
  - Exports `createObservabilityEngine({ db, workspaceRoot })` returning:
    - `getMetrics()`: Returns `{ ok: true, tool: 'krusch_observability_metrics', summary: string, data: { memory: { active, superseded, invalidated, stale_drift }, harness_2pc: { total_tasks, staged, applied, blocked_invariant, rejected, aborted, journals_rolled_back, journals_in_flight }, action_harness: { sessions, events, spin_loops_blocked, read_streaks_blocked, duplicate_writes_blocked, held_for_revision }, grounded_harness: { sessions, events, memoized_reads, spin_loops_blocked, output_defects_caught, policy_floor_blocks, duplicate_writes_blocked, turn0_duplicates_suppressed }, hitl_gates: { total, pending, approved, rejected } } }`.
    - `explainDecisions({ id, sessionId, limit = 10 } = {})`: Returns `{ ok: true, tool: 'krusch_observability_explain', summary: string, data: { filter: { id: string | null, session_id: string | null, limit: number }, count: number, decisions: Array<{ source: 'harness_2pc' | 'action_harness' | 'grounded_harness' | 'hitl_gate', id: string, session_id: string | null, target: string, decision: string, status: string, blocked: boolean, why: string, reasons: Array<string>, timestamp: string | number }> } }`.
- **`scripts/reproduce_clean_room.js`**:
  - Executable CLI & exportable `runCleanRoomReproduction({ includeCrashDrill = true } = {})` verifying deterministic memory/span-drift/lineage, 2PC `BLOCKED_INVARIANT` & `SIGKILL` journal rollback, `actionHarness` spin-loop & duplicate-write blocks, and `groundedHarness` Turn-0 CSV `"NA"` hazard + memoization + defect gate, outputting a deterministic SHA-256 verification receipt.
