# KruschStack (`krusch-stack`) — Specification

> **Repository**: `https://github.com/kruschdev/krusch-stack.git`
> **Version**: `1.0.0`
> **Runtime**: Node.js `>=22.0.0` (Native ESM + `node:sqlite`) & Docker Compose (`pgvector/pgvector:pg16`)
> **License**: MIT

---

## 1. Overview

**KruschStack** (`krusch-stack`) is the unified, single-install distribution of the Krusch Sovereign AI & Coding Agent Ecosystem. Instead of manually installing, configuring, and wiring 7 separate repositories across IDEs and databases, developers can install the entire stack with a single `npx` command or `docker compose up -d`:

1. **Tier 1 — Working Memory & Invariants (`krusch-context-mcp`)**: `retrieve`, `remember`, `revise`, `nudge`, `health` with `INV-12` span-grounded drift detection.
2. **Tier 2A — Codebase AST & Git DAG (`krusch-git`)**: `list_repos`, `read_tree`, `read_blob`, `search_symbols`, `file_symbols`, `dependency_graph`, `semantic_search`.
3. **Tier 2B — OS Filesystem & Page-Anchored Memory (`krusch-fs`)**: `locate`, `search`, `page_tree`, `read_page`, `remember_on_page`, `sync` with SHA-256 page drift tracking (`VALID` vs `STALE_DRIFT`).
4. **Tier 3 — 2PC Staged Execution Harness (`krusch-harness`)**: `run`, `task_status`, `diff`, `apply_diff`, `explain`, `reject`, `abort` — stages unified diffs, enforces invariants, and verifies before touching the working tree.
5. **Frontend Design & Styling Engine (`krusch-frontend-mcp`)**: `generate_color_palette`, `css_to_tailwind`, `query_design_rules`, `get_canonical_template`, `list_canonical_templates`, `generate_responsive_breakpoints`.
6. **Workspace Hub & Hybrid RAG (`g-krusch`)**: `get_agent_steering`, `search_drive_rag`, `read_drive_file`, `write_drive_file`, `list_drive_workspace`, `get_workspace_status`.
7. **Cognitive Model Router (`krusch-cascade-router`)**: `krusch_route_task` & `krusch_stack_status` — `<25µs` L1 heuristic fast-path + L2/L3 model escalation across local Ollama and cloud APIs.

---

## 2. Architectural Invariants

- **`INV-STACK-01` (Zero-Setup Local SQLite Default + Optional PostgreSQL Upgrade)**: Every engine in `krusch-stack` operates out-of-the-box with zero external dependencies using Node 22 native `node:sqlite` (`.krusch-stack/stack.db` or in-memory `:memory:` when `KRUSCH_EPHEMERAL=1`), and upgrades to `pgvector/pgvector:pg16` when `DATABASE_URL` is configured.
- **`INV-STACK-02` (Universal Return Envelope)**: Every engine function and MCP tool payload returns a deterministic JSON envelope `{ ok: boolean, tool: string, summary: string, data: object }` serialized as JSON text inside the MCP `content` array.
- **`INV-STACK-03` (4-Boolean MCP Tool Annotations — Memory #567)**: Every registered MCP tool in `src/mcp/server.js` MUST explicitly declare `annotations: { title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint }` as booleans and ship with a root MIT `LICENSE` file.
- **`INV-STACK-04` (Public Sanitization — Memory #594)**: Zero internal homelab hostnames, private LAN/Tailscale IPs (`192.168.x.x`, `10.10.10.x`, `100.x.x.x`), or private OS usernames in any source file, test, `docker-compose.yml`, or documentation. All defaults use `127.0.0.1` / `localhost` or environment variables.
- **`INV-STACK-05` (Profile Filtering)**: The MCP server and IDE installer support `--profile core` (Tiers 1, 2A, 2B, 3 + Router) and `--profile full` (all 7 pillars including Frontend MCP and G-Krusch Workspace Hub, default `full`), plus granular `--components <csv>`.
- **`INV-STACK-06` (2PC Staged Harness Safety)**: `krusch_run` stages file modifications as unified diffs in SQLite/PostgreSQL and evaluates active `invariant` memories via `nudge` before transitioning to `STAGED`. Working tree files are only mutated when `krusch_apply_diff` is explicitly called on a `STAGED` task.
- **`INV-STACK-07` (External-Content Porter `FTS5` & Lazy Top-K Hydration)**: `ensureStackSchemaMigrations(db)` in `src/db/sqlite.js` idempotently provisions SQLite external-content Porter `FTS5` virtual tables (`git_symbols_fts`, `fs_pages_fts`, `fs_page_memories_fts` with `tokenize='porter unicode61'`), `AFTER INSERT`/`DELETE`/`UPDATE` synchronization triggers using raw `old.<col>` and `new.<col>` column references (never `coalesce` on `'delete'`), and one-time `'rebuild'` backfill when legacy base tables contain rows with an empty `*_fts_docsize` shadow table. Tier 2A (`semanticSearch`) and Tier 2B (`search`) evaluate candidate metadata + `FTS5` `bm25(...)` ranks first and lazily hydrate full `snippet` / `page_text` payloads only for the Top-K winning rows.
- **`INV-STACK-08` (Tier 2B `.env` `KEYS_ONLY` Redaction & Pre-Write Secret Shield)**: `src/engines/fs-engine.js` redacts sensitive `.env` and `.env.*` file values (`KEY=[REDACTED]`, excluding `.env.example`, `.env.sample`, `.env.template`, `.env.schema`, `.env.dist`) via `redactEnvSecrets` before computing SHA-256 `page_hash` or storing `fs_pages.page_text`, and blocks raw API keys, tokens, PEM private keys, and inline URL passwords in `rememberOnPage` via `scanForSecretLeak(text)` before SQLite insertion while permitting `[REDACTED]` placeholders.
- **`INV-STACK-09` (Tier 2A 2-Hop `git_edges` Call-Graph Bridging & Token/Identifier Telemetry)**: `semanticSearch` in `src/engines/git-engine.js` expands Top-3 Hop-1 symbol hits across 1-hop `git_edges` callers/callees when multi-term queries (`>= 2` distinctive tokens) leave at least one query token uncovered, capping bridged symbol scores strictly at `Math.min(topHop1Score * 0.84, Math.max(0.01, topHop1Score - 0.01))` (`bridge_hop: true`, `bridge_via`), and both `krusch_git_semantic_search` and `krusch_fs_search` accept optional `limit_tokens` while reporting `unattested_query_identifiers` / `unattested_query_terms` (`string[]`) without altering `ALL_STACK_TOOLS.length === 39`.

---

## 3. Frozen Module Contracts (Subagent Boundaries)

### Module Group A — Tiers 1 & 2 Engines (`src/engines/context-engine.js`, `src/engines/git-engine.js`, `src/engines/fs-engine.js`)
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

### Module Group B — Tier 3, Frontend, Workspace & Router Engines (`src/engines/harness-engine.js`, `src/engines/frontend-engine.js`, `src/engines/workspace-engine.js`, `src/engines/router-engine.js`)
- **`src/engines/harness-engine.js`**:
  - Exports `createHarnessEngine({ db, workspaceRoot, contextEngine })` returning:
    - `run({ goal, files = [], test_command })`
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
  - Exports `createRouterEngine({ config })` returning:
    - `routeTask({ prompt, task_type, budget_tier })`
    - `getStackStatus({ engines })`

### Module Group C — Installer, Doctor & Docker (`src/installer/ide-config.js`, `src/installer/doctor.js`, `Dockerfile`, `docker-compose.yml`, `db/init.sql`)
- **`src/installer/ide-config.js`**:
  - Exports `generateIdeConfig({ ide = "all", mode = "unified", profile = "full", workspaceRoot })` and `writeIdeConfigs({ targetDir, ide, mode, profile })`.
  - Supports Claude Code (`.mcp.json`), Cursor (`.cursor/mcp.json`), Windsurf (`mcp_config.json`), and Antigravity (`mcp_config.json`).
- **`src/installer/doctor.js`**:
  - Exports `runStackDoctor({ workspaceRoot, engines })` returning structured health report `{ ok, nodeVersion, sqliteReady, postgresConfigured, ollamaHost, components, summary }`.
- **`Dockerfile`, `docker-compose.yml`, `db/init.sql`**:
  - Multi-container stack with `pgvector/pgvector:pg16` (`postgres`) and `krusch-stack` gateway service on port `3780`.
