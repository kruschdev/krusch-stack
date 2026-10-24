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
  - Supports optional 1024-dim dense embeddings in SQLite (`context_memories.embedding TEXT` with automatic `ALTER TABLE` migration), RM3 pseudo-relevance feedback, in-session episode kernel smoothing, 3-tier `prunePreSynthesis` (`680 / 440 / 320` char) progressive condensation, and `INV-12` span drift (`VALID`, `HEALED_LINE_SHIFT`, `STALE_DRIFT`).
- **`src/engines/git-engine.js`**:
  - Exports `createGitEngine({ db, workspaceRoot })` returning:
    - `listRepos()`
    - `readTree({ repo, path = "" })`
    - `readBlob({ repo, path, start_line, end_line })`
    - `searchSymbols({ repo, query, symbol_type })`
    - `fileSymbols({ repo, file_path })`
    - `dependencyGraph({ repo, symbol })`
    - `semanticSearch({ repo, query, limit = 10 })`
    - `indexRepo({ repoPath })`
  - Uses comment/string-masked AST brace matching (`INV-GIT-01`) to extract functions, classes, methods, exports, and markdown sections, plus inbound/outbound call edges.
- **`src/engines/fs-engine.js`**:
  - Exports `createFsEngine({ db, workspaceRoot })` returning:
    - `locate({ pattern = "*", category = "all", min_size_bytes = 0 })`
    - `search({ query, category = "all", limit = 10 })`
    - `pageTree({ path })`
    - `readPage({ path, page_number = 1 })`
    - `rememberOnPage({ path, page_number = 1, note, category = "annotation" })`
    - `sync({ paths = [] })`
  - Splits files into bounded structural pages (~80 lines/page or markdown heading boundaries), computes SHA-256 `page_hash`, and checks anchored page notes for `VALID` vs `STALE_DRIFT`.

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
