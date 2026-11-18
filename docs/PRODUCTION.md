# `krusch-stack` Production Operations, Multi-User Topology & Failure Recovery

This guide explains what `krusch-stack` runs locally out of the box on Node 22 `node:sqlite`, how teams deploy shared multi-user PostgreSQL 16 + HTTP gateway infrastructure, how to inspect agent decisions in real time, and how `krusch-stack` recovers deterministically from crashes, disk corruption, and timeouts.

---

## 1. Solo Local (`node:sqlite` WAL) vs. Multi-User / Team (`PostgreSQL 16 + pgvector`)

`krusch-stack` intentionally separates **single-developer local simplicity** from **shared multi-user team infrastructure** without diverging table schemas:

| Dimension | Solo Developer Workstation (`node:sqlite` WAL Default) | Multi-User / Team Deployment (`PostgreSQL 16 + pgvector` & Gateway) |
| :--- | :--- | :--- |
| **Target Workload** | Single developer running Claude Code, Cursor, Windsurf, Antigravity, or Codex against a local git checkout. | Multiple engineers or CI/SRE agents sharing organizational memory, Brick Exchange commons, and centralized 2PC audit logs. |
| **Storage Engine** | Built-in Node 22 `node:sqlite` (`DatabaseSync`) at `.krusch-stack/stack.db` (or `DB_PATH`). Zero external daemons. | PostgreSQL 16 + `pgvector` provisioned via `db/init.sql` (`21` tables + composite indexes) paired with pooled `DATABASE_URL` services. |
| **Concurrency Model** | `PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, `busy_timeout = 5000`, `foreign_keys = ON`. Concurrent local readers + serialized single-machine writers. | Full MVCC row-level locking via `DATABASE_URL` connection pools in standalone [`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp) and [`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness). |
| **Namespace Scoping** | Per-repo `.krusch-stack/stack.db` + `workspaceRoot` path containment (`assertPathWithinWorkspace`). | Explicit `workspace_name` / `repo_name` column scoping across all `21` tables + org-scoped `viewerId` grants in Brick Exchange. |
| **Network & Auth Perimeter** | Local `stdio` pipes only (zero open TCP ports). | Loopback/TLS-fronted HTTP gateway (`krusch-stack serve`) with SHA-256 `timingSafeEqual` Bearer auth + `Host`/`Origin` CSRF guards. |

### What Runs on `node:sqlite` Out of the Box

When you run `npx krusch-stack init` or `npx krusch-stack mcp`, `src/db/sqlite.js` opens `.krusch-stack/stack.db` in Write-Ahead Logging (`WAL`) mode with a `5,000ms` busy timeout. Multiple local IDE tabs (for example, an editor MCP session plus `npx krusch-stack explain` in a terminal) safely read and write against the same local file.

> **Filesystem Constraint**: Keep `.krusch-stack/stack.db` on a local POSIX/NVMe/SSD filesystem. Never place SQLite WAL files on network filesystems (`NFS`, `SMB`, or cloud-synced folders) where POSIX advisory locks can drop and corrupt WAL frames.

### Deploying Shared Multi-User / Team Infrastructure

For shared team environments, combine the 21-table `db/init.sql` schema, standalone PostgreSQL-pooled microservices, and hardened HTTP gateway settings:

1. **Provision the 21-Table PostgreSQL 16 + `pgvector` Schema**:
   `db/init.sql` maintains `100%` table, column, primary-key, foreign-key, and composite-index parity with `src/db/sqlite.js` (continuously verified by `tests/postgres-schema-parity.test.js`). When you want true multi-writer network concurrency across developer machines or CI runners, deploy standalone [`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp) (shared working memory + 1024-dim `pgvector` cosine search) and [`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness) (shared PostgreSQL 2PC task state machine) pointed at a shared `DATABASE_URL` pool alongside `db/init.sql`.
2. **Per-Project & Org-Scoped Isolation**:
   - **Workspace Scoping**: Multi-project tables (`git_repos`, `git_symbols`, `hydrascope_nodes`, `hydrascope_edges`, `harness_tasks`) partition rows by `repo_name` or `workspace_name`, preventing cross-repository symbol or ADR bleed.
   - **Org-Scoped Brick Exchange Grants**: `brick_exchange_bricks` and `brick_exchange_grants` enforce tiered visibility. On `POST /brick-exchange/*`, internal callback keys are stripped from JSON payloads, Ed25519 seals + signed `blueprint.ontology` hashes are verified (`TAMPERED_ONTOLOGY` rejection), inline `invariantScript` execution over HTTP is blocked, and `POST /brick-exchange/ontology-compose` requires an authenticated `viewerId` so cross-team bricks are only composed when an active non-revoked grant exists.
3. **Hardening `krusch-stack serve` (Auth, `Host`/`Origin` CSRF & Body Caps)**:
   When running the HTTP gateway (`npx krusch-stack serve` or `docker compose up -d`), configure these environment variables:
   ```bash
   export KRUSCH_STACK_HOST=127.0.0.1
   export KRUSCH_STACK_PORT=3780
   export KRUSCH_STACK_API_TOKEN="$(openssl rand -hex 32)"
   export KRUSCH_ALLOWED_HOSTS="127.0.0.1:3780,localhost:3780"
   export KRUSCH_MAX_BODY_BYTES=2097152
   ```
   - **Constant-Time Bearer Auth**: When `KRUSCH_STACK_API_TOKEN` is set, every protected route hashes both the configured secret and incoming `Authorization: Bearer <token>` header with `SHA-256` and compares the fixed 32-byte digests via `crypto.timingSafeEqual` (returning `401 UNAUTHORIZED` on mismatch without leaking token length).
   - **DNS-Rebinding & Browser CSRF Protection**: The gateway validates `Host` and `Origin` headers against `KRUSCH_ALLOWED_HOSTS` (loopback only by default) and requires `Content-Type: application/json` on every `POST` route (`415 UNSUPPORTED_MEDIA_TYPE` blocks HTML `<form>` CSRF).
   - **Bounded Memory Protection**: Requests exceeding `KRUSCH_MAX_BODY_BYTES` (`2 MiB` default) are rejected with `413 Payload Too Large`, and streaming sockets exceeding `maxBodyBytes + 64 KiB` are forcibly destroyed.

---

## 2. Observability & Debugging (`"Why Did the Agent Do That?"`)

When an agent refuses a file edit, skips a duplicate read, or blocks a stop attempt, you can inspect the exact deterministic rule that fired without digging through raw SQLite tables.

### Terminal Decision Inspector (`npx krusch-stack explain`)

```bash
# Show the 10 most recent control-plane decisions across 2PC, Action Harness, Grounded Gate & HITL
npx krusch-stack explain

# Inspect a specific 2PC task ID or Grounded/Action session ID
npx krusch-stack explain gh-001

# Emit machine-readable JSON for CI artifacts or jq filtering
npx krusch-stack explain --limit 10 --json
```

Each entry reports the timestamp, subsystem (`harness`, `action_harness`, `grounded_harness`, `context`, or `hitl`), decision verdict (`BLOCKED_INVARIANT`, `BLOCK_SPIN_LOOP`, `MEMOIZED_PRIOR_READ`, `HOLD_FOR_REVISION`, `REJECT_OUTPUT_DEFECT`, `APPLIED`), matched invariant or rule ID, and a bounded diff/argument preview.

### Structured Telemetry Endpoint (`GET /telemetry`)

Query `GET /telemetry` on a running `krusch-stack serve` instance (authenticated with `KRUSCH_STACK_API_TOKEN` if configured) to scrape zero-overhead SQLite control-plane counters:

```bash
curl -fsS -H "Authorization: Bearer $KRUSCH_STACK_API_TOKEN" \
  http://127.0.0.1:3780/telemetry
```

```json
{
  "ok": true,
  "tool": "krusch_observability_telemetry",
  "summary": "Control-plane telemetry snapshot collected",
  "data": {
    "counters": {
      "blocked_invariant": 3,
      "staged_2pc_commits": 14,
      "spin_loops_blocked": 7,
      "memoized_reads": 19,
      "output_defects_caught": 2,
      "active_memories": 42,
      "stale_drift": 1,
      "journals_rolled_back": 0
    }
  }
}
```

---

## 3. Failure Modes & Deterministic Recovery

### Failure Mode A: Interrupted 2PC Apply (`SIGKILL` / Power Loss / OOM Kill)

Multi-file agent edits fail catastrophically in naive tools when the process dies after writing file 2 of 4. `krusch-stack` prevents torn multi-file writes using a write-ahead apply journal (`harness_apply_journal`):

1. **Pre-Commit Journaling**: Before mutating any target file in `krusch_apply_diff`, `harness-engine.js` snapshots every target file's `existed_before` state, exact `before_content`, and SHA-256 digest into `harness_apply_journal` (`status = 'IN_FLIGHT'`).
2. **Sibling Staging & `fsync`**: New contents are written to `.krusch-tmp-<uuid>` sibling files in the same filesystem directory, flushed with `fsyncSync(fd)`, and swapped into place via POSIX atomic `renameSync`, followed by parent directory `fsyncDirectory`.
3. **Automatic Startup Rollback (`recoverInFlight`)**: Whenever `createKruschStack` or `createHarnessEngine` initializes after a hard crash, `harness.recoverInFlight()` scans `harness_apply_journal` for incomplete `IN_FLIGHT` records, restores every modified file to its exact pre-apply content (or unlinks newly created files), deletes any orphaned `.krusch-tmp-*` files, and marks the journal `ROLLED_BACK` (incrementing `journals_rolled_back` in `/telemetry`).

**Live Verification**: Test this mechanism safely in an isolated temp workspace at any time:

```bash
npx krusch-stack doctor --crash-drill
```

*(Spawns a child worker, triggers a multi-file 2PC apply, sends a real OS `SIGKILL` mid-commit, boots a second process, and asserts byte-for-byte rollback and zero orphan `.krusch-tmp-*` files.)*

### Failure Mode B: SQLite Store Corruption (`STORAGE_ERROR` Fail-Closed Mode)

If disk hardware errors, power loss on a faulty drive, or external file truncation corrupt `.krusch-stack/stack.db` or its `FTS5` shadow tables:

1. **Detection (`PRAGMA quick_check` & Error Classification)**: `runStackDoctor`, `context.health()`, and `isSqliteCorruptionError` detect `SQLITE_CORRUPT`, `SQLITE_NOTADB`, and malformed B-tree / `FTS5` pages via `PRAGMA quick_check`.
2. **Fail-Closed Epistemic Signaling**: Instead of catching the error and returning an empty `memories: []` array (which would trick an agent into thinking zero project invariants exist), `krusch-stack` fails closed and surfaces `ok: false` / `epistemic_status: "STORAGE_ERROR"` so the caller halts mutating actions immediately.
3. **Clean Recovery Procedure**:
   ```bash
   # 1. Stop active IDE MCP clients and back up the damaged file + WAL/SHM sidecars
   cp .krusch-stack/stack.db .krusch-stack/stack.db.corrupt.bak

   # 2. If only external-content FTS5 shadow indexes drifted, rebuild FTS5 from base tables:
   sqlite3 .krusch-stack/stack.db "INSERT INTO git_symbols_fts(git_symbols_fts) VALUES('rebuild'); INSERT INTO fs_pages_fts(fs_pages_fts) VALUES('rebuild'); INSERT INTO fs_page_memories_fts(fs_page_memories_fts) VALUES('rebuild');"

   # 3. If base B-tree pages are damaged, salvage intact rows with sqlite3 .recover:
   sqlite3 .krusch-stack/stack.db ".recover" | sqlite3 .krusch-stack/stack.recovered.db
   mv .krusch-stack/stack.recovered.db .krusch-stack/stack.db

   # 4. Re-verify schema migrations, triggers, and PRAGMA quick_check
   npx krusch-stack doctor
   ```

### Failure Mode C: Subprocess Timeouts, Context Overflow & Runaway Spend

1. **Timeout Partial-`stdout` Preservation (`execCommandWithPartialStdout`)**: When a sandboxed test suite or verification command exceeds its timeout, standard Node `execSync` discards buffered output or throws an opaque timeout error, causing agents to retry the exact same command blindly. `grounded-harness-engine.js` captures streaming buffers and formats a deterministic timeout diagnostic containing the partial `stdout`/`stderr` emitted prior to termination so the agent can diagnose the hang on the next turn.
2. **Pre-Flight Context Budgeting (`resilience.assembleContextBudget`)**: Enforces hard `maxContextTokens` and `outputReserveTokens` ceilings before prompt dispatch, paired with 3-tier progressive memory condensation (`680 -> 440 -> 320` chars) so long-running sessions never crash on context window overflow.
3. **Cost Kill-Switch & HITL Leases**: `stack.resilience` enforces a configurable trajectory cost ceiling (`$0.50` default kill-switch) to halt runaway frontier API loops, and supports 72-hour HMAC-SHA256 signed human-in-the-loop (`stack_hitl_gates`) approval leases for high-impact operations.
