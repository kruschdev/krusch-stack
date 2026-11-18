# Contributing to `krusch-stack`

Thank you for your interest in contributing to `krusch-stack`! To keep the control plane fast, deterministic, and dependency-light, I maintain strict module boundaries and automated CI invariants across the repository. This guide shows how to verify your environment in seconds and work on a single subsystem without needing to learn all 10 pillars first.

---

## 1. Prerequisites

- **Node.js `>= 22.0.0`** (uses built-in `node:sqlite`, `node:test`, `node:assert/strict`, and `node:crypto`).
- **Zero Docker containers, zero C++ compilers, and zero cloud API keys** are required for local development or running the full test suite.

---

## 2. Quick Verification (`<15 Seconds`)

Run these commands from the repository root before and after making changes:

```bash
# 1. Clean deterministic install
npm ci

# 2. Run the full unit, integration, sanitization, and PostgreSQL DDL parity suite
npm test

# 3. Run the <1s 3-act offline walkthrough in an isolated temp directory
npm run demo

# 4. Run the clean-room benchmark gate & SHA-256 receipt verifier
npm run bench:repro

# 5. Run the 2-process SIGKILL mid-apply journal rollback self-test
node bin/krusch-stack.js doctor --crash-drill
```

To run a single test file while iterating:

```bash
node --test tests/krusch-stack.test.js
node --test tests/postgres-schema-parity.test.js
```

---

## 3. Repository Layout & Working on One Isolated Engine

You do **not** need to load or understand all 10 pillars to fix a bug or improve an engine. Every engine in `src/engines/*` is a pure factory function accepting a `node:sqlite` `DatabaseSync` handle:

```text
krusch-stack/
├── bin/krusch-stack.js          # Unified CLI (`init`, `mcp`, `doctor`, `demo`, `explain`, `route`, `serve`)
├── db/init.sql                  # 21-table PostgreSQL 16 + pgvector companion DDL (parity-tested)
├── docs/PRODUCTION.md           # Solo SQLite vs. Team PostgreSQL, telemetry, & failure recovery guide
├── scripts/                     # Clean-room reproducer (`reproduce_clean_room.js`) & parity scripts
├── src/
│   ├── index.js                 # Public programmatic factory (`createKruschStack`) & subpath re-exports
│   ├── db/sqlite.js             # `node:sqlite` WAL bootstrap, FTS5 migrations, & `okEnvelope`
│   ├── engines/                 # Isolated domain engines (work on one file at a time!)
│   ├── installer/               # `ide-config.js`, `doctor.js`, and `demo.js`
│   └── mcp/                     # `server.js` (profiles + 39 tools) & `deferred-bridge.js` (BM25 deferral)
└── tests/*.test.js              # Isolated Node 22 `node:test` suites
```

### Minimal Example: Testing One Engine in Isolation

```javascript
import { openStackDatabase } from './src/db/sqlite.js';
import { createContextEngine } from './src/engines/context-engine.js';

// Opens an ephemeral in-memory `:memory:` SQLite database with all 21 tables ready
const db = openStackDatabase({ ephemeral: true });
const context = createContextEngine({ db, workspaceRoot: process.cwd(), ephemeral: true });

const saved = context.remember({
  category: 'invariant',
  content: 'Always parameterize SQL queries.'
});
console.log(saved); // { ok: true, tool: 'krusch_context_remember', summary: '...', data: { ... } }
```

### Upstream Standalone Repositories

`krusch-stack` bundles standalone packages that also live in dedicated MIT repositories ([`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp), [`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness), [`grounded-harness`](https://github.com/kruschdev/grounded-harness), [`krusch-git`](https://github.com/kruschdev/krusch-git), [`HydraScope`](https://github.com/kruschdev/HydraScope), and [`toolkit`](https://github.com/kruschdev/toolkit)). Feel free to open an issue or PR here in `krusch-stack` or in the corresponding standalone repo; I keep parity synchronized across releases.

---

## 4. Non-Negotiable CI Invariants (`INV-STACK-01..15`)

Automated tests in `tests/` enforce the following architectural invariants on every pull request:

1. **Zero-Setup `node:sqlite` + 21-Table PostgreSQL Parity (`INV-STACK-01`)**:
   - Runtime storage must work out-of-the-box on Node 22 native `node:sqlite` without requiring PostgreSQL or Docker at startup.
   - Any table or index change in `src/db/sqlite.js` (or engine `*_SCHEMA_SQL` constants) **must** have exact 1:1 DDL and index parity in `db/init.sql`, verified by `tests/postgres-schema-parity.test.js`. Observability helpers (`src/engines/observability-engine.js`) query existing tables without inflating table count beyond `21`.
2. **Universal Return Envelope (`INV-STACK-02`)**:
   - Every engine method and MCP tool handler must return `{ ok: true, tool: '<name>', summary: '<human_summary>', data: { ... } }` on success, or `{ ok: false, tool: '<name>', summary: '<reason>', error: '<CODE>' }` on failure.
3. **MCP Tool Count & 4-Boolean Annotations (`INV-STACK-03`)**:
   - Every tool in `src/mcp/server.js` must define explicit boolean `annotations: { title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint }`.
   - **`ALL_STACK_TOOLS.length === 39` is locked** on the default unified MCP surface. New specialized capabilities belong on programmatic subpaths, HTTP gateway routes, or `--modular` / `--include-extended` extension servers (`MODULAR_EXTENSION_TOOLS`).
4. **Public Sanitization (`INV-STACK-04`)**:
   - Zero RFC 1918 private LAN IPs, Tailscale CGNAT IPs, internal hostnames, or private local OS user paths are permitted anywhere in source code, SQL migrations, tests, or markdown docs (`tests/krusch-stack.test.js` scans the entire repo tree). Always use `127.0.0.1`, `localhost`, or environment variables.
5. **Progressive Profiles & Core Engine Safety (`INV-STACK-05..15`)**:
   - Profile normalization (`memory-only` [5 tools], `coding-agent` [19 tools, default for `init`], `core` [27 tools], `full` [39 tools]), pre-disk 2PC staging (`INV-STACK-06`), external-content Porter `FTS5` triggers (`INV-STACK-07`), `.env` `KEYS_ONLY` secret redaction (`INV-STACK-08`), 2-hop call-graph score capping (`INV-STACK-09`), 2PC Action Harness (`INV-STACK-10`), Turn-0 Grounded Harness (`INV-STACK-11`), Ed25519 Brick Exchange (`INV-STACK-12`), HydraScope `asOf` lineage (`INV-STACK-13`), Git Alignment + ToolGraph (`INV-STACK-14`), and offline `demo` / `observability` / `bench:repro` (`INV-STACK-15`).
6. **Frozen Benchmark-Pinned Files (Do Not Reformat or Edit Casually)**:
   - **`src/mcp/deferred-bridge.js`** (pinned by SHA-256 in the `BFCL v3` clean-room verifier) and **`src/engines/action-harness-engine.js`** (pinned by SHA-256 in the `DABstep` clean-room verifier) are cryptographically attested in published benchmark bundles. Do not touch whitespace, comments, or code in those two files unless explicitly coordinating a new benchmark verification epoch.
7. **Documentation Style (`INV-SOLO-VOICE-01`)**:
   - Keep documentation direct, concrete, and honest about benchmark verification tiers. Write in singular first-person (`"I"`, `"my"`) or second-person (`"you"`, `"your"`), and use standard ASCII punctuation (`--`, `->`, colons, or parentheses) rather than em dashes.

---

## 5. Submitting Issues & Pull Requests

1. **Issues**: Include your OS, `node -v` output, `npx krusch-stack doctor --json` output, and minimal reproduction steps.
2. **Pull Requests**:
   - Keep each PR focused on a single concern (one engine fix, test addition, or documentation improvement).
   - Add regression tests in `tests/` covering both the happy path and failure/recovery cases.
   - Confirm `npm test`, `npm run demo`, and `npm run bench:repro` pass with zero errors before opening the PR.
