# KruschStack (`krusch-stack`) Agent Guide

> Last updated: 2026-11-21

## Safety & Invariants
- **SHA-256 Benchmark Pin (`CRITICAL`)**: Never modify `src/mcp/deferred-bridge.js` without re-pinning external BFCL v3 benchmark audit logs (`ALL_STACK_TOOLS.length === 39` must remain preserved alongside the 23 modular extension tools).
- **Zero-Leak Public Package (`dev.krusch/krusch-stack`)**: Never introduce private IPv4/IPv6 addresses, internal hostnames, absolute home directory paths, or unredacted credentials into tracked files.
- **Dual-Backend DDL Parity**: Any schema addition in `src/db/sqlite.js` must maintain parity in `src/db/postgres.js` (`21` tables).

## Quick Start
```bash
npm test                     # Run 92/92 unit & integration tests across 13 suites
npx krusch-stack demo        # Sub-second zero-cloud 3-act walkthrough
npx krusch-stack doctor      # Validate SQLite/PostgreSQL & profile configuration
npx krusch-stack serve       # Start HTTP gateway (:3780)
```

## Architecture (3-Layer Pattern)
1. **Transport (`bin/krusch-stack.js`, `src/mcp/`, `src/http/`)**: Progressive MCP stdio profiles (`memory-only` `5` tools, `coding-agent` `19` tools, `core` `27`, `full` `39`, plus `--defer-tools` BM25 bridge) and authenticated HTTP `:3780` server (`/health`, `/telemetry`, `/explain`).
2. **Domain (`src/engines/`, `src/installer/`)**: 10-pillar engines covering working memory, AST symbol & git-alignment graphs, OS page trees, 2PC diff staging, Turn-0 grounded sessions, HydraScope/Brick Ontology, ToolGraph composition, polyglot audits, and decision observability.
3. **Persistence (`src/db/sqlite.js`, `src/db/postgres.js`)**: Zero-config `node:sqlite` WAL + external-content Porter `FTS5` (`.krusch-stack/stack.db`) with optional PostgreSQL + `pgvector` sync.
