/**
 * @module installer/doctor
 * Diagnostic health check runner for KruschStack (`krusch-stack doctor`).
 * Verifies Node.js >=22 runtime, native `node:sqlite` schema readiness,
 * optional PostgreSQL (`DATABASE_URL`) configuration, local Ollama host defaults,
 * and active stack components.
 * Enforces INV-STACK-02 (return envelope) and INV-STACK-04 (sanitized localhost defaults).
 */

import path from 'node:path';
import { openStackDatabase, okEnvelope } from '../db/sqlite.js';

const REQUIRED_TABLES = [
  'context_memories',
  'git_repositories',
  'git_symbols',
  'git_edges',
  'fs_pages',
  'fs_page_memories',
  'harness_tasks',
  'frontend_design_rules',
  'workspace_files'
];

const ALL_COMPONENTS = [
  {
    id: 'context',
    name: 'krusch-context-mcp',
    tier: 'Tier 1',
    description: 'Working Memory, Invariants & Span-Grounded Drift Detection',
    core: true
  },
  {
    id: 'git',
    name: 'krusch-git',
    tier: 'Tier 2A',
    description: 'Codebase AST Symbols, Call Graph & Hybrid Search',
    core: true
  },
  {
    id: 'fs',
    name: 'krusch-fs',
    tier: 'Tier 2B',
    description: 'OS Filesystem Structural Pages & SHA-256 PageMemory',
    core: true
  },
  {
    id: 'harness',
    name: 'krusch-harness',
    tier: 'Tier 3',
    description: '2PC Staged Execution Harness & Invariant Gate',
    core: true
  },
  {
    id: 'router',
    name: 'krusch-cascade-router',
    tier: 'Router',
    description: 'Cognitive L1-L3 Task & Model Cascade Router',
    core: true
  },
  {
    id: 'frontend',
    name: 'krusch-frontend-mcp',
    tier: 'Tier 4',
    description: 'Frontend Design Rules, Color Palettes & Canonical Templates',
    core: false
  },
  {
    id: 'workspace',
    name: 'g-krusch',
    tier: 'Tier 5',
    description: 'Workspace Hub, Steering & Hybrid Document RAG',
    core: false
  }
];

/**
 * Execute a full diagnostic check across the KruschStack runtime and storage engines.
 * @param {object} [options]
 * @param {string} [options.workspaceRoot=process.cwd()]
 * @param {import('node:sqlite').DatabaseSync} [options.db]
 * @param {'core'|'full'} [options.profile='full']
 * @param {object} [options.engines]
 */
export function runStackDoctor({
  workspaceRoot = process.cwd(),
  db,
  profile = 'full'
} = {}) {
  const resolvedRoot = path.resolve(workspaceRoot);
  const normalizedProfile = profile === 'core' ? 'core' : 'full';

  const nodeVersion = process.versions.node;
  const majorVersion = Number(nodeVersion.split('.')[0] || 0);
  const nodeSupported = majorVersion >= 22;

  let sqliteReady = false;
  let tablesVerified = [];
  let ownedDb = null;

  try {
    const activeDb = db || (ownedDb = openStackDatabase({ workspaceRoot: resolvedRoot }));
    const ping = activeDb.prepare('SELECT 1 AS ok').get();
    const rows = activeDb
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all();
    const existingSet = new Set(rows.map((r) => r.name));
    tablesVerified = REQUIRED_TABLES.filter((t) => existingSet.has(t));
    sqliteReady = Boolean(ping && ping.ok === 1 && tablesVerified.length === REQUIRED_TABLES.length);
  } catch {
    sqliteReady = false;
  } finally {
    if (ownedDb) {
      try {
        ownedDb.close();
      } catch {
        // ignore close errors
      }
    }
  }

  const postgresConfigured = Boolean(
    process.env.DATABASE_URL || process.env.POSTGRES_URL
  );
  const ollamaHost = process.env.OLLAMA_HOST || 'http://127.0.0.1:11434';

  const selectedComponents = ALL_COMPONENTS.filter(
    (comp) => normalizedProfile === 'full' || comp.core
  ).map((comp) => ({
    id: comp.id,
    name: comp.name,
    tier: comp.tier,
    description: comp.description,
    ready: sqliteReady && nodeSupported,
    status: sqliteReady && nodeSupported ? 'ready' : 'degraded'
  }));

  const ok = nodeSupported && sqliteReady;
  const summary = `KruschStack Doctor: ${ok ? 'HEALTHY' : 'DEGRADED'} (Node v${nodeVersion}, SQLite=${sqliteReady ? 'ready' : 'error'}, Postgres=${postgresConfigured ? 'configured' : 'optional-unconfigured'}, profile=${normalizedProfile}, components=${selectedComponents.length}).`;

  const data = {
    node_version: nodeVersion,
    nodeVersion,
    node_supported: nodeSupported,
    nodeSupported,
    sqlite_ready: sqliteReady,
    sqliteReady,
    tables_verified: tablesVerified,
    postgres_configured: postgresConfigured,
    postgresConfigured,
    ollama_host: ollamaHost,
    ollamaHost,
    workspace_root: resolvedRoot,
    profile: normalizedProfile,
    components: selectedComponents
  };

  const envelope = okEnvelope('krusch_stack_doctor', summary, data, ok);

  return {
    ...envelope,
    nodeVersion,
    nodeSupported,
    sqliteReady,
    postgresConfigured,
    ollamaHost,
    profile: normalizedProfile,
    components: selectedComponents
  };
}
