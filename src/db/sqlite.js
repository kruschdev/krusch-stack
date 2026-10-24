/**
 * @module db/sqlite
 * Zero-dependency Node 22 native SQLite (node:sqlite) database manager for KruschStack.
 * Enforces INV-STACK-01: Works out-of-the-box with local SQLite (.krusch-stack/stack.db)
 * or in-memory (:memory:) when KRUSCH_EPHEMERAL=1.
 */

import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

export const STACK_SCHEMA_SQL = `
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;

  -- Tier 1: krusch-context-mcp Working Memory & Invariants
  CREATE TABLE IF NOT EXISTS context_memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL CHECK(category IN ('decision', 'invariant', 'bug', 'lesson', 'blocker')),
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'superseded', 'invalidated')),
    superseded_by INTEGER,
    revocation_reason TEXT,
    provenance_file TEXT,
    provenance_locator TEXT,
    quoted_sentence TEXT,
    anchor_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_context_memories_status_cat ON context_memories(status, category);

  -- Tier 2A: krusch-git AST Symbols & Call Graph
  CREATE TABLE IF NOT EXISTS git_repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    root_path TEXT NOT NULL,
    head_commit TEXT,
    indexed_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS git_symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    symbol_name TEXT NOT NULL,
    symbol_type TEXT NOT NULL,
    signature TEXT,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    symbol_hash TEXT NOT NULL,
    snippet TEXT,
    UNIQUE(repo_name, file_path, symbol_name, start_line)
  );

  CREATE INDEX IF NOT EXISTS idx_git_symbols_lookup ON git_symbols(repo_name, symbol_name);

  CREATE TABLE IF NOT EXISTS git_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_name TEXT NOT NULL,
    from_file TEXT NOT NULL,
    from_symbol TEXT NOT NULL,
    to_symbol TEXT NOT NULL,
    edge_type TEXT NOT NULL DEFAULT 'calls'
  );

  CREATE INDEX IF NOT EXISTS idx_git_edges_from ON git_edges(repo_name, from_symbol);
  CREATE INDEX IF NOT EXISTS idx_git_edges_to ON git_edges(repo_name, to_symbol);

  -- Tier 2B: krusch-fs OS Filesystem Pages & Anchored PageMemory
  CREATE TABLE IF NOT EXISTS fs_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    page_number INTEGER NOT NULL,
    section_title TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    page_hash TEXT NOT NULL,
    page_text TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(file_path, page_number)
  );

  CREATE TABLE IF NOT EXISTS fs_page_memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    page_number INTEGER NOT NULL,
    category TEXT NOT NULL DEFAULT 'annotation',
    note TEXT NOT NULL,
    anchored_page_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_fs_page_memories_path ON fs_page_memories(file_path, page_number);

  -- Tier 3: krusch-harness Staged 2PC Tasks
  CREATE TABLE IF NOT EXISTS harness_tasks (
    task_id TEXT PRIMARY KEY,
    goal TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'STAGED', 'BLOCKED_INVARIANT', 'APPLIED', 'REJECTED', 'ABORTED')),
    unified_diff TEXT NOT NULL DEFAULT '',
    files_json TEXT NOT NULL DEFAULT '[]',
    invariant_findings_json TEXT NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Tier 4: krusch-frontend-mcp Design Rules
  CREATE TABLE IF NOT EXISTS frontend_design_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    guidance TEXT NOT NULL,
    tokens_json TEXT NOT NULL DEFAULT '{}'
  );

  -- Tier 5: g-krusch Workspace Files & RAG
  CREATE TABLE IF NOT EXISTS workspace_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    mime_type TEXT NOT NULL DEFAULT 'text/markdown',
    content TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`;

/**
 * Open or initialize a KruschStack SQLite database instance.
 * @param {object} [options]
 * @param {string} [options.workspaceRoot]
 * @param {string} [options.dbPath]
 * @param {boolean} [options.ephemeral]
 * @returns {DatabaseSync}
 */
export function openStackDatabase(options = {}) {
  const ephemeral = Boolean(options.ephemeral || process.env.KRUSCH_EPHEMERAL === '1');
  if (ephemeral || options.dbPath === ':memory:') {
    const memDb = new DatabaseSync(':memory:');
    memDb.exec('PRAGMA busy_timeout = 5000;');
    memDb.exec('PRAGMA foreign_keys = ON;');
    memDb.exec(STACK_SCHEMA_SQL);
    return memDb;
  }

  const workspaceRoot = path.resolve(options.workspaceRoot || process.cwd());
  const resolvedPath = options.dbPath
    ? path.resolve(options.dbPath)
    : path.join(workspaceRoot, '.krusch-stack', 'stack.db');

  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
  let db = new DatabaseSync(resolvedPath);
  try {
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec('PRAGMA foreign_keys = ON;');
    const check = db.prepare('PRAGMA quick_check;').get();
    if (check && check.quick_check && check.quick_check !== 'ok') {
      throw new Error(`SQLite quick_check failed: ${check.quick_check}`);
    }
    db.exec(STACK_SCHEMA_SQL);
  } catch (corruptErr) {
    try {
      db.close();
    } catch {}
    const backupSuffix = `.corrupt.${Date.now()}`;
    for (const ext of ['', '-wal', '-shm']) {
      if (fs.existsSync(`${resolvedPath}${ext}`)) {
        try {
          fs.renameSync(`${resolvedPath}${ext}`, `${resolvedPath}${ext}${backupSuffix}`);
        } catch {}
      }
    }
    db = new DatabaseSync(resolvedPath);
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec('PRAGMA foreign_keys = ON;');
    db.exec(STACK_SCHEMA_SQL);
  }
  return db;
}

/**
 * Format a standard INV-STACK-02 return envelope.
 * @param {string} tool
 * @param {string} summary
 * @param {object} data
 * @param {boolean} [ok=true]
 */
export function okEnvelope(tool, summary, data = {}, ok = true) {
  return {
    ok: Boolean(ok),
    tool,
    summary,
    data
  };
}
