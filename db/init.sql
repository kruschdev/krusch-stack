-- KruschStack PostgreSQL 16 + pgvector Initialization Schema
-- Mirrors src/db/sqlite.js with optional pgvector semantic embedding columns.

CREATE EXTENSION IF NOT EXISTS vector;

-- Tier 1: krusch-context-mcp Working Memory & Invariants
CREATE TABLE IF NOT EXISTS context_memories (
  id BIGSERIAL PRIMARY KEY,
  category TEXT NOT NULL CHECK (category IN ('decision', 'invariant', 'bug', 'lesson', 'blocker')),
  content TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded', 'invalidated')),
  superseded_by BIGINT REFERENCES context_memories(id),
  revocation_reason TEXT,
  provenance_file TEXT,
  provenance_locator TEXT,
  quoted_sentence TEXT,
  anchor_hash TEXT,
  embedding vector(1024),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_context_memories_status_cat
  ON context_memories(status, category);

-- Tier 2A: krusch-git AST Symbols & Call Graph
CREATE TABLE IF NOT EXISTS git_repositories (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  root_path TEXT NOT NULL,
  head_commit TEXT,
  indexed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS git_symbols (
  id BIGSERIAL PRIMARY KEY,
  repo_name TEXT NOT NULL,
  file_path TEXT NOT NULL,
  symbol_name TEXT NOT NULL,
  symbol_type TEXT NOT NULL,
  signature TEXT,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  symbol_hash TEXT NOT NULL,
  snippet TEXT,
  embedding vector(1024),
  UNIQUE (repo_name, file_path, symbol_name, start_line)
);

CREATE INDEX IF NOT EXISTS idx_git_symbols_lookup
  ON git_symbols(repo_name, symbol_name);

CREATE TABLE IF NOT EXISTS git_edges (
  id BIGSERIAL PRIMARY KEY,
  repo_name TEXT NOT NULL,
  from_file TEXT NOT NULL,
  from_symbol TEXT NOT NULL,
  to_symbol TEXT NOT NULL,
  edge_type TEXT NOT NULL DEFAULT 'calls'
);

CREATE INDEX IF NOT EXISTS idx_git_edges_from
  ON git_edges(repo_name, from_symbol);

CREATE INDEX IF NOT EXISTS idx_git_edges_to
  ON git_edges(repo_name, to_symbol);

-- Tier 2B: krusch-fs OS Filesystem Pages & Anchored PageMemory
CREATE TABLE IF NOT EXISTS fs_pages (
  id BIGSERIAL PRIMARY KEY,
  file_path TEXT NOT NULL,
  page_number INTEGER NOT NULL,
  section_title TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  page_hash TEXT NOT NULL,
  page_text TEXT NOT NULL,
  embedding vector(1024),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (file_path, page_number)
);

CREATE TABLE IF NOT EXISTS fs_page_memories (
  id BIGSERIAL PRIMARY KEY,
  file_path TEXT NOT NULL,
  page_number INTEGER NOT NULL,
  category TEXT NOT NULL DEFAULT 'annotation',
  note TEXT NOT NULL,
  anchored_page_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fs_page_memories_path
  ON fs_page_memories(file_path, page_number);

-- Tier 3: krusch-harness Staged 2PC Tasks
CREATE TABLE IF NOT EXISTS harness_tasks (
  task_id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'STAGED', 'BLOCKED_INVARIANT', 'APPLIED', 'REJECTED', 'ABORTED')),
  unified_diff TEXT NOT NULL DEFAULT '',
  files_json TEXT NOT NULL DEFAULT '[]',
  invariant_findings_json TEXT NOT NULL DEFAULT '[]',
  explanation TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tier 4: krusch-frontend-mcp Design Rules
CREATE TABLE IF NOT EXISTS frontend_design_rules (
  id BIGSERIAL PRIMARY KEY,
  rule_id TEXT NOT NULL UNIQUE,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  guidance TEXT NOT NULL,
  tokens_json TEXT NOT NULL DEFAULT '{}'
);

-- Tier 5: g-krusch Workspace Files & RAG
CREATE TABLE IF NOT EXISTS workspace_files (
  id BIGSERIAL PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  mime_type TEXT NOT NULL DEFAULT 'text/markdown',
  content TEXT NOT NULL,
  embedding vector(1024),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
