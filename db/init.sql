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

CREATE INDEX IF NOT EXISTS idx_context_memories_embedding_hnsw ON context_memories USING hnsw (embedding vector_cosine_ops);

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

CREATE INDEX IF NOT EXISTS idx_git_symbols_embedding_hnsw ON git_symbols USING hnsw (embedding vector_cosine_ops);

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

CREATE INDEX IF NOT EXISTS idx_fs_pages_embedding_hnsw ON fs_pages USING hnsw (embedding vector_cosine_ops);

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

-- Tier 3: krusch-harness Staged 2PC Tasks & Durable Apply Journal
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

CREATE TABLE IF NOT EXISTS harness_apply_journal (
  task_id TEXT PRIMARY KEY,
  state TEXT NOT NULL CHECK (state IN ('APPLYING', 'APPLIED', 'ROLLED_BACK', 'RECOVERY_PENDING')),
  entries_json TEXT NOT NULL DEFAULT '[]',
  last_error TEXT,
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

CREATE INDEX IF NOT EXISTS idx_workspace_files_embedding_hnsw ON workspace_files USING hnsw (embedding vector_cosine_ops);

-- Resilience Engine: Async HITL Lease Gates & Non-Blocking Shadow Runs
CREATE TABLE IF NOT EXISTS stack_hitl_gates (
  gate_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  summary TEXT NOT NULL,
  staged_payload TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms BIGINT NOT NULL,
  expires_at_ms BIGINT NOT NULL,
  decided_at_ms BIGINT,
  reviewer TEXT,
  decision_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_stack_hitl_gates_task_status
  ON stack_hitl_gates(task_id, status);

CREATE TABLE IF NOT EXISTS stack_shadow_runs (
  comparison_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  primary_model TEXT NOT NULL,
  shadow_model TEXT NOT NULL,
  sequence_similarity DOUBLE PRECISION NOT NULL,
  exact_dag_match INTEGER NOT NULL,
  latency_delta_ms DOUBLE PRECISION NOT NULL,
  cost_delta_usd DOUBLE PRECISION NOT NULL,
  created_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stack_shadow_runs_request
  ON stack_shadow_runs(request_id, created_at_ms);

-- INV-STACK-10: 2PC Tool-Action Harness, Trajectory Spin-Loop Guard & Verify-on-Stop Gate
CREATE TABLE IF NOT EXISTS action_harness_sessions (
  session_id TEXT PRIMARY KEY,
  persona TEXT NOT NULL DEFAULT '',
  goal TEXT NOT NULL,
  anchor_date TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  max_identical_reads INTEGER NOT NULL DEFAULT 1,
  max_duplicate_writes INTEGER NOT NULL DEFAULT 1,
  max_read_streak INTEGER NOT NULL DEFAULT 6,
  max_verify_nudges INTEGER NOT NULL DEFAULT 1,
  enforce_context_nudge INTEGER NOT NULL DEFAULT 0,
  consecutive_app_reads INTEGER NOT NULL DEFAULT 0,
  committed_reads INTEGER NOT NULL DEFAULT 0,
  committed_mutations INTEGER NOT NULL DEFAULT 0,
  verify_nudges_used INTEGER NOT NULL DEFAULT 0,
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_harness_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  step INTEGER NOT NULL DEFAULT 0,
  tool_name TEXT NOT NULL,
  is_mutating INTEGER NOT NULL DEFAULT 0,
  is_memory_search INTEGER NOT NULL DEFAULT 0,
  canonical_args_json TEXT NOT NULL,
  call_signature TEXT NOT NULL,
  decision TEXT NOT NULL,
  status TEXT NOT NULL,
  issues_json TEXT NOT NULL DEFAULT '[]',
  result_preview TEXT NOT NULL DEFAULT '',
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_action_harness_events_sig
  ON action_harness_events(session_id, call_signature);

CREATE INDEX IF NOT EXISTS idx_action_harness_events_session_time
  ON action_harness_events(session_id, created_at_ms);

-- INV-STACK-11: Turn-0 Grounded, Scale-Aware, Defect-Only Harness (INV-GH-01..12)
CREATE TABLE IF NOT EXISTS grounded_sessions (
  session_id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  model TEXT NOT NULL DEFAULT '',
  scale_tier TEXT NOT NULL,
  scale_profile_json TEXT NOT NULL,
  anchor_date TEXT NOT NULL DEFAULT '',
  prefix_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  max_duplicate_writes INTEGER NOT NULL DEFAULT 1,
  seen_chunks_json TEXT NOT NULL DEFAULT '[]',
  file_digests_json TEXT NOT NULL DEFAULT '{}',
  allowed_scopes_json TEXT NOT NULL DEFAULT '[]',
  drift_state_json TEXT NOT NULL DEFAULT '{}',
  schema_tokens_saved INTEGER NOT NULL DEFAULT 0,
  schema_reduction_pct DOUBLE PRECISION NOT NULL DEFAULT 0,
  turn0_tokens INTEGER NOT NULL DEFAULT 0,
  exploratory_reads INTEGER NOT NULL DEFAULT 0,
  committed_reads INTEGER NOT NULL DEFAULT 0,
  committed_mutations INTEGER NOT NULL DEFAULT 0,
  memoized_reads INTEGER NOT NULL DEFAULT 0,
  spin_loops_blocked INTEGER NOT NULL DEFAULT 0,
  output_defects_caught INTEGER NOT NULL DEFAULT 0,
  timeouts_with_partial_stdout INTEGER NOT NULL DEFAULT 0,
  turn0_duplicates_suppressed INTEGER NOT NULL DEFAULT 0,
  duplicate_writes_blocked INTEGER NOT NULL DEFAULT 0,
  policy_floor_blocks INTEGER NOT NULL DEFAULT 0,
  auth_drift_holds INTEGER NOT NULL DEFAULT 0,
  dart_repairs_applied INTEGER NOT NULL DEFAULT 0,
  dart_holds INTEGER NOT NULL DEFAULT 0,
  truncation_recoveries INTEGER NOT NULL DEFAULT 0,
  verify_nudges_used INTEGER NOT NULL DEFAULT 0,
  pending_diffs_count INTEGER NOT NULL DEFAULT 0,
  latest_verification_passed INTEGER NOT NULL DEFAULT 1,
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS grounded_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  step INTEGER NOT NULL DEFAULT 0,
  tool_name TEXT NOT NULL,
  is_mutating INTEGER NOT NULL DEFAULT 0,
  is_foraging INTEGER NOT NULL DEFAULT 0,
  canonical_args_json TEXT NOT NULL,
  call_signature TEXT NOT NULL,
  decision TEXT NOT NULL,
  status TEXT NOT NULL,
  issues_json TEXT NOT NULL DEFAULT '[]',
  result_preview TEXT NOT NULL DEFAULT '',
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_grounded_events_sig
  ON grounded_events(session_id, call_signature);

CREATE INDEX IF NOT EXISTS idx_grounded_events_session_time
  ON grounded_events(session_id, created_at_ms);
