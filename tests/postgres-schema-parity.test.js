import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { STACK_SCHEMA_SQL } from '../src/db/sqlite.js';
import { RESILIENCE_SCHEMA_SQL } from '../src/engines/resilience-engine.js';
import { GROUNDED_HARNESS_SCHEMA_SQL } from '../src/engines/grounded-harness-engine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const INIT_SQL_PATH = path.join(REPO_ROOT, 'db', 'init.sql');

const REQUIRED_POSTGRES_TABLES = [
  'context_memories',
  'git_repositories',
  'git_symbols',
  'git_edges',
  'fs_pages',
  'fs_page_memories',
  'harness_tasks',
  'harness_apply_journal',
  'frontend_design_rules',
  'workspace_files',
  'stack_hitl_gates',
  'stack_shadow_runs',
  'action_harness_sessions',
  'action_harness_events',
  'grounded_sessions',
  'grounded_events'
];

/**
 * Lex SQL text into semicolon-terminated statements while tracking single-quote
 * literals, line/block comments, and parenthesis balance.
 * @param {string} sqlText
 */
function parseSqlDocument(sqlText) {
  const statements = [];
  let current = '';
  let parenDepth = 0;
  let minParenDepth = 0;
  let inSingleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < sqlText.length; i += 1) {
    const ch = sqlText[i];
    const next = sqlText[i + 1] || '';

    if (inLineComment) {
      if (ch === '\n') {
        inLineComment = false;
        current += '\n';
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i += 1;
      }
      continue;
    }

    if (inSingleQuote) {
      current += ch;
      if (ch === "'" && next === "'") {
        current += next;
        i += 1;
      } else if (ch === "'") {
        inSingleQuote = false;
      }
      continue;
    }

    if (ch === '-' && next === '-') {
      inLineComment = true;
      i += 1;
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i += 1;
      continue;
    }

    if (ch === "'") {
      inSingleQuote = true;
      current += ch;
      continue;
    }

    if (ch === '(') {
      parenDepth += 1;
      current += ch;
      continue;
    }

    if (ch === ')') {
      parenDepth -= 1;
      if (parenDepth < minParenDepth) minParenDepth = parenDepth;
      current += ch;
      continue;
    }

    if (ch === ';' && parenDepth === 0) {
      const trimmed = current.trim();
      if (trimmed.length > 0) {
        statements.push(`${trimmed};`);
      }
      current = '';
      continue;
    }

    current += ch;
  }

  return {
    statements,
    unterminatedTrailing: current.trim(),
    finalParenDepth: parenDepth,
    minParenDepth,
    unclosedSingleQuote: inSingleQuote,
    unclosedBlockComment: inBlockComment
  };
}

/**
 * Split a parenthesized `CREATE TABLE (...)` body into top-level comma-delimited entries,
 * extracting column definitions (`name` -> normalized SQL clause) and table constraints.
 * @param {string} sqlText
 * @returns {Map<string, Map<string, string>>}
 */
function extractTableColumns(sqlText) {
  const { statements } = parseSqlDocument(sqlText);
  const tables = new Map();

  for (const stmt of statements) {
    const headerMatch = stmt.match(
      /^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([\s\S]*)\)\s*;$/i
    );
    if (!headerMatch) continue;

    const tableName = headerMatch[1];
    const body = headerMatch[2];
    const entries = [];
    let buf = '';
    let depth = 0;
    let inQuote = false;

    for (let i = 0; i < body.length; i += 1) {
      const ch = body[i];
      const next = body[i + 1] || '';
      if (inQuote) {
        buf += ch;
        if (ch === "'" && next === "'") {
          buf += next;
          i += 1;
        } else if (ch === "'") {
          inQuote = false;
        }
        continue;
      }
      if (ch === "'") {
        inQuote = true;
        buf += ch;
        continue;
      }
      if (ch === '(') depth += 1;
      else if (ch === ')') depth -= 1;

      if (ch === ',' && depth === 0) {
        if (buf.trim()) entries.push(buf.trim());
        buf = '';
      } else {
        buf += ch;
      }
    }
    if (buf.trim()) entries.push(buf.trim());

    const colMap = new Map();
    for (const entry of entries) {
      const normalized = entry.replace(/\s+/g, ' ').trim();
      if (/^(UNIQUE|PRIMARY\s+KEY|FOREIGN\s+KEY|CHECK|CONSTRAINT)\b/i.test(normalized)) {
        continue;
      }
      const colMatch = normalized.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s+([\s\S]+)$/);
      assert.ok(colMatch, `Malformed column definition in ${tableName}: ${normalized}`);
      colMap.set(colMatch[1], colMatch[2]);
    }
    tables.set(tableName, colMap);
  }

  return tables;
}

/**
 * Scan text for INV-STACK-04 private RFC1918/CGNAT IPs, internal hostnames, or OS home paths.
 * @param {string} content
 * @returns {string[]}
 */
function findSanitizationViolations(content) {
  const violations = [];
  const ipv4CandidateRe = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;

  for (const match of content.matchAll(ipv4CandidateRe)) {
    const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
    if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    const [o1, o2] = octets;
    const isRfc1918ClassA = o1 === 10;
    const isRfc1918ClassB = o1 === 172 && o2 >= 16 && o2 <= 31;
    const isRfc1918ClassC = o1 === 192 && o2 === 168;
    const isTailscaleCgnat = o1 === 100 && o2 >= 64 && o2 <= 127;
    if (isRfc1918ClassA || isRfc1918ClassB || isRfc1918ClassC || isTailscaleCgnat) {
      violations.push(`Private/Tailscale IPv4: ${match[0]}`);
    }
  }

  const forbiddenPatterns = [
    { label: 'private domain suffix', re: /\.(lan|local|internal|ts\.net)\b/i },
    { label: 'private fleet node hostname', re: /\bkrusch(?!stack\b)[a-z0-9]+\b/i },
    { label: 'tablet/mobile node hostname', re: /\b(crush\d+|[a-z]{2}\d+yoga)\b/i },
    { label: 'OS user home directory path', re: new RegExp('/' + '(?:home|Users)/[A-Za-z0-9._-]+') }
  ];

  for (const { label, re } of forbiddenPatterns) {
    const hit = content.match(re);
    if (hit) {
      violations.push(`${label}: ${hit[0]}`);
    }
  }

  return violations;
}

describe('PostgreSQL 16 + pgvector Schema Parity Suite (db/init.sql)', () => {
  const initSql = fs.readFileSync(INIT_SQL_PATH, 'utf-8');
  const parsed = parseSqlDocument(initSql);
  const pgTables = extractTableColumns(initSql);

  test('db/init.sql parses cleanly with balanced parentheses and semicolon-terminated CREATE TABLE IF NOT EXISTS statements', () => {
    assert.equal(parsed.unclosedSingleQuote, false, 'All SQL string literals must be closed');
    assert.equal(parsed.unclosedBlockComment, false, 'All SQL block comments must be closed');
    assert.equal(parsed.minParenDepth, 0, 'Parenthesis depth must never drop below zero');
    assert.equal(parsed.finalParenDepth, 0, 'Parentheses must be balanced across db/init.sql');
    assert.equal(parsed.unterminatedTrailing, '', 'Every SQL statement must terminate with ";"');
    assert.ok(parsed.statements.length >= 25, 'Expected extension, 14 tables, and index statements');

    assert.ok(
      parsed.statements.some((s) => /^CREATE\s+EXTENSION\s+IF\s+EXISTS\b/i.test(s) === false) &&
        parsed.statements.some((s) => /^CREATE\s+EXTENSION\s+IF\s+NOT\s+EXISTS\s+vector\s*;$/i.test(s)),
      'CREATE EXTENSION IF NOT EXISTS vector; must be present'
    );

    const createTableStmts = parsed.statements.filter((s) => /^CREATE\s+TABLE\b/i.test(s));
    assert.equal(createTableStmts.length, REQUIRED_POSTGRES_TABLES.length);

    for (const stmt of createTableStmts) {
      assert.match(
        stmt,
        /^CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+[a-z_][a-z0-9_]*\s*\([\s\S]+\)\s*;$/i,
        `CREATE TABLE statement must use IF NOT EXISTS and terminate with ");": ${stmt.slice(0, 60)}`
      );

      let localDepth = 0;
      let inQuote = false;
      for (let i = 0; i < stmt.length; i += 1) {
        const ch = stmt[i];
        if (ch === "'" && stmt[i + 1] === "'") {
          i += 1;
          continue;
        }
        if (ch === "'") {
          inQuote = !inQuote;
          continue;
        }
        if (!inQuote && ch === '(') localDepth += 1;
        if (!inQuote && ch === ')') localDepth -= 1;
        assert.ok(localDepth >= 0, `Unbalanced ")" inside statement: ${stmt.slice(0, 60)}`);
      }
      assert.equal(localDepth, 0, `Unbalanced "(" inside statement: ${stmt.slice(0, 60)}`);
    }

    const createIndexStmts = parsed.statements.filter((s) => /^CREATE\s+INDEX\b/i.test(s));
    assert.ok(createIndexStmts.length >= 12, 'Expected HNSW and B-tree indexes in db/init.sql');
    for (const stmt of createIndexStmts) {
      const idxMatch = stmt.match(
        /^CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+([a-z_][a-z0-9_]*)\s+ON\s+([a-z_][a-z0-9_]*)\b[\s\S]*;$/i
      );
      assert.ok(idxMatch, `CREATE INDEX must use IF NOT EXISTS and end with ";": ${stmt}`);
      assert.ok(
        pgTables.has(idxMatch[2]),
        `Index ${idxMatch[1]} references undefined table ${idxMatch[2]}`
      );
    }
  });

  test('All 16 core, journal, resilience, INV-STACK-10 action-harness, and INV-STACK-11 grounded-harness tables and indexes match SQLite parity', () => {
    for (const tableName of REQUIRED_POSTGRES_TABLES) {
      assert.ok(pgTables.has(tableName), `Missing required PostgreSQL table: ${tableName}`);
    }
    assert.equal(pgTables.size, REQUIRED_POSTGRES_TABLES.length);

    // 1. Cross-check all SQLite STACK_SCHEMA_SQL tables (including harness_apply_journal)
    const sqliteCoreTables = extractTableColumns(STACK_SCHEMA_SQL);
    for (const [tableName, sqliteCols] of sqliteCoreTables.entries()) {
      const pgCols = pgTables.get(tableName);
      assert.ok(pgCols, `SQLite table ${tableName} missing from db/init.sql`);
      for (const colName of sqliteCols.keys()) {
        assert.ok(
          pgCols.has(colName),
          `Column ${tableName}.${colName} from src/db/sqlite.js missing in db/init.sql`
        );
      }
    }

    // Verify harness_apply_journal exact Postgres types & CHECK constraint
    const journalCols = pgTables.get('harness_apply_journal');
    assert.equal(journalCols.get('task_id'), 'TEXT PRIMARY KEY');
    assert.match(
      journalCols.get('state'),
      /^TEXT NOT NULL CHECK\s*\(\s*state IN \('APPLYING', 'APPLIED', 'ROLLED_BACK', 'RECOVERY_PENDING'\)\s*\)$/
    );
    assert.equal(journalCols.get('entries_json'), "TEXT NOT NULL DEFAULT '[]'");
    assert.equal(journalCols.get('last_error'), 'TEXT');
    assert.equal(journalCols.get('created_at'), 'TIMESTAMPTZ NOT NULL DEFAULT NOW()');
    assert.equal(journalCols.get('updated_at'), 'TIMESTAMPTZ NOT NULL DEFAULT NOW()');

    // 2. Cross-check RESILIENCE_SCHEMA_SQL tables (BIGINT for integer *_ms, DOUBLE PRECISION for REAL)
    const sqliteResilienceTables = extractTableColumns(RESILIENCE_SCHEMA_SQL);
    for (const [tableName, sqliteCols] of sqliteResilienceTables.entries()) {
      const pgCols = pgTables.get(tableName);
      assert.ok(pgCols, `Resilience table ${tableName} missing from db/init.sql`);
      assert.deepEqual([...pgCols.keys()], [...sqliteCols.keys()]);
    }

    const hitlCols = pgTables.get('stack_hitl_gates');
    assert.equal(hitlCols.get('gate_id'), 'TEXT PRIMARY KEY');
    assert.equal(hitlCols.get('created_at_ms'), 'BIGINT NOT NULL');
    assert.equal(hitlCols.get('expires_at_ms'), 'BIGINT NOT NULL');
    assert.equal(hitlCols.get('decided_at_ms'), 'BIGINT');

    const shadowCols = pgTables.get('stack_shadow_runs');
    assert.equal(shadowCols.get('comparison_id'), 'TEXT PRIMARY KEY');
    assert.equal(shadowCols.get('sequence_similarity'), 'DOUBLE PRECISION NOT NULL');
    assert.equal(shadowCols.get('exact_dag_match'), 'INTEGER NOT NULL');
    assert.equal(shadowCols.get('latency_delta_ms'), 'DOUBLE PRECISION NOT NULL');
    assert.equal(shadowCols.get('cost_delta_usd'), 'DOUBLE PRECISION NOT NULL');
    assert.equal(shadowCols.get('created_at_ms'), 'BIGINT NOT NULL');

    // 3. Verify INV-STACK-10 2PC Tool-Action Harness tables & indexes
    const sessionCols = pgTables.get('action_harness_sessions');
    assert.deepEqual(
      [...sessionCols.entries()],
      [
        ['session_id', 'TEXT PRIMARY KEY'],
        ['persona', "TEXT NOT NULL DEFAULT ''"],
        ['goal', 'TEXT NOT NULL'],
        ['anchor_date', "TEXT NOT NULL DEFAULT ''"],
        ['status', "TEXT NOT NULL DEFAULT 'ACTIVE'"],
        ['max_identical_reads', 'INTEGER NOT NULL DEFAULT 1'],
        ['max_duplicate_writes', 'INTEGER NOT NULL DEFAULT 1'],
        ['max_read_streak', 'INTEGER NOT NULL DEFAULT 6'],
        ['max_verify_nudges', 'INTEGER NOT NULL DEFAULT 1'],
        ['enforce_context_nudge', 'INTEGER NOT NULL DEFAULT 0'],
        ['consecutive_app_reads', 'INTEGER NOT NULL DEFAULT 0'],
        ['committed_reads', 'INTEGER NOT NULL DEFAULT 0'],
        ['committed_mutations', 'INTEGER NOT NULL DEFAULT 0'],
        ['verify_nudges_used', 'INTEGER NOT NULL DEFAULT 0'],
        ['created_at_ms', 'BIGINT NOT NULL'],
        ['updated_at_ms', 'BIGINT NOT NULL']
      ]
    );

    const eventCols = pgTables.get('action_harness_events');
    assert.deepEqual(
      [...eventCols.entries()],
      [
        ['event_id', 'TEXT PRIMARY KEY'],
        ['session_id', 'TEXT NOT NULL'],
        ['step', 'INTEGER NOT NULL DEFAULT 0'],
        ['tool_name', 'TEXT NOT NULL'],
        ['is_mutating', 'INTEGER NOT NULL DEFAULT 0'],
        ['is_memory_search', 'INTEGER NOT NULL DEFAULT 0'],
        ['canonical_args_json', 'TEXT NOT NULL'],
        ['call_signature', 'TEXT NOT NULL'],
        ['decision', 'TEXT NOT NULL'],
        ['status', 'TEXT NOT NULL'],
        ['issues_json', "TEXT NOT NULL DEFAULT '[]'"],
        ['result_preview', "TEXT NOT NULL DEFAULT ''"],
        ['created_at_ms', 'BIGINT NOT NULL'],
        ['updated_at_ms', 'BIGINT NOT NULL']
      ]
    );

    // 4. Cross-check INV-STACK-11 Grounded Harness tables & types
    const sqliteGroundedTables = extractTableColumns(GROUNDED_HARNESS_SCHEMA_SQL);
    for (const [tableName, sqliteCols] of sqliteGroundedTables.entries()) {
      const pgCols = pgTables.get(tableName);
      assert.ok(pgCols, `Grounded harness table ${tableName} missing from db/init.sql`);
      assert.deepEqual([...pgCols.keys()], [...sqliteCols.keys()]);
    }

    const groundedSessionCols = pgTables.get('grounded_sessions');
    assert.equal(groundedSessionCols.get('session_id'), 'TEXT PRIMARY KEY');
    assert.equal(
      groundedSessionCols.get('schema_reduction_pct'),
      'DOUBLE PRECISION NOT NULL DEFAULT 0'
    );
    assert.equal(groundedSessionCols.get('created_at_ms'), 'BIGINT NOT NULL');
    assert.equal(groundedSessionCols.get('updated_at_ms'), 'BIGINT NOT NULL');

    const groundedEventCols = pgTables.get('grounded_events');
    assert.equal(groundedEventCols.get('event_id'), 'TEXT PRIMARY KEY');
    assert.equal(groundedEventCols.get('created_at_ms'), 'BIGINT NOT NULL');
    assert.equal(groundedEventCols.get('updated_at_ms'), 'BIGINT NOT NULL');

    const requiredIndexes = [
      ['idx_stack_hitl_gates_task_status', 'stack_hitl_gates', '(task_id, status)'],
      ['idx_stack_shadow_runs_request', 'stack_shadow_runs', '(request_id, created_at_ms)'],
      ['idx_action_harness_events_sig', 'action_harness_events', '(session_id, call_signature)'],
      ['idx_action_harness_events_session_time', 'action_harness_events', '(session_id, created_at_ms)'],
      ['idx_grounded_events_sig', 'grounded_events', '(session_id, call_signature)'],
      ['idx_grounded_events_session_time', 'grounded_events', '(session_id, created_at_ms)']
    ];

    for (const [idxName, tblName, colTuple] of requiredIndexes) {
      const matchingIdx = parsed.statements.find(
        (s) =>
          s.includes(idxName) &&
          s.includes(`ON ${tblName}`) &&
          s.replace(/\s+/g, ' ').includes(colTuple)
      );
      assert.ok(matchingIdx, `Expected index ${idxName} ON ${tblName}${colTuple} in db/init.sql`);
    }
  });

  test('INV-STACK-04: Zero private LAN/Tailscale IPs, internal hostnames, or OS user paths exist in db/init.sql', () => {
    const sqlViolations = findSanitizationViolations(initSql);
    assert.deepEqual(
      sqlViolations,
      [],
      `Expected zero INV-STACK-04 violations in db/init.sql, found: ${sqlViolations.join('; ')}`
    );

    const selfTestSource = fs.readFileSync(__filename, 'utf-8');
    const selfViolations = findSanitizationViolations(selfTestSource);
    assert.deepEqual(
      selfViolations,
      [],
      `Expected zero INV-STACK-04 violations in test file, found: ${selfViolations.join('; ')}`
    );
  });
});
