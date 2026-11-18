/**
 * @module engines/observability-engine
 * Structured Decision Observability & "Why Did The Agent Do That?" Explainer (`INV-STACK-15`).
 * Aggregates metrics and chronological decision explanations across existing SQLite tables
 * (`context_memories`, `harness_tasks`, `harness_apply_journal`, `action_harness_sessions`,
 * `action_harness_events`, `grounded_sessions`, `grounded_events`, `stack_hitl_gates`)
 * without adding new DDL tables (preserving 21-table SQLite/PostgreSQL parity and 39 MCP tools).
 *
 * Enforces INV-STACK-01 (zero external npm dependencies), INV-STACK-02 (okEnvelope),
 * and INV-STACK-04 (zero private IPs or hostnames).
 */

import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

const AUTH_DRIFT_ISSUE_RE =
  /AUTH|DRIFT|SCOPE|OVERCOLLECTION|CREDENTIAL|EXFILTRATION|TRAVERSAL|SERS/i;

/**
 * Safely execute a `.all()` SQLite query, returning `[]` if the table is absent or empty.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sql
 * @param {Array<any>} [params=[]]
 * @returns {Array<object>}
 */
function safeAll(db, sql, params = []) {
  if (!db || typeof db.prepare !== 'function') return [];
  try {
    return db.prepare(sql).all(...params);
  } catch {
    return [];
  }
}

/**
 * Safely execute a `.get()` SQLite query, returning `null` if the table is absent.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} sql
 * @param {Array<any>} [params=[]]
 * @returns {object | null}
 */
function safeGet(db, sql, params = []) {
  if (!db || typeof db.prepare !== 'function') return null;
  try {
    return db.prepare(sql).get(...params) ?? null;
  } catch {
    return null;
  }
}

/**
 * Parse a JSON array string safely.
 *
 * @param {unknown} raw
 * @returns {Array<any>}
 */
function safeParseArray(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * Normalize an integer millisecond timestamp or SQLite UTC datetime string to epoch ms for sorting.
 *
 * @param {unknown} rawTs
 * @returns {{ timestamp: string | number, sortMs: number }}
 */
function normalizeTimestamp(rawTs) {
  if (typeof rawTs === 'number' && Number.isFinite(rawTs)) {
    return { timestamp: rawTs, sortMs: rawTs };
  }
  const str = String(rawTs ?? '').trim();
  if (!str) {
    return { timestamp: 0, sortMs: 0 };
  }
  if (/^\d+$/.test(str)) {
    const num = Number(str);
    return { timestamp: num, sortMs: Number.isFinite(num) ? num : 0 };
  }
  const isoCandidate = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(str)
    ? `${str.replace(' ', 'T')}Z`
    : str;
  const parsedMs = Date.parse(isoCandidate);
  return {
    timestamp: str,
    sortMs: Number.isFinite(parsedMs) ? parsedMs : 0
  };
}

/**
 * Determine whether a decision or status represents a blocked, held, rejected, aborted, or rolled-back gate.
 *
 * @param {string} decision
 * @param {string} status
 * @returns {boolean}
 */
export function isBlockedDecision(decision, status) {
  const matchesPrefix = (val) => {
    const upper = String(val || '').trim().toUpperCase();
    return (
      upper.startsWith('BLOCK') ||
      upper.startsWith('HOLD') ||
      upper === 'HELD' ||
      upper.startsWith('REJECT') ||
      upper.startsWith('ABORT') ||
      upper.startsWith('ROLLED_BACK')
    );
  };
  return matchesPrefix(decision) || matchesPrefix(status);
}

/**
 * Fallback span-drift counter when `contextEngine.health()` is not wired.
 *
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {string} workspaceRoot
 * @returns {number}
 */
function countFallbackStaleDrift(db, workspaceRoot) {
  if (!workspaceRoot) return 0;
  const rootDir = path.resolve(workspaceRoot);
  const rows = safeAll(
    db,
    `SELECT provenance_file, quoted_sentence
     FROM context_memories
     WHERE status = 'active' AND provenance_file IS NOT NULL AND provenance_file != ''`
  );
  let drifted = 0;
  for (const row of rows) {
    const rel = String(row.provenance_file || '').trim();
    if (!rel) continue;
    const abs = path.resolve(rootDir, rel);
    if (abs !== rootDir && !abs.startsWith(rootDir + path.sep)) continue;
    try {
      const content = fs.readFileSync(abs, 'utf8');
      const quoted = String(row.quoted_sentence || '').trim();
      if (quoted && !content.includes(quoted)) {
        drifted += 1;
      }
    } catch {
      drifted += 1;
    }
  }
  return drifted;
}

/**
 * Format structured issue objects into concise reason strings.
 *
 * @param {Array<any>} issues
 * @returns {Array<string>}
 */
function formatIssueReasons(issues) {
  const out = [];
  for (const item of issues) {
    if (!item) continue;
    if (typeof item === 'string') {
      out.push(item);
      continue;
    }
    if (typeof item === 'object') {
      const code = item.code || item.invariant_id || item.category || '';
      const field = item.field && item.field !== '*' ? `[${item.field}] ` : '';
      const msg = item.message || item.rule || item.detail || item.error || '';
      if (code && msg) {
        out.push(`${code}: ${field}${msg}`);
      } else if (msg) {
        out.push(`${field}${msg}`);
      } else if (code) {
        out.push(String(code));
      }
    }
  }
  return out;
}

/**
 * Derive a specific canonical decision code and human-readable explanation for a `grounded_events` row.
 *
 * @param {object} row
 * @param {Array<object>} rawIssues
 * @param {Array<string>} reasons
 * @returns {{ decision: string, why: string }}
 */
function classifyGroundedEvent(row, rawIssues, reasons) {
  const rawDecision = String(row.decision || '').trim().toUpperCase();
  const tool = String(row.tool_name || 'tool');
  const isMutating = Number(row.is_mutating) === 1;
  const preview = String(row.result_preview || '');
  const codes = rawIssues.map((iss) => String(iss?.code || '')).filter(Boolean);
  const firstCode = codes[0] || '';

  if (rawDecision === 'MEMOIZED' || rawDecision === 'MEMOIZED_PRIOR_READ' || rawDecision === 'ALREADY_GROUNDED_TURN_ZERO') {
    if (rawDecision === 'ALREADY_GROUNDED_TURN_ZERO' || /Turn 0/i.test(preview)) {
      return {
        decision: 'ALREADY_GROUNDED_TURN_ZERO',
        why: `Suppressed redundant read of ${tool} because the file was already grounded at Turn 0 with an identical SHA-256 digest.`
      };
    }
    return {
      decision: 'MEMOIZED_PRIOR_READ',
      why: `Reused memoized result for ${tool} because no mutating call occurred since the identical prior read.`
    };
  }

  if (rawDecision === 'BLOCK' || rawDecision.startsWith('BLOCK_')) {
    if (
      rawDecision === 'BLOCK_POLICY_FLOOR' ||
      codes.includes('POLICY_FLOOR_DESTRUCTIVE_COMMAND') ||
      codes.includes('SECRET_LEAK_BLOCKED')
    ) {
      return {
        decision: 'BLOCK_POLICY_FLOOR',
        why: `Blocked ${tool} at the frozen policy floor (${firstCode || 'policy violation'})${reasons[0] ? `: ${reasons[0]}` : '.'}`
      };
    }
    if (rawDecision === 'BLOCK_AUTH_DRIFT' || codes.some((c) => AUTH_DRIFT_ISSUE_RE.test(c))) {
      return {
        decision: 'BLOCK_AUTH_DRIFT',
        why: `Blocked ${tool} due to authorization or scope drift (${firstCode || 'unattested sensitive scope'}).`
      };
    }
    if (rawDecision === 'BLOCK_DUPLICATE_WRITE' || (rawDecision === 'BLOCK' && isMutating)) {
      return {
        decision: 'BLOCK_DUPLICATE_WRITE',
        why: `Blocked duplicate mutating call to ${tool} with identical canonical arguments to prevent repeated side effects.`
      };
    }
    return {
      decision: 'BLOCK_SPIN_LOOP',
      why: `Blocked repeated read call to ${tool} after an identical prior call failed or already memoized with zero intervening mutations.`
    };
  }

  if (rawDecision === 'HOLD' || rawDecision.startsWith('HOLD_')) {
    if (rawDecision === 'HOLD_DART_BOUNDARY' || codes.some((c) => /DART|CLI_/i.test(c))) {
      return {
        decision: 'HOLD_DART_BOUNDARY',
        why: `Held ${tool} at the DART MCP-vs-CLI realization boundary until malformed flags or stringified null identifiers are repaired.`
      };
    }
    if (rawDecision === 'HOLD_AUTH_DRIFT' || codes.some((c) => AUTH_DRIFT_ISSUE_RE.test(c))) {
      return {
        decision: 'HOLD_AUTH_DRIFT',
        why: `Held ${tool} for SERS data-minimization or scope alignment (${firstCode || 'scope drift'}).`
      };
    }
    if (codes.some((c) => /LOOP|ECHO/i.test(c))) {
      return {
        decision: `HOLD_${firstCode || 'SPIN_LOOP'}`,
        why: `Held ${tool} after detecting a repetitive command loop (${firstCode}).`
      };
    }
    return {
      decision: rawDecision === 'HOLD' ? 'HOLD_SMALL_MODEL_ARGS' : rawDecision,
      why: `Held ${tool} before execution so unresolved placeholders or malformed date arguments can be revised.`
    };
  }

  if (rawDecision.startsWith('REJECT')) {
    return {
      decision: rawDecision,
      why: `Rejected stop output for ${tool} due to detected output defect${reasons[0] ? ` (${reasons[0]})` : '.'}`
    };
  }

  if (rawDecision === 'ALLOW' || rawDecision === 'ALLOW_READ' || rawDecision === 'ALLOW_MUTATION') {
    const allowDecision = isMutating ? 'ALLOW_MUTATION' : 'ALLOW_READ';
    return {
      decision: allowDecision,
      why: `Allowed ${isMutating ? 'mutating' : 'read-only'} call to ${tool} (outcome status: ${row.status || 'STAGED'}).`
    };
  }

  return {
    decision: rawDecision || 'UNKNOWN',
    why: `Recorded ${rawDecision || 'event'} on ${tool} (status: ${row.status || 'UNKNOWN'}).`
  };
}

/**
 * Create the SQLite-backed Decision Observability Engine (`INV-STACK-15`).
 *
 * @param {object} [options={}]
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 * @param {{ health?: () => any } | null} [options.contextEngine=null]
 */
export function createObservabilityEngine({
  db,
  workspaceRoot = process.cwd(),
  contextEngine = null
} = {}) {
  if (!db || typeof db.prepare !== 'function') {
    throw new Error('createObservabilityEngine requires a valid Node 22 SQLite DatabaseSync instance.');
  }

  /**
   * Aggregate structured telemetry counters across memory, 2PC harness, action harness,
   * grounded harness, and HITL lease gates without mutating any state.
   */
  function getMetrics() {
    const memCounts = { active: 0, superseded: 0, invalidated: 0, stale_drift: 0 };
    for (const row of safeAll(db, 'SELECT status, COUNT(*) AS cnt FROM context_memories GROUP BY status')) {
      if (row.status === 'active') memCounts.active = Number(row.cnt || 0);
      else if (row.status === 'superseded') memCounts.superseded = Number(row.cnt || 0);
      else if (row.status === 'invalidated') memCounts.invalidated = Number(row.cnt || 0);
    }
    if (typeof contextEngine?.health === 'function') {
      try {
        const healthRes = contextEngine.health();
        memCounts.stale_drift = Number(
          healthRes?.data?.drifted ?? healthRes?.data?.drifted_count ?? 0
        );
      } catch {
        memCounts.stale_drift = countFallbackStaleDrift(db, workspaceRoot);
      }
    } else {
      memCounts.stale_drift = countFallbackStaleDrift(db, workspaceRoot);
    }

    const harness2pc = {
      total_tasks: 0,
      staged: 0,
      applied: 0,
      blocked_invariant: 0,
      rejected: 0,
      aborted: 0,
      journals_rolled_back: 0,
      journals_in_flight: 0
    };
    for (const row of safeAll(db, 'SELECT status, COUNT(*) AS cnt FROM harness_tasks GROUP BY status')) {
      const cnt = Number(row.cnt || 0);
      harness2pc.total_tasks += cnt;
      if (row.status === 'STAGED') harness2pc.staged = cnt;
      else if (row.status === 'APPLIED') harness2pc.applied = cnt;
      else if (row.status === 'BLOCKED_INVARIANT') harness2pc.blocked_invariant = cnt;
      else if (row.status === 'REJECTED') harness2pc.rejected = cnt;
      else if (row.status === 'ABORTED') harness2pc.aborted = cnt;
    }
    for (const row of safeAll(db, 'SELECT state, COUNT(*) AS cnt FROM harness_apply_journal GROUP BY state')) {
      const cnt = Number(row.cnt || 0);
      if (row.state === 'ROLLED_BACK') harness2pc.journals_rolled_back += cnt;
      else if (row.state === 'APPLYING' || row.state === 'RECOVERY_PENDING') {
        harness2pc.journals_in_flight += cnt;
      }
    }

    const ahSessRow = safeGet(db, 'SELECT COUNT(*) AS cnt FROM action_harness_sessions');
    const ahEvtRow = safeGet(
      db,
      `SELECT
         COUNT(*) AS events,
         COALESCE(SUM(CASE WHEN decision = 'BLOCK_SPIN_LOOP' THEN 1 ELSE 0 END), 0) AS spin_loops_blocked,
         COALESCE(SUM(CASE WHEN decision = 'BLOCK_READ_STREAK' THEN 1 ELSE 0 END), 0) AS read_streaks_blocked,
         COALESCE(SUM(CASE WHEN decision = 'BLOCK_DUPLICATE_WRITE' THEN 1 ELSE 0 END), 0) AS duplicate_writes_blocked,
         COALESCE(SUM(CASE WHEN decision = 'HOLD_FOR_REVISION' THEN 1 ELSE 0 END), 0) AS held_for_revision
       FROM action_harness_events`
    );
    const actionHarness = {
      sessions: Number(ahSessRow?.cnt || 0),
      events: Number(ahEvtRow?.events || 0),
      spin_loops_blocked: Number(ahEvtRow?.spin_loops_blocked || 0),
      read_streaks_blocked: Number(ahEvtRow?.read_streaks_blocked || 0),
      duplicate_writes_blocked: Number(ahEvtRow?.duplicate_writes_blocked || 0),
      held_for_revision: Number(ahEvtRow?.held_for_revision || 0)
    };

    const ghSessAgg = safeGet(
      db,
      `SELECT
         COUNT(*) AS sessions,
         COALESCE(SUM(memoized_reads), 0) AS memoized_reads,
         COALESCE(SUM(spin_loops_blocked), 0) AS spin_loops_blocked,
         COALESCE(SUM(output_defects_caught), 0) AS output_defects_caught,
         COALESCE(SUM(policy_floor_blocks), 0) AS policy_floor_blocks,
         COALESCE(SUM(duplicate_writes_blocked), 0) AS duplicate_writes_blocked,
         COALESCE(SUM(turn0_duplicates_suppressed), 0) AS turn0_duplicates_suppressed
       FROM grounded_sessions`
    );
    const ghEvtRows = safeAll(
      db,
      'SELECT decision, is_mutating, issues_json, result_preview FROM grounded_events'
    );
    let evMemoized = 0;
    let evSpin = 0;
    let evPolicy = 0;
    let evDupWrite = 0;
    let evTurn0 = 0;
    let evDefects = 0;
    for (const ev of ghEvtRows) {
      const classified = classifyGroundedEvent(ev, safeParseArray(ev.issues_json), []);
      if (classified.decision === 'ALREADY_GROUNDED_TURN_ZERO') evTurn0 += 1;
      else if (classified.decision === 'MEMOIZED_PRIOR_READ') evMemoized += 1;
      else if (classified.decision === 'BLOCK_SPIN_LOOP') evSpin += 1;
      else if (classified.decision === 'BLOCK_POLICY_FLOOR' || classified.decision === 'BLOCK_AUTH_DRIFT') {
        evPolicy += 1;
      } else if (classified.decision === 'BLOCK_DUPLICATE_WRITE') evDupWrite += 1;
      else if (classified.decision.startsWith('REJECT')) evDefects += 1;
    }

    const groundedHarness = {
      sessions: Number(ghSessAgg?.sessions || 0),
      events: ghEvtRows.length,
      memoized_reads: Math.max(Number(ghSessAgg?.memoized_reads || 0), evMemoized),
      spin_loops_blocked: Math.max(Number(ghSessAgg?.spin_loops_blocked || 0), evSpin),
      output_defects_caught: Math.max(Number(ghSessAgg?.output_defects_caught || 0), evDefects),
      policy_floor_blocks: Math.max(Number(ghSessAgg?.policy_floor_blocks || 0), evPolicy),
      duplicate_writes_blocked: Math.max(Number(ghSessAgg?.duplicate_writes_blocked || 0), evDupWrite),
      turn0_duplicates_suppressed: Math.max(
        Number(ghSessAgg?.turn0_duplicates_suppressed || 0),
        evTurn0
      )
    };

    const hitlGates = { total: 0, pending: 0, approved: 0, rejected: 0 };
    for (const row of safeAll(db, 'SELECT status, COUNT(*) AS cnt FROM stack_hitl_gates GROUP BY status')) {
      const cnt = Number(row.cnt || 0);
      const st = String(row.status || '').toUpperCase();
      hitlGates.total += cnt;
      if (st === 'PENDING' || st === 'PENDING_APPROVAL') hitlGates.pending += cnt;
      else if (st === 'APPROVED') hitlGates.approved += cnt;
      else if (st === 'REJECTED' || st === 'DENIED') hitlGates.rejected += cnt;
    }

    const totalBlocks =
      harness2pc.blocked_invariant +
      actionHarness.spin_loops_blocked +
      actionHarness.read_streaks_blocked +
      actionHarness.duplicate_writes_blocked +
      groundedHarness.spin_loops_blocked +
      groundedHarness.policy_floor_blocks +
      groundedHarness.output_defects_caught;

    return okEnvelope(
      'krusch_observability_metrics',
      `Observability metrics: ${memCounts.active} active memories (${memCounts.stale_drift} drifted), ${harness2pc.total_tasks} 2PC tasks, ${totalBlocks} safety/loop interventions.`,
      {
        memory: memCounts,
        harness_2pc: harness2pc,
        action_harness: actionHarness,
        grounded_harness: groundedHarness,
        hitl_gates: hitlGates
      }
    );
  }

  /**
   * Answer "Why did the agent do or refuse that?" across 2PC tasks, action-harness trajectories,
   * grounded-harness guardrails, and HITL gates.
   *
   * @param {object} [options={}]
   * @param {string} [options.id]
   * @param {string} [options.sessionId]
   * @param {number} [options.limit=10]
   * @param {boolean} [options.onlyBlocked=false]
   */
  function explainDecisions({
    id,
    sessionId,
    limit = 10,
    onlyBlocked = false
  } = {}) {
    const filterId = typeof id === 'string' && id.trim() ? id.trim() : null;
    const filterSessionId =
      typeof sessionId === 'string' && sessionId.trim() ? sessionId.trim() : null;
    const filterOnlyBlocked = Boolean(onlyBlocked);
    const boundedLimit = Math.max(1, Math.min(100, Math.trunc(Number(limit) || 10)));

    const collected = [];

    // 1. Tier 3A 2PC Harness Tasks + Crash Recovery Journal (`harness_tasks` LEFT JOIN `harness_apply_journal`)
    let taskRows = [];
    if (filterId) {
      taskRows = safeAll(
        db,
        `SELECT t.*, j.state AS journal_state, j.last_error AS journal_error, j.updated_at AS journal_updated_at
         FROM harness_tasks t
         LEFT JOIN harness_apply_journal j ON j.task_id = t.task_id
         WHERE t.task_id = ?`,
        [filterId]
      );
    } else if (filterSessionId) {
      taskRows = safeAll(
        db,
        `SELECT t.*, j.state AS journal_state, j.last_error AS journal_error, j.updated_at AS journal_updated_at
         FROM harness_tasks t
         LEFT JOIN harness_apply_journal j ON j.task_id = t.task_id
         WHERE t.task_id = ?`,
        [filterSessionId]
      );
    } else {
      taskRows = safeAll(
        db,
        `SELECT t.*, j.state AS journal_state, j.last_error AS journal_error, j.updated_at AS journal_updated_at
         FROM harness_tasks t
         LEFT JOIN harness_apply_journal j ON j.task_id = t.task_id
         ORDER BY t.rowid DESC
         LIMIT 200`
      );
    }

    for (const row of taskRows) {
      const filesRaw = safeParseArray(row.files_json);
      const fileNames = filesRaw
        .map((f) => (typeof f === 'string' ? f : f?.file_path))
        .filter(Boolean);
      const target = fileNames.length > 0 ? fileNames.join(', ') : String(row.goal || row.task_id);
      const findings = safeParseArray(row.invariant_findings_json);
      const reasons = formatIssueReasons(findings);

      const journalRolledBack = row.journal_state === 'ROLLED_BACK';
      if (row.journal_error) {
        reasons.push(`journal_error: ${row.journal_error}`);
      } else if (journalRolledBack) {
        reasons.push('journal_state: ROLLED_BACK (atomic preimage restored)');
      }

      const decision = journalRolledBack ? 'ROLLED_BACK' : String(row.status || 'UNKNOWN');
      const status = String(row.status || 'UNKNOWN');

      let why = String(row.explanation || '').trim();
      if (journalRolledBack) {
        why = `Task "${row.goal}" (${target}) rolled back via durable apply journal${row.journal_error ? ` after fault: ${row.journal_error}` : ' to preserve atomic working-tree state.'}`;
      } else if (status === 'BLOCKED_INVARIANT') {
        why = `Refused to stage "${row.goal}" (${target}) because ${findings.length || 1} active invariant check(s) failed${reasons[0] ? ` (${reasons[0]})` : '.'}`;
      } else if (status === 'STAGED' && !why) {
        why = `Staged unified diff for "${row.goal}" (${target}) cleanly in SQLite without mutating disk.`;
      } else if (status === 'APPLIED' && !why) {
        why = `Atomically applied ${fileNames.length || 1} staged file(s) (${target}) to workspace.`;
      } else if (!why) {
        why = `2PC task "${row.goal}" (${target}) recorded status ${status}.`;
      }

      if (reasons.length === 0 && isBlockedDecision(decision, status) && row.explanation) {
        reasons.push(String(row.explanation));
      }

      const ts = normalizeTimestamp(row.journal_updated_at || row.updated_at || row.created_at);
      collected.push({
        source: 'harness_2pc',
        id: String(row.task_id),
        session_id: null,
        target,
        decision,
        status,
        blocked: isBlockedDecision(decision, status),
        why,
        reasons,
        timestamp: ts.timestamp,
        _sortMs: ts.sortMs
      });
    }

    // 2. 2PC Tool-Action Harness Events (`action_harness_events`)
    let ahRows = [];
    if (filterId && filterSessionId) {
      ahRows = safeAll(
        db,
        `SELECT * FROM action_harness_events
         WHERE (event_id = ? OR session_id = ?) AND session_id = ?
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`,
        [filterId, filterId, filterSessionId]
      );
    } else if (filterId) {
      ahRows = safeAll(
        db,
        `SELECT * FROM action_harness_events
         WHERE event_id = ? OR session_id = ?
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`,
        [filterId, filterId]
      );
    } else if (filterSessionId) {
      ahRows = safeAll(
        db,
        `SELECT * FROM action_harness_events
         WHERE session_id = ?
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`,
        [filterSessionId]
      );
    } else {
      ahRows = safeAll(
        db,
        `SELECT * FROM action_harness_events
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`
      );
    }

    for (const row of ahRows) {
      const issues = safeParseArray(row.issues_json);
      const reasons = formatIssueReasons(issues);
      const decision = String(row.decision || 'UNKNOWN');
      const status = String(row.status || 'UNKNOWN');
      const tool = String(row.tool_name || 'tool');

      let why;
      if (decision === 'BLOCK_SPIN_LOOP') {
        why = `Blocked duplicate read call to ${tool} because identical canonical arguments were already executed in session "${row.session_id}".`;
        if (reasons.length === 0) reasons.push('SPIN_LOOP_DUPLICATE_READ');
      } else if (decision === 'BLOCK_READ_STREAK') {
        why = `Blocked ${tool} after exceeding the consecutive read-streak cap without consulting memory or progressing.`;
        if (reasons.length === 0) reasons.push('READ_STREAK_EXCEEDED');
      } else if (decision === 'BLOCK_DUPLICATE_WRITE') {
        why = `Blocked duplicate mutating call to ${tool} to prevent repeated external side effects.`;
        if (reasons.length === 0) reasons.push('DUPLICATE_SIDE_EFFECT');
      } else if (decision === 'HOLD_FOR_REVISION') {
        why = `Held mutating call to ${tool} before side-effect execution (${issues.length || 1} pre-commit argument/invariant issue(s))${reasons[0] ? `: ${reasons[0]}` : '.'}`;
      } else if (decision === 'CONTINUE_VERIFY') {
        why = `Intercepted premature turn stop in session "${row.session_id}" and nudged the agent to complete or verify its action.`;
      } else {
        why = `Allowed ${Number(row.is_mutating) === 1 ? 'mutating' : 'read'} call to ${tool} (status: ${status}).`;
      }

      const ts = normalizeTimestamp(row.updated_at_ms || row.created_at_ms);
      collected.push({
        source: 'action_harness',
        id: String(row.event_id),
        session_id: row.session_id ? String(row.session_id) : null,
        target: tool,
        decision,
        status,
        blocked: isBlockedDecision(decision, status),
        why,
        reasons,
        timestamp: ts.timestamp,
        _sortMs: ts.sortMs
      });
    }

    // 3. Turn-0 Grounded Harness Events (`grounded_events` + session-level output-defect gates)
    let ghRows = [];
    if (filterId && filterSessionId) {
      ghRows = safeAll(
        db,
        `SELECT * FROM grounded_events
         WHERE (event_id = ? OR session_id = ?) AND session_id = ?
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`,
        [filterId, filterId, filterSessionId]
      );
    } else if (filterId) {
      ghRows = safeAll(
        db,
        `SELECT * FROM grounded_events
         WHERE event_id = ? OR session_id = ?
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`,
        [filterId, filterId]
      );
    } else if (filterSessionId) {
      ghRows = safeAll(
        db,
        `SELECT * FROM grounded_events
         WHERE session_id = ?
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`,
        [filterSessionId]
      );
    } else {
      ghRows = safeAll(
        db,
        `SELECT * FROM grounded_events
         ORDER BY created_at_ms DESC, rowid DESC
         LIMIT 200`
      );
    }

    const sessionsWithExplicitDefectEvent = new Set();
    for (const row of ghRows) {
      const rawIssues = safeParseArray(row.issues_json);
      const reasons = formatIssueReasons(rawIssues);
      const { decision, why } = classifyGroundedEvent(row, rawIssues, reasons);
      const status = String(row.status || 'UNKNOWN');
      if (decision.startsWith('REJECT') && row.session_id) {
        sessionsWithExplicitDefectEvent.add(String(row.session_id));
      }
      if (reasons.length === 0 && isBlockedDecision(decision, status)) {
        reasons.push(decision);
      }

      const ts = normalizeTimestamp(row.updated_at_ms || row.created_at_ms);
      collected.push({
        source: 'grounded_harness',
        id: String(row.event_id),
        session_id: row.session_id ? String(row.session_id) : null,
        target: String(row.tool_name || 'tool'),
        decision,
        status,
        blocked: isBlockedDecision(decision, status),
        why,
        reasons,
        timestamp: ts.timestamp,
        _sortMs: ts.sortMs
      });
    }

    // Surface session-level REJECT_OUTPUT_DEFECT gates recorded on `grounded_sessions`
    let ghDefectSessions = [];
    if (filterId && filterSessionId) {
      ghDefectSessions = safeAll(
        db,
        `SELECT session_id, goal, output_defects_caught, updated_at_ms, created_at_ms
         FROM grounded_sessions
         WHERE output_defects_caught > 0
           AND (session_id = ? OR ? = session_id || ':verify_stop')
           AND session_id = ?`,
        [filterId, filterId, filterSessionId]
      );
    } else if (filterId) {
      ghDefectSessions = safeAll(
        db,
        `SELECT session_id, goal, output_defects_caught, updated_at_ms, created_at_ms
         FROM grounded_sessions
         WHERE output_defects_caught > 0
           AND (session_id = ? OR ? = session_id || ':verify_stop')`,
        [filterId, filterId]
      );
    } else if (filterSessionId) {
      ghDefectSessions = safeAll(
        db,
        `SELECT session_id, goal, output_defects_caught, updated_at_ms, created_at_ms
         FROM grounded_sessions
         WHERE output_defects_caught > 0 AND session_id = ?`,
        [filterSessionId]
      );
    } else {
      ghDefectSessions = safeAll(
        db,
        `SELECT session_id, goal, output_defects_caught, updated_at_ms, created_at_ms
         FROM grounded_sessions
         WHERE output_defects_caught > 0
         ORDER BY updated_at_ms DESC
         LIMIT 100`
      );
    }

    for (const sess of ghDefectSessions) {
      const sid = String(sess.session_id);
      if (sessionsWithExplicitDefectEvent.has(sid)) continue;
      const count = Number(sess.output_defects_caught || 0);
      const ts = normalizeTimestamp(sess.updated_at_ms || sess.created_at_ms);
      collected.push({
        source: 'grounded_harness',
        id: `${sid}:verify_stop`,
        session_id: sid,
        target: '__verify_stop__',
        decision: 'REJECT_OUTPUT_DEFECT',
        status: 'REJECTED',
        blocked: true,
        why: `Stop gate rejected candidate output in grounded session "${sid}" (${count} output defect(s) caught, e.g. raw DataFrame/NumPy repr, empty scalar bailout, or truncated response).`,
        reasons: [`REJECT_OUTPUT_DEFECT (count=${count})`],
        timestamp: ts.timestamp,
        _sortMs: ts.sortMs
      });
    }

    // 4. Async HITL Lease Gates (`stack_hitl_gates`)
    let gateRows = [];
    if (filterId) {
      gateRows = safeAll(
        db,
        `SELECT * FROM stack_hitl_gates
         WHERE gate_id = ? OR task_id = ?
         ORDER BY created_at_ms DESC
         LIMIT 100`,
        [filterId, filterId]
      );
    } else if (filterSessionId) {
      gateRows = safeAll(
        db,
        `SELECT * FROM stack_hitl_gates
         WHERE task_id = ? OR gate_id = ?
         ORDER BY created_at_ms DESC
         LIMIT 100`,
        [filterSessionId, filterSessionId]
      );
    } else {
      gateRows = safeAll(
        db,
        `SELECT * FROM stack_hitl_gates
         ORDER BY created_at_ms DESC
         LIMIT 100`
      );
    }

    for (const row of gateRows) {
      const status = String(row.status || 'PENDING');
      const decision = status;
      const reasons = [];
      if (row.decision_reason) reasons.push(String(row.decision_reason));
      if (row.reviewer) reasons.push(`reviewer=${row.reviewer}`);
      if (reasons.length === 0 && (status === 'PENDING' || status === 'PENDING_APPROVAL')) {
        reasons.push('Awaiting human-in-the-loop lease approval');
      }

      const why =
        status === 'PENDING' || status === 'PENDING_APPROVAL'
          ? `HITL gate "${row.gate_id}" for ${row.action_type} (${row.summary}) is pending operator approval.`
          : `HITL gate "${row.gate_id}" for ${row.action_type} (${row.summary}) resolved as ${status}${row.decision_reason ? ` (${row.decision_reason})` : ''}.`;

      const ts = normalizeTimestamp(row.decided_at_ms || row.created_at_ms);
      collected.push({
        source: 'hitl_gate',
        id: String(row.gate_id),
        session_id: row.task_id ? String(row.task_id) : null,
        target: String(row.action_type || 'hitl_action'),
        decision,
        status,
        blocked: isBlockedDecision(decision, status),
        why,
        reasons,
        timestamp: ts.timestamp,
        _sortMs: ts.sortMs
      });
    }

    const filtered = filterOnlyBlocked ? collected.filter((d) => d.blocked) : collected;
    filtered.sort((a, b) => {
      if (b._sortMs !== a._sortMs) return b._sortMs - a._sortMs;
      return String(b.id).localeCompare(String(a.id));
    });

    const decisions = filtered.slice(0, boundedLimit).map(({ _sortMs, ...item }) => item);
    const blockedInPage = decisions.filter((d) => d.blocked).length;

    return okEnvelope(
      'krusch_observability_explain',
      `Explained ${decisions.length} decision(s) (${blockedInPage} blocked/held/rejected).`,
      {
        filter: {
          id: filterId,
          session_id: filterSessionId,
          only_blocked: filterOnlyBlocked,
          limit: boundedLimit
        },
        count: decisions.length,
        decisions
      }
    );
  }

  return {
    getMetrics,
    explainDecisions
  };
}

/**
 * Format human-readable CLI output for `npx krusch-stack explain`.
 * Uses ASCII `--` and `->` separators only (zero em dashes or private hostnames).
 *
 * @param {{ data?: object }} explainResult
 * @param {{ data?: object } | null} [metricsResult=null]
 * @returns {string}
 */
export function formatExplainReportText(explainResult = {}, metricsResult = null) {
  const lines = [
    'KruschStack Decision Observability Report',
    '========================================='
  ];

  const m = metricsResult?.data;
  if (m) {
    lines.push(
      `Metrics: memories=${m.memory?.active ?? 0} active (${m.memory?.stale_drift ?? 0} drifted) | 2PC=${m.harness_2pc?.total_tasks ?? 0} tasks (${m.harness_2pc?.blocked_invariant ?? 0} blocked, ${m.harness_2pc?.journals_rolled_back ?? 0} rolled back) | loops_blocked=${(m.action_harness?.spin_loops_blocked ?? 0) + (m.grounded_harness?.spin_loops_blocked ?? 0)} | defects_caught=${m.grounded_harness?.output_defects_caught ?? 0}`
    );
    lines.push('-----------------------------------------');
  }

  const decisions = Array.isArray(explainResult?.data?.decisions)
    ? explainResult.data.decisions
    : [];

  if (decisions.length === 0) {
    lines.push('No matching agent decisions recorded in SQLite.');
    return lines.join('\n');
  }

  for (const item of decisions) {
    const tag = item.blocked ? '[BLOCKED]' : '[ALLOWED]';
    const sess = item.session_id ? ` session=${item.session_id}` : '';
    lines.push(`${tag} [${item.source}] ${item.decision} (${item.status}) -> target=${item.target} id=${item.id}${sess}`);
    lines.push(`  Why: ${item.why}`);
    if (Array.isArray(item.reasons) && item.reasons.length > 0) {
      lines.push(`  Reasons: ${item.reasons.join(' | ')}`);
    }
  }

  return lines.join('\n');
}
