/**
 * @module engines/action-harness-engine
 * Tier 3 Extension: 2PC Tool-Action Harness, Trajectory Spin-Loop Guard & Verify-on-Stop Gate.
 * Enforces INV-STACK-01 (zero external dependencies, Node 22 native node:sqlite + node:crypto),
 * INV-STACK-02 (deterministic okEnvelope return contract), INV-STACK-04 (sanitized public defaults),
 * and INV-STACK-10 (external RPC/MCP trajectory spin-loop blocking, duplicate side-effect prevention,
 * pre-commit 2PC argument verification, and premature zero-mutation stop gating).
 */

import crypto from 'node:crypto';
import { okEnvelope } from '../db/sqlite.js';
import { scanForSecretLeak } from './fs-engine.js';

export const ACTION_HARNESS_SCHEMA_SQL = `
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
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
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
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_action_harness_events_sig
    ON action_harness_events(session_id, call_signature);

  CREATE INDEX IF NOT EXISTS idx_action_harness_events_time
    ON action_harness_events(session_id, created_at_ms);
`;

const READ_ONLY_VERBS = [
  'describe',
  'inspect',
  'lookup',
  'search',
  'verify',
  'check',
  'count',
  'fetch',
  'query',
  'find',
  'list',
  'ping',
  'read',
  'show',
  'stat',
  'view',
  'get'
];

const MUTATING_VERBS = [
  'reschedule',
  'purchase',
  'schedule',
  'transfer',
  'approve',
  'archive',
  'execute',
  'forward',
  'trigger',
  'assign',
  'cancel',
  'charge',
  'create',
  'delete',
  'invite',
  'refund',
  'remove',
  'reopen',
  'submit',
  'update',
  'close',
  'merge',
  'order',
  'patch',
  'reply',
  'write',
  'book',
  'edit',
  'flag',
  'post',
  'send',
  'add',
  'pay',
  'put',
  'run'
];

const PLACEHOLDER_VALUE_RE =
  /<insert[^>]*>|\[insert[^\]]*\]|\{\s*todo\s*\}|\byour_name_here\b|\bplaceholder\b/i;

const EXACT_PLACEHOLDER_RE = /^(?:TBD|TODO|YYYY-MM-DD)$/i;

const DATE_FIELD_KEY_RE =
  /(?:^|_)(?:date|check_in|check_out|due_date|start_date|end_date|departure_date|return_date)$/i;

const UNRESOLVED_DATE_WORD_RE =
  /^(?:tbd|todo|yyyy-mm-dd|mm\/dd\/yyyy|tomorrow|yesterday|next\s+\w+|unknown)$/i;

const ISO_DATE_PREFIX_RE = /^(\d{4})-(\d{2})-(\d{2})/;

const HARD_ISSUE_CODES = new Set(['SECRET_LEAK_BLOCKED', 'CONTEXT_INVARIANT_NUDGE']);

const DRAFT_ONLY_GOAL_EXEMPT_RE =
  /\b(?:draft\s+only|only\s+draft|do\s+not\s+send|don't\s+send|do\s+not\s+execute|don't\s+execute|ask\s+before\s+sending|just\s+show\s+me|what\s+would\s+you)\b/i;

const PERMISSION_ASK_FINAL_TEXT_RE =
  /\b(?:would\s+you\s+like\s+me\s+to|shall\s+i\s+(?:send|create|book|post|schedule|update|add|proceed|submit|archive|delete|pay)|should\s+i\s+(?:go\s+ahead|send|create|book|post|schedule|proceed)|let\s+me\s+know\s+if\s+you(?:'d|\s+would)?\s+(?:like|want)\s+me\s+to|confirm\s+before\s+i\s+(?:send|create|book|post|schedule))\b/i;

const FORMATTED_DRAFT_HEADER_RE =
  /(?:^|\n)\s*(?:\*\*?)?(?:draft|subject|proposed\s+(?:email|message|post|document))(?:\*\*?)?\s*:/i;

const SERIALIZED_TOOL_CALL_IN_TEXT_RE =
  /<tool_call\b|<function=|\{\s*"name"\s*:\s*"[A-Za-z0-9_.-]+"\s*,\s*"arguments"\s*:\s*\{|(?:^|\n)\s*name\s*:\s*[A-Za-z0-9_.-]+\s*,\s*arguments\s*:\s*\{/i;

const IMPERATIVE_GOAL_VERB_RE =
  /\b(?:send|create|schedule|book|post|add|update|archive|delete|remove|pay|flag|approve|order|reply|forward|invite|reschedule|cancel|assign|submit|write|draft|compile|prepare)\b/i;

const POLICY_ABSTENTION_RATIONALE_RE =
  /\b(?:per\s+your\s+(?:rule|rules|policy|policies|preference|preferences|standing|instruction|instructions)|standing\s+(?:rule|rules|policy|policies)|channel\s+(?:rule|rules|policy|policies)|not\s+(?:yet\s+)?green|pre-green|cannot|can't|unable\s+to|holding\s+off|held\s+off|skipping|skipped|did\s+not\s+(?:add|send|post|create|book|process)|do\s+not\s+qualify|doesn't\s+qualify|does\s+not\s+qualify|already\s+(?:exists|scheduled|in\s+the\s+crm|sent|archived|paid)|no\s+(?:action|changes|updates)\s+(?:needed|required)|prohibited|deprecated|waiting\s+until|flagged\s+instead|requires\s+manual)\b/i;

const PURE_QUESTION_GOAL_RE =
  /^\s*(?:what|when|where|who|why|how|which|is|are|did|do|does|can\s+you\s+tell|check\s+whether|summarize|list)\b/i;

const VERIFY_STOP_STEER_PROMPT =
  'VERIFICATION GATE: Zero mutating tool calls have been committed in this session, yet the user requested an action. If standing policy/state permits the action, execute the required tool call(s) now with exact parameters instead of printing a draft or asking for confirmation. If a standing rule or live state prohibits the action, explicitly state the governing policy/state reason.';

const VERIFY_STOP_SERIALIZED_TOOL_STEER_PROMPT =
  'VERIFICATION GATE: Your previous message printed a raw XML/JSON tool invocation inside plain text instead of structured tool_calls, so zero tools executed. Re-issue the intended tool call now via the structured tool_calls API rather than plain-text JSON or <tool_call> tags.';

const MAX_RESULT_PREVIEW_CHARS = 512;
const MAX_ARG_SCAN_DEPTH = 16;

/**
 * Strip optional MCP or namespace prefixes (`mcp__app__tool`, `app.tool`, `app:tool`, `app/tool`).
 * @param {string} toolName
 * @returns {string}
 */
function stripToolNamespace(toolName) {
  let base = String(toolName || '').trim();
  if (!base) return '';
  base = base.replace(/^mcp__(?:[^_]|_(?!_))+__/i, '');
  base = base.replace(/^(?:[A-Za-z0-9_-]+[.:/])+/, '');
  return base;
}

/**
 * Test whether `baseName` starts with one of `verbs` followed by end-of-string, `_`, `-`,
 * or a camelCase/PascalCase uppercase transition (`getUser`, `GetUser`, `addCrmRow`).
 * Avoids substring false-positives such as `address_book` matching `add` or `payees` matching `pay`.
 * @param {string} baseName
 * @param {string[]} verbs
 * @returns {boolean}
 */
function matchesVerbPrefix(baseName, verbs) {
  if (!baseName) return false;
  const lower = baseName.toLowerCase();
  for (const verb of verbs) {
    if (!lower.startsWith(verb)) continue;
    if (baseName.length === verb.length) return true;
    const nextChar = baseName[verb.length];
    if (nextChar === '_' || nextChar === '-') return true;
    const prevChar = baseName[verb.length - 1];
    const isPrevLower = prevChar >= 'a' && prevChar <= 'z';
    const isNextUpper = nextChar >= 'A' && nextChar <= 'Z';
    if (isPrevLower && isNextUpper) return true;
  }
  return false;
}

/**
 * Classify whether a tool call is mutating or read-only.
 * Explicit boolean override takes precedence; otherwise strips optional MCP/app namespaces
 * and matches base verb prefixes, defaulting conservatively to `false`.
 * @param {string} toolName
 * @param {boolean} [explicitMutating]
 * @returns {boolean}
 */
export function classifyToolMutability(toolName, explicitMutating) {
  if (typeof explicitMutating === 'boolean') {
    return explicitMutating;
  }
  const baseName = stripToolNamespace(toolName);
  if (!baseName) return false;
  if (matchesVerbPrefix(baseName, READ_ONLY_VERBS)) {
    return false;
  }
  if (matchesVerbPrefix(baseName, MUTATING_VERBS)) {
    return true;
  }
  return false;
}

/**
 * Recursively produce a key-sorted canonical JSON-compatible structure.
 * Arrays preserve element order while canonicalizing nested objects; `undefined`, functions,
 * and symbols on object properties are omitted identically to `JSON.stringify`.
 * @param {unknown} value
 * @param {WeakSet<object>} [seen]
 * @returns {unknown}
 */
function canonicalizeJsonValue(value, seen = new WeakSet()) {
  if (value === null || value === undefined) {
    return value === undefined ? undefined : null;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      return null;
    }
    return value;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    const arr = value.map((item) => {
      if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
        return null;
      }
      const next = canonicalizeJsonValue(item, seen);
      return next === undefined ? null : next;
    });
    seen.delete(value);
    return arr;
  }

  const sortedKeys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const out = {};
  for (const key of sortedKeys) {
    const propVal = value[key];
    if (propVal === undefined || typeof propVal === 'function' || typeof propVal === 'symbol') {
      continue;
    }
    const canonicalProp = canonicalizeJsonValue(propVal, seen);
    if (canonicalProp !== undefined) {
      out[key] = canonicalProp;
    }
  }
  seen.delete(value);
  return out;
}

/**
 * Normalize an incoming `args` payload (object, JSON string, or nullish) to an inspectable value.
 * @param {unknown} args
 * @returns {unknown}
 */
function normalizeRawArgs(args) {
  if (args === undefined || args === null) {
    return {};
  }
  if (typeof args === 'string') {
    const trimmed = args.trim();
    if (!trimmed) return {};
    if (
      (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
      (trimmed.startsWith('[') && trimmed.endsWith(']'))
    ) {
      try {
        return JSON.parse(trimmed);
      } catch {
        return { _raw: args };
      }
    }
    return { _raw: args };
  }
  return args;
}

/**
 * Deterministically canonicalize `(toolName, args)` and compute its SHA-256 hex signature.
 * @param {string} toolName
 * @param {unknown} [args={}]
 * @returns {{ toolName: string, canonicalArgs: unknown, canonicalArgsJson: string, callSignature: string }}
 */
export function canonicalizeToolCallKey(toolName, args = {}) {
  const normalizedTool = String(toolName || '').trim();
  const normalizedArgsInput = normalizeRawArgs(args);
  const canonicalArgs = canonicalizeJsonValue(normalizedArgsInput);
  const serialized = JSON.stringify(canonicalArgs === undefined ? {} : canonicalArgs);
  const canonicalArgsJson = typeof serialized === 'string' ? serialized : '{}';
  const callSignature = crypto
    .createHash('sha256')
    .update(`${normalizedTool}:${canonicalArgsJson}`, 'utf8')
    .digest('hex');

  return {
    toolName: normalizedTool,
    canonicalArgs,
    canonicalArgsJson,
    callSignature
  };
}

/**
 * Clamp a numeric limit parameter to a non-negative integer, falling back to `defaultValue`.
 * @param {unknown} raw
 * @param {number} defaultValue
 * @returns {number}
 */
function normalizeNonNegativeInt(raw, defaultValue) {
  if (raw === undefined || raw === null || raw === '') return defaultValue;
  const num = Number(raw);
  if (!Number.isFinite(num) || num < 0) return defaultValue;
  return Math.trunc(num);
}

/**
 * Return the exact number of calendar days in a 1-indexed `(year, month)` pair.
 * @param {number} year
 * @param {number} month
 * @returns {number}
 */
function daysInCalendarMonth(year, month) {
  if (month === 2) {
    const isLeap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return isLeap ? 29 : 28;
  }
  if (month === 4 || month === 6 || month === 9 || month === 11) {
    return 30;
  }
  return 31;
}

/**
 * Check whether an object key represents an explicit date-typed parameter.
 * @param {string} leafKey
 * @returns {boolean}
 */
function isDateFieldKey(leafKey) {
  if (!leafKey) return false;
  if (DATE_FIELD_KEY_RE.test(leafKey)) return true;
  const snakeKey = leafKey.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
  return DATE_FIELD_KEY_RE.test(snakeKey);
}

/**
 * Validate a string value assigned to a date-keyed argument field.
 * Returns a descriptive error message when malformed/unresolved, or `null` when valid.
 * Permits valid ISO dates and timestamps (`2026-05-14`, `2026-05-14T09:30:00Z`, `2026-05-14 09:30`).
 * @param {string} rawValue
 * @param {string} anchorDate
 * @returns {string | null}
 */
function validateDateFieldString(rawValue, anchorDate) {
  const trimmed = String(rawValue ?? '').trim();
  if (!trimmed) return null;

  const anchorHint = anchorDate
    ? ` (session anchor_date: ${anchorDate})`
    : '';

  if (UNRESOLVED_DATE_WORD_RE.test(trimmed)) {
    return `Unresolved or relative date placeholder "${trimmed}"${anchorHint}; supply a concrete valid YYYY-MM-DD ISO date.`;
  }

  const isoMatch = trimmed.match(ISO_DATE_PREFIX_RE);
  if (isoMatch) {
    const year = Number.parseInt(isoMatch[1], 10);
    const month = Number.parseInt(isoMatch[2], 10);
    const day = Number.parseInt(isoMatch[3], 10);
    if (month < 1 || month > 12) {
      return `Invalid calendar month "${isoMatch[2]}" in "${trimmed}"${anchorHint}; month must be between 01 and 12.`;
    }
    const maxDay = daysInCalendarMonth(year, month);
    if (day < 1 || day > maxDay) {
      return `Invalid calendar day "${isoMatch[3]}" for ${isoMatch[1]}-${isoMatch[2]} in "${trimmed}"${anchorHint}; valid day range is 01..${String(maxDay).padStart(2, '0')}.`;
    }
  }

  return null;
}

/**
 * Walk nested argument structures and invoke `visitor(fieldPath, leafKey, strValue)` for strings.
 * @param {unknown} node
 * @param {(fieldPath: string, leafKey: string, value: string) => void} visitor
 * @param {string} [pathPrefix='']
 * @param {string} [leafKey='']
 * @param {number} [depth=0]
 * @param {WeakSet<object>} [seen]
 */
function walkArgumentStrings(
  node,
  visitor,
  pathPrefix = '',
  leafKey = '',
  depth = 0,
  seen = new WeakSet()
) {
  if (depth > MAX_ARG_SCAN_DEPTH || node === null || node === undefined) {
    return;
  }
  if (typeof node === 'string') {
    visitor(pathPrefix || leafKey || 'value', leafKey, node);
    return;
  }
  if (typeof node !== 'object') {
    return;
  }
  if (seen.has(node)) {
    return;
  }
  seen.add(node);

  if (Array.isArray(node)) {
    for (let idx = 0; idx < node.length; idx += 1) {
      const nextPath = pathPrefix ? `${pathPrefix}[${idx}]` : `[${idx}]`;
      walkArgumentStrings(node[idx], visitor, nextPath, leafKey, depth + 1, seen);
    }
    seen.delete(node);
    return;
  }

  for (const key of Object.keys(node)) {
    const nextPath = pathPrefix ? `${pathPrefix}.${key}` : key;
    walkArgumentStrings(node[key], visitor, nextPath, key, depth + 1, seen);
  }
  seen.delete(node);
}

/**
 * Parse a stored JSON array column safely.
 * @param {string} raw
 * @returns {Array<object>}
 */
function safeParseIssuesJson(raw) {
  if (!raw || typeof raw !== 'string') return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/**
 * Normalize an outcome status string to `'COMMITTED' | 'ERROR' | 'ABORTED'` (or `null` if invalid).
 * @param {unknown} rawStatus
 * @returns {'COMMITTED' | 'ERROR' | 'ABORTED' | null}
 */
function normalizeOutcomeStatus(rawStatus) {
  const upper = String(rawStatus ?? 'COMMITTED')
    .trim()
    .toUpperCase();
  if (upper === 'COMMITTED' || upper === 'OK' || upper === 'SUCCESS') {
    return 'COMMITTED';
  }
  if (upper === 'ERROR' || upper === 'FAILED' || upper === 'FAILURE') {
    return 'ERROR';
  }
  if (upper === 'ABORTED' || upper === 'CANCELLED' || upper === 'CANCELED') {
    return 'ABORTED';
  }
  return null;
}

/**
 * Create the SQLite-backed 2PC Tool-Action Harness Engine (`INV-STACK-10`).
 * @param {object} [options={}]
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {{ nudge?: (params: { trigger: string, code: string }) => any } | null} [options.contextEngine=null]
 */
export function createActionHarnessEngine({ db, contextEngine = null } = {}) {
  if (!db || typeof db.exec !== 'function' || typeof db.prepare !== 'function') {
    throw new Error('createActionHarnessEngine requires a valid Node 22 SQLite DatabaseSync instance.');
  }

  db.exec(ACTION_HARNESS_SCHEMA_SQL);

  const selectSessionStmt = db.prepare(`
    SELECT *
    FROM action_harness_sessions
    WHERE session_id = ?
  `);

  const insertSessionStmt = db.prepare(`
    INSERT INTO action_harness_sessions (
      session_id,
      persona,
      goal,
      anchor_date,
      status,
      max_identical_reads,
      max_duplicate_writes,
      max_read_streak,
      max_verify_nudges,
      enforce_context_nudge,
      consecutive_app_reads,
      committed_reads,
      committed_mutations,
      verify_nudges_used,
      created_at_ms,
      updated_at_ms
    ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?)
  `);

  const updateSessionKeepCountersStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET persona = ?,
        goal = ?,
        anchor_date = ?,
        status = 'ACTIVE',
        max_identical_reads = ?,
        max_duplicate_writes = ?,
        max_read_streak = ?,
        max_verify_nudges = ?,
        enforce_context_nudge = ?,
        updated_at_ms = ?
    WHERE session_id = ?
  `);

  const resetSessionCountersStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET persona = ?,
        goal = ?,
        anchor_date = ?,
        status = 'ACTIVE',
        max_identical_reads = ?,
        max_duplicate_writes = ?,
        max_read_streak = ?,
        max_verify_nudges = ?,
        enforce_context_nudge = ?,
        consecutive_app_reads = 0,
        committed_reads = 0,
        committed_mutations = 0,
        verify_nudges_used = 0,
        updated_at_ms = ?
    WHERE session_id = ?
  `);

  const deleteSessionEventsStmt = db.prepare(`
    DELETE FROM action_harness_events
    WHERE session_id = ?
  `);

  const countSignatureActiveEventsStmt = db.prepare(`
    SELECT COUNT(*) AS cnt
    FROM action_harness_events
    WHERE session_id = ?
      AND call_signature = ?
      AND status IN ('STAGED', 'COMMITTED')
  `);

  const selectActiveEventIdsStmt = db.prepare(`
    SELECT event_id, call_signature
    FROM action_harness_events
    WHERE session_id = ?
      AND status IN ('STAGED', 'COMMITTED')
  `);

  const preOutcomeSignaturesBySession = new Map();

  function recordPreOutcomeSignature(sessionId, eventId, rawSignature) {
    let byEvent = preOutcomeSignaturesBySession.get(sessionId);
    if (!byEvent) {
      byEvent = new Map();
      preOutcomeSignaturesBySession.set(sessionId, byEvent);
    }
    if (!byEvent.has(eventId)) {
      byEvent.set(eventId, rawSignature);
    }
  }

  function countMatchingActiveEvents(sessionId, candidateSignature) {
    const byEvent = preOutcomeSignaturesBySession.get(sessionId);
    if (!byEvent || byEvent.size === 0) {
      const row = countSignatureActiveEventsStmt.get(sessionId, candidateSignature);
      return Number(row?.cnt || 0);
    }
    const activeRows = selectActiveEventIdsStmt.all(sessionId);
    let matches = 0;
    for (const row of activeRows) {
      if (
        row.call_signature === candidateSignature ||
        byEvent.get(row.event_id) === candidateSignature
      ) {
        matches += 1;
      }
    }
    return matches;
  }

  const selectPriorHoldsForToolStmt = db.prepare(`
    SELECT issues_json
    FROM action_harness_events
    WHERE session_id = ?
      AND tool_name = ?
      AND decision = 'HOLD_FOR_REVISION'
  `);

  const insertEventStmt = db.prepare(`
    INSERT INTO action_harness_events (
      event_id,
      session_id,
      step,
      tool_name,
      is_mutating,
      is_memory_search,
      canonical_args_json,
      call_signature,
      decision,
      status,
      issues_json,
      result_preview,
      created_at_ms,
      updated_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const touchSessionTimestampStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET updated_at_ms = ?
    WHERE session_id = ?
  `);

  const updateConsecutiveReadsStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET consecutive_app_reads = ?,
        updated_at_ms = ?
    WHERE session_id = ?
  `);

  const selectEventBySessionStmt = db.prepare(`
    SELECT *
    FROM action_harness_events
    WHERE event_id = ?
      AND session_id = ?
  `);

  const updateEventOutcomeStmt = db.prepare(`
    UPDATE action_harness_events
    SET canonical_args_json = ?,
        call_signature = ?,
        status = ?,
        result_preview = ?,
        updated_at_ms = ?
    WHERE event_id = ?
      AND session_id = ?
  `);

  const countCommittedTotalsStmt = db.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN status = 'COMMITTED' AND is_mutating = 1 THEN 1 ELSE 0 END), 0) AS committed_mutations,
      COALESCE(SUM(CASE WHEN status = 'COMMITTED' AND is_mutating = 0 THEN 1 ELSE 0 END), 0) AS committed_reads
    FROM action_harness_events
    WHERE session_id = ?
      AND tool_name != '__verify_stop__'
  `);

  const updateSessionCommittedTotalsStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET committed_mutations = ?,
        committed_reads = ?,
        updated_at_ms = ?
    WHERE session_id = ?
  `);

  const incrementVerifyNudgeStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET verify_nudges_used = ?,
        updated_at_ms = ?
    WHERE session_id = ?
  `);

  const markSessionCompletedStmt = db.prepare(`
    UPDATE action_harness_sessions
    SET status = 'COMPLETED',
        updated_at_ms = ?
    WHERE session_id = ?
  `);

  const selectSessionEventsOrderedStmt = db.prepare(`
    SELECT *
    FROM action_harness_events
    WHERE session_id = ?
    ORDER BY created_at_ms ASC, rowid ASC
  `);

  /**
   * Start or reset an action-harness trajectory governance session.
   * @param {object} [params={}]
   */
  function startSession({
    session_id,
    persona = '',
    goal,
    anchor_date = '',
    max_identical_reads = 1,
    max_duplicate_writes = 1,
    max_read_streak = 6,
    max_verify_nudges = 1,
    enforce_context_nudge = false,
    reset = false
  } = {}) {
    if (typeof goal !== 'string' || !goal.trim()) {
      return okEnvelope(
        'krusch_action_session_start',
        'Action harness session requires a non-empty goal string.',
        { status: 'INVALID_SESSION_ARGS' },
        false
      );
    }

    const resolvedSessionId =
      typeof session_id === 'string' && session_id.trim()
        ? session_id.trim()
        : `act_${crypto.randomUUID()}`;
    const normalizedPersona = String(persona ?? '').trim();
    const normalizedGoal = goal.trim();
    const normalizedAnchorDate = String(anchor_date ?? '').trim();
    const maxIdenticalReads = normalizeNonNegativeInt(max_identical_reads, 1);
    const maxDuplicateWrites = normalizeNonNegativeInt(max_duplicate_writes, 1);
    const maxReadStreak = normalizeNonNegativeInt(max_read_streak, 6);
    const maxVerifyNudges = normalizeNonNegativeInt(max_verify_nudges, 1);
    const enforceNudgeInt = enforce_context_nudge ? 1 : 0;
    const now = Date.now();

    const existing = selectSessionStmt.get(resolvedSessionId);
    db.exec('BEGIN IMMEDIATE');
    try {
      if (!existing) {
        if (reset) {
          deleteSessionEventsStmt.run(resolvedSessionId);
          preOutcomeSignaturesBySession.delete(resolvedSessionId);
        }
        insertSessionStmt.run(
          resolvedSessionId,
          normalizedPersona,
          normalizedGoal,
          normalizedAnchorDate,
          maxIdenticalReads,
          maxDuplicateWrites,
          maxReadStreak,
          maxVerifyNudges,
          enforceNudgeInt,
          now,
          now
        );
      } else if (reset) {
        deleteSessionEventsStmt.run(resolvedSessionId);
        preOutcomeSignaturesBySession.delete(resolvedSessionId);
        resetSessionCountersStmt.run(
          normalizedPersona,
          normalizedGoal,
          normalizedAnchorDate,
          maxIdenticalReads,
          maxDuplicateWrites,
          maxReadStreak,
          maxVerifyNudges,
          enforceNudgeInt,
          now,
          resolvedSessionId
        );
      } else {
        updateSessionKeepCountersStmt.run(
          normalizedPersona,
          normalizedGoal,
          normalizedAnchorDate,
          maxIdenticalReads,
          maxDuplicateWrites,
          maxReadStreak,
          maxVerifyNudges,
          enforceNudgeInt,
          now,
          resolvedSessionId
        );
      }
      db.exec('COMMIT');
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* ignore rollback error */
      }
      throw err;
    }

    return okEnvelope(
      'krusch_action_session_start',
      `Action harness session ${resolvedSessionId} initialized (ACTIVE).`,
      {
        status: 'ACTIVE',
        session_id: resolvedSessionId,
        persona: normalizedPersona,
        goal: normalizedGoal,
        anchor_date: normalizedAnchorDate,
        limits: {
          max_identical_reads: maxIdenticalReads,
          max_duplicate_writes: maxDuplicateWrites,
          max_read_streak: maxReadStreak,
          max_verify_nudges: maxVerifyNudges,
          enforce_context_nudge: Boolean(enforce_context_nudge)
        }
      },
      true
    );
  }

  /**
   * Intercept a proposed tool call prior to execution, enforcing spin-loop read guards,
   * consecutive read-streak caps, duplicate write prevention, and 2PC pre-commit argument checks.
   * @param {object} [params={}]
   */
  function interceptToolCall({
    session_id,
    step = 0,
    tool_name,
    args = {},
    is_mutating,
    is_memory_search = false,
    goal
  } = {}) {
    const normalizedToolName = typeof tool_name === 'string' ? tool_name.trim() : '';
    if (!normalizedToolName) {
      return okEnvelope(
        'krusch_action_intercept',
        'interceptToolCall requires a non-empty tool_name.',
        { status: 'INVALID_INTERCEPT_ARGS', allowed: false },
        false
      );
    }

    const requestedSessionId = typeof session_id === 'string' ? session_id.trim() : '';
    let session = requestedSessionId ? selectSessionStmt.get(requestedSessionId) : null;

    if (!session) {
      if (typeof goal === 'string' && goal.trim()) {
        const started = startSession({
          session_id: requestedSessionId || undefined,
          goal: goal.trim()
        });
        if (!started.ok) {
          return okEnvelope(
            'krusch_action_intercept',
            started.summary,
            { status: 'SESSION_NOT_FOUND', allowed: false },
            false
          );
        }
        session = selectSessionStmt.get(started.data.session_id);
      } else {
        return okEnvelope(
          'krusch_action_intercept',
          `Action harness session "${requestedSessionId}" not found.`,
          {
            status: 'SESSION_NOT_FOUND',
            session_id: requestedSessionId,
            allowed: false
          },
          false
        );
      }
    }

    const baseToolName = stripToolNamespace(normalizedToolName);
    const isMemory = Boolean(
      is_memory_search ||
        normalizedToolName === 'search_persona_memory' ||
        baseToolName === 'search_persona_memory'
    );
    const mutating = isMemory ? false : classifyToolMutability(normalizedToolName, is_mutating);
    const { canonicalArgs, canonicalArgsJson, callSignature } = canonicalizeToolCallKey(
      normalizedToolName,
      args
    );
    const stepNum = normalizeNonNegativeInt(step, 0);
    const eventId = `evt_${crypto.randomUUID()}`;
    const now = Date.now();

    if (!mutating) {
      const priorIdentical = countMatchingActiveEvents(session.session_id, callSignature);

      if (priorIdentical >= Number(session.max_identical_reads)) {
        insertEventStmt.run(
          eventId,
          session.session_id,
          stepNum,
          normalizedToolName,
          0,
          isMemory ? 1 : 0,
          canonicalArgsJson,
          callSignature,
          'BLOCK_SPIN_LOOP',
          'BLOCKED',
          '[]',
          '',
          now,
          now
        );
        touchSessionTimestampStmt.run(now, session.session_id);

        return okEnvelope(
          'krusch_action_intercept',
          `Blocked duplicate read spin-loop for ${normalizedToolName} (repeat #${priorIdentical + 1}).`,
          {
            event_id: eventId,
            session_id: session.session_id,
            tool_name: normalizedToolName,
            is_mutating: false,
            allowed: false,
            decision: 'BLOCK_SPIN_LOOP',
            call_signature: callSignature,
            repeat_count: priorIdentical + 1,
            synthetic_tool_result: {
              ok: false,
              blocked_by: 'krusch-action-harness',
              code: 'SPIN_LOOP_DUPLICATE_READ',
              message:
                'Identical read tool call with these exact arguments already executed in this session. Do not repeat identical read/list calls; query memory if historical context is missing, or proceed with the required action or response.'
            }
          },
          true
        );
      }

      const currentStreak = Number(session.consecutive_app_reads || 0);
      const maxStreak = Number(session.max_read_streak);
      if (!isMemory && currentStreak + 1 > maxStreak) {
        insertEventStmt.run(
          eventId,
          session.session_id,
          stepNum,
          normalizedToolName,
          0,
          0,
          canonicalArgsJson,
          callSignature,
          'BLOCK_READ_STREAK',
          'BLOCKED',
          '[]',
          '',
          now,
          now
        );
        touchSessionTimestampStmt.run(now, session.session_id);

        return okEnvelope(
          'krusch_action_intercept',
          `Blocked runaway consecutive read streak (${currentStreak}/${maxStreak}) on ${normalizedToolName}.`,
          {
            event_id: eventId,
            session_id: session.session_id,
            tool_name: normalizedToolName,
            is_mutating: false,
            allowed: false,
            decision: 'BLOCK_READ_STREAK',
            call_signature: callSignature,
            consecutive_app_reads: currentStreak,
            max_read_streak: maxStreak,
            synthetic_tool_result: {
              ok: false,
              blocked_by: 'krusch-action-harness',
              code: 'READ_STREAK_EXCEEDED',
              message: `Consecutive application read streak limit (${maxStreak}) reached. Stop polling application read endpoints repeatedly; consult persona memory if context is missing, or proceed with the required action or response.`
            }
          },
          true
        );
      }

      const nextStreak = isMemory ? 0 : currentStreak + 1;
      db.exec('BEGIN IMMEDIATE');
      try {
        insertEventStmt.run(
          eventId,
          session.session_id,
          stepNum,
          normalizedToolName,
          0,
          isMemory ? 1 : 0,
          canonicalArgsJson,
          callSignature,
          'ALLOW_READ',
          'STAGED',
          '[]',
          '',
          now,
          now
        );
        updateConsecutiveReadsStmt.run(nextStreak, now, session.session_id);
        db.exec('COMMIT');
      } catch (err) {
        try {
          db.exec('ROLLBACK');
        } catch {
          /* ignore rollback error */
        }
        throw err;
      }

      return okEnvelope(
        'krusch_action_intercept',
        `Allowed read call ${normalizedToolName}.`,
        {
          event_id: eventId,
          session_id: session.session_id,
          tool_name: normalizedToolName,
          is_mutating: false,
          is_memory_search: isMemory,
          allowed: true,
          staged: true,
          decision: 'ALLOW_READ',
          call_signature: callSignature,
          consecutive_app_reads: nextStreak
        },
        true
      );
    }

    // Mutating path (2PC staging + duplicate side-effect guard + pre-commit argument audit)
    const priorDupWrites = countMatchingActiveEvents(session.session_id, callSignature);

    if (priorDupWrites >= Number(session.max_duplicate_writes)) {
      insertEventStmt.run(
        eventId,
        session.session_id,
        stepNum,
        normalizedToolName,
        1,
        0,
        canonicalArgsJson,
        callSignature,
        'BLOCK_DUPLICATE_WRITE',
        'BLOCKED',
        '[]',
        '',
        now,
        now
      );
      touchSessionTimestampStmt.run(now, session.session_id);

      return okEnvelope(
        'krusch_action_intercept',
        `Blocked duplicate mutating call ${normalizedToolName} (repeat #${priorDupWrites + 1}).`,
        {
          event_id: eventId,
          session_id: session.session_id,
          tool_name: normalizedToolName,
          is_mutating: true,
          allowed: false,
          decision: 'BLOCK_DUPLICATE_WRITE',
          call_signature: callSignature,
          repeat_count: priorDupWrites + 1,
          synthetic_tool_result: {
            ok: false,
            blocked_by: 'krusch-action-harness',
            code: 'DUPLICATE_SIDE_EFFECT',
            message:
              'Identical mutating tool call with these exact arguments was already staged/executed in this session. Avoid duplicate side effects; verify whether the task is already satisfied or requires distinct parameters.'
          }
        },
        true
      );
    }

    const issues = [];

    // 1. Secret leak scan (hard block, never bypassed)
    const secretLeakReason = scanForSecretLeak(canonicalArgsJson);
    if (secretLeakReason) {
      issues.push({
        code: 'SECRET_LEAK_BLOCKED',
        field: '*',
        message: `Secret leak blocked (${secretLeakReason}): never pass raw API keys, access tokens, private keys, or inline credentials into external tool calls.`
      });
    }

    // 2. Unresolved template placeholder & 3. Explicit date-field sanity scan
    walkArgumentStrings(canonicalArgs, (fieldPath, leafKey, strVal) => {
      const trimmedVal = strVal.trim();
      if (PLACEHOLDER_VALUE_RE.test(strVal) || EXACT_PLACEHOLDER_RE.test(trimmedVal)) {
        issues.push({
          code: 'UNRESOLVED_PLACEHOLDER',
          field: fieldPath,
          message: `Field "${fieldPath}" contains an unresolved placeholder ("${trimmedVal.slice(0, 80)}"). Populate concrete values before executing ${normalizedToolName}.`
        });
      }

      if (isDateFieldKey(leafKey)) {
        const dateErr = validateDateFieldString(strVal, session.anchor_date);
        if (dateErr) {
          issues.push({
            code: 'MALFORMED_DATE_ARGUMENT',
            field: fieldPath,
            message: dateErr
          });
        }
      }
    });

    // 4. Optional Tier 1 context invariant nudge check (hard block)
    if (Number(session.enforce_context_nudge) === 1 && typeof contextEngine?.nudge === 'function') {
      const nudgeRes = contextEngine.nudge({
        trigger: 'pre_commit',
        code: `${normalizedToolName}(${canonicalArgsJson})`
      });
      const findings = nudgeRes?.data?.findings;
      if (Array.isArray(findings) && findings.length > 0) {
        for (const finding of findings) {
          if (finding && finding.blocking !== false && finding.severity !== 'info') {
            issues.push({
              code: 'CONTEXT_INVARIANT_NUDGE',
              field: '*',
              memory_id: finding.memory_id ?? null,
              matched_token: finding.matched_token ?? null,
              message:
                finding.message ||
                finding.rule ||
                `Context invariant violation triggered on ${normalizedToolName}.`
            });
          }
        }
      }
    }

    if (issues.length > 0) {
      const hasHardIssue = issues.some((iss) => HARD_ISSUE_CODES.has(iss.code));
      const priorHoldRows = selectPriorHoldsForToolStmt.all(
        session.session_id,
        normalizedToolName
      );
      const priorSoftHoldsForTool = priorHoldRows.filter((row) => {
        const parsed = safeParseIssuesJson(row.issues_json);
        return (
          parsed.length > 0 && !parsed.some((item) => HARD_ISSUE_CODES.has(item?.code))
        );
      }).length;

      if (hasHardIssue || priorSoftHoldsForTool === 0) {
        const serializedIssues = JSON.stringify(issues);
        insertEventStmt.run(
          eventId,
          session.session_id,
          stepNum,
          normalizedToolName,
          1,
          0,
          canonicalArgsJson,
          callSignature,
          'HOLD_FOR_REVISION',
          'HELD',
          serializedIssues,
          '',
          now,
          now
        );
        touchSessionTimestampStmt.run(now, session.session_id);

        const issueDetails = issues
          .map((iss) => (iss.field && iss.field !== '*' ? `[${iss.field}] ${iss.message}` : iss.message))
          .join(' | ');

        return okEnvelope(
          'krusch_action_intercept',
          `Held mutating call ${normalizedToolName} for pre-commit revision (${issues.length} issue(s)).`,
          {
            event_id: eventId,
            session_id: session.session_id,
            tool_name: normalizedToolName,
            is_mutating: true,
            allowed: false,
            staged: false,
            decision: 'HOLD_FOR_REVISION',
            call_signature: callSignature,
            issues,
            synthetic_tool_result: {
              ok: false,
              blocked_by: 'krusch-action-harness',
              code: hasHardIssue ? issues[0].code : 'HOLD_FOR_REVISION',
              issues,
              message: `2PC pre-commit check held ${normalizedToolName} before side-effect execution: ${issueDetails} Revise the flagged parameter(s) and re-call ${normalizedToolName}.`
            }
          },
          true
        );
      }
    }

    db.exec('BEGIN IMMEDIATE');
    try {
      insertEventStmt.run(
        eventId,
        session.session_id,
        stepNum,
        normalizedToolName,
        1,
        0,
        canonicalArgsJson,
        callSignature,
        'ALLOW_MUTATION',
        'STAGED',
        '[]',
        '',
        now,
        now
      );
      updateConsecutiveReadsStmt.run(0, now, session.session_id);
      db.exec('COMMIT');
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* ignore rollback error */
      }
      throw err;
    }

    return okEnvelope(
      'krusch_action_intercept',
      `Staged mutating call ${normalizedToolName} (ALLOW_MUTATION).`,
      {
        event_id: eventId,
        session_id: session.session_id,
        tool_name: normalizedToolName,
        is_mutating: true,
        allowed: true,
        staged: true,
        decision: 'ALLOW_MUTATION',
        call_signature: callSignature,
        issues: []
      },
      true
    );
  }

  /**
   * Commit or finalize the execution outcome of an intercepted tool event.
   * Recomputes session committed counters idempotently and optionally updates canonical signature.
   * @param {object} [params={}]
   */
  function recordToolOutcome({
    session_id,
    event_id,
    status = 'COMMITTED',
    canonical_args,
    result_preview = ''
  } = {}) {
    const trimmedSessionId = typeof session_id === 'string' ? session_id.trim() : '';
    const session = trimmedSessionId ? selectSessionStmt.get(trimmedSessionId) : null;
    if (!session) {
      return okEnvelope(
        'krusch_action_outcome',
        `Action harness session "${trimmedSessionId}" not found.`,
        { status: 'SESSION_NOT_FOUND', session_id: trimmedSessionId },
        false
      );
    }

    const trimmedEventId = typeof event_id === 'string' ? event_id.trim() : '';
    const event = trimmedEventId
      ? selectEventBySessionStmt.get(trimmedEventId, session.session_id)
      : null;
    if (!event) {
      return okEnvelope(
        'krusch_action_outcome',
        `Action harness event "${trimmedEventId}" not found in session "${session.session_id}".`,
        {
          status: 'EVENT_NOT_FOUND',
          session_id: session.session_id,
          event_id: trimmedEventId
        },
        false
      );
    }

    const normalizedStatus = normalizeOutcomeStatus(status);
    if (!normalizedStatus) {
      return okEnvelope(
        'krusch_action_outcome',
        `Unsupported outcome status "${String(status)}"; expected COMMITTED, ERROR, or ABORTED.`,
        {
          status: 'INVALID_OUTCOME_STATUS',
          session_id: session.session_id,
          event_id: event.event_id
        },
        false
      );
    }

    let nextCanonicalJson = event.canonical_args_json;
    let nextCallSignature = event.call_signature;
    if (canonical_args && typeof canonical_args === 'object') {
      const recomputed = canonicalizeToolCallKey(event.tool_name, canonical_args);
      if (recomputed.callSignature !== event.call_signature) {
        recordPreOutcomeSignature(session.session_id, event.event_id, event.call_signature);
      }
      nextCanonicalJson = recomputed.canonicalArgsJson;
      nextCallSignature = recomputed.callSignature;
    }

    const boundedPreview = String(result_preview ?? '').slice(0, MAX_RESULT_PREVIEW_CHARS);
    const now = Date.now();

    let committedMutations = Number(session.committed_mutations || 0);
    let committedReads = Number(session.committed_reads || 0);

    db.exec('BEGIN IMMEDIATE');
    try {
      updateEventOutcomeStmt.run(
        nextCanonicalJson,
        nextCallSignature,
        normalizedStatus,
        boundedPreview,
        now,
        event.event_id,
        session.session_id
      );

      const totals = countCommittedTotalsStmt.get(session.session_id);
      committedMutations = Number(totals?.committed_mutations || 0);
      committedReads = Number(totals?.committed_reads || 0);

      updateSessionCommittedTotalsStmt.run(
        committedMutations,
        committedReads,
        now,
        session.session_id
      );
      db.exec('COMMIT');
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* ignore rollback error */
      }
      throw err;
    }

    return okEnvelope(
      'krusch_action_outcome',
      `Recorded ${normalizedStatus} outcome for ${event.tool_name} (${event.event_id}).`,
      {
        session_id: session.session_id,
        event_id: event.event_id,
        status: normalizedStatus,
        call_signature: nextCallSignature,
        committed_mutations: committedMutations,
        committed_reads: committedReads
      },
      true
    );
  }

  /**
   * Verify whether the model may terminate its turn or should be nudged to execute its action
   * instead of printing an uncommitted draft or prematurely stopping with zero mutations.
   * @param {object} [params={}]
   */
  function verifyStop({
    session_id,
    step = 0,
    final_text = '',
    has_mutating_tools_available = true
  } = {}) {
    const trimmedSessionId = typeof session_id === 'string' ? session_id.trim() : '';
    const session = trimmedSessionId ? selectSessionStmt.get(trimmedSessionId) : null;
    if (!session) {
      return okEnvelope(
        'krusch_action_verify_stop',
        `Action harness session "${trimmedSessionId}" not found.`,
        {
          status: 'SESSION_NOT_FOUND',
          session_id: trimmedSessionId,
          allow_stop: true
        },
        false
      );
    }

    const committedMutations = Number(session.committed_mutations || 0);
    const verifyNudgesUsed = Number(session.verify_nudges_used || 0);
    const maxVerifyNudges = Number(session.max_verify_nudges || 0);
    const finalText = String(final_text ?? '');
    const goalText = String(session.goal ?? '');
    const stepNum = normalizeNonNegativeInt(step, 0);
    const now = Date.now();

    const eligibleForNudge =
      committedMutations === 0 &&
      verifyNudgesUsed < maxVerifyNudges &&
      has_mutating_tools_available !== false &&
      !DRAFT_ONLY_GOAL_EXEMPT_RE.test(goalText);

    if (eligibleForNudge) {
      let reasonCode = null;
      let steerPrompt = VERIFY_STOP_STEER_PROMPT;

      if (SERIALIZED_TOOL_CALL_IN_TEXT_RE.test(finalText)) {
        reasonCode = 'SERIALIZED_TOOL_CALL_IN_TEXT';
        steerPrompt = VERIFY_STOP_SERIALIZED_TOOL_STEER_PROMPT;
      } else if (
        PERMISSION_ASK_FINAL_TEXT_RE.test(finalText) ||
        FORMATTED_DRAFT_HEADER_RE.test(finalText)
      ) {
        reasonCode = 'UNCOMMITTED_DRAFT_OR_PERMISSION_ASK';
      } else if (
        IMPERATIVE_GOAL_VERB_RE.test(goalText) &&
        !POLICY_ABSTENTION_RATIONALE_RE.test(finalText) &&
        !PURE_QUESTION_GOAL_RE.test(goalText)
      ) {
        reasonCode = 'IMPERATIVE_GOAL_ZERO_MUTATION';
      }

      if (reasonCode) {
        const nextVerifyNudges = verifyNudgesUsed + 1;
        const eventId = `evt_${crypto.randomUUID()}`;
        const { canonicalArgsJson, callSignature } = canonicalizeToolCallKey('__verify_stop__', {
          step: stepNum,
          reason_code: reasonCode
        });

        db.exec('BEGIN IMMEDIATE');
        try {
          incrementVerifyNudgeStmt.run(nextVerifyNudges, now, session.session_id);
          insertEventStmt.run(
            eventId,
            session.session_id,
            stepNum,
            '__verify_stop__',
            0,
            0,
            canonicalArgsJson,
            callSignature,
            'CONTINUE_VERIFY',
            'NUDGED',
            JSON.stringify([{ code: reasonCode }]),
            finalText.slice(0, MAX_RESULT_PREVIEW_CHARS),
            now,
            now
          );
          db.exec('COMMIT');
        } catch (err) {
          try {
            db.exec('ROLLBACK');
          } catch {
            /* ignore rollback error */
          }
          throw err;
        }

        return okEnvelope(
          'krusch_action_verify_stop',
          `Verify-on-stop gate triggered CONTINUE_VERIFY (${reasonCode}).`,
          {
            session_id: session.session_id,
            decision: 'CONTINUE_VERIFY',
            allow_stop: false,
            reason_code: reasonCode,
            verify_nudges_used: nextVerifyNudges,
            steer_prompt: steerPrompt
          },
          true
        );
      }
    }

    markSessionCompletedStmt.run(now, session.session_id);

    return okEnvelope(
      'krusch_action_verify_stop',
      `Session ${session.session_id} verified complete (ALLOW_STOP).`,
      {
        session_id: session.session_id,
        decision: 'ALLOW_STOP',
        allow_stop: true,
        reason_code: 'VERIFIED_COMPLETE',
        verify_nudges_used: verifyNudgesUsed
      },
      true
    );
  }

  /**
   * Return full audit summary and ordered event log for a session.
   * @param {object} [params={}]
   */
  function sessionSummary({ session_id } = {}) {
    const trimmedSessionId = typeof session_id === 'string' ? session_id.trim() : '';
    const session = trimmedSessionId ? selectSessionStmt.get(trimmedSessionId) : null;
    if (!session) {
      return okEnvelope(
        'krusch_action_summary',
        `Action harness session "${trimmedSessionId}" not found.`,
        { status: 'SESSION_NOT_FOUND', session_id: trimmedSessionId },
        false
      );
    }

    const rawEvents = selectSessionEventsOrderedStmt.all(session.session_id);
    let blockedSpinLoops = 0;
    let blockedReadStreaks = 0;
    let blockedDuplicateWrites = 0;
    let heldForRevision = 0;

    const events = rawEvents.map((row) => {
      if (row.decision === 'BLOCK_SPIN_LOOP') blockedSpinLoops += 1;
      else if (row.decision === 'BLOCK_READ_STREAK') blockedReadStreaks += 1;
      else if (row.decision === 'BLOCK_DUPLICATE_WRITE') blockedDuplicateWrites += 1;
      else if (row.decision === 'HOLD_FOR_REVISION') heldForRevision += 1;

      return {
        event_id: row.event_id,
        session_id: row.session_id,
        step: Number(row.step || 0),
        tool_name: row.tool_name,
        is_mutating: Boolean(row.is_mutating),
        is_memory_search: Boolean(row.is_memory_search),
        canonical_args_json: row.canonical_args_json,
        call_signature: row.call_signature,
        decision: row.decision,
        status: row.status,
        issues: safeParseIssuesJson(row.issues_json),
        result_preview: row.result_preview,
        created_at_ms: Number(row.created_at_ms),
        updated_at_ms: Number(row.updated_at_ms)
      };
    });

    return okEnvelope(
      'krusch_action_summary',
      `Session ${session.session_id} (${session.status}): ${events.length} event(s), ${Number(session.committed_mutations)} committed mutation(s).`,
      {
        session_id: session.session_id,
        status: session.status,
        persona: session.persona,
        goal: session.goal,
        anchor_date: session.anchor_date,
        counts: {
          total_events: events.length,
          committed_reads: Number(session.committed_reads || 0),
          committed_mutations: Number(session.committed_mutations || 0),
          blocked_spin_loops: blockedSpinLoops,
          blocked_read_streaks: blockedReadStreaks,
          blocked_duplicate_writes: blockedDuplicateWrites,
          held_for_revision: heldForRevision,
          verify_nudges_used: Number(session.verify_nudges_used || 0)
        },
        events
      },
      true
    );
  }

  return {
    startSession,
    interceptToolCall,
    recordToolOutcome,
    verifyStop,
    sessionSummary
  };
}
