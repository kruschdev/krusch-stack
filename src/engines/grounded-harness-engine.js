/**
 * @module engines/grounded-harness-engine
 * Tier 3B Extension: Turn-0 Grounded, Scale-Aware, Defect-Only Agent Harness Engine (INV-STACK-11).
 *
 * Enforces INV-STACK-01 (zero external dependencies, Node 22 native node:sqlite + node:crypto + node:fs),
 * INV-STACK-02 (deterministic okEnvelope return contract), INV-STACK-04 (sanitized public defaults),
 * and INV-GH-01..10:
 *   1. Zero-LLM Turn-0 workspace schema introspection (RFC-4180 CSV/TSV literal "NA" keep_default_na=False
 *      flags, JSON/JSONL null vs [] wildcard flags, read-only SQLite DDL & row counts, code symbol headers,
 *      and 256/32-token Raw-RAG BM25 document chunks) + SHA-256 prefixHash KV-cache normalization.
 *   2. Gemini tool-less guard (functionCallingConfig: { mode: 'NONE' } when tools is omitted/empty).
 *   3. Monotonic scale-aware thinking & verification curve (SMALL_MODEL, MID_MODEL, FRONTIER_REASONING).
 *   4. Quote-safe, Python-floor-division-safe comment-normalized call hashing (MEMOIZED_PRIOR_READ -> BLOCK_SPIN_LOOP)
 *      with maxReadStreak = 0 (unlimited distinct multi-step reads) and post-mutation verification re-reads.
 *   5. Passive safety floor, secret-leak guard, duplicate-write guard, staged-diff-only FORCE_VERIFY,
 *      and zero-turn-when-healthy defect-only output gate (inspectOutputDefects).
 *   6. Partial stdout preservation on subprocess/sandbox timeouts (execCommandWithPartialStdout).
 *   7. INV-GH-11 Meta-Harness failure-trace mining, holdout-verified regex synthesis, and default
 *      evolved rules (GH-EVO-01..05).
 *   8. INV-GH-12 Early Scope & Authorization Drift + SERS data-minimization guard and DART
 *      zero-turn MCP-vs-CLI boundary realization repair/hold.
 *   9. INV-GH-13 3-Strike Zero-Progress Mutation Stall Breaker (evaluateMutationStallGuard).
 *  10. INV-GH-14 Upstream Source Fingerprint Drift Invalidation (evaluateSourceFingerprintDrift).
 *  11. INV-GH-15 // INFALLIBLE: <reason> Panic & Assertion Surface Auditor (auditInfallibleAssertions).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { okEnvelope } from '../db/sqlite.js';
import { scanForSecretLeak } from './fs-engine.js';
import { classifyToolMutability } from './action-harness-engine.js';
import {
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift
} from './grounded-auth-drift.js';
import {
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  compileExecutableRules,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  synthesizeRulesWithTeacher,
  evolveRulesFromTraces
} from './grounded-trace-synthesizer.js';

export const GROUNDED_HARNESS_SCHEMA_SQL = `
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
    schema_reduction_pct REAL NOT NULL DEFAULT 0,
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
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
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
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_grounded_events_sig
    ON grounded_events(session_id, call_signature);

  CREATE INDEX IF NOT EXISTS idx_grounded_events_session_time
    ON grounded_events(session_id, created_at_ms);
`;

export const SCALE_TIERS = Object.freeze({
  SMALL_MODEL: 'SMALL_MODEL',
  MID_MODEL: 'MID_MODEL',
  FRONTIER_REASONING: 'FRONTIER_REASONING'
});

const FRONTIER_MODEL_RE =
  /\b(?:gemini-(?:2\.5|3|4)|argon|gpt-(?:4\.1|5)|o[134](?:-|\b)|claude-(?:3-7|4|opus|sonnet-4|sonnet-5)|deepseek-r1|qwq|kimi-k[23])\b/i;

const NATIVE_THINKING_MODEL_RE =
  /\b(?:gemini-(?:3|4)|argon|deepseek-r1|qwq|o[134](?:-|\b)|gpt-5)\b/i;

const KNOWN_MOE_TOTAL_ACTIVE = [
  { re: /qwen3(?:-coder)?-30b(?:-a3b|-moe)?/i, totalParamsB: 30.5, activeParamsB: 3.3 },
  { re: /qwen3(?:-coder)?-next-80b/i, totalParamsB: 80, activeParamsB: 3.0 },
  { re: /gpt-oss[:-]?120b/i, totalParamsB: 117, activeParamsB: 5.1 },
  { re: /gpt-oss[:-]?20b/i, totalParamsB: 21, activeParamsB: 3.6 },
  { re: /mixtral[-_:]?8x7b/i, totalParamsB: 47, activeParamsB: 13 },
  { re: /mixtral[-_:]?8x22b/i, totalParamsB: 141, activeParamsB: 39 }
];

const DESTRUCTIVE_SHELL_RE =
  /(?:\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+\/(?:\s|["';|&)]|$)|:\(\)\s*\{\s*:\|:&\s*\};:|\bmkfs\.[a-z0-9]+\b|\bdd\s+if=\/dev\/zero\s+of=\/dev\/(?:sd|nvme|vd)[a-z0-9]+|\bDROP\s+DATABASE\s+production\b)/i;

const PLACEHOLDER_RE =
  /\{\{\s*[a-zA-Z0-9_.-]+\s*\}\}|<insert[^>]*>|\[insert[^\]]*\]|\{\s*todo\s*\}|\byour_name_here\b|\bplaceholder\b/i;

const EXACT_PLACEHOLDER_TOKEN_RE = /^(?:TBD|TODO|YYYY-MM-DD|MM\/DD\/YYYY)$/i;

const DATE_FIELD_KEY_RE =
  /(?:^|_)(?:date|check_in|check_out|due_date|start_date|end_date|departure_date|return_date)$/i;

const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})/;

const CODE_LIKE_KEY_RE =
  /(?:^|_)(?:code|script|sql|query|command|cmd|python|py|bash|sh)$/i;

const EMPTY_SCALAR_BAILOUT_SET = new Set(['', 'none', 'null', 'nan', 'undefined', '[]', '{}']);

const TRUNCATED_FINISH_REASONS = new Set([
  'length',
  'max_tokens',
  'MAX_TOKENS',
  'MALFORMED_FUNCTION_CALL',
  'malformed_function_call',
  'incomplete'
]);

const SERIALIZED_TOOL_CALL_RE =
  /<tool_call\b[\s\S]*?>|<function=[a-zA-Z0-9_.-]+|\bcall:[a-zA-Z0-9_.-]+\s*\{|\{\s*"name"\s*:\s*"[a-zA-Z0-9_.-]+"\s*,\s*"(?:arguments|parameters)"\s*:\s*\{/i;

const RAW_REPR_LEAK_RE =
  /\bnp\.(?:float(?:16|32|64)|int(?:8|16|32|64)|uint(?:8|16|32|64)|bool_)\s*\(|(?:\[\d+\s+rows\s+x\s+\d+\s+columns\]|\bName:\s+[^\n]+,\s*dtype:\s*(?:float64|int64|object|bool)\b|^Empty DataFrame\b)/m;

const UNCOMMITTED_DRAFT_RE =
  /(?:^|\n)\s*(?:\*\*?)?(?:subject|draft|proposed\s+(?:email|message|reply))(?:\*\*?)?\s*:/i;

const POLICY_ABSTENTION_RE =
  /\b(?:cannot|can't|unable\s+to|prohibited|policy|requires\s+(?:approval|sign-off|manual)|not\s+authorized|declining|skipping|abstain)\b/i;

const LITERAL_NA_TOKENS = new Set(['NA', 'N/A', '#N/A', 'NULL']);

const IGNORED_GROUND_DIRS = new Set([
  '.git',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.pytest_cache',
  '.agent',
  '.krusch-stack',
  'dist',
  'build',
  'logs'
]);

const FORAGING_TOOL_RE =
  /(?:^|_|\.)(?:read_file|list_dir|read_tree|locate|glob|ls|head|schema|describe_table|list_tables)$/i;

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

function estimateTokens(text) {
  const s = String(text || '');
  if (!s) return 0;
  return Math.ceil(s.length / 4);
}

/**
 * Infer total/active parameter counts (in billions) and MoE/frontier flags from a model identifier.
 * @param {string} [model='']
 */
export function inferModelScaleMetadata(model = '') {
  const raw = String(model || '').trim();
  for (const entry of KNOWN_MOE_TOTAL_ACTIVE) {
    if (entry.re.test(raw)) {
      return {
        isMoe: true,
        totalParamsB: entry.totalParamsB,
        activeParamsB: entry.activeParamsB,
        isFrontierFamily: entry.totalParamsB >= 70 || FRONTIER_MODEL_RE.test(raw),
        nativeThinkingDefault: NATIVE_THINKING_MODEL_RE.test(raw)
      };
    }
  }

  const moeNxM = raw.match(/\b(\d+)\s*x\s*(\d+(?:\.\d+)?)\s*b\b/i);
  if (moeNxM) {
    const experts = Number(moeNxM[1]);
    const perExpert = Number(moeNxM[2]);
    const total = Math.round(experts * perExpert);
    const active = Math.round(Math.min(total, perExpert * 2));
    return {
      isMoe: true,
      totalParamsB: total,
      activeParamsB: active,
      isFrontierFamily: total >= 70 || FRONTIER_MODEL_RE.test(raw),
      nativeThinkingDefault: NATIVE_THINKING_MODEL_RE.test(raw)
    };
  }

  const edgeParamMatch = raw.match(/(?:^|[:-])e(\d+(?:\.\d+)?)b\b/i);
  const stdParamMatch = raw.match(/(?:^|[^a-zA-Z0-9])(\d+(?:\.\d+)?)b\b/i);
  const parsedB = edgeParamMatch
    ? Number(edgeParamMatch[1])
    : stdParamMatch
      ? Number(stdParamMatch[1])
      : null;

  const isFrontier = FRONTIER_MODEL_RE.test(raw) || (parsedB !== null && parsedB >= 70);
  return {
    isMoe: /\bmoe\b|-a\d+b\b/i.test(raw),
    totalParamsB: parsedB,
    activeParamsB: parsedB,
    isFrontierFamily: isFrontier,
    nativeThinkingDefault: NATIVE_THINKING_MODEL_RE.test(raw)
  };
}

/**
 * Resolve monotonic scale-aware harness profile (`INV-GH-03`).
 * @param {object} [options]
 */
export function resolveScaleProfile(options = {}) {
  const model = String(options.model || '').trim();
  const inferred = inferModelScaleMetadata(model);

  const totalParamsB =
    typeof options.totalParamsB === 'number' && Number.isFinite(options.totalParamsB)
      ? options.totalParamsB
      : inferred.totalParamsB;
  const activeParamsB =
    typeof options.activeParamsB === 'number' && Number.isFinite(options.activeParamsB)
      ? options.activeParamsB
      : inferred.activeParamsB;

  const reasoningEffort = String(options.reasoningEffort || '').trim().toLowerCase();
  const thinkingEnabled =
    typeof options.thinkingEnabled === 'boolean'
      ? options.thinkingEnabled
      : reasoningEffort === 'low' || reasoningEffort === 'medium' || reasoningEffort === 'high'
        ? true
        : reasoningEffort === 'none'
          ? false
          : inferred.nativeThinkingDefault;

  let tier = SCALE_TIERS.MID_MODEL;
  if (
    thinkingEnabled ||
    inferred.isFrontierFamily ||
    (totalParamsB !== null && totalParamsB >= 70)
  ) {
    tier = SCALE_TIERS.FRONTIER_REASONING;
  } else if (
    inferred.isMoe &&
    totalParamsB !== null &&
    totalParamsB >= 15 &&
    !options.preferThinkingStepForSmallActive
  ) {
    tier = SCALE_TIERS.MID_MODEL;
  } else if (
    (activeParamsB !== null && activeParamsB < 15) ||
    (totalParamsB !== null && totalParamsB < 15)
  ) {
    tier = SCALE_TIERS.SMALL_MODEL;
  }

  const isSmall = tier === SCALE_TIERS.SMALL_MODEL;
  const isFrontier = tier === SCALE_TIERS.FRONTIER_REASONING;

  return {
    model,
    tier,
    isMoe: inferred.isMoe,
    inferredActiveParamsB: activeParamsB !== null ? Math.round(activeParamsB) : null,
    inferredTotalParamsB: totalParamsB !== null ? Math.round(totalParamsB) : null,
    thinkingEnabled: Boolean(thinkingEnabled),
    injectPlanBindStep: isSmall,
    softHoldPlaceholdersAndDates: isSmall,
    rescueSerializedToolCalls: !isFrontier,
    maxMechanicalVerifyNudges: isSmall ? 1 : 0,
    maxReadStreak: 0,
    enforceZeroMutationImperativeNudge: false,
    enforceTwoPhaseAnalyticalNudge: false
  };
}

/**
 * Emit compact scale-tier guidance (`[PLAN -> BIND -> ACT]` for SMALL_MODEL; empty string otherwise).
 * @param {ReturnType<typeof resolveScaleProfile>} profile
 */
export function buildScaleAwareDirective(profile) {
  if (!profile || !profile.injectPlanBindStep) return '';
  return '[PLAN -> BIND -> ACT] Before calling any mutating tool, verify target IDs, dates (YYYY-MM-DD), and concrete parameter values from grounded state; never pass placeholders.';
}

/**
 * Inject Gemini `functionCallingConfig: { mode: 'NONE' }` when `tools` is omitted or empty (`INV-GH-09`).
 * @param {object} [options]
 */
export function buildSafeGeminiToolConfig({
  tools,
  toolConfig,
  disableAutoToolConfigNone = false
} = {}) {
  if (toolConfig && typeof toolConfig === 'object') {
    return toolConfig;
  }
  if (disableAutoToolConfigNone === true) {
    return null;
  }
  const hasTools = Array.isArray(tools) && tools.length > 0;
  if (!hasTools) {
    return { functionCallingConfig: { mode: 'NONE' } };
  }
  return null;
}

/**
 * Strip comments outside string literals while preserving Python `//` integer floor division
 * and line indentation (`INV-GH-04`).
 * @param {string} [source='']
 * @param {string} [keyHint='']
 */
export function normalizeCodeSnippetForHash(source = '', keyHint = '') {
  const raw = String(source ?? '');
  if (!raw) return '';
  const hint = String(keyHint || '').toLowerCase();
  const isSql = hint.includes('sql') || /^\s*(?:select|with|insert|update|delete|pragma)\b/i.test(raw);
  const isJsLike =
    hint === 'js' || hint === 'ts' || /\b(?:const|let|export\s+function|=>)\b/.test(raw);

  const lines = raw.replace(/\r\n/g, '\n').split('\n');
  const cleanedLines = [];

  for (const line of lines) {
    let out = '';
    let inSingle = false;
    let inDouble = false;
    let inBacktick = false;

    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      const next = line[i + 1] || '';

      if ((inSingle || inDouble || inBacktick) && ch === '\\') {
        out += ch + next;
        i += 1;
        continue;
      }
      if (!inDouble && !inBacktick && ch === "'") {
        inSingle = !inSingle;
        out += ch;
        continue;
      }
      if (!inSingle && !inBacktick && ch === '"') {
        inDouble = !inDouble;
        out += ch;
        continue;
      }
      if (!inSingle && !inDouble && ch === '`') {
        inBacktick = !inBacktick;
        out += ch;
        continue;
      }

      if (!inSingle && !inDouble && !inBacktick) {
        if (isSql && ch === '-' && next === '-') {
          break;
        }
        if (!isJsLike && ch === '#') {
          break;
        }
        if (isJsLike && ch === '/' && next === '/') {
          break;
        }
      }
      out += ch;
    }

    const trimmedRight = out.replace(/[ \t]+$/g, '');
    if (trimmedRight.trim().length > 0) {
      cleanedLines.push(trimmedRight);
    }
  }

  return cleanedLines.join('\n');
}

function canonicalizeValue(value, keyHint = '', seen = new WeakSet()) {
  if (value === null || value === undefined) {
    return value === undefined ? undefined : null;
  }
  if (typeof value === 'string') {
    if (CODE_LIKE_KEY_RE.test(keyHint)) {
      return normalizeCodeSnippetForHash(value, keyHint);
    }
    return value;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : null;
  }
  if (typeof value !== 'object') {
    return value;
  }
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) {
    const arr = value.map((item) => {
      const next = canonicalizeValue(item, keyHint, seen);
      return next === undefined ? null : next;
    });
    seen.delete(value);
    return arr;
  }
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    const next = canonicalizeValue(value[key], key, seen);
    if (next !== undefined) {
      sorted[key] = next;
    }
  }
  seen.delete(value);
  return sorted;
}

/**
 * Compute comment-normalized canonical JSON and SHA-256 signature for a tool call (`INV-GH-04`).
 * @param {string} toolName
 * @param {object} [args={}]
 */
export function canonicalizeGroundedToolCallKey(toolName, args = {}) {
  const normalizedName = String(toolName || '').trim();
  const safeArgs = args && typeof args === 'object' && !Array.isArray(args) ? args : {};
  const canonicalArgs = canonicalizeValue(safeArgs);
  const canonicalArgsJson = JSON.stringify(canonicalArgs);
  const callSignature = sha256Hex(`${normalizedName}\n${canonicalArgsJson}`);
  return { canonicalArgs, canonicalArgsJson, callSignature };
}

function stripMarkdownCodeBlocks(text) {
  return String(text || '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`\n]+`/g, ' ');
}

/**
 * Zero-turn-when-healthy objective output defect inspector (`INV-GH-05`).
 * Never blocks legitimate answers such as `0`, `"0"`, `false`, `"Not Applicable"`, or `"N/A"`.
 * @param {object} [options]
 */
export function inspectOutputDefects({
  candidateAnswer = undefined,
  assistantText = '',
  finishReason = null,
  truncatedToolCalls = false,
  toolCalls = [],
  expectNonEmptyAnswer = false
} = {}) {
  const defects = [];
  const rawAssistant = String(assistantText ?? '');
  const hasStructuredTools = Array.isArray(toolCalls) && toolCalls.length > 0;

  if (
    truncatedToolCalls === true ||
    (finishReason && TRUNCATED_FINISH_REASONS.has(String(finishReason).trim()))
  ) {
    defects.push({
      code: 'TRUNCATED_OUTPUT',
      message: `Model generation terminated with truncation/malformed reason (${String(finishReason || 'truncatedToolCalls')}). Emit a concise, complete response or smaller tool payload.`
    });
  }

  if (!hasStructuredTools && SERIALIZED_TOOL_CALL_RE.test(stripMarkdownCodeBlocks(rawAssistant))) {
    defects.push({
      code: 'SERIALIZED_TOOL_CALL_IN_TEXT',
      message:
        'Detected a serialized XML/JSON tool invocation inside plain text while toolCalls is empty. Re-issue via structured tool_calls.'
    });
  }

  const candidateProvided = candidateAnswer !== undefined;
  const candidateStr = candidateProvided
    ? typeof candidateAnswer === 'string'
      ? candidateAnswer.trim()
      : JSON.stringify(candidateAnswer)
    : rawAssistant.trim();

  if (expectNonEmptyAnswer) {
    const normalizedLower = String(candidateStr ?? '').trim().toLowerCase();
    if (
      candidateAnswer === null ||
      (typeof candidateAnswer === 'number' && Number.isNaN(candidateAnswer)) ||
      EMPTY_SCALAR_BAILOUT_SET.has(normalizedLower)
    ) {
      defects.push({
        code: 'EMPTY_OR_NULL_BAILOUT',
        message:
          'Output resolved to an empty/null/NaN bailout token where a concrete answer is expected. Compute and return the exact scalar, string, or structured answer.'
      });
    }
  }

  const reprTarget = candidateProvided ? String(candidateAnswer ?? '') : stripMarkdownCodeBlocks(rawAssistant);
  if (RAW_REPR_LEAK_RE.test(reprTarget)) {
    defects.push({
      code: 'RAW_DATAFRAME_OR_NUMPY_REPR',
      message:
        'Detected unformatted pandas DataFrame summary or NumPy scalar repr (e.g. np.float64(...) / dtype:). Format clean scalar/JSON values.'
    });
  }

  const primaryDefect = defects[0] || null;
  return {
    hasDefect: defects.length > 0,
    defects,
    primaryDefect,
    correctivePrompt: primaryDefect ? `OUTPUT DEFECT GATE (${primaryDefect.code}): ${primaryDefect.message}` : null,
    rescuedToolCalls: []
  };
}

/**
 * Format a subprocess/sandbox timeout while preserving partial stdout (`INV-GH-10`).
 * @param {object} [options]
 */
export function formatTimeoutWithPartialStdout({
  timeoutMs = 0,
  timeoutSeconds = null,
  stdout = '',
  stderr = '',
  maxStdoutChars = 8000,
  label = 'Sandbox execution'
} = {}) {
  const secs =
    typeof timeoutSeconds === 'number' && Number.isFinite(timeoutSeconds)
      ? timeoutSeconds
      : Number((Number(timeoutMs || 0) / 1000).toFixed(2));
  const boundedStdout = String(stdout || '').slice(0, maxStdoutChars);
  const boundedStderr = String(stderr || '').slice(0, 2000);
  const errorMsg = `TimeoutError: ${label} exceeded ${secs}s limit.`;
  const formattedObservation = boundedStdout
    ? `${errorMsg}\n[PARTIAL STDOUT BEFORE TIMEOUT]\n${boundedStdout}`
    : errorMsg;

  return {
    ok: false,
    timedOut: true,
    stdout: boundedStdout,
    stderr: boundedStderr,
    hasFinalAnswer: false,
    finalAnswer: null,
    error: errorMsg,
    formattedObservation
  };
}

/**
 * Execute a subprocess with hard timeout while preserving partial stdout emitted before kill (`INV-GH-10`).
 * @param {string} command
 * @param {string[]} [args=[]]
 * @param {object} [options={}]
 */
export function execCommandWithPartialStdout(command, args = [], options = {}) {
  const timeoutMs = Math.max(25, Number(options.timeoutMs || 10000));
  const maxStdoutChars = Math.max(256, Number(options.maxStdoutChars || 8000));
  const label = String(options.label || command);

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;

    const child = spawn(command, args, {
      cwd: options.cwd || process.cwd(),
      env: options.env || process.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    }, timeoutMs);

    child.stdout?.on('data', (chunk) => {
      if (stdout.length < maxStdoutChars) {
        stdout += chunk.toString('utf8').slice(0, maxStdoutChars - stdout.length);
      }
    });

    child.stderr?.on('data', (chunk) => {
      if (stderr.length < 4000) {
        stderr += chunk.toString('utf8').slice(0, 4000 - stderr.length);
      }
    });

    const finish = (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (timedOut) {
        resolve(
          formatTimeoutWithPartialStdout({
            timeoutMs,
            stdout,
            stderr,
            maxStdoutChars,
            label
          })
        );
        return;
      }
      resolve({
        ok: exitCode === 0,
        timedOut: false,
        exitCode,
        stdout,
        stderr,
        hasFinalAnswer: false,
        finalAnswer: null,
        error: exitCode === 0 ? null : stderr || `Process exited with code ${String(exitCode)}`,
        formattedObservation: stdout
      });
    };

    child.on('error', (err) => {
      stderr = `${stderr}\n${err.message}`.trim();
      finish(1);
    });
    child.on('close', (code) => finish(code ?? 1));
  });
}

function parseDelimitedLine(line, delimiter = ',') {
  const cells = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
    } else if (ch === delimiter) {
      cells.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  cells.push(cur);
  return cells;
}

function inferColumnProfile(name, values) {
  const nonEmpty = [];
  const literalNaTokens = new Set();
  for (const raw of values) {
    const trimmed = String(raw ?? '').trim();
    if (trimmed === '') continue;
    if (LITERAL_NA_TOKENS.has(trimmed.toUpperCase())) {
      literalNaTokens.add(trimmed);
    }
    nonEmpty.push(trimmed);
  }

  let inferredType = 'string';
  const nonHazard = nonEmpty.filter((v) => !LITERAL_NA_TOKENS.has(v.toUpperCase()));
  if (nonEmpty.length > 0 && literalNaTokens.size === 0 && nonHazard.length > 0) {
    if (nonHazard.every((v) => /^-?\d+(?:\.\d+)?$/.test(v))) {
      inferredType = nonHazard.every((v) => /^-?\d+$/.test(v)) ? 'integer' : 'number';
    } else if (nonHazard.every((v) => /^(?:true|false)$/i.test(v))) {
      inferredType = 'boolean';
    }
  }

  return {
    name,
    inferredType: literalNaTokens.size > 0 ? 'string' : inferredType,
    hasLiteralNaString: literalNaTokens.size > 0,
    literalNaTokens: [...literalNaTokens],
    sampleValues: [...new Set(nonEmpty)].slice(0, 4)
  };
}

/**
 * Zero-LLM Turn-0 workspace schema & hazard introspector (`INV-GH-01`).
 * Skips `.env` and secret files automatically.
 * @param {string} workspaceDir
 * @param {object} [options={}]
 */
export function introspectWorkspaceSchemas(workspaceDir, options = {}) {
  const rootDir = path.resolve(workspaceDir || process.cwd());
  const maxFiles = Math.max(1, Number(options.maxFiles || 48));
  const files = [];
  const docFiles = [];
  const fileDigests = {};
  const summaryLines = [];

  function walk(dir) {
    if (files.length >= maxFiles || !fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name)
    );
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      if (entry.isSymbolicLink()) continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_GROUND_DIRS.has(entry.name)) continue;
        walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (
        entry.name === '.env' ||
        (entry.name.startsWith('.env.') && entry.name !== '.env.example')
      ) {
        continue;
      }

      const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');
      const stat = fs.statSync(fullPath);
      if (stat.size > 8 * 1024 * 1024) continue;

      const ext = path.extname(entry.name).toLowerCase();
      const rawBuf = fs.readFileSync(fullPath);
      fileDigests[relPath] = sha256Hex(rawBuf);

      if (ext === '.csv' || ext === '.tsv') {
        const delimiter = ext === '.tsv' ? '\t' : ',';
        const text = rawBuf.toString('utf8');
        const lines = text.replace(/\r\n/g, '\n').split('\n').filter((l) => l.length > 0);
        const headers = lines.length > 0 ? parseDelimitedLine(lines[0], delimiter) : [];
        const sampleRows = lines.slice(1, 201).map((l) => parseDelimitedLine(l, delimiter));
        const columns = headers.map((h, colIdx) =>
          inferColumnProfile(
            h,
            sampleRows.map((r) => r[colIdx] ?? '')
          )
        );
        const naHazardColumns = columns.filter((c) => c.hasLiteralNaString).map((c) => c.name);
        const hasLiteralNaHazard = naHazardColumns.length > 0;
        files.push({
          relPath,
          kind: 'tabular',
          rowCountEstimate: Math.max(0, lines.length - 1),
          columns,
          hasLiteralNaHazard,
          naHazardColumns
        });
        const colSummary = columns
          .map((c) => `${c.name}:${c.inferredType}(e.g. ${c.sampleValues.slice(0, 2).join('|')})`)
          .join(', ');
        summaryLines.push(`- [TABULAR] ${relPath} (~${Math.max(0, lines.length - 1)} rows): ${colSummary}`);
        if (hasLiteralNaHazard) {
          summaryLines.push(
            `  ⚠️ CSV LITERAL "NA" HAZARD in ${relPath} [${naHazardColumns.join(', ')}]: Load with keep_default_na=False (or na_filter=False) so "NA" codes are not coerced to NaN!`
          );
        }
      } else if (ext === '.json' || ext === '.jsonl') {
        const text = rawBuf.toString('utf8').trim();
        let records = [];
        try {
          if (ext === '.jsonl') {
            records = text
              .split('\n')
              .slice(0, 100)
              .filter(Boolean)
              .map((l) => JSON.parse(l));
          } else {
            const parsed = JSON.parse(text);
            records = Array.isArray(parsed) ? parsed.slice(0, 100) : [parsed];
          }
        } catch {
          records = [];
        }
        const objRecords = records.filter((r) => r && typeof r === 'object' && !Array.isArray(r));
        const keySet = new Set();
        const nullFields = new Set();
        const emptyArrayFields = new Set();
        for (const rec of objRecords) {
          for (const [k, v] of Object.entries(rec)) {
            keySet.add(k);
            if (v === null) nullFields.add(k);
            if (Array.isArray(v) && v.length === 0) emptyArrayFields.add(k);
          }
        }
        const wildcardCandidateFields = [...new Set([...nullFields, ...emptyArrayFields])];
        files.push({
          relPath,
          kind: 'json',
          recordCount: records.length,
          keys: [...keySet],
          nullFields: [...nullFields],
          emptyArrayFields: [...emptyArrayFields],
          wildcardCandidateFields
        });
        summaryLines.push(`- [JSON] ${relPath} (${records.length} record(s)): keys=[${[...keySet].join(', ')}]`);
        if (wildcardCandidateFields.length > 0) {
          summaryLines.push(
            `  ⚠️ JSON NULL / EMPTY-LIST [] WILDCARD HAZARD in ${relPath}: fields [${wildcardCandidateFields.join(', ')}] contain null or [] — check domain wildcard/applies-to-all semantics!`
          );
        }
      } else if (ext === '.sqlite' || ext === '.db') {
        try {
          const roDb = new DatabaseSync(fullPath, { readOnly: true });
          try {
            const tbls = roDb
              .prepare(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
              )
              .all();
            const tableSummaries = tbls.map((t) => {
              const safeName = String(t.name).replace(/"/g, '""');
              const cnt = Number(roDb.prepare(`SELECT COUNT(*) AS c FROM "${safeName}"`).get()?.c || 0);
              return { name: t.name, rowCount: cnt, ddl: String(t.sql || '').replace(/\s+/g, ' ').trim() };
            });
            files.push({ relPath, kind: 'sqlite', tables: tableSummaries });
            summaryLines.push(
              `- [SQLITE] ${relPath}: ${tableSummaries.map((t) => `${t.name}(${t.rowCount} rows) -> ${t.ddl}`).join(' ; ')}`
            );
          } finally {
            roDb.close();
          }
        } catch {
          files.push({ relPath, kind: 'sqlite', tables: [] });
        }
      } else if (['.js', '.mjs', '.ts', '.py'].includes(ext)) {
        const text = rawBuf.toString('utf8');
        const symbols = [];
        const symRe =
          /(?:export\s+(?:async\s+)?function\s+([A-Za-z0-9_]+)|export\s+const\s+([A-Za-z0-9_]+)|def\s+([A-Za-z0-9_]+)\s*\(|class\s+([A-Za-z0-9_]+))/g;
        for (const m of text.matchAll(symRe)) {
          const sym = m[1] || m[2] || m[3] || m[4];
          if (sym && !symbols.includes(sym)) symbols.push(sym);
        }
        files.push({ relPath, kind: 'code', symbols });
        summaryLines.push(`- [CODE] ${relPath}: symbols=[${symbols.slice(0, 12).join(', ')}]`);
      } else if (['.md', '.txt', '.rst'].includes(ext)) {
        const text = rawBuf.toString('utf8');
        files.push({ relPath, kind: 'doc', bytes: rawBuf.length });
        docFiles.push({ relPath, text });
        summaryLines.push(`- [DOC] ${relPath} (${rawBuf.length} bytes)`);
      }
    }
  }

  walk(rootDir);

  return {
    workspaceDir: rootDir,
    fileCount: files.length,
    files,
    docFiles,
    fileDigests,
    schemaSummaryText: summaryLines.join('\n')
  };
}

function chunkAndRankRawDocs(docFiles, goalQuery, maxChunks = 4) {
  const windows = [];
  for (const doc of docFiles) {
    const words = String(doc.text || '').split(/\s+/).filter(Boolean);
    const windowWords = 192; // ~256 tokens
    const strideWords = 168; // ~32-token overlap
    if (words.length === 0) continue;
    for (let start = 0, idx = 0; start < words.length; start += strideWords, idx += 1) {
      const slice = words.slice(start, start + windowWords).join(' ');
      const chunkId = `${doc.relPath}#win_${idx}`;
      windows.push({ chunkId, file: doc.relPath, text: slice });
      if (start + windowWords >= words.length) break;
    }
  }
  if (windows.length === 0) return [];

  const qTerms = [
    ...new Set(
      String(goalQuery || '')
        .toLowerCase()
        .split(/[^a-z0-9_]+/)
        .filter((t) => t.length >= 2)
    )
  ];

  const N = windows.length;
  const avgDl = windows.reduce((acc, w) => acc + w.text.length, 0) / N || 1;
  const df = new Map();
  for (const term of qTerms) {
    let count = 0;
    for (const w of windows) {
      if (w.text.toLowerCase().includes(term)) count += 1;
    }
    df.set(term, count);
  }

  const scored = windows.map((w, orderIdx) => {
    const lower = w.text.toLowerCase();
    let score = 0;
    for (const term of qTerms) {
      const matches = lower.split(term).length - 1;
      if (matches <= 0) continue;
      const n = df.get(term) || 0;
      const idf = Math.log(1 + (N - n + 0.5) / (n + 0.5));
      const k1 = 1.2;
      const b = 0.75;
      const norm = matches * (k1 + 1) / (matches + k1 * (1 - b + b * (w.text.length / avgDl)));
      score += idf * norm;
    }
    return { ...w, score, orderIdx };
  });

  scored.sort((a, b) => b.score - a.score || a.orderIdx - b.orderIdx);
  return scored.slice(0, maxChunks);
}

function deferToolsForTurnZero(tools = [], pinnedToolNames = [], deferThreshold = 12) {
  const safeTools = Array.isArray(tools) ? tools : [];
  const rawTokens = estimateTokens(JSON.stringify(safeTools));
  if (safeTools.length <= deferThreshold) {
    return {
      deferred: false,
      exposedTools: safeTools,
      savings: { rawTokens, exposedTokens: rawTokens, tokensSaved: 0, reductionPct: 0 }
    };
  }
  const pinnedSet = new Set(pinnedToolNames);
  const pinned = safeTools.filter((t) => pinnedSet.has(t.name));
  const metaTools = [
    {
      name: 'tool_search',
      description: `Search ${safeTools.length} available tools by keyword/intent before invoking.`,
      inputSchema: {
        type: 'object',
        properties: { query: { type: 'string' }, limit: { type: 'number' } },
        required: ['query']
      },
      annotations: {
        title: 'Search Deferred Tools (BM25)',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    {
      name: 'tool_describe',
      description: 'Inspect the exact JSON Schema of a discovered tool by name.',
      inputSchema: {
        type: 'object',
        properties: { toolName: { type: 'string' } },
        required: ['toolName']
      },
      annotations: {
        title: 'Describe Deferred Tool Schema',
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    {
      name: 'tool_call',
      description: 'Invoke a discovered deferred tool with validated arguments.',
      inputSchema: {
        type: 'object',
        properties: { toolName: { type: 'string' }, args: { type: 'object' } },
        required: ['toolName']
      },
      annotations: {
        title: 'Invoke Deferred Tool',
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    }
  ];
  const exposedTools = [...pinned, ...metaTools];
  const exposedTokens = estimateTokens(JSON.stringify(exposedTools));
  const tokensSaved = Math.max(0, rawTokens - exposedTokens);
  const reductionPct = rawTokens > 0 ? Number(((tokensSaved / rawTokens) * 100).toFixed(2)) : 0;
  return {
    deferred: true,
    exposedTools,
    savings: { rawTokens, exposedTokens, tokensSaved, reductionPct }
  };
}

/**
 * Compile Turn-0 workspace schemas, 256/32 Raw-RAG chunks, scale-tier directive,
 * Gemini NONE toolConfig, and KV-cache-stable SHA-256 `prefixHash` (`INV-GH-01`, `INV-GH-02`, `INV-GH-09`).
 * @param {object} [options={}]
 */
export function compileTurnZeroGrounding(options = {}) {
  const goal = String(options.goal || '').trim();
  const workspaceDir = options.workspaceDir || process.cwd();
  const maxGroundingTokens = Math.max(256, Number(options.maxGroundingTokens || 3200));
  const standingInvariants = Array.isArray(options.standingInvariants)
    ? options.standingInvariants.map((s) => String(s).trim()).filter(Boolean)
    : [];
  const tools = Array.isArray(options.tools) ? options.tools : [];
  const deferThreshold = Number.isFinite(Number(options.deferThreshold))
    ? Number(options.deferThreshold)
    : 12;

  const scaleProfile = resolveScaleProfile({
    model: options.model || '',
    activeParamsB: options.activeParamsB,
    totalParamsB: options.totalParamsB,
    thinkingEnabled: options.thinkingEnabled,
    reasoningEffort: options.reasoningEffort
  });
  const scaleDirective = buildScaleAwareDirective(scaleProfile);
  const geminiToolConfig = buildSafeGeminiToolConfig({
    tools,
    toolConfig: options.toolConfig,
    disableAutoToolConfigNone: options.disableAutoToolConfigNone
  });

  const workspace = introspectWorkspaceSchemas(workspaceDir, { maxFiles: options.maxFiles });
  const toolGate = deferToolsForTurnZero(tools, options.pinnedToolNames || [], deferThreshold);

  const staticPrefixParts = [
    options.systemPrompt ? String(options.systemPrompt).trim() : 'You are a grounded autonomous engineering & analytics agent.',
    standingInvariants.length > 0
      ? `[STANDING INVARIANTS]\n${standingInvariants.map((inv, idx) => `${idx + 1}. ${inv}`).join('\n')}`
      : '',
    scaleDirective,
    workspace.schemaSummaryText ? `[WORKSPACE SCHEMAS & HAZARDS]\n${workspace.schemaSummaryText}` : ''
  ].filter(Boolean);

  const compiledSystemPrompt = staticPrefixParts.join('\n\n');
  const canonicalToolNames = toolGate.exposedTools.map((t) => t.name).sort().join(',');
  const prefixHash = sha256Hex(`${compiledSystemPrompt}\n[TOOLS:${canonicalToolNames}]`);

  const schemaTokens = estimateTokens(workspace.schemaSummaryText);
  const remainingChunkBudget = Math.max(128, maxGroundingTokens - Math.min(schemaTokens, maxGroundingTokens - 128));
  const rawChunks = chunkAndRankRawDocs(workspace.docFiles, goal, 6);

  const retrievedChunks = [];
  let chunkTokensUsed = 0;
  for (const ch of rawChunks) {
    const t = estimateTokens(ch.text);
    if (retrievedChunks.length > 0 && chunkTokensUsed + t > remainingChunkBudget) break;
    const boundedText =
      chunkTokensUsed + t > remainingChunkBudget
        ? ch.text.slice(0, remainingChunkBudget * 4)
        : ch.text;
    retrievedChunks.push({
      chunkId: ch.chunkId,
      file: ch.file,
      score: Number(ch.score.toFixed(4)),
      text: boundedText
    });
    chunkTokensUsed += estimateTokens(boundedText);
  }

  const compiledContextBlock = [
    goal ? `[GOAL]\n${goal}` : '',
    retrievedChunks.length > 0
      ? `[RETRIEVED WORKSPACE EVIDENCE]\n${retrievedChunks.map((c) => `(${c.chunkId}) ${c.text}`).join('\n\n')}`
      : ''
  ]
    .filter(Boolean)
    .join('\n\n');

  const totalGroundingTokens = Math.min(
    maxGroundingTokens,
    estimateTokens(workspace.schemaSummaryText) + chunkTokensUsed
  );

  return okEnvelope(
    'krusch_ground_turn_zero',
    `Grounded ${workspace.fileCount} workspace file(s) and ${retrievedChunks.length} Raw-RAG chunk(s) in 0 LLM calls (prefix=${prefixHash.slice(0, 12)}).`,
    {
      scaleProfile,
      prefixHash,
      geminiToolConfig,
      workspace: {
        workspaceDir: workspace.workspaceDir,
        fileCount: workspace.fileCount,
        files: workspace.files,
        schemaSummaryText: workspace.schemaSummaryText
      },
      retrievedChunks,
      seenChunkIds: retrievedChunks.map((c) => c.chunkId),
      fileDigests: workspace.fileDigests,
      compiledSystemPrompt,
      compiledContextBlock,
      exposedTools: toolGate.exposedTools,
      toolSavings: toolGate.savings,
      tokenStats: {
        schemaTokens,
        chunkTokens: chunkTokensUsed,
        totalGroundingTokens,
        maxGroundingTokens
      },
      llmIngestionCalls: 0
    }
  );
}

function validateIsoCalendarDate(value) {
  const trimmed = String(value || '').trim();
  if (EXACT_PLACEHOLDER_TOKEN_RE.test(trimmed)) {
    return `Unresolved date placeholder "${trimmed}".`;
  }
  const m = trimmed.match(ISO_DATE_RE);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return `Invalid calendar date "${trimmed}".`;
  }
  const dt = new Date(Date.UTC(year, month - 1, day));
  if (
    dt.getUTCFullYear() !== year ||
    dt.getUTCMonth() + 1 !== month ||
    dt.getUTCDate() !== day
  ) {
    return `Non-existent calendar date "${trimmed}".`;
  }
  return null;
}

function scanSmallModelArgumentIssues(obj, prefix = '', acc = []) {
  if (!obj || typeof obj !== 'object') return acc;
  for (const [k, v] of Object.entries(obj)) {
    const pathKey = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string') {
      if (PLACEHOLDER_RE.test(v) || EXACT_PLACEHOLDER_TOKEN_RE.test(v.trim())) {
        acc.push({
          code: 'UNRESOLVED_PLACEHOLDER',
          field: pathKey,
          message: `Field "${pathKey}" contains placeholder "${v.trim().slice(0, 60)}".`
        });
      }
      if (DATE_FIELD_KEY_RE.test(k)) {
        const dateErr = validateIsoCalendarDate(v);
        if (dateErr) {
          acc.push({ code: 'INVALID_CALENDAR_DATE', field: pathKey, message: dateErr });
        }
      }
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      scanSmallModelArgumentIssues(v, pathKey, acc);
    }
  }
  return acc;
}

const OUTBOUND_TOOL_HINT_RE =
  /(?:^|[_.:/-])(?:send|email|mail|reply|forward|post|publish|webhook|slack|upload|dispatch|share|invite|http_post)(?:$|[_.:/-])/i;

function safeParseJsonArray(rawJson) {
  if (typeof rawJson !== 'string' || !rawJson.trim()) return [];
  try {
    const parsed = JSON.parse(rawJson);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function safeParseJsonObject(rawJson) {
  if (typeof rawJson !== 'string' || !rawJson.trim()) return {};
  try {
    const parsed = JSON.parse(rawJson);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function extractCommandTextFromArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return '';
  const cmd = args.command ?? args.cmd ?? args.CommandLine ?? args.commandLine ?? '';
  return typeof cmd === 'string' ? cmd : '';
}

function matchesEvolvedRule(rule, toolName, commandText) {
  if (!commandText) return false;
  if (!rule.toolRe.test(toolName)) return false;
  if (!rule.commandRe.test(commandText)) return false;
  if (rule.excludeRe && rule.excludeRe.test(commandText)) return false;
  return true;
}

function normalizeDigestRelPath(rawPath, resolvedRoot = null) {
  const raw = String(rawPath ?? '').trim();
  if (!raw) return '';
  if (resolvedRoot && path.isAbsolute(raw)) {
    const rel = path.relative(resolvedRoot, path.resolve(raw));
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
      return rel.replace(/\\/g, '/').replace(/^\.\//, '').trim();
    }
  }
  return raw.replace(/\\/g, '/').replace(/^\.\//, '').trim();
}

function extractMutatedPathsFromArgs(args, extraPaths = [], resolvedRoot = null) {
  const collected = new Set();
  const pushCandidate = (val) => {
    if (typeof val !== 'string') return;
    const norm = normalizeDigestRelPath(val, resolvedRoot);
    if (norm) collected.add(norm);
  };

  if (args && typeof args === 'object' && !Array.isArray(args)) {
    const scalarKeys = [
      'path',
      'relPath',
      'rel_path',
      'file_path',
      'filePath',
      'target_file',
      'targetFile',
      'filename',
      'destination',
      'file'
    ];
    for (const k of scalarKeys) {
      pushCandidate(args[k]);
    }
    const arrayKeys = ['paths', 'files', 'mutated_paths', 'mutatedPaths'];
    for (const k of arrayKeys) {
      if (Array.isArray(args[k])) {
        for (const item of args[k]) pushCandidate(item);
      }
    }
  }

  if (Array.isArray(extraPaths)) {
    for (const item of extraPaths) pushCandidate(item);
  }

  return [...collected];
}

/**
 * 3-Strike Zero-Progress Mutation Stall Breaker (`INV-GH-13`).
 * Tracks consecutive verified edit cycles without throttling normal multi-file edits prior to verification.
 * @param {object} [options={}]
 */
export function evaluateMutationStallGuard(options = {}) {
  const {
    priorState = {},
    isMutating = false,
    passedCases,
    totalCases,
    verificationPassed,
    maxStalledMutations = 3
  } = options || {};

  const threshold =
    Number.isInteger(Number(maxStalledMutations)) && Number(maxStalledMutations) > 0
      ? Number(maxStalledMutations)
      : 3;

  const safePrior =
    priorState && typeof priorState === 'object' && !Array.isArray(priorState) ? priorState : {};
  const prevStreak =
    Number.isFinite(Number(safePrior.stalledStreak)) && Number(safePrior.stalledStreak) >= 0
      ? Math.trunc(Number(safePrior.stalledStreak))
      : 0;
  const prevBest =
    safePrior.bestPassedCases !== null &&
    safePrior.bestPassedCases !== undefined &&
    safePrior.bestPassedCases !== '' &&
    typeof safePrior.bestPassedCases !== 'boolean' &&
    Number.isFinite(Number(safePrior.bestPassedCases))
      ? Math.max(0, Math.trunc(Number(safePrior.bestPassedCases)))
      : null;
  const prevMutations =
    Number.isFinite(Number(safePrior.mutationsSinceLastEval)) &&
    Number(safePrior.mutationsSinceLastEval) >= 0
      ? Math.trunc(Number(safePrior.mutationsSinceLastEval))
      : 0;
  const prevHolds =
    Number.isFinite(Number(safePrior.stalledHolds)) && Number(safePrior.stalledHolds) >= 0
      ? Math.trunc(Number(safePrior.stalledHolds))
      : 0;

  const hasNumericPassed =
    passedCases !== undefined &&
    passedCases !== null &&
    passedCases !== '' &&
    typeof passedCases !== 'boolean' &&
    Number.isFinite(Number(passedCases));
  const hasNumericTotal =
    totalCases !== undefined &&
    totalCases !== null &&
    totalCases !== '' &&
    typeof totalCases !== 'boolean' &&
    Number.isFinite(Number(totalCases));
  const hasEvalSignal = typeof verificationPassed === 'boolean' || hasNumericPassed;

  let stalledStreak = prevStreak;
  let bestPassedCases = prevBest;
  let mutationsSinceLastEval = prevMutations;

  if (!hasEvalSignal) {
    if (isMutating === true) {
      mutationsSinceLastEval = prevMutations + 1;
    }
  } else {
    const numericPassed = hasNumericPassed ? Math.max(0, Math.trunc(Number(passedCases))) : null;
    const numericTotal = hasNumericTotal ? Math.max(0, Math.trunc(Number(totalCases))) : null;
    const allPassed =
      verificationPassed === true ||
      (numericPassed !== null &&
        numericTotal !== null &&
        numericTotal > 0 &&
        numericPassed >= numericTotal &&
        verificationPassed !== false);

    if (allPassed) {
      stalledStreak = 0;
      mutationsSinceLastEval = 0;
      bestPassedCases = numericPassed !== null ? Math.max(prevBest ?? 0, numericPassed) : prevBest;
    } else if (prevBest !== null && numericPassed !== null && numericPassed > prevBest) {
      stalledStreak = 0;
      bestPassedCases = numericPassed;
      mutationsSinceLastEval = 0;
    } else if (prevBest === null && prevMutations === 0 && isMutating !== true) {
      bestPassedCases = numericPassed ?? 0;
      stalledStreak = 0;
      mutationsSinceLastEval = 0;
    } else {
      stalledStreak = prevStreak + 1;
      bestPassedCases =
        prevBest === null
          ? (numericPassed ?? 0)
          : numericPassed !== null
            ? Math.max(prevBest, numericPassed)
            : prevBest;
      mutationsSinceLastEval = 0;
    }
  }

  const stalled = stalledStreak >= threshold;
  const reason = stalled ? 'STALLED_MUTATION_LOOP' : null;
  const correctivePrompt = stalled
    ? `MUTATION STALL GUARD (STALLED_MUTATION_LOOP): ${stalledStreak} consecutive verified mutation cycle(s) failed to improve passing test cases (bestPassedCases=${bestPassedCases ?? 0}). Stop blind editing, diagnose the remaining assertion mismatches or missing domain rules, or escalate blockers to the user.`
    : null;

  return {
    stalled,
    stalledStreak,
    bestPassedCases,
    mutationsSinceLastEval,
    maxStalledMutations: threshold,
    reason,
    correctivePrompt,
    nextState: {
      stalledStreak,
      bestPassedCases,
      mutationsSinceLastEval,
      stalledHolds: prevHolds
    }
  };
}

/**
 * Upstream Source Fingerprint Drift Invalidation (`INV-GH-14`).
 * Compares baseline SHA-256 fileDigests against currentDigests or safe bounded workspaceDir reads,
 * ignoring paths mutated by the active session (`sessionMutatedPaths`).
 * @param {object} [options={}]
 */
export function evaluateSourceFingerprintDrift(options = {}) {
  const {
    baselineDigests = {},
    currentDigests = null,
    workspaceDir = null,
    sessionMutatedPaths = []
  } = options || {};

  const safeBaseline =
    baselineDigests && typeof baselineDigests === 'object' && !Array.isArray(baselineDigests)
      ? baselineDigests
      : {};
  const hasCurrentMap =
    currentDigests !== null &&
    typeof currentDigests === 'object' &&
    !Array.isArray(currentDigests);
  const resolvedWorkspace =
    typeof workspaceDir === 'string' && workspaceDir.trim()
      ? path.resolve(workspaceDir.trim())
      : null;

  if (!hasCurrentMap && !resolvedWorkspace) {
    return {
      drifted: false,
      driftedFiles: [],
      checkedCount: 0,
      reason: null,
      correctivePrompt: null
    };
  }

  const mutatedSet = new Set(
    (Array.isArray(sessionMutatedPaths) ? sessionMutatedPaths : [])
      .map((p) => normalizeDigestRelPath(p, resolvedWorkspace))
      .filter(Boolean)
  );

  const normalizedCurrentMap = new Map();
  if (hasCurrentMap) {
    for (const [rawKey, val] of Object.entries(currentDigests)) {
      const normKey = normalizeDigestRelPath(rawKey, resolvedWorkspace);
      if (!normKey) continue;
      normalizedCurrentMap.set(
        normKey,
        typeof val === 'string' && val.trim() ? val.trim() : null
      );
    }
  }

  const baselineEntries = Object.entries(safeBaseline)
    .map(([rawKey, expectedVal]) => ({
      normPath: normalizeDigestRelPath(rawKey, resolvedWorkspace),
      expectedSha256: typeof expectedVal === 'string' ? expectedVal.trim() : ''
    }))
    .filter((entry) => entry.normPath && entry.expectedSha256)
    .sort((a, b) => a.normPath.localeCompare(b.normPath));

  const driftedFiles = [];
  let checkedCount = 0;

  let realWorkspace = null;
  if (resolvedWorkspace) {
    try {
      realWorkspace = fs.realpathSync(resolvedWorkspace);
    } catch {
      realWorkspace = null;
    }
  }

  const isLexicallyContained = (rootDir, targetAbs) => {
    const rel = path.relative(rootDir, targetAbs);
    return Boolean(
      rel &&
      rel !== '..' &&
      !rel.startsWith('../') &&
      !rel.startsWith('..\\') &&
      !path.isAbsolute(rel)
    );
  };

  const readSafeStackWorkspaceSha256 = (normPath) => {
    if (!resolvedWorkspace || !realWorkspace || !normPath || path.isAbsolute(normPath)) {
      return { validPath: false, sha256: null };
    }
    const segments = normPath.split('/');
    if (segments.some((seg) => seg === '..' || seg === '')) {
      return { validPath: false, sha256: null };
    }
    const candidateFull = path.resolve(resolvedWorkspace, normPath);
    if (!isLexicallyContained(resolvedWorkspace, candidateFull)) {
      return { validPath: false, sha256: null };
    }

    let probeDir = path.dirname(candidateFull);
    while (probeDir.length >= resolvedWorkspace.length) {
      if (fs.existsSync(probeDir)) {
        try {
          const realAncestor = fs.realpathSync(probeDir);
          if (realAncestor !== realWorkspace && !isLexicallyContained(realWorkspace, realAncestor)) {
            return { validPath: false, sha256: null };
          }
        } catch {
          return { validPath: false, sha256: null };
        }
        break;
      }
      const nextParent = path.dirname(probeDir);
      if (nextParent === probeDir) break;
      probeDir = nextParent;
    }

    let lstat;
    try {
      lstat = fs.lstatSync(candidateFull);
    } catch (err) {
      if (err && typeof err === 'object' && err.code === 'ENOENT') {
        return { validPath: true, sha256: null };
      }
      return { validPath: false, sha256: null };
    }

    try {
      const realTarget = fs.realpathSync(candidateFull);
      if (realTarget !== realWorkspace && !isLexicallyContained(realWorkspace, realTarget)) {
        return { validPath: false, sha256: null };
      }
      const st = lstat.isSymbolicLink() ? fs.statSync(realTarget) : lstat;
      if (!st.isFile() || st.size > 16 * 1024 * 1024) {
        return { validPath: false, sha256: null };
      }
      return { validPath: true, sha256: sha256Hex(fs.readFileSync(realTarget)) };
    } catch {
      return { validPath: false, sha256: null };
    }
  };

  for (const { normPath, expectedSha256 } of baselineEntries) {
    if (mutatedSet.has(normPath)) continue;

    let actualSha256 = null;
    if (hasCurrentMap) {
      if (normalizedCurrentMap.has(normPath)) {
        actualSha256 = normalizedCurrentMap.get(normPath);
      } else if (resolvedWorkspace) {
        const diskRes = readSafeStackWorkspaceSha256(normPath);
        if (!diskRes.validPath) {
          continue;
        }
        actualSha256 = diskRes.sha256;
      } else {
        actualSha256 = null;
      }
      checkedCount += 1;
    } else if (resolvedWorkspace) {
      const diskRes = readSafeStackWorkspaceSha256(normPath);
      if (!diskRes.validPath) {
        continue;
      }
      checkedCount += 1;
      actualSha256 = diskRes.sha256;
    }

    if (actualSha256 === null) {
      driftedFiles.push({
        path: normPath,
        expectedSha256,
        actualSha256: null,
        status: 'DELETED_UPSTREAM'
      });
    } else if (actualSha256.toLowerCase() !== expectedSha256.toLowerCase()) {
      driftedFiles.push({
        path: normPath,
        expectedSha256,
        actualSha256,
        status: 'MODIFIED_UPSTREAM'
      });
    }
  }

  const drifted = driftedFiles.length > 0;
  return {
    drifted,
    driftedFiles,
    checkedCount,
    reason: drifted ? 'STALE_GROUNDING_DRIFT' : null,
    correctivePrompt: drifted
      ? `SOURCE FINGERPRINT DRIFT (STALE_GROUNDING_DRIFT): ${driftedFiles.length} upstream file(s) changed outside this session (${driftedFiles.map((f) => `${f.path}:${f.status}`).join(', ')}). Re-ground or re-read affected files and re-verify before stopping.`
      : null
  };
}

function stripCodeForInfallibleAudit(src, lang) {
  const len = src.length;
  const out = new Array(len);
  const rawLines = src.split('\n');
  const lineHasInfallible = new Array(rawLines.length).fill(false);
  let i = 0;
  let lineIdx = 0;
  let lastNonWsChar = '';
  let inJsTemplate = false;
  let jsBraceDepth = 0;
  const jsTemplateBraceStack = [];

  while (i < len) {
    const ch = src[i];
    const next = src[i + 1] || '';

    if (inJsTemplate) {
      if (ch === '\\' && i + 1 < len) {
        out[i] = ' ';
        if (src[i + 1] === '\n') {
          out[i + 1] = '\n';
          lineIdx += 1;
        } else {
          out[i + 1] = ' ';
        }
        i += 2;
        continue;
      }
      if (ch === '$' && next === '{') {
        jsTemplateBraceStack.push(jsBraceDepth);
        inJsTemplate = false;
        out[i] = ' ';
        out[i + 1] = ' ';
        lastNonWsChar = '{';
        i += 2;
        continue;
      }
      if (ch === '`') {
        inJsTemplate = false;
        out[i] = ' ';
        lastNonWsChar = '`';
        i += 1;
        continue;
      }
      if (ch === '\n') {
        out[i] = '\n';
        lineIdx += 1;
      } else {
        out[i] = ' ';
      }
      i += 1;
      continue;
    }

    if (ch === '\n') {
      out[i] = '\n';
      lineIdx += 1;
      i += 1;
      continue;
    }

    // Line comment //
    if (ch === '/' && next === '/') {
      const commentStart = i;
      while (i < len && src[i] !== '\n') {
        out[i] = ' ';
        i += 1;
      }
      const commentSlice = src.slice(commentStart, i);
      if (/^\/\/\s*INFALLIBLE\s*:\s*(?:\S\s*){3,}/.test(commentSlice)) {
        lineHasInfallible[lineIdx] = true;
      }
      continue;
    }

    // Block comment /* ... */ (supports nested comments in Rust)
    if (ch === '/' && next === '*') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      let depth = 1;
      while (i < len && depth > 0) {
        if (src[i] === '\n') {
          out[i] = '\n';
          lineIdx += 1;
          i += 1;
        } else if (lang === 'rust' && src[i] === '/' && src[i + 1] === '*') {
          depth += 1;
          out[i] = ' ';
          out[i + 1] = ' ';
          i += 2;
        } else if (src[i] === '*' && src[i + 1] === '/') {
          depth -= 1;
          out[i] = ' ';
          out[i + 1] = ' ';
          i += 2;
        } else {
          out[i] = ' ';
          i += 1;
        }
      }
      continue;
    }

    if (lang === 'rust') {
      // Rust raw strings r"...", r#"..."#, br#"..."#
      const prevChar = i > 0 ? src[i - 1] : '';
      if (
        !/[A-Za-z0-9_]/.test(prevChar) &&
        (ch === 'r' || (ch === 'b' && next === 'r'))
      ) {
        let p = ch === 'b' ? i + 2 : i + 1;
        let hashes = 0;
        while (p < len && src[p] === '#') {
          hashes += 1;
          p += 1;
        }
        if (p < len && src[p] === '"') {
          for (let k = i; k <= p; k += 1) out[k] = ' ';
          i = p + 1;
          while (i < len) {
            if (src[i] === '\n') {
              out[i] = '\n';
              lineIdx += 1;
              i += 1;
              continue;
            }
            if (src[i] === '"') {
              let matched = 0;
              while (matched < hashes && src[i + 1 + matched] === '#') {
                matched += 1;
              }
              if (matched === hashes) {
                for (let k = 0; k <= hashes; k += 1) out[i + k] = ' ';
                i += hashes + 1;
                lastNonWsChar = '"';
                break;
              }
            }
            out[i] = ' ';
            i += 1;
          }
          continue;
        }
      }

      // Rust char literals vs lifetimes ('a / 'static)
      if (ch === "'") {
        if (next === '\\') {
          let endQuote = -1;
          for (let k = i + 2; k < Math.min(len, i + 14) && src[k] !== '\n'; k += 1) {
            if (src[k] === "'") {
              endQuote = k;
              break;
            }
          }
          if (endQuote !== -1) {
            for (let k = i; k <= endQuote; k += 1) out[k] = ' ';
            i = endQuote + 1;
            lastNonWsChar = "'";
            continue;
          }
        } else if (i + 2 < len && next !== "'" && next !== '\n' && src[i + 2] === "'") {
          out[i] = ' ';
          out[i + 1] = ' ';
          out[i + 2] = ' ';
          i += 3;
          lastNonWsChar = "'";
          continue;
        }
        out[i] = ch;
        lastNonWsChar = ch;
        i += 1;
        continue;
      }

      // Rust standard string "..."
      if (ch === '"') {
        out[i] = ' ';
        i += 1;
        while (i < len) {
          if (src[i] === '\n') {
            out[i] = '\n';
            lineIdx += 1;
            i += 1;
          } else if (src[i] === '\\') {
            out[i] = ' ';
            if (i + 1 < len) {
              if (src[i + 1] === '\n') {
                out[i + 1] = '\n';
                lineIdx += 1;
              } else {
                out[i + 1] = ' ';
              }
              i += 2;
            } else {
              i += 1;
            }
          } else if (src[i] === '"') {
            out[i] = ' ';
            i += 1;
            lastNonWsChar = '"';
            break;
          } else {
            out[i] = ' ';
            i += 1;
          }
        }
        continue;
      }
    } else {
      // JS/TS string & template literals (with ${...} interpolation code recovery)
      if (ch === '`') {
        inJsTemplate = true;
        out[i] = ' ';
        i += 1;
        continue;
      }
      if (ch === '{') {
        jsBraceDepth += 1;
        out[i] = '{';
        lastNonWsChar = '{';
        i += 1;
        continue;
      }
      if (ch === '}') {
        if (
          jsTemplateBraceStack.length > 0 &&
          jsBraceDepth === jsTemplateBraceStack[jsTemplateBraceStack.length - 1]
        ) {
          jsTemplateBraceStack.pop();
          inJsTemplate = true;
          out[i] = ' ';
          i += 1;
          continue;
        }
        jsBraceDepth = Math.max(0, jsBraceDepth - 1);
        out[i] = '}';
        lastNonWsChar = '}';
        i += 1;
        continue;
      }
      if (ch === "'" || ch === '"') {
        const quote = ch;
        out[i] = ' ';
        i += 1;
        while (i < len) {
          if (src[i] === '\n') {
            out[i] = '\n';
            lineIdx += 1;
            i += 1;
            break;
          } else if (src[i] === '\\') {
            out[i] = ' ';
            if (i + 1 < len) {
              if (src[i + 1] === '\n') {
                out[i + 1] = '\n';
                lineIdx += 1;
              } else {
                out[i + 1] = ' ';
              }
              i += 2;
            } else {
              i += 1;
            }
          } else if (src[i] === quote) {
            out[i] = ' ';
            i += 1;
            lastNonWsChar = quote;
            break;
          } else {
            out[i] = ' ';
            i += 1;
          }
        }
        continue;
      }

      // JS/TS single-line regex literal /.../flags
      if (
        ch === '/' &&
        (!lastNonWsChar || '=(,[!&|?:;{}~+-*%^<>'.includes(lastNonWsChar))
      ) {
        let p = i + 1;
        let inCharClass = false;
        let closeSlash = -1;
        while (p < len && src[p] !== '\n') {
          if (src[p] === '\\') {
            p += 2;
            continue;
          }
          if (src[p] === '[') {
            inCharClass = true;
            p += 1;
            continue;
          }
          if (src[p] === ']') {
            inCharClass = false;
            p += 1;
            continue;
          }
          if (!inCharClass && src[p] === '/') {
            closeSlash = p;
            break;
          }
          p += 1;
        }
        if (closeSlash > i + 1) {
          let endRe = closeSlash + 1;
          while (endRe < len && /[dgimsuvy]/.test(src[endRe])) {
            endRe += 1;
          }
          for (let k = i; k < endRe; k += 1) out[k] = ' ';
          i = endRe;
          lastNonWsChar = '/';
          continue;
        }
      }
    }

    out[i] = ch;
    if (!/\s/.test(ch)) {
      lastNonWsChar = ch;
    }
    i += 1;
  }

  // Blank out Rust #[cfg(test)] items while preserving exact line numbers
  if (lang === 'rust') {
    const joined = out.join('');
    const cfgTestRe = /#\[\s*cfg\s*\(\s*test\s*\)\s*\]/g;
    for (const m of joined.matchAll(cfgTestRe)) {
      const startIdx = m.index;
      if (out[startIdx] === ' ') continue;
      let cursor = startIdx + m[0].length;
      while (cursor < len) {
        while (cursor < len && /\s/.test(out[cursor])) cursor += 1;
        if (out[cursor] === '#' && out[cursor + 1] === '[') {
          let bracketDepth = 1;
          cursor += 2;
          while (cursor < len && bracketDepth > 0) {
            if (out[cursor] === '[') bracketDepth += 1;
            else if (out[cursor] === ']') bracketDepth -= 1;
            cursor += 1;
          }
          continue;
        }
        break;
      }
      while (cursor < len && out[cursor] !== '{' && out[cursor] !== ';') {
        cursor += 1;
      }
      let endIdx = cursor;
      if (cursor < len && out[cursor] === '{') {
        let braceDepth = 1;
        cursor += 1;
        while (cursor < len && braceDepth > 0) {
          if (out[cursor] === '{') braceDepth += 1;
          else if (out[cursor] === '}') braceDepth -= 1;
          cursor += 1;
        }
        endIdx = cursor - 1;
      }
      for (let k = startIdx; k <= Math.min(len - 1, endIdx); k += 1) {
        if (out[k] !== '\n') out[k] = ' ';
      }
    }
  }

  return {
    rawLines,
    strippedCode: out.join(''),
    strippedLines: out.join('').split('\n'),
    lineHasInfallible
  };
}

/**
 * `// INFALLIBLE: <reason>` Panic & Assertion Surface Auditor (`INV-GH-15`).
 * Scans fallible Rust (`Result<...>`) and JS/TS (`okEnvelope`/`errorEnvelope`) modules while ignoring
 * string literals, comments, and Rust `#[cfg(test)]` modules.
 * @param {object} [options={}]
 */
export function auditInfallibleAssertions(options = {}) {
  const {
    code = '',
    filePath = '',
    language = '',
    requireFallibleContract = true
  } = options || {};

  const normalizedCode = String(code ?? '').replace(/\r\n/g, '\n');
  const safeFilePath = String(filePath || '');
  const langHint = String(language || '').trim().toLowerCase();
  const extHint = path.extname(safeFilePath.trim()).toLowerCase();

  let detectedLanguage = 'javascript';
  if (langHint === 'rust' || langHint === 'rs') {
    detectedLanguage = 'rust';
  } else if (
    langHint === 'js' ||
    langHint === 'javascript' ||
    langHint === 'mjs' ||
    langHint === 'cjs' ||
    langHint === 'ts' ||
    langHint === 'tsx' ||
    langHint === 'jsx' ||
    langHint === 'typescript'
  ) {
    detectedLanguage = 'javascript';
  } else if (
    extHint === '.rs' ||
    /\bfn\s+[A-Za-z0-9_]+\s*(?:<[^>]*>)?\s*\([^)]*\)\s*->\s*Result\b|\bpub\s+(?:fn|struct|enum|mod|trait)\b|#\[\s*cfg\s*\(|\b(?:unimplemented|todo|panic)!\s*[([]/.test(
      normalizedCode
    )
  ) {
    detectedLanguage = 'rust';
  }

  const { rawLines, strippedCode, strippedLines, lineHasInfallible } =
    stripCodeForInfallibleAudit(normalizedCode, detectedLanguage);

  const fallibleContractDetected =
    detectedLanguage === 'rust'
      ? /\bResult\s*</.test(strippedCode)
      : /\b(?:okEnvelope|errorEnvelope)\b/.test(strippedCode);

  if (requireFallibleContract !== false && !fallibleContractDetected) {
    return {
      passed: true,
      language: detectedLanguage,
      fallibleContractDetected: false,
      findings: [],
      reason: null,
      correctivePrompt: null
    };
  }

  const rules =
    detectedLanguage === 'rust'
      ? [
          {
            kind: 'unwrap',
            re: /\.\s*unwrap\s*\(\s*\)/g,
            allowInfallibleComment: true,
            fix: 'Propagate errors via Result/? or annotate mathematically guaranteed invariants with // INFALLIBLE: <reason>.'
          },
          {
            kind: 'expect',
            re: /\.\s*expect\s*\(/g,
            allowInfallibleComment: true,
            fix: 'Propagate errors via Result/? or annotate mathematically guaranteed invariants with // INFALLIBLE: <reason>.'
          },
          {
            kind: 'panic!',
            re: /\bpanic!\s*[([]/g,
            allowInfallibleComment: true,
            fix: 'Return Err(...) instead of panicking or annotate unreachable invariant with // INFALLIBLE: <reason>.'
          },
          {
            kind: 'unimplemented!',
            re: /\bunimplemented!\s*[([]/g,
            allowInfallibleComment: false,
            fix: 'Replace unimplemented! stub with a complete fallible implementation.'
          },
          {
            kind: 'todo!',
            re: /\btodo!\s*[([]/g,
            allowInfallibleComment: false,
            fix: 'Replace todo! stub with a complete fallible implementation.'
          }
        ]
      : [
          {
            kind: 'process.exit',
            re: /\bprocess\s*\.\s*exit\s*\(/g,
            allowInfallibleComment: true,
            fix: 'Return errorEnvelope(...) instead of calling process.exit(...), or annotate CLI entrypoint boundary with // INFALLIBLE: <reason>.'
          }
        ];

  const findings = [];
  for (let idx = 0; idx < strippedLines.length; idx += 1) {
    const lineText = strippedLines[idx];
    if (!lineText.trim()) continue;
    const hasAnnotation =
      Boolean(lineHasInfallible[idx]) || (idx > 0 && Boolean(lineHasInfallible[idx - 1]));

    for (const rule of rules) {
      if (rule.allowInfallibleComment && hasAnnotation) continue;
      rule.re.lastIndex = 0;
      for (const m of lineText.matchAll(rule.re)) {
        findings.push({
          line: idx + 1,
          column: (m.index ?? 0) + 1,
          kind: rule.kind,
          snippet: String(rawLines[idx] || '').trim().slice(0, 160),
          filePath: safeFilePath,
          fix: rule.fix
        });
      }
    }
  }

  findings.sort((a, b) => a.line - b.line || a.column - b.column);
  const passed = findings.length === 0;
  return {
    passed,
    language: detectedLanguage,
    fallibleContractDetected,
    findings,
    reason: passed ? null : 'UNEXPLAINED_INFALLIBLE_ASSERTION',
    correctivePrompt: passed
      ? null
      : `INFALLIBLE ASSERTION AUDIT (UNEXPLAINED_INFALLIBLE_ASSERTION): Found ${findings.length} unannotated panic/exit/stub site(s) in ${safeFilePath || detectedLanguage} (${findings.map((f) => `L${f.line}:${f.kind}`).join(', ')}). Propagate errors cleanly or add // INFALLIBLE: <reason> where guaranteed.`
  };
}

/**
 * Create the zero-dependency SQLite-backed Grounded Harness Engine (`stack.groundedHarness`).
 * @param {object} options
 * @param {DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 * @param {Array<object>} [options.evolvedRules]
 */
export function createGroundedHarnessEngine({
  db,
  workspaceRoot = process.cwd(),
  evolvedRules = DEFAULT_EVOLVED_HARNESS_RULES
} = {}) {
  if (!db || typeof db.exec !== 'function') {
    throw new Error('createGroundedHarnessEngine requires a Node 22 DatabaseSync instance.');
  }
  db.exec(GROUNDED_HARNESS_SCHEMA_SQL);

  // Idempotent column migrations for pre-existing .krusch-stack/stack.db databases
  const migrationCols = [
    "allowed_scopes_json TEXT NOT NULL DEFAULT '[]'",
    "drift_state_json TEXT NOT NULL DEFAULT '{}'",
    'auth_drift_holds INTEGER NOT NULL DEFAULT 0',
    'dart_repairs_applied INTEGER NOT NULL DEFAULT 0',
    'dart_holds INTEGER NOT NULL DEFAULT 0'
  ];
  for (const colDef of migrationCols) {
    try {
      db.exec(`ALTER TABLE grounded_sessions ADD COLUMN ${colDef}`);
    } catch {
      // Column already exists on initialized schema
    }
  }

  const activeEvolvedRules = compileExecutableRules(evolvedRules);
  const ruleStreaks = new Map();

  const selectSessionStmt = db.prepare('SELECT * FROM grounded_sessions WHERE session_id = ?');
  const upsertSessionStmt = db.prepare(`
    INSERT INTO grounded_sessions (
      session_id, goal, model, scale_tier, scale_profile_json, anchor_date, prefix_hash,
      status, max_duplicate_writes, seen_chunks_json, file_digests_json,
      allowed_scopes_json, drift_state_json,
      schema_tokens_saved, schema_reduction_pct, turn0_tokens,
      exploratory_reads, committed_reads, committed_mutations, memoized_reads,
      spin_loops_blocked, output_defects_caught, timeouts_with_partial_stdout,
      turn0_duplicates_suppressed, duplicate_writes_blocked, policy_floor_blocks,
      auth_drift_holds, dart_repairs_applied, dart_holds,
      truncation_recoveries, verify_nudges_used, pending_diffs_count,
      latest_verification_passed, created_at_ms, updated_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      goal = excluded.goal,
      model = excluded.model,
      scale_tier = excluded.scale_tier,
      scale_profile_json = excluded.scale_profile_json,
      anchor_date = excluded.anchor_date,
      prefix_hash = excluded.prefix_hash,
      status = 'ACTIVE',
      max_duplicate_writes = excluded.max_duplicate_writes,
      seen_chunks_json = excluded.seen_chunks_json,
      file_digests_json = excluded.file_digests_json,
      allowed_scopes_json = excluded.allowed_scopes_json,
      drift_state_json = excluded.drift_state_json,
      schema_tokens_saved = excluded.schema_tokens_saved,
      schema_reduction_pct = excluded.schema_reduction_pct,
      turn0_tokens = excluded.turn0_tokens,
      exploratory_reads = 0,
      committed_reads = 0,
      committed_mutations = 0,
      memoized_reads = 0,
      spin_loops_blocked = 0,
      output_defects_caught = 0,
      timeouts_with_partial_stdout = 0,
      turn0_duplicates_suppressed = 0,
      duplicate_writes_blocked = 0,
      policy_floor_blocks = 0,
      auth_drift_holds = 0,
      dart_repairs_applied = 0,
      dart_holds = 0,
      truncation_recoveries = 0,
      verify_nudges_used = 0,
      pending_diffs_count = 0,
      latest_verification_passed = 1,
      updated_at_ms = excluded.updated_at_ms
  `);
  const deleteSessionEventsStmt = db.prepare('DELETE FROM grounded_events WHERE session_id = ?');
  const insertEventStmt = db.prepare(`
    INSERT INTO grounded_events (
      event_id, session_id, step, tool_name, is_mutating, is_foraging,
      canonical_args_json, call_signature, decision, status, issues_json,
      result_preview, created_at_ms, updated_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const selectEventsBySigStmt = db.prepare(`
    SELECT rowid AS _rowid, * FROM grounded_events
    WHERE session_id = ? AND call_signature = ?
    ORDER BY created_at_ms DESC, rowid DESC
  `);
  const countMutationsAfterStmt = db.prepare(`
    SELECT COUNT(*) AS cnt FROM grounded_events
    WHERE session_id = ? AND is_mutating = 1 AND status = 'COMMITTED' AND rowid > ?
  `);
  const maxDiffMutationRowStmt = db.prepare(`
    SELECT MAX(rowid) AS max_rowid FROM grounded_events
    WHERE session_id = ? AND is_mutating = 1 AND status = 'COMMITTED' AND call_signature != ?
  `);
  const selectEventStmt = db.prepare(
    'SELECT * FROM grounded_events WHERE event_id = ? AND session_id = ?'
  );
  const selectAllSessionEventsStmt = db.prepare(
    'SELECT * FROM grounded_events WHERE session_id = ? ORDER BY created_at_ms ASC, rowid ASC'
  );

  function resolveScale(params = {}) {
    const profile = resolveScaleProfile(params);
    const directive = buildScaleAwareDirective(profile);
    return okEnvelope(
      'krusch_resolve_scale_profile',
      `Resolved ${profile.tier} scale profile for "${profile.model || 'default'}".`,
      { profile, directive }
    );
  }

  function groundWorkspace(params = {}) {
    const rawDir = params.workspaceDir || params.workspace_dir;
    const resolvedDir =
      typeof rawDir === 'string' && rawDir.trim()
        ? path.resolve(workspaceRoot, rawDir.trim())
        : workspaceRoot;
    return compileTurnZeroGrounding({
      ...params,
      workspaceDir: resolvedDir
    });
  }

  function startSession(params = {}) {
    const goal = String(params.goal || '').trim();
    if (!goal) {
      return okEnvelope(
        'krusch_grounded_session_start',
        'startSession requires a non-empty goal.',
        { status: 'INVALID_SESSION_ARGS' },
        false
      );
    }
    const sessionId = String(params.session_id || params.sessionId || `gh_${crypto.randomUUID()}`).trim();
    const scaleProfile = resolveScaleProfile({
      model: params.model || '',
      activeParamsB: params.activeParamsB,
      totalParamsB: params.totalParamsB,
      thinkingEnabled: params.thinkingEnabled,
      reasoningEffort: params.reasoningEffort
    });
    const seenChunks = Array.isArray(params.seen_chunk_ids ?? params.seenChunkIds)
      ? (params.seen_chunk_ids ?? params.seenChunkIds)
      : [];
    const rawDigests = params.file_digests ?? params.fileDigests;
    const fileDigests = rawDigests && typeof rawDigests === 'object' ? rawDigests : {};

    const rawAllowedScopes = params.allowed_scopes ?? params.allowedScopes;
    const allowedScopes = Array.isArray(rawAllowedScopes)
      ? Array.from(
          new Set(
            rawAllowedScopes
              .map((s) => String(s ?? '').trim().toUpperCase())
              .filter(Boolean)
          )
        )
      : [];
    const rawBulk = Number(params.max_bulk_limit ?? params.maxBulkLimit ?? 1000);
    const maxBulkLimit = Number.isFinite(rawBulk) && rawBulk > 0 ? Math.trunc(rawBulk) : 1000;
    const enableAuthDriftGuard =
      params.enable_auth_drift_guard !== false && params.enableAuthDriftGuard !== false;
    const enableDartBoundaryGuard =
      params.enable_dart_boundary_guard !== false && params.enableDartBoundaryGuard !== false;
    const rawMaxStall = Number(
      params.max_stalled_mutations ?? params.maxStalledMutations ?? 3
    );
    const maxStalledMutations =
      Number.isInteger(rawMaxStall) && rawMaxStall > 0 ? rawMaxStall : 3;
    const enableMutationStallGuard =
      params.enable_mutation_stall_guard !== false && params.enableMutationStallGuard !== false;
    const enableSourceDriftGuard =
      params.enable_source_drift_guard !== false && params.enableSourceDriftGuard !== false;
    const enableInfallibleAudit =
      params.enable_infallible_audit !== false && params.enableInfallibleAudit !== false;
    const rawExplicitWorkspaceDir = params.workspace_dir ?? params.workspaceDir;
    const explicitWorkspaceDir =
      typeof rawExplicitWorkspaceDir === 'string' && rawExplicitWorkspaceDir.trim()
        ? path.resolve(workspaceRoot, rawExplicitWorkspaceDir.trim())
        : null;
    const initialDriftState = {
      driftScore: 0,
      overcollectionCount: 0,
      scopeViolations: 0,
      taintedDomains: [],
      maxBulkLimit,
      enableAuthDriftGuard,
      enableDartBoundaryGuard,
      maxStalledMutations,
      enableMutationStallGuard,
      enableSourceDriftGuard,
      enableInfallibleAudit,
      workspaceDir: explicitWorkspaceDir,
      sessionMutatedPaths: [],
      mutationStall: {
        stalledStreak: 0,
        bestPassedCases: null,
        mutationsSinceLastEval: 0,
        stalledHolds: 0
      },
      stalledMutationHolds: 0,
      staleGroundingBlocks: 0,
      infallibleAuditBlocks: 0
    };
    const attestedScopes = inferGoalAttestedScopes(goal, allowedScopes);
    const now = Date.now();

    db.exec('BEGIN IMMEDIATE');
    try {
      deleteSessionEventsStmt.run(sessionId);
      upsertSessionStmt.run(
        sessionId,
        goal,
        scaleProfile.model,
        scaleProfile.tier,
        JSON.stringify(scaleProfile),
        String(params.anchor_date ?? params.anchorDate ?? ''),
        String(params.prefix_hash ?? params.prefixHash ?? ''),
        Math.max(1, Number(params.max_duplicate_writes ?? params.maxDuplicateWrites ?? 1)),
        JSON.stringify(seenChunks),
        JSON.stringify(fileDigests),
        JSON.stringify(allowedScopes),
        JSON.stringify(initialDriftState),
        Number(params.schema_tokens_saved ?? params.schemaTokensSaved ?? 0),
        Number(params.schema_reduction_pct ?? params.schemaReductionPct ?? 0),
        Number(params.turn0_tokens ?? params.turn0Tokens ?? 0),
        now,
        now
      );
      db.exec('COMMIT');
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* ignore */
      }
      throw err;
    }

    for (const key of Array.from(ruleStreaks.keys())) {
      if (key.startsWith(`${sessionId}::`)) {
        ruleStreaks.delete(key);
      }
    }

    return okEnvelope(
      'krusch_grounded_session_start',
      `Grounded session ${sessionId} initialized (${scaleProfile.tier}).`,
      {
        session_id: sessionId,
        goal,
        status: 'ACTIVE',
        scaleProfile,
        directive: buildScaleAwareDirective(scaleProfile),
        attestedScopes
      }
    );
  }

  function groundAndStartSession(params = {}) {
    const grounding = groundWorkspace(params);
    const started = startSession({
      ...params,
      prefix_hash: grounding.data.prefixHash,
      seen_chunk_ids: grounding.data.seenChunkIds,
      file_digests: grounding.data.fileDigests,
      schema_tokens_saved: grounding.data.toolSavings.tokensSaved,
      schema_reduction_pct: grounding.data.toolSavings.reductionPct,
      turn0_tokens: grounding.data.tokenStats.totalGroundingTokens
    });
    if (!started.ok) return started;
    return okEnvelope(
      'krusch_ground_and_start',
      `Grounded workspace and started session ${started.data.session_id} (${started.data.scaleProfile.tier}).`,
      { session: started.data, grounding: grounding.data }
    );
  }

  function evaluateTurn({ session_id, turn_response = {} } = {}) {
    const session = session_id ? selectSessionStmt.get(String(session_id).trim()) : null;
    const finishReason = String(turn_response.finishReason || turn_response.finish_reason || '');
    const toolCalls = Array.isArray(turn_response.toolCalls) ? turn_response.toolCalls : [];
    let malformedJson = false;
    for (const tc of toolCalls) {
      if (typeof tc?.rawArguments === 'string') {
        try {
          JSON.parse(tc.rawArguments);
        } catch {
          malformedJson = true;
        }
      }
    }
    const poisoned = TRUNCATED_FINISH_REASONS.has(finishReason) || malformedJson;
    if (poisoned && session) {
      db.prepare(
        'UPDATE grounded_sessions SET truncation_recoveries = truncation_recoveries + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(Date.now(), session.session_id);
    }
    return okEnvelope(
      'krusch_grounded_evaluate_turn',
      poisoned
        ? 'Detected truncated/malformed turn output; tool execution blocked.'
        : 'Turn output clean.',
      { poisoned, safeToExecuteTools: !poisoned, finishReason }
    );
  }

  function interceptToolCall(params = {}) {
    const {
      session_id,
      sessionId: altSessionId,
      step = 0,
      tool_name,
      toolName: altToolName,
      args = {},
      tool_schema,
      toolSchema,
      mutating,
      is_outbound,
      isOutbound,
      allowed_scopes,
      allowedScopes,
      max_bulk_limit,
      maxBulkLimit,
      enable_auth_drift_guard,
      enableAuthDriftGuard,
      enable_dart_boundary_guard,
      enableDartBoundaryGuard,
      enable_mutation_stall_guard,
      enableMutationStallGuard,
      allow_stalled_mutation,
      allowStalledMutation,
      max_stalled_mutations,
      maxStalledMutations,
      suppress_turn0_reads = true,
      block_spin_loop = false
    } = params || {};

    const sessionId = String(session_id ?? altSessionId ?? '').trim();
    const session = sessionId ? selectSessionStmt.get(sessionId) : null;
    if (!session) {
      return okEnvelope(
        'krusch_grounded_intercept',
        `Grounded session "${sessionId}" not found.`,
        { decision: 'BLOCK', reason: 'SESSION_NOT_FOUND' },
        false
      );
    }

    const toolName = String(tool_name ?? altToolName ?? '').trim();
    const isMutating = classifyToolMutability(toolName, mutating);
    const storedDriftState = safeParseJsonObject(session.drift_state_json);
    const storedAllowedScopes = safeParseJsonArray(session.allowed_scopes_json)
      .map((s) => String(s ?? ''))
      .filter(Boolean);

    const dartEnabled =
      storedDriftState.enableDartBoundaryGuard !== false &&
      enable_dart_boundary_guard !== false &&
      enableDartBoundaryGuard !== false;
    const authDriftEnabled =
      storedDriftState.enableAuthDriftGuard !== false &&
      enable_auth_drift_guard !== false &&
      enableAuthDriftGuard !== false;

    const rawSafeArgs = args && typeof args === 'object' && !Array.isArray(args) ? args : {};
    const dartResult = dartEnabled
      ? inspectAndRepairDartBoundaries({
          toolName,
          args: rawSafeArgs,
          toolSchema: tool_schema ?? toolSchema ?? null
        })
      : {
          action: 'ALLOW',
          repaired: false,
          repairedArgs: rawSafeArgs,
          repairs: [],
          issues: [],
          correctivePrompt: null
        };
    const effectiveArgs = dartResult.repaired ? dartResult.repairedArgs : rawSafeArgs;

    const isForaging = !isMutating && FORAGING_TOOL_RE.test(toolName);
    const rawKey = canonicalizeGroundedToolCallKey(toolName, rawSafeArgs);
    const { canonicalArgs, canonicalArgsJson, callSignature } = dartResult.repaired
      ? canonicalizeGroundedToolCallKey(toolName, effectiveArgs)
      : rawKey;

    const eventId = `ghe_${crypto.randomUUID()}`;
    const now = Date.now();
    const stepNum = Math.max(0, Math.trunc(Number(step || 0)));
    const scaleProfile = JSON.parse(session.scale_profile_json);

    // 1. Frozen destructive policy floor (checked across both raw and DART-repaired arguments)
    if (
      DESTRUCTIVE_SHELL_RE.test(rawKey.canonicalArgsJson) ||
      DESTRUCTIVE_SHELL_RE.test(canonicalArgsJson)
    ) {
      insertEventStmt.run(
        eventId,
        sessionId,
        stepNum,
        toolName,
        isMutating ? 1 : 0,
        isForaging ? 1 : 0,
        canonicalArgsJson,
        callSignature,
        'BLOCK',
        'BLOCKED',
        JSON.stringify([{ code: 'POLICY_FLOOR_DESTRUCTIVE_COMMAND' }]),
        '',
        now,
        now
      );
      db.prepare(
        'UPDATE grounded_sessions SET policy_floor_blocks = policy_floor_blocks + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(now, sessionId);
      return okEnvelope('krusch_grounded_intercept', `Blocked destructive command in ${toolName}.`, {
        event_id: eventId,
        decision: 'BLOCK',
        reason: 'POLICY_FLOOR_DESTRUCTIVE_COMMAND',
        issues: [{ code: 'POLICY_FLOOR_DESTRUCTIVE_COMMAND' }]
      });
    }

    // 2. Secret leak guard
    const secretHit =
      scanForSecretLeak(rawKey.canonicalArgsJson) || scanForSecretLeak(canonicalArgsJson);
    if (secretHit) {
      insertEventStmt.run(
        eventId,
        sessionId,
        stepNum,
        toolName,
        isMutating ? 1 : 0,
        isForaging ? 1 : 0,
        canonicalArgsJson,
        callSignature,
        'BLOCK',
        'BLOCKED',
        JSON.stringify([{ code: 'SECRET_LEAK_BLOCKED', detail: secretHit }]),
        '',
        now,
        now
      );
      db.prepare(
        'UPDATE grounded_sessions SET policy_floor_blocks = policy_floor_blocks + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(now, sessionId);
      return okEnvelope('krusch_grounded_intercept', `Blocked secret leak in ${toolName}.`, {
        event_id: eventId,
        decision: 'BLOCK',
        reason: 'SECRET_LEAK_BLOCKED',
        issues: [{ code: 'SECRET_LEAK_BLOCKED', detail: secretHit }]
      });
    }

    // 2.2. DART MCP-vs-CLI Action Realization Boundary Hold (INV-GH-12)
    if (dartResult.action === 'HOLD') {
      insertEventStmt.run(
        eventId,
        sessionId,
        stepNum,
        toolName,
        isMutating ? 1 : 0,
        isForaging ? 1 : 0,
        canonicalArgsJson,
        callSignature,
        'HOLD',
        'HELD',
        JSON.stringify(dartResult.issues),
        '',
        now,
        now
      );
      db.prepare(
        'UPDATE grounded_sessions SET dart_holds = dart_holds + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(now, sessionId);
      return okEnvelope(
        'krusch_grounded_intercept',
        `Held ${toolName} by DART boundary guard (${dartResult.issues.length} issue(s)).`,
        {
          event_id: eventId,
          decision: 'HOLD',
          reason: AUTH_DRIFT_REASON_CODES.DART_BOUNDARY_HOLD,
          issues: dartResult.issues,
          correctivePrompt: dartResult.correctivePrompt
        }
      );
    }

    // 2.3. Early Scope & Authorization Drift Guard + SERS Data Minimization (INV-GH-12)
    let updatedDriftStateObj = null;
    let updatedDriftStateJson = null;
    if (authDriftEnabled) {
      const groundedFiles = safeParseJsonObject(session.file_digests_json);
      const seenChunks = safeParseJsonArray(session.seen_chunks_json);
      const hasTurnZeroGrounding =
        Object.keys(groundedFiles).length > 0 || seenChunks.length > 0;
      const extraScopes = allowed_scopes ?? allowedScopes;
      const mergedAllowedScopes = Array.isArray(extraScopes)
        ? [...storedAllowedScopes, ...extraScopes]
        : storedAllowedScopes;
      const sessionMaxBulkLimit =
        max_bulk_limit ?? maxBulkLimit ?? storedDriftState.maxBulkLimit ?? 1000;
      const isOutboundCall = Boolean(
        is_outbound ?? isOutbound ?? OUTBOUND_TOOL_HINT_RE.test(toolName)
      );

      const driftVerdict = evaluateAuthorizationDrift({
        toolName,
        args: effectiveArgs,
        isMutating,
        isOutbound: isOutboundCall,
        step: stepNum,
        goal: session.goal,
        allowedScopes: mergedAllowedScopes,
        groundedFiles,
        hasTurnZeroGrounding,
        priorDriftState: storedDriftState,
        maxBulkLimit: sessionMaxBulkLimit
      });

      updatedDriftStateObj = {
        ...storedDriftState,
        ...driftVerdict.nextDriftState
      };
      updatedDriftStateJson = JSON.stringify(updatedDriftStateObj);

      if (driftVerdict.decision === 'BLOCK') {
        insertEventStmt.run(
          eventId,
          sessionId,
          stepNum,
          toolName,
          isMutating ? 1 : 0,
          isForaging ? 1 : 0,
          canonicalArgsJson,
          callSignature,
          'BLOCK',
          'BLOCKED',
          JSON.stringify(driftVerdict.issues),
          '',
          now,
          now
        );
        db.prepare(
          `UPDATE grounded_sessions
           SET policy_floor_blocks = policy_floor_blocks + 1,
               auth_drift_holds = auth_drift_holds + 1,
               drift_state_json = ?,
               updated_at_ms = ?
           WHERE session_id = ?`
        ).run(updatedDriftStateJson, now, sessionId);
        return okEnvelope(
          'krusch_grounded_intercept',
          `Blocked ${toolName} by authorization drift guard (${driftVerdict.code}).`,
          {
            event_id: eventId,
            decision: 'BLOCK',
            reason: AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_BLOCK,
            driftCode: driftVerdict.code,
            issues: driftVerdict.issues,
            correctivePrompt: driftVerdict.correctivePrompt,
            driftState: driftVerdict.nextDriftState
          }
        );
      }

      if (driftVerdict.decision === 'HOLD') {
        insertEventStmt.run(
          eventId,
          sessionId,
          stepNum,
          toolName,
          isMutating ? 1 : 0,
          isForaging ? 1 : 0,
          canonicalArgsJson,
          callSignature,
          'HOLD',
          'HELD',
          JSON.stringify(driftVerdict.issues),
          '',
          now,
          now
        );
        db.prepare(
          `UPDATE grounded_sessions
           SET auth_drift_holds = auth_drift_holds + 1,
               drift_state_json = ?,
               updated_at_ms = ?
           WHERE session_id = ?`
        ).run(updatedDriftStateJson, now, sessionId);
        return okEnvelope(
          'krusch_grounded_intercept',
          `Held ${toolName} by authorization drift guard (${driftVerdict.code}).`,
          {
            event_id: eventId,
            decision: 'HOLD',
            reason: AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_HOLD,
            driftCode: driftVerdict.code,
            issues: driftVerdict.issues,
            correctivePrompt: driftVerdict.correctivePrompt,
            driftState: driftVerdict.nextDriftState
          }
        );
      }
    }

    // 2.5. Meta-Harness Evolved HOLD_* Rules (INV-GH-11)
    const commandText = extractCommandTextFromArgs(effectiveArgs);
    for (const rule of activeEvolvedRules) {
      if (
        rule.action !== SYNTHESIZED_RULE_ACTIONS.HOLD_PSEUDO_COMPLETION_LOOP &&
        rule.action !== SYNTHESIZED_RULE_ACTIONS.HOLD_TOOL_PATTERN
      ) {
        continue;
      }
      const streakKey = `${sessionId}::${rule.id}`;
      if (matchesEvolvedRule(rule, toolName, commandText)) {
        const nextStreak = (ruleStreaks.get(streakKey) || 0) + 1;
        ruleStreaks.set(streakKey, nextStreak);
        if (nextStreak >= rule.minConsecutiveMatches) {
          const reasonCode =
            rule.action === SYNTHESIZED_RULE_ACTIONS.HOLD_PSEUDO_COMPLETION_LOOP
              ? 'PSEUDO_COMPLETION_ECHO_LOOP'
              : rule.id;
          insertEventStmt.run(
            eventId,
            sessionId,
            stepNum,
            toolName,
            isMutating ? 1 : 0,
            isForaging ? 1 : 0,
            canonicalArgsJson,
            callSignature,
            'HOLD',
            'HELD',
            JSON.stringify([{ code: reasonCode, rule_id: rule.id, message: rule.correctivePrompt }]),
            '',
            now,
            now
          );
          db.prepare(
            'UPDATE grounded_sessions SET spin_loops_blocked = spin_loops_blocked + 1, updated_at_ms = ? WHERE session_id = ?'
          ).run(now, sessionId);
          return okEnvelope(
            'krusch_grounded_intercept',
            `Held ${toolName} by evolved rule ${rule.id} (${reasonCode}).`,
            {
              event_id: eventId,
              decision: 'HOLD',
              reason: reasonCode,
              rule_id: rule.id,
              correctivePrompt: rule.correctivePrompt,
              issues: [{ code: reasonCode, rule_id: rule.id, message: rule.correctivePrompt }]
            }
          );
        }
      } else if (ruleStreaks.has(streakKey)) {
        ruleStreaks.set(streakKey, 0);
      }
    }

    const persistDartAndDriftOnAllow = (extraExploratory = 0) => {
      const dartRepairDelta = dartResult.repaired ? dartResult.repairs.length : 0;
      if (extraExploratory > 0 || dartRepairDelta > 0 || updatedDriftStateJson !== null) {
        db.prepare(
          `UPDATE grounded_sessions
           SET exploratory_reads = exploratory_reads + ?,
               dart_repairs_applied = dart_repairs_applied + ?,
               drift_state_json = COALESCE(?, drift_state_json),
               updated_at_ms = ?
           WHERE session_id = ?`
        ).run(extraExploratory, dartRepairDelta, updatedDriftStateJson, now, sessionId);
      }
    };

    const dartAllowFields = dartResult.repaired
      ? { repairedArgs: effectiveArgs, dartRepairs: dartResult.repairs }
      : {};

    // 3. Read-only path: Turn-0 digest suppression + post-mutation re-read allowance + MEMOIZED -> BLOCK_SPIN_LOOP
    if (!isMutating) {
      if (suppress_turn0_reads && effectiveArgs && typeof effectiveArgs === 'object') {
        const relPath = String(effectiveArgs.relPath || effectiveArgs.path || '').replace(/\\/g, '/');
        const reqDigest = String(effectiveArgs.fileDigest || '');
        const digests = safeParseJsonObject(session.file_digests_json);
        if (relPath && reqDigest && digests[relPath] && digests[relPath] === reqDigest) {
          insertEventStmt.run(
            eventId,
            sessionId,
            stepNum,
            toolName,
            0,
            isForaging ? 1 : 0,
            canonicalArgsJson,
            callSignature,
            'MEMOIZED',
            'MEMOIZED',
            '[]',
            'Already grounded at Turn 0 with identical SHA-256 digest.',
            now,
            now
          );
          db.prepare(
            'UPDATE grounded_sessions SET turn0_duplicates_suppressed = turn0_duplicates_suppressed + 1, updated_at_ms = ? WHERE session_id = ?'
          ).run(now, sessionId);
          return okEnvelope('krusch_grounded_intercept', `Suppressed redundant Turn-0 read of ${relPath}.`, {
            event_id: eventId,
            decision: 'MEMOIZED',
            reason: 'ALREADY_GROUNDED_TURN_ZERO',
            cachedPreview: `File ${relPath} is unchanged since Turn-0 grounding (sha256=${reqDigest}).`,
            issues: []
          });
        }
      }

      const priorReads = selectEventsBySigStmt.all(sessionId, callSignature);
      if (priorReads.length > 0) {
        const latestPrior = priorReads[0];
        const mutationsSincePrior = Number(
          countMutationsAfterStmt.get(sessionId, Number(latestPrior._rowid || 0))?.cnt || 0
        );

        // Allow verification re-read if a mutation committed since the prior identical read!
        if (mutationsSincePrior === 0) {
          if (
            block_spin_loop ||
            latestPrior.status === 'FAILED' ||
            latestPrior.decision === 'MEMOIZED' ||
            latestPrior.decision === 'BLOCK'
          ) {
            insertEventStmt.run(
              eventId,
              sessionId,
              stepNum,
              toolName,
              0,
              isForaging ? 1 : 0,
              canonicalArgsJson,
              callSignature,
              'BLOCK',
              'BLOCKED',
              '[]',
              latestPrior.result_preview || '',
              now,
              now
            );
            db.prepare(
              'UPDATE grounded_sessions SET spin_loops_blocked = spin_loops_blocked + 1, updated_at_ms = ? WHERE session_id = ?'
            ).run(now, sessionId);
            return okEnvelope('krusch_grounded_intercept', `Blocked spin-loop repeat on ${toolName}.`, {
              event_id: eventId,
              decision: 'BLOCK',
              reason: 'BLOCK_SPIN_LOOP',
              cachedPreview: latestPrior.result_preview || '',
              issues: []
            });
          }

          if (latestPrior.status === 'COMMITTED') {
            insertEventStmt.run(
              eventId,
              sessionId,
              stepNum,
              toolName,
              0,
              isForaging ? 1 : 0,
              canonicalArgsJson,
              callSignature,
              'MEMOIZED',
              'MEMOIZED',
              '[]',
              latestPrior.result_preview || '',
              now,
              now
            );
            db.prepare(
              'UPDATE grounded_sessions SET memoized_reads = memoized_reads + 1, updated_at_ms = ? WHERE session_id = ?'
            ).run(now, sessionId);
            return okEnvelope('krusch_grounded_intercept', `Memoized prior read for ${toolName}.`, {
              event_id: eventId,
              decision: 'MEMOIZED',
              reason: 'MEMOIZED_PRIOR_READ',
              cachedPreview: latestPrior.result_preview || '',
              issues: []
            });
          }
        }
      }

      insertEventStmt.run(
        eventId,
        sessionId,
        stepNum,
        toolName,
        0,
        isForaging ? 1 : 0,
        canonicalArgsJson,
        callSignature,
        'ALLOW',
        'STAGED',
        '[]',
        '',
        now,
        now
      );
      persistDartAndDriftOnAllow(isForaging ? 1 : 0);
      return okEnvelope('krusch_grounded_intercept', `Allowed read call ${toolName}.`, {
        event_id: eventId,
        decision: 'ALLOW',
        reason: 'ALLOW_READ',
        issues: [],
        ...dartAllowFields
      });
    }

    // 4. Mutating path: 3-strike mutation stall breaker (INV-GH-13) + duplicate-write prevention + SMALL_MODEL soft holds
    const stallGuardEnabled =
      storedDriftState.enableMutationStallGuard !== false &&
      enable_mutation_stall_guard !== false &&
      enableMutationStallGuard !== false;
    const allowStalled =
      allow_stalled_mutation === true || allowStalledMutation === true;

    if (stallGuardEnabled && !allowStalled) {
      const priorStall =
        storedDriftState.mutationStall && typeof storedDriftState.mutationStall === 'object'
          ? storedDriftState.mutationStall
          : {};
      const effectiveMaxStall =
        max_stalled_mutations ??
        maxStalledMutations ??
        storedDriftState.maxStalledMutations ??
        3;
      const stallCheck = evaluateMutationStallGuard({
        priorState: priorStall,
        isMutating: false,
        maxStalledMutations: effectiveMaxStall
      });
      if (stallCheck.stalled) {
        const nextStallHolds = Number(storedDriftState.stalledMutationHolds || 0) + 1;
        const nextMutationStall = {
          ...stallCheck.nextState,
          stalledHolds: Number(priorStall.stalledHolds || 0) + 1
        };
        const baseDrift = updatedDriftStateObj || storedDriftState;
        const stalledDriftJson = JSON.stringify({
          ...baseDrift,
          mutationStall: nextMutationStall,
          stalledMutationHolds: nextStallHolds
        });
        const stallIssues = [
          {
            code: 'STALLED_MUTATION_LOOP',
            stalledStreak: stallCheck.stalledStreak,
            bestPassedCases: stallCheck.bestPassedCases,
            maxStalledMutations: stallCheck.maxStalledMutations,
            message: stallCheck.correctivePrompt
          }
        ];
        insertEventStmt.run(
          eventId,
          sessionId,
          stepNum,
          toolName,
          1,
          0,
          canonicalArgsJson,
          callSignature,
          'HOLD',
          'HELD',
          JSON.stringify(stallIssues),
          '',
          now,
          now
        );
        db.prepare(
          'UPDATE grounded_sessions SET drift_state_json = ?, updated_at_ms = ? WHERE session_id = ?'
        ).run(stalledDriftJson, now, sessionId);
        return okEnvelope(
          'krusch_grounded_intercept',
          `Held ${toolName} by mutation stall guard (${stallCheck.stalledStreak} stalled verified cycle(s)).`,
          {
            event_id: eventId,
            decision: 'HOLD',
            reason: 'STALLED_MUTATION_LOOP',
            stalledStreak: stallCheck.stalledStreak,
            bestPassedCases: stallCheck.bestPassedCases,
            maxStalledMutations: stallCheck.maxStalledMutations,
            correctivePrompt: stallCheck.correctivePrompt,
            issues: stallIssues
          }
        );
      }
    }

    const exemptDuplicateWrite = activeEvolvedRules.some(
      (rule) =>
        rule.action === SYNTHESIZED_RULE_ACTIONS.EXEMPT_DUPLICATE_WRITE &&
        matchesEvolvedRule(rule, toolName, commandText)
    );

    if (!exemptDuplicateWrite) {
      const afterDiffRowId = Number(
        maxDiffMutationRowStmt.get(sessionId, callSignature)?.max_rowid || 0
      );
      const priorMutations = selectEventsBySigStmt
        .all(sessionId, callSignature)
        .filter(
          (r) =>
            Number(r._rowid || 0) > afterDiffRowId &&
            (r.status === 'STAGED' || r.status === 'COMMITTED')
        );
      if (priorMutations.length >= Number(session.max_duplicate_writes || 1)) {
        insertEventStmt.run(
          eventId,
          sessionId,
          stepNum,
          toolName,
          1,
          0,
          canonicalArgsJson,
          callSignature,
          'BLOCK',
          'BLOCKED',
          '[]',
          '',
          now,
          now
        );
        db.prepare(
          'UPDATE grounded_sessions SET duplicate_writes_blocked = duplicate_writes_blocked + 1, updated_at_ms = ? WHERE session_id = ?'
        ).run(now, sessionId);
        return okEnvelope('krusch_grounded_intercept', `Blocked duplicate write on ${toolName}.`, {
          event_id: eventId,
          decision: 'BLOCK',
          reason: 'BLOCK_DUPLICATE_WRITE',
          issues: []
        });
      }
    }

    if (scaleProfile.softHoldPlaceholdersAndDates) {
      const issues = scanSmallModelArgumentIssues(canonicalArgs);
      if (issues.length > 0) {
        insertEventStmt.run(
          eventId,
          sessionId,
          stepNum,
          toolName,
          1,
          0,
          canonicalArgsJson,
          callSignature,
          'HOLD',
          'HELD',
          JSON.stringify(issues),
          '',
          now,
          now
        );
        return okEnvelope(
          'krusch_grounded_intercept',
          `Held ${toolName} for SMALL_MODEL argument revision (${issues.length} issue(s)).`,
          {
            event_id: eventId,
            decision: 'HOLD',
            reason: 'SMALL_MODEL_ARGUMENT_HOLD',
            issues
          }
        );
      }
    }

    insertEventStmt.run(
      eventId,
      sessionId,
      stepNum,
      toolName,
      1,
      0,
      canonicalArgsJson,
      callSignature,
      'ALLOW',
      'STAGED',
      '[]',
      '',
      now,
      now
    );
    persistDartAndDriftOnAllow(0);
    return okEnvelope('krusch_grounded_intercept', `Allowed mutating call ${toolName}.`, {
      event_id: eventId,
      decision: 'ALLOW',
      reason: 'ALLOW_MUTATION',
      issues: [],
      ...dartAllowFields
    });
  }

  function recordToolOutcome(params = {}) {
    const {
      session_id,
      sessionId: altSessionId,
      event_id,
      eventId: altEventId,
      ok = true,
      result_preview,
      resultPreview,
      timed_out,
      timedOut,
      partial_stdout,
      partialStdout,
      pending_diffs_delta,
      pendingDiffsDelta,
      verification_passed,
      verificationPassed,
      clear_pending_diffs,
      clearPendingDiffs,
      passed_cases,
      passedCases,
      total_cases,
      totalCases,
      mutated_paths,
      mutatedPaths,
      reset_mutation_stall,
      resetMutationStall,
      max_stalled_mutations,
      maxStalledMutations,
      updated_file_digests,
      updatedFileDigests
    } = params || {};

    const sessionId = String(session_id ?? altSessionId ?? '').trim();
    const session = sessionId ? selectSessionStmt.get(sessionId) : null;
    if (!session) {
      return okEnvelope(
        'krusch_grounded_outcome',
        `Grounded session "${sessionId}" not found.`,
        { status: 'SESSION_NOT_FOUND' },
        false
      );
    }
    const resolvedEventId = String(event_id ?? altEventId ?? '').trim();
    const event = resolvedEventId ? selectEventStmt.get(resolvedEventId, sessionId) : null;
    if (!event) {
      return okEnvelope(
        'krusch_grounded_outcome',
        `Event "${resolvedEventId}" not found.`,
        { status: 'EVENT_NOT_FOUND' },
        false
      );
    }

    const isTimeout = Boolean(timed_out ?? timedOut ?? false);
    const finalStatus = !isTimeout && ok !== false ? 'COMMITTED' : 'FAILED';
    const rawPreview = result_preview ?? resultPreview ?? '';
    const rawPartial = partial_stdout ?? partialStdout ?? '';
    const preview = isTimeout
      ? String(rawPartial || rawPreview || '').slice(0, 2000)
      : String(rawPreview || '').slice(0, 1024);
    const now = Date.now();
    const deltaNum = Number(pending_diffs_delta ?? pendingDiffsDelta ?? 0);
    const effectiveVerificationPassed =
      verification_passed !== undefined ? verification_passed : verificationPassed;
    const effectiveClearPendingDiffs =
      clear_pending_diffs !== undefined ? clear_pending_diffs : clearPendingDiffs;
    const effectivePassedCases = passed_cases !== undefined ? passed_cases : passedCases;
    const effectiveTotalCases = total_cases !== undefined ? total_cases : totalCases;

    const eventArgs = safeParseJsonObject(event.canonical_args_json);
    const eventCommandText = extractCommandTextFromArgs(eventArgs);
    const eventToolName = String(event.tool_name || '');

    let nextDiffs = Number(session.pending_diffs_count || 0);
    let nextVerifyPassed = Number(session.latest_verification_passed ?? 1);
    let exemptCleanupDiff = false;
    let creditedInlineVerify = false;

    if (finalStatus === 'COMMITTED') {
      exemptCleanupDiff =
        Boolean(event.is_mutating) &&
        nextDiffs === 0 &&
        nextVerifyPassed === 1 &&
        activeEvolvedRules.some(
          (rule) =>
            rule.action === SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF &&
            matchesEvolvedRule(rule, eventToolName, eventCommandText)
        );

      if (!exemptCleanupDiff) {
        nextDiffs = Math.max(0, nextDiffs + deltaNum);
        if (deltaNum > 0 && effectiveVerificationPassed === undefined) {
          nextVerifyPassed = 0;
        }
      }

      if (effectiveVerificationPassed === undefined && deltaNum <= 0) {
        const creditInlineVerify = activeEvolvedRules.some(
          (rule) =>
            rule.action === SYNTHESIZED_RULE_ACTIONS.CREDIT_INLINE_VERIFY &&
            matchesEvolvedRule(rule, eventToolName, eventCommandText)
        );
        if (creditInlineVerify) {
          creditedInlineVerify = true;
          nextVerifyPassed = 1;
          if (effectiveClearPendingDiffs !== false) {
            nextDiffs = 0;
          }
        }
      }
    }

    if (effectiveVerificationPassed === true) {
      nextVerifyPassed = 1;
      if (effectiveClearPendingDiffs !== false) {
        nextDiffs = 0;
      }
    } else if (effectiveVerificationPassed === false) {
      nextVerifyPassed = 0;
    } else if (
      effectivePassedCases !== undefined &&
      effectivePassedCases !== null &&
      effectiveTotalCases !== undefined &&
      effectiveTotalCases !== null &&
      Number.isFinite(Number(effectivePassedCases)) &&
      Number.isFinite(Number(effectiveTotalCases)) &&
      Number(effectiveTotalCases) > 0
    ) {
      if (Number(effectivePassedCases) >= Number(effectiveTotalCases)) {
        nextVerifyPassed = 1;
        if (effectiveClearPendingDiffs !== false) {
          nextDiffs = 0;
        }
      } else {
        nextVerifyPassed = 0;
      }
    }

    // Hydrate & evolve drift_state_json (sessionMutatedPaths + mutationStall)
    const storedDriftState = safeParseJsonObject(session.drift_state_json);
    const resolvedSessionRoot =
      typeof storedDriftState.workspaceDir === 'string' && storedDriftState.workspaceDir.trim()
        ? path.resolve(storedDriftState.workspaceDir.trim())
        : null;
    const existingMutatedPaths = Array.isArray(storedDriftState.sessionMutatedPaths)
      ? storedDriftState.sessionMutatedPaths.map((p) => String(p))
      : [];
    const mutatedSet = new Set(existingMutatedPaths);
    if (finalStatus === 'COMMITTED' && Boolean(event.is_mutating) && !exemptCleanupDiff) {
      const newlyMutated = extractMutatedPathsFromArgs(
        eventArgs,
        mutated_paths ?? mutatedPaths ?? [],
        resolvedSessionRoot
      );
      for (const mp of newlyMutated) mutatedSet.add(mp);
    } else if (Array.isArray(mutated_paths ?? mutatedPaths)) {
      const extraMutated = extractMutatedPathsFromArgs(
        null,
        mutated_paths ?? mutatedPaths,
        resolvedSessionRoot
      );
      for (const mp of extraMutated) mutatedSet.add(mp);
    }
    const nextMutatedPaths = [...mutatedSet];

    const priorStall =
      storedDriftState.mutationStall && typeof storedDriftState.mutationStall === 'object'
        ? storedDriftState.mutationStall
        : {
            stalledStreak: 0,
            bestPassedCases: null,
            mutationsSinceLastEval: 0,
            stalledHolds: 0
          };
    const shouldResetStall =
      reset_mutation_stall === true || resetMutationStall === true;
    const effectiveMaxStall =
      max_stalled_mutations ??
      maxStalledMutations ??
      storedDriftState.maxStalledMutations ??
      3;

    let nextMutationStall;
    if (shouldResetStall) {
      nextMutationStall = {
        stalledStreak: 0,
        bestPassedCases: null,
        mutationsSinceLastEval: 0,
        stalledHolds: Number(priorStall.stalledHolds || 0)
      };
    } else {
      const evalVerifSignal =
        typeof effectiveVerificationPassed === 'boolean'
          ? effectiveVerificationPassed
          : creditedInlineVerify
            ? true
            : undefined;
      const stallEval = evaluateMutationStallGuard({
        priorState: priorStall,
        isMutating: Boolean(event.is_mutating) && finalStatus === 'COMMITTED' && !exemptCleanupDiff,
        passedCases: effectivePassedCases,
        totalCases: effectiveTotalCases,
        verificationPassed: evalVerifSignal,
        maxStalledMutations: effectiveMaxStall
      });
      nextMutationStall = stallEval.nextState;
    }

    const nextDriftStateJson = JSON.stringify({
      ...storedDriftState,
      sessionMutatedPaths: nextMutatedPaths,
      mutationStall: nextMutationStall
    });

    const rawUpdatedDigests = updated_file_digests ?? updatedFileDigests;
    const nextFileDigestsJson =
      rawUpdatedDigests && typeof rawUpdatedDigests === 'object' && !Array.isArray(rawUpdatedDigests)
        ? JSON.stringify(rawUpdatedDigests)
        : null;

    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(
        'UPDATE grounded_events SET status = ?, result_preview = ?, updated_at_ms = ? WHERE event_id = ? AND session_id = ?'
      ).run(finalStatus, preview, now, event.event_id, sessionId);

      const addRead = finalStatus === 'COMMITTED' && !event.is_mutating ? 1 : 0;
      const addMut = finalStatus === 'COMMITTED' && event.is_mutating ? 1 : 0;
      const addTimeout = isTimeout ? 1 : 0;

      db.prepare(`
        UPDATE grounded_sessions
        SET committed_reads = committed_reads + ?,
            committed_mutations = committed_mutations + ?,
            timeouts_with_partial_stdout = timeouts_with_partial_stdout + ?,
            pending_diffs_count = ?,
            latest_verification_passed = ?,
            drift_state_json = ?,
            file_digests_json = COALESCE(?, file_digests_json),
            updated_at_ms = ?
        WHERE session_id = ?
      `).run(
        addRead,
        addMut,
        addTimeout,
        nextDiffs,
        nextVerifyPassed,
        nextDriftStateJson,
        nextFileDigestsJson,
        now,
        sessionId
      );
      db.exec('COMMIT');
    } catch (err) {
      try {
        db.exec('ROLLBACK');
      } catch {
        /* ignore */
      }
      throw err;
    }

    return okEnvelope('krusch_grounded_outcome', `Recorded ${finalStatus} for ${event.tool_name}.`, {
      session_id: sessionId,
      event_id: event.event_id,
      status: finalStatus,
      pending_diffs_count: nextDiffs,
      latest_verification_passed: nextVerifyPassed,
      mutation_stall: nextMutationStall,
      session_mutated_paths: nextMutatedPaths,
      timed_out: isTimeout,
      preserved_stdout: isTimeout ? preview : undefined,
      has_final_answer: false,
      final_answer: null
    });
  }

  function verifyStop(params = {}) {
    const {
      session_id,
      sessionId: altSessionId,
      assistant_text,
      assistantText,
      candidate_answer,
      candidateAnswer,
      finish_reason,
      finishReason,
      truncated_tool_calls,
      truncatedToolCalls,
      tool_calls,
      toolCalls,
      expect_non_empty_answer,
      expectNonEmptyAnswer,
      pending_diffs_count,
      pendingDiffsCount,
      latest_verification_passed,
      latestVerificationPassed,
      verification_command,
      verificationCommand,
      current_file_digests,
      currentFileDigests,
      workspace_dir,
      workspaceDir,
      session_mutated_paths,
      sessionMutatedPaths,
      audited_files,
      auditedFiles,
      enable_source_drift_guard,
      enableSourceDriftGuard,
      enable_infallible_audit,
      enableInfallibleAudit
    } = params || {};

    const sessionId = String(session_id ?? altSessionId ?? '').trim();
    const session = sessionId ? selectSessionStmt.get(sessionId) : null;
    if (!session) {
      return okEnvelope(
        'krusch_grounded_verify_stop',
        `Grounded session "${sessionId}" not found.`,
        { allowStop: true, shouldNudge: false, action: 'SESSION_NOT_FOUND' },
        false
      );
    }

    const now = Date.now();
    const scaleProfile = JSON.parse(session.scale_profile_json);
    const effectiveAssistantText = String(assistant_text ?? assistantText ?? '');
    const effectiveCandidateAnswer =
      candidate_answer !== undefined ? candidate_answer : candidateAnswer;
    const effectiveFinishReason = finish_reason ?? finishReason ?? null;
    const effectiveTruncatedToolCalls = Boolean(
      truncated_tool_calls ?? truncatedToolCalls ?? false
    );
    const effectiveToolCalls = Array.isArray(tool_calls ?? toolCalls)
      ? (tool_calls ?? toolCalls)
      : [];
    const effectiveExpectNonEmpty = Boolean(
      expect_non_empty_answer ?? expectNonEmptyAnswer ?? false
    );
    const rawPendingOverride =
      pending_diffs_count !== undefined ? pending_diffs_count : pendingDiffsCount;
    const effectivePendingDiffs =
      rawPendingOverride !== undefined
        ? Number(rawPendingOverride)
        : Number(session.pending_diffs_count || 0);
    const rawVerifiedOverride =
      latest_verification_passed !== undefined
        ? latest_verification_passed
        : latestVerificationPassed;
    const effectiveVerified =
      rawVerifiedOverride !== undefined
        ? Boolean(rawVerifiedOverride)
        : Boolean(session.latest_verification_passed);
    const effectiveVerifyCmd = String(
      verification_command ?? verificationCommand ?? 'npm test'
    );

    // 1. Staged-diff-only FORCE_VERIFY (INV-GH-05: ONLY when pendingDiffsCount > 0 && !latestVerificationPassed)
    if (effectivePendingDiffs > 0 && !effectiveVerified) {
      db.prepare(
        'UPDATE grounded_sessions SET verify_nudges_used = verify_nudges_used + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(now, sessionId);
      return okEnvelope(
        'krusch_grounded_verify_stop',
        `Blocked stop: ${effectivePendingDiffs} unverified staged diff(s) require verification.`,
        {
          allowStop: false,
          shouldNudge: true,
          action: 'FORCE_VERIFY',
          reason: 'UNVERIFIED_STAGED_DIFFS',
          correctivePrompt: `Run verification (${effectiveVerifyCmd}) before completing ${effectivePendingDiffs} staged diff(s).`
        }
      );
    }

    const storedDriftState = safeParseJsonObject(session.drift_state_json);

    // 2. Upstream Source Fingerprint Drift Invalidation (INV-GH-14)
    const sourceDriftEnabled =
      storedDriftState.enableSourceDriftGuard !== false &&
      enable_source_drift_guard !== false &&
      enableSourceDriftGuard !== false;
    const rawCurrentDigests = current_file_digests ?? currentFileDigests ?? null;
    const rawVerifyWorkspace =
      workspace_dir ?? workspaceDir ?? storedDriftState.workspaceDir ?? null;
    const resolvedVerifyWorkspace =
      typeof rawVerifyWorkspace === 'string' && rawVerifyWorkspace.trim()
        ? path.resolve(workspaceRoot, rawVerifyWorkspace.trim())
        : null;

    if (
      sourceDriftEnabled &&
      ((rawCurrentDigests && typeof rawCurrentDigests === 'object') || resolvedVerifyWorkspace)
    ) {
      const baselineDigests = safeParseJsonObject(session.file_digests_json);
      const storedMutated = Array.isArray(storedDriftState.sessionMutatedPaths)
        ? storedDriftState.sessionMutatedPaths
        : [];
      const extraMutated = Array.isArray(session_mutated_paths ?? sessionMutatedPaths)
        ? (session_mutated_paths ?? sessionMutatedPaths)
        : [];
      const driftCheck = evaluateSourceFingerprintDrift({
        baselineDigests,
        currentDigests: rawCurrentDigests,
        workspaceDir: resolvedVerifyWorkspace,
        sessionMutatedPaths: [...storedMutated, ...extraMutated]
      });
      if (driftCheck.drifted) {
        const nextStaleBlocks = Number(storedDriftState.staleGroundingBlocks || 0) + 1;
        const updatedDriftJson = JSON.stringify({
          ...storedDriftState,
          staleGroundingBlocks: nextStaleBlocks
        });
        db.prepare(
          `UPDATE grounded_sessions
           SET verify_nudges_used = verify_nudges_used + 1,
               latest_verification_passed = 0,
               drift_state_json = ?,
               updated_at_ms = ?
           WHERE session_id = ?`
        ).run(updatedDriftJson, now, sessionId);
        return okEnvelope(
          'krusch_grounded_verify_stop',
          `Blocked stop: ${driftCheck.driftedFiles.length} upstream file(s) drifted since Turn-0 grounding.`,
          {
            allowStop: false,
            shouldNudge: true,
            action: 'FORCE_REVERIFY_STALE_SOURCE',
            reason: driftCheck.reason,
            driftedFiles: driftCheck.driftedFiles,
            checkedCount: driftCheck.checkedCount,
            nudgePrompt: driftCheck.correctivePrompt,
            correctivePrompt: driftCheck.correctivePrompt
          }
        );
      }
    }

    // 3. // INFALLIBLE: <reason> Panic & Assertion Surface Auditor (INV-GH-15)
    const infallibleAuditEnabled =
      storedDriftState.enableInfallibleAudit !== false &&
      enable_infallible_audit !== false &&
      enableInfallibleAudit !== false;
    const rawAuditedFiles = audited_files ?? auditedFiles;

    if (infallibleAuditEnabled && rawAuditedFiles) {
      const normalizedFileEntries = [];
      if (Array.isArray(rawAuditedFiles)) {
        for (const item of rawAuditedFiles) {
          if (!item || typeof item !== 'object') continue;
          const itemPath = String(item.filePath ?? item.file_path ?? item.path ?? item.file ?? '');
          let itemCode = item.code ?? item.content ?? item.source;
          if (itemCode === undefined && itemPath && resolvedVerifyWorkspace) {
            const fullPath = path.resolve(resolvedVerifyWorkspace, itemPath);
            const relCheck = path.relative(resolvedVerifyWorkspace, fullPath);
            if (relCheck && !relCheck.startsWith('..') && !path.isAbsolute(relCheck)) {
              try {
                if (fs.existsSync(fullPath) && fs.lstatSync(fullPath).isFile()) {
                  itemCode = fs.readFileSync(fullPath, 'utf8');
                }
              } catch {
                itemCode = '';
              }
            }
          }
          normalizedFileEntries.push({
            filePath: itemPath,
            code: String(itemCode ?? ''),
            language: String(item.language ?? item.lang ?? ''),
            requireFallibleContract:
              item.requireFallibleContract ?? item.require_fallible_contract ?? true
          });
        }
      } else if (typeof rawAuditedFiles === 'object') {
        for (const [fPath, fCode] of Object.entries(rawAuditedFiles)) {
          normalizedFileEntries.push({
            filePath: String(fPath),
            code: String(fCode ?? ''),
            language: '',
            requireFallibleContract: true
          });
        }
      }

      const allFindings = [];
      const prompts = [];
      for (const entry of normalizedFileEntries) {
        const auditRes = auditInfallibleAssertions(entry);
        if (!auditRes.passed) {
          allFindings.push(...auditRes.findings);
          if (auditRes.correctivePrompt) prompts.push(auditRes.correctivePrompt);
        }
      }

      if (allFindings.length > 0) {
        const nextInfallibleBlocks = Number(storedDriftState.infallibleAuditBlocks || 0) + 1;
        const updatedDriftJson = JSON.stringify({
          ...storedDriftState,
          infallibleAuditBlocks: nextInfallibleBlocks
        });
        const mergedPrompt = prompts.join(' ');
        db.prepare(
          `UPDATE grounded_sessions
           SET verify_nudges_used = verify_nudges_used + 1,
               drift_state_json = ?,
               updated_at_ms = ?
           WHERE session_id = ?`
        ).run(updatedDriftJson, now, sessionId);
        return okEnvelope(
          'krusch_grounded_verify_stop',
          `Blocked stop: ${allFindings.length} unannotated panic/exit/stub assertion(s) detected.`,
          {
            allowStop: false,
            shouldNudge: true,
            action: 'REJECT_UNEXPLAINED_PANIC',
            reason: 'UNEXPLAINED_INFALLIBLE_ASSERTION',
            infallibleFindings: allFindings,
            findings: allFindings,
            nudgePrompt: mergedPrompt,
            correctivePrompt: mergedPrompt
          }
        );
      }
    }

    // 4. Universal zero-turn-when-healthy Output Defect Gate (max 1 defect retry)
    const defectCheck = inspectOutputDefects({
      candidateAnswer: effectiveCandidateAnswer,
      assistantText: effectiveAssistantText,
      finishReason: effectiveFinishReason,
      truncatedToolCalls: effectiveTruncatedToolCalls,
      toolCalls: effectiveToolCalls,
      expectNonEmptyAnswer: effectiveExpectNonEmpty
    });
    if (defectCheck.hasDefect && Number(session.output_defects_caught || 0) < 1) {
      db.prepare(
        'UPDATE grounded_sessions SET output_defects_caught = output_defects_caught + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(now, sessionId);
      return okEnvelope(
        'krusch_grounded_verify_stop',
        `Output defect caught (${defectCheck.primaryDefect.code}).`,
        {
          allowStop: false,
          shouldNudge: true,
          action: 'REJECT_OUTPUT_DEFECT',
          reason: defectCheck.primaryDefect.code,
          defects: defectCheck.defects,
          correctivePrompt: defectCheck.correctivePrompt
        }
      );
    }

    // 5. SMALL_MODEL uncommitted draft rescue (never nudges policy abstentions!)
    if (
      scaleProfile.maxMechanicalVerifyNudges > 0 &&
      Number(session.committed_mutations || 0) === 0 &&
      Number(session.verify_nudges_used || 0) < scaleProfile.maxMechanicalVerifyNudges &&
      UNCOMMITTED_DRAFT_RE.test(effectiveAssistantText) &&
      !POLICY_ABSTENTION_RE.test(effectiveAssistantText)
    ) {
      db.prepare(
        'UPDATE grounded_sessions SET verify_nudges_used = verify_nudges_used + 1, updated_at_ms = ? WHERE session_id = ?'
      ).run(now, sessionId);
      return okEnvelope(
        'krusch_grounded_verify_stop',
        'Nudging SMALL_MODEL uncommitted draft to execute tool call.',
        {
          allowStop: false,
          shouldNudge: true,
          action: 'NUDGE_SMALL_MODEL_DRAFT',
          reason: 'UNCOMMITTED_SMALL_MODEL_DRAFT',
          correctivePrompt:
            'You printed a draft without invoking the mutating tool. Execute the required tool call now if policy allows.'
        }
      );
    }

    db.prepare("UPDATE grounded_sessions SET status = 'COMPLETED', updated_at_ms = ? WHERE session_id = ?").run(
      now,
      sessionId
    );
    return okEnvelope('krusch_grounded_verify_stop', `Session ${sessionId} verified complete.`, {
      allowStop: true,
      shouldNudge: false,
      action: 'ALLOW_STOP'
    });
  }

  function sessionSummary(params = {}) {
    const sessionId = String(params?.session_id ?? params?.sessionId ?? '').trim();
    const row = sessionId ? selectSessionStmt.get(sessionId) : null;
    if (!row) {
      return okEnvelope(
        'krusch_grounded_summary',
        `Grounded session "${sessionId}" not found.`,
        { status: 'SESSION_NOT_FOUND' },
        false
      );
    }
    const events = selectAllSessionEventsStmt.all(sessionId).map((e) => ({
      event_id: e.event_id,
      step: Number(e.step || 0),
      tool_name: e.tool_name,
      is_mutating: Boolean(e.is_mutating),
      is_foraging: Boolean(e.is_foraging),
      decision: e.decision,
      status: e.status,
      issues: JSON.parse(e.issues_json || '[]'),
      result_preview: e.result_preview
    }));

    const hydratedDrift = safeParseJsonObject(row.drift_state_json);
    const rawMutationStall =
      hydratedDrift.mutationStall && typeof hydratedDrift.mutationStall === 'object'
        ? hydratedDrift.mutationStall
        : {};
    const mutationStall = {
      stalledStreak: Number(rawMutationStall.stalledStreak || 0),
      bestPassedCases:
        rawMutationStall.bestPassedCases !== null &&
        rawMutationStall.bestPassedCases !== undefined &&
        Number.isFinite(Number(rawMutationStall.bestPassedCases))
          ? Number(rawMutationStall.bestPassedCases)
          : null,
      mutationsSinceLastEval: Number(rawMutationStall.mutationsSinceLastEval || 0),
      stalledHolds: Number(rawMutationStall.stalledHolds || 0)
    };

    return okEnvelope('krusch_grounded_summary', `Summary for grounded session ${sessionId}.`, {
      session: {
        session_id: row.session_id,
        goal: row.goal,
        model: row.model,
        scale_tier: row.scale_tier,
        status: row.status,
        prefix_hash: row.prefix_hash
      },
      metrics: {
        schemaTokensSaved: Number(row.schema_tokens_saved || 0),
        schemaReductionPct: Number(row.schema_reduction_pct || 0),
        turn0Tokens: Number(row.turn0_tokens || 0),
        exploratoryReads: Number(row.exploratory_reads || 0),
        committedReads: Number(row.committed_reads || 0),
        committedMutations: Number(row.committed_mutations || 0),
        memoizedReads: Number(row.memoized_reads || 0),
        spinLoopsBlocked: Number(row.spin_loops_blocked || 0),
        outputDefectsCaught: Number(row.output_defects_caught || 0),
        timeoutsWithPartialStdout: Number(row.timeouts_with_partial_stdout || 0),
        turn0DuplicatesSuppressed: Number(row.turn0_duplicates_suppressed || 0),
        duplicateWritesBlocked: Number(row.duplicate_writes_blocked || 0),
        policyFloorBlocks: Number(row.policy_floor_blocks || 0),
        authDriftHolds: Number(row.auth_drift_holds || 0),
        dartRepairsApplied: Number(row.dart_repairs_applied || 0),
        dartHolds: Number(row.dart_holds || 0),
        driftScore: Number(hydratedDrift.driftScore || 0),
        taintedDomains: Array.isArray(hydratedDrift.taintedDomains)
          ? hydratedDrift.taintedDomains
          : [],
        stalledMutationHolds: Number(hydratedDrift.stalledMutationHolds || 0),
        staleGroundingBlocks: Number(hydratedDrift.staleGroundingBlocks || 0),
        infallibleAuditBlocks: Number(hydratedDrift.infallibleAuditBlocks || 0),
        mutationStall,
        truncationRecoveries: Number(row.truncation_recoveries || 0),
        verifyNudgesUsed: Number(row.verify_nudges_used || 0)
      },
      events
    });
  }

  return {
    resolveScale,
    groundWorkspace,
    startSession,
    groundAndStartSession,
    evaluateTurn,
    interceptToolCall,
    recordToolOutcome,
    verifyStop,
    sessionSummary
  };
}

export {
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift,
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  compileExecutableRules,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  synthesizeRulesWithTeacher,
  evolveRulesFromTraces
};
