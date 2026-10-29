/**
 * @module engines/resilience-engine
 * Zero-dependency Node 22 (`node:sqlite` + `node:crypto`) Production Agentic Resilience Engine
 * for KruschStack. Enforces INV-STACK-01 (SQLite or in-memory operation), INV-STACK-02 (okEnvelope),
 * and INV-STACK-04 (zero private hostnames or private LAN/Tailscale IPs).
 *
 * Implements five deterministic production guardrails:
 *   1. Pre-flight 3-bucket + conversation history context token budget assembly (`assembleContextBudget`)
 *   2. $0.50 hard cost kill-switch with local Ollama fallback & loop-depth breaker (`evaluateCostKillSwitch`, `recordCostUsage`)
 *   3. Topological trajectory DAG verifier (`verifyTrajectoryDag`)
 *   4. Non-blocking shadow run Levenshtein & exact-DAG comparator (`recordShadowComparison`)
 *   5. 72-hour async HITL lease gate with Slack `v0=` HMAC-SHA256 `timingSafeEqual` verification (`draftHitlGate`, `resolveHitlGate`)
 */

import crypto from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { okEnvelope } from '../db/sqlite.js';

export const RESILIENCE_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS stack_hitl_gates (
    gate_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    staged_payload TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    decided_at_ms INTEGER,
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
    sequence_similarity REAL NOT NULL,
    exact_dag_match INTEGER NOT NULL,
    latency_delta_ms REAL NOT NULL,
    cost_delta_usd REAL NOT NULL,
    created_at_ms INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_stack_shadow_runs_request
    ON stack_shadow_runs(request_id, created_at_ms);
`;

const FRONTIER_MODEL_PRICING_PER_1M = Object.freeze({
  'gemini-4-argon': { inputUsd: 2.5, outputUsd: 10.0 },
  'gemini-3.8-flash': { inputUsd: 0.15, outputUsd: 0.6 },
  'gemini-3.1-flash-lite': { inputUsd: 0.1, outputUsd: 0.4 },
  'gpt-5': { inputUsd: 5.0, outputUsd: 15.0 },
  'gpt-4o': { inputUsd: 2.5, outputUsd: 10.0 },
  o3: { inputUsd: 10.0, outputUsd: 40.0 },
  'claude-4-opus': { inputUsd: 15.0, outputUsd: 75.0 },
  'claude-4-sonnet': { inputUsd: 3.0, outputUsd: 15.0 },
  'claude-3.5-sonnet': { inputUsd: 3.0, outputUsd: 15.0 },
  'moonshotai/kimi-k3': { inputUsd: 0.6, outputUsd: 2.4 }
});

const LOCAL_MODEL_PATTERNS = [
  /^ollama\//i,
  /^local\//i,
  /^qwen/i,
  /^gemma/i,
  /^hermes/i,
  /^gpt-oss/i,
  /^snowflake-arctic-embed/i,
  /^deepseek-r1:/i,
  /^llama/i,
  /^mistral/i,
  /^spectralquant/i,
  /:(7b|8b|9b|14b|27b|30b|32b|70b|120b|e4b|latest)$/i
];

const SLACK_REPLAY_WINDOW_MS = 5 * 60 * 1000;

/**
 * Attach non-enumerable `status` alias onto a standard `{ ok, tool, summary, data }` envelope
 * so `Object.keys` / `JSON.stringify` preserve strict INV-STACK-02 shape while convenient
 * `result.status` property reads resolve identically to `result.data.status`.
 * @param {object} envelope
 * @returns {object}
 */
function attachStatusAccessor(envelope) {
  if (envelope && envelope.data && typeof envelope.data.status === 'string') {
    Object.defineProperty(envelope, 'status', {
      value: envelope.data.status,
      enumerable: false,
      configurable: true
    });
  }
  return envelope;
}

/**
 * Deterministically estimate token count from UTF-8 byte length (~4 bytes/token).
 * Empty strings always evaluate to 0 tokens.
 * @param {string} [text='']
 * @returns {number}
 */
export function estimateTokenCount(text = '') {
  const str = String(text ?? '');
  if (str.length === 0) return 0;
  return Math.ceil(Buffer.byteLength(str, 'utf8') / 4);
}

/**
 * Truncate a UTF-8 string so that `estimateTokenCount(result) <= maxTokens` strictly holds.
 * @param {string} text
 * @param {number} maxTokens
 * @returns {string}
 */
function truncateToTokenBudget(text = '', maxTokens = 0) {
  const cap = Math.max(0, Math.floor(Number(maxTokens) || 0));
  if (cap === 0) return '';
  const str = String(text ?? '');
  if (estimateTokenCount(str) <= cap) return str;

  const maxBytes = cap * 4;
  const buf = Buffer.from(str, 'utf8');
  if (buf.length <= maxBytes) return str;

  let sliceEnd = maxBytes;
  while (sliceEnd > 0 && (buf[sliceEnd] & 0xc0) === 0x80) {
    sliceEnd -= 1;
  }
  let candidate = buf.subarray(0, sliceEnd).toString('utf8');
  while (candidate.length > 0 && estimateTokenCount(candidate) > cap) {
    candidate = candidate.slice(0, -1);
  }
  return candidate;
}

/**
 * Determine whether a model identifier corresponds to a $0.00 local open-weights runtime.
 * @param {string} model
 * @returns {boolean}
 */
export function isLocalZeroCostModel(model = '') {
  const clean = String(model || '').trim();
  if (!clean) return false;
  if (Object.prototype.hasOwnProperty.call(FRONTIER_MODEL_PRICING_PER_1M, clean.toLowerCase())) {
    return false;
  }
  return LOCAL_MODEL_PATTERNS.some((re) => re.test(clean));
}

/**
 * Compute deterministic USD cost for a model call given prompt and completion token counts.
 * Local Ollama models always evaluate to $0.00.
 * @param {string} model
 * @param {number} promptTokens
 * @param {number} completionTokens
 * @returns {number}
 */
export function computeModelCostUsd(model = 'gemini-4-argon', promptTokens = 0, completionTokens = 0) {
  if (isLocalZeroCostModel(model)) return 0;
  const key = String(model || '').trim().toLowerCase();
  const rates = FRONTIER_MODEL_PRICING_PER_1M[key] || { inputUsd: 2.5, outputUsd: 10.0 };
  const inTokens = Math.max(0, Number(promptTokens) || 0);
  const outTokens = Math.max(0, Number(completionTokens) || 0);
  const raw = (inTokens / 1_000_000) * rates.inputUsd + (outTokens / 1_000_000) * rates.outputUsd;
  return Number(raw.toFixed(8));
}

/**
 * Compute Levenshtein edit distance across two ordered arrays of tool names.
 * @param {string[]} seqA
 * @param {string[]} seqB
 * @returns {number}
 */
export function levenshteinSequenceDistance(seqA = [], seqB = []) {
  const m = seqA.length;
  const n = seqB.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = seqA[i - 1] === seqB[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + cost
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/**
 * Compute a Slack `v0=<hex>` HMAC-SHA256 signature for HITL webhook verification.
 * @param {object} params
 * @param {string} params.signingSecret
 * @param {string|number} params.timestampHeader
 * @param {string} params.rawBody
 * @returns {string}
 */
export function computeSlackSignature({ signingSecret, timestampHeader, rawBody = '' } = {}) {
  const baseString = `v0:${String(timestampHeader)}:${String(rawBody)}`;
  const digest = crypto
    .createHmac('sha256', String(signingSecret))
    .update(baseString, 'utf8')
    .digest('hex');
  return `v0=${digest}`;
}

function tokenizeTerms(text = '') {
  return new Set(
    String(text || '')
      .toLowerCase()
      .split(/[^a-z0-9_]+/)
      .filter((w) => w.length >= 2)
  );
}

function lexicalOverlapScore(queryTerms, candidateText = '') {
  if (!queryTerms || queryTerms.size === 0) return 0;
  const candTerms = tokenizeTerms(candidateText);
  if (candTerms.size === 0) return 0;
  let hits = 0;
  for (const term of queryTerms) {
    if (candTerms.has(term)) hits += 1;
  }
  return hits / queryTerms.size;
}

function normalizeToolName(item) {
  if (typeof item === 'string') return item.trim();
  if (item && typeof item === 'object') {
    if (item.function && typeof item.function === 'object' && item.function.name) {
      return String(item.function.name).trim();
    }
    return String(item.tool || item.tool_name || item.toolName || item.name || item.action || '').trim();
  }
  return '';
}

function extractToolArgKeys(item) {
  if (!item || typeof item !== 'object') return [];
  const toolName = normalizeToolName(item) || 'tool';
  let rawArgs =
    item.arguments ??
    item.args ??
    (item.function && typeof item.function === 'object' ? item.function.arguments : undefined);
  if (typeof rawArgs === 'string') {
    try {
      rawArgs = JSON.parse(rawArgs);
    } catch {
      rawArgs = null;
    }
  }
  if (!rawArgs || typeof rawArgs !== 'object' || Array.isArray(rawArgs)) return [];
  return Object.keys(rawArgs).map((k) => `${toolName}:${k}`);
}

function normalizePrecedenceEdge(edge) {
  if (Array.isArray(edge) && edge.length >= 2) {
    return { from: String(edge[0] || '').trim(), to: String(edge[1] || '').trim() };
  }
  if (typeof edge === 'string' && edge.includes('->')) {
    const [lhs, rhs] = edge.split('->');
    return { from: String(lhs || '').trim(), to: String(rhs || '').trim() };
  }
  if (edge && typeof edge === 'object') {
    const from = String(edge.from || edge.before || edge.prerequisite || edge.source || '').trim();
    const to = String(edge.to || edge.after || edge.dependent || edge.target || '').trim();
    return { from, to };
  }
  return { from: '', to: '' };
}

function formatMessageForBudget(msg) {
  if (typeof msg === 'string') return msg;
  const role = msg?.role || 'user';
  const rawContent =
    typeof msg?.content === 'string' ? msg.content : JSON.stringify(msg?.content ?? '');
  return `${role}: ${rawContent}`;
}

function truncateMessageToBudget(msg, maxTokens) {
  const cap = Math.max(0, Math.floor(Number(maxTokens) || 0));
  if (cap <= 0) return null;
  if (typeof msg === 'string') {
    const truncated = truncateToTokenBudget(msg, cap);
    if (!truncated) return null;
    return { item: truncated, tokens: estimateTokenCount(truncated) };
  }
  const role = msg?.role || 'user';
  const prefix = `${role}: `;
  if (estimateTokenCount(prefix) > cap) {
    return null;
  }
  const rawContent =
    typeof msg?.content === 'string' ? msg.content : JSON.stringify(msg?.content ?? '');
  const maxContentBytes = Math.max(0, cap * 4 - Buffer.byteLength(prefix, 'utf8'));
  const buf = Buffer.from(rawContent, 'utf8');
  let sliceEnd = Math.min(buf.length, maxContentBytes);
  while (sliceEnd > 0 && (buf[sliceEnd] & 0xc0) === 0x80) {
    sliceEnd -= 1;
  }
  let candidateContent = buf.subarray(0, sliceEnd).toString('utf8');
  while (candidateContent.length > 0 && estimateTokenCount(`${prefix}${candidateContent}`) > cap) {
    candidateContent = candidateContent.slice(0, -1);
  }
  const cloned = { ...msg, content: candidateContent };
  const tokens = estimateTokenCount(formatMessageForBudget(cloned));
  if (tokens > cap) return null;
  return { item: cloned, tokens };
}

function resolveStepArgField(args, field) {
  if (!field) return args;
  if (!args || typeof args !== 'object') return undefined;
  if (Object.prototype.hasOwnProperty.call(args, field)) return args[field];
  if (typeof field === 'string' && field.includes('.')) {
    let cursor = args;
    for (const seg of field.split('.')) {
      if (cursor === null || cursor === undefined || typeof cursor !== 'object') return undefined;
      if (!Object.prototype.hasOwnProperty.call(cursor, seg)) return undefined;
      cursor = cursor[seg];
    }
    return cursor;
  }
  return undefined;
}

function argValueContainsPattern(actualValue, pattern) {
  if (actualValue === undefined || actualValue === null) return false;
  const needle = String(pattern);
  if (typeof actualValue === 'string') return actualValue.includes(needle);
  if (Array.isArray(actualValue)) {
    return actualValue.some(
      (item) =>
        isDeepStrictEqual(item, pattern) || (typeof item === 'string' && item.includes(needle))
    );
  }
  if (typeof actualValue === 'object') return JSON.stringify(actualValue).includes(needle);
  return String(actualValue).includes(needle);
}

/**
 * Create the KruschStack Resilience & Production Agentic Systems Engine.
 * @param {object} [options]
 * @param {import('node:sqlite').DatabaseSync|null} [options.db=null]
 */
export function createResilienceEngine({ db = null } = {}) {
  if (db && typeof db.exec === 'function') {
    db.exec(RESILIENCE_SCHEMA_SQL);
  }

  const costSessions = new Map();
  const memoryHitlGates = new Map();
  const memoryShadowRuns = [];
  const pendingShadows = new Set();

  function getOrCreateSession(sessionId = 'default') {
    const key = String(sessionId || 'default');
    let state = costSessions.get(key);
    if (!state) {
      state = {
        sessionId: key,
        cumulativeUsd: 0,
        loopDepth: 0,
        calls: 0,
        downgradedCalls: 0,
        pendingEvalStep: false
      };
      costSessions.set(key, state);
    }
    return state;
  }

  /**
   * 1. Strict 3-bucket (`system+query`, `tools`, `docs`) + `messages` history token allocator
   * guaranteeing `totalAllocatedTokens <= maxContextTokens - outputReserveTokens`.
   */
  function assembleContextBudget({
    systemPrompt = '',
    query = '',
    docs = [],
    tools = [],
    messages = [],
    maxContextTokens = 16384,
    outputReserveTokens = 2048
  } = {}) {
    const maxCtx = Math.floor(Number(maxContextTokens));
    const outReserve = Math.floor(Number(outputReserveTokens));

    if (
      !Number.isFinite(maxCtx) ||
      !Number.isFinite(outReserve) ||
      maxCtx <= 0 ||
      outReserve < 0 ||
      maxCtx <= outReserve
    ) {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_assemble_context_budget',
          'Invalid context budget: maxContextTokens must strictly exceed outputReserveTokens',
          {
            status: 'INVALID_BUDGET',
            maxContextTokens: maxCtx,
            outputReserveTokens: outReserve,
            availableTokens: Math.max(0, (maxCtx || 0) - (outReserve || 0)),
            totalAllocatedTokens: 0
          },
          false
        )
      );
    }

    const availableTokens = maxCtx - outReserve;
    const rawSystem = String(systemPrompt ?? '');
    const rawQuery = String(query ?? '');
    const queryTerms = tokenizeTerms(rawQuery);

    const hasAuxBuckets =
      (Array.isArray(docs) && docs.length > 0) ||
      (Array.isArray(tools) && tools.length > 0) ||
      (Array.isArray(messages) && messages.length > 0);

    // Core bucket (query + systemPrompt): reserve room for aux buckets when present,
    // while guaranteeing core never exceeds availableTokens.
    const coreSoftCap = hasAuxBuckets
      ? Math.max(1, Math.floor(availableTokens * 0.35))
      : availableTokens;

    const queryCap = Math.min(availableTokens, Math.max(coreSoftCap, Math.floor(availableTokens * 0.5)));
    const allocatedQuery = truncateToTokenBudget(rawQuery, queryCap);
    const queryTokens = estimateTokenCount(allocatedQuery);

    const systemCap = hasAuxBuckets
      ? Math.max(0, Math.min(availableTokens - queryTokens, Math.max(0, coreSoftCap - queryTokens)))
      : Math.max(0, availableTokens - queryTokens);
    let allocatedSystem = truncateToTokenBudget(rawSystem, systemCap);
    let systemTokens = estimateTokenCount(allocatedSystem);

    const remainingPool = Math.max(0, availableTokens - queryTokens - systemTokens);

    // Soft bucket quotas across the 3 auxiliary planes: Tools (25%), Docs (45%), History (30%)
    const toolSoftCap = Math.floor(remainingPool * 0.25);
    const docSoftCap = Math.floor(remainingPool * 0.45);
    const historySoftCap = Math.max(0, remainingPool - toolSoftCap - docSoftCap);

    // Prepare Tools sorted by pinned -> explicit score/relevance -> query lexical overlap -> index.
    // Measure the FULL serialized representation of `tool` so OpenAI `{ type: 'function', function: {...} }`,
    // `{ schema }`, `{ schema_def }`, and `{ inputSchema }` envelopes match returned `selectedTools` byte-for-byte.
    const indexedTools = (Array.isArray(tools) ? tools : []).map((tool, index) => {
      const serialized = typeof tool === 'string' ? tool : JSON.stringify(tool ?? {});
      const tokens = estimateTokenCount(serialized);
      const pinned = Boolean(tool && typeof tool === 'object' && tool.pinned === true);
      const explicitScore =
        tool && typeof tool === 'object' && Number.isFinite(Number(tool.score ?? tool.relevance))
          ? Number(tool.score ?? tool.relevance)
          : lexicalOverlapScore(queryTerms, serialized);
      return { item: tool, index, tokens, pinned, score: explicitScore };
    });

    indexedTools.sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      if (b.score !== a.score) return b.score - a.score;
      return a.index - b.index;
    });

    // Prepare Docs sorted by pinned -> salience/score -> query lexical overlap -> index
    const indexedDocs = (Array.isArray(docs) ? docs : []).map((doc, index) => {
      const text =
        typeof doc === 'string'
          ? doc
          : String(doc?.content ?? doc?.text ?? JSON.stringify(doc ?? ''));
      const tokens = estimateTokenCount(text);
      const pinned = Boolean(doc && typeof doc === 'object' && doc.pinned === true);
      const salience =
        doc && typeof doc === 'object' && Number.isFinite(Number(doc.salience ?? doc.score))
          ? Number(doc.salience ?? doc.score)
          : lexicalOverlapScore(queryTerms, text);
      return { item: doc, index, tokens, pinned, score: salience };
    });

    indexedDocs.sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      if (b.score !== a.score) return b.score - a.score;
      return a.index - b.index;
    });

    // Prepare Messages prioritized by pinned -> most recent first (preserving chronological output)
    const indexedMessages = (Array.isArray(messages) ? messages : []).map((msg, index) => {
      const text = formatMessageForBudget(msg);
      const tokens = estimateTokenCount(text);
      const pinned = Boolean(msg && typeof msg === 'object' && msg.pinned === true);
      return { item: msg, index, tokens, pinned };
    });

    // When `query` is omitted/empty, identify the latest user turn so the active objective is never dropped
    let latestUserEntry = null;
    if (rawQuery.trim().length === 0 && indexedMessages.length > 0) {
      for (let i = indexedMessages.length - 1; i >= 0; i--) {
        const candidate = indexedMessages[i];
        const role =
          typeof candidate.item === 'string'
            ? 'user'
            : String(candidate.item?.role || 'user').toLowerCase();
        if (role === 'user') {
          latestUserEntry = candidate;
          break;
        }
      }
      if (!latestUserEntry) {
        latestUserEntry = indexedMessages[indexedMessages.length - 1];
      }
    }

    const recencyOrderedMessages = [...indexedMessages].sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return b.index - a.index;
    });

    const chosenTools = new Set();
    const chosenDocs = new Set();
    const chosenMessages = new Set();

    let toolTokens = 0;
    let docTokens = 0;
    let messageTokens = 0;

    // Pass 1: Allocate within isolated per-bucket soft caps
    for (const entry of indexedTools) {
      if (toolTokens + entry.tokens <= toolSoftCap) {
        chosenTools.add(entry.index);
        toolTokens += entry.tokens;
      }
    }
    for (const entry of indexedDocs) {
      if (docTokens + entry.tokens <= docSoftCap) {
        chosenDocs.add(entry.index);
        docTokens += entry.tokens;
      }
    }

    const olderHistorySoftCap =
      latestUserEntry && latestUserEntry.tokens > historySoftCap
        ? Math.floor(historySoftCap * 0.4)
        : historySoftCap;

    for (const entry of recencyOrderedMessages) {
      const effectiveCap =
        latestUserEntry && entry.index !== latestUserEntry.index && !entry.pinned
          ? olderHistorySoftCap
          : historySoftCap;
      if (messageTokens + entry.tokens <= effectiveCap) {
        chosenMessages.add(entry.index);
        messageTokens += entry.tokens;
      }
    }

    // Reserve unused history quota for the oversized latest user objective before docs/tools consume spillover
    const objectiveReserve =
      latestUserEntry && !chosenMessages.has(latestUserEntry.index)
        ? Math.max(0, historySoftCap - messageTokens)
        : 0;

    // Pass 2: Work-conserving spillover of unused tokens without exceeding availableTokens
    let spareTokens =
      availableTokens -
      (queryTokens + systemTokens + toolTokens + docTokens + messageTokens + objectiveReserve);

    if (spareTokens > 0 && allocatedSystem.length < rawSystem.length) {
      const expandedSystem = truncateToTokenBudget(rawSystem, systemTokens + spareTokens);
      const expandedSysTokens = estimateTokenCount(expandedSystem);
      spareTokens -= expandedSysTokens - systemTokens;
      allocatedSystem = expandedSystem;
      systemTokens = expandedSysTokens;
    }

    for (const entry of indexedDocs) {
      if (!chosenDocs.has(entry.index) && entry.tokens <= spareTokens) {
        chosenDocs.add(entry.index);
        docTokens += entry.tokens;
        spareTokens -= entry.tokens;
      }
    }
    for (const entry of indexedTools) {
      if (!chosenTools.has(entry.index) && entry.tokens <= spareTokens) {
        chosenTools.add(entry.index);
        toolTokens += entry.tokens;
        spareTokens -= entry.tokens;
      }
    }

    spareTokens += objectiveReserve;

    if (latestUserEntry && !chosenMessages.has(latestUserEntry.index) && spareTokens > 0) {
      if (latestUserEntry.tokens <= spareTokens) {
        chosenMessages.add(latestUserEntry.index);
        messageTokens += latestUserEntry.tokens;
        spareTokens -= latestUserEntry.tokens;
      } else {
        const truncatedObj = truncateMessageToBudget(latestUserEntry.item, spareTokens);
        if (truncatedObj) {
          indexedMessages[latestUserEntry.index] = {
            ...latestUserEntry,
            item: truncatedObj.item,
            tokens: truncatedObj.tokens
          };
          chosenMessages.add(latestUserEntry.index);
          messageTokens += truncatedObj.tokens;
          spareTokens -= truncatedObj.tokens;
        }
      }
    }

    for (const entry of recencyOrderedMessages) {
      if (!chosenMessages.has(entry.index) && entry.tokens <= spareTokens) {
        chosenMessages.add(entry.index);
        messageTokens += entry.tokens;
        spareTokens -= entry.tokens;
      }
    }

    const selectedTools = indexedTools
      .filter((e) => chosenTools.has(e.index))
      .map((e) => e.item);
    const evictedTools = indexedTools
      .filter((e) => !chosenTools.has(e.index))
      .map((e) => e.item);

    const selectedDocs = indexedDocs
      .filter((e) => chosenDocs.has(e.index))
      .map((e) => e.item);
    const evictedDocs = indexedDocs
      .filter((e) => !chosenDocs.has(e.index))
      .map((e) => e.item);

    const selectedMessages = indexedMessages
      .filter((e) => chosenMessages.has(e.index))
      .map((e) => e.item);
    const evictedMessages = indexedMessages
      .filter((e) => !chosenMessages.has(e.index))
      .map((e) => e.item);

    const totalAllocatedTokens =
      systemTokens + queryTokens + toolTokens + docTokens + messageTokens;

    return attachStatusAccessor(
      okEnvelope(
        'krusch_assemble_context_budget',
        `Allocated ${totalAllocatedTokens}/${availableTokens} tokens (reserve ${outReserve}); evicted ${evictedDocs.length} doc(s), ${evictedTools.length} tool(s), ${evictedMessages.length} message(s)`,
        {
          status: 'ALLOCATED',
          maxContextTokens: maxCtx,
          outputReserveTokens: outReserve,
          availableTokens,
          totalAllocatedTokens,
          remainingTokens: availableTokens - totalAllocatedTokens,
          withinBudget: totalAllocatedTokens <= availableTokens,
          buckets: {
            system: systemTokens,
            query: queryTokens,
            tools: toolTokens,
            docs: docTokens,
            messages: messageTokens
          },
          systemPrompt: allocatedSystem,
          query: allocatedQuery,
          selectedTools,
          evictedTools,
          selectedDocs,
          evictedDocs,
          selectedMessages,
          evictedMessages,
          ledger: {
            max_context_tokens: maxCtx,
            output_reserve_tokens: outReserve,
            available_tokens: availableTokens,
            total_allocated_tokens: totalAllocatedTokens,
            evicted_counts: {
              tools: evictedTools.length,
              docs: evictedDocs.length,
              messages: evictedMessages.length
            }
          }
        },
        true
      )
    );
  }

  /**
   * 2A. Record actual token spend & loop depth for a session.
   */
  function recordCostUsage({
    sessionId = 'default',
    model = 'gemini-4-argon',
    promptTokens = 0,
    completionTokens = 0,
    costUsd
  } = {}) {
    const session = getOrCreateSession(sessionId);
    const resolvedCost =
      typeof costUsd === 'number' && Number.isFinite(costUsd) && costUsd >= 0
        ? Number(costUsd.toFixed(8))
        : computeModelCostUsd(model, promptTokens, completionTokens);

    session.cumulativeUsd = Number((session.cumulativeUsd + resolvedCost).toFixed(8));
    session.calls += 1;
    if (session.pendingEvalStep) {
      session.pendingEvalStep = false;
    } else {
      session.loopDepth += 1;
    }

    return attachStatusAccessor(
      okEnvelope(
        'krusch_record_cost_usage',
        `Recorded $${resolvedCost.toFixed(6)} for ${model} (session ${session.sessionId} cumulative $${session.cumulativeUsd.toFixed(6)}, depth ${session.loopDepth})`,
        {
          status: 'RECORDED',
          sessionId: session.sessionId,
          model: String(model || ''),
          promptTokens: Math.max(0, Number(promptTokens) || 0),
          completionTokens: Math.max(0, Number(completionTokens) || 0),
          callCostUsd: resolvedCost,
          cumulativeUsd: session.cumulativeUsd,
          loopDepth: session.loopDepth,
          calls: session.calls
        },
        true
      )
    );
  }

  /**
   * 2B. Evaluate $0.50 cost kill-switch and max loop-depth circuit breaker.
   * Downgrades paid frontier calls to $0.00 local Ollama (`qwen2.5-coder:7b`) before $0.50 overflow,
   * and halts (`ok: false, status: 'HALTED_BUDGET_EXCEEDED'`) at `>= $0.50` or `> maxLoopDepth`.
   */
  function evaluateCostKillSwitch({
    sessionId = 'default',
    model = 'gemini-4-argon',
    promptTokens = 1000,
    projectedCompletionTokens = 2048,
    hardLimitUsd = 0.5,
    maxLoopDepth = 12,
    fallbackModel = 'qwen2.5-coder:7b'
  } = {}) {
    const session = getOrCreateSession(sessionId);
    const limitUsd = Number(hardLimitUsd);
    const maxDepth = Math.floor(Number(maxLoopDepth));

    session.loopDepth += 1;
    session.pendingEvalStep = true;

    const requestedModel = String(model || 'gemini-4-argon');
    const rawProjectedCostUsd = computeModelCostUsd(
      requestedModel,
      promptTokens,
      projectedCompletionTokens
    );

    if (session.cumulativeUsd >= limitUsd) {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_cost_kill_switch',
          `Kill-switch tripped for session '${session.sessionId}': cumulative spend $${session.cumulativeUsd.toFixed(4)} >= $${limitUsd.toFixed(2)} hard limit`,
          {
            status: 'HALTED_BUDGET_EXCEEDED',
            reason: 'HARD_COST_LIMIT_REACHED',
            sessionId: session.sessionId,
            requestedModel,
            selectedModel: null,
            downgraded: false,
            cumulativeUsd: session.cumulativeUsd,
            projectedCallCostUsd: rawProjectedCostUsd,
            projectedTotalUsd: Number((session.cumulativeUsd + rawProjectedCostUsd).toFixed(8)),
            hardLimitUsd: limitUsd,
            loopDepth: session.loopDepth,
            maxLoopDepth: maxDepth
          },
          false
        )
      );
    }

    if (session.loopDepth > maxDepth) {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_cost_kill_switch',
          `Kill-switch tripped for session '${session.sessionId}': loop depth ${session.loopDepth} exceeds maxLoopDepth ${maxDepth}`,
          {
            status: 'HALTED_BUDGET_EXCEEDED',
            reason: 'MAX_LOOP_DEPTH_EXCEEDED',
            sessionId: session.sessionId,
            requestedModel,
            selectedModel: null,
            downgraded: false,
            cumulativeUsd: session.cumulativeUsd,
            projectedCallCostUsd: rawProjectedCostUsd,
            projectedTotalUsd: Number((session.cumulativeUsd + rawProjectedCostUsd).toFixed(8)),
            hardLimitUsd: limitUsd,
            loopDepth: session.loopDepth,
            maxLoopDepth: maxDepth
          },
          false
        )
      );
    }

    const projectedTotalUsd = Number((session.cumulativeUsd + rawProjectedCostUsd).toFixed(8));

    if (projectedTotalUsd >= limitUsd && rawProjectedCostUsd > 0) {
      const cleanFallback = String(fallbackModel || '').trim();
      if (cleanFallback && isLocalZeroCostModel(cleanFallback)) {
        session.downgradedCalls += 1;
        return attachStatusAccessor(
          okEnvelope(
            'krusch_cost_kill_switch',
            `Projected spend $${projectedTotalUsd.toFixed(4)} would breach $${limitUsd.toFixed(2)} limit; downgraded ${requestedModel} to $0.00 local ${cleanFallback}`,
            {
              status: 'DOWNGRADED_LOCAL_FALLBACK',
              reason: 'PROJECTED_BUDGET_OVERFLOW_DOWNGRADE',
              sessionId: session.sessionId,
              requestedModel,
              selectedModel: cleanFallback,
              effectiveModel: cleanFallback,
              downgraded: true,
              cumulativeUsd: session.cumulativeUsd,
              projectedCallCostUsd: 0,
              avoidedCostUsd: rawProjectedCostUsd,
              projectedTotalUsd: session.cumulativeUsd,
              hardLimitUsd: limitUsd,
              loopDepth: session.loopDepth,
              maxLoopDepth: maxDepth
            },
            true
          )
        );
      }

      return attachStatusAccessor(
        okEnvelope(
          'krusch_cost_kill_switch',
          `Kill-switch tripped for session '${session.sessionId}': projected spend $${projectedTotalUsd.toFixed(4)} >= $${limitUsd.toFixed(2)} with no zero-cost local fallback`,
          {
            status: 'HALTED_BUDGET_EXCEEDED',
            reason: 'PROJECTED_BUDGET_EXCEEDED_NO_FALLBACK',
            sessionId: session.sessionId,
            requestedModel,
            selectedModel: null,
            downgraded: false,
            cumulativeUsd: session.cumulativeUsd,
            projectedCallCostUsd: rawProjectedCostUsd,
            projectedTotalUsd,
            hardLimitUsd: limitUsd,
            loopDepth: session.loopDepth,
            maxLoopDepth: maxDepth
          },
          false
        )
      );
    }

    return attachStatusAccessor(
      okEnvelope(
        'krusch_cost_kill_switch',
        `Allowed ${requestedModel} at step ${session.loopDepth}/${maxDepth} (projected total $${projectedTotalUsd.toFixed(4)} / $${limitUsd.toFixed(2)})`,
        {
          status: 'ALLOWED',
          reason: 'WITHIN_BUDGET',
          sessionId: session.sessionId,
          requestedModel,
          selectedModel: requestedModel,
          effectiveModel: requestedModel,
          downgraded: false,
          cumulativeUsd: session.cumulativeUsd,
          projectedCallCostUsd: rawProjectedCostUsd,
          projectedTotalUsd,
          hardLimitUsd: limitUsd,
          loopDepth: session.loopDepth,
          maxLoopDepth: maxDepth
        },
        true
      )
    );
  }

  /**
   * 3. Verify an executed agent tool trajectory against a declarative Golden DAG specification.
   * Checks `requiredTools`, `forbiddenTools`, `precedenceEdges`, `requirePassingPrerequisite`
   * (both edge-pair arrays `[[prereq, target], ...]` and boolean `true`), `argGuards`, and `maxSteps`.
   */
  function verifyTrajectoryDag({ steps = [], goldenDag = {} } = {}) {
    const normalizedSteps = (Array.isArray(steps) ? steps : []).map((step, index) => {
      if (typeof step === 'string') {
        return { index, tool: step.trim(), passed: true, args: {} };
      }
      const tool = normalizeToolName(step);
      let passed = true;
      if (typeof step?.passed === 'boolean') {
        passed = step.passed;
      } else if (typeof step?.ok === 'boolean') {
        passed = step.ok;
      } else if (typeof step?.success === 'boolean') {
        passed = step.success;
      } else if (typeof step?.status === 'string') {
        passed = !/^(fail|failed|error|blocked|halted|rejected|aborted)$/i.test(step.status.trim());
      } else if (step?.error) {
        passed = false;
      }
      let args = {};
      if (step && typeof step === 'object') {
        const rawArgs = step.args ?? step.arguments ?? step.function?.arguments;
        if (typeof rawArgs === 'string') {
          try {
            const parsed = JSON.parse(rawArgs);
            if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) args = parsed;
          } catch {
            args = {};
          }
        } else if (rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs)) {
          args = rawArgs;
        }
      }
      return { index, tool, passed, args };
    });

    const requiredTools = (
      goldenDag?.requiredTools ??
      goldenDag?.required_tools ??
      []
    ).map((t) => String(t).trim()).filter(Boolean);

    const forbiddenTools = (
      goldenDag?.forbiddenTools ??
      goldenDag?.forbidden_tools ??
      []
    ).map((t) => String(t).trim()).filter(Boolean);

    const rawEdges = goldenDag?.precedenceEdges ?? goldenDag?.precedence_edges ?? [];
    const precedenceEdges = (Array.isArray(rawEdges) ? rawEdges : [])
      .map(normalizePrecedenceEdge)
      .filter((e) => e.from && e.to);

    const rawPassingPrereq =
      goldenDag?.requirePassingPrerequisite ?? goldenDag?.require_passing_prerequisite ?? false;
    const globalRequirePassing = rawPassingPrereq === true;
    const passingPrereqEdges = Array.isArray(rawPassingPrereq)
      ? rawPassingPrereq.map(normalizePrecedenceEdge).filter((e) => e.from && e.to)
      : [];

    const rawArgGuards = goldenDag?.argGuards ?? goldenDag?.arg_guards ?? [];
    const argGuards = Array.isArray(rawArgGuards) ? rawArgGuards : [];

    const rawMaxSteps = goldenDag?.maxSteps ?? goldenDag?.max_steps;
    const maxSteps =
      rawMaxSteps !== undefined && rawMaxSteps !== null && Number.isFinite(Number(rawMaxSteps))
        ? Number(rawMaxSteps)
        : null;

    const violations = [];
    const forbiddenSet = new Set(forbiddenTools);

    for (const step of normalizedSteps) {
      if (forbiddenSet.has(step.tool)) {
        violations.push({
          type: 'FORBIDDEN_TOOL_INVOKED',
          tool: step.tool,
          stepIndex: step.index,
          message: `Forbidden tool '${step.tool}' invoked at step ${step.index}`
        });
      }
    }

    for (const reqTool of requiredTools) {
      const matching = normalizedSteps.filter((s) => s.tool === reqTool);
      if (matching.length === 0) {
        violations.push({
          type: 'MISSING_REQUIRED_TOOL',
          tool: reqTool,
          message: `Required tool '${reqTool}' was never invoked in trajectory`
        });
      } else if (globalRequirePassing && !matching.some((s) => s.passed)) {
        violations.push({
          type: 'FAILED_REQUIRED_TOOL',
          tool: reqTool,
          message: `Required tool '${reqTool}' was invoked but never succeeded`
        });
      }
    }

    for (const edge of precedenceEdges) {
      for (const targetStep of normalizedSteps) {
        if (targetStep.tool !== edge.to) continue;
        const priorPrereqs = normalizedSteps.filter(
          (s) => s.index < targetStep.index && s.tool === edge.from
        );
        if (priorPrereqs.length === 0) {
          violations.push({
            type: 'PRECEDENCE_VIOLATION',
            from: edge.from,
            to: edge.to,
            stepIndex: targetStep.index,
            message: `Tool '${edge.to}' at step ${targetStep.index} executed before prerequisite '${edge.from}'`
          });
        } else if (globalRequirePassing && !priorPrereqs.some((s) => s.passed)) {
          violations.push({
            type: 'FAILED_PREREQUISITE',
            from: edge.from,
            to: edge.to,
            stepIndex: targetStep.index,
            message: `Tool '${edge.to}' at step ${targetStep.index} executed without a prior passing '${edge.from}' step`
          });
        }
      }
    }

    for (const edge of passingPrereqEdges) {
      for (const targetStep of normalizedSteps) {
        if (targetStep.tool !== edge.to) continue;
        const priorPrereqs = normalizedSteps.filter(
          (s) => s.index < targetStep.index && s.tool === edge.from
        );
        if (!priorPrereqs.some((s) => s.passed)) {
          violations.push({
            type: 'FAILED_PREREQUISITE',
            from: edge.from,
            to: edge.to,
            stepIndex: targetStep.index,
            message: `Tool '${edge.to}' at step ${targetStep.index} executed without a prior passing '${edge.from}' step`
          });
        }
      }
    }

    for (const guard of argGuards) {
      if (!guard || typeof guard !== 'object' || typeof guard.tool !== 'string') continue;
      for (const step of normalizedSteps) {
        if (guard.tool !== '*' && step.tool !== guard.tool) continue;
        const actualValue = resolveStepArgField(step.args, guard.field);
        const fieldLabel = guard.field || '*';

        if (Object.prototype.hasOwnProperty.call(guard, 'equals') && guard.equals !== undefined) {
          if (!isDeepStrictEqual(actualValue, guard.equals)) {
            violations.push({
              type: 'ARG_GUARD_VIOLATION',
              constraint: 'equals',
              tool: step.tool,
              field: fieldLabel,
              stepIndex: step.index,
              message: `Arg guard 'equals' failed on '${step.tool}.${fieldLabel}' at step ${step.index}`
            });
          }
        }
        if (guard.mustContain !== undefined) {
          const patterns = Array.isArray(guard.mustContain) ? guard.mustContain : [guard.mustContain];
          for (const pat of patterns) {
            if (!argValueContainsPattern(actualValue, pat)) {
              violations.push({
                type: 'ARG_GUARD_VIOLATION',
                constraint: 'mustContain',
                tool: step.tool,
                field: fieldLabel,
                stepIndex: step.index,
                message: `Arg guard 'mustContain' failed on '${step.tool}.${fieldLabel}' at step ${step.index}`
              });
            }
          }
        }
        if (guard.mustNotContain !== undefined) {
          const patterns = Array.isArray(guard.mustNotContain)
            ? guard.mustNotContain
            : [guard.mustNotContain];
          for (const pat of patterns) {
            if (argValueContainsPattern(actualValue, pat)) {
              violations.push({
                type: 'ARG_GUARD_VIOLATION',
                constraint: 'mustNotContain',
                tool: step.tool,
                field: fieldLabel,
                stepIndex: step.index,
                message: `Arg guard 'mustNotContain' failed on '${step.tool}.${fieldLabel}' at step ${step.index}`
              });
            }
          }
        }
      }
    }

    if (maxSteps !== null && normalizedSteps.length > maxSteps) {
      violations.push({
        type: 'MAX_STEPS_EXCEEDED',
        maxSteps,
        actualSteps: normalizedSteps.length,
        message: `Trajectory length ${normalizedSteps.length} exceeded maxSteps ${maxSteps}`
      });
    }

    const passed = violations.length === 0;
    return attachStatusAccessor(
      okEnvelope(
        'krusch_verify_trajectory_dag',
        passed
          ? `Trajectory DAG verified across ${normalizedSteps.length} step(s) with 0 violations`
          : `Trajectory DAG failed with ${violations.length} violation(s)`,
        {
          status: passed ? 'PASSED' : 'DAG_INVARIANT_VIOLATION',
          passed,
          valid: passed,
          stepCount: normalizedSteps.length,
          observedTools: normalizedSteps.map((s) => s.tool),
          violations,
          checked: {
            requiredTools,
            forbiddenTools,
            precedenceEdges,
            requirePassingPrerequisite: globalRequirePassing ? true : passingPrereqEdges,
            argGuardsCount: argGuards.length,
            maxSteps
          }
        },
        passed
      )
    );
  }

  /**
   * 4. Compute Levenshtein sequence similarity + exact DAG match between primary and shadow
   * trajectories, persisting telemetry into `stack_shadow_runs` (or in-memory list when `db` is null).
   */
  function recordShadowComparison({
    requestId,
    primaryModel,
    shadowModel,
    primaryTools = [],
    shadowTools = [],
    primaryLatencyMs = 0,
    shadowLatencyMs = 0,
    primaryCostUsd = 0,
    shadowCostUsd = 0
  } = {}) {
    const comparisonId = `shd_${crypto.randomUUID().replace(/-/g, '')}`;
    const resolvedRequestId = String(requestId || comparisonId).trim();
    const resolvedPrimaryModel = String(primaryModel || 'primary-unspecified').trim();
    const resolvedShadowModel = String(shadowModel || 'shadow-unspecified').trim();

    const primarySeq = (Array.isArray(primaryTools) ? primaryTools : [])
      .map(normalizeToolName)
      .filter(Boolean);
    const shadowSeq = (Array.isArray(shadowTools) ? shadowTools : [])
      .map(normalizeToolName)
      .filter(Boolean);

    const editDistance = levenshteinSequenceDistance(primarySeq, shadowSeq);
    const maxLen = Math.max(primarySeq.length, shadowSeq.length);
    const sequenceSimilarity =
      maxLen === 0 ? 1.0 : Number((1 - editDistance / maxLen).toFixed(4));

    const exactDagMatchBool =
      primarySeq.length === shadowSeq.length &&
      primarySeq.every((tool, idx) => tool === shadowSeq[idx]);
    const exactDagMatchInt = exactDagMatchBool ? 1 : 0;

    const primarySet = new Set(primarySeq);
    const shadowSet = new Set(shadowSeq);
    let setIntersection = 0;
    for (const tool of primarySet) {
      if (shadowSet.has(tool)) setIntersection += 1;
    }
    const setUnion = primarySet.size + shadowSet.size - setIntersection;
    const jaccardSimilarity =
      setUnion === 0 ? 1.0 : Number((setIntersection / setUnion).toFixed(4));

    const primaryArgSet = new Set(
      (Array.isArray(primaryTools) ? primaryTools : []).flatMap(extractToolArgKeys)
    );
    const shadowArgSet = new Set(
      (Array.isArray(shadowTools) ? shadowTools : []).flatMap(extractToolArgKeys)
    );
    let argIntersection = 0;
    for (const key of primaryArgSet) {
      if (shadowArgSet.has(key)) argIntersection += 1;
    }
    const argUnion = primaryArgSet.size + shadowArgSet.size - argIntersection;
    const argKeyJaccard =
      argUnion === 0 ? jaccardSimilarity : Number((argIntersection / argUnion).toFixed(4));

    const latencyDeltaMs = Number(
      ((Number(shadowLatencyMs) || 0) - (Number(primaryLatencyMs) || 0)).toFixed(3)
    );
    const costDeltaUsd = Number(
      ((Number(shadowCostUsd) || 0) - (Number(primaryCostUsd) || 0)).toFixed(6)
    );
    const createdAtMs = Date.now();

    const rowRecord = {
      comparison_id: comparisonId,
      request_id: resolvedRequestId,
      primary_model: resolvedPrimaryModel,
      shadow_model: resolvedShadowModel,
      sequence_similarity: sequenceSimilarity,
      exact_dag_match: exactDagMatchInt,
      latency_delta_ms: latencyDeltaMs,
      cost_delta_usd: costDeltaUsd,
      created_at_ms: createdAtMs
    };

    if (db && typeof db.prepare === 'function') {
      db.prepare(
        `INSERT INTO stack_shadow_runs (
          comparison_id, request_id, primary_model, shadow_model,
          sequence_similarity, exact_dag_match, latency_delta_ms, cost_delta_usd, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        rowRecord.comparison_id,
        rowRecord.request_id,
        rowRecord.primary_model,
        rowRecord.shadow_model,
        rowRecord.sequence_similarity,
        rowRecord.exact_dag_match,
        rowRecord.latency_delta_ms,
        rowRecord.cost_delta_usd,
        rowRecord.created_at_ms
      );
    } else {
      memoryShadowRuns.push(rowRecord);
    }

    return attachStatusAccessor(
      okEnvelope(
        'krusch_record_shadow_comparison',
        `Shadow comparison ${comparisonId}: similarity=${sequenceSimilarity}, argKeyJaccard=${argKeyJaccard}, exactDagMatch=${exactDagMatchBool}, costDelta=$${costDeltaUsd.toFixed(6)}`,
        {
          status: 'RECORDED',
          comparisonId,
          comparison_id: comparisonId,
          requestId: resolvedRequestId,
          primaryModel: resolvedPrimaryModel,
          shadowModel: resolvedShadowModel,
          primaryTools: primarySeq,
          shadowTools: shadowSeq,
          editDistance,
          sequenceSimilarity,
          sequence_similarity: sequenceSimilarity,
          jaccardSimilarity,
          argKeyJaccard,
          arg_key_jaccard: argKeyJaccard,
          exactDagMatch: exactDagMatchBool,
          exact_dag_match: exactDagMatchInt,
          primaryLatencyMs: Number(primaryLatencyMs) || 0,
          shadowLatencyMs: Number(shadowLatencyMs) || 0,
          latencyDeltaMs,
          latency_delta_ms: latencyDeltaMs,
          primaryCostUsd: Number(primaryCostUsd) || 0,
          shadowCostUsd: Number(shadowCostUsd) || 0,
          costDeltaUsd,
          cost_delta_usd: costDeltaUsd,
          persistedTo: db ? 'sqlite' : 'memory',
          createdAtMs
        },
        true
      )
    );
  }

  /**
   * 4B. Non-blocking configurable 5% shadow traffic sampler & background runner (`INV-SHADOW-01`).
   * Deterministically hashes `requestId` into `[0, 1)` and dispatches `shadowRunner` in the background
   * with `0 ms` blocking on the primary request path.
   */
  function scheduleShadowComparison({
    requestId,
    sampleRate = 0.05,
    force = false,
    primaryModel,
    shadowModel,
    primaryTools = [],
    primaryLatencyMs = 0,
    primaryCostUsd = 0,
    shadowRunner
  } = {}) {
    const resolvedReqId = String(requestId || `req_${crypto.randomUUID().replace(/-/g, '')}`).trim();
    const rate = Math.max(0, Math.min(1, Number(sampleRate ?? 0.05)));
    const digestHex = crypto.createHash('sha256').update(resolvedReqId, 'utf8').digest('hex').slice(0, 8);
    const bucket = parseInt(digestHex, 16) / 0x100000000;
    const sampled = Boolean(force) || (rate > 0 && bucket < rate);

    if (!sampled || typeof shadowRunner !== 'function') {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_schedule_shadow_comparison',
          sampled
            ? `Shadow request ${resolvedReqId} sampled, but no shadowRunner function was supplied`
            : `Shadow request ${resolvedReqId} skipped by deterministic ${(rate * 100).toFixed(1)}% sampling`,
          {
            status: 'SKIPPED_SAMPLE',
            sampled: false,
            sampleRate: rate,
            bucket: Number(bucket.toFixed(6)),
            requestId: resolvedReqId
          },
          true
        )
      );
    }

    const bgPromise = Promise.resolve()
      .then(async () => {
        const t0 = performance.now();
        const candidate = (await shadowRunner()) || {};
        const measuredMs = Number((performance.now() - t0).toFixed(3));
        return recordShadowComparison({
          requestId: resolvedReqId,
          primaryModel,
          shadowModel,
          primaryTools,
          shadowTools: candidate.tools ?? candidate.toolCalls ?? candidate.tool_calls ?? [],
          primaryLatencyMs,
          shadowLatencyMs: candidate.latencyMs ?? candidate.latency_ms ?? measuredMs,
          primaryCostUsd,
          shadowCostUsd: candidate.costUsd ?? candidate.cost_usd ?? 0
        });
      })
      .catch(() => null);

    pendingShadows.add(bgPromise);
    bgPromise.finally(() => pendingShadows.delete(bgPromise));

    return attachStatusAccessor(
      okEnvelope(
        'krusch_schedule_shadow_comparison',
        `Scheduled non-blocking background shadow run for ${resolvedReqId} (rate=${(rate * 100).toFixed(1)}%)`,
        {
          status: 'SCHEDULED',
          sampled: true,
          sampleRate: rate,
          bucket: Number(bucket.toFixed(6)),
          requestId: resolvedReqId,
          pendingCount: pendingShadows.size
        },
        true
      )
    );
  }

  async function flushPendingShadows() {
    const active = [...pendingShadows];
    await Promise.allSettled(active);
    return okEnvelope(
      'krusch_flush_shadows',
      `Flushed ${active.length} background shadow comparison(s)`,
      { flushedCount: active.length, remainingCount: pendingShadows.size },
      true
    );
  }

  /**
   * 5A. Draft a 72-hour asynchronous Human-in-the-Loop (HITL) approval lease in `stack_hitl_gates`.
   */
  function draftHitlGate({
    taskId,
    actionType,
    summary,
    stagedPayload = {},
    ttlMs = 72 * 60 * 60 * 1000,
    nowMs = Date.now()
  } = {}) {
    const cleanTaskId = String(taskId || '').trim();
    const cleanActionType = String(actionType || '').trim();
    if (!cleanTaskId || !cleanActionType) {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_draft_hitl_gate',
          'taskId and actionType are required to draft a HITL gate',
          {
            status: 'INVALID_GATE_REQUEST',
            error: 'MISSING_REQUIRED_FIELDS'
          },
          false
        )
      );
    }

    const leaseTtlMs = Math.floor(Number(ttlMs));
    if (!Number.isFinite(leaseTtlMs) || leaseTtlMs <= 0) {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_draft_hitl_gate',
          'ttlMs must be a positive duration in milliseconds',
          {
            status: 'INVALID_GATE_REQUEST',
            error: 'INVALID_TTL_MS'
          },
          false
        )
      );
    }

    const cleanSummary =
      String(summary || '').trim() ||
      `HITL approval required for ${cleanActionType} on task ${cleanTaskId}`;
    const gateId = `hitl_${crypto.randomUUID().replace(/-/g, '')}`;
    const createdAtMs = Math.floor(Number(nowMs));
    const expiresAtMs = createdAtMs + leaseTtlMs;
    const payloadStr =
      typeof stagedPayload === 'string' ? stagedPayload : JSON.stringify(stagedPayload ?? {});

    const record = {
      gate_id: gateId,
      task_id: cleanTaskId,
      action_type: cleanActionType,
      summary: cleanSummary,
      staged_payload: payloadStr,
      status: 'PENDING_APPROVAL',
      created_at_ms: createdAtMs,
      expires_at_ms: expiresAtMs,
      decided_at_ms: null,
      reviewer: null,
      decision_reason: null
    };

    if (db && typeof db.prepare === 'function') {
      db.prepare(
        `INSERT INTO stack_hitl_gates (
          gate_id, task_id, action_type, summary, staged_payload,
          status, created_at_ms, expires_at_ms, decided_at_ms, reviewer, decision_reason
        ) VALUES (?, ?, ?, ?, ?, 'PENDING_APPROVAL', ?, ?, NULL, NULL, NULL)`
      ).run(
        record.gate_id,
        record.task_id,
        record.action_type,
        record.summary,
        record.staged_payload,
        record.created_at_ms,
        record.expires_at_ms
      );
    } else {
      memoryHitlGates.set(gateId, record);
    }

    const slackBlocks = [
      {
        type: 'header',
        text: { type: 'plain_text', text: `HITL Gate: ${cleanActionType}` }
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Task:* \`${cleanTaskId}\`\n*Gate:* \`${gateId}\`\n*Summary:* ${cleanSummary}`
        }
      },
      {
        type: 'actions',
        elements: [
          {
            type: 'button',
            action_id: 'hitl_approve',
            style: 'primary',
            text: { type: 'plain_text', text: 'Approve' },
            value: gateId
          },
          {
            type: 'button',
            action_id: 'hitl_reject',
            style: 'danger',
            text: { type: 'plain_text', text: 'Reject' },
            value: gateId
          }
        ]
      }
    ];

    return attachStatusAccessor(
      okEnvelope(
        'krusch_draft_hitl_gate',
        `Drafted PENDING_APPROVAL HITL gate ${gateId} for task ${cleanTaskId} (TTL ${Math.round(leaseTtlMs / 3600000)}h)`,
        {
          status: 'PENDING_APPROVAL',
          gateId,
          gate_id: gateId,
          taskId: cleanTaskId,
          actionType: cleanActionType,
          summary: cleanSummary,
          stagedPayload,
          createdAtMs,
          expiresAtMs,
          ttlMs: leaseTtlMs,
          slackBlocks
        },
        true
      )
    );
  }

  /**
   * 5B. Resolve a pending HITL approval lease with 72h TTL enforcement and Slack
   * `v0=` HMAC-SHA256 `crypto.timingSafeEqual` webhook authentication.
   */
  function resolveHitlGate({
    gateId,
    decision,
    reviewer = 'human',
    reason = '',
    signingSecret = '',
    requireSignature = false,
    timestampHeader = '',
    signatureHeader = '',
    rawBody = '',
    nowMs = Date.now()
  } = {}) {
    const cleanGateId = String(gateId || '').trim();
    const evalNowMs = Math.floor(Number(nowMs));
    const secret = String(signingSecret || '').trim();

    // Slack `v0=` HMAC-SHA256 + 5m replay protection check (mandatory when requireSignature=true)
    if (Boolean(requireSignature) || secret.length > 0 || String(signatureHeader || '').length > 0) {
      if (!secret || !timestampHeader || !signatureHeader) {
        return attachStatusAccessor(
          okEnvelope(
            'krusch_resolve_hitl_gate',
            'Slack webhook verification failed: signingSecret, timestampHeader, and signatureHeader are required',
            {
              status: 'UNAUTHORIZED_SIGNATURE',
              reason: !secret ? 'MISSING_SIGNING_SECRET' : 'MISSING_SIGNATURE_HEADERS',
              gateId: cleanGateId,
              signatureVerified: false
            },
            false
          )
        );
      }

      const rawTs = Number(timestampHeader);
      const tsMs = rawTs > 1e11 ? rawTs : rawTs * 1000;
      if (!Number.isFinite(tsMs) || Math.abs(evalNowMs - tsMs) > SLACK_REPLAY_WINDOW_MS) {
        return attachStatusAccessor(
          okEnvelope(
            'krusch_resolve_hitl_gate',
            'Slack webhook verification failed: request timestamp outside 5-minute replay window',
            {
              status: 'UNAUTHORIZED_SIGNATURE',
              reason: 'REPLAY_WINDOW_EXCEEDED',
              gateId: cleanGateId,
              signatureVerified: false
            },
            false
          )
        );
      }

      const expectedSig = computeSlackSignature({
        signingSecret: secret,
        timestampHeader,
        rawBody
      });
      const expectedBuf = Buffer.from(expectedSig, 'utf8');
      const actualBuf = Buffer.from(String(signatureHeader), 'utf8');
      const sigValid =
        expectedBuf.length === actualBuf.length &&
        crypto.timingSafeEqual(expectedBuf, actualBuf);

      if (!sigValid) {
        return attachStatusAccessor(
          okEnvelope(
            'krusch_resolve_hitl_gate',
            'Slack webhook verification failed: HMAC-SHA256 digest mismatch',
            {
              status: 'UNAUTHORIZED_SIGNATURE',
              reason: 'HMAC_MISMATCH',
              gateId: cleanGateId,
              signatureVerified: false
            },
            false
          )
        );
      }
    }

    const row =
      db && typeof db.prepare === 'function'
        ? db.prepare('SELECT * FROM stack_hitl_gates WHERE gate_id = ?').get(cleanGateId)
        : memoryHitlGates.get(cleanGateId);

    if (!row) {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_resolve_hitl_gate',
          `HITL gate '${cleanGateId}' not found`,
          {
            status: 'NOT_FOUND',
            gateId: cleanGateId
          },
          false
        )
      );
    }

    if (row.status !== 'PENDING_APPROVAL' && row.status !== 'PENDING') {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_resolve_hitl_gate',
          `HITL gate '${cleanGateId}' was already resolved with status ${row.status}`,
          {
            status: row.status,
            gateId: cleanGateId,
            taskId: row.task_id,
            alreadyDecided: true,
            reviewer: row.reviewer,
            decidedAtMs: row.decided_at_ms
          },
          false
        )
      );
    }

    if (evalNowMs >= Number(row.expires_at_ms)) {
      if (db && typeof db.prepare === 'function') {
        db.prepare(
          `UPDATE stack_hitl_gates
           SET status = 'EXPIRED', decided_at_ms = ?, decision_reason = 'TTL_LEASE_EXPIRED'
           WHERE gate_id = ?`
        ).run(evalNowMs, cleanGateId);
      } else {
        row.status = 'EXPIRED';
        row.decided_at_ms = evalNowMs;
        row.decision_reason = 'TTL_LEASE_EXPIRED';
      }

      return attachStatusAccessor(
        okEnvelope(
          'krusch_resolve_hitl_gate',
          `HITL gate '${cleanGateId}' expired at ${row.expires_at_ms} (now ${evalNowMs})`,
          {
            status: 'EXPIRED',
            gateId: cleanGateId,
            taskId: row.task_id,
            expiresAtMs: Number(row.expires_at_ms),
            nowMs: evalNowMs
          },
          false
        )
      );
    }

    const normDecision = String(decision || '').trim().toLowerCase();
    let finalStatus = null;
    if (['approve', 'approved', 'allow', 'accept'].includes(normDecision)) {
      finalStatus = 'APPROVED';
    } else if (['reject', 'rejected', 'deny', 'denied', 'abort'].includes(normDecision)) {
      finalStatus = 'REJECTED';
    } else {
      return attachStatusAccessor(
        okEnvelope(
          'krusch_resolve_hitl_gate',
          `Invalid HITL decision '${decision}'; expected 'approve' or 'reject'`,
          {
            status: 'INVALID_DECISION',
            gateId: cleanGateId,
            decision
          },
          false
        )
      );
    }

    const cleanReviewer = String(reviewer || 'human').trim();
    const cleanReason = String(reason || '').trim();

    if (db && typeof db.prepare === 'function') {
      db.prepare(
        `UPDATE stack_hitl_gates
         SET status = ?, decided_at_ms = ?, reviewer = ?, decision_reason = ?
         WHERE gate_id = ?`
      ).run(finalStatus, evalNowMs, cleanReviewer, cleanReason, cleanGateId);
    } else {
      row.status = finalStatus;
      row.decided_at_ms = evalNowMs;
      row.reviewer = cleanReviewer;
      row.decision_reason = cleanReason;
    }

    let parsedPayload = {};
    try {
      parsedPayload = JSON.parse(row.staged_payload || '{}');
    } catch {
      parsedPayload = { raw: row.staged_payload };
    }

    return attachStatusAccessor(
      okEnvelope(
        'krusch_resolve_hitl_gate',
        `HITL gate ${cleanGateId} ${finalStatus} by ${cleanReviewer}`,
        {
          status: finalStatus,
          approved: finalStatus === 'APPROVED',
          gateId: cleanGateId,
          gate_id: cleanGateId,
          taskId: row.task_id,
          actionType: row.action_type,
          reviewer: cleanReviewer,
          reason: cleanReason,
          decidedAtMs: evalNowMs,
          expiresAtMs: Number(row.expires_at_ms),
          signatureVerified: Boolean(secret),
          stagedPayload: parsedPayload
        },
        true
      )
    );
  }

  return {
    assembleContextBudget,
    evaluateCostKillSwitch,
    recordCostUsage,
    verifyTrajectoryDag,
    recordShadowComparison,
    scheduleShadowComparison,
    flushPendingShadows,
    draftHitlGate,
    resolveHitlGate
  };
}
