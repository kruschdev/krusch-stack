/**
 * @module engines/tool-graph-engine
 * Zero-dependency typed prerequisite tool router, automatic prompt-entity `given` extractor,
 * two-pass budget allocator, and bounded-LRU gap-driven outcome learner for KruschStack.
 *
 * Enforces INV-STACK-01 (zero external npm dependencies, Node 22 built-ins only),
 * INV-STACK-02 (deterministic okEnvelope return contract), and INV-STACK-04 (sanitized
 * public defaults with zero private network literals, hostnames, or OS home paths).
 */

import { okEnvelope } from '../db/sqlite.js';

/**
 * Build a deterministic `INV-LEGO-01` / `INV-STACK-02` error envelope.
 *
 * @param {string} code
 * @param {string} message
 * @param {unknown} [details=null]
 * @param {string} [tool='tool_graph']
 * @returns {{ ok: false, tool: string, summary: string, error: { code: string, message: string, details?: unknown } }}
 */
export function errorEnvelope(code, message, details = null, tool = 'tool_graph') {
  return {
    ok: false,
    tool: String(tool || 'tool_graph'),
    summary: String(message || code || 'Request failed'),
    error: {
      code: String(code || 'INTERNAL_ERROR'),
      message: String(message || 'Request failed'),
      ...(details !== null && details !== undefined ? { details } : {})
    }
  };
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'before', 'by', 'can', 'do', 'for',
  'from', 'get', 'give', 'has', 'have', 'how', 'i', 'if', 'in', 'into', 'is', 'it',
  'its', 'let', 'me', 'my', 'need', 'now', 'of', 'on', 'or', 'our', 'please', 'should',
  'so', 'some', 'that', 'the', 'their', 'them', 'then', 'there', 'these', 'this', 'to',
  'up', 'us', 'use', 'using', 'want', 'we', 'what', 'when', 'where', 'which', 'who',
  'with', 'would', 'you', 'your'
]);

/**
 * Canonical cross-component data types that safely bridge across MCP servers
 * (unlike opaque primary keys such as `channel_id` or `page_id`, which are scoped per server).
 */
export const CANONICAL_SHARED_TYPES = Object.freeze([
  'email_address',
  'repo_path',
  'file_path',
  'url',
  'uuid',
  'commit_sha',
  'channel_name',
  'symbol',
  'task_id',
  'memory_id',
  'page_number',
  'sql_query'
]);

export const TOOL_GRAPH_SHARED_TYPES = CANONICAL_SHARED_TYPES;

const SHARED_TYPE_SET = new Set(CANONICAL_SHARED_TYPES);

/**
 * Parameter-name aliases mapped to canonical shared types or component-scoped ID types.
 */
const PARAM_SHARED_ALIASES = new Map([
  ['email', 'email_address'],
  ['email_address', 'email_address'],
  ['to_email', 'email_address'],
  ['recipient_email', 'email_address'],
  ['sender_email', 'email_address'],
  ['repo', 'repo_path'],
  ['repository', 'repo_path'],
  ['repo_path', 'repo_path'],
  ['repo_full_name', 'repo_path'],
  ['full_repo_name', 'repo_path'],
  ['file_path', 'file_path'],
  ['filepath', 'file_path'],
  ['abs_path', 'file_path'],
  ['target_path', 'file_path'],
  ['url', 'url'],
  ['uri', 'url'],
  ['endpoint_url', 'url'],
  ['webhook_url', 'url'],
  ['uuid', 'uuid'],
  ['commit_sha', 'commit_sha'],
  ['commit_hash', 'commit_sha'],
  ['sha', 'commit_sha'],
  ['channel_name', 'channel_name'],
  ['symbol', 'symbol'],
  ['symbol_name', 'symbol'],
  ['task_id', 'task_id'],
  ['memory_id', 'memory_id'],
  ['target_id', 'memory_id'],
  ['page_number', 'page_number']
]);

/**
 * Producer verb prefixes indicating a tool can materialize/discover an entity reference.
 */
const PRODUCER_VERBS = new Set([
  'find', 'search', 'list', 'lookup', 'locate', 'resolve', 'discover',
  'create', 'open', 'start', 'run', 'submit', 'retrieve', 'fetch', 'query', 'sync'
]);

/**
 * Entity noun -> canonical or namespace-scoped output type suffix.
 */
const ENTITY_NOUN_TO_TYPE = Object.freeze([
  { pattern: /\b(?:pull_requests?|prs?)\b/i, type: 'pr_id', shared: false },
  { pattern: /\bchannels?\b/i, type: 'channel_id', shared: false },
  { pattern: /\bthreads?\b/i, type: 'thread_id', shared: false },
  { pattern: /\bissues?\b/i, type: 'issue_id', shared: false },
  { pattern: /\b(?:users?|members?|contacts?)\b/i, type: 'user_id', shared: false },
  { pattern: /\bdatabases?\b/i, type: 'database_id', shared: false },
  { pattern: /\bpages?\b/i, type: 'page_id', shared: false },
  { pattern: /\bmessages?\b/i, type: 'message_id', shared: false },
  { pattern: /\bevents?\b/i, type: 'event_id', shared: false },
  { pattern: /\bcustomers?\b/i, type: 'customer_id', shared: false },
  { pattern: /\binvoices?\b/i, type: 'invoice_id', shared: false },
  { pattern: /\bdeployments?\b/i, type: 'deployment_id', shared: false },
  { pattern: /\bprojects?\b/i, type: 'project_id', shared: false },
  { pattern: /\bdocuments?\b|\bdocs?\b/i, type: 'document_id', shared: false },
  { pattern: /\b(?:repos?|repositories)\b/i, type: 'repo_path', shared: true },
  { pattern: /\bfiles?\b/i, type: 'file_path', shared: true },
  { pattern: /\bsymbols?\b/i, type: 'symbol', shared: true },
  { pattern: /\bcommits?\b/i, type: 'commit_sha', shared: true },
  { pattern: /\bemails?\b/i, type: 'email_address', shared: true }
]);

/**
 * Curated prerequisite contracts for standard KruschStack MCP workflows (`krusch-stack`,
 * `krusch-git`, `krusch-fs`, `krusch-harness`, `krusch-context-mcp`).
 */
const CURATED_TOOL_CONTRACTS = new Map([
  ['krusch_run', { consumes: [], produces: ['task_id'], capabilities: ['submit_task', 'stage_execution'] }],
  ['krusch_task_status', { consumes: ['task_id'], produces: [], capabilities: ['inspect_task_status'] }],
  ['krusch_diff', { consumes: ['task_id'], produces: [], capabilities: ['review_staged_diff'] }],
  ['krusch_apply_diff', { consumes: ['task_id'], produces: [], capabilities: ['apply_staged_diff', 'commit_2pc'] }],
  ['krusch_explain', { consumes: ['task_id'], produces: [], capabilities: ['explain_blocked_task'] }],
  ['krusch_reject', { consumes: ['task_id'], produces: [], capabilities: ['reject_staged_diff'] }],
  ['krusch_abort', { consumes: ['task_id'], produces: [], capabilities: ['abort_task'] }],
  ['krusch_fs_locate', { consumes: [], produces: ['file_path'], capabilities: ['locate_files', 'glob_search'] }],
  ['krusch_fs_search', { consumes: [], produces: ['file_path'], capabilities: ['search_filesystem', 'bm25_vector_search'] }],
  ['krusch_fs_page_tree', { consumes: ['file_path'], produces: ['page_number'], capabilities: ['inspect_page_tree', 'table_of_contents'] }],
  ['krusch_fs_read_page', { consumes: ['file_path', 'page_number'], produces: [], capabilities: ['read_bounded_page'] }],
  ['krusch_fs_remember_on_page', { consumes: ['file_path', 'page_number'], produces: [], capabilities: ['annotate_page'] }],
  ['krusch_git_list_repos', { consumes: [], produces: ['repo_path'], capabilities: ['list_repositories'] }],
  ['krusch_git_search_symbols', { consumes: [], produces: ['symbol', 'file_path'], capabilities: ['search_ast_symbols'] }],
  ['krusch_git_file_symbols', { consumes: ['file_path'], produces: ['symbol'], capabilities: ['list_file_symbols'] }],
  ['krusch_git_dependency_graph', { consumes: ['symbol'], produces: [], capabilities: ['ast_blast_radius', 'call_graph'] }],
  ['krusch_git_read_blob', { consumes: ['file_path'], produces: [], capabilities: ['read_git_blob'] }],
  ['krusch_context_retrieve', { consumes: [], produces: ['memory_id'], capabilities: ['hydrate_context', 'retrieve_invariants'] }],
  ['krusch_context_revise', { consumes: ['memory_id'], produces: ['memory_id'], capabilities: ['supersede_memory', 'invalidate_memory'] }]
]);

/**
 * Deep-frozen default options for ToolGraph routing.
 */
export const DEFAULT_TOOL_GRAPH_OPTIONS = Object.freeze({
  budget: 8,
  minBudget: 1,
  maxBudget: 64,
  maxDepth: 4,
  maxIntents: 512,
  maxEdgesPerNode: 64,
  minWeight: 0,
  maxWeight: 5,
  successBoost: 1.0,
  nextBoost: 0.75,
  gapBoost: 1.5,
  failurePenalty: 0.5,
  learnedNextThreshold: 1.25,
  maxLearnedNextSlots: 2,
  primaryCutoffRatio: 0.55,
  bm25K1: 1.2,
  bm25B: 0.75,
  exposeOutcomeTool: false
});

const MAX_TASK_CHARS = 8192;

const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const CHANNEL_HASH_RE = /(?:^|[\s(['"`])#([a-z0-9][a-z0-9_-]{0,79})\b/gi;
const FILE_PATH_RE = /(?:^|[\s(['"`])((?:\.{1,2}\/|~\/|\/[A-Za-z0-9_.-]+\/)[A-Za-z0-9_./-]+|(?<![A-Za-z0-9_./-])[A-Za-z0-9_.-]+\.(?:js|mjs|cjs|ts|tsx|jsx|py|php|java|cs|go|rb|rs|kt|json|yaml|yml|toml|md|sql|sh|csv|pdf|html|css))\b/g;
const REPO_SLUG_RE = /(?:^|[\s(['"`])([A-Za-z0-9_.-]{2,64}\/[A-Za-z0-9_.-]{2,64})(?=$|[\s)\]'":;,!?])/g;
const HEX_SHA_RE = /\b[0-9a-f]{7,40}\b/gi;
const TASK_ID_LITERAL_RE = /\btask[-_][A-Za-z0-9_-]{2,64}\b/gi;
const PAGE_NUMBER_RE = /\bpage\s+#?\d+\b/gi;
const SLASH_STOP_PAIRS = new Set([
  'and/or', 'yes/no', 'true/false', 'read/write', 'input/output', 'ci/cd', 'http/https', 'tcp/ip'
]);
const CLAUSE_SPLIT_RE = /\b(?:and then|after that|followed by|then|and|before|from|into|onto|to|via)\b|[;,\n]+/i;

function isSafeKey(value) {
  return typeof value === 'string' && value.trim().length > 0 && !FORBIDDEN_KEYS.has(value.trim());
}

function normalizeIdentifier(raw) {
  if (typeof raw !== 'string') return '';
  const cleaned = raw
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9_.:-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
  if (!cleaned || FORBIDDEN_KEYS.has(cleaned)) return '';
  return cleaned;
}

/**
 * Light morphological stemmer so plurals/inflections (`prs` -> `pr`, `channels` -> `channel`,
 * `posting` -> `post`, `repositories` -> `repository`) align cleanly in zero-LLM BM25.
 *
 * @param {string} token
 * @returns {string}
 */
function stemToken(token) {
  if (token.length <= 2) return token;
  if (token === 'prs') return 'pr';
  if (token.endsWith('ies') && token.length > 4) return `${token.slice(0, -3)}y`;
  if (token.endsWith('ing') && token.length > 5) return `${token.slice(0, -3)}`;
  if (token.endsWith('ed') && token.length > 4) return `${token.slice(0, -2)}`;
  if (token.endsWith('es') && token.length > 4 && /(?:ches|shes|xes|zes|ses)$/.test(token)) {
    return token.slice(0, -2);
  }
  if (token.endsWith('s') && !token.endsWith('ss') && !token.endsWith('us') && token.length > 3) {
    return token.slice(0, -1);
  }
  return token;
}

/**
 * Tokenize text into normalized, stemmed lexical terms with camelCase and snake_case splitting.
 *
 * @param {unknown} text
 * @param {{ keepStopwords?: boolean }} [options]
 * @returns {string[]}
 */
function tokenizeTerms(text, { keepStopwords = false } = {}) {
  const expanded = String(text ?? '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase();
  const rawTokens = expanded.split(/[^a-z0-9]+/g);
  const out = [];
  for (const tok of rawTokens) {
    if (!tok || tok.length < 2) continue;
    if (!keepStopwords && STOPWORDS.has(tok)) continue;
    const stemmed = stemToken(tok);
    if (!keepStopwords && STOPWORDS.has(stemmed)) continue;
    out.push(stemmed);
  }
  return out;
}

/**
 * Infer a tool's component/server namespace (`slack`, `github`, `krusch-fs`, etc.).
 *
 * @param {Record<string, any>} tool
 * @returns {string}
 */
function resolveToolComponent(tool) {
  const explicit = tool?.component || tool?.server || tool?.namespace || '';
  if (typeof explicit === 'string' && explicit.trim()) {
    return normalizeIdentifier(explicit);
  }
  const name = String(tool?.name || '').trim();
  if (name.includes('.')) {
    return normalizeIdentifier(name.split('.')[0]);
  }
  if (name.includes('__')) {
    return normalizeIdentifier(name.split('__')[0]);
  }
  if (name.includes('/')) {
    return normalizeIdentifier(name.split('/')[0]);
  }
  const underscoreParts = name.split('_');
  if (underscoreParts.length >= 3 && underscoreParts[0].toLowerCase() === 'krusch') {
    return normalizeIdentifier(`${underscoreParts[0]}_${underscoreParts[1]}`);
  }
  if (underscoreParts.length >= 2) {
    return normalizeIdentifier(underscoreParts[0]);
  }
  return 'default';
}

/**
 * Normalize a declared or inferred data-type token, scoping opaque `*_id` types by component
 * unless already namespace-qualified or in `CANONICAL_SHARED_TYPES`.
 *
 * @param {string} rawType
 * @param {string} component
 * @returns {string}
 */
function qualifyTypeToken(rawType, component) {
  const norm = normalizeIdentifier(rawType);
  if (!norm) return '';
  if (PARAM_SHARED_ALIASES.has(norm)) {
    return PARAM_SHARED_ALIASES.get(norm);
  }
  if (SHARED_TYPE_SET.has(norm)) {
    return norm;
  }
  if (norm.includes('.')) {
    return norm;
  }
  if (norm.endsWith('_id') && component && component !== 'default') {
    return `${component}.${norm}`;
  }
  return norm;
}

/**
 * Mask concrete user literals (emails, URLs, UUIDs, `#channels`, paths, `owner/repo` slugs,
 * quoted strings, and numbers) into a canonical structural intent signature for zero-LLM learning.
 *
 * @param {string} taskText
 * @returns {{ maskedText: string, intentSignature: string, tokens: string[] }}
 */
export function maskTaskEntities(taskText) {
  const raw = String(taskText ?? '').slice(0, MAX_TASK_CHARS).trim();
  if (!raw) {
    return { maskedText: '', intentSignature: 'empty_intent', tokens: [] };
  }

  const masked = raw
    .replace(URL_RE, ' <url> ')
    .replace(EMAIL_RE, ' <email> ')
    .replace(UUID_RE, ' <uuid> ')
    .replace(CHANNEL_HASH_RE, ' <channel> ')
    .replace(FILE_PATH_RE, ' <path> ')
    .replace(REPO_SLUG_RE, ' <repo> ')
    .replace(/"[^"\n]{1,120}"|'[^'\n]{1,120}'/g, ' <str> ')
    .replace(/\b\d+\b/g, ' <num> ')
    .replace(/\s+/g, ' ')
    .trim();

  const tokens = [];
  const seen = new Set();
  for (const part of masked.toLowerCase().split(/\s+/g)) {
    if (part.startsWith('<') && part.endsWith('>')) {
      if (!seen.has(part)) {
        seen.add(part);
        tokens.push(part);
      }
      continue;
    }
    for (const term of tokenizeTerms(part)) {
      if (!seen.has(term)) {
        seen.add(term);
        tokens.push(term);
      }
    }
  }

  const intentSignature = tokens.length > 0 ? tokens.slice(0, 16).join(':') : 'generic_intent';
  return { maskedText: masked, intentSignature, tokens };
}

/**
 * Automatically extract canonical `given` data types already present as concrete literals in
 * the task prompt, merged with any caller-supplied `extraGiven` parameter/type names.
 *
 * @param {string} taskText
 * @param {string[]} [extraGiven=[]]
 * @returns {{ givenTypes: string[], detections: Record<string, string[]> }}
 */
export function extractGivenTypesFromTask(taskText, extraGiven = []) {
  const text = String(taskText ?? '').slice(0, MAX_TASK_CHARS);
  const givenSet = new Set();
  const detections = Object.create(null);

  const record = (typeName, sample) => {
    if (!isSafeKey(typeName)) return;
    givenSet.add(typeName);
    if (sample !== undefined) {
      if (!detections[typeName]) detections[typeName] = [];
      if (detections[typeName].length < 8 && !detections[typeName].includes(sample)) {
        detections[typeName].push(sample);
      }
    }
  };

  // Strip URLs first into a working copy so URL path segments do not false-trigger repo/file regexes
  const urls = text.match(URL_RE) || [];
  for (const u of urls) record('url', u);
  const textWithoutUrls = text.replace(URL_RE, ' ');

  const emails = textWithoutUrls.match(EMAIL_RE) || [];
  for (const e of emails) record('email_address', e);
  const textWithoutEmails = textWithoutUrls.replace(EMAIL_RE, ' ');

  const uuids = textWithoutEmails.match(UUID_RE) || [];
  for (const id of uuids) record('uuid', id);
  const textWithoutUuids = textWithoutEmails.replace(UUID_RE, ' ');

  let m;
  CHANNEL_HASH_RE.lastIndex = 0;
  while ((m = CHANNEL_HASH_RE.exec(textWithoutUuids)) !== null) {
    record('channel_name', `#${m[1]}`);
  }

  const matchedFileSpans = [];
  FILE_PATH_RE.lastIndex = 0;
  while ((m = FILE_PATH_RE.exec(textWithoutUuids)) !== null) {
    const candidate = m[1].trim();
    matchedFileSpans.push(candidate);
    record('file_path', candidate);
  }

  let textWithoutFiles = textWithoutUuids;
  for (const span of matchedFileSpans) {
    textWithoutFiles = textWithoutFiles.split(span).join(' ');
  }

  REPO_SLUG_RE.lastIndex = 0;
  while ((m = REPO_SLUG_RE.exec(textWithoutFiles)) !== null) {
    const slug = m[1];
    const [owner, repo] = slug.split('/');
    if (
      owner &&
      repo &&
      !SLASH_STOP_PAIRS.has(slug.toLowerCase()) &&
      !/^\d+\/\d+$/.test(slug)
    ) {
      record('repo_path', slug);
    }
  }

  HEX_SHA_RE.lastIndex = 0;
  while ((m = HEX_SHA_RE.exec(textWithoutFiles)) !== null) {
    const sha = m[0];
    if (sha.length === 40 || (/[0-9]/.test(sha) && /[a-f]/i.test(sha))) {
      record('commit_sha', sha);
    }
  }

  const taskIds = textWithoutFiles.match(TASK_ID_LITERAL_RE) || [];
  for (const tid of taskIds) record('task_id', tid);

  const pageRefs = textWithoutFiles.match(PAGE_NUMBER_RE) || [];
  for (const pref of pageRefs) record('page_number', pref);

  if (Array.isArray(extraGiven)) {
    for (const item of extraGiven) {
      if (typeof item !== 'string') continue;
      const trimmed = item.trim();
      if (!trimmed) continue;
      const norm = normalizeIdentifier(trimmed);
      if (!norm) continue;
      record(norm, trimmed);
      if (PARAM_SHARED_ALIASES.has(norm)) {
        record(PARAM_SHARED_ALIASES.get(norm), trimmed);
      }
    }
  }

  return {
    givenTypes: Array.from(givenSet).sort(),
    detections: { ...detections }
  };
}

/**
 * Compile plain MCP tool definitions into a deterministic typed dependency schema
 * (`nodes`, `producersByType`, `consumersByType`).
 *
 * @param {Array<Record<string, any>>} tools
 * @param {{ customContracts?: Record<string, { consumes?: string[], produces?: string[], capabilities?: string[] }> }} [options]
 */
export function inferToolGraphSchema(tools = [], options = {}) {
  if (!Array.isArray(tools)) {
    throw new TypeError('inferToolGraphSchema requires an array of MCP tool definitions');
  }

  const customContracts = options?.customContracts && typeof options.customContracts === 'object'
    ? options.customContracts
    : null;

  const nodes = [];
  const nodeByName = new Map();
  const producersByType = new Map();
  const consumersByType = new Map();

  for (const rawTool of tools) {
    if (!rawTool || typeof rawTool !== 'object') continue;
    const name = String(rawTool.name || '').trim();
    if (!isSafeKey(name) || nodeByName.has(name)) continue;

    const component = resolveToolComponent(rawTool);
    const title = String(rawTool.title || rawTool.annotations?.title || '').trim();
    const description = String(rawTool.description || '').trim();
    const inputSchema = rawTool.inputSchema && typeof rawTool.inputSchema === 'object'
      ? rawTool.inputSchema
      : { type: 'object', properties: {} };
    const properties = inputSchema.properties && typeof inputSchema.properties === 'object'
      ? inputSchema.properties
      : {};
    const requiredSet = new Set(Array.isArray(inputSchema.required) ? inputSchema.required.map(String) : []);

    const curated = CURATED_TOOL_CONTRACTS.get(name);
    const custom = customContracts && isSafeKey(name) && customContracts[name]
      ? customContracts[name]
      : null;

    const consumesSet = new Set();
    const producesSet = new Set();
    const capabilitiesSet = new Set();

    const explicitConsumes = custom?.consumes ?? rawTool.consumes ?? curated?.consumes;
    const explicitProduces = custom?.produces ?? rawTool.produces ?? curated?.produces;
    const explicitCaps = custom?.capabilities ?? rawTool.capabilities ?? curated?.capabilities;

    if (Array.isArray(explicitConsumes)) {
      for (const c of explicitConsumes) {
        const q = qualifyTypeToken(String(c), component);
        if (q) consumesSet.add(q);
      }
    } else {
      for (const [propName, propSpec] of Object.entries(properties)) {
        if (!isSafeKey(propName)) continue;
        const normProp = normalizeIdentifier(propName);
        if (!normProp) continue;

        const isRequired = requiredSet.has(propName);
        const explicitRefType = propSpec && typeof propSpec === 'object' && typeof propSpec['x-ref-type'] === 'string'
          ? qualifyTypeToken(propSpec['x-ref-type'], component)
          : '';

        if (explicitRefType) {
          consumesSet.add(explicitRefType);
          continue;
        }

        if (PARAM_SHARED_ALIASES.has(normProp) && isRequired) {
          consumesSet.add(PARAM_SHARED_ALIASES.get(normProp));
          continue;
        }

        if (normProp.endsWith('_id') && isRequired) {
          consumesSet.add(qualifyTypeToken(normProp, component));
        }
      }
    }

    if (Array.isArray(explicitProduces)) {
      for (const p of explicitProduces) {
        const q = qualifyTypeToken(String(p), component);
        if (q) producesSet.add(q);
      }
    } else {
      const outProps = rawTool.outputSchema?.properties;
      if (outProps && typeof outProps === 'object') {
        for (const propName of Object.keys(outProps)) {
          const normProp = normalizeIdentifier(propName);
          if (PARAM_SHARED_ALIASES.has(normProp)) {
            const candidate = PARAM_SHARED_ALIASES.get(normProp);
            if (!consumesSet.has(candidate)) producesSet.add(candidate);
          } else if (normProp.endsWith('_id')) {
            const candidate = qualifyTypeToken(normProp, component);
            if (!consumesSet.has(candidate)) producesSet.add(candidate);
          }
        }
      }

      const localName = name.includes('.')
        ? name.split('.').slice(1).join('_')
        : name.includes('__')
          ? name.split('__').slice(1).join('_')
          : name;
      const nameParts = normalizeIdentifier(localName).split('_').filter(Boolean);
      const hasProducerVerb = nameParts.some((part) => PRODUCER_VERBS.has(part));
      if (hasProducerVerb) {
        const matchSurface = `${localName} ${title}`;
        for (const rule of ENTITY_NOUN_TO_TYPE) {
          if (rule.pattern.test(matchSurface)) {
            const outType = rule.shared
              ? rule.type
              : qualifyTypeToken(rule.type, component);
            if (outType && !consumesSet.has(outType)) {
              producesSet.add(outType);
            }
          }
        }
      }
    }

    if (Array.isArray(explicitCaps)) {
      for (const cap of explicitCaps) {
        const normCap = normalizeIdentifier(String(cap));
        if (normCap) capabilitiesSet.add(normCap);
      }
    }

    const paramNames = Object.keys(properties).filter(isSafeKey);
    const schemaBytes = Buffer.byteLength(JSON.stringify(rawTool), 'utf8');

    const node = {
      name,
      component,
      title,
      description,
      paramNames,
      requiredParams: Array.from(requiredSet),
      consumes: Array.from(consumesSet),
      produces: Array.from(producesSet),
      capabilities: Array.from(capabilitiesSet),
      schemaBytes,
      estimatedTokens: Math.ceil(schemaBytes / 4),
      rawTool
    };

    nodes.push(node);
    nodeByName.set(name, node);

    for (const cType of node.consumes) {
      if (!consumersByType.has(cType)) consumersByType.set(cType, []);
      consumersByType.get(cType).push(name);
    }
    for (const pType of node.produces) {
      if (!producersByType.has(pType)) producersByType.set(pType, []);
      producersByType.get(pType).push(name);
    }
  }

  return {
    nodes,
    nodeByName,
    producersByType,
    consumersByType
  };
}

export const compileToolGraph = inferToolGraphSchema;
export const buildToolPrerequisiteGraph = inferToolGraphSchema;

/**
 * Create a bounded LRU Map helper that evicts the least-recently-used entry above `maxEntries`.
 *
 * @param {number} maxEntries
 */
function createBoundedLruMap(maxEntries) {
  const store = new Map();
  return {
    get size() {
      return store.size;
    },
    has(key) {
      return store.has(key);
    },
    get(key) {
      if (!store.has(key)) return undefined;
      const val = store.get(key);
      store.delete(key);
      store.set(key, val);
      return val;
    },
    set(key, value) {
      if (!isSafeKey(key)) return;
      if (store.has(key)) {
        store.delete(key);
      } else if (store.size >= maxEntries) {
        const oldestKey = store.keys().next().value;
        if (oldestKey !== undefined) store.delete(oldestKey);
      }
      store.set(key, value);
    },
    delete(key) {
      return store.delete(key);
    },
    clear() {
      store.clear();
    },
    entries() {
      return Array.from(store.entries());
    }
  };
}

/**
 * Split a multi-goal natural-language prompt into clause sub-queries so multi-server tasks
 * retain high recall on every clause.
 *
 * @param {string} taskText
 * @returns {string[]}
 */
function decomposeTaskClauses(taskText) {
  const raw = String(taskText ?? '').trim();
  if (!raw) return [];
  const segments = raw
    .split(CLAUSE_SPLIT_RE)
    .map((s) => s.trim())
    .filter((s) => s.length >= 3);
  const unique = [];
  const seen = new Set();
  for (const seg of segments) {
    const terms = tokenizeTerms(seg);
    if (terms.length === 0) continue;
    const sig = terms.join(' ');
    if (!seen.has(sig)) {
      seen.add(sig);
      unique.push(seg);
    }
  }
  return unique;
}

/**
 * Create a stateful ToolGraph router and deferred MCP meta-tool bridge.
 * Accepts either `(toolsArray, options)` or `({ tools, ...options })`.
 *
 * @param {Array<Record<string, any>> | Record<string, any>} [tools=[]]
 * @param {Record<string, any>} [options={}]
 */
export function createToolGraph(tools = [], options = {}) {
  let resolvedTools;
  let resolvedOptions;

  if (Array.isArray(tools)) {
    resolvedTools = tools;
    resolvedOptions = options && typeof options === 'object' ? options : {};
  } else if (tools && typeof tools === 'object') {
    if (tools.tools !== undefined && !Array.isArray(tools.tools)) {
      throw new TypeError('createToolGraph requires tools to be an array of tool definitions');
    }
    resolvedTools = Array.isArray(tools.tools) ? tools.tools : [];
    resolvedOptions = {
      ...tools,
      ...(options && typeof options === 'object' ? options : {})
    };
  } else {
    throw new TypeError('createToolGraph requires an array of tool definitions');
  }

  const cfg = {
    ...DEFAULT_TOOL_GRAPH_OPTIONS,
    ...resolvedOptions
  };

  const rawBudget = resolvedOptions?.budget ?? resolvedOptions?.maxReturnedTools ?? DEFAULT_TOOL_GRAPH_OPTIONS.budget;
  const defaultBudget = Math.max(
    cfg.minBudget,
    Math.min(cfg.maxBudget, Math.trunc(Number(rawBudget) || DEFAULT_TOOL_GRAPH_OPTIONS.budget))
  );
  const maxDepth = Math.max(1, Math.min(10, Math.trunc(Number(cfg.maxDepth) || 4)));
  const maxIntents = Math.max(8, Math.min(10_000, Math.trunc(Number(cfg.maxIntents) || 512)));
  const maxEdgesPerNode = Math.max(4, Math.min(512, Math.trunc(Number(cfg.maxEdgesPerNode) || 64)));
  const minWeight = Number.isFinite(cfg.minWeight) ? Number(cfg.minWeight) : 0;
  const maxWeight = Number.isFinite(cfg.maxWeight) ? Number(cfg.maxWeight) : 5;
  const rawAlwaysLoaded = resolvedOptions?.alwaysLoaded ?? resolvedOptions?.pinnedToolNames ?? [];
  const alwaysLoadedNames = new Set(
    Array.isArray(rawAlwaysLoaded) ? rawAlwaysLoaded.map(String) : []
  );
  const handlers = resolvedOptions?.handlers instanceof Map
    ? Object.fromEntries(resolvedOptions.handlers.entries())
    : (resolvedOptions?.handlers && typeof resolvedOptions.handlers === 'object' ? resolvedOptions.handlers : {});
  const dispatcher = typeof resolvedOptions?.dispatcher === 'function' ? resolvedOptions.dispatcher : null;

  const graph = inferToolGraphSchema(resolvedTools, { customContracts: resolvedOptions?.customContracts });
  const fullCatalogSchemaBytes = graph.nodes.reduce((sum, n) => sum + n.schemaBytes, 0);

  const docInfos = [];
  const dfMap = new Map();
  let totalWeightedLen = 0;

  for (const node of graph.nodes) {
    const weightedBag = new Map();
    const addFieldTerms = (text, weight) => {
      const fieldTerms = tokenizeTerms(text);
      for (const term of fieldTerms) {
        weightedBag.set(term, (weightedBag.get(term) || 0) + weight);
      }
      if (fieldTerms.includes('pull') && fieldTerms.includes('request')) {
        weightedBag.set('pr', (weightedBag.get('pr') || 0) + weight);
      }
    };

    addFieldTerms(node.name, 3.0);
    addFieldTerms(node.title, 2.0);
    addFieldTerms(node.capabilities.join(' '), 2.0);
    addFieldTerms(node.component, 1.8);
    addFieldTerms(node.paramNames.join(' '), 1.5);
    addFieldTerms(node.description, 1.0);

    let docLen = 0;
    for (const [term, tf] of weightedBag.entries()) {
      docLen += tf;
      dfMap.set(term, (dfMap.get(term) || 0) + 1);
    }
    totalWeightedLen += docLen;
    docInfos.push({ node, weightedBag, docLen });
  }

  const avgDocLen = docInfos.length > 0 ? Math.max(1, totalWeightedLen / docInfos.length) : 1;

  const intentSolvedStore = createBoundedLruMap(maxIntents);
  const nextEdgeStore = new Map();
  const dynamicConsumesStore = new Map();

  let findCalls = 0;
  let outcomeCalls = 0;
  let describeCalls = 0;
  let executeCalls = 0;

  function clampWeight(w) {
    return Math.max(minWeight, Math.min(maxWeight, Math.round(w * 10000) / 10000));
  }

  function setBoundedEdgeWeight(edgeMap, targetKey, newWeight) {
    if (!isSafeKey(targetKey)) return;
    const clamped = clampWeight(newWeight);
    if (clamped <= minWeight) {
      edgeMap.delete(targetKey);
      return;
    }
    if (edgeMap.has(targetKey)) {
      edgeMap.delete(targetKey);
    } else if (edgeMap.size >= maxEdgesPerNode) {
      let minKey;
      let minVal = Infinity;
      for (const [k, v] of edgeMap.entries()) {
        if (v < minVal) {
          minVal = v;
          minKey = k;
        }
      }
      if (minKey !== undefined) edgeMap.delete(minKey);
    }
    edgeMap.set(targetKey, clamped);
  }

  function getEffectiveConsumes(node) {
    const extra = dynamicConsumesStore.get(node.name);
    if (!extra || extra.size === 0) return node.consumes;
    const merged = new Set(node.consumes);
    for (const item of extra) merged.add(item);
    return Array.from(merged);
  }

  function scoreBm25Terms(queryTerms, allowedComponent) {
    const scores = new Map();
    const matchedTermsByTool = new Map();
    const N = docInfos.length;
    if (N === 0 || queryTerms.length === 0) {
      return { scores, matchedTermsByTool };
    }

    const uniqueTerms = Array.from(new Set(queryTerms));
    for (const { node, weightedBag, docLen } of docInfos) {
      if (allowedComponent && node.component !== allowedComponent) continue;
      let score = 0;
      const matched = [];
      for (const term of uniqueTerms) {
        const tf = weightedBag.get(term) || 0;
        if (tf <= 0) continue;
        const df = dfMap.get(term) || 0;
        const idf = Math.log(1 + (N - df + 0.5) / (df + 0.5));
        const denom = tf + cfg.bm25K1 * (1 - cfg.bm25B + cfg.bm25B * (docLen / avgDocLen));
        score += idf * ((tf * (cfg.bm25K1 + 1)) / denom);
        matched.push(term);
      }
      if (score > 0) {
        scores.set(node.name, score);
        matchedTermsByTool.set(node.name, matched);
      }
    }
    return { scores, matchedTermsByTool };
  }

  function resolvePrerequisiteChain(toolName, satisfiedTypes, scoreMap, allowedComponent, visitedTools = new Set(), depth = 0) {
    const node = graph.nodeByName.get(toolName);
    if (!node || depth >= maxDepth) {
      return { feasible: true, steps: [] };
    }

    const nextVisited = new Set(visitedTools);
    nextVisited.add(toolName);

    const localSatisfied = new Set(satisfiedTypes);
    const steps = [];
    const consumes = getEffectiveConsumes(node);

    for (const reqType of consumes) {
      if (localSatisfied.has(reqType)) continue;
      const bareSuffix = reqType.includes('.') ? reqType.split('.').slice(1).join('.') : reqType;
      if (localSatisfied.has(bareSuffix) && SHARED_TYPE_SET.has(bareSuffix)) {
        continue;
      }

      const candidateProducers = (graph.producersByType.get(reqType) || [])
        .filter((pName) => !nextVisited.has(pName))
        .filter((pName) => {
          if (!allowedComponent) return true;
          const pNode = graph.nodeByName.get(pName);
          return pNode && pNode.component === allowedComponent;
        });

      if (candidateProducers.length === 0) {
        continue;
      }

      let bestPlan = null;
      for (const prodName of candidateProducers) {
        const subPlan = resolvePrerequisiteChain(
          prodName,
          localSatisfied,
          scoreMap,
          allowedComponent,
          nextVisited,
          depth + 1
        );
        if (!subPlan.feasible) continue;

        const prodNode = graph.nodeByName.get(prodName);
        const prodConsumes = getEffectiveConsumes(prodNode);
        const unsatisfiedOwnCount = prodConsumes.filter((t) => !localSatisfied.has(t)).length;
        const relevance = scoreMap.get(prodName) || 0;
        const totalSteps = subPlan.steps.length + 1;

        const candidatePlan = {
          prodName,
          prodNode,
          subSteps: subPlan.steps,
          totalSteps,
          unsatisfiedOwnCount,
          relevance
        };

        if (
          !bestPlan ||
          candidatePlan.totalSteps < bestPlan.totalSteps ||
          (candidatePlan.totalSteps === bestPlan.totalSteps &&
            candidatePlan.unsatisfiedOwnCount < bestPlan.unsatisfiedOwnCount) ||
          (candidatePlan.totalSteps === bestPlan.totalSteps &&
            candidatePlan.unsatisfiedOwnCount === bestPlan.unsatisfiedOwnCount &&
            candidatePlan.relevance > bestPlan.relevance) ||
          (candidatePlan.totalSteps === bestPlan.totalSteps &&
            candidatePlan.unsatisfiedOwnCount === bestPlan.unsatisfiedOwnCount &&
            candidatePlan.relevance === bestPlan.relevance &&
            candidatePlan.prodName.localeCompare(bestPlan.prodName) < 0)
        ) {
          bestPlan = candidatePlan;
        }
      }

      if (bestPlan) {
        for (const sub of bestPlan.subSteps) {
          if (!steps.some((s) => s.toolName === sub.toolName)) {
            steps.push(sub);
            const sNode = graph.nodeByName.get(sub.toolName);
            if (sNode) {
              for (const outT of sNode.produces) localSatisfied.add(outT);
            }
          }
        }
        if (!steps.some((s) => s.toolName === bestPlan.prodName)) {
          steps.push({
            toolName: bestPlan.prodName,
            produces: reqType,
            forTool: toolName,
            depth: depth + 1
          });
        }
        for (const outT of bestPlan.prodNode.produces) {
          localSatisfied.add(outT);
        }
      }
    }

    return { feasible: true, steps };
  }

  /**
   * Route a natural-language task to a minimal, prerequisite-complete subset of tools.
   *
   * @param {{ task: string, given?: string[], budget?: number, component?: string }} params
   */
  function findTools(params = {}) {
    findCalls += 1;
    const rawTask = typeof params === 'string'
      ? params
      : typeof params?.task === 'string'
        ? params.task
        : typeof params?.query === 'string'
          ? params.query
          : '';
    const task = rawTask.slice(0, MAX_TASK_CHARS).trim();
    if (!task) {
      return errorEnvelope(
        'EMPTY_TASK',
        'findTools requires a non-empty task description',
        { field: 'task' },
        'tool_graph.find_tools'
      );
    }

    const effectiveBudget = Math.max(
      cfg.minBudget,
      Math.min(
        cfg.maxBudget,
        params?.budget !== undefined ? Math.trunc(Number(params.budget)) || defaultBudget : defaultBudget
      )
    );
    const allowedComponent = typeof params?.component === 'string' && params.component.trim()
      ? normalizeIdentifier(params.component)
      : '';

    const { givenTypes: extractedGiven, detections } = extractGivenTypesFromTask(
      task,
      Array.isArray(params?.given) ? params.given : []
    );
    const satisfiedTypes = new Set(extractedGiven);

    const { intentSignature, tokens: maskedIntentTokens } = maskTaskEntities(task);
    const exactIntentEdges = intentSolvedStore.get(intentSignature);

    const intentBoostByTool = new Map();
    if (exactIntentEdges) {
      for (const [tName, w] of exactIntentEdges.entries()) {
        intentBoostByTool.set(tName, w);
      }
    } else if (maskedIntentTokens.length > 0 && intentSolvedStore.size > 0) {
      const qSet = new Set(maskedIntentTokens);
      for (const [storedSig, edgeMap] of intentSolvedStore.entries()) {
        const sTokens = storedSig.split(':').filter(Boolean);
        let overlap = 0;
        for (const tok of sTokens) {
          if (qSet.has(tok)) overlap += 1;
        }
        const union = qSet.size + sTokens.length - overlap;
        const jaccard = union > 0 ? overlap / union : 0;
        if (jaccard >= 0.6) {
          for (const [tName, w] of edgeMap.entries()) {
            const scaled = w * jaccard;
            if (scaled > (intentBoostByTool.get(tName) || 0)) {
              intentBoostByTool.set(tName, scaled);
            }
          }
        }
      }
    }

    const queryTerms = tokenizeTerms(task);
    const { scores: fullScores, matchedTermsByTool } = scoreBm25Terms(queryTerms, allowedComponent);

    const clauses = decomposeTaskClauses(task);
    const clauseWinners = [];
    for (const clause of clauses) {
      const cTerms = tokenizeTerms(clause);
      if (cTerms.length === 0) continue;
      const { scores: cScores } = scoreBm25Terms(cTerms, allowedComponent);
      let topTool = '';
      let topScore = 0;
      for (const [tName, sc] of cScores.entries()) {
        if (sc > topScore) {
          topScore = sc;
          topTool = tName;
        }
      }
      if (topTool && topScore >= 1.5 && !clauseWinners.some((cw) => cw.toolName === topTool)) {
        clauseWinners.push({ toolName: topTool, clauseScore: topScore });
      }
    }

    const queryTermSet = new Set(queryTerms);
    const extractedGivenSet = new Set(extractedGiven);
    const combinedScores = new Map();
    for (const node of graph.nodes) {
      if (allowedComponent && node.component !== allowedComponent) continue;
      let bm25 = fullScores.get(node.name) || 0;
      if (
        bm25 > 0 &&
        node.produces.length > 0 &&
        node.produces.every((p) => extractedGivenSet.has(p))
      ) {
        const nameTokens = tokenizeTerms(
          node.name.includes('.') ? node.name.split('.').slice(1).join('_') : node.name
        );
        const hasExplicitProducerVerbInQuery = nameTokens.some(
          (tok) => PRODUCER_VERBS.has(tok) && queryTermSet.has(tok)
        );
        if (!hasExplicitProducerVerbInQuery) {
          bm25 *= 0.3;
        }
      }
      const learned = intentBoostByTool.get(node.name) || 0;
      const total = bm25 + learned * 1.6;
      if (total > 0) {
        combinedScores.set(node.name, total);
      }
    }

    const clauseLeadSet = new Set(clauseWinners.map((c) => c.toolName));
    const rankedPrimaryNames = Array.from(combinedScores.keys()).sort((a, b) => {
      const scoreDiff = (combinedScores.get(b) || 0) - (combinedScores.get(a) || 0);
      if (Math.abs(scoreDiff) > 1e-9) return scoreDiff;
      return a.localeCompare(b);
    });

    const prioritizedCandidates = [];
    const seenCandidates = new Set();
    for (const cw of clauseWinners.sort((a, b) => (combinedScores.get(b.toolName) || 0) - (combinedScores.get(a.toolName) || 0))) {
      if (combinedScores.has(cw.toolName) && !seenCandidates.has(cw.toolName)) {
        seenCandidates.add(cw.toolName);
        prioritizedCandidates.push(cw.toolName);
      }
    }
    for (const name of rankedPrimaryNames) {
      if (!seenCandidates.has(name)) {
        seenCandidates.add(name);
        prioritizedCandidates.push(name);
      }
    }

    const selectedMap = new Map();

    const admitBundle = (primaryName, isClauseAnchor) => {
      if (selectedMap.has(primaryName)) return true;
      if (selectedMap.size >= effectiveBudget) return false;

      const chain = resolvePrerequisiteChain(
        primaryName,
        satisfiedTypes,
        combinedScores,
        allowedComponent
      );
      const missingSteps = chain.steps.filter((s) => !selectedMap.has(s.toolName));
      const neededSlots = missingSteps.length + 1;

      if (selectedMap.size + neededSlots > effectiveBudget) {
        if (selectedMap.size === 0) {
          const maxPrereqs = Math.max(0, effectiveBudget - 1);
          for (const step of missingSteps.slice(0, maxPrereqs)) {
            const sNode = graph.nodeByName.get(step.toolName);
            selectedMap.set(step.toolName, {
              node: sNode,
              why: {
                role: 'prerequisite',
                produces: step.produces,
                for: step.forTool,
                depth: step.depth
              }
            });
            for (const pType of sNode.produces) satisfiedTypes.add(pType);
          }
          const pNode = graph.nodeByName.get(primaryName);
          selectedMap.set(primaryName, {
            node: pNode,
            why: {
              role: 'match',
              score: Math.round((combinedScores.get(primaryName) || 0) * 1000) / 1000,
              matchedTerms: matchedTermsByTool.get(primaryName) || [],
              intentBoost: Math.round((intentBoostByTool.get(primaryName) || 0) * 1000) / 1000,
              clauseAnchor: Boolean(isClauseAnchor)
            }
          });
          for (const pType of pNode.produces) satisfiedTypes.add(pType);
          return true;
        }
        return false;
      }

      for (const step of missingSteps) {
        const sNode = graph.nodeByName.get(step.toolName);
        selectedMap.set(step.toolName, {
          node: sNode,
          why: {
            role: 'prerequisite',
            produces: step.produces,
            for: step.forTool,
            depth: step.depth
          }
        });
        for (const pType of sNode.produces) satisfiedTypes.add(pType);
      }

      const pNode = graph.nodeByName.get(primaryName);
      selectedMap.set(primaryName, {
        node: pNode,
        why: {
          role: 'match',
          score: Math.round((combinedScores.get(primaryName) || 0) * 1000) / 1000,
          matchedTerms: matchedTermsByTool.get(primaryName) || [],
          intentBoost: Math.round((intentBoostByTool.get(primaryName) || 0) * 1000) / 1000,
          clauseAnchor: Boolean(isClauseAnchor)
        }
      });
      for (const pType of pNode.produces) satisfiedTypes.add(pType);
      return true;
    };

    const cutoffRatio = Number.isFinite(cfg.primaryCutoffRatio) ? Number(cfg.primaryCutoffRatio) : 0.55;
    const topPrimaryScore = prioritizedCandidates.length > 0
      ? (combinedScores.get(prioritizedCandidates[0]) || 0)
      : 0;
    const strongMatchFloor = Math.max(1.5, topPrimaryScore * cutoffRatio);

    for (const candName of prioritizedCandidates) {
      if (selectedMap.size >= effectiveBudget) break;
      const sc = combinedScores.get(candName) || 0;
      const isAnchor = clauseLeadSet.has(candName) && sc >= Math.max(1.5, topPrimaryScore * 0.35);
      if (isAnchor || sc >= strongMatchFloor || selectedMap.size === 0) {
        admitBundle(candName, isAnchor);
      }
    }

    let learnedAdded = 0;
    if (selectedMap.size < effectiveBudget && cfg.maxLearnedNextSlots > 0) {
      const learnedCandidates = [];
      for (const anchorName of selectedMap.keys()) {
        const nextMap = nextEdgeStore.get(anchorName);
        if (!nextMap) continue;
        for (const [targetName, weight] of nextMap.entries()) {
          if (weight < cfg.learnedNextThreshold) continue;
          if (selectedMap.has(targetName)) continue;
          const tNode = graph.nodeByName.get(targetName);
          if (!tNode) continue;
          if (allowedComponent && tNode.component !== allowedComponent) continue;
          learnedCandidates.push({ anchorName, targetName, weight });
        }
      }

      learnedCandidates.sort((a, b) => b.weight - a.weight || a.targetName.localeCompare(b.targetName));

      for (const lc of learnedCandidates) {
        if (selectedMap.size >= effectiveBudget || learnedAdded >= cfg.maxLearnedNextSlots) break;
        if (selectedMap.has(lc.targetName)) continue;

        const chain = resolvePrerequisiteChain(
          lc.targetName,
          satisfiedTypes,
          combinedScores,
          allowedComponent
        );
        const missingSteps = chain.steps.filter((s) => !selectedMap.has(s.toolName));
        if (selectedMap.size + missingSteps.length + 1 > effectiveBudget) continue;

        for (const step of missingSteps) {
          const sNode = graph.nodeByName.get(step.toolName);
          selectedMap.set(step.toolName, {
            node: sNode,
            why: {
              role: 'prerequisite',
              produces: step.produces,
              for: step.forTool,
              depth: step.depth
            }
          });
          for (const pType of sNode.produces) satisfiedTypes.add(pType);
        }

        const tNode = graph.nodeByName.get(lc.targetName);
        selectedMap.set(lc.targetName, {
          node: tNode,
          why: {
            role: 'learned_next',
            after: lc.anchorName,
            weight: lc.weight
          }
        });
        for (const pType of tNode.produces) satisfiedTypes.add(pType);
        learnedAdded += 1;
      }
    }

    const selectedEntries = Array.from(selectedMap.values());
    const selectedSchemaBytes = selectedEntries.reduce((sum, e) => sum + e.node.schemaBytes, 0);
    const tokenReductionPct = fullCatalogSchemaBytes > 0
      ? Math.round(((1 - selectedSchemaBytes / fullCatalogSchemaBytes) * 100) * 100) / 100
      : 0;

    const toolsOut = selectedEntries.map(({ node, why }) => ({
      name: node.name,
      component: node.component,
      title: node.title || undefined,
      description: node.description,
      requiredParams: node.requiredParams,
      consumes: getEffectiveConsumes(node),
      produces: node.produces,
      why,
      inputSchema: node.rawTool.inputSchema || { type: 'object', properties: {} }
    }));

    return okEnvelope(
      'tool_graph.find_tools',
      `Selected ${toolsOut.length}/${graph.nodes.length} tools (${tokenReductionPct}% schema byte reduction)`,
      {
        task,
        intentSignature,
        extractedGiven,
        detections,
        budget: effectiveBudget,
        totalCatalogTools: graph.nodes.length,
        selectedTools: toolsOut.map((t) => t.name),
        tools: toolsOut,
        metrics: {
          fullCatalogSchemaBytes,
          selectedSchemaBytes,
          estimatedFullTokens: Math.ceil(fullCatalogSchemaBytes / 4),
          estimatedSelectedTokens: Math.ceil(selectedSchemaBytes / 4),
          schemaReductionPct: tokenReductionPct
        }
      }
    );
  }

  /**
   * Record execution feedback (`success: true | false`) and optional `missingInput` types
   * to update bounded-LRU `SOLVED_WITH`, `NEXT`, and gap-driven prerequisite edges.
   *
   * @param {{ task: string, tools?: string[], success: boolean, missingInput?: string | string[], given?: string[] }} params
   */
  function reportOutcome(params = {}) {
    outcomeCalls += 1;
    const rawTask = typeof params?.task === 'string'
      ? params.task
      : typeof params?.query === 'string'
        ? params.query
        : '';
    const task = rawTask.slice(0, MAX_TASK_CHARS).trim();
    if (!task) {
      return errorEnvelope(
        'EMPTY_TASK',
        'reportOutcome requires a non-empty task description',
        { field: 'task' },
        'tool_graph.report_outcome'
      );
    }

    const executedTools = Array.isArray(params?.tools)
      ? params.tools.map((t) => String(t || '').trim()).filter((t) => graph.nodeByName.has(t))
      : [];
    const success = Boolean(params?.success);
    const { intentSignature } = maskTaskEntities(task);

    let intentEdges = intentSolvedStore.get(intentSignature);
    if (!intentEdges) {
      intentEdges = new Map();
      intentSolvedStore.set(intentSignature, intentEdges);
    }

    const updatedIntentWeights = Object.create(null);
    const updatedNextWeights = Object.create(null);
    const gapProducersBoosted = [];

    if (success) {
      for (let idx = 0; idx < executedTools.length; idx++) {
        const toolName = executedTools[idx];
        const stepScale = idx === 0 ? 1.0 : 0.2;
        const prev = intentEdges.get(toolName) || 0;
        setBoundedEdgeWeight(intentEdges, toolName, prev + cfg.successBoost * stepScale);
        updatedIntentWeights[toolName] = intentEdges.get(toolName) || 0;
      }

      for (let idx = 0; idx < executedTools.length - 1; idx++) {
        const fromTool = executedTools[idx];
        const toTool = executedTools[idx + 1];
        if (fromTool === toTool) continue;
        if (!nextEdgeStore.has(fromTool)) nextEdgeStore.set(fromTool, new Map());
        const nextMap = nextEdgeStore.get(fromTool);
        const prev = nextMap.get(toTool) || 0;
        setBoundedEdgeWeight(nextMap, toTool, prev + cfg.nextBoost);
        updatedNextWeights[`${fromTool}->${toTool}`] = nextMap.get(toTool) || 0;
      }
    } else {
      for (const toolName of executedTools) {
        if (intentEdges.has(toolName)) {
          const prev = intentEdges.get(toolName) || 0;
          setBoundedEdgeWeight(intentEdges, toolName, prev - cfg.failurePenalty);
          updatedIntentWeights[toolName] = intentEdges.get(toolName) || 0;
        }
      }

      for (let idx = 0; idx < executedTools.length - 1; idx++) {
        const fromTool = executedTools[idx];
        const toTool = executedTools[idx + 1];
        const nextMap = nextEdgeStore.get(fromTool);
        if (nextMap && nextMap.has(toTool)) {
          const prev = nextMap.get(toTool) || 0;
          setBoundedEdgeWeight(nextMap, toTool, prev - cfg.failurePenalty * 0.5);
          updatedNextWeights[`${fromTool}->${toTool}`] = nextMap.get(toTool) || 0;
        }
      }

      const rawMissing = Array.isArray(params?.missingInput)
        ? params.missingInput
        : typeof params?.missingInput === 'string' && params.missingInput.trim()
          ? [params.missingInput]
          : [];

      const lastFailedNode = executedTools.length > 0
        ? graph.nodeByName.get(executedTools[executedTools.length - 1])
        : null;
      const fallbackComponent = lastFailedNode ? lastFailedNode.component : 'default';

      for (const rawInput of rawMissing) {
        if (typeof rawInput !== 'string' || !rawInput.trim()) continue;
        const scopedCandidate = qualifyTypeToken(rawInput, fallbackComponent);
        const bareCandidate = normalizeIdentifier(rawInput);
        const matchedType = graph.producersByType.has(scopedCandidate)
          ? scopedCandidate
          : graph.producersByType.has(bareCandidate)
            ? bareCandidate
            : scopedCandidate;

        if (!matchedType) continue;

        if (lastFailedNode && !lastFailedNode.produces.includes(matchedType)) {
          if (!dynamicConsumesStore.has(lastFailedNode.name)) {
            dynamicConsumesStore.set(lastFailedNode.name, new Set());
          }
          const dynSet = dynamicConsumesStore.get(lastFailedNode.name);
          if (dynSet.has(matchedType)) {
            dynSet.delete(matchedType);
          } else if (dynSet.size >= cfg.maxEdgesPerNode) {
            const oldestKey = dynSet.values().next().value;
            if (oldestKey !== undefined) dynSet.delete(oldestKey);
          }
          dynSet.add(matchedType);
        }

        const producers = graph.producersByType.get(matchedType) || [];
        for (const prodName of producers) {
          if (executedTools.includes(prodName)) continue;
          const prev = intentEdges.get(prodName) || 0;
          setBoundedEdgeWeight(intentEdges, prodName, prev + cfg.gapBoost);
          updatedIntentWeights[prodName] = intentEdges.get(prodName) || 0;
          gapProducersBoosted.push({ missingType: matchedType, producer: prodName, weight: intentEdges.get(prodName) || 0 });
        }
      }
    }

    if (intentEdges.size === 0) {
      intentSolvedStore.delete(intentSignature);
    }

    return okEnvelope(
      'tool_graph.report_outcome',
      success
        ? `Reinforced ${executedTools.length} tool(s) for intent ${intentSignature}`
        : `Recorded failure feedback for intent ${intentSignature} (${gapProducersBoosted.length} gap producer(s) boosted)`,
      {
        intentSignature,
        success,
        tools: executedTools,
        updatedIntentWeights: { ...updatedIntentWeights },
        updatedNextWeights: { ...updatedNextWeights },
        gapProducersBoosted
      }
    );
  }

  /**
   * Inspect full JSON Schema, typed `consumes`/`produces` contracts, and learned `NEXT` edges
   * for a single catalog tool on demand.
   *
   * @param {string | { name?: string, tool_name?: string, tool?: string }} toolNameOrObj
   */
  function describeTool(toolNameOrObj) {
    describeCalls += 1;
    const isObj = Boolean(
      toolNameOrObj && typeof toolNameOrObj === 'object' && !Array.isArray(toolNameOrObj)
    );
    const cleanName = isObj
      ? String(toolNameOrObj.name ?? toolNameOrObj.tool_name ?? toolNameOrObj.tool ?? '').trim()
      : String(toolNameOrObj || '').trim();
    const node = graph.nodeByName.get(cleanName);
    if (!node) {
      return errorEnvelope(
        'UNKNOWN_TOOL',
        `Tool not found in ToolGraph catalog: ${cleanName || '<empty>'}`,
        { toolName: cleanName },
        'tool_graph.describe_tool'
      );
    }

    const nextMap = nextEdgeStore.get(cleanName);
    const learnedNext = nextMap
      ? Array.from(nextMap.entries())
        .map(([name, weight]) => ({ name, weight }))
        .sort((a, b) => b.weight - a.weight || a.name.localeCompare(b.name))
      : [];

    return okEnvelope(
      'tool_graph.describe_tool',
      `Loaded full schema and dependency contract for ${node.name}`,
      {
        name: node.name,
        component: node.component,
        title: node.title || undefined,
        description: node.description,
        consumes: getEffectiveConsumes(node),
        produces: node.produces,
        capabilities: node.capabilities,
        learnedNext,
        inputSchema: node.rawTool.inputSchema || { type: 'object', properties: {} },
        annotations: node.rawTool.annotations || undefined
      }
    );
  }

  const META_TOOL_NAMES = new Set([
    'find_tools',
    'describe_tool',
    'call_tool',
    'report_tool_outcome'
  ]);

  /**
   * Execute a deferred tool by name through the registered handler map or fallback dispatcher
   * while blocking recursive meta-tool invocation loops.
   *
   * @param {string | { name?: string, tool_name?: string, tool?: string, arguments?: Record<string, any>, args?: Record<string, any> }} toolNameOrObj
   * @param {Record<string, any>} [args={}]
   */
  async function callTool(toolNameOrObj, args = {}) {
    executeCalls += 1;
    const isObjCall = Boolean(
      toolNameOrObj && typeof toolNameOrObj === 'object' && !Array.isArray(toolNameOrObj)
    );
    const cleanName = isObjCall
      ? String(toolNameOrObj.name ?? toolNameOrObj.tool_name ?? toolNameOrObj.tool ?? '').trim()
      : String(toolNameOrObj || '').trim();
    const rawArgs = isObjCall
      ? (toolNameOrObj.arguments ?? toolNameOrObj.args ?? {})
      : args;
    const safeArgs = rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs) ? rawArgs : {};

    if (META_TOOL_NAMES.has(cleanName)) {
      return errorEnvelope(
        'RECURSIVE_META_TOOL_CALL',
        `Meta-tool "${cleanName}" cannot be invoked recursively through call_tool`,
        { toolName: cleanName },
        'tool_graph.call_tool'
      );
    }

    const node = graph.nodeByName.get(cleanName);
    if (!node) {
      return errorEnvelope(
        'UNKNOWN_TOOL',
        `Tool not found in ToolGraph catalog: ${cleanName || '<empty>'}`,
        { toolName: cleanName },
        'tool_graph.call_tool'
      );
    }

    const handler = isSafeKey(cleanName) ? handlers[cleanName] : undefined;
    if (typeof handler !== 'function' && !dispatcher) {
      return errorEnvelope(
        'MISSING_TOOL_HANDLER',
        `No execution handler registered for tool: ${cleanName}`,
        { toolName: cleanName },
        'tool_graph.call_tool'
      );
    }

    try {
      if (typeof handler === 'function') {
        const result = await handler(safeArgs);
        return okEnvelope(
          'tool_graph.call_tool',
          `Executed deferred tool ${cleanName}`,
          {
            toolName: cleanName,
            result
          }
        );
      }

      const result = await dispatcher(cleanName, safeArgs);
      if (
        result &&
        typeof result === 'object' &&
        !Array.isArray(result) &&
        typeof result.ok === 'boolean' &&
        typeof result.tool === 'string' &&
        typeof result.summary === 'string'
      ) {
        return result.data !== undefined || result.error !== undefined
          ? result
          : { ...result, data: {} };
      }
      return okEnvelope(
        'tool_graph.call_tool',
        `Executed deferred tool ${cleanName}`,
        {
          toolName: cleanName,
          result
        }
      );
    } catch (err) {
      return errorEnvelope(
        'TOOL_EXECUTION_FAILED',
        err instanceof Error ? err.message : String(err),
        { toolName: cleanName },
        'tool_graph.call_tool'
      );
    }
  }

  /**
   * Return the compact Turn-0 exposed MCP tool surface (`alwaysLoaded` + ToolGraph meta-tools)
   * with full `INV-STACK-03` 4-boolean MCP annotations and titles.
   */
  function getExposedTools() {
    const pinned = graph.nodes
      .filter((n) => alwaysLoadedNames.has(n.name))
      .map((n) => n.rawTool);

    const metaTools = [
      {
        name: 'find_tools',
        description: 'Route a single- or multi-step task to a minimal, prerequisite-complete subset of MCP tools.',
        annotations: {
          title: 'Find Prerequisite-Complete Tools',
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false
        },
        inputSchema: {
          type: 'object',
          properties: {
            task: { type: 'string', description: 'Natural-language task or sub-goal to route.' },
            given: {
              type: 'array',
              items: { type: 'string' },
              description: 'Optional data types or parameter names already known in context.'
            },
            budget: { type: 'integer', minimum: 1, maximum: 64, description: 'Maximum tools to return.' },
            component: { type: 'string', description: 'Optional server/component filter.' }
          },
          required: ['task']
        }
      },
      {
        name: 'describe_tool',
        description: 'Fetch full JSON Schema, typed prerequisite inputs/outputs, and learned follow-up tools for a named tool.',
        annotations: {
          title: 'Describe Tool Schema & Dependencies',
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false
        },
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Exact tool name returned by find_tools.' }
          },
          required: ['name']
        }
      },
      {
        name: 'call_tool',
        description: 'Invoke a deferred tool by name with validated JSON arguments.',
        annotations: {
          title: 'Invoke Deferred Tool',
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: false,
          openWorldHint: true
        },
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Exact deferred tool name to invoke.' },
            arguments: { type: 'object', description: 'Arguments matching the tool inputSchema.' }
          },
          required: ['name']
        }
      }
    ];

    if (cfg.exposeOutcomeTool) {
      metaTools.push({
        name: 'report_tool_outcome',
        description: 'Report whether a routed tool sequence succeeded or failed due to a missing prerequisite input.',
        annotations: {
          title: 'Report Tool Execution Outcome',
          readOnlyHint: false,
          destructiveHint: false,
          idempotentHint: false,
          openWorldHint: false
        },
        inputSchema: {
          type: 'object',
          properties: {
            task: { type: 'string' },
            tools: { type: 'array', items: { type: 'string' } },
            success: { type: 'boolean' },
            missingInput: { type: 'array', items: { type: 'string' } }
          },
          required: ['task', 'success']
        }
      });
    }

    return [...pinned, ...metaTools];
  }

  /**
   * Export deterministic JSON-serializable learned graph state (`SOLVED_WITH`, `NEXT`,
   * and gap-discovered `dynamicConsumes`).
   */
  function exportState() {
    const intents = [];
    for (const [intentSignature, edgeMap] of intentSolvedStore.entries()) {
      intents.push({
        intentSignature,
        weights: Object.fromEntries(edgeMap.entries())
      });
    }

    const nextEdges = Object.create(null);
    for (const [fromTool, edgeMap] of nextEdgeStore.entries()) {
      if (edgeMap.size > 0) {
        nextEdges[fromTool] = Object.fromEntries(edgeMap.entries());
      }
    }

    const dynamicConsumes = Object.create(null);
    for (const [toolName, typeSet] of dynamicConsumesStore.entries()) {
      if (typeSet.size > 0) {
        dynamicConsumes[toolName] = Array.from(typeSet);
      }
    }

    return okEnvelope(
      'tool_graph.export_state',
      `Exported ToolGraph state (${intents.length} intent(s), ${Object.keys(nextEdges).length} NEXT source(s))`,
      {
        version: 1,
        intents,
        nextEdges: { ...nextEdges },
        dynamicConsumes: { ...dynamicConsumes }
      }
    );
  }

  /**
   * Restore learned graph state from a snapshot previously returned by `exportState()`.
   *
   * @param {Record<string, any>} snapshot
   */
  function importState(snapshot) {
    const payload = snapshot?.ok === true && snapshot?.data ? snapshot.data : snapshot;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return errorEnvelope(
        'INVALID_SNAPSHOT',
        'importState requires a valid state snapshot object',
        null,
        'tool_graph.import_state'
      );
    }

    intentSolvedStore.clear();
    nextEdgeStore.clear();
    dynamicConsumesStore.clear();

    let importedIntents = 0;
    if (Array.isArray(payload.intents)) {
      for (const entry of payload.intents.slice(-maxIntents)) {
        if (!entry || typeof entry !== 'object') continue;
        const sig = String(entry.intentSignature || '').trim();
        if (!isSafeKey(sig) || !entry.weights || typeof entry.weights !== 'object') continue;
        const edgeMap = new Map();
        for (const [toolName, weight] of Object.entries(entry.weights)) {
          if (!graph.nodeByName.has(toolName)) continue;
          const num = Number(weight);
          if (Number.isFinite(num) && num > minWeight) {
            setBoundedEdgeWeight(edgeMap, toolName, num);
          }
        }
        if (edgeMap.size > 0) {
          intentSolvedStore.set(sig, edgeMap);
          importedIntents += 1;
        }
      }
    }

    let importedNextEdges = 0;
    if (payload.nextEdges && typeof payload.nextEdges === 'object' && !Array.isArray(payload.nextEdges)) {
      for (const [fromTool, targets] of Object.entries(payload.nextEdges)) {
        if (!graph.nodeByName.has(fromTool) || !targets || typeof targets !== 'object') continue;
        const edgeMap = new Map();
        for (const [toTool, weight] of Object.entries(targets)) {
          if (!graph.nodeByName.has(toTool) || toTool === fromTool) continue;
          const num = Number(weight);
          if (Number.isFinite(num) && num > minWeight) {
            setBoundedEdgeWeight(edgeMap, toTool, num);
            importedNextEdges += 1;
          }
        }
        if (edgeMap.size > 0) {
          nextEdgeStore.set(fromTool, edgeMap);
        }
      }
    }

    if (payload.dynamicConsumes && typeof payload.dynamicConsumes === 'object' && !Array.isArray(payload.dynamicConsumes)) {
      for (const [toolName, types] of Object.entries(payload.dynamicConsumes)) {
        if (!graph.nodeByName.has(toolName) || !Array.isArray(types)) continue;
        const set = new Set();
        for (const t of types) {
          if (set.size >= cfg.maxEdgesPerNode) break;
          const norm = typeof t === 'string' ? t.trim() : '';
          if (isSafeKey(norm)) set.add(norm);
        }
        if (set.size > 0) dynamicConsumesStore.set(toolName, set);
      }
    }

    return okEnvelope(
      'tool_graph.import_state',
      `Imported ${importedIntents} intent(s) and ${importedNextEdges} NEXT edge(s)`,
      {
        importedIntents,
        importedNextEdges,
        dynamicConsumesCount: dynamicConsumesStore.size
      }
    );
  }

  function resetState() {
    intentSolvedStore.clear();
    nextEdgeStore.clear();
    dynamicConsumesStore.clear();
    return okEnvelope('tool_graph.reset_state', 'Cleared learned ToolGraph state', { cleared: true });
  }

  function getStats() {
    const exposed = getExposedTools();
    const exposedBytes = Buffer.byteLength(JSON.stringify(exposed), 'utf8');
    const surfaceReductionPct = fullCatalogSchemaBytes > 0
      ? Math.round(((1 - exposedBytes / fullCatalogSchemaBytes) * 100) * 100) / 100
      : 0;

    let totalNextEdges = 0;
    for (const m of nextEdgeStore.values()) totalNextEdges += m.size;

    return {
      totalCatalogTools: graph.nodes.length,
      exposedToolCount: exposed.length,
      typedProducerTypes: graph.producersByType.size,
      typedConsumerTypes: graph.consumersByType.size,
      learnedIntentCount: intentSolvedStore.size,
      maxIntents,
      learnedNextEdgeCount: totalNextEdges,
      dynamicConsumesCount: dynamicConsumesStore.size,
      fullCatalogSchemaBytes,
      exposedSchemaBytes: exposedBytes,
      surfaceReductionPct,
      calls: {
        findTools: findCalls,
        reportOutcome: outcomeCalls,
        describeTool: describeCalls,
        callTool: executeCalls
      }
    };
  }

  return {
    findTools,
    routeTools: findTools,
    reportOutcome,
    describeTool,
    callTool,
    getExposedTools,
    exportState,
    importState,
    resetState,
    getStats,
    schema: {
      nodes: graph.nodes,
      producersByType: Object.fromEntries(graph.producersByType.entries()),
      consumersByType: Object.fromEntries(graph.consumersByType.entries())
    }
  };
}

export const createToolGraphRouter = createToolGraph;
export const createToolGraphEngine = createToolGraph;
