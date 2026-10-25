/**
 * @module engines/context-lexical
 * Domain-agnostic lexical tokenization, morphological stemming, FNV-1a hashing,
 * and token budget estimation helpers for KruschStack Tier 1 Context Engine.
 */

export const CHARS_PER_ESTIMATED_TOKEN = 4;

export function fnv1a32(str = '') {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36);
}

export const STOP_WORDS = new Set([
  'what', 'where', 'when', 'which', 'who', 'whom', 'whose', 'why', 'how',
  'does', 'did', 'the', 'and', 'for', 'with', 'from', 'that', 'this',
  'these', 'those', 'are', 'was', 'were', 'been', 'being', 'have', 'has',
  'had', 'you', 'your', 'yours', 'yourself', 'myself', 'ourselves',
  'our', 'their', 'there', 'they', 'them', 'him', 'her', 'its',
  'about', 'into', 'onto', 'upon',
  'can', 'could', 'would', 'should', 'will', 'shall', 'may', 'might',
  'tell', 'show', 'give', 'find', 'get', 'list'
]);

export const TEMPORAL_CUE_WORDS = new Set([
  'before', 'prior', 'previous', 'previously', 'original', 'originally',
  'initial', 'initially', 'first', 'history', 'historical', 'timeline',
  'chronological', 'chronologically', 'order', 'ordered', 'sequence',
  'evolution', 'supersede', 'superseded', 'formerly', 'migrated',
  'changed', 'current', 'currently', 'now', 'latest', 'today', 'active',
  'across', 'sessions', 'session', 'step', 'steps', 'after', 'since'
]);

export const GENERIC_INFRA_WORDS = new Set([
  'policy', 'rule', 'rules', 'system', 'service', 'project', 'server',
  'node', 'nodes', 'port', 'version', 'config', 'configuration', 'setting',
  'settings', 'status', 'mode', 'default', 'cluster', 'data', 'use',
  'used', 'using', 'uses', 'run', 'running', 'runs', 'set', 'value',
  'exactly', 'strictly', 'only', 'just', 'about', 'around', 'roughly',
  'approximately', 'nearly', 'almost', 'least', 'most', 'more', 'less',
  'over', 'under', 'than', 'remain', 'remains', 'each', 'every'
]);

export const TECH_TWO_CHAR_TOKENS = new Set([
  'db', 'ip', 'ui', 'ci', 'cd', 'os', 'ha', 'io', 'vm', 'gc', 'pr', 'qa', 'ai', 'ml', 'id'
]);

export const META_QUERY_WORDS = new Set([
  'many', 'much', 'want', 'wanted', 'trying', 'try', 'tried', 'make', 'made',
  'sure', 'need', 'needed', 'help', 'helped', 'implement', 'implemented',
  'implementing', 'feature', 'features', 'aspect', 'aspects', 'conversation',
  'conversations', 'discussion', 'discussions', 'throughout', 'mention',
  'mentioned', 'items', 'item', 'summary', 'summarize', 'comprehensive',
  'progressed', 'progress', 'handled', 'handle', 'handling', 'suggest',
  'suggested', 'take', 'taken', 'looking', 'planning', 'plan', 'planned',
  'bring', 'brought', 'different', 'various', 'overall', 'consider',
  'considering', 'based', 'specific', 'specifically', 'provide', 'provided',
  'walk', 'through', 'explain', 'explained', 'approach', 'approached',
  'work', 'worked', 'working', 'develop', 'developing', 'development',
  'developed', 'far', 'time', 'times', 'recommend', 'recommended', 'passed',
  'between', 'ever'
]);

export const DIRECTIVE_REGEX = /\b(always|never|make sure to|please remember to|from now on|every time|whenever you|be sure to|don't ever|do not ever|remember that i want you to|i prefer|my preference|i like to|i'd rather|i would rather|i always use|i usually prefer|i'm a fan of|i tend to prefer|keep .* lightweight|minimal dependencies|favor .* over)\b/i;

const STEM_CACHE = new Map();

/**
 * Normalizes a lowercase token to its morphological stem so singular/plural and verb inflections match.
 * @param {string} word
 * @returns {string}
 */
export function stemToken(word) {
  const w = String(word || '').toLowerCase();
  if (w.length <= 3) return w;
  const cached = STEM_CACHE.get(w);
  if (cached !== undefined) return cached;
  let res = w;
  if (w.endsWith('ies') && w.length > 4) res = w.slice(0, -3) + 'y';
  else if (w.endsWith('ing') && w.length > 5) res = w.slice(0, -3).replace(/(.)\1$/, '$1');
  else if (w.endsWith('ed') && w.length > 4) res = w.slice(0, -2).replace(/(.)\1$/, '$1');
  else if (
    w.endsWith('es') &&
    w.length > 4 &&
    !w.endsWith('tes') &&
    !w.endsWith('les') &&
    !w.endsWith('res') &&
    !w.endsWith('ves')
  ) {
    res = w.slice(0, -2);
  } else if (w.endsWith('s') && !w.endsWith('ss') && !w.endsWith('us') && !w.endsWith('is')) {
    res = w.slice(0, -1);
  }
  if (res.length > 4 && res.endsWith('e') && !res.endsWith('ee')) {
    res = res.slice(0, -1);
  }
  if (STEM_CACHE.size < 30000) STEM_CACHE.set(w, res);
  return res;
}

/**
 * Detects whether a query asks about temporal history, superseded states, chronological ordering, or multi-session progression.
 * @param {string} query
 * @returns {boolean}
 */
export function isTemporalOrLineageQuery(query) {
  if (!query || typeof query !== 'string') return false;
  return /\b(before|prior|previous|previously|original|originally|initial|initially|first|history|historical|timeline|chronological|chronologically|order|sequence|evolution|supersede|superseded|used\s+to|formerly|migrated\s+from|changed\s+from|when\s+did|what\s+was|over\s+time|across\s+sessions|across\s+my|throughout\s+our|summary|summarize|progressed|evolved|step\s+by\s+step)\b/i.test(query);
}

/**
 * Extracts normalized query terms and distinctive domain terms from a cleaned query.
 * @param {string} lowerQuery
 * @returns {{ queryTerms: string[], domainTerms: string[], distinctiveTerms: string[] }}
 */
export function extractQueryTokens(lowerQuery) {
  const rawTokens = String(lowerQuery || '')
    .toLowerCase()
    .split(/[^a-z0-9_.-]+/)
    .map((t) => t.replace(/^[.-]+|[.-]+$/g, ''))
    .filter(
      (t) =>
        t.length > 2 ||
        /^\d+$/.test(t) ||
        /^[a-z]\d+|\d+[a-z]$/i.test(t) ||
        TECH_TWO_CHAR_TOKENS.has(t)
    );

  const uniqueTokens = [...new Set(rawTokens)];
  const queryTerms = uniqueTokens.filter((t) => !STOP_WORDS.has(t));
  const nonTemporal = queryTerms.filter((t) => !TEMPORAL_CUE_WORDS.has(t));
  const nonMeta = nonTemporal.filter((t) => !META_QUERY_WORDS.has(t));
  const domainTerms = nonMeta.length > 0 ? nonMeta : (nonTemporal.length > 0 ? nonTemporal : queryTerms);
  const distinctive = domainTerms.filter((t) => !GENERIC_INFRA_WORDS.has(t));
  const distinctiveTerms = distinctive.length > 0 ? distinctive : domainTerms;

  return { queryTerms, domainTerms, distinctiveTerms };
}

/**
 * Estimates token count for a text string (~4 characters per token).
 * @param {string} text
 * @returns {number}
 */
export function estimateTokens(text) {
  if (!text) return 0;
  return Math.ceil(String(text).length / CHARS_PER_ESTIMATED_TOKEN);
}

/**
 * Checks if an embedding vector is a synthetic constant vector (e.g. new Array(1024).fill(0.05) in unit tests).
 * @param {Array<number>|Float64Array|null} vec
 * @returns {boolean}
 */
export function isSyntheticConstantVector(vec) {
  if (!vec || vec.length < 4) return false;
  const first = vec[0];
  for (let i = 1; i < vec.length; i++) {
    if (Math.abs(first - vec[i]) > 1e-9) return false;
  }
  return true;
}

/**
 * Computes cosine similarity between two numeric arrays or Float64Arrays.
 * @param {Array<number>|Float64Array|null} vecA
 * @param {Array<number>|Float64Array|null} vecB
 * @returns {number}
 */
export function cosineSimilarity(vecA, vecB) {
  if (!vecA || !vecB || !vecA.length || !vecB.length) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  const len = Math.min(vecA.length, vecB.length);
  for (let i = 0; i < len; i++) {
    const a = vecA[i];
    const b = vecB[i];
    dotProduct += a * b;
    normA += a * a;
    normB += b * b;
  }
  if (normA === 0 || normB === 0) return 0;
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

const PARSED_VECTOR_CACHE = new Map();
const MAX_PARSED_VECTOR_CACHE = 4096;

/**
 * Parses and caches a serialized embedding vector string into a Float64Array.
 * @param {string|Array<number>|Float64Array|null} raw
 * @returns {Float64Array|Array<number>|null}
 */
export function parseEmbeddingVector(raw) {
  if (!raw) return null;
  if (ArrayBuffer.isView(raw)) {
    return raw.length > 0 ? raw : null;
  }
  if (Array.isArray(raw)) {
    return raw.length > 0 ? raw : null;
  }
  if (typeof raw !== 'string') return null;

  const cached = PARSED_VECTOR_CACHE.get(raw);
  if (cached) return cached;

  try {
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr) || arr.length === 0) return null;
    const typed = Float64Array.from(arr);
    if (PARSED_VECTOR_CACHE.size >= MAX_PARSED_VECTOR_CACHE) {
      const oldestKey = PARSED_VECTOR_CACHE.keys().next().value;
      if (oldestKey !== undefined) PARSED_VECTOR_CACHE.delete(oldestKey);
    }
    PARSED_VECTOR_CACHE.set(raw, typed);
    return typed;
  } catch {
    return null;
  }
}

/**
 * Validates and serializes a numeric embedding vector for SQLite TEXT persistence.
 * @param {Array<number>|Float64Array|string|null} vec
 * @returns {string|null}
 */
export function serializeEmbeddingVector(vec) {
  if (!vec) return null;
  if (typeof vec === 'string') {
    const parsed = parseEmbeddingVector(vec);
    return parsed ? vec : null;
  }
  if (Array.isArray(vec) || ArrayBuffer.isView(vec)) {
    if (vec.length === 0) return null;
    for (let i = 0; i < vec.length; i++) {
      if (!Number.isFinite(Number(vec[i]))) return null;
    }
    return JSON.stringify(Array.from(vec));
  }
  return null;
}

const LIVE_EMBED_CACHE = new Map();
const MAX_LIVE_EMBED_CACHE = 256;
let lastEmbedFailureAt = 0;
const EMBED_FAILURE_COOLDOWN_MS = 15_000;

export function clearOptionalEmbeddingCache() {
  LIVE_EMBED_CACHE.clear();
  lastEmbedFailureAt = 0;
}

/**
 * Fetches an optional dense embedding from a local Ollama or OpenAI-compatible endpoint.
 * Honors INV-STACK-01: fails fast and silently returns null when offline, ephemeral, or CI=true.
 * @param {string} text
 * @param {object} [options={}]
 * @param {string} [options.endpoint]
 * @param {string} [options.model]
 * @param {number} [options.timeoutMs=1500]
 * @param {boolean} [options.ephemeral=false]
 * @param {boolean} [options.autoEmbed]
 * @returns {Promise<number[]|null>}
 */
export async function fetchOptionalEmbedding(text, options = {}) {
  const trimmed = String(text || '').trim();
  if (!trimmed) return null;

  const explicitEndpoint =
    options.endpoint ||
    process.env.KRUSCH_EMBED_URL ||
    process.env.OLLAMA_EMBED_URL ||
    process.env.EMBEDDING_URL ||
    null;

  if (options.autoEmbed === false || process.env.KRUSCH_DISABLE_EMBEDDINGS === '1') {
    return null;
  }
  if (
    !explicitEndpoint &&
    options.autoEmbed !== true &&
    (options.ephemeral ||
      process.env.KRUSCH_EPHEMERAL === '1' ||
      process.env.CI === 'true' ||
      process.env.CI === '1' ||
      process.env.MOCK_EMBEDDINGS === '1')
  ) {
    return null;
  }

  const baseHost = (process.env.OLLAMA_HOST || 'http://127.0.0.1:11434').replace(/\/+$/, '');
  const endpoint = explicitEndpoint || `${baseHost}/api/embed`;
  const model =
    options.model ||
    process.env.KRUSCH_EMBED_MODEL ||
    process.env.EMBED_MODEL ||
    process.env.EMBEDDING_MODEL ||
    'snowflake-arctic-embed2:latest';
  const truncated = trimmed.slice(0, 1800);
  const cacheKey = `${endpoint}:${model}:${truncated}`;

  if (LIVE_EMBED_CACHE.has(cacheKey)) {
    const val = LIVE_EMBED_CACHE.get(cacheKey);
    LIVE_EMBED_CACHE.delete(cacheKey);
    LIVE_EMBED_CACHE.set(cacheKey, val);
    return val;
  }

  if (!explicitEndpoint && Date.now() - lastEmbedFailureAt < EMBED_FAILURE_COOLDOWN_MS) {
    return null;
  }

  const timeoutMs = Number(options.timeoutMs) > 0 ? Number(options.timeoutMs) : 1500;
  try {
    const isOpenAiCompat = endpoint.includes('/v1/embeddings') || endpoint.includes('openrouter.ai');
    const isLegacyOllama = endpoint.endsWith('/api/embeddings');
    const payload = isLegacyOllama
      ? { model, prompt: truncated, truncate: true }
      : { model, input: truncated };
    const headers = { 'Content-Type': 'application/json' };
    const apiKey = process.env.KRUSCH_EMBED_API_KEY || process.env.EMBEDDING_API_KEY || null;
    if (apiKey) {
      headers.Authorization = `Bearer ${apiKey}`;
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!res.ok) {
      if (!explicitEndpoint) lastEmbedFailureAt = Date.now();
      return null;
    }

    const data = await res.json();
    let vec = null;
    if (Array.isArray(data?.embeddings) && Array.isArray(data.embeddings[0])) {
      vec = data.embeddings[0];
    } else if (Array.isArray(data?.embedding)) {
      vec = data.embedding;
    } else if (isOpenAiCompat && Array.isArray(data?.data?.[0]?.embedding)) {
      vec = data.data[0].embedding;
    }

    if (!Array.isArray(vec) || vec.length === 0) {
      return null;
    }

    if (LIVE_EMBED_CACHE.size >= MAX_LIVE_EMBED_CACHE) {
      const oldestKey = LIVE_EMBED_CACHE.keys().next().value;
      if (oldestKey !== undefined) LIVE_EMBED_CACHE.delete(oldestKey);
    }
    LIVE_EMBED_CACHE.set(cacheKey, vec);
    return vec;
  } catch {
    if (!explicitEndpoint) lastEmbedFailureAt = Date.now();
    return null;
  }
}
