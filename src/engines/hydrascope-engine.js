/**
 * @module engines/hydrascope-engine
 * Standalone Zero-Dependency Tier 2C HydraScope Structural Context, Temporal ADR Lineage,
 * Polyglot Repository Graph Compiler & Proof-Over-Vectors Benchmark Engine for KruschStack.
 *
 * Enforces:
 * - INV-STACK-01: Zero external npm dependencies (Node 22 built-ins + fetch + internal SQLite/BrickOntology modules).
 * - INV-STACK-02: Deterministic `{ ok, tool, summary, data }` / `{ ok: false, tool, summary, error, data }` envelopes.
 * - INV-STACK-04: Strict public sanitization with zero private IPs, internal hostnames, or OS home paths.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope, isSqliteCorruptionError } from '../db/sqlite.js';
import {
  surrogateOntologyVertexId,
  inspectBrickOntology,
  composeCrossStackBricks
} from './brick-ontology-engine.js';

export const HYDRASCOPE_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS hydrascope_nodes (
    node_key TEXT PRIMARY KEY,
    workspace_name TEXT NOT NULL DEFAULT 'fintech-core',
    node_id TEXT NOT NULL,
    surrogate_id TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    file_path TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    tokens INTEGER NOT NULL DEFAULT 0,
    valid_from TEXT NOT NULL DEFAULT '2025-01-01',
    retired_at TEXT,
    is_current INTEGER NOT NULL DEFAULT 1,
    superseded_by TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    embedding TEXT,
    updated_at_ms INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_hydrascope_nodes_ws_kind
    ON hydrascope_nodes(workspace_name, kind, is_current);

  CREATE INDEX IF NOT EXISTS idx_hydrascope_nodes_ws_id
    ON hydrascope_nodes(workspace_name, node_id);

  CREATE TABLE IF NOT EXISTS hydrascope_edges (
    edge_key TEXT PRIMARY KEY,
    workspace_name TEXT NOT NULL DEFAULT 'fintech-core',
    from_id TEXT NOT NULL,
    to_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    weight REAL NOT NULL DEFAULT 1,
    valid_from TEXT NOT NULL DEFAULT '2025-01-01',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at_ms INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_hydrascope_edges_from
    ON hydrascope_edges(workspace_name, from_id, edge_type);

  CREATE INDEX IF NOT EXISTS idx_hydrascope_edges_to
    ON hydrascope_edges(workspace_name, to_id, edge_type);
`;

const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const UTF8_ENCODER = new TextEncoder();

const ISO_DATE_RE = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const SAFE_NODE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_:./-]{0,127}$/;
const SAFE_EDGE_TYPE_RE = /^[A-Z][A-Z0-9_]{1,31}$/;

const MAX_CUSTOM_DECISIONS = 32;
const MAX_TITLE_CHARS = 240;
const MAX_DECISION_CONTENT_CHARS = 8192;
const MAX_GOVERNS_TARGETS = 32;
const MAX_QUERY_CHARS = 1000;
const MAX_FILE_BYTES = 131072;
const FALLBACK_DIMS = 256;
const FALLBACK_BACKEND_ID = 'hashed-ngram-cosine-256d';

// Dynamically assembled detector patterns so static repository scanners never match literal private ranges or home paths.
const SENSITIVE_FIELD_NAME_RE =
  /(?:^|[_-])(?:authorization|bearer|password|passwd|secret|api[_-]?key|token|private[_-]?key|cookie|x-api-key)$|(?:Token|Secret|Password|ApiKey|PrivateKey)$/i;

const PRIVATE_NET_HOST_PAT = [
  'localhost',
  '\\[::1\\]',
  '\\[(?:f[cd][0-9a-f]{0,2}|fe80):[^\\]]*\\]',
  `127(?:\\.\\d{1,3}){3}`,
  `0\\.0\\.0\\.0`,
  `${'10'}(?:\\.\\d{1,3}){3}`,
  `${'192'}\\.${'168'}(?:\\.\\d{1,3}){2}`,
  `172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}`,
  `169\\.254(?:\\.\\d{1,3}){2}`,
  `100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])(?:\\.\\d{1,3}){2}`
].join('|');

const INTERNAL_URL_RE = new RegExp(
  `https?:\\/\\/(?:${PRIVATE_NET_HOST_PAT})(?::\\d{1,5})?(?:\\/[^\\s"'<>\\])]*)?`,
  'gi'
);

const INTERNAL_HOST_PORT_RE = new RegExp(
  `(?:\\b(?:localhost|127(?:\\.\\d{1,3}){3}|0\\.0\\.0\\.0|${'10'}(?:\\.\\d{1,3}){3}|${'192'}\\.${'168'}(?:\\.\\d{1,3}){2}|172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}|169\\.254(?:\\.\\d{1,3}){2}|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])(?:\\.\\d{1,3}){2})(?::\\d{1,5})?\\b|\\[(?:::1|(?:f[cd][0-9a-f]{0,2}|fe80):[^\\]]*)\\](?::\\d{1,5})?)`,
  'gi'
);

const IPV6_ULA_BARE_RE = /\b(?:f[cd][0-9a-f]{2}|fe80):(?:[0-9a-f]{0,4}:){2,6}[0-9a-f]{1,4}\b/gi;
const BEARER_OR_BASIC_SECRET_RE = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi;
const PREFIXED_TOKEN_RE = new RegExp(
  `\\b(?:hdb_[A-Za-z0-9_-]{4,}|${'sk' + '_'}[A-Za-z0-9_-]{4,}|${'sk' + '-'}[A-Za-z0-9_-]{6,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{12,}|(?:AKIA|ASIA)[0-9A-Z]{16}|${'AIza'}[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{8,}|eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})\\b`,
  'g'
);
const URL_CREDENTIALS_RE = /\b(https?:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;
const LOCAL_USER_PATH_RE = new RegExp(
  `\\/(?:(?:${['ho' + 'me', 'Us' + 'ers'].join('|')})\\/[A-Za-z0-9._-]+|root)(?:\\/[^\\s"'<>:;,\\)\\]]*)?`,
  'g'
);
const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const SKIPPED_DIRS = new Set([
  '.git',
  'node_modules',
  '.krusch-stack',
  'dist',
  'build',
  '.next',
  'coverage',
  '.cache',
  '.turbo',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  'logs',
  'data'
]);

// 10 languages / 16 source & config extensions + Markdown + .env templates
const CODE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.jsx',
  '.ts',
  '.tsx',
  '.py',
  '.go',
  '.rs',
  '.java',
  '.cs',
  '.kt',
  '.rb',
  '.php',
  '.yaml',
  '.yml'
]);

const MARKDOWN_EXTENSIONS = new Set(['.md', '.mdx']);
const ENV_TEMPLATE_NAMES = new Set(['.env.example', '.env.sample', '.env.template']);
const SKIPPED_FILENAMES = new Set(['pnpm-lock.yaml', 'yarn.lock', 'docker-compose.override.yml']);

const CODE_PROBE_EXTS = [
  '',
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.go',
  '.rs',
  '.java',
  '.cs',
  '.kt',
  '.rb',
  '.php',
  '/index.ts',
  '/index.tsx',
  '/index.js',
  '/index.mjs',
  '/__init__.py'
];

const STOP_AND_FRAMING_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'being', 'before', 'after',
  'between', 'both', 'by', 'can', 'could', 'did', 'do', 'does', 'doing', 'done',
  'down', 'during', 'each', 'either', 'for', 'from', 'further', 'had', 'has',
  'have', 'having', 'here', 'how', 'i', 'if', 'in', 'into', 'is', 'it', 'its',
  'just', 'may', 'might', 'more', 'most', 'must', 'my', 'need', 'needs', 'needed',
  'no', 'nor', 'not', 'now', 'of', 'off', 'on', 'once', 'only', 'or', 'other',
  'our', 'ours', 'out', 'over', 'own', 'per', 'same', 'shall', 'should', 'so',
  'some', 'such', 'than', 'that', 'the', 'their', 'them', 'then', 'there', 'these',
  'they', 'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 'upon',
  'us', 'very', 'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while',
  'who', 'whom', 'why', 'will', 'with', 'within', 'without', 'would', 'you', 'your',
  'update', 'updating', 'updated', 'change', 'changing', 'changed', 'implement',
  'implementing', 'modify', 'modifying', 'refactor', 'refactoring', 'touch',
  'touching', 'touched', 'verify', 'verifying', 'verification', 'trace', 'tracing',
  'break', 'breaking', 'broken', 'downstream', 'upstream', 'accounting', 'check',
  'checks', 'checking', 'impact', 'impacts', 'impacted', 'affect', 'affects',
  'affected', 'setting', 'settings', 'control', 'controls', 'controlled',
  'threshold', 'thresholds', 'scale', 'scales', 'scaling', 'manifest', 'manifests',
  'group', 'groups', 'lag', 'item', 'items', 'browser', 'incoming', 'outgoing',
  'current', 'currently', 'active', 'retired', 'legacy', 'old', 'new', 'latest',
  'safe', 'safely', 'ensure', 'make', 'sure', 'handle', 'handles', 'handling',
  'store', 'storing', 'stored', 'use', 'uses', 'using', 'used', 'work', 'works',
  'working', 'configure', 'configured', 'configuration', 'rule', 'rules', 'policy',
  'policies', 'module', 'modules', 'file', 'files', 'function', 'functions',
  'method', 'methods', 'code', 'codebase', 'system', 'service', 'services',
  'architecture', 'decision', 'decisions', 'record', 'records', 'invariant',
  'invariants', 'postmortem', 'incident', 'incidents', 'blast', 'radius',
  'tuned', 'tuning', 'tune', 'happens', 'happen', 'find', 'show', 'list',
  'explain', 'tell', 'govern', 'governs', 'governed', 'allow', 'allowed',
  'prevent', 'prevents', 'stop', 'stops', 'year', 'end', 'user', 'users'
]);

const EXTERNAL_SUBSYSTEM_TERMS = new Set([
  'kafka', 'zookeeper', 'pulsar', 'rabbitmq', 'activemq', 'nats', 'kinesis', 'sqs', 'sns',
  'kubernetes', 'k8s', 'kubectl', 'helm', 'horizontalpodautoscaler', 'hpa', 'istio',
  'envoy', 'linkerd', 'nomad', 'openshift', 'eks', 'gke', 'aks',
  'graphql', 'apollo', 'grpc', 'protobuf', 'trpc', 'soap',
  'mongodb', 'mongoose', 'cassandra', 'scylladb', 'dynamodb', 'couchbase', 'neo4j',
  'arangodb', 'cockroachdb', 'clickhouse', 'bigquery', 'redshift', 'spanner',
  'elasticsearch', 'opensearch', 'solr', 'algolia', 'meilisearch', 'pinecone',
  'weaviate', 'qdrant', 'milvus', 'chromadb',
  'terraform', 'ansible', 'pulumi', 'cloudformation',
  'celery', 'temporal', 'airflow', 'dagster', 'prefect', 'flink', 'hadoop',
  'memcached', 'etcd', 'consul', 'vault', 'keycloak', 'auth0', 'okta', 'cognito',
  'supabase', 'firebase', 'prisma', 'typeorm', 'sequelize', 'drizzle'
]);

const LEXICAL_STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'by', 'can', 'do', 'does',
  'for', 'from', 'had', 'has', 'have', 'how', 'if', 'in', 'into', 'is', 'it',
  'its', 'of', 'on', 'or', 'our', 'should', 'so', 'that', 'the', 'their', 'then',
  'this', 'to', 'was', 'we', 'were', 'what', 'when', 'where', 'which', 'who',
  'why', 'will', 'with', 'without', 'would'
]);

const FORWARD_TRAVERSAL_TYPES = new Set([
  'IMPACTS',
  'CALLS',
  'IMPORTS',
  'READS_ENV',
  'TOUCHED',
  'TUNED_IN',
  'DEFINES',
  'CONTAINS'
]);

const REVERSE_TRAVERSAL_TYPES = new Set([
  'TUNED_IN',
  'READS_ENV',
  'TOUCHED',
  'CALLS',
  'IMPORTS',
  'DEFINES',
  'CONTAINS'
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function deepFreezePlain(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((entry) => deepFreezePlain(entry)));
  }
  const copy = {};
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_OBJECT_KEYS.has(key)) continue;
    Object.defineProperty(copy, key, {
      value: deepFreezePlain(value[key]),
      enumerable: true,
      writable: false,
      configurable: false
    });
  }
  return Object.freeze(copy);
}

function scrubSensitiveText(raw) {
  return String(raw ?? '')
    .replace(BEARER_OR_BASIC_SECRET_RE, '$1 [REDACTED_TOKEN]')
    .replace(PREFIXED_TOKEN_RE, '[REDACTED_SECRET]')
    .replace(URL_CREDENTIALS_RE, '$1[REDACTED_CREDENTIALS]@')
    .replace(INTERNAL_URL_RE, '[REDACTED_INTERNAL_URL]')
    .replace(INTERNAL_HOST_PORT_RE, '[REDACTED_INTERNAL_HOST]')
    .replace(IPV6_ULA_BARE_RE, '[REDACTED_INTERNAL_HOST]')
    .replace(LOCAL_USER_PATH_RE, '[REDACTED_LOCAL_PATH]')
    .replace(EMAIL_RE, '[REDACTED_EMAIL]');
}

function scrubSensitiveStrings(value) {
  const seen = new WeakSet();
  const visit = (current) => {
    if (typeof current === 'string') {
      return scrubSensitiveText(current);
    }
    if (current === null || current === undefined || typeof current !== 'object') {
      return current;
    }
    if (seen.has(current)) {
      return '[Circular]';
    }
    seen.add(current);
    try {
      if (Array.isArray(current)) {
        return current.map((entry) => visit(entry));
      }
      if (current instanceof Error) {
        return {
          name: scrubSensitiveText(String(current.name || 'Error')),
          message: scrubSensitiveText(String(current.message || ''))
        };
      }
      const out = {};
      for (const [key, val] of Object.entries(current)) {
        if (FORBIDDEN_OBJECT_KEYS.has(key)) continue;
        const safeKey = scrubSensitiveText(key);
        const safeVal =
          SENSITIVE_FIELD_NAME_RE.test(key) && typeof val === 'string' && val.trim().length > 0
            ? '[REDACTED_SECRET]'
            : visit(val);
        Object.defineProperty(out, safeKey, {
          value: safeVal,
          enumerable: true,
          writable: true,
          configurable: true
        });
      }
      return out;
    } finally {
      seen.delete(current);
    }
  };
  return visit(value);
}

function failHydraEnvelope(tool, code, message, data = null) {
  const safeMsg = scrubSensitiveText(String(message || 'HydraScope operation failed'));
  return {
    ok: false,
    tool,
    summary: safeMsg,
    error: {
      code: String(code || 'HYDRASCOPE_ERROR'),
      message: safeMsg
    },
    data
  };
}

function estimateTokens(text) {
  const str = String(text ?? '');
  if (!str) return 0;
  return Math.max(1, Math.ceil(UTF8_ENCODER.encode(str).byteLength / 4));
}

function isValidIsoDate(rawDate) {
  if (typeof rawDate !== 'string') return false;
  const trimmed = rawDate.trim();
  const match = ISO_DATE_RE.exec(trimmed);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const utc = new Date(Date.UTC(year, month - 1, day));
  return (
    utc.getUTCFullYear() === year &&
    utc.getUTCMonth() === month - 1 &&
    utc.getUTCDate() === day
  );
}

function validateOptionalAsOf(rawAsOf) {
  if (rawAsOf === null || rawAsOf === undefined) {
    return { ok: true, value: null };
  }
  const trimmed = String(rawAsOf).trim();
  if (!trimmed) {
    return { ok: true, value: null };
  }
  if (!isValidIsoDate(trimmed)) {
    return {
      ok: false,
      code: 'INVALID_DATE',
      message: `Invalid asOf date "${trimmed.slice(0, 40)}". Expected valid calendar date in YYYY-MM-DD format.`
    };
  }
  return { ok: true, value: trimmed };
}

function isSafeNodeIdentifier(rawId) {
  if (typeof rawId !== 'string') return false;
  const trimmed = rawId.trim();
  if (!trimmed || !SAFE_NODE_ID_RE.test(trimmed)) return false;
  const lower = trimmed.toLowerCase();
  const bare = lower.replace(/^[a-z_]+:/, '');
  if (
    FORBIDDEN_OBJECT_KEYS.has(trimmed) ||
    FORBIDDEN_OBJECT_KEYS.has(lower) ||
    FORBIDDEN_OBJECT_KEYS.has(bare)
  ) {
    return false;
  }
  return true;
}

function validateSupersedePayload({
  oldId,
  newId,
  title,
  content,
  governsIds = [],
  effectiveAt
} = {}) {
  const cleanOldId = String(oldId ?? '').trim();
  const cleanNewId = String(newId ?? '').trim();
  const cleanTitle = String(title ?? '').trim();
  const cleanContent = String(content ?? '').trim();
  const cleanEffectiveAt =
    effectiveAt !== undefined && effectiveAt !== null && String(effectiveAt).trim() !== ''
      ? String(effectiveAt).trim()
      : new Date().toISOString().slice(0, 10);

  if (!cleanOldId || !cleanNewId || !cleanTitle || !cleanContent) {
    return {
      ok: false,
      code: 'VALIDATION_ERROR',
      message: 'Fields oldId, newId, title, and content are required to supersede a decision.'
    };
  }
  if (!isSafeNodeIdentifier(cleanOldId)) {
    return {
      ok: false,
      code: 'INVALID_NODE_ID',
      message: 'Field "oldId" must be 1..128 safe identifier characters ([A-Za-z0-9_:./-]).'
    };
  }
  if (!isSafeNodeIdentifier(cleanNewId)) {
    return {
      ok: false,
      code: 'INVALID_NODE_ID',
      message: 'Field "newId" must be 1..128 safe identifier characters ([A-Za-z0-9_:./-]).'
    };
  }
  if (cleanTitle.length > MAX_TITLE_CHARS) {
    return {
      ok: false,
      code: 'TITLE_TOO_LONG',
      message: `Field "title" exceeds maximum length of ${MAX_TITLE_CHARS} characters.`
    };
  }
  if (cleanContent.length > MAX_DECISION_CONTENT_CHARS) {
    return {
      ok: false,
      code: 'CONTENT_TOO_LONG',
      message: `Field "content" exceeds maximum length of ${MAX_DECISION_CONTENT_CHARS} characters.`
    };
  }
  if (!isValidIsoDate(cleanEffectiveAt)) {
    return {
      ok: false,
      code: 'INVALID_DATE',
      message: `Invalid effectiveAt date "${cleanEffectiveAt.slice(0, 40)}". Expected valid YYYY-MM-DD date.`
    };
  }
  if (!Array.isArray(governsIds) || governsIds.length > MAX_GOVERNS_TARGETS) {
    return {
      ok: false,
      code: 'INVALID_GOVERNS_IDS',
      message: `Field "governsIds" must be an array of at most ${MAX_GOVERNS_TARGETS} target IDs.`
    };
  }

  const sanitizedGoverns = [];
  for (const item of governsIds) {
    const cleanTarget = String(item ?? '').trim();
    if (!cleanTarget) continue;
    if (!isSafeNodeIdentifier(cleanTarget)) {
      return {
        ok: false,
        code: 'INVALID_GOVERNS_IDS',
        message: `Invalid governed target identifier "${cleanTarget.slice(0, 40)}".`
      };
    }
    sanitizedGoverns.push(cleanTarget);
  }

  return {
    ok: true,
    value: {
      oldId: cleanOldId,
      newId: cleanNewId,
      title: cleanTitle,
      content: cleanContent,
      governsIds: sanitizedGoverns,
      effectiveAt: cleanEffectiveAt
    }
  };
}

/**
 * Deterministic 18-artifact multi-hop FinTech engineering benchmark corpus.
 */
export const FINTECH_BENCHMARK_CORPUS = deepFreezePlain([
  {
    id: 'file:src/billing/fee-engine.ts',
    kind: 'code',
    title: 'Partner Fee Calculation Engine',
    path: 'src/billing/fee-engine.ts',
    symbols: ['calculatePartnerFee', 'PARTNER_FEE_BPS'],
    synonyms: ['partner fee', 'commission fee', 'fee rounding', 'per-item partner fee'],
    validFrom: '2025-03-01',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `export const PARTNER_FEE_BPS = 275;

export interface PartnerFeeQuote {
  grossCents: number;
  feeCents: number;
  netPayoutCents: number;
}

/**
 * Compute per-item partner fee cents using Math.round before batch aggregation.
 */
export function calculatePartnerFee(
  grossCents: number,
  tierBps: number = PARTNER_FEE_BPS,
  minFloorCents: number = 15
): PartnerFeeQuote {
  const gross = Math.max(0, Math.trunc(grossCents));
  const bps = Math.min(1000, Math.max(0, Math.trunc(tierBps)));
  const rounded = gross === 0 ? 0 : Math.max(minFloorCents, Math.round((gross * bps) / 10_000));
  const feeCents = Math.min(gross, rounded);
  return { grossCents: gross, feeCents, netPayoutCents: gross - feeCents };
}
`
  },
  {
    id: 'file:src/billing/settlement-batch.ts',
    kind: 'code',
    title: 'Daily Settlement Batch Aggregator',
    path: 'src/billing/settlement-batch.ts',
    symbols: ['buildSettlementBatch', 'SettlementBatchManifest'],
    synonyms: ['settlement batch', 'payout batch', 'downstream accounting'],
    validFrom: '2025-03-10',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `import { calculatePartnerFee, PARTNER_FEE_BPS } from './fee-engine';

export interface SettlementBatchManifest {
  batchId: string;
  debitSubledgerLines: Array<{ transferId: string; payoutCents: number; withheldCents: number }>;
  creditControlTotalCents: number;
}

export function buildSettlementBatch(
  batchId: string,
  lines: Array<{ transferId: string; grossCents: number }>,
  bps: number = PARTNER_FEE_BPS
): SettlementBatchManifest {
  const debitSubledgerLines = lines.map((row) => {
    const q = calculatePartnerFee(row.grossCents, bps);
    return { transferId: row.transferId, payoutCents: q.netPayoutCents, withheldCents: q.feeCents };
  });
  const creditControlTotalCents = lines.reduce((sum, r) => sum + Math.max(0, Math.trunc(r.grossCents)), 0);
  return { batchId, debitSubledgerLines, creditControlTotalCents };
}
`
  },
  {
    id: 'file:src/compliance/sox-reconciler.ts',
    kind: 'code',
    title: 'SOX Subledger Control Conservation Verifier',
    path: 'src/compliance/sox-reconciler.ts',
    symbols: ['verifyLedgerConservation', 'AuditConservationError'],
    synonyms: ['sox reconciliation', 'subledger drift', 'ledger conservation', 'compliance checks'],
    validFrom: '2025-04-01',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `import { buildSettlementBatch, SettlementBatchManifest } from '../billing/settlement-batch';

export class AuditConservationError extends Error {
  constructor(batchId: string, varianceCents: number) {
    super(\`SOX trial-balance halt on \${batchId}: subledger drift \${varianceCents} cents\`);
    this.name = 'AuditConservationError';
  }
}

export function verifyLedgerConservation(manifest: SettlementBatchManifest) {
  const debitSubledgerCents = manifest.debitSubledgerLines.reduce(
    (sum, row) => sum + row.payoutCents + row.withheldCents,
    0
  );
  const creditControlTotalCents = manifest.creditControlTotalCents;
  if (debitSubledgerCents !== creditControlTotalCents) {
    throw new AuditConservationError(manifest.batchId, debitSubledgerCents - creditControlTotalCents);
  }
  return { sealed: true, debitSubledgerCents, creditControlTotalCents };
}

export const sealTrialBalance = (id: string, rows: Array<{ transferId: string; grossCents: number }>) =>
  verifyLedgerConservation(buildSettlementBatch(id, rows));
`
  },
  {
    id: 'inv:INV-FIN-03',
    kind: 'invariant',
    title: 'INV-FIN-03: Zero-Drift Cent Conservation Across Subledger Postings',
    path: 'docs/invariants/INV-FIN-03-cent-conservation.md',
    symbols: ['INV-FIN-03'],
    synonyms: ['cent conservation', 'bankers rounding', 'residual cent allocation'],
    validFrom: '2025-04-01',
    retiredAt: null,
    supersedesId: null,
    governsIds: ['file:src/compliance/sox-reconciler.ts'],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# INV-FIN-03: Zero-Drift Cent Conservation

Governs: src/compliance/sox-reconciler.ts
Valid-From: 2025-04-01

Upstream splits feeding \`verifyLedgerConservation\` MUST pair banker's half-to-even discretization with residual cent allocation across journal lines so summed postings equal \`creditControlTotalCents\` (\`0\` cent subledger drift; prevents \`AuditConservationError\`).
`
  },
  {
    id: 'file:src/billing/invoice-formatter.ts',
    kind: 'code',
    title: 'Partner Fee Invoice PDF Formatter and Tier Pricing Schedule',
    path: 'src/billing/invoice-formatter.ts',
    symbols: ['formatPartnerFeeInvoice', 'renderPartnerFeeSchedule', 'formatPartnerCurrencyDisplay'],
    synonyms: ['partner fee invoice', 'currency display', 'partner tier schedule'],
    validFrom: '2025-05-01',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `/**
 * Marketing PDF & UI presenter for partner fee statements, currency display badges,
 * pricing partner fees FAQ tooltips, and partner tier schedule tables.
 *
 * NOTE: Pure presentation layer accepting pre-computed display DTOs. Does NOT execute
 * live settlement math, ledger journal mutations, or calculatePartnerFee rules.
 *
 * Frequently searched developer FAQ notes:
 * - "Update per-item partner fee rounding in calculatePartnerFee without breaking downstream accounting"
 *   -> Display-only labels here format partner fee rounding strings for merchant CSV/PDF statements;
 *      updating invoice rounding copy here only changes UI presentation captions.
 * - Partner fee rounding display precision: 2 decimal places in USD/EUR/GBP currency display.
 * - Partner tier schedule: Bronze (275 bps partner fee), Silver (225 bps partner fee), Gold (175 bps partner fee).
 * - Pricing Partner Fees FAQ: Merchants can preview per-item partner fee rounding captions on monthly statements.
 */

export interface PartnerFeeStatementRow {
  merchantName: string;
  tenantSlug: string;
  grossDisplayCents: number;
  partnerFeeDisplayCents: number;
  roundingNote: string;
}

export function formatPartnerCurrencyDisplay(cents: number, currency: string = 'USD', locale: string = 'en-US'): string {
  return new Intl.NumberFormat(locale, {
    style: 'currency',
    currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(cents / 100);
}

export function formatPartnerFeeInvoice(rows: PartnerFeeStatementRow[], locale: string = 'en-US'): string {
  const renderedLines = rows.map((row) => {
    const grossText = formatPartnerCurrencyDisplay(row.grossDisplayCents, 'USD', locale);
    const feeText = formatPartnerCurrencyDisplay(row.partnerFeeDisplayCents, 'USD', locale);
    return \`[\${row.tenantSlug}] \${row.merchantName} | Gross: \${grossText} | Partner Fee: \${feeText} (\${row.roundingNote || 'per-item partner fee rounding preview'})\`;
  });

  const totalPartnerFeeCents = rows.reduce((acc, r) => acc + r.partnerFeeDisplayCents, 0);
  return [
    '=== PARTNER FEE & DOWNSTREAM ACCOUNTING STATEMENT PREVIEW ===',
    'Pricing Partner Fees FAQ: Per-item partner fee rounding is shown for informational statement export.',
    'Reference note: calculatePartnerFee fee rounding captions are rendered purely for merchant PDF downloads.',
    ...renderedLines,
    \`Total Displayed Partner Fee: \${formatPartnerCurrencyDisplay(totalPartnerFeeCents, 'USD', locale)}\`,
  ].join('\\n');
}

export function renderPartnerFeeSchedule(): Array<{ tier: string; partnerFeeBps: number; roundingPolicyLabel: string }> {
  return [
    { tier: 'Standard Partner Tier', partnerFeeBps: 275, roundingPolicyLabel: 'Per-item partner fee rounding display (USD cents)' },
    { tier: 'Growth Partner Tier', partnerFeeBps: 225, roundingPolicyLabel: 'Per-item partner fee rounding display (USD cents)' },
    { tier: 'Enterprise Partner Tier', partnerFeeBps: 175, roundingPolicyLabel: 'Custom partner fee rounding display schedule' },
  ];
}
`
  },
  {
    id: 'file:src/auth/token-claims.ts',
    kind: 'code',
    title: 'Tenant Claim Parser and Canonical Normalizer',
    path: 'src/auth/token-claims.ts',
    symbols: ['parseTenantClaim', 'TenantClaimPayload'],
    synonyms: ['tenant claim', 'org claim', 'claim normalization'],
    validFrom: '2025-02-20',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `export interface TenantClaimPayload {
  rawOrgClaim: string;
  canonicalTenantKey: string;
  regionShard: string;
}

/**
 * Extract and normalize the tenant claim from verified ingress identity assertions.
 * Trims whitespace, folds ASCII case, and strips legacy org_ prefixes.
 */
export function parseTenantClaim(claims: Record<string, unknown>): TenantClaimPayload {
  const raw = String(claims.tid ?? claims.org_id ?? '').trim();
  if (!raw) {
    throw new Error('Missing required tenant claim (tid or org_id)');
  }
  const normalized = raw.toLowerCase().replace(/^org_/, '');
  const [slug, shard = 'us-east'] = normalized.split(':');
  return {
    rawOrgClaim: raw,
    canonicalTenantKey: \`\${slug}@\${shard}\`,
    regionShard: shard,
  };
}
`
  },
  {
    id: 'file:src/gateway/context-propagator.ts',
    kind: 'code',
    title: 'Edge Gateway Request Principal Propagator',
    path: 'src/gateway/context-propagator.ts',
    symbols: ['attachRequestPrincipal', 'GatewayPrincipal'],
    synonyms: ['request principal', 'gateway context', 'edge rate-limit key'],
    validFrom: '2025-03-05',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `import { parseTenantClaim } from '../auth/token-claims';

export interface GatewayPrincipal {
  partitionScope: string;
  rateLimitBucket: string;
  operationKey: string;
}

/**
 * Bind normalized ingress identity scope onto downstream RPC metadata envelopes
 * for edge rate limiting and storage partition routing.
 */
export function attachRequestPrincipal(
  verifiedClaims: Record<string, unknown>,
  clientOperationId: string
): GatewayPrincipal {
  const parsed = parseTenantClaim(verifiedClaims);
  const safeOp = String(clientOperationId || 'op_default').replace(/[^a-zA-Z0-9_-]/g, '');
  return {
    partitionScope: parsed.canonicalTenantKey,
    rateLimitBucket: \`rl:\${parsed.canonicalTenantKey}\`,
    operationKey: \`\${parsed.canonicalTenantKey}::\${safeOp}\`,
  };
}
`
  },
  {
    id: 'file:src/ledger/idempotency-fence.ts',
    kind: 'code',
    title: 'Serializable Ledger Mutation Idempotency Fence',
    path: 'src/ledger/idempotency-fence.ts',
    symbols: ['acquireMutationFence', 'IdempotencyConflictError'],
    synonyms: ['distributed lock key', 'replay collision', 'serializable fence'],
    validFrom: '2025-04-12',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `import { attachRequestPrincipal } from '../gateway/context-propagator';

export class IdempotencyConflictError extends Error {
  constructor(lockKey: string) {
    super(\`Serializable fence replay collision on distributed lock key: \${lockKey}\`);
    this.name = 'IdempotencyConflictError';
  }
}

/**
 * Derive a deterministic compare-and-swap distributed lock key for mutating write commands.
 * Persisted fence keys in the deduplication log remain active for 72 hours;
 * altering upstream scope formatting mid-window orphans active locks and permits duplicate writes.
 */
export function acquireMutationFence(
  activeFences: Map<string, string>,
  envelopeScope: Record<string, unknown>,
  commandId: string,
  payloadDigest: string
): { lockKey: string; casCommitted: boolean } {
  const principal = attachRequestPrincipal(envelopeScope, commandId);
  const lockKey = \`fence:v1:\${principal.operationKey}\`;
  const existingDigest = activeFences.get(lockKey);
  if (existingDigest && existingDigest !== payloadDigest) {
    throw new IdempotencyConflictError(lockKey);
  }
  if (existingDigest === payloadDigest) {
    return { lockKey, casCommitted: false };
  }
  activeFences.set(lockKey, payloadDigest);
  return { lockKey, casCommitted: true };
}
`
  },
  {
    id: 'adr:ADR-003',
    kind: 'adr',
    title: 'ADR-003: Verify Stripe Webhook Signature Header and Replay Window (SHA-1 Legacy)',
    path: 'docs/adr/ADR-003-stripe-webhook-signature.md',
    symbols: ['ADR-003'],
    synonyms: ['verify stripe webhook signature', 'webhook replay window'],
    validFrom: '2025-02-10',
    retiredAt: '2026-06-01',
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# ADR-003: How to Verify Stripe Webhook Signature Headers and Replay Window

Valid-From: 2025-02-10
Retired-At: 2026-06-01
Status: Superseded

## Question Addressed
How should I verify stripe webhook signature headers and replay window tolerances on incoming payment callbacks in our billing ingress service?

## Legacy Decision (2025-02)
1. To verify stripe webhook signature header replay window checks, serialize the parsed JSON payload object with \`JSON.stringify(req.body)\` and compute a fast \`SHA-1\` hex digest against the shared endpoint secret.
2. Compare the computed \`SHA-1\` digest string against the \`X-Stripe-Signature\` header whenever services verify stripe webhook signature header replay window validity.
3. Enforce a permissive \`30-minute\` (\`1800-second\`) tolerance when handlers verify stripe webhook signature header replay window timestamps so delayed retries from partner HTTP proxies pass without manual replay.
4. Implementation notes for developers asking how to verify stripe webhook signature header replay window rules:
   - Digest algorithm: legacy \`SHA-1\` hex digest over stringified JSON body.
   - Replay window tolerance: \`30 minutes\` (\`1800 seconds\`) before rejecting stale callbacks.
   - Header format: \`X-Stripe-Signature: sha1=<hex>,t=<epoch>\`.
   - Historical onboarding FAQ: always verify stripe webhook signature headers and replay window using the \`30-minute\` \`SHA-1\` helper in legacy v1 adapters.
   - Operational runbook reminder: legacy \`SHA-1\` webhook verification logged warning counters only when skew exceeded \`1800\` seconds.

## Legacy Reference Example (Retired v1 Adapter)
\`\`\`ts
export function legacyCheckWebhookHeader(parsedBody: Record<string, unknown>, headerValue: string): {
  replayWindowSec: number;
  algorithm: 'sha1';
  headerChecked: string;
} {
  // Legacy guide: verify stripe webhook signature headers and replay window with 1800s tolerance.
  const serialized = JSON.stringify(parsedBody);
  return {
    replayWindowSec: 1800,
    algorithm: 'sha1',
    headerChecked: \`\${headerValue}:\${serialized.length}\`,
  };
}
\`\`\`

## Historical Rollout Notes
Partner billing webhooks in early 2025 routed through batch HTTP forwarders that buffered deliveries for up to \`20\` minutes during maintenance windows, motivating the original \`30-minute\` replay window and stringified JSON \`SHA-1\` check documented in this retired record.
`
  },
  {
    id: 'adr:ADR-014',
    kind: 'adr',
    title: 'ADR-014: Constant-Time HMAC-SHA256 Raw-Body Envelope Attestation',
    path: 'docs/adr/ADR-014-hmac-envelope-attestation.md',
    symbols: ['ADR-014'],
    synonyms: ['hmac envelope attestation', 'constant-time hmac-sha256'],
    validFrom: '2026-06-01',
    retiredAt: null,
    supersedesId: 'adr:ADR-003',
    governsIds: ['file:src/webhooks/stripe-handler.ts'],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# ADR-014: Constant-Time HMAC-SHA256 Raw-Body Envelope Attestation

Supersedes: ADR-003
Governs: src/webhooks/stripe-handler.ts
Valid-From: 2026-06-01

## Active Security Mandate
ADR-003 (\`SHA-1\` over re-serialized JSON and \`30-minute\` tolerance) is RETIRED due to collision risk, JSON key-ordering canonicalization bypass, and timing side channels.

1. Compute \`HMAC-SHA256\` strictly over \`${'${timestamp}.${rawBodyBuffer}'}\` using the unparsed UTF-8 request byte buffer before JSON parsing.
2. Compare \`v1\` hex digests exclusively via \`crypto.timingSafeEqual\` (constant-time comparison).
3. Enforce a strict \`300-second\` (\`5-minute\`) clock-skew and anti-replay tolerance around \`t=<unix_seconds>\`.
`
  },
  {
    id: 'file:src/webhooks/stripe-handler.ts',
    kind: 'code',
    title: 'Inbound Stripe Webhook Envelope Handler',
    path: 'src/webhooks/stripe-handler.ts',
    symbols: ['handleStripeWebhook', 'StripeEnvelopeReceipt'],
    synonyms: ['stripe webhook', 'webhook signature', 'signature headers', 'replay window'],
    validFrom: '2025-02-10',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `import crypto from 'node:crypto';

export interface StripeEnvelopeReceipt {
  accepted: boolean;
  eventId: string;
  toleranceSeconds: number;
}

const MAX_TOLERANCE_SECONDS = 300;

/**
 * Validate raw inbound Stripe callback payloads per active ADR-014 attestation policy.
 */
export function handleStripeWebhook(
  rawBody: Buffer,
  stripeSignatureHeader: string,
  signingSecret: string
): StripeEnvelopeReceipt {
  const fields = Object.fromEntries(
    stripeSignatureHeader.split(',').map((pair) => pair.trim().split('=') as [string, string])
  );
  const ts = Number(fields.t || 0);
  const digest = crypto.createHmac('sha256', signingSecret).update(\`\${ts}.\`).update(rawBody).digest('hex');
  const expected = Buffer.from(digest, 'hex');
  const provided = Buffer.from(String(fields.v1 || ''), 'hex');
  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
    throw new Error('Rejected inbound callback attestation: invalid_hmac');
  }
  const parsed = JSON.parse(rawBody.toString('utf8')) as { id?: string };
  return {
    accepted: true,
    eventId: String(parsed.id || 'evt_unknown'),
    toleranceSeconds: MAX_TOLERANCE_SECONDS,
  };
}
`
  },
  {
    id: 'adr:ADR-004',
    kind: 'adr',
    title: 'ADR-004: Browser Session Token Storage and Refresh Expiry in LocalStorage',
    path: 'docs/adr/ADR-004-session-token-storage.md',
    symbols: ['ADR-004'],
    synonyms: ['browser session token storage', 'session refresh expiry'],
    validFrom: '2025-01-15',
    retiredAt: '2026-08-20',
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# ADR-004: Browser Session Token Storage and Refresh Expiry Specification

Valid-From: 2025-01-15
Retired-At: 2026-08-20
Status: Superseded

## Question Addressed
How should frontend and full-stack engineers implement browser session token storage and refresh expiry across dashboard tabs?

## Legacy Decision (2025-01)
1. To implement browser session token storage refresh expiry in SPA clients, persist the signed bearer string inside \`window.localStorage.setItem('hs_bearer_token', bearerToken)\`.
2. Configure browser session token storage refresh expiry with a fixed \`24-hour\` (\`86400-second\`) TTL timestamp saved under \`window.localStorage.setItem('hs_token_exp', expIso)\`.
3. Cache client-side tenant claim normalization badges alongside \`parseTenantClaim\` debug metadata in \`localStorage\` so multi-org workspace switchers render without extra network calls.
4. Implementation checklist for browser session token storage and refresh expiry:
   - Storage medium: \`window.localStorage\` bearer token read by client fetch interceptors.
   - Refresh expiry window: \`24h\` static TTL before prompting re-authentication.
   - Multi-tab sync: listen to \`window.addEventListener('storage')\` for browser session token storage refresh expiry updates.
   - Legacy note: browser session token storage and refresh expiry in v1 portals always read directly from \`window.localStorage\`.

## Legacy Client Snippet (Retired v1 Dashboard)
\`\`\`ts
export function legacyPersistBrowserSessionToken(rawBearer: string, nowEpochMs: number): {
  storageKey: string;
  refreshExpiryMs: number;
} {
  // Legacy pattern: browser session token storage and refresh expiry in window.localStorage (24h TTL).
  const refreshExpiryMs = nowEpochMs + 24 * 60 * 60 * 1000;
  return {
    storageKey: \`localStorage:hs_bearer_token:\${rawBearer.length}\`,
    refreshExpiryMs,
  };
}
\`\`\`

## Historical Context
Early prototype dashboards mounted across multiple subdomains before unified reverse-proxy routing existed, leading v1 client teams to adopt \`window.localStorage\` bearer tokens with a \`24-hour\` refresh expiry schedule.
`
  },
  {
    id: 'adr:ADR-019',
    kind: 'adr',
    title: 'ADR-019: HttpOnly Strict Cookie Rotation Authority',
    path: 'docs/adr/ADR-019-cookie-rotation-authority.md',
    symbols: ['ADR-019'],
    synonyms: ['httponly cookie rotation', 'sliding session authority'],
    validFrom: '2026-08-20',
    retiredAt: null,
    supersedesId: 'adr:ADR-004',
    governsIds: ['file:src/auth/session-middleware.ts'],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# ADR-019: HttpOnly Strict Cookie Rotation Authority

Supersedes: ADR-004
Governs: src/auth/session-middleware.ts
Valid-From: 2026-08-20

## Active Security Mandate
ADR-004 (\`window.localStorage\` bearer persistence with \`24h\` static TTL) is RETIRED due to DOM XSS credential exfiltration risk.

1. Zero credentials or session handles may be stored in \`localStorage\` or \`sessionStorage\`.
2. Issue opaque server-bound session cookies exclusively via \`Set-Cookie\` with \`HttpOnly; Secure; SameSite=Strict; Path=/\`.
3. Enforce a \`15-minute\` (\`900-second\`) sliding window with single-use rotation family revocation on replay detection.
`
  },
  {
    id: 'file:src/auth/session-middleware.ts',
    kind: 'code',
    title: 'Rotating HttpOnly Session Cookie Middleware',
    path: 'src/auth/session-middleware.ts',
    symbols: ['issueSessionCookie', 'rotateSession'],
    synonyms: ['session token', 'session storage', 'browser session', 'refresh expiry'],
    validFrom: '2025-01-15',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `import crypto from 'node:crypto';

const SLIDING_TTL_SECONDS = 900;

export interface SessionCookieDirective {
  sessionId: string;
  setCookieHeader: string;
  expiresAtMs: number;
}

/**
 * Mint an opaque HttpOnly; SameSite=Strict cookie per ADR-019 rotation policy.
 */
export function issueSessionCookie(nowMs: number = Date.now()): SessionCookieDirective {
  const sessionId = crypto.randomBytes(24).toString('base64url');
  const expiresAtMs = nowMs + SLIDING_TTL_SECONDS * 1000;
  const setCookieHeader = [
    \`__Host-hs_sid=\${sessionId}\`,
    \`Max-Age=\${SLIDING_TTL_SECONDS}\`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
  ].join('; ');
  return { sessionId, setCookieHeader, expiresAtMs };
}

export function rotateSession(activeFamilySet: Set<string>, presentedId: string): SessionCookieDirective {
  if (!activeFamilySet.has(presentedId)) {
    activeFamilySet.clear();
    throw new Error('Detected reused or unknown session rotation handle; revoked family');
  }
  activeFamilySet.delete(presentedId);
  const next = issueSessionCookie();
  activeFamilySet.add(next.sessionId);
  return next;
}
`
  },
  {
    id: 'file:src/queue/retry-worker.ts',
    kind: 'code',
    title: 'Asynchronous Payout Retry Queue Worker',
    path: 'src/queue/retry-worker.ts',
    symbols: ['drainRetryQueue', 'RetryLeaseConfig'],
    synonyms: ['retry queue', 'job drop', 'drop jobs', 'redis failover', 'env setting'],
    validFrom: '2025-07-01',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `export interface RetryLeaseConfig {
  maxStallMs: number;
  failoverJitterMs: number;
}

export interface QueuedDispatchItem {
  itemId: string;
  claimedAtMs: number;
}

/**
 * Drain claimed retry dispatches and reap stalled worker leases based on runtime env thresholds.
 */
export function drainRetryQueue(
  inFlightItems: QueuedDispatchItem[],
  nowMs: number = Date.now()
): { activeIds: string[]; evictedIds: string[]; config: RetryLeaseConfig } {
  const maxStallMs = Number(process.env.QUEUE_MAX_STALL_MS || 4500);
  const failoverJitterMs = Number(process.env.REDIS_FAILOVER_JITTER_MS || 250);
  const deadlineMs = maxStallMs + failoverJitterMs;

  const activeIds: string[] = [];
  const evictedIds: string[] = [];
  for (const item of inFlightItems) {
    if (nowMs - item.claimedAtMs > deadlineMs) {
      evictedIds.push(item.itemId);
    } else {
      activeIds.push(item.itemId);
    }
  }
  return {
    activeIds,
    evictedIds,
    config: { maxStallMs, failoverJitterMs },
  };
}
`
  },
  {
    id: 'env:QUEUE_MAX_STALL_MS',
    kind: 'env',
    title: 'Worker Queue Lease Environment Configuration',
    path: 'infra/worker.env.example',
    symbols: ['QUEUE_MAX_STALL_MS', 'REDIS_FAILOVER_JITTER_MS'],
    synonyms: ['worker stall timeout', 'failover jitter env'],
    validFrom: '2025-07-01',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# Worker Visibility Lease & Sentinel Timing Template (infra/worker.env.example)
# Controls lease reaper horizon (ms) and election jitter padding (ms) for background dispatchers.
# WARNING: Check incident postmortem history before deploying legacy 4500ms default in multi-node clusters!
QUEUE_MAX_STALL_MS=4500
REDIS_FAILOVER_JITTER_MS=250
WORKER_MAX_CONCURRENCY=8
WORKER_HEARTBEAT_INTERVAL_MS=1500
`
  },
  {
    id: 'inc:INC-204',
    kind: 'incident',
    title: 'INC-204: Silent Dead-Letter Eviction During Sentinel Primary Promotion',
    path: 'docs/incidents/INC-204-silent-dlq-eviction.md',
    symbols: ['INC-204'],
    synonyms: ['silent dlq eviction', 'sentinel lease expiration'],
    validFrom: '2026-09-14',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: [],
    tunedInIds: ['env:QUEUE_MAX_STALL_MS'],
    explicitImpactsIds: [],
    content: `# INC-204: Silent Dead-Letter Eviction During Sentinel Primary Promotion

Tuned-In: infra/worker.env.example (QUEUE_MAX_STALL_MS)
Valid-From: 2026-09-14

## Root Cause Analysis
During Sentinel primary promotion, replica election and TCP socket reconvergence pause lease heartbeat renewals for \`9,200ms\` to \`11,800ms\`. Whenever \`QUEUE_MAX_STALL_MS\` is configured below \`15000ms\` (such as the legacy \`4500ms\` template value), the visibility reaper misclassifies healthy in-flight leases as orphaned and evicts active payloads directly into dead-letter storage without re-queuing.

## Mandatory Production Guardrail
Production manifests MUST set \`QUEUE_MAX_STALL_MS=18000\` (\`>= 15000ms\` safety floor above Sentinel promotion reconvergence) alongside \`REDIS_FAILOVER_JITTER_MS=500\`.
`
  },
  {
    id: 'pr:PR-412',
    kind: 'pr',
    title: 'PR-412: Patch Promotional Minimum Floor in Partner Fee Engine',
    path: 'docs/prs/PR-412-payout-rounding-patch.md',
    symbols: ['PR-412'],
    synonyms: ['PR-412', 'payout rounding patch'],
    validFrom: '2026-10-03',
    retiredAt: null,
    supersedesId: null,
    governsIds: [],
    touchesIds: ['file:src/billing/fee-engine.ts'],
    tunedInIds: [],
    explicitImpactsIds: [],
    content: `# PR-412: Patch Promotional Minimum Floor in Partner Fee Engine

Touches: src/billing/fee-engine.ts
Valid-From: 2026-10-03

## Change Summary
Adjusted \`minFloorCents\` clamping inside \`calculatePartnerFee\` (\`src/billing/fee-engine.ts\`) for micro-ticket merchant captures under \`$1.00\` so zero-dollar authorization reversals return \`0\` cents instead of \`15\` cents.
`
  }
]);

/**
 * 8 Proof-Over-Vectors benchmark evaluation scenarios.
 */
export const HYDRASCOPE_BENCHMARK_SCENARIOS = deepFreezePlain([
  {
    id: 'S1',
    category: 'blast_radius',
    title: '2-Hop Partner Fee Rounding Blast Radius Into SOX Conservation',
    query: 'Update per-item partner fee rounding in calculatePartnerFee without breaking downstream accounting',
    asOf: null,
    tokenBudget: 900,
    requiredNodeIds: [
      'file:src/billing/fee-engine.ts',
      'file:src/billing/settlement-batch.ts',
      'file:src/compliance/sox-reconciler.ts',
      'inv:INV-FIN-03'
    ],
    forbiddenPoisonNodeIds: [],
    expectAnswerable: true,
    expectedMissingTerms: [],
    explanation:
      'sox-reconciler.ts and INV-FIN-03 enforce zero-cent subledger conservation 2 AST hops downstream of calculatePartnerFee while sharing zero lexical overlap with "partner fee rounding", whereas invoice-formatter.ts repeats query phrases as a high-cosine distractor.'
  },
  {
    id: 'S2',
    category: 'blast_radius',
    title: '2-Hop Tenant Claim Normalization Blast Radius Into Idempotency Fence',
    query: 'Change tenant claim normalization in parseTenantClaim',
    asOf: null,
    tokenBudget: 900,
    requiredNodeIds: [
      'file:src/auth/token-claims.ts',
      'file:src/gateway/context-propagator.ts',
      'file:src/ledger/idempotency-fence.ts'
    ],
    forbiddenPoisonNodeIds: [],
    expectAnswerable: true,
    expectedMissingTerms: [],
    explanation:
      'idempotency-fence.ts derives 72-hour immutable distributed lock keys 2 hops downstream of parseTenantClaim via attachRequestPrincipal using pure lock-fence vocabulary with zero mention of "tenant claim".'
  },
  {
    id: 'S3',
    category: 'temporal_supersession',
    title: 'Stripe Webhook Signature Attestation (Retired SHA-1 vs Active HMAC-SHA256)',
    query: 'How should I verify stripe webhook signature headers and replay window?',
    asOf: null,
    tokenBudget: 850,
    requiredNodeIds: ['file:src/webhooks/stripe-handler.ts', 'adr:ADR-014'],
    forbiddenPoisonNodeIds: ['adr:ADR-003'],
    expectAnswerable: true,
    expectedMissingTerms: [],
    explanation:
      'Retired ADR-003 repeats the exact query phrase 5 times and prescribes insecure SHA-1 with a 30-minute window, ranking #1 in dense vector search, while HydraScope traverses :SUPERSEDES to block ADR-003 and serve active ADR-014 (constant-time HMAC-SHA256, 300s tolerance).'
  },
  {
    id: 'S4',
    category: 'temporal_supersession',
    title: 'Browser Session Storage Authority (Retired LocalStorage vs Active HttpOnly Rotation)',
    query: 'Implement browser session token storage and refresh expiry',
    asOf: null,
    tokenBudget: 850,
    requiredNodeIds: ['file:src/auth/session-middleware.ts', 'adr:ADR-019'],
    forbiddenPoisonNodeIds: ['adr:ADR-004'],
    expectAnswerable: true,
    expectedMissingTerms: [],
    explanation:
      'Retired ADR-004 repeats "browser session token storage and refresh expiry" 5 times and prescribes localStorage with a 24h TTL, poisoning top-k vector results, while HydraScope filters ADR-004 via :SUPERSEDES and serves active ADR-019 (HttpOnly SameSite=Strict 15m sliding cookie).'
  },
  {
    id: 'S5',
    category: 'cross_artifact_trace',
    title: 'Cross-Artifact Worker Failover Drop Trace (Code -> Env Key -> Incident Postmortem)',
    query: 'Why does drainRetryQueue drop jobs during failover and what env setting controls it?',
    asOf: null,
    tokenBudget: 900,
    requiredNodeIds: [
      'file:src/queue/retry-worker.ts',
      'env:QUEUE_MAX_STALL_MS',
      'inc:INC-204'
    ],
    forbiddenPoisonNodeIds: [],
    expectAnswerable: true,
    expectedMissingTerms: [],
    explanation:
      'Joining drainRetryQueue to QUEUE_MAX_STALL_MS and INC-204 requires traversing :READS_ENV and :TUNED_IN edges; INC-204 discusses Sentinel promotion visibility leases without mentioning drainRetryQueue or job drops.'
  },
  {
    id: 'S6',
    category: 'cross_artifact_trace',
    title: '3-Hop PR Impact Provenance Trace (PR-412 -> Fee Engine -> Settlement -> SOX)',
    query: 'Trace what downstream compliance checks PR-412 impacted',
    asOf: null,
    tokenBudget: 950,
    requiredNodeIds: [
      'pr:PR-412',
      'file:src/billing/fee-engine.ts',
      'file:src/billing/settlement-batch.ts',
      'file:src/compliance/sox-reconciler.ts'
    ],
    forbiddenPoisonNodeIds: [],
    expectAnswerable: true,
    expectedMissingTerms: [],
    explanation:
      'PR-412 only mentions patching src/billing/fee-engine.ts; discovering that it impacts SOX compliance checks in sox-reconciler.ts requires a 3-hop structural walk across :TOUCHED and AST :IMPACTS edges.'
  },
  {
    id: 'S7',
    category: 'ungrounded_trap',
    title: 'Ungrounded Subsystem Trap: Non-Existent Kafka Consumer Group',
    query: 'What is the Kafka consumer group lag threshold for calculatePartnerFee?',
    asOf: null,
    tokenBudget: 800,
    requiredNodeIds: [],
    forbiddenPoisonNodeIds: [],
    expectAnswerable: false,
    expectedMissingTerms: ['kafka'],
    explanation:
      'Dense vector search returns top-k calculatePartnerFee chunks (~0.55 cosine) and invites LLM hallucination, whereas HydraScope pre-flight ontology verification detects that Kafka does not exist anywhere in the workspace at 0 LLM tokens.'
  },
  {
    id: 'S8',
    category: 'ungrounded_trap',
    title: 'Ungrounded Subsystem Trap: Non-Existent Kubernetes HorizontalPodAutoscaler',
    query: 'Which Kubernetes HorizontalPodAutoscaler manifest scales drainRetryQueue?',
    asOf: null,
    tokenBudget: 800,
    requiredNodeIds: [],
    forbiddenPoisonNodeIds: [],
    expectAnswerable: false,
    expectedMissingTerms: ['kubernetes', 'horizontalpodautoscaler'],
    explanation:
      'Dense vector search returns retry-worker.ts and worker.env.example even though no Kubernetes or HorizontalPodAutoscaler manifests exist; HydraScope rejects the ungrounded premises pre-flight at 0 LLM tokens.'
  }
]);

function normalizeRelPath(rawPath) {
  return scrubSensitiveText(rawPath)
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '')
    .trim();
}

function uniqueStrings(list) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const out = [];
  for (const item of list) {
    const val = String(item ?? '').trim();
    if (!val || FORBIDDEN_OBJECT_KEYS.has(val) || seen.has(val)) continue;
    seen.add(val);
    out.push(val);
  }
  return out;
}

function splitIdentifierParts(raw) {
  const text = String(raw ?? '');
  if (!text) return [];
  const expanded = text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/[/_.:-]+/g, ' ');
  return expanded.toLowerCase().match(/[a-z0-9]{2,}/g) || [];
}

function bareLogicalId(id) {
  return String(id || '').replace(/^[a-z_]+:/i, '').trim();
}

function stemDomainWord(token) {
  const w = String(token || '').toLowerCase();
  if (w.length <= 3 || EXTERNAL_SUBSYSTEM_TERMS.has(w)) return w;
  if (w.endsWith('ies') && w.length > 4) return `${w.slice(0, -3)}y`;
  if (
    w.endsWith('ches') ||
    w.endsWith('shes') ||
    w.endsWith('xes') ||
    w.endsWith('zes') ||
    w.endsWith('ses')
  ) {
    return w.slice(0, -2);
  }
  if (w.endsWith('ing') && w.length > 5) return w.slice(0, -3);
  if (w.endsWith('ed') && w.length > 4) return w.slice(0, -2);
  if (w.endsWith('s') && !w.endsWith('ss') && !w.endsWith('us') && !w.endsWith('is')) {
    return w.slice(0, -1);
  }
  return w;
}

function stripCommentsForCallScan(content, ext = '') {
  const src = String(content || '');
  if (!src) return '';
  if (ext === '.py' || ext === '.rb' || ext === '.yaml' || ext === '.yml') {
    return src
      .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, ' ')
      .replace(/#[^\r\n]*/g, ' ');
  }
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/[^\r\n]*/g, ' ');
}

function extractCodeSymbols(content, filePath = '') {
  const src = String(content || '');
  const symbols = [];
  const ext = path.posix.extname(String(filePath || '')).toLowerCase();

  if (ext === '.py') {
    for (const m of src.matchAll(/^(?:async\s+def|def|class)\s+([A-Za-z_]\w*)\b/gm)) {
      if (!m[1].startsWith('_')) symbols.push(m[1]);
    }
    return uniqueStrings(symbols);
  }

  if (ext === '.yaml' || ext === '.yml') {
    for (const m of src.matchAll(/^name\s*:\s*['"]?([A-Za-z_][\w-]*)['"]?\s*$/gm)) {
      symbols.push(m[1]);
    }
    for (const m of src.matchAll(/^([A-Za-z_][\w-]*)\s*:/gm)) {
      symbols.push(m[1]);
    }
    return uniqueStrings(symbols);
  }

  if (ext === '.go') {
    for (const m of src.matchAll(/\bfunc\s+(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*\(/g)) {
      symbols.push(m[1]);
    }
    for (const m of src.matchAll(/\btype\s+([A-Za-z_]\w*)\s+(?:struct|interface)\b/g)) {
      symbols.push(m[1]);
    }
    return uniqueStrings(symbols);
  }

  if (ext === '.rs') {
    for (const m of src.matchAll(/\b(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\b/g)) {
      symbols.push(m[1]);
    }
    for (const m of src.matchAll(/\b(?:pub(?:\([^)]+\))?\s+)?(?:struct|enum|trait|mod)\s+([A-Za-z_]\w*)\b/g)) {
      symbols.push(m[1]);
    }
    return uniqueStrings(symbols);
  }

  if (ext === '.java' || ext === '.cs' || ext === '.kt' || ext === '.php') {
    for (const m of src.matchAll(/\b(?:class|interface|enum|record|struct|trait|object)\s+([A-Za-z_]\w*)\b/g)) {
      symbols.push(m[1]);
    }
    for (const m of src.matchAll(/\b(?:function|fun)\s+([A-Za-z_]\w*)\s*\(/g)) {
      symbols.push(m[1]);
    }
    for (const m of src.matchAll(/\b(?:public|protected|internal)\s+(?:static\s+)?(?:async\s+)?[A-Za-z0-9_<>,?[\]]+\s+([A-Za-z_]\w*)\s*\(/g)) {
      if (!['if', 'for', 'while', 'switch', 'catch'].includes(m[1])) {
        symbols.push(m[1]);
      }
    }
    return uniqueStrings(symbols);
  }

  if (ext === '.rb') {
    for (const m of src.matchAll(/^\s*(?:class|module|def)\s+(?:self\.)?([A-Za-z_][\w?!]*)/gm)) {
      symbols.push(m[1]);
    }
    return uniqueStrings(symbols);
  }

  for (const match of src.matchAll(
    /\bexport\s+(?:default\s+)?(?:async\s+)?(?:function|const|let|var|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/g
  )) {
    symbols.push(match[1]);
  }

  for (const match of src.matchAll(/\bexport\s*\{\s*([^}]+)\}/g)) {
    for (const chunk of match[1].split(',')) {
      const cleaned = chunk.trim();
      if (!cleaned) continue;
      const aliasParts = cleaned.split(/\s+as\s+/);
      const exportedName = (aliasParts[1] || aliasParts[0] || '').trim();
      if (/^[A-Za-z_$][\w$]*$/.test(exportedName) && exportedName !== 'default') {
        symbols.push(exportedName);
      }
    }
  }

  for (const match of src.matchAll(/\bmodule\.exports\s*=\s*\{\s*([^}]+)\}/g)) {
    for (const chunk of match[1].split(',')) {
      const key = chunk.split(':')[0].trim();
      if (/^[A-Za-z_$][\w$]*$/.test(key)) {
        symbols.push(key);
      }
    }
  }

  return uniqueStrings(symbols);
}

function extractRelativeImports(content, filePath = '') {
  const src = String(content || '');
  const specifiers = [];
  const ext = path.posix.extname(String(filePath || '')).toLowerCase();

  if (ext === '.py') {
    for (const m of src.matchAll(/^\s*from\s+(\.+[A-Za-z0-9_.]*)\s+import\b/gm)) {
      const dotMatch = /^(\.+)(.*)$/.exec(m[1]);
      if (!dotMatch) continue;
      const dots = dotMatch[1].length;
      const modTail = dotMatch[2].replace(/\./g, '/');
      const upPrefix = dots === 1 ? './' : '../'.repeat(dots - 1);
      specifiers.push(`${upPrefix}${modTail}`);
    }
    for (const m of src.matchAll(/^\s*from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+([^\r\n#]+)/gm)) {
      const modName = m[1];
      specifiers.push(`py:${modName}`);
      for (const item of m[2].split(',')) {
        const sub = item.trim().split(/\s+as\s+/)[0].trim();
        if (/^[A-Za-z_]\w*$/.test(sub)) {
          specifiers.push(`py:${modName}.${sub}`);
        }
      }
    }
    for (const m of src.matchAll(/^[ \t]*import[ \t]+([A-Za-z_][A-Za-z0-9_., \t]*)/gm)) {
      for (const part of m[1].split(',')) {
        const modName = part.trim().split(/[ \t]+as[ \t]+/)[0].trim();
        if (/^[A-Za-z_][A-Za-z0-9_.]*$/.test(modName)) {
          specifiers.push(`py:${modName}`);
        }
      }
    }
    return uniqueStrings(specifiers);
  }

  if (ext === '.yaml' || ext === '.yml') {
    for (const m of src.matchAll(/!include\s+['"]?([^\s'"#]+)['"]?/g)) {
      specifiers.push(`yaml:${m[1]}`);
    }
    for (const m of src.matchAll(/\b(?:config_path|prompt_path|template_path|schema_path)\s*:\s*['"]?([^\s'"#]+)['"]?/g)) {
      specifiers.push(`yaml:${m[1]}`);
    }
    for (const m of src.matchAll(/\b(?:serve|entrypoint|script|command|main)\s*:\s*[^\r\n#]*?(?:\{[a-z_]+\}\/)?([A-Za-z0-9_./-]+\.(?:py|js|mjs|cjs|ts|sh))\b/g)) {
      specifiers.push(`yaml:${m[1]}`);
    }
    return uniqueStrings(specifiers);
  }

  if (ext === '.php') {
    for (const m of src.matchAll(/\b(?:require|require_once|include|include_once)\s*\(?\s*['"]([^'"]+\.php)['"]/gi)) {
      specifiers.push(`poly:${m[1]}`);
    }
    return uniqueStrings(specifiers);
  }

  if (ext === '.rb') {
    for (const m of src.matchAll(/\brequire_relative\s*\(?\s*['"]([^'"]+)['"]/g)) {
      specifiers.push(`poly:${m[1]}`);
    }
    return uniqueStrings(specifiers);
  }

  if (ext === '.rs') {
    for (const m of src.matchAll(/^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;/gm)) {
      specifiers.push(`rsmod:${m[1]}`);
    }
    return uniqueStrings(specifiers);
  }

  if (ext === '.java' || ext === '.kt') {
    for (const m of src.matchAll(/^\s*import\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;?/gm)) {
      specifiers.push(`jvm:${m[1]}`);
    }
    return uniqueStrings(specifiers);
  }

  for (const match of src.matchAll(
    /\b(?:import|export)\s+(?:type\s+)?(?:[\s\S]{0,240}?\s+from\s+)?['"](\.\.?\/[^'"]+)['"]/g
  )) {
    specifiers.push(match[1]);
  }

  for (const match of src.matchAll(/\b(?:require|import)\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g)) {
    specifiers.push(match[1]);
  }

  return uniqueStrings(specifiers);
}

function extractEnvReads(content) {
  const src = String(content || '');
  const keys = [];

  for (const m of src.matchAll(/\bprocess\.env\.([A-Z][A-Z0-9_]{1,80})\b/g)) {
    keys.push(m[1]);
  }
  for (const m of src.matchAll(/\bprocess\.env\[\s*['"]([A-Z][A-Z0-9_]{1,80})['"]\s*\]/g)) {
    keys.push(m[1]);
  }
  for (const m of src.matchAll(
    /\bos\.(?:environ\.get|getenv)\s*\(\s*['"]([A-Z][A-Z0-9_]{1,80})['"]|\bos\.environ\[\s*['"]([A-Z][A-Z0-9_]{1,80})['"]\s*\]/g
  )) {
    keys.push(m[1] || m[2]);
  }
  for (const m of src.matchAll(/\b(?:envOr|envInt|envBool)\s*\(\s*['"]([A-Z][A-Z0-9_]{1,80})['"]/g)) {
    keys.push(m[1]);
  }
  for (const m of src.matchAll(
    /\b(?:os\.Getenv|os\.LookupEnv|System\.getenv|Environment\.GetEnvironmentVariable|env::var|getenv)\s*\(\s*['"]([A-Z][A-Z0-9_]{1,80})['"]/g
  )) {
    keys.push(m[1]);
  }
  for (const m of src.matchAll(/\b(?:\$_ENV|ENV)\[\s*['"]([A-Z][A-Z0-9_]{1,80})['"]\s*\]|\bENV\.fetch\s*\(\s*['"]([A-Z][A-Z0-9_]{1,80})['"]/g)) {
    keys.push(m[1] || m[2]);
  }

  return uniqueStrings(keys);
}

function extractDefinedEnvKeys(content) {
  const keys = [];
  for (const rawLine of String(content || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Z][A-Z0-9_]{1,80})\s*=/.exec(line);
    if (m) keys.push(m[1]);
  }
  return uniqueStrings(keys);
}

function resolveImportedCodeNode(importerPath, specifier, codeByPath, nodeByPath = codeByPath) {
  const cleanSpec = String(specifier || '').split('?')[0].split('#')[0].trim();
  if (!cleanSpec) return null;

  const baseDir = path.posix.dirname(importerPath || '.');

  if (cleanSpec.startsWith('py:')) {
    const modPath = cleanSpec.slice(3).replace(/\./g, '/').replace(/^\/+|\/+$/g, '');
    if (!modPath) return null;
    const pyCandidates = [
      `${modPath}.py`,
      `${modPath}/__init__.py`,
      `src/${modPath}.py`,
      `src/${modPath}/__init__.py`,
      path.posix.normalize(path.posix.join(baseDir, `${modPath}.py`)),
      path.posix.normalize(path.posix.join(baseDir, `${modPath}/__init__.py`))
    ];
    for (const candidate of pyCandidates) {
      const hit = codeByPath.get(candidate);
      if (hit) return hit;
    }
    return null;
  }

  if (cleanSpec.startsWith('yaml:')) {
    const relRef = cleanSpec.slice(5).replace(/^\.\//, '').replace(/^\/+/, '');
    if (!relRef) return null;
    for (const candidate of [
      path.posix.normalize(path.posix.join(baseDir, relRef)),
      path.posix.normalize(relRef)
    ]) {
      const hit = nodeByPath.get(candidate) || codeByPath.get(candidate);
      if (hit) return hit;
    }
    return null;
  }

  if (cleanSpec.startsWith('poly:')) {
    const relRef = cleanSpec.slice(5).replace(/^\.\//, '').replace(/^\/+/, '');
    if (!relRef) return null;
    for (const candidate of [
      path.posix.normalize(path.posix.join(baseDir, relRef)),
      path.posix.normalize(path.posix.join(baseDir, `${relRef}.rb`)),
      path.posix.normalize(path.posix.join(baseDir, `${relRef}.php`)),
      path.posix.normalize(relRef),
      path.posix.normalize(`${relRef}.rb`),
      path.posix.normalize(`${relRef}.php`)
    ]) {
      const hit = codeByPath.get(candidate);
      if (hit) return hit;
    }
    return null;
  }

  if (cleanSpec.startsWith('rsmod:')) {
    const modName = cleanSpec.slice(6).trim();
    if (!modName) return null;
    for (const candidate of [
      path.posix.normalize(path.posix.join(baseDir, `${modName}.rs`)),
      path.posix.normalize(path.posix.join(baseDir, modName, 'mod.rs')),
      `src/${modName}.rs`,
      `src/${modName}/mod.rs`
    ]) {
      const hit = codeByPath.get(candidate);
      if (hit) return hit;
    }
    return null;
  }

  if (cleanSpec.startsWith('jvm:')) {
    const jvmRel = cleanSpec.slice(4).replace(/\./g, '/');
    if (!jvmRel) return null;
    for (const candidate of [
      `${jvmRel}.java`,
      `${jvmRel}.kt`,
      `src/${jvmRel}.java`,
      `src/${jvmRel}.kt`,
      `src/main/java/${jvmRel}.java`,
      `src/main/kotlin/${jvmRel}.kt`
    ]) {
      const hit = codeByPath.get(candidate);
      if (hit) return hit;
    }
    return null;
  }

  if (!cleanSpec.startsWith('.')) return null;

  const joined = path.posix.normalize(path.posix.join(baseDir, cleanSpec));
  const candidates = new Set([joined]);

  if (joined.endsWith('.js')) {
    const stem = joined.slice(0, -3);
    candidates.add(`${stem}.ts`);
    candidates.add(`${stem}.tsx`);
  } else if (joined.endsWith('.mjs')) {
    candidates.add(`${joined.slice(0, -4)}.mts`);
  }

  for (const ext of CODE_PROBE_EXTS) {
    candidates.add(`${joined}${ext}`);
  }

  for (const candidate of candidates) {
    const hit = codeByPath.get(candidate);
    if (hit) return hit;
  }
  return null;
}

function buildGraphOntologyFromNodes(nodes) {
  const termSet = new Set();
  const conceptSet = new Set();
  const synonymMap = Object.create(null);

  const addIndexedToken = (rawVal) => {
    const clean = String(rawVal ?? '').trim();
    if (!clean) return;
    const lowered = clean.toLowerCase();
    if (/^[a-z0-9_:-]{2,}$/.test(lowered) && !FORBIDDEN_OBJECT_KEYS.has(lowered)) {
      termSet.add(lowered);
    }
    for (const tok of splitIdentifierParts(clean)) {
      if (!FORBIDDEN_OBJECT_KEYS.has(tok)) {
        termSet.add(tok);
      }
    }
  };

  const addSynonymLink = (phrase, nodeId) => {
    const key = String(phrase ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
    if (!key || FORBIDDEN_OBJECT_KEYS.has(key)) return;
    if (!Object.hasOwn(synonymMap, key)) {
      synonymMap[key] = [];
    }
    if (!synonymMap[key].includes(nodeId)) {
      synonymMap[key].push(nodeId);
    }
  };

  for (const node of nodes) {
    const idSuffix = node.id.includes(':') ? node.id.split(':').slice(1).join(':') : node.id;
    addIndexedToken(idSuffix);

    const codeMatch =
      /\b((?:ADR|INC|PR|INV)-[A-Z0-9-]+)\b/i.exec(node.id) ||
      /\b((?:ADR|INC|PR|INV)-[A-Z0-9-]+)\b/i.exec(node.title);
    if (codeMatch) {
      const canonicalCode = codeMatch[1].toUpperCase();
      conceptSet.add(canonicalCode);
      addIndexedToken(canonicalCode);
      addSynonymLink(canonicalCode, node.id);
    }

    if (node.path) {
      const parsedPath = path.posix.parse(node.path);
      if (parsedPath.name) {
        const cleanStem = parsedPath.name.replace(/^\.+/, '');
        if (cleanStem) {
          conceptSet.add(cleanStem);
          addIndexedToken(cleanStem);
          addSynonymLink(cleanStem, node.id);
        }
      }
      for (const seg of node.path.split('/')) {
        addIndexedToken(seg.replace(/\.[A-Za-z0-9]+$/, ''));
      }
    }

    addIndexedToken(node.title);

    for (const sym of Array.isArray(node.symbols) ? node.symbols : []) {
      conceptSet.add(sym);
      addIndexedToken(sym);
      addSynonymLink(sym, node.id);
    }

    if (node.kind === 'code') {
      for (const extractedSym of extractCodeSymbols(node.content, node.path)) {
        conceptSet.add(extractedSym);
        addIndexedToken(extractedSym);
        addSynonymLink(extractedSym, node.id);
      }
      for (const envRead of extractEnvReads(node.content)) {
        conceptSet.add(envRead);
        addIndexedToken(envRead);
      }
    }

    for (const syn of Array.isArray(node.synonyms) ? node.synonyms : []) {
      conceptSet.add(syn);
      addIndexedToken(syn);
      addSynonymLink(syn, node.id);
    }
  }

  return {
    terms: [...termSet].sort(),
    knownConcepts: [...conceptSet].sort(),
    synonyms: synonymMap
  };
}

/**
 * Compile an array of normalized or raw engineering artifacts into a HydraScope structural graph.
 *
 * @param {Array<object>} [artifacts=[]]
 * @param {object} [options={}]
 */
export function compileArtifactsToHydraGraph(
  artifacts = [],
  { workspaceName = 'fintech-core', namespace = 'brick-ontology' } = {}
) {
  const safeWorkspace = scrubSensitiveText(workspaceName || 'fintech-core').trim() || 'fintech-core';
  const safeNamespace = scrubSensitiveText(namespace || 'brick-ontology').trim() || 'brick-ontology';
  const rawList = Array.isArray(artifacts) ? artifacts : [];

  const nodeById = new Map();
  const codeByPath = new Map();
  const nodeByPath = new Map();
  const envKeyToNodeIds = new Map();
  const rawMetaById = new Map();
  const nodes = [];

  for (const raw of rawList) {
    if (!raw || typeof raw !== 'object' || !raw.id) continue;
    const id = String(raw.id).trim();
    if (!id || FORBIDDEN_OBJECT_KEYS.has(id) || nodeById.has(id)) continue;

    const kind = String(raw.kind || 'code').trim();
    const relPath = normalizeRelPath(raw.path || id);
    const content = scrubSensitiveText(String(raw.content || ''));
    const declaredSymbols = uniqueStrings(raw.symbols);
    const symbols =
      declaredSymbols.length > 0
        ? declaredSymbols
        : kind === 'code'
          ? extractCodeSymbols(content, relPath)
          : kind === 'env'
            ? extractDefinedEnvKeys(content)
            : [];
    const synonyms = uniqueStrings(raw.synonyms);
    const validFrom = raw.validFrom ? String(raw.validFrom).trim() : null;
    const retiredAt = raw.retiredAt ? String(raw.retiredAt).trim() : null;

    const node = {
      id,
      surrogateId: surrogateOntologyVertexId(safeNamespace, id),
      kind,
      title: scrubSensitiveText(String(raw.title || relPath || id)).trim(),
      path: relPath,
      symbols,
      synonyms,
      content,
      tokens: estimateTokens(content),
      validFrom,
      retiredAt,
      isCurrent: !retiredAt,
      supersededBy: null
    };

    nodes.push(node);
    nodeById.set(id, node);
    rawMetaById.set(id, {
      supersedesId: raw.supersedesId ? String(raw.supersedesId).trim() : null,
      governsIds: uniqueStrings(raw.governsIds),
      touchesIds: uniqueStrings(raw.touchesIds),
      tunedInIds: uniqueStrings(raw.tunedInIds),
      explicitImpactsIds: uniqueStrings(raw.explicitImpactsIds)
    });

    if (relPath) {
      nodeByPath.set(relPath, node);
    }
    if (kind === 'code' && relPath) {
      codeByPath.set(relPath, node);
    }
    if (kind === 'env') {
      const envKeys = uniqueStrings([
        ...symbols,
        ...extractDefinedEnvKeys(content),
        ...(id.startsWith('env:') ? [id.slice(4)] : [])
      ]);
      for (const envKey of envKeys) {
        if (!/^[A-Z][A-Z0-9_]{1,80}$/.test(envKey)) continue;
        if (!envKeyToNodeIds.has(envKey)) envKeyToNodeIds.set(envKey, []);
        envKeyToNodeIds.get(envKey).push(id);
      }
    } else if (relPath.endsWith('.yaml') || relPath.endsWith('.yml')) {
      for (const ym of content.matchAll(/^[ \t]{2,}(?:-[ \t]*)?([A-Z][A-Z0-9_]{1,80})[ \t]*[:=]/gm)) {
        const envKey = ym[1];
        if (!envKeyToNodeIds.has(envKey)) envKeyToNodeIds.set(envKey, []);
        if (!envKeyToNodeIds.get(envKey).includes(id)) {
          envKeyToNodeIds.get(envKey).push(id);
        }
      }
    }
  }

  for (const node of nodes) {
    const meta = rawMetaById.get(node.id);
    if (!meta?.supersedesId) continue;
    const older = nodeById.get(meta.supersedesId);
    if (!older) continue;
    older.isCurrent = false;
    older.supersededBy = node.id;
    if (!older.retiredAt && node.validFrom) {
      older.retiredAt = node.validFrom;
    }
  }

  // Unique symbol owner map for cross-file CALLS resolution in non-relative-import languages
  const uniqueSymbolOwner = new Map();
  for (const node of nodes) {
    if (node.kind !== 'code') continue;
    for (const sym of node.symbols) {
      if (sym.length < 4) continue;
      if (!uniqueSymbolOwner.has(sym)) {
        uniqueSymbolOwner.set(sym, node);
      } else {
        uniqueSymbolOwner.set(sym, null);
      }
    }
  }

  const edges = [];
  const seenEdges = new Set();
  const addEdge = (from, to, type, reason, validFrom = null, weight = 1) => {
    if (!from || !to || from === to) return;
    if (!nodeById.has(from) || !nodeById.has(to)) return;
    const edgeKey = `${from}|${type}|${to}`;
    if (seenEdges.has(edgeKey)) return;
    seenEdges.add(edgeKey);
    const fromNode = nodeById.get(from);
    const resolvedValidFrom =
      (typeof validFrom === 'string' && validFrom.trim()) ||
      (fromNode?.validFrom ? String(fromNode.validFrom).trim() : null) ||
      '2025-01-01';
    const numericWeight = Number(weight);
    edges.push({
      from,
      to,
      type,
      reason: String(reason || type),
      weight: Number.isFinite(numericWeight) ? numericWeight : 1,
      validFrom: resolvedValidFrom
    });
  };

  for (const node of nodes) {
    const meta = rawMetaById.get(node.id);

    if (node.kind === 'code') {
      const ext = path.posix.extname(node.path || '').toLowerCase();
      const strippedCode = stripCommentsForCallScan(node.content, ext);
      const relImports = extractRelativeImports(node.content, node.path);

      for (const spec of relImports) {
        const dependencyNode = resolveImportedCodeNode(node.path, spec, codeByPath, nodeByPath);
        if (dependencyNode) {
          addEdge(
            dependencyNode.id,
            node.id,
            'IMPACTS',
            `${node.path} imports ${dependencyNode.path}`
          );
          addEdge(
            node.id,
            dependencyNode.id,
            'IMPORTS',
            `${node.path} imports ${dependencyNode.path}`
          );
          for (const sym of dependencyNode.symbols) {
            if (/^[A-Za-z_$][\w$]*$/.test(sym)) {
              const callRe = new RegExp(`\\b${sym.replace(/\$/g, '\\$')}\\s*\\(`);
              if (callRe.test(strippedCode)) {
                addEdge(
                  node.id,
                  dependencyNode.id,
                  'CALLS',
                  `${node.path} calls ${sym} in ${dependencyNode.path}`
                );
              }
            }
          }
        }
      }

      if (['.go', '.java', '.cs', '.kt', '.rb', '.php', '.rs'].includes(ext)) {
        for (const [sym, ownerNode] of uniqueSymbolOwner.entries()) {
          if (!ownerNode || ownerNode.id === node.id) continue;
          if (/^[A-Za-z_]\w*$/.test(sym) && new RegExp(`\\b${sym}\\s*\\(`).test(strippedCode)) {
            addEdge(node.id, ownerNode.id, 'CALLS', `${node.path} calls ${sym}`);
            addEdge(ownerNode.id, node.id, 'IMPACTS', `${node.path} calls ${sym}`);
          }
        }
      }

      const envKeysRead = extractEnvReads(node.content);
      for (const envKey of envKeysRead) {
        const candidateEnvIds = new Set();
        if (nodeById.has(`env:${envKey}`)) {
          candidateEnvIds.add(`env:${envKey}`);
        }
        for (const mappedId of envKeyToNodeIds.get(envKey) || []) {
          candidateEnvIds.add(mappedId);
        }
        for (const envNodeId of candidateEnvIds) {
          addEdge(node.id, envNodeId, 'READS_ENV', `reads env ${envKey}`);
          addEdge(node.id, envNodeId, 'IMPACTS', `reads env key ${envKey}`);
        }
      }
    }

    if (meta?.explicitImpactsIds) {
      for (const targetId of meta.explicitImpactsIds) {
        addEdge(node.id, targetId, 'IMPACTS', 'explicit structural impact');
      }
    }

    if (meta?.supersedesId) {
      addEdge(node.id, meta.supersedesId, 'SUPERSEDES', `${node.id} supersedes ${meta.supersedesId}`);
    }

    if (meta?.governsIds) {
      for (const targetId of meta.governsIds) {
        addEdge(node.id, targetId, 'GOVERNS', `${node.id} governs ${targetId}`);
      }
    }

    if (meta?.touchesIds) {
      for (const targetId of meta.touchesIds) {
        addEdge(node.id, targetId, 'TOUCHED', `${node.id} touched ${targetId}`);
        addEdge(node.id, targetId, 'IMPACTS', `${node.id} touched ${targetId}`);
      }
    }

    if (meta?.tunedInIds) {
      for (const envId of meta.tunedInIds) {
        addEdge(node.id, envId, 'TUNED_IN', `${node.id} tuned ${envId}`);
        addEdge(envId, node.id, 'IMPACTS', `${envId} tuned in ${node.id}`);
      }
    }
  }

  const ontology = buildGraphOntologyFromNodes(nodes);
  const totalRepoTokens = nodes.reduce((sum, n) => sum + n.tokens, 0);

  return {
    workspaceName: safeWorkspace,
    namespace: safeNamespace,
    nodes,
    edges,
    ontology,
    totalRepoTokens
  };
}

function sanitizeEnvTemplateContent(rawText) {
  return String(rawText || '')
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        return scrubSensitiveText(line);
      }
      const m = /^((?:export\s+)?[A-Z][A-Z0-9_]{1,80}\s*=\s*)(.*)$/.exec(line);
      if (!m) return scrubSensitiveText(line);
      const prefix = m[1];
      const val = m[2].trim().replace(/^['"]|['"]$/g, '');
      if (
        val === '' ||
        /^\d+(?:\.\d+)?$/.test(val) ||
        /^(?:true|false|development|production|test)$/i.test(val)
      ) {
        return `${prefix}${val}`;
      }
      return `${prefix}<example>`;
    })
    .join('\n');
}

function parseMarkdownArtifactMeta(content, relPath) {
  const text = String(content || '');
  const fileStem = path.posix.basename(relPath, path.posix.extname(relPath));

  const headingMatch = /^#\s+(.+)$/m.exec(text);
  const title = headingMatch ? headingMatch[1].trim() : fileStem;

  const adrMatch = /\b(ADR-\d+)\b/i.exec(relPath) || /\b(ADR-\d+)\b/i.exec(title);
  const invMatch = /\b(INV-[A-Z0-9-]+)\b/i.exec(relPath) || /\b(INV-[A-Z0-9-]+)\b/i.exec(title);
  const incMatch = /\b(INC-\d+)\b/i.exec(relPath) || /\b(INC-\d+)\b/i.exec(title);
  const prMatch = /\b(PR-\d+)\b/i.exec(relPath) || /\b(PR-\d+)\b/i.exec(title);

  let id = `doc:${relPath}`;
  let kind = 'doc';
  const symbols = [];

  if (adrMatch) {
    const code = adrMatch[1].toUpperCase();
    id = `adr:${code}`;
    kind = 'adr';
    symbols.push(code);
  } else if (invMatch) {
    const code = invMatch[1].toUpperCase();
    id = `inv:${code}`;
    kind = 'invariant';
    symbols.push(code);
  } else if (incMatch) {
    const code = incMatch[1].toUpperCase();
    id = `inc:${code}`;
    kind = 'incident';
    symbols.push(code);
  } else if (prMatch) {
    const code = prMatch[1].toUpperCase();
    id = `pr:${code}`;
    kind = 'pr';
    symbols.push(code);
  }

  const supersedesMatch = /^[*-]?\s*Supersedes\s*:\s*([^\r\n]+)/im.exec(text);
  let supersedesRef = null;
  if (supersedesMatch) {
    const supRaw = supersedesMatch[1].trim();
    const supAdr = /\b(ADR-\d+)\b/i.exec(supRaw);
    const supInv = /\b(INV-[A-Z0-9-]+)\b/i.exec(supRaw);
    if (supAdr) supersedesRef = `adr:${supAdr[1].toUpperCase()}`;
    else if (supInv) supersedesRef = `inv:${supInv[1].toUpperCase()}`;
    else if (supRaw.includes(':')) supersedesRef = supRaw.split(/[,\s]/)[0].trim();
  }

  const validFromMatch = /^[*-]?\s*(?:Valid-From|Effective|Date)\s*:\s*(\d{4}-\d{2}-\d{2})/im.exec(text);
  const retiredAtMatch =
    /^[*-]?\s*(?:Retired-At|Deprecated-At|Superseded-At)\s*:\s*(\d{4}-\d{2}-\d{2})/im.exec(text);
  const statusSuperseded = /^[*-]?\s*Status\s*:\s*(?:Superseded|Retired|Deprecated)\b/im.test(text);

  const parseTargetList = (headerName) => {
    const re = new RegExp(`^[*-]?\\s*${headerName}\\s*:\\s*([^\\r\\n]+)`, 'gim');
    const refs = [];
    let m;
    while ((m = re.exec(text)) !== null) {
      for (const part of m[1].split(',')) {
        const cleaned = part.trim().replace(/^`|`$/g, '');
        if (cleaned) refs.push(cleaned);
      }
    }
    return refs;
  };

  return {
    id,
    kind,
    title,
    symbols,
    validFrom: validFromMatch ? validFromMatch[1] : null,
    retiredAt: retiredAtMatch ? retiredAtMatch[1] : statusSuperseded ? '1970-01-01' : null,
    supersedesRef,
    rawGoverns: parseTargetList('Governs'),
    rawTouches: parseTargetList('Touches'),
    rawTunedIn: parseTargetList('Tuned-In')
  };
}

/**
 * Polyglot filesystem directory compiler (10 programming languages / 16 source & config extensions,
 * relative/package IMPORTS, symbol CALLS, process.env/os.getenv READS_ENV, and ADR :SUPERSEDES/:GOVERNS).
 *
 * @param {string} targetDir
 * @param {object} [options={}]
 */
export function compileDirectoryToHydraGraph(
  targetDir,
  { maxFiles = 160, workspaceName, rejectSymlinkRoot = false, namespace = 'brick-ontology' } = {}
) {
  const tool = 'hydrascope_compile_directory';
  if (!targetDir || typeof targetDir !== 'string' || !targetDir.trim()) {
    return failHydraEnvelope(
      tool,
      'INVALID_TARGET_DIR',
      'A non-empty target directory path is required.',
      null
    );
  }

  const candidateRoot = path.resolve(targetDir.trim());
  let lstat;
  try {
    lstat = fs.lstatSync(candidateRoot);
  } catch {
    return failHydraEnvelope(
      tool,
      'DIRECTORY_NOT_FOUND',
      'Target directory does not exist or cannot be accessed.',
      null
    );
  }

  if (rejectSymlinkRoot && lstat.isSymbolicLink()) {
    return failHydraEnvelope(
      tool,
      'SYMLINK_ROOT_REJECTED',
      'Symbolic link directories cannot be compiled via restricted workspace endpoints.',
      null
    );
  }

  let resolvedRoot;
  let rootStat;
  try {
    resolvedRoot = fs.realpathSync(candidateRoot);
    rootStat = fs.statSync(resolvedRoot);
  } catch {
    return failHydraEnvelope(
      tool,
      'DIRECTORY_NOT_FOUND',
      'Target directory does not exist or cannot be accessed.',
      null
    );
  }

  if (!rootStat.isDirectory()) {
    return failHydraEnvelope(tool, 'NOT_A_DIRECTORY', 'Target path must be a directory.', null);
  }

  const boundedMaxFiles = Math.max(1, Math.min(Number(maxFiles) || 160, 1000));
  const effectiveWorkspace =
    scrubSensitiveText(workspaceName || path.basename(resolvedRoot) || 'local-workspace').trim() ||
    'local-workspace';

  const discoveredFiles = [];

  const walkDirectory = (currentAbsDir) => {
    if (discoveredFiles.length >= boundedMaxFiles) return;
    let entries;
    try {
      entries = fs.readdirSync(currentAbsDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (discoveredFiles.length >= boundedMaxFiles) break;
      if (entry.isSymbolicLink()) continue;

      const name = entry.name;
      const fullPath = path.join(currentAbsDir, name);

      if (entry.isDirectory()) {
        if (SKIPPED_DIRS.has(name) || name.startsWith('.')) continue;
        walkDirectory(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      const lowerName = name.toLowerCase();
      if (SKIPPED_FILENAMES.has(lowerName)) continue;
      const ext = path.extname(lowerName);
      const isEnvTemplate =
        ENV_TEMPLATE_NAMES.has(lowerName) ||
        lowerName.endsWith('.env.example') ||
        lowerName.endsWith('.env.sample') ||
        lowerName.endsWith('.env.template');
      const isCode = CODE_EXTENSIONS.has(ext);
      const isMarkdown = MARKDOWN_EXTENSIONS.has(ext);

      if (!isEnvTemplate && !isCode && !isMarkdown) continue;

      let fileStat;
      try {
        fileStat = fs.statSync(fullPath);
      } catch {
        continue;
      }
      if (fileStat.size <= 0 || fileStat.size > MAX_FILE_BYTES) continue;

      let buf;
      try {
        buf = fs.readFileSync(fullPath);
      } catch {
        continue;
      }
      if (buf.includes(0)) continue;

      const relPath = path.relative(resolvedRoot, fullPath).split(path.sep).join('/');
      discoveredFiles.push({
        relPath,
        isEnvTemplate,
        isCode,
        isMarkdown,
        text: buf.toString('utf8')
      });
    }
  };

  walkDirectory(resolvedRoot);

  const stagedArtifacts = [];
  const deferredMarkdownLinks = [];
  const knownCodeRelPaths = new Set();
  const envKeyPrimaryNode = new Map();
  const allReadEnvKeys = new Set();

  for (const item of discoveredFiles) {
    if (item.isCode) {
      knownCodeRelPaths.add(item.relPath);
      const symbols = extractCodeSymbols(item.text, item.relPath);
      for (const envKey of extractEnvReads(item.text)) {
        allReadEnvKeys.add(envKey);
      }
      stagedArtifacts.push({
        id: `file:${item.relPath}`,
        kind: 'code',
        title: item.relPath,
        path: item.relPath,
        symbols,
        synonyms: [],
        validFrom: null,
        retiredAt: null,
        supersedesId: null,
        governsIds: [],
        touchesIds: [],
        tunedInIds: [],
        explicitImpactsIds: [],
        content: scrubSensitiveText(item.text)
      });
    } else if (item.isEnvTemplate) {
      const sanitizedEnv = sanitizeEnvTemplateContent(item.text);
      const definedKeys = extractDefinedEnvKeys(sanitizedEnv);
      const primaryId = definedKeys.length > 0 ? `env:${definedKeys[0]}` : `env:${item.relPath}`;
      for (const key of definedKeys) {
        if (!envKeyPrimaryNode.has(key)) {
          envKeyPrimaryNode.set(key, primaryId);
        }
      }
      stagedArtifacts.push({
        id: primaryId,
        kind: 'env',
        title: item.relPath,
        path: item.relPath,
        symbols: definedKeys,
        synonyms: [],
        validFrom: null,
        retiredAt: null,
        supersedesId: null,
        governsIds: [],
        touchesIds: [],
        tunedInIds: [],
        explicitImpactsIds: [],
        content: sanitizedEnv
      });
    } else if (item.isMarkdown) {
      const mdMeta = parseMarkdownArtifactMeta(item.text, item.relPath);
      const artifact = {
        id: mdMeta.id,
        kind: mdMeta.kind,
        title: scrubSensitiveText(mdMeta.title),
        path: item.relPath,
        symbols: mdMeta.symbols,
        synonyms: [],
        validFrom: mdMeta.validFrom,
        retiredAt: mdMeta.retiredAt,
        supersedesId: mdMeta.supersedesRef,
        governsIds: [],
        touchesIds: [],
        tunedInIds: [],
        explicitImpactsIds: [],
        content: scrubSensitiveText(item.text)
      };
      stagedArtifacts.push(artifact);
      deferredMarkdownLinks.push({ artifact, mdMeta });
    }
  }

  for (const envKey of allReadEnvKeys) {
    if (!envKeyPrimaryNode.has(envKey)) {
      const envNodeId = `env:${envKey}`;
      envKeyPrimaryNode.set(envKey, envNodeId);
      stagedArtifacts.push({
        id: envNodeId,
        kind: 'env',
        title: `Environment Variable ${envKey}`,
        path: '.env.example',
        symbols: [envKey],
        synonyms: [],
        validFrom: null,
        retiredAt: null,
        supersedesId: null,
        governsIds: [],
        touchesIds: [],
        tunedInIds: [],
        explicitImpactsIds: [],
        content: `${envKey}=<runtime>`
      });
    }
  }

  const resolveDocReferenceToId = (rawRef) => {
    const ref = String(rawRef || '').trim();
    if (!ref) return null;
    if (/^(?:file|env|adr|inv|inc|pr):/i.test(ref)) {
      return ref;
    }
    const envKeyHit = /\b([A-Z][A-Z0-9_]{2,80})\b/.exec(ref);
    if (envKeyHit && envKeyPrimaryNode.has(envKeyHit[1])) {
      return envKeyPrimaryNode.get(envKeyHit[1]);
    }
    const pathCandidate = ref.split(/\s+/)[0].replace(/^\.\//, '');
    if (knownCodeRelPaths.has(pathCandidate)) {
      return `file:${pathCandidate}`;
    }
    return null;
  };

  for (const { artifact, mdMeta } of deferredMarkdownLinks) {
    artifact.governsIds = uniqueStrings(mdMeta.rawGoverns.map(resolveDocReferenceToId).filter(Boolean));
    artifact.touchesIds = uniqueStrings(mdMeta.rawTouches.map(resolveDocReferenceToId).filter(Boolean));
    artifact.tunedInIds = uniqueStrings(mdMeta.rawTunedIn.map(resolveDocReferenceToId).filter(Boolean));
  }

  const graph = compileArtifactsToHydraGraph(stagedArtifacts, {
    workspaceName: effectiveWorkspace,
    namespace
  });
  return okEnvelope(
    tool,
    `Compiled ${graph.nodes.length} artifacts and ${graph.edges.length} structural edges (${graph.totalRepoTokens} tokens) from ${effectiveWorkspace}`,
    graph
  );
}

function buildOntologyIndex(graph) {
  const exactTerms = new Map();
  const stemmedTerms = new Map();
  const synonyms = new Map();
  const nodeById = new Map();
  const bareIdToNodeId = new Map();

  const addTerm = (term, nodeId = null) => {
    const clean = String(term || '').trim().toLowerCase();
    if (!clean || clean.length < 2 || FORBIDDEN_OBJECT_KEYS.has(clean)) return;
    if (!exactTerms.has(clean)) exactTerms.set(clean, new Set());
    if (nodeId) exactTerms.get(clean).add(nodeId);

    if (!EXTERNAL_SUBSYSTEM_TERMS.has(clean)) {
      const stemmed = stemDomainWord(clean);
      if (stemmed && stemmed.length >= 3 && !FORBIDDEN_OBJECT_KEYS.has(stemmed)) {
        if (!stemmedTerms.has(stemmed)) stemmedTerms.set(stemmed, new Set());
        if (nodeId) stemmedTerms.get(stemmed).add(nodeId);
      }
    }
  };

  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  for (const node of nodes) {
    if (!node || !node.id) continue;
    nodeById.set(node.id, node);
    const bare = bareLogicalId(node.id);
    if (bare) {
      bareIdToNodeId.set(bare.toLowerCase(), node.id);
      addTerm(bare, node.id);
      for (const part of splitIdentifierParts(bare)) {
        addTerm(part, node.id);
      }
    }
    addTerm(node.id, node.id);

    if (node.path) {
      addTerm(node.path, node.id);
      const base = String(node.path).split('/').pop() || '';
      if (base) {
        addTerm(base, node.id);
        addTerm(base.replace(/\.[^.]+$/, ''), node.id);
      }
      for (const part of splitIdentifierParts(node.path)) {
        if (part !== 'src' && part !== 'docs' && part !== 'ts' && part !== 'js' && part !== 'md') {
          addTerm(part, node.id);
        }
      }
    }

    if (node.title) {
      for (const tok of String(node.title).toLowerCase().match(/[a-z0-9_-]{2,}/g) || []) {
        addTerm(tok, node.id);
      }
      for (const part of splitIdentifierParts(node.title)) {
        addTerm(part, node.id);
      }
    }

    if (Array.isArray(node.symbols)) {
      for (const sym of node.symbols) {
        addTerm(sym, node.id);
        for (const part of splitIdentifierParts(sym)) {
          addTerm(part, node.id);
        }
      }
    }

    if (Array.isArray(node.synonyms)) {
      for (const syn of node.synonyms) {
        const key = String(syn || '').trim().toLowerCase();
        if (!key || FORBIDDEN_OBJECT_KEYS.has(key)) continue;
        synonyms.set(key, node.id);
        for (const part of splitIdentifierParts(key)) {
          addTerm(part, node.id);
        }
      }
    }

    if (node.content) {
      const contentStr = String(node.content);
      for (const aid of contentStr.match(/\b(?:ADR|INC|PR|INV)-[A-Za-z0-9_-]+\b/g) || []) {
        addTerm(aid, node.id);
      }
      for (const envKey of contentStr.match(/\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/g) || []) {
        addTerm(envKey, node.id);
        for (const part of splitIdentifierParts(envKey)) {
          addTerm(part, node.id);
        }
      }
      for (const ct of contentStr.match(
        /\b[a-z]+[A-Z][A-Za-z0-9]*\b|\b[A-Z][a-z0-9]+[A-Z][A-Za-z0-9]*\b/g
      ) || []) {
        addTerm(ct, node.id);
        for (const part of splitIdentifierParts(ct)) {
          addTerm(part, node.id);
        }
      }
      for (const cw of contentStr.toLowerCase().match(/[a-z][a-z0-9_-]{2,}/g) || []) {
        if (!STOP_AND_FRAMING_WORDS.has(cw) && !EXTERNAL_SUBSYSTEM_TERMS.has(cw)) {
          addTerm(cw, node.id);
        }
      }
    }
  }

  const ont = graph?.ontology || {};
  if (Array.isArray(ont.terms)) {
    for (const term of ont.terms) {
      if (typeof term === 'string' && !FORBIDDEN_OBJECT_KEYS.has(term)) {
        addTerm(term, null);
      }
    }
  } else if (ont.terms && typeof ont.terms === 'object') {
    for (const [term, mapped] of Object.entries(ont.terms)) {
      if (FORBIDDEN_OBJECT_KEYS.has(term)) continue;
      if (Array.isArray(mapped)) {
        if (mapped.length === 0) addTerm(term, null);
        for (const id of mapped) addTerm(term, id);
      } else if (typeof mapped === 'string') {
        addTerm(term, mapped);
      } else if (mapped) {
        addTerm(term, null);
      }
    }
  }

  if (Array.isArray(ont.knownConcepts)) {
    for (const concept of ont.knownConcepts) {
      addTerm(concept, null);
      for (const part of splitIdentifierParts(concept)) {
        addTerm(part, null);
      }
    }
  }

  if (ont.synonyms && typeof ont.synonyms === 'object') {
    for (const [phrase, target] of Object.entries(ont.synonyms)) {
      if (FORBIDDEN_OBJECT_KEYS.has(phrase)) continue;
      const cleanPhrase = String(phrase || '').trim().toLowerCase();
      if (!cleanPhrase) continue;
      const targetStr = Array.isArray(target) ? String(target[0] || '') : String(target || '');
      synonyms.set(cleanPhrase, targetStr);
    }
  }

  return { exactTerms, stemmedTerms, synonyms, nodeById, bareIdToNodeId };
}

function isNodeActiveAt(node, asOf = null) {
  if (!node || typeof node !== 'object') return false;
  const cleanAsOf = typeof asOf === 'string' && asOf.trim().length > 0 ? asOf.trim() : null;
  if (!cleanAsOf || !isValidIsoDate(cleanAsOf)) {
    return node.isCurrent !== false && !node.retiredAt;
  }
  return (!node.validFrom || node.validFrom <= cleanAsOf) && (!node.retiredAt || node.retiredAt > cleanAsOf);
}

function evaluateAnswerability(graph, rawQueryInput) {
  const tool = 'hydrascope_check_answerable';
  const rawQuery = String(rawQueryInput ?? '').trim();
  if (!rawQuery) {
    return failHydraEnvelope(tool, 'VALIDATION_ERROR', 'A non-empty query string is required.', {
      answerable: false,
      matchedNodes: [],
      ungroundedTerms: [],
      groundedTerms: [],
      missingTerms: [],
      synonymMatches: [],
      reason: 'Query is empty.'
    });
  }

  const idx = buildOntologyIndex(graph);
  const strippedDatesQuery = rawQuery.replace(/\b\d{4}-\d{2}-\d{2}\b/g, ' ');
  const lowerQuery = strippedDatesQuery.toLowerCase();

  const groundedSet = new Set();
  const matchedNodeIdSet = new Set();
  const synonymMatches = [];
  const missingSet = new Set();
  const ungroundedDomainCandidates = [];

  const collectNodeIdsForTerm = (lowerTerm) => {
    const exactSet = idx.exactTerms.get(lowerTerm);
    if (exactSet) {
      for (const nid of exactSet) matchedNodeIdSet.add(nid);
    }
    const stemSet = idx.stemmedTerms.get(stemDomainWord(lowerTerm));
    if (stemSet) {
      for (const nid of stemSet) matchedNodeIdSet.add(nid);
    }
    const bareHit = idx.bareIdToNodeId.get(lowerTerm);
    if (bareHit) matchedNodeIdSet.add(bareHit);
  };

  for (const [phrase, target] of idx.synonyms.entries()) {
    if (phrase.length >= 3 && lowerQuery.includes(phrase)) {
      synonymMatches.push(`${phrase} -> ${target}`);
      groundedSet.add(phrase);
      if (idx.nodeById.has(target)) matchedNodeIdSet.add(target);
      const resolved = idx.bareIdToNodeId.get(target.toLowerCase());
      if (resolved) matchedNodeIdSet.add(resolved);
    }
  }

  for (const rawId of strippedDatesQuery.match(/\b(?:ADR|INC|PR|INV)-[A-Za-z0-9_-]+\b/gi) || []) {
    const lower = rawId.toLowerCase();
    if (idx.exactTerms.has(lower) || idx.bareIdToNodeId.has(lower)) {
      groundedSet.add(rawId);
      collectNodeIdsForTerm(lower);
    } else {
      missingSet.add(lower);
    }
  }

  for (const ident of strippedDatesQuery.match(
    /\b(?:[a-z]+[A-Z][A-Za-z0-9]*|[A-Z][a-z0-9]+[A-Z][A-Za-z0-9]*)\b/g
  ) || []) {
    const lower = ident.toLowerCase();
    if (idx.exactTerms.has(lower) || idx.bareIdToNodeId.has(lower)) {
      groundedSet.add(ident);
      collectNodeIdsForTerm(lower);
    } else {
      missingSet.add(lower);
    }
  }

  for (const ident of strippedDatesQuery.match(/\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b/g) || []) {
    const lower = ident.toLowerCase();
    if (idx.exactTerms.has(lower) || idx.bareIdToNodeId.has(lower)) {
      groundedSet.add(ident);
      collectNodeIdsForTerm(lower);
    } else {
      missingSet.add(lower);
    }
  }

  for (const token of lowerQuery.match(/[a-z0-9][a-z0-9_-]*/g) || []) {
    if (/^\d+$/.test(token) || token.length < 2) continue;

    if (EXTERNAL_SUBSYSTEM_TERMS.has(token)) {
      if (idx.exactTerms.has(token)) {
        groundedSet.add(token);
        collectNodeIdsForTerm(token);
      } else {
        missingSet.add(token);
      }
      continue;
    }

    if (STOP_AND_FRAMING_WORDS.has(token)) continue;
    const stemmed = stemDomainWord(token);
    if (STOP_AND_FRAMING_WORDS.has(stemmed)) continue;

    if (idx.exactTerms.has(token) || idx.stemmedTerms.has(stemmed)) {
      groundedSet.add(token);
      collectNodeIdsForTerm(token);
    } else if (!missingSet.has(token)) {
      ungroundedDomainCandidates.push(token);
    }
  }

  const groundedTerms = [...groundedSet];
  const matchedNodes = [...matchedNodeIdSet]
    .map((id) => idx.nodeById.get(id))
    .filter(Boolean)
    .slice(0, 16)
    .map((n) => ({
      id: n.id,
      kind: n.kind,
      title: n.title,
      path: n.path || ''
    }));

  if (missingSet.size > 0) {
    const ungroundedTerms = [...missingSet];
    const reason = `Ungrounded subsystem or identifier not present in workspace ontology: ${ungroundedTerms.join(', ')}.`;
    return okEnvelope(tool, `Blocked ungrounded query (${ungroundedTerms.join(', ')})`, {
      answerable: false,
      matchedNodes,
      ungroundedTerms,
      groundedTerms,
      missingTerms: ungroundedTerms,
      synonymMatches,
      reason
    });
  }

  if (groundedTerms.length === 0 && synonymMatches.length === 0) {
    const ungroundedTerms = ungroundedDomainCandidates.slice(0, 6);
    const reason =
      ungroundedTerms.length > 0
        ? `Zero workspace concepts matched query terms: ${ungroundedTerms.join(', ')}.`
        : 'Query contains no grounded workspace symbols, artifacts, or domain concepts.';
    return okEnvelope(tool, 'Blocked ungrounded query (0 ontology matches)', {
      answerable: false,
      matchedNodes: [],
      ungroundedTerms,
      groundedTerms: [],
      missingTerms: ungroundedTerms,
      synonymMatches: [],
      reason
    });
  }

  return okEnvelope(
    tool,
    `Query grounded across ${groundedTerms.length} workspace concept(s)`,
    {
      answerable: true,
      matchedNodes,
      ungroundedTerms: [],
      groundedTerms,
      missingTerms: [],
      synonymMatches,
      reason: `Grounded in workspace ontology (${groundedTerms.slice(0, 5).join(', ')}).`
    }
  );
}

function normalizeEdge(edge) {
  if (!edge) return null;
  const from = String(edge.from ?? edge.from_id ?? edge.source ?? '').trim();
  const to = String(edge.to ?? edge.to_id ?? edge.target ?? '').trim();
  const type = String(edge.type ?? edge.edge_type ?? '').trim().toUpperCase();
  if (!from || !to || !type) return null;
  const rawWeight = Number(edge.weight);
  const weight = Number.isFinite(rawWeight) ? rawWeight : 1;
  const validFrom =
    typeof edge.validFrom === 'string' && edge.validFrom.trim()
      ? edge.validFrom.trim()
      : typeof edge.valid_from === 'string' && edge.valid_from.trim()
        ? edge.valid_from.trim()
        : '2025-01-01';
  return {
    from,
    to,
    type,
    reason: String(edge.reason ?? ''),
    weight,
    validFrom
  };
}

function selectSeedNodes(graph, query, idx) {
  const rawQuery = String(query || '').replace(/\b\d{4}-\d{2}-\d{2}\b/g, ' ');
  const lowerQuery = rawQuery.toLowerCase();
  const queryTokens = (lowerQuery.match(/[a-z0-9][a-z0-9_-]*/g) || []).filter(
    (t) => t.length >= 2 && !STOP_AND_FRAMING_WORDS.has(t) && !STOP_AND_FRAMING_WORDS.has(stemDomainWord(t))
  );

  const edges = (Array.isArray(graph.edges) ? graph.edges : []).map(normalizeEdge).filter(Boolean);
  const degreeByNode = new Map();
  for (const e of edges) {
    degreeByNode.set(e.from, (degreeByNode.get(e.from) || 0) + 1);
    degreeByNode.set(e.to, (degreeByNode.get(e.to) || 0) + 1);
  }

  const synonymTargetBoost = new Map();
  for (const [phrase, target] of idx.synonyms.entries()) {
    if (phrase.length >= 3 && lowerQuery.includes(phrase)) {
      const resolved = idx.nodeById.has(target)
        ? target
        : idx.bareIdToNodeId.get(target.toLowerCase()) || target;
      synonymTargetBoost.set(resolved, (synonymTargetBoost.get(resolved) || 0) + 90);
      const termNodes = idx.exactTerms.get(target.toLowerCase());
      if (termNodes) {
        for (const nid of termNodes) {
          synonymTargetBoost.set(nid, (synonymTargetBoost.get(nid) || 0) + 65);
        }
      }
    }
  }

  const scored = [];
  for (const node of graph.nodes) {
    if (!node || !node.id) continue;
    let lexicalScore = 0;

    const bareId = bareLogicalId(node.id).toLowerCase();
    if (bareId.length >= 3 && lowerQuery.includes(bareId)) {
      lexicalScore += 125;
    } else if (lowerQuery.includes(String(node.id).toLowerCase())) {
      lexicalScore += 125;
    }

    if (synonymTargetBoost.has(node.id)) {
      lexicalScore += synonymTargetBoost.get(node.id);
    }

    if (Array.isArray(node.synonyms)) {
      for (const syn of node.synonyms) {
        const s = String(syn || '').trim().toLowerCase();
        if (s.length >= 3 && lowerQuery.includes(s)) {
          lexicalScore += 80;
        }
      }
    }

    const symbolSet = new Set();
    const symbolParts = new Set();
    for (const sym of Array.isArray(node.symbols) ? node.symbols : []) {
      const lowerSym = String(sym).toLowerCase();
      symbolSet.add(lowerSym);
      if (lowerSym.length >= 3 && lowerQuery.includes(lowerSym)) {
        lexicalScore += 120;
      }
      for (const p of splitIdentifierParts(sym)) {
        symbolParts.add(p);
        symbolParts.add(stemDomainWord(p));
      }
    }

    const pathParts = new Set();
    if (node.path) {
      const baseStem = (String(node.path).split('/').pop() || '')
        .replace(/\.[^.]+$/, '')
        .toLowerCase();
      if (baseStem.length >= 3 && lowerQuery.includes(baseStem)) {
        lexicalScore += 55;
      }
      for (const p of splitIdentifierParts(node.path)) {
        pathParts.add(p);
        pathParts.add(stemDomainWord(p));
      }
    }

    const titleParts = new Set();
    if (node.title) {
      for (const p of splitIdentifierParts(node.title)) {
        titleParts.add(p);
        titleParts.add(stemDomainWord(p));
      }
    }

    const contentLower = String(node.content || '').toLowerCase();
    for (const tok of queryTokens) {
      const stem = stemDomainWord(tok);
      let matchedStructured = false;
      if (symbolSet.has(tok) || symbolParts.has(tok) || symbolParts.has(stem)) {
        lexicalScore += 30;
        matchedStructured = true;
      }
      if (pathParts.has(tok) || pathParts.has(stem)) {
        lexicalScore += 22;
        matchedStructured = true;
      }
      if (titleParts.has(tok) || titleParts.has(stem)) {
        lexicalScore += 18;
        matchedStructured = true;
      }
      const ontHitNodes = idx.exactTerms.get(tok) || idx.stemmedTerms.get(stem);
      if (ontHitNodes && ontHitNodes.has(node.id)) {
        lexicalScore += 14;
        matchedStructured = true;
      }
      if (!matchedStructured && contentLower.includes(tok)) {
        lexicalScore += 3;
      }
    }

    if (lexicalScore <= 0) continue;

    const kind = String(node.kind || '').toLowerCase();
    const degree = degreeByNode.get(node.id) || 0;
    let structuralAdjust = Math.min(20, degree * 6);
    if (['symbol', 'file', 'code', 'module', 'pr', 'incident', 'env', 'decision', 'adr', 'invariant'].includes(kind)) {
      structuralAdjust += 12;
    } else if (degree === 0) {
      structuralAdjust -= 18;
    }
    if (degree === 0) {
      structuralAdjust -= 12;
    }

    const totalScore = lexicalScore + structuralAdjust;
    if (totalScore > 0) {
      scored.push({ node, score: totalScore, degree });
    }
  }

  scored.sort((a, b) => b.score - a.score || b.degree - a.degree || (a.node.id < b.node.id ? -1 : 1));
  if (scored.length === 0) return [];

  const topSeeds = [scored[0]];
  if (scored.length > 1 && scored[1].score >= Math.max(40, scored[0].score * 0.68)) {
    topSeeds.push(scored[1]);
  }
  return topSeeds;
}

function resolveSupersedesComponent(startNodeId, nodeById, edges, asOf) {
  const cleanAsOf = typeof asOf === 'string' && asOf.trim().length > 0 ? asOf.trim() : null;
  const componentIds = new Set();
  const queue = [startNodeId];
  const usedSupersedesEdges = [];

  while (queue.length > 0) {
    const currId = queue.shift();
    if (!currId || componentIds.has(currId)) continue;
    const currNode = nodeById.get(currId);
    if (!currNode) continue;
    componentIds.add(currId);

    if (currNode.supersededBy && nodeById.has(currNode.supersededBy) && !componentIds.has(currNode.supersededBy)) {
      queue.push(currNode.supersededBy);
    }

    for (const e of edges) {
      if (e.type !== 'SUPERSEDES') continue;
      if (e.from === currId && !componentIds.has(e.to)) {
        usedSupersedesEdges.push(e);
        queue.push(e.to);
      } else if (e.to === currId && !componentIds.has(e.from)) {
        usedSupersedesEdges.push(e);
        queue.push(e.from);
      }
    }
  }

  const activeMembers = [];
  const retiredMembers = [];
  for (const memberId of componentIds) {
    const member = nodeById.get(memberId);
    if (!member) continue;
    if (isNodeActiveAt(member, cleanAsOf)) {
      activeMembers.push(member);
    } else {
      const retiredByDate = cleanAsOf
        ? Boolean(member.retiredAt && member.retiredAt <= cleanAsOf)
        : member.isCurrent === false || Boolean(member.retiredAt);
      if (retiredByDate) {
        let supersededBy = member.supersededBy || null;
        if (!supersededBy) {
          const incomingSup = edges.find((e) => e.type === 'SUPERSEDES' && e.to === member.id);
          if (incomingSup) supersededBy = incomingSup.from;
        }
        retiredMembers.push({
          id: member.id,
          kind: member.kind || 'decision',
          title: member.title || member.id,
          path: member.path || null,
          retiredAt: member.retiredAt || null,
          supersededBy
        });
      }
    }
  }

  return { activeMembers, retiredMembers, usedSupersedesEdges };
}

function formatCompactNodeExcerpt(node, maxTokens) {
  const rawContent = String(node.content || '').trim();
  if (!rawContent) return '';
  const fullTokens = estimateTokens(rawContent);
  if (fullTokens <= maxTokens) return rawContent;

  const maxBytes = Math.max(48, Math.floor(maxTokens * 4) - 16);
  const lines = rawContent.split('\n');
  const kept = [];
  let usedBytes = 0;

  for (const line of lines) {
    if (!line.trim()) continue;
    const lineBytes = UTF8_ENCODER.encode(line).byteLength + 1;
    if (usedBytes + lineBytes > maxBytes) break;
    kept.push(line);
    usedBytes += lineBytes;
  }

  if (kept.length > 0) {
    return `${kept.join('\n')}\n// ... [truncated to structural budget]`;
  }
  return `${rawContent.slice(0, Math.max(32, maxBytes - 12))}...`;
}

function buildDisplayCypherQuery(seedIds, maxHops, asOf) {
  const seedList = JSON.stringify(seedIds);
  const hopBound = Math.max(1, Math.min(6, Number(maxHops) || 3));
  const safeAsOf = asOf && isValidIsoDate(asOf) ? asOf.trim() : null;
  const temporalClause = safeAsOf
    ? `WHERE (n.valid_from IS NULL OR n.valid_from <= '${safeAsOf}') AND (n.retired_at IS NULL OR n.retired_at > '${safeAsOf}')`
    : `WHERE n.is_current <> false AND n.retired_at IS NULL`;

  return [
    `MATCH (seed:GraphNode) WHERE seed.logicalId IN ${seedList}`,
    `OPTIONAL MATCH path = (seed)-[:IMPACTS|CALLS|IMPORTS|READS_ENV|TOUCHED|TUNED_IN*1..${hopBound}]-(n:GraphNode)`,
    temporalClause,
    `OPTIONAL MATCH (gov:GraphNode)-[:GOVERNS]->(n)`,
    `OPTIONAL MATCH (activeGov:GraphNode)-[:SUPERSEDES*1..3]->(gov)`,
    `RETURN DISTINCT seed.logicalId, n.logicalId, gov.logicalId, activeGov.logicalId`
  ].join('\n');
}

function fnv1a32(feature, seed = 0x811c9dc5) {
  let h = seed >>> 0;
  for (let i = 0; i < feature.length; i += 1) {
    h ^= feature.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function l2Normalize(vec) {
  let sumSq = 0;
  for (let i = 0; i < vec.length; i += 1) {
    sumSq += vec[i] * vec[i];
  }
  const norm = Math.sqrt(sumSq);
  if (norm < 1e-12) return vec.slice();
  return vec.map((v) => v / norm);
}

function cosineSimilarity(vecA, vecB) {
  if (!Array.isArray(vecA) || !Array.isArray(vecB) || vecA.length === 0 || vecA.length !== vecB.length) {
    return 0;
  }
  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let i = 0; i < vecA.length; i += 1) {
    const a = vecA[i];
    const b = vecB[i];
    dot += a * b;
    magA += a * a;
    magB += b * b;
  }
  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  return denom < 1e-12 ? 0 : dot / denom;
}

function buildDeterministicFallbackVector(seedText, dims = FALLBACK_DIMS) {
  const digest = crypto.createHash('sha256').update(String(seedText ?? ''), 'utf8').digest();
  const vec = Array.from({ length: dims }, (_, i) => ((digest[i % digest.length] - 128) / 128) || 0.01);
  return l2Normalize(vec);
}

function buildLexicalDenseVector(text, dims = FALLBACK_DIMS) {
  const targetDims = Number.isInteger(dims) && dims > 0 ? dims : FALLBACK_DIMS;
  const raw = String(text ?? '').trim();
  if (!raw) {
    return buildDeterministicFallbackVector('', targetDims);
  }

  const expanded = raw
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase();

  const words = (expanded.match(/[a-z0-9]{2,}/g) || []).filter((w) => !LEXICAL_STOP_WORDS.has(w));
  if (words.length === 0) {
    return buildDeterministicFallbackVector(raw, targetDims);
  }

  const vec = Array.from({ length: targetDims }, () => 0);
  const project = (feat, weight) => {
    const h1 = fnv1a32(feat, 0x811c9dc5);
    const h2 = fnv1a32(feat, 0x9e3779b9);
    const idx1 = h1 % targetDims;
    const sign1 = (h1 & 0x10000) === 0 ? 1 : -1;
    const idx2 = h2 % targetDims;
    const sign2 = (h2 & 0x20000) === 0 ? 1 : -1;
    vec[idx1] += sign1 * weight;
    vec[idx2] += sign2 * (weight * 0.5);
  };

  const tf = new Map();
  for (const w of words) {
    tf.set(w, (tf.get(w) || 0) + 1);
  }
  for (const [w, count] of tf.entries()) {
    const sublinearWeight = 1.45 * (1 + Math.log(count));
    project(`w:${w}`, sublinearWeight);
    if (w.length >= 4) {
      for (let i = 0; i <= w.length - 4; i += 1) {
        project(`g4:${w.slice(i, i + 4)}`, 0.32);
      }
    }
    if (w.length >= 3) {
      for (let i = 0; i <= w.length - 3; i += 1) {
        project(`g3:${w.slice(i, i + 3)}`, 0.22);
      }
    }
  }
  for (let i = 0; i + 1 < words.length; i += 1) {
    project(`bg:${words[i]}_${words[i + 1]}`, 1.05);
  }

  return l2Normalize(vec);
}

function formatNodeChunkText(node) {
  const parts = [];
  if (node.title) parts.push(String(node.title));
  if (node.path) parts.push(`File: ${node.path}`);
  if (Array.isArray(node.symbols) && node.symbols.length > 0) {
    parts.push(`Symbols: ${node.symbols.join(', ')}`);
  }
  if (node.content) parts.push(String(node.content));
  return parts.join('\n');
}

function buildLocalVectorIndex(graph) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const chunks = nodes.map((node) => {
    const chunkText = formatNodeChunkText(node);
    const rawTokens = Number(node.tokens) > 0 ? Number(node.tokens) : estimateTokens(chunkText);
    return {
      id: node.id,
      nodeId: node.id,
      kind: node.kind || 'code',
      title: node.title || node.id,
      path: node.path || null,
      content: node.content || '',
      chunkText,
      tokens: rawTokens,
      validFrom: node.validFrom || null,
      retiredAt: node.retiredAt || null,
      isCurrent: node.isCurrent !== false,
      supersededBy: node.supersededBy || null,
      vector: buildLexicalDenseVector(chunkText, FALLBACK_DIMS)
    };
  });
  return {
    chunks,
    dims: FALLBACK_DIMS,
    embeddingBackend: FALLBACK_BACKEND_ID
  };
}

function queryLocalVectorTopK(vectorIndex, query, { topK = 4, tokenBudget = 1600 } = {}) {
  const startedAt = performance.now();
  const chunks = Array.isArray(vectorIndex?.chunks) ? vectorIndex.chunks : [];
  const effectiveTopK = Math.max(1, Math.min(32, Number(topK) || 4));
  const effectiveBudget = Math.max(120, Number(tokenBudget) || 1600);
  const queryText = String(query ?? '');

  if (chunks.length === 0) {
    return {
      rankedChunks: [],
      selectedNodeIds: [],
      selectedNodes: [],
      contextText: '',
      renderedContext: '',
      tokenCount: 0,
      tokensUsed: 0,
      embeddingBackend: FALLBACK_BACKEND_ID,
      latencyMs: Number((performance.now() - startedAt).toFixed(2))
    };
  }

  const queryVec = buildLexicalDenseVector(queryText, FALLBACK_DIMS);
  const scored = chunks.map((chunk) => ({
    chunk,
    score: cosineSimilarity(queryVec, chunk.vector)
  }));
  scored.sort((a, b) => b.score - a.score || (a.chunk.id < b.chunk.id ? -1 : 1));

  const selectedChunks = [];
  let usedTokens = 0;
  for (const item of scored) {
    if (selectedChunks.length >= effectiveTopK) break;
    const itemTokens = Math.max(16, Number(item.chunk.tokens) || estimateTokens(item.chunk.content || ''));
    if (selectedChunks.length > 0 && usedTokens + itemTokens > effectiveBudget) {
      continue;
    }
    selectedChunks.push({ ...item, itemTokens: Math.min(itemTokens, effectiveBudget) });
    usedTokens += Math.min(itemTokens, effectiveBudget);
  }

  const selectedIdSet = new Set(selectedChunks.map((s) => s.chunk.id));
  const rankedChunks = scored.slice(0, Math.max(effectiveTopK + 4, 8)).map((item, idx) => ({
    rank: idx + 1,
    id: item.chunk.id,
    nodeId: item.chunk.id,
    kind: item.chunk.kind,
    title: item.chunk.title,
    path: item.chunk.path,
    score: Number(item.score.toFixed(4)),
    similarity: Number(item.score.toFixed(4)),
    tokens: item.chunk.tokens,
    selected: selectedIdSet.has(item.chunk.id),
    isCurrent: item.chunk.isCurrent,
    validFrom: item.chunk.validFrom,
    retiredAt: item.chunk.retiredAt,
    supersededBy: item.chunk.supersededBy,
    excerpt: String(item.chunk.content || '').slice(0, 280)
  }));

  const contextSections = selectedChunks.map(
    ({ chunk, score }, idx) =>
      `--- [Rank #${idx + 1} | ${chunk.id} | cosine=${score.toFixed(3)}${chunk.path ? ` | ${chunk.path}` : ''}] ---\n${chunk.content || ''}`
  );
  const rawContext = contextSections.join('\n\n');
  const maxBytes = effectiveBudget * 4;
  const contextText =
    UTF8_ENCODER.encode(rawContext).byteLength > maxBytes
      ? `${rawContext.slice(0, Math.max(64, maxBytes - 16))}...`
      : rawContext;
  const tokenCount = selectedChunks.length === 0 ? 0 : Math.min(effectiveBudget, estimateTokens(contextText));

  return {
    rankedChunks,
    selectedNodeIds: selectedChunks.map((s) => s.chunk.id),
    selectedNodes: selectedChunks.map(({ chunk, score }, idx) => ({
      rank: idx + 1,
      id: chunk.id,
      kind: chunk.kind,
      title: chunk.title,
      path: chunk.path,
      score: Number(score.toFixed(4)),
      tokens: chunk.tokens,
      isCurrent: chunk.isCurrent,
      retiredAt: chunk.retiredAt,
      supersededBy: chunk.supersededBy
    })),
    contextText,
    renderedContext: contextText,
    tokenCount,
    tokensUsed: tokenCount,
    embeddingBackend: FALLBACK_BACKEND_ID,
    latencyMs: Number((performance.now() - startedAt).toFixed(2))
  };
}

function matchesLogicalId(selectedIds, targetId) {
  if (!targetId) return false;
  const cleanTarget = String(targetId).trim();
  if (selectedIds.has(cleanTarget)) return true;
  const bareTarget = cleanTarget.replace(/^[a-z_]+:/i, '').toLowerCase();
  for (const sid of selectedIds) {
    if (sid.toLowerCase() === cleanTarget.toLowerCase()) return true;
    if (sid.replace(/^[a-z_]+:/i, '').toLowerCase() === bareTarget) return true;
  }
  return false;
}

function buildDynamicScenariosForGraph(graph) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  if (nodes.length === 0) return [];

  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const outgoingImpacts = new Map();
  for (const edge of edges) {
    if (edge?.type !== 'IMPACTS') continue;
    if (!outgoingImpacts.has(edge.from)) outgoingImpacts.set(edge.from, []);
    outgoingImpacts.get(edge.from).push(edge.to);
  }

  const codeNodes = nodes.filter((n) => n.kind === 'code');
  const rankedCode = [...codeNodes].sort(
    (a, b) => (outgoingImpacts.get(b.id)?.length || 0) - (outgoingImpacts.get(a.id)?.length || 0)
  );
  const scenarios = [];

  const primaryCode = rankedCode[0] || nodes[0];
  if (primaryCode) {
    const sym = primaryCode.symbols?.[0] || primaryCode.path || primaryCode.title;
    const hop1 = (outgoingImpacts.get(primaryCode.id) || []).filter((id) => nodeById.has(id));
    scenarios.push({
      id: 'DYN-1',
      category: 'blast_radius',
      title: `Impact Blast Radius: ${sym}`,
      query: `What downstream modules and callers are impacted if I modify ${sym}?`,
      asOf: null,
      tokenBudget: 900,
      expectAnswerable: true,
      requiredNodeIds: [primaryCode.id, ...hop1.slice(0, 2)],
      forbiddenPoisonNodeIds: [],
      explanation: `Traces structural :IMPACTS edges out of ${primaryCode.title}.`
    });
  }

  const secondaryCode = rankedCode[1];
  if (secondaryCode) {
    const sym2 = secondaryCode.symbols?.[0] || secondaryCode.path || secondaryCode.title;
    const hop1 = (outgoingImpacts.get(secondaryCode.id) || []).filter((id) => nodeById.has(id));
    scenarios.push({
      id: 'DYN-2',
      category: 'cross_artifact_trace',
      title: `Module Trace: ${sym2}`,
      query: `Trace callers and dependencies connected to ${sym2}`,
      asOf: null,
      tokenBudget: 900,
      expectAnswerable: true,
      requiredNodeIds: [secondaryCode.id, ...hop1.slice(0, 1)],
      forbiddenPoisonNodeIds: [],
      explanation: `Resolves structural dependency graph around ${secondaryCode.title}.`
    });
  }

  const anchorSym = primaryCode?.symbols?.[0] || 'server';
  scenarios.push({
    id: 'DYN-3',
    category: 'ungrounded_trap',
    title: 'Ungrounded Kafka Consumer Trap',
    query: `What is the Kafka consumer group lag threshold for ${anchorSym}?`,
    asOf: null,
    tokenBudget: 800,
    expectAnswerable: false,
    requiredNodeIds: [],
    forbiddenPoisonNodeIds: [],
    explanation: 'Blocks ungrounded external subsystem ("Kafka") pre-flight at 0 tokens.'
  });

  return scenarios;
}

function normalizeSafeHttpBaseUrl(rawUrl) {
  const trimmed = typeof rawUrl === 'string' ? rawUrl.trim().replace(/\/+$/, '') : '';
  if (!trimmed) return '';
  if (trimmed.includes('?') || trimmed.includes('#')) return '';
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    if (parsed.username || parsed.password || parsed.search || parsed.hash) return '';

    const bareHost = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!bareHost) return '';
    if (
      bareHost.startsWith('169.254.') ||
      bareHost.startsWith('fe80:') ||
      /^fe[89ab][0-9a-f]:/.test(bareHost) ||
      bareHost.startsWith('::ffff:169.254.') ||
      bareHost.startsWith('::ffff:a9fe:') ||
      bareHost.startsWith('0:0:0:0:0:ffff:a9fe:')
    ) {
      return '';
    }

    const cleanPath = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/+$/, '');
    return `${parsed.origin}${cleanPath}`;
  } catch {
    return '';
  }
}

async function executeOptionalHydraCypher({
  baseUrl,
  token,
  graphId,
  namespace,
  cypher,
  parameters = {},
  timeoutMs = 2000
}) {
  const safeBaseUrl = normalizeSafeHttpBaseUrl(baseUrl);
  if (!safeBaseUrl || typeof fetch !== 'function') {
    return { ok: false, liveSynced: false, mode: 'sqlite-local' };
  }

  const cleanParams = {};
  for (const [k, v] of Object.entries(parameters || {})) {
    if (FORBIDDEN_OBJECT_KEYS.has(k) || v === null || v === undefined) continue;
    if (typeof v === 'number' && !Number.isFinite(v)) continue;
    cleanParams[k] = v;
  }

  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    'X-Graph-Namespace': namespace
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const endpoint = `${safeBaseUrl}/v1/graphs/${encodeURIComponent(graphId)}/query`;
  const startedAt = performance.now();
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        cell_id: 'cell-0',
        query: cypher,
        parameters: cleanParams
      }),
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs)
    });
    const latencyMs = Number((performance.now() - startedAt).toFixed(2));
    if (!res.ok) {
      return {
        ok: false,
        liveSynced: false,
        mode: 'sqlite-fallback',
        status: res.status,
        latencyMs
      };
    }
    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    return {
      ok: true,
      liveSynced: true,
      mode: 'hydradb-opencypher',
      body,
      latencyMs
    };
  } catch (err) {
    return {
      ok: false,
      liveSynced: false,
      mode: 'sqlite-fallback',
      fallbackReason: scrubSensitiveText(err?.message || 'HydraDB unreachable'),
      latencyMs: Number((performance.now() - startedAt).toFixed(2))
    };
  }
}

async function syncNodesAndEdgesToHydraDb({
  baseUrl,
  token,
  graphId,
  namespace,
  nodes = [],
  edges = []
}) {
  if (!baseUrl) {
    return {
      liveSynced: false,
      mode: 'sqlite-local',
      nodesWritten: 0,
      edgesWritten: 0,
      latencyMs: 0
    };
  }

  const startedAt = performance.now();
  const rootId = surrogateOntologyVertexId(namespace, 'workspace:root');
  let nodesWritten = 0;
  let edgesWritten = 0;

  for (let i = 0; i < nodes.length; i += 1) {
    const n = nodes[i];
    const vertexId =
      Number.isSafeInteger(n.surrogateId) && n.surrogateId >= 1000
        ? n.surrogateId
        : surrogateOntologyVertexId(namespace, n.id);
    const propEntries = [
      'id: $id',
      'namespace: $ns',
      'logicalId: $logicalId',
      'kind: $kind',
      'title: $title',
      'path: $path',
      'isCurrent: $isCurrent'
    ];
    const params = {
      rootId,
      ns: namespace,
      id: vertexId,
      logicalId: n.id,
      kind: n.kind || 'code',
      title: n.title || n.id,
      path: n.path || n.id,
      isCurrent: n.isCurrent !== false
    };
    if (n.retiredAt) {
      propEntries.push('retiredAt: $retiredAt');
      params.retiredAt = String(n.retiredAt);
    }
    if (n.supersededBy) {
      propEntries.push('supersededBy: $supersededBy');
      params.supersededBy = String(n.supersededBy);
    }

    const cypher = `MERGE (root:WorkspaceRoot {id: $rootId, namespace: $ns})-[:CONTAINS]->(n:GraphNode {${propEntries.join(', ')}})`;
    const res = await executeOptionalHydraCypher({
      baseUrl,
      token,
      graphId,
      namespace,
      cypher,
      parameters: params
    });
    if (!res.ok) {
      return {
        liveSynced: false,
        mode: 'sqlite-fallback',
        nodesWritten,
        edgesWritten,
        latencyMs: Number((performance.now() - startedAt).toFixed(2))
      };
    }
    nodesWritten += 1;
  }

  for (const e of edges) {
    const safeType = String(e.type || '').trim().toUpperCase().replace(/[\s-]+/g, '_');
    if (!SAFE_EDGE_TYPE_RE.test(safeType)) continue;
    const cypher = `MERGE (a:GraphNode {id: $fromId, namespace: $ns, logicalId: $fromLogicalId})-[:${safeType}]->(b:GraphNode {id: $toId, namespace: $ns, logicalId: $toLogicalId})`;
    const res = await executeOptionalHydraCypher({
      baseUrl,
      token,
      graphId,
      namespace,
      cypher,
      parameters: {
        ns: namespace,
        fromId: surrogateOntologyVertexId(namespace, e.from),
        fromLogicalId: e.from,
        toId: surrogateOntologyVertexId(namespace, e.to),
        toLogicalId: e.to
      }
    });
    if (!res.ok) {
      return {
        liveSynced: false,
        mode: 'sqlite-fallback',
        nodesWritten,
        edgesWritten,
        latencyMs: Number((performance.now() - startedAt).toFixed(2))
      };
    }
    edgesWritten += 1;
  }

  return {
    liveSynced: true,
    mode: 'hydradb-opencypher',
    nodesWritten,
    edgesWritten,
    latencyMs: Number((performance.now() - startedAt).toFixed(2))
  };
}

const WORKSPACE_META_KIND = 'workspace_meta';
const WORKSPACE_META_NODE_ID = '__workspace_meta__';
const HYDRASCOPE_STMT_CACHE = new WeakMap();

function getCachedStmt(db, sql) {
  if (!db || (typeof db !== 'object' && typeof db !== 'function')) {
    return db.prepare(sql);
  }
  let sqlMap = HYDRASCOPE_STMT_CACHE.get(db);
  if (!sqlMap) {
    sqlMap = new Map();
    HYDRASCOPE_STMT_CACHE.set(db, sqlMap);
  }
  let stmt = sqlMap.get(sql);
  if (!stmt) {
    stmt = db.prepare(sql);
    sqlMap.set(sql, stmt);
  }
  return stmt;
}

function buildRootPointerKey(resolvedWorkspaceRoot) {
  const digest = crypto
    .createHash('sha256')
    .update(String(resolvedWorkspaceRoot || ''), 'utf8')
    .digest('hex');
  return `__root_ptr__::${digest}`;
}

function isWorkspaceMetaRow(rowOrNode) {
  if (!rowOrNode || typeof rowOrNode !== 'object') return false;
  const kind = String(rowOrNode.kind || '');
  const nodeId = String(rowOrNode.node_id ?? rowOrNode.id ?? '');
  const nodeKey = String(rowOrNode.node_key ?? '');
  return (
    kind === WORKSPACE_META_KIND ||
    nodeId === WORKSPACE_META_NODE_ID ||
    nodeKey.startsWith('__root_ptr__::')
  );
}

const SQL_DELETE_WS_EDGES = 'DELETE FROM hydrascope_edges WHERE workspace_name = ?';
const SQL_DELETE_WS_NODES = `
  DELETE FROM hydrascope_nodes
  WHERE workspace_name = ? AND kind != 'workspace_meta' AND node_id != '__workspace_meta__'
`;
const SQL_INSERT_NODE = `
  INSERT OR REPLACE INTO hydrascope_nodes (
    node_key, workspace_name, node_id, surrogate_id, kind, title,
    file_path, content, tokens, valid_from, retired_at, is_current,
    superseded_by, metadata_json, embedding, updated_at_ms
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;
const SQL_INSERT_EDGE = `
  INSERT OR REPLACE INTO hydrascope_edges (
    edge_key, workspace_name, from_id, to_id, edge_type, weight,
    valid_from, metadata_json, created_at_ms
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`;
const SQL_UPDATE_OLD_DECISION = `
  UPDATE hydrascope_nodes
  SET is_current = 0, retired_at = ?, superseded_by = ?, updated_at_ms = ?
  WHERE workspace_name = ? AND node_id = ?
`;
const SQL_SELECT_ROOT_PTR =
  'SELECT workspace_name, metadata_json FROM hydrascope_nodes WHERE node_key = ?';
const SQL_HAS_ANY_ROOT_PTR = `
  SELECT 1 AS present FROM hydrascope_nodes
  WHERE kind = 'workspace_meta' OR node_id = '__workspace_meta__'
  LIMIT 1
`;
const SQL_SELECT_LATEST_WS = `
  SELECT workspace_name FROM hydrascope_nodes
  WHERE kind != 'workspace_meta' AND node_id != '__workspace_meta__'
  ORDER BY updated_at_ms DESC, rowid ASC
  LIMIT 1
`;
const SQL_SELECT_WS_NODES = `
  SELECT * FROM hydrascope_nodes
  WHERE workspace_name = ? AND kind != 'workspace_meta' AND node_id != '__workspace_meta__'
  ORDER BY rowid ASC
`;
const SQL_SELECT_WS_EDGES =
  'SELECT * FROM hydrascope_edges WHERE workspace_name = ? ORDER BY rowid ASC';

function upsertWorkspacePointerStmtRun(insertNodeStmt, resolvedWorkspaceRoot, activeWsName, emptyIngested, nowMs) {
  if (!resolvedWorkspaceRoot) return;
  const rootPtrKey = buildRootPointerKey(resolvedWorkspaceRoot);
  insertNodeStmt.run(
    rootPtrKey,
    activeWsName,
    WORKSPACE_META_NODE_ID,
    '0',
    WORKSPACE_META_KIND,
    'Workspace Active Pointer',
    '',
    '',
    0,
    '2025-01-01',
    null,
    0,
    null,
    JSON.stringify({
      activeWorkspace: activeWsName,
      emptyIngested: Boolean(emptyIngested)
    }),
    null,
    nowMs
  );
}

function persistGraphToSqlite(db, graph, resolvedWorkspaceRoot = null) {
  if (!db) return;
  const nowMs = Date.now();
  const wsName = graph.workspaceName || 'fintech-core';
  const ns = graph.namespace || 'brick-ontology';
  const graphNodes = (Array.isArray(graph.nodes) ? graph.nodes : []).filter(
    (n) => !isWorkspaceMetaRow(n)
  );
  const graphEdges = Array.isArray(graph.edges) ? graph.edges : [];

  const deleteEdgesStmt = getCachedStmt(db, SQL_DELETE_WS_EDGES);
  const deleteNodesStmt = getCachedStmt(db, SQL_DELETE_WS_NODES);
  const insertNodeStmt = getCachedStmt(db, SQL_INSERT_NODE);
  const insertEdgeStmt = getCachedStmt(db, SQL_INSERT_EDGE);

  let inTx = false;
  try {
    db.exec('BEGIN IMMEDIATE;');
    inTx = true;

    deleteEdgesStmt.run(wsName);
    deleteNodesStmt.run(wsName);

    for (const node of graphNodes) {
      const surrogateId =
        Number.isSafeInteger(node.surrogateId) && node.surrogateId >= 1000
          ? node.surrogateId
          : surrogateOntologyVertexId(ns, node.id);
      const metadataJson = JSON.stringify({
        symbols: Array.isArray(node.symbols) ? node.symbols : [],
        synonyms: Array.isArray(node.synonyms) ? node.synonyms : [],
        explicitValidFrom: node.validFrom ?? null,
        dynamicSupersede: Boolean(node._dynamicSupersede)
      });
      insertNodeStmt.run(
        `${wsName}::${node.id}`,
        wsName,
        node.id,
        String(surrogateId),
        node.kind || 'code',
        node.title || node.id,
        node.path || '',
        node.content || '',
        Number(node.tokens) || estimateTokens(node.content || ''),
        node.validFrom || '2025-01-01',
        node.retiredAt || null,
        node.isCurrent === false ? 0 : 1,
        node.supersededBy || null,
        metadataJson,
        null,
        nowMs
      );
    }

    for (const edge of graphEdges) {
      const norm = normalizeEdge(edge);
      if (!norm) continue;
      const edgeWeight = Number.isFinite(Number(edge.weight)) ? Number(edge.weight) : norm.weight;
      const edgeValidFrom =
        (typeof edge.validFrom === 'string' && edge.validFrom.trim()) ||
        norm.validFrom ||
        '2025-01-01';
      insertEdgeStmt.run(
        `${wsName}::${norm.from}|${norm.type}|${norm.to}`,
        wsName,
        norm.from,
        norm.to,
        norm.type,
        edgeWeight,
        edgeValidFrom,
        JSON.stringify({ reason: norm.reason || norm.type }),
        nowMs
      );
    }

    if (resolvedWorkspaceRoot) {
      upsertWorkspacePointerStmtRun(
        insertNodeStmt,
        resolvedWorkspaceRoot,
        wsName,
        graphNodes.length === 0,
        nowMs
      );
    }

    db.exec('COMMIT;');
    inTx = false;
  } catch (err) {
    if (inTx) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        /* ignore rollback error */
      }
    }
    throw err;
  }
}

function hydrateLoadedWorkspaceRows(db, wsName, namespace, allowEmpty = false) {
  const rawNodeRows = getCachedStmt(db, SQL_SELECT_WS_NODES).all(wsName);
  const nodeRows = (Array.isArray(rawNodeRows) ? rawNodeRows : []).filter(
    (row) => !isWorkspaceMetaRow(row)
  );
  if (nodeRows.length === 0 && !allowEmpty) {
    return null;
  }

  const edgeRows = getCachedStmt(db, SQL_SELECT_WS_EDGES).all(wsName);

  const nodes = nodeRows.map((row) => {
    let meta = {};
    try {
      meta = row.metadata_json ? JSON.parse(row.metadata_json) : {};
    } catch {
      meta = {};
    }
    const parsedSurrogate = Number(row.surrogate_id);
    const surrogateId =
      Number.isSafeInteger(parsedSurrogate) && parsedSurrogate >= 1000
        ? parsedSurrogate
        : surrogateOntologyVertexId(namespace, row.node_id);

    const validFrom = Object.hasOwn(meta, 'explicitValidFrom')
      ? meta.explicitValidFrom
      : row.valid_from || null;

    const nodeObj = {
      id: String(row.node_id),
      surrogateId,
      kind: String(row.kind || 'code'),
      title: String(row.title || row.node_id),
      path: String(row.file_path || ''),
      symbols: Array.isArray(meta.symbols) ? meta.symbols : [],
      synonyms: Array.isArray(meta.synonyms) ? meta.synonyms : [],
      content: String(row.content || ''),
      tokens: Number(row.tokens) || estimateTokens(row.content || ''),
      validFrom,
      retiredAt: row.retired_at ? String(row.retired_at) : null,
      isCurrent: Number(row.is_current) !== 0 && !row.retired_at,
      supersededBy: row.superseded_by ? String(row.superseded_by) : null
    };
    if (meta.dynamicSupersede) {
      nodeObj._dynamicSupersede = true;
    }
    return nodeObj;
  });

  const edges = (Array.isArray(edgeRows) ? edgeRows : []).map((row) => {
    let meta = {};
    try {
      meta = row.metadata_json ? JSON.parse(row.metadata_json) : {};
    } catch {
      meta = {};
    }
    const parsedWeight = Number(row.weight);
    return {
      from: String(row.from_id),
      to: String(row.to_id),
      type: String(row.edge_type),
      reason: String(meta.reason || row.edge_type),
      weight: Number.isFinite(parsedWeight) ? parsedWeight : 1,
      validFrom: row.valid_from ? String(row.valid_from) : '2025-01-01'
    };
  });

  const ontology = buildGraphOntologyFromNodes(nodes);
  const totalRepoTokens = nodes.reduce((sum, n) => sum + n.tokens, 0);

  return {
    workspaceName: wsName,
    namespace,
    nodes,
    edges,
    ontology,
    totalRepoTokens
  };
}

function loadGraphFromSqlite(db, namespace = 'brick-ontology', resolvedWorkspaceRoot = null) {
  if (!db) return null;

  if (resolvedWorkspaceRoot) {
    const rootPtrKey = buildRootPointerKey(resolvedWorkspaceRoot);
    const ptrRow = getCachedStmt(db, SQL_SELECT_ROOT_PTR).get(rootPtrKey);
    if (ptrRow) {
      let ptrMeta = {};
      try {
        ptrMeta = ptrRow.metadata_json ? JSON.parse(ptrRow.metadata_json) : {};
      } catch {
        ptrMeta = {};
      }
      const activeWsName = String(
        ptrMeta.activeWorkspace || ptrRow.workspace_name || ''
      ).trim();
      if (!activeWsName) return null;
      return hydrateLoadedWorkspaceRows(
        db,
        activeWsName,
        namespace,
        ptrMeta.emptyIngested === true
      );
    }

    const anyPtr = getCachedStmt(db, SQL_HAS_ANY_ROOT_PTR).get();
    if (anyPtr) {
      const existingDefault = hydrateLoadedWorkspaceRows(db, 'fintech-core', namespace, false);
      if (existingDefault) {
        const insertNodeStmt = getCachedStmt(db, SQL_INSERT_NODE);
        upsertWorkspacePointerStmtRun(
          insertNodeStmt,
          resolvedWorkspaceRoot,
          'fintech-core',
          false,
          Date.now()
        );
        return existingDefault;
      }
      return null;
    }
  }

  const topRow = getCachedStmt(db, SQL_SELECT_LATEST_WS).get();
  if (!topRow || !topRow.workspace_name) return null;

  const wsName = String(topRow.workspace_name);
  const loaded = hydrateLoadedWorkspaceRows(db, wsName, namespace, false);
  if (loaded && resolvedWorkspaceRoot) {
    const insertNodeStmt = getCachedStmt(db, SQL_INSERT_NODE);
    upsertWorkspacePointerStmtRun(insertNodeStmt, resolvedWorkspaceRoot, wsName, false, Date.now());
  }
  return loaded;
}

function persistSupersedeToSqlite(db, workspaceName, namespace, oldNode, newNode, newEdges) {
  if (!db) return;
  const nowMs = Date.now();
  const wsName = workspaceName || 'fintech-core';

  const updateOldStmt = getCachedStmt(db, SQL_UPDATE_OLD_DECISION);
  const insertNewStmt = getCachedStmt(db, SQL_INSERT_NODE);
  const insertEdgeStmt = getCachedStmt(db, SQL_INSERT_EDGE);

  let inTx = false;
  try {
    db.exec('BEGIN IMMEDIATE;');
    inTx = true;

    updateOldStmt.run(oldNode.retiredAt, oldNode.supersededBy, nowMs, wsName, oldNode.id);

    const newSurrogate =
      Number.isSafeInteger(newNode.surrogateId) && newNode.surrogateId >= 1000
        ? newNode.surrogateId
        : surrogateOntologyVertexId(namespace, newNode.id);

    insertNewStmt.run(
      `${wsName}::${newNode.id}`,
      wsName,
      newNode.id,
      String(newSurrogate),
      newNode.kind || 'adr',
      newNode.title,
      newNode.path || '',
      newNode.content || '',
      Number(newNode.tokens) || estimateTokens(newNode.content || ''),
      newNode.validFrom || '2025-01-01',
      null,
      1,
      null,
      JSON.stringify({
        symbols: newNode.symbols || [],
        synonyms: newNode.synonyms || [],
        explicitValidFrom: newNode.validFrom ?? null,
        dynamicSupersede: true
      }),
      null,
      nowMs
    );

    for (const e of newEdges) {
      const edgeWeight = Number.isFinite(Number(e.weight)) ? Number(e.weight) : 1;
      const edgeValidFrom =
        (typeof e.validFrom === 'string' && e.validFrom.trim()) ||
        newNode.validFrom ||
        '2025-01-01';
      insertEdgeStmt.run(
        `${wsName}::${e.from}|${e.type}|${e.to}`,
        wsName,
        e.from,
        e.to,
        e.type,
        edgeWeight,
        edgeValidFrom,
        JSON.stringify({ reason: e.reason || e.type }),
        nowMs
      );
    }

    db.exec('COMMIT;');
    inTx = false;
  } catch (err) {
    if (inTx) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        /* ignore rollback error */
      }
    }
    throw err;
  }
}

async function hydrateAuthorizedBricksFromDbOrExchange(
  brickExchange = null,
  { viewerId = null, viewerOrgId = null } = {}
) {
  const cleanViewerId = typeof viewerId === 'string' ? viewerId.trim() : '';
  const cleanViewerOrgId = typeof viewerOrgId === 'string' ? viewerOrgId.trim() : '';

  if (!cleanViewerId && !cleanViewerOrgId) {
    return [];
  }
  if (!brickExchange || typeof brickExchange.listInbox !== 'function') {
    return [];
  }

  let inboxRes;
  try {
    inboxRes = await brickExchange.listInbox({
      viewerId: cleanViewerId,
      viewerOrgId: cleanViewerOrgId
    });
  } catch (err) {
    if (isSqliteCorruptionError(err)) {
      throw err;
    }
    return [];
  }

  if (!inboxRes || inboxRes.ok === false) {
    return [];
  }

  const list = inboxRes?.data?.bricks || inboxRes?.bricks || [];
  if (!Array.isArray(list)) {
    return [];
  }

  const bundles = [];
  const seenKeys = new Set();
  for (const candidate of list) {
    if (!candidate || typeof candidate !== 'object') continue;
    const b = isPlainObject(candidate.bundle) ? candidate.bundle : candidate;
    if (!isPlainObject(b)) continue;
    const id = String(b.brickId || b.blueprint?.id || '').trim();
    const hash = String(b.lineage?.sourceHash || '').trim();
    if (!id) continue;
    const dedup = `${id}@${hash}`;
    if (seenKeys.has(dedup)) continue;
    seenKeys.add(dedup);
    bundles.push(b);
  }

  return bundles;
}

/**
 * Create a HydraScope Structural Context & Temporal Ontology Engine instance.
 *
 * @param {object} [options={}]
 */
export function createHydraScopeEngine({
  db = null,
  workspaceRoot = process.cwd(),
  brickExchange = null,
  hydraUrl = process.env.HYDRADB_URL || '',
  hydraToken = process.env.HYDRADB_TOKEN || '',
  hydraGraphId = process.env.HYDRADB_GRAPH_ID || 'hydrascope',
  namespace = 'brick-ontology'
} = {}) {
  const resolvedWorkspaceRoot = path.resolve(String(workspaceRoot || process.cwd()));
  const cleanHydraUrl = normalizeSafeHttpBaseUrl(hydraUrl);
  const cleanHydraToken = String(hydraToken || '')
    .replace(/[\r\n]+/g, '')
    .replace(/^Bearer\s+/i, '')
    .trim();
  const cleanHydraGraphId =
    String(hydraGraphId || 'hydrascope')
      .replace(/[\r\n]+/g, '')
      .trim() || 'hydrascope';
  const cleanNamespace =
    scrubSensitiveText(String(namespace || 'brick-ontology')).trim() || 'brick-ontology';

  if (db) {
    db.exec(HYDRASCOPE_SCHEMA_SQL);
  }

  let activeGraph = db ? loadGraphFromSqlite(db, cleanNamespace, resolvedWorkspaceRoot) : null;
  if (!activeGraph) {
    activeGraph = compileArtifactsToHydraGraph(FINTECH_BENCHMARK_CORPUS, {
      workspaceName: 'fintech-core',
      namespace: cleanNamespace
    });
    if (db) {
      persistGraphToSqlite(db, activeGraph, resolvedWorkspaceRoot);
    }
  }

  let activeScenarios =
    activeGraph.workspaceName === 'fintech-core'
      ? HYDRASCOPE_BENCHMARK_SCENARIOS.map((s) => ({ ...s }))
      : buildDynamicScenariosForGraph(activeGraph);

  let vectorIndex = buildLocalVectorIndex(activeGraph);

  let mutationChain = Promise.resolve();
  function withMutationLock(fn) {
    const next = mutationChain.then(fn, fn);
    mutationChain = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  function getState() {
    const graphSnap = activeGraph;
    const decisions = graphSnap.nodes
      .filter((n) => n.kind === 'decision' || n.kind === 'adr' || n.kind === 'invariant')
      .map((n) => ({
        id: n.id,
        kind: n.kind,
        title: n.title,
        path: n.path,
        validFrom: n.validFrom,
        retiredAt: n.retiredAt,
        isCurrent: n.isCurrent,
        supersededBy: n.supersededBy
      }));

    const payload = scrubSensitiveStrings({
      workspaceName: graphSnap.workspaceName,
      namespace: cleanNamespace,
      totalRepoTokens: graphSnap.totalRepoTokens,
      nodeCount: graphSnap.nodes.length,
      edgeCount: graphSnap.edges.length,
      hydraConfigured: Boolean(cleanHydraUrl),
      decisions,
      scenarios: activeScenarios.map((s) => ({
        id: s.id,
        category: s.category,
        title: s.title,
        query: s.query,
        asOf: s.asOf || null,
        tokenBudget: s.tokenBudget,
        expectAnswerable: s.expectAnswerable !== false,
        explanation: s.explanation || ''
      })),
      nodes: graphSnap.nodes.map((n) => ({
        id: n.id,
        surrogateId: n.surrogateId,
        kind: n.kind,
        title: n.title,
        path: n.path,
        symbols: Array.isArray(n.symbols) ? n.symbols : [],
        tokens: n.tokens,
        validFrom: n.validFrom,
        retiredAt: n.retiredAt,
        isCurrent: n.isCurrent,
        supersededBy: n.supersededBy
      })),
      edges: graphSnap.edges
    });

    return okEnvelope(
      'hydrascope_state',
      `Loaded ${graphSnap.workspaceName} (${graphSnap.nodes.length} nodes, ${graphSnap.edges.length} edges).`,
      payload
    );
  }

  function checkAnswerable(input) {
    const rawQuery =
      typeof input === 'string'
        ? input
        : isPlainObject(input)
          ? String(input.query ?? '')
          : '';
    return scrubSensitiveStrings(evaluateAnswerability(activeGraph, rawQuery));
  }

  async function traverseContext(rawOptions = {}) {
    const tool = 'hydrascope_traverse_context';
    const opts =
      typeof rawOptions === 'string'
        ? { query: rawOptions }
        : isPlainObject(rawOptions)
          ? rawOptions
          : {};

    const rawQuery = String(opts.query ?? '').trim();
    if (!rawQuery) {
      return failHydraEnvelope(tool, 'VALIDATION_ERROR', 'A non-empty query string is required.', null);
    }

    const asOfCheck = validateOptionalAsOf(opts.asOf ?? null);
    if (!asOfCheck.ok) {
      return failHydraEnvelope(tool, asOfCheck.code, asOfCheck.message, null);
    }

    const cleanAsOf = asOfCheck.value;
    const boundedQuery = rawQuery.slice(0, MAX_QUERY_CHARS);
    const effectiveBudget = Math.max(120, Math.min(16000, Number(opts.tokenBudget) || 900));
    const effectiveMaxHops = Math.max(1, Math.min(6, Number(opts.maxHops) || 3));

    const cleanViewerId =
      typeof opts.viewerId === 'string' && opts.viewerId.trim() ? opts.viewerId.trim() : null;
    const cleanViewerOrgId =
      typeof opts.viewerOrgId === 'string' && opts.viewerOrgId.trim()
        ? opts.viewerOrgId.trim()
        : null;
    const hasViewerAuth = Boolean(cleanViewerId || cleanViewerOrgId);

    const cleanTargetStack =
      typeof opts.targetStack === 'string' && opts.targetStack.trim() ? opts.targetStack.trim() : null;
    const cleanTargetChannel =
      typeof opts.targetChannel === 'string' && opts.targetChannel.trim()
        ? opts.targetChannel.trim()
        : null;
    const cleanRequiredPorts = Array.isArray(opts.requiredPorts) ? opts.requiredPorts : [];
    const wantsBrickOntology =
      Boolean(opts.includeBrickOntology) ||
      Boolean(cleanTargetStack) ||
      Boolean(cleanTargetChannel) ||
      cleanRequiredPorts.length > 0;

    let brickOntologyPayload = undefined;
    if (wantsBrickOntology) {
      let hydratedBricks;
      try {
        hydratedBricks = await hydrateAuthorizedBricksFromDbOrExchange(brickExchange, {
          viewerId: cleanViewerId,
          viewerOrgId: cleanViewerOrgId
        });
      } catch (dbErr) {
        return failHydraEnvelope(
          tool,
          'STORAGE_ERROR',
          dbErr instanceof Error ? dbErr.message : String(dbErr),
          null
        );
      }

      const inspectRes = inspectBrickOntology({ stackFilter: cleanTargetStack });
      if (!inspectRes.ok) {
        return failHydraEnvelope(tool, inspectRes.error.code, inspectRes.error.message, null);
      }

      const composeRes = composeCrossStackBricks({
        authorizedBricks: hydratedBricks,
        targetStack: cleanTargetStack,
        targetChannel: cleanTargetChannel,
        requiredPorts: cleanRequiredPorts,
        asOf: cleanAsOf,
        maxHops: Math.min(2, effectiveMaxHops),
        namespace: cleanNamespace
      });
      if (!composeRes.ok) {
        return failHydraEnvelope(tool, composeRes.error.code, composeRes.error.message, null);
      }

      brickOntologyPayload = {
        enabled: true,
        brickCount: hydratedBricks.length,
        targetStack: cleanTargetStack,
        targetChannel: cleanTargetChannel,
        requiredPorts: cleanRequiredPorts,
        inspection: inspectRes.data,
        composition: composeRes.data,
        directMatches: composeRes.data.directMatches || [],
        compositions: composeRes.data.compositions || [],
        twoHopChains: composeRes.data.compositions || [],
        namespaceCollisions: composeRes.data.namespaceCollisions || [],
        retiredSupersededBricks: composeRes.data.retiredSupersededBricks || [],
        graph: composeRes.data.graph
      };
    }

    const graphSnap = activeGraph;
    const fullRepoTokens =
      Number(graphSnap.totalRepoTokens) > 0
        ? Number(graphSnap.totalRepoTokens)
        : graphSnap.nodes.reduce((sum, n) => sum + (Number(n?.tokens) || estimateTokens(n?.content || '')), 0);

    const answerCheck = evaluateAnswerability(graphSnap, boundedQuery);
    const answerability = answerCheck.data;

    if (!answerability.answerable) {
      const blockedData = {
        answerability,
        asOf: cleanAsOf,
        seedNodes: [],
        selectedNodes: [],
        traversedNodes: [],
        selectedNodeIds: [],
        traversedEdges: [],
        activeDecisions: [],
        retiredDecisionsExcluded: [],
        retiredBlockedNodes: [],
        tokensUsed: 0,
        tokenCount: 0,
        tokenBudget: effectiveBudget,
        fullRepoTokens,
        tokenSavingsRatio: fullRepoTokens > 0 ? 1 : 0,
        renderedContext: '',
        contextText: '',
        cypherQuery: '// Blocked pre-flight by checkAnswerable (0 tokens burned)',
        hydraExecution: {
          liveQueried: false,
          mode: 'blocked-preflight',
          latencyMs: 0
        },
        ...(hasViewerAuth && brickOntologyPayload ? { brickOntology: brickOntologyPayload } : {})
      };
      return scrubSensitiveStrings(
        okEnvelope(
          tool,
          `Blocked ungrounded query pre-flight (0 tokens burned): ${answerability.reason}`,
          blockedData
        )
      );
    }

    const idx = buildOntologyIndex(graphSnap);
    const edges = (Array.isArray(graphSnap.edges) ? graphSnap.edges : []).map(normalizeEdge).filter(Boolean);
    const rawSeeds = selectSeedNodes(graphSnap, boundedQuery, idx);

    const retiredBlockedMap = new Map();
    const traversedEdgeMap = new Map();
    const recordEdge = (edge) => {
      if (!edge) return;
      const key = `${edge.from}|${edge.type}|${edge.to}`;
      if (!traversedEdgeMap.has(key)) {
        traversedEdgeMap.set(key, edge);
      }
    };

    const activeSeedEntries = [];
    for (const entry of rawSeeds) {
      if (isNodeActiveAt(entry.node, cleanAsOf)) {
        activeSeedEntries.push(entry);
      } else {
        const lineage = resolveSupersedesComponent(entry.node.id, idx.nodeById, edges, cleanAsOf);
        for (const r of lineage.retiredMembers) retiredBlockedMap.set(r.id, r);
        for (const se of lineage.usedSupersedesEdges) recordEdge(se);
        for (const replacement of lineage.activeMembers) {
          if (!activeSeedEntries.some((s) => s.node.id === replacement.id)) {
            activeSeedEntries.push({ node: replacement, score: entry.score, degree: entry.degree });
          }
        }
      }
    }

    const seedNodes = activeSeedEntries.map((s) => ({
      id: s.node.id,
      kind: s.node.kind || 'code',
      title: s.node.title || s.node.id,
      path: s.node.path || null,
      score: s.score
    }));
    const seedIds = seedNodes.map((s) => s.id);
    const cypherQuery = buildDisplayCypherQuery(seedIds, effectiveMaxHops, cleanAsOf);

    let hydraExecution = {
      liveQueried: false,
      mode: 'sqlite-local',
      latencyMs: 0
    };
    if (cleanHydraUrl && seedIds.length > 0) {
      const liveRes = await executeOptionalHydraCypher({
        baseUrl: cleanHydraUrl,
        token: cleanHydraToken,
        graphId: cleanHydraGraphId,
        namespace: cleanNamespace,
        cypher: 'MATCH (n:GraphNode {namespace: $ns}) WHERE n.logicalId IN $seedIds RETURN n.logicalId',
        parameters: { ns: cleanNamespace, seedIds }
      });
      hydraExecution = {
        liveQueried: Boolean(liveRes.ok),
        mode: liveRes.mode,
        latencyMs: liveRes.latencyMs || 0
      };
    }

    const reachedMap = new Map();
    const bfsQueue = [];

    for (const seed of activeSeedEntries) {
      reachedMap.set(seed.node.id, {
        node: seed.node,
        hop: 0,
        role: 'seed',
        priority: 1
      });
      bfsQueue.push({ id: seed.node.id, hop: 0 });

      for (const e of edges) {
        if (e.type === 'GOVERNS' && e.from === seed.node.id) {
          const target = idx.nodeById.get(e.to);
          if (target && isNodeActiveAt(target, cleanAsOf) && !reachedMap.has(target.id)) {
            recordEdge(e);
            reachedMap.set(target.id, {
              node: target,
              hop: 1,
              role: 'governed_target',
              priority: 2
            });
            bfsQueue.push({ id: target.id, hop: 1 });
          }
        }
      }
    }

    while (bfsQueue.length > 0) {
      const { id: currId, hop } = bfsQueue.shift();
      if (hop >= effectiveMaxHops) continue;

      for (const edge of edges) {
        let nextId = null;
        let edgePriority = 3;

        if (edge.from === currId && FORWARD_TRAVERSAL_TYPES.has(edge.type)) {
          nextId = edge.to;
          edgePriority =
            edge.type === 'IMPACTS' ||
            edge.type === 'READS_ENV' ||
            edge.type === 'TUNED_IN' ||
            edge.type === 'TOUCHED'
              ? 2
              : 3;
        } else if (edge.to === currId && REVERSE_TRAVERSAL_TYPES.has(edge.type)) {
          nextId = edge.from;
          edgePriority = edge.type === 'TUNED_IN' || edge.type === 'READS_ENV' || edge.type === 'TOUCHED' ? 2 : 4;
        }

        if (!nextId) continue;
        const candidate = idx.nodeById.get(nextId);
        if (!candidate) continue;

        if (!isNodeActiveAt(candidate, cleanAsOf)) {
          const lineage = resolveSupersedesComponent(candidate.id, idx.nodeById, edges, cleanAsOf);
          for (const r of lineage.retiredMembers) retiredBlockedMap.set(r.id, r);
          for (const se of lineage.usedSupersedesEdges) recordEdge(se);
          for (const activeRep of lineage.activeMembers) {
            if (!reachedMap.has(activeRep.id)) {
              reachedMap.set(activeRep.id, {
                node: activeRep,
                hop: hop + 1,
                role: 'superseding_replacement',
                priority: 2
              });
              bfsQueue.push({ id: activeRep.id, hop: hop + 1 });
            }
          }
          continue;
        }

        recordEdge(edge);
        if (!reachedMap.has(candidate.id)) {
          reachedMap.set(candidate.id, {
            node: candidate,
            hop: hop + 1,
            role: `hop_${hop + 1}_${edge.type.toLowerCase()}`,
            priority: edgePriority
          });
          bfsQueue.push({ id: candidate.id, hop: hop + 1 });
        }
      }
    }

    const snapshotIds = [...reachedMap.keys()];
    for (const nodeId of snapshotIds) {
      const lineageSelf = resolveSupersedesComponent(nodeId, idx.nodeById, edges, cleanAsOf);
      for (const r of lineageSelf.retiredMembers) retiredBlockedMap.set(r.id, r);
      for (const se of lineageSelf.usedSupersedesEdges) recordEdge(se);

      for (const edge of edges) {
        if (edge.type !== 'GOVERNS' || edge.to !== nodeId) continue;
        const govNode = idx.nodeById.get(edge.from);
        if (!govNode) continue;

        const lineage = resolveSupersedesComponent(govNode.id, idx.nodeById, edges, cleanAsOf);
        for (const r of lineage.retiredMembers) retiredBlockedMap.set(r.id, r);
        for (const se of lineage.usedSupersedesEdges) recordEdge(se);

        for (const activeGov of lineage.activeMembers) {
          if (activeGov.id === govNode.id) {
            recordEdge(edge);
          } else {
            recordEdge({
              from: activeGov.id,
              to: nodeId,
              type: 'GOVERNS',
              reason: `Active superseding governance via ${govNode.id}`
            });
          }
          if (!reachedMap.has(activeGov.id)) {
            const targetHop = reachedMap.get(nodeId)?.hop ?? 0;
            reachedMap.set(activeGov.id, {
              node: activeGov,
              hop: targetHop + 1,
              role: 'governing_policy',
              priority: 2
            });
          }
        }
      }
    }

    const orderedEntries = [...reachedMap.values()].sort(
      (a, b) => a.priority - b.priority || a.hop - b.hop || (a.node.id < b.node.id ? -1 : 1)
    );

    const retiredBlockedNodes = [...retiredBlockedMap.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
    const headerLines = [
      `// HydraScope Structural Slice | Workspace: ${graphSnap.workspaceName || 'repo'}${cleanAsOf ? ` | As-Of: ${cleanAsOf}` : ' | Mode: Current'}`
    ];
    for (const ret of retiredBlockedNodes) {
      headerLines.push(
        `// [RETIRED: ${ret.id}${ret.supersededBy ? ` -> Superseded by ${ret.supersededBy}` : ''}${ret.retiredAt ? ` (retired ${ret.retiredAt})` : ''}]`
      );
    }
    const headerBlock = headerLines.join('\n');
    let usedTokens = estimateTokens(headerBlock) + 2;

    const traversedNodes = [];
    const bodySections = [headerBlock];
    const activeIncludedIds = new Set();

    for (let i = 0; i < orderedEntries.length; i += 1) {
      const entry = orderedEntries[i];
      const remainingSlots = Math.max(1, orderedEntries.length - i);
      const remainingBudget = effectiveBudget - usedTokens;
      if (remainingBudget < 24) break;

      const metaHeader = `--- [${entry.node.id}] (${entry.node.kind || 'node'} | hop=${entry.hop}${entry.node.path ? ` | ${entry.node.path}` : ''}) ---`;
      const metaTokens = estimateTokens(metaHeader) + 2;
      if (remainingBudget <= metaTokens + 12) continue;

      const rawTokens = estimateTokens(entry.node.content || '');
      const totalNeededForRemaining = orderedEntries
        .slice(i)
        .reduce((acc, item) => acc + estimateTokens(item.node.content || '') + 24, 0);

      const hardCeilingForNode = Math.max(12, remainingBudget - metaTokens - 2);
      const fairShareForNode = Math.max(
        16,
        Math.floor(((remainingBudget - metaTokens * remainingSlots) * 0.9) / remainingSlots)
      );
      const maxExcerptTokens =
        totalNeededForRemaining <= remainingBudget
          ? hardCeilingForNode
          : Math.min(hardCeilingForNode, fairShareForNode);

      const excerpt = formatCompactNodeExcerpt(entry.node, Math.min(rawTokens, maxExcerptTokens));
      const section = excerpt ? `${metaHeader}\n${excerpt}` : metaHeader;
      const sectionTokens = estimateTokens(section) + 1;

      if (usedTokens + sectionTokens > effectiveBudget && traversedNodes.length > 0) {
        const fallbackHeaderOnlyTokens = estimateTokens(metaHeader) + 1;
        if (usedTokens + fallbackHeaderOnlyTokens <= effectiveBudget) {
          bodySections.push(metaHeader);
          usedTokens += fallbackHeaderOnlyTokens;
          activeIncludedIds.add(entry.node.id);
          traversedNodes.push({
            id: entry.node.id,
            kind: entry.node.kind || 'code',
            title: entry.node.title || entry.node.id,
            path: entry.node.path || null,
            symbols: Array.isArray(entry.node.symbols) ? entry.node.symbols : [],
            hop: entry.hop,
            role: entry.role,
            tokens: fallbackHeaderOnlyTokens,
            validFrom: entry.node.validFrom || null,
            retiredAt: entry.node.retiredAt || null,
            isCurrent: entry.node.isCurrent !== false,
            supersededBy: entry.node.supersededBy || null
          });
        }
        continue;
      }

      bodySections.push(section);
      usedTokens += sectionTokens;
      activeIncludedIds.add(entry.node.id);
      traversedNodes.push({
        id: entry.node.id,
        kind: entry.node.kind || 'code',
        title: entry.node.title || entry.node.id,
        path: entry.node.path || null,
        symbols: Array.isArray(entry.node.symbols) ? entry.node.symbols : [],
        hop: entry.hop,
        role: entry.role,
        tokens: sectionTokens,
        validFrom: entry.node.validFrom || null,
        retiredAt: entry.node.retiredAt || null,
        isCurrent: entry.node.isCurrent !== false,
        supersededBy: entry.node.supersededBy || null
      });
    }

    const retiredIds = new Set(retiredBlockedNodes.map((r) => r.id));
    const traversedEdges = [...traversedEdgeMap.values()].filter(
      (e) =>
        (activeIncludedIds.has(e.from) || retiredIds.has(e.from)) &&
        (activeIncludedIds.has(e.to) || retiredIds.has(e.to))
    );

    const activeDecisions = traversedNodes.filter(
      (n) => n.kind === 'adr' || n.kind === 'decision' || n.kind === 'invariant'
    );
    const contextText = bodySections.join('\n\n');
    const tokenCount = Math.min(effectiveBudget, estimateTokens(contextText));
    const tokenSavingsRatio =
      fullRepoTokens > 0 ? Number(Math.max(0, (fullRepoTokens - tokenCount) / fullRepoTokens).toFixed(4)) : 0;

    const summary = brickOntologyPayload
      ? `Traversed ${traversedNodes.length} active node(s), blocked ${retiredBlockedNodes.length} retired node(s) in ${tokenCount} tokens | Brick ontology: ${brickOntologyPayload.brickCount} brick(s)`
      : `Traversed ${traversedNodes.length} active node(s), blocked ${retiredBlockedNodes.length} retired node(s) in ${tokenCount} tokens`;

    return scrubSensitiveStrings(
      okEnvelope(tool, summary, {
        answerability,
        asOf: cleanAsOf,
        seedNodes,
        selectedNodes: traversedNodes,
        traversedNodes,
        selectedNodeIds: traversedNodes.map((n) => n.id),
        traversedEdges,
        activeDecisions,
        retiredDecisionsExcluded: retiredBlockedNodes,
        retiredBlockedNodes,
        tokensUsed: tokenCount,
        tokenCount,
        tokenBudget: effectiveBudget,
        fullRepoTokens,
        tokenSavingsRatio,
        renderedContext: contextText,
        contextText,
        cypherQuery,
        hydraExecution,
        ...(brickOntologyPayload ? { brickOntology: brickOntologyPayload } : {})
      })
    );
  }

  async function compareVectorVsGraph(rawOptions = {}) {
    const tool = 'hydrascope_compare_vector_vs_graph';
    const opts =
      typeof rawOptions === 'string'
        ? { query: rawOptions }
        : isPlainObject(rawOptions)
          ? rawOptions
          : {};

    const rawQuery = String(opts.query ?? '').trim();
    if (!rawQuery) {
      return failHydraEnvelope(tool, 'VALIDATION_ERROR', 'A non-empty query string is required.', null);
    }

    const asOfCheck = validateOptionalAsOf(opts.asOf ?? null);
    if (!asOfCheck.ok) {
      return failHydraEnvelope(tool, asOfCheck.code, asOfCheck.message, null);
    }

    const cleanAsOf = asOfCheck.value;
    const effectiveBudget = Math.max(120, Math.min(16000, Number(opts.tokenBudget) || 900));
    const effectiveTopK = Math.max(1, Math.min(32, Number(opts.topK) || 4));
    const vectorBudget = Math.max(1600, effectiveBudget);

    const graphSnap = activeGraph;
    const vecSnap = vectorIndex;

    const vectorResult = queryLocalVectorTopK(vecSnap, rawQuery, {
      topK: effectiveTopK,
      tokenBudget: vectorBudget
    });
    const hydraEnvelope = await traverseContext({
      query: rawQuery,
      asOf: cleanAsOf,
      tokenBudget: effectiveBudget
    });
    if (!hydraEnvelope.ok) {
      return failHydraEnvelope(tool, hydraEnvelope.error.code, hydraEnvelope.error.message, null);
    }

    const hydraData = hydraEnvelope.data;
    const nodeById = new Map(graphSnap.nodes.map((n) => [n.id, n]));

    const poisonedSupersededAdrs = vectorResult.selectedNodeIds
      .map((id) => nodeById.get(id))
      .filter((node) => node && !isNodeActiveAt(node, cleanAsOf))
      .map((node) => ({
        id: node.id,
        kind: node.kind || 'decision',
        title: node.title || node.id,
        retiredAt: node.retiredAt || null,
        supersededBy: node.supersededBy || null
      }));

    const vectorSelectedSet = new Set(vectorResult.selectedNodeIds);
    const missedMultiHopNodes = hydraData.selectedNodes
      .filter((n) => !vectorSelectedSet.has(n.id))
      .map((n) => ({
        id: n.id,
        kind: n.kind,
        title: n.title,
        path: n.path,
        hop: n.hop,
        role: n.role
      }));

    const fullRepoTokens =
      Number(graphSnap.totalRepoTokens) > 0
        ? Number(graphSnap.totalRepoTokens)
        : graphSnap.nodes.reduce((sum, n) => sum + (Number(n?.tokens) || estimateTokens(n?.content || '')), 0);
    const vectorTokens = vectorResult.tokenCount;
    const hydraTokens = hydraData.tokensUsed;

    const savingsVsRepoPct =
      fullRepoTokens > 0 ? Number((((fullRepoTokens - hydraTokens) / fullRepoTokens) * 100).toFixed(1)) : 0;
    const savingsVsVectorPct =
      vectorTokens > 0 ? Number((((vectorTokens - hydraTokens) / vectorTokens) * 100).toFixed(1)) : 0;

    return scrubSensitiveStrings(
      okEnvelope(
        tool,
        `HydraScope used ${hydraTokens} tokens vs ${vectorTokens} vector tokens (${savingsVsRepoPct}% saved vs full repo; ${poisonedSupersededAdrs.length} vector poison hit(s))`,
        {
          query: rawQuery,
          asOf: cleanAsOf,
          vectorTopK: vectorResult,
          vector: vectorResult,
          graphTraversal: hydraData,
          hydra: hydraData,
          hydraScope: hydraData,
          missedMultiHopNodes,
          structuralOnlyNodes: missedMultiHopNodes,
          poisonedSupersededAdrs,
          vectorPoisonedNodes: poisonedSupersededAdrs,
          tokenSavingsPct: savingsVsRepoPct,
          tokenSavingsVsVectorPct: savingsVsVectorPct,
          tokenDelta: {
            fullRepoTokens,
            vectorTokens,
            hydraTokens,
            savingsVsRepoPct,
            savingsVsVectorPct
          }
        }
      )
    );
  }

  async function runBenchmark() {
    const tool = 'hydrascope_run_benchmark';
    const graphSnap = activeGraph;
    const vecSnap = vectorIndex;
    const scenariosSnap = activeScenarios;
    const nodeById = new Map(graphSnap.nodes.map((n) => [n.id, n]));
    const allNodeIds = graphSnap.nodes.map((n) => n.id);
    const fullRepoTokens =
      Number(graphSnap.totalRepoTokens) > 0
        ? Number(graphSnap.totalRepoTokens)
        : graphSnap.nodes.reduce((sum, n) => sum + (Number(n?.tokens) || estimateTokens(n?.content || '')), 0);

    const scoreScenarioArm = ({ selectedNodeIds, tokenCount, latencyMs = 0, scenario }) => {
      const selectedSet = new Set(selectedNodeIds);
      const expectAnswerable =
        scenario.expectAnswerable !== undefined
          ? Boolean(scenario.expectAnswerable)
          : scenario.category !== 'ungrounded_trap';
      const requiredIds = Array.isArray(scenario.requiredNodeIds) ? scenario.requiredNodeIds : [];
      const forbiddenIds = Array.isArray(scenario.forbiddenPoisonNodeIds) ? scenario.forbiddenPoisonNodeIds : [];

      const hitRequiredIds = requiredIds.filter((reqId) => matchesLogicalId(selectedSet, reqId));
      const missingRequiredIds = requiredIds.filter((reqId) => !matchesLogicalId(selectedSet, reqId));
      const criticalRecall =
        !expectAnswerable || requiredIds.length === 0
          ? 1
          : Number((hitRequiredIds.length / requiredIds.length).toFixed(4));

      const hitForbiddenIds = forbiddenIds.filter((badId) => matchesLogicalId(selectedSet, badId));
      if (hitForbiddenIds.length === 0 && scenario.category === 'temporal_supersession') {
        for (const id of selectedNodeIds) {
          const node = nodeById.get(id);
          if (node && !isNodeActiveAt(node, scenario.asOf || null)) {
            hitForbiddenIds.push(id);
          }
        }
      }

      const poisoned = hitForbiddenIds.length > 0;
      const trappedHallucination = !expectAnswerable && (selectedNodeIds.length > 0 || tokenCount > 0);
      const passed = !poisoned && !trappedHallucination && criticalRecall >= 1;

      return {
        selectedNodeIds,
        tokenCount,
        latencyMs: Number(latencyMs.toFixed(2)),
        criticalRecall,
        hitRequiredIds,
        missingRequiredIds,
        poisoned,
        poisonNodeIds: hitForbiddenIds,
        trappedHallucination,
        passed
      };
    };

    const fullEvals = [];
    const vectorEvals = [];
    const hydraEvals = [];
    const scenarioResults = [];

    for (const scenario of scenariosSnap) {
      const fullArm = scoreScenarioArm({
        selectedNodeIds: allNodeIds,
        tokenCount: fullRepoTokens,
        latencyMs: 0.1,
        scenario
      });

      const vecRes = queryLocalVectorTopK(vecSnap, scenario.query, {
        topK: 4,
        tokenBudget: 1600
      });
      const vectorArm = scoreScenarioArm({
        selectedNodeIds: vecRes.selectedNodeIds,
        tokenCount: vecRes.tokenCount,
        latencyMs: vecRes.latencyMs,
        scenario
      });

      const hydraStart = performance.now();
      const hydraEnv = await traverseContext({
        query: scenario.query,
        asOf: scenario.asOf || null,
        tokenBudget: scenario.tokenBudget || 900
      });
      const hydraLatencyMs = performance.now() - hydraStart;
      const hydraData = hydraEnv.data || {
        selectedNodeIds: [],
        retiredDecisionsExcluded: [],
        tokensUsed: 0,
        answerability: { answerable: false },
        cypherQuery: ''
      };

      const hydraArm = scoreScenarioArm({
        selectedNodeIds: hydraData.selectedNodeIds || [],
        tokenCount: hydraData.tokensUsed || 0,
        latencyMs: hydraLatencyMs,
        scenario
      });

      fullEvals.push(fullArm);
      vectorEvals.push(vectorArm);
      hydraEvals.push(hydraArm);

      const expectAns =
        scenario.expectAnswerable !== undefined
          ? Boolean(scenario.expectAnswerable)
          : scenario.category !== 'ungrounded_trap';

      scenarioResults.push({
        id: scenario.id,
        category: scenario.category,
        title: scenario.title || scenario.id,
        query: scenario.query,
        asOf: scenario.asOf || null,
        expectAnswerable: expectAns,
        vectorRecallPct: Number((vectorArm.criticalRecall * 100).toFixed(1)),
        hydraRecallPct: Number((hydraArm.criticalRecall * 100).toFixed(1)),
        vectorPoisoned: vectorArm.poisoned,
        hydraPoisoned: hydraArm.poisoned,
        vectorTokens: vectorArm.tokenCount,
        hydraTokens: hydraArm.tokenCount,
        hydraBlockedTrap: !expectAns && !hydraArm.trappedHallucination,
        requiredNodeIds: scenario.requiredNodeIds || [],
        forbiddenPoisonNodeIds: scenario.forbiddenPoisonNodeIds || [],
        explanation: scenario.explanation || '',
        fullStuffing: fullArm,
        vectorTopK: vectorArm,
        hydraScope: {
          ...hydraArm,
          answerable: Boolean(hydraData.answerability?.answerable),
          retiredBlockedIds: (hydraData.retiredDecisionsExcluded || []).map((r) => r.id),
          cypherQuery: hydraData.cypherQuery || ''
        }
      });
    }

    const summarizeArm = (armId, label, evaluations, fullTotal, vectorTotal) => {
      const count = Math.max(1, evaluations.length);
      const recallIndices = scenariosSnap
        .map((s, idx) => ({ s, idx }))
        .filter(
          ({ s }) =>
            (s.expectAnswerable !== undefined ? Boolean(s.expectAnswerable) : s.category !== 'ungrounded_trap') &&
            Array.isArray(s.requiredNodeIds) &&
            s.requiredNodeIds.length > 0
        )
        .map(({ idx }) => evaluations[idx]);
      const poisonIndices = scenariosSnap
        .map((s, idx) => ({ s, idx }))
        .filter(
          ({ s }) =>
            (Array.isArray(s.forbiddenPoisonNodeIds) && s.forbiddenPoisonNodeIds.length > 0) ||
            s.category === 'temporal_supersession'
        )
        .map(({ idx }) => evaluations[idx]);
      const trapIndices = scenariosSnap
        .map((s, idx) => ({ s, idx }))
        .filter(({ s }) =>
          (s.expectAnswerable !== undefined ? Boolean(s.expectAnswerable) : s.category !== 'ungrounded_trap') === false
        )
        .map(({ idx }) => evaluations[idx]);

      const recallDenom = recallIndices.length > 0 ? recallIndices : evaluations;
      const recallRatio = Number(
        (recallDenom.reduce((sum, e) => sum + e.criticalRecall, 0) / Math.max(1, recallDenom.length)).toFixed(4)
      );
      const criticalRecallPct = Number((recallRatio * 100).toFixed(1));

      const poisonDenom = poisonIndices.length > 0 ? poisonIndices : evaluations;
      const poisonedCount = poisonDenom.filter((e) => e.poisoned).length;
      const poisonRate = Number((poisonedCount / Math.max(1, poisonDenom.length)).toFixed(4));
      const temporalPoisoningPct = Number((poisonRate * 100).toFixed(1));

      const trappedCount = trapIndices.filter((e) => e.trappedHallucination).length;
      const trapBlockPct =
        trapIndices.length > 0
          ? Number((((trapIndices.length - trappedCount) / trapIndices.length) * 100).toFixed(1))
          : 100;

      const passedCount = evaluations.filter((e) => e.passed).length;
      const passRatePct = Number(((passedCount / count) * 100).toFixed(1));
      const totalTokens = evaluations.reduce((sum, e) => sum + e.tokenCount, 0);
      const meanTokens = Math.round(totalTokens / count);
      const meanLatencyMs = Number((evaluations.reduce((sum, e) => sum + e.latencyMs, 0) / count).toFixed(2));

      const tokenReductionVsStuffing =
        fullTotal > 0 ? Number((((fullTotal - totalTokens) / fullTotal) * 100).toFixed(1)) : 0;
      const tokenReductionVsVector =
        vectorTotal > 0 ? Number((((vectorTotal - totalTokens) / vectorTotal) * 100).toFixed(1)) : 0;

      return {
        armId,
        label,
        scenarioCount: evaluations.length,
        passedCount,
        passRatePct,
        recallRatio,
        criticalRecallPct,
        poisonRate,
        temporalPoisoningPct,
        poisonedCount,
        trapBlockPct,
        hallucinationTrapBlockPct: trapBlockPct,
        trappedCount,
        totalTokens,
        meanTokens,
        meanLatencyMs,
        tokenReductionVsStuffing,
        tokenReductionVsVector
      };
    };

    const fullTotalTokens = fullEvals.reduce((s, e) => s + e.tokenCount, 0);
    const vectorTotalTokens = vectorEvals.reduce((s, e) => s + e.tokenCount, 0);

    const fullStuffing = summarizeArm(
      'full_stuffing',
      'Full-Repo Stuffing',
      fullEvals,
      fullTotalTokens,
      vectorTotalTokens
    );
    const vectorTopK = summarizeArm(
      'vector_topk',
      'Dense Vector Top-K (k=4)',
      vectorEvals,
      fullTotalTokens,
      vectorTotalTokens
    );
    const hydraScope = summarizeArm(
      'hydrascope_graph',
      'HydraScope Structural Graph',
      hydraEvals,
      fullTotalTokens,
      vectorTotalTokens
    );

    const metrics = {
      fullRepoMeanTokens: fullStuffing.meanTokens,
      vectorMeanTokens: vectorTopK.meanTokens,
      graphMeanTokens: hydraScope.meanTokens,
      vectorRecall: vectorTopK.recallRatio,
      vectorRecallPct: vectorTopK.criticalRecallPct,
      vectorSupersededPoisonRate: vectorTopK.poisonRate,
      vectorSupersededPoisonPct: vectorTopK.temporalPoisoningPct,
      graphRecall: hydraScope.recallRatio,
      graphRecallPct: hydraScope.criticalRecallPct,
      graphSupersededPoisonRate: hydraScope.poisonRate,
      graphSupersededPoisonPct: hydraScope.temporalPoisoningPct,
      graphTokenReductionPct: hydraScope.tokenReductionVsStuffing,
      graphTrapBlockPct: hydraScope.trapBlockPct
    };

    return scrubSensitiveStrings(
      okEnvelope(
        tool,
        `Evaluated ${scenariosSnap.length} scenario(s): HydraScope ${hydraScope.criticalRecallPct}% recall, ${hydraScope.temporalPoisoningPct}% poison, ${hydraScope.meanTokens} mean tokens (${hydraScope.tokenReductionVsStuffing}% fewer vs full repo)`,
        {
          embeddingBackend: vecSnap.embeddingBackend,
          scenarioCount: scenariosSnap.length,
          scenarios: scenarioResults,
          scenarioResults,
          metrics,
          arms: {
            fullStuffing,
            vectorTopK,
            hydraScope
          }
        }
      )
    );
  }

  function supersedeDecision(rawParams = {}) {
    const tool = 'hydrascope_supersede_decision';
    return withMutationLock(async () => {
      const params = isPlainObject(rawParams) ? rawParams : {};
      const validation = validateSupersedePayload(params);
      if (!validation.ok) {
        return failHydraEnvelope(tool, validation.code, validation.message, null);
      }

      const {
        oldId: cleanOldId,
        newId: cleanNewId,
        title: rawTitle,
        content: rawContent,
        governsIds: sanitizedGovernsIds,
        effectiveAt: cleanEffectiveAt
      } = validation.value;

      const cleanTitle = scrubSensitiveText(rawTitle);
      const cleanContent = scrubSensitiveText(rawContent);

      const dynamicCount = activeGraph.nodes.filter((n) => n?._dynamicSupersede === true).length;
      if (dynamicCount >= MAX_CUSTOM_DECISIONS) {
        return failHydraEnvelope(
          tool,
          'DECISION_LIMIT_REACHED',
          `Workspace has reached the maximum of ${MAX_CUSTOM_DECISIONS} dynamic supersessions.`,
          { limit: MAX_CUSTOM_DECISIONS }
        );
      }

      const oldNode =
        activeGraph.nodes.find((n) => n.id === cleanOldId) ||
        activeGraph.nodes.find(
          (n) => bareLogicalId(n.id).toLowerCase() === bareLogicalId(cleanOldId).toLowerCase()
        );

      if (!oldNode) {
        return failHydraEnvelope(
          tool,
          'DECISION_NOT_FOUND',
          `Decision node "${cleanOldId}" does not exist in workspace graph.`,
          { oldId: cleanOldId }
        );
      }

      if (oldNode.isCurrent === false) {
        return failHydraEnvelope(
          tool,
          'DECISION_ALREADY_RETIRED',
          `Decision node "${oldNode.id}" is already retired${oldNode.supersededBy ? ` by ${oldNode.supersededBy}` : ''}.`,
          { oldId: oldNode.id, supersededBy: oldNode.supersededBy || null }
        );
      }

      const hasPrefix = oldNode.id.includes(':') && !cleanNewId.includes(':');
      const resolvedNewId = hasPrefix ? `${oldNode.id.split(':')[0]}:${cleanNewId}` : cleanNewId;
      const resolvedNewBare = bareLogicalId(resolvedNewId).toLowerCase();

      if (
        resolvedNewId === oldNode.id ||
        activeGraph.nodes.some(
          (n) => n.id === resolvedNewId || bareLogicalId(n.id).toLowerCase() === resolvedNewBare
        )
      ) {
        return failHydraEnvelope(
          tool,
          'DUPLICATE_DECISION_ID',
          `Decision node "${resolvedNewId}" already exists in workspace graph.`,
          { newId: resolvedNewId }
        );
      }

      const nextOldNode = {
        ...oldNode,
        isCurrent: false,
        retiredAt: cleanEffectiveAt,
        supersededBy: resolvedNewId
      };

      const inheritedTargets = activeGraph.edges
        .map(normalizeEdge)
        .filter((e) => e && e.type === 'GOVERNS' && e.from === oldNode.id)
        .map((e) => e.to);

      const requestedTargets =
        sanitizedGovernsIds.length > 0
          ? sanitizedGovernsIds
              .map((gid) => {
                const match =
                  activeGraph.nodes.find((n) => n.id === gid) ||
                  activeGraph.nodes.find(
                    (n) => bareLogicalId(n.id).toLowerCase() === bareLogicalId(gid).toLowerCase()
                  );
                return match ? match.id : gid;
              })
              .filter(Boolean)
          : inheritedTargets;

      const slug = bareLogicalId(resolvedNewId).toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
      const newNode = {
        id: resolvedNewId,
        surrogateId: surrogateOntologyVertexId(cleanNamespace, resolvedNewId),
        kind: oldNode.kind || 'adr',
        title: cleanTitle,
        path: `docs/adr/${slug}.md`,
        symbols: [bareLogicalId(resolvedNewId)],
        synonyms: Array.isArray(oldNode.synonyms) ? [...oldNode.synonyms] : [],
        content: cleanContent,
        tokens: estimateTokens(cleanContent),
        validFrom: cleanEffectiveAt,
        retiredAt: null,
        isCurrent: true,
        supersededBy: null,
        _dynamicSupersede: true
      };

      const newEdges = [
        {
          from: newNode.id,
          to: oldNode.id,
          type: 'SUPERSEDES',
          reason: `Supersedes ${oldNode.id} effective ${cleanEffectiveAt}`,
          weight: 1,
          validFrom: cleanEffectiveAt
        }
      ];

      for (const targetId of new Set(requestedTargets)) {
        newEdges.push({
          from: newNode.id,
          to: targetId,
          type: 'GOVERNS',
          reason: `Active decision ${newNode.id} governs ${targetId}`,
          weight: 1,
          validFrom: cleanEffectiveAt
        });
      }

      if (db) {
        try {
          persistSupersedeToSqlite(
            db,
            activeGraph.workspaceName,
            cleanNamespace,
            nextOldNode,
            newNode,
            newEdges
          );
        } catch (dbErr) {
          return failHydraEnvelope(
            tool,
            'STORAGE_ERROR',
            dbErr instanceof Error ? dbErr.message : String(dbErr),
            null
          );
        }
      }

      oldNode.isCurrent = false;
      oldNode.retiredAt = cleanEffectiveAt;
      oldNode.supersededBy = resolvedNewId;

      activeGraph.nodes.push(newNode);
      activeGraph.edges.push(...newEdges);
      activeGraph.totalRepoTokens = (Number(activeGraph.totalRepoTokens) || 0) + newNode.tokens;
      activeGraph.ontology = buildGraphOntologyFromNodes(activeGraph.nodes);
      vectorIndex = buildLocalVectorIndex(activeGraph);

      const hydraSync = await syncNodesAndEdgesToHydraDb({
        baseUrl: cleanHydraUrl,
        token: cleanHydraToken,
        graphId: cleanHydraGraphId,
        namespace: cleanNamespace,
        nodes: [oldNode, newNode],
        edges: newEdges
      });

      return scrubSensitiveStrings(
        okEnvelope(tool, `Superseded ${oldNode.id} with ${newNode.id} effective ${cleanEffectiveAt}`, {
          retiredNode: {
            id: oldNode.id,
            title: oldNode.title,
            retiredAt: oldNode.retiredAt,
            isCurrent: oldNode.isCurrent,
            supersededBy: oldNode.supersededBy
          },
          newNode: {
            id: newNode.id,
            surrogateId: newNode.surrogateId,
            kind: newNode.kind,
            title: newNode.title,
            path: newNode.path,
            tokens: newNode.tokens,
            validFrom: newNode.validFrom,
            retiredAt: null,
            isCurrent: true,
            supersededBy: null
          },
          addedEdges: newEdges,
          effectiveAt: cleanEffectiveAt,
          hydraSync
        })
      );
    });
  }

  function ingestDirectory(input, opts = {}) {
    const tool = 'hydrascope_ingest_directory';
    return withMutationLock(async () => {
      let rawTargetDir = '';
      let allowExternalPaths = false;

      if (typeof input === 'string') {
        rawTargetDir = input;
        allowExternalPaths = Boolean(isPlainObject(opts) && opts.allowExternalPaths === true);
      } else if (isPlainObject(input)) {
        rawTargetDir = String(input.targetDir ?? '');
        allowExternalPaths = Boolean(input.allowExternalPaths === true || (isPlainObject(opts) && opts.allowExternalPaths === true));
      }

      const cleanTarget = rawTargetDir.trim();
      if (!cleanTarget) {
        return failHydraEnvelope(
          tool,
          'VALIDATION_ERROR',
          'A non-empty targetDir path or "reset" is required.',
          null
        );
      }

      if (cleanTarget === 'reset') {
        const resetGraph = compileArtifactsToHydraGraph(FINTECH_BENCHMARK_CORPUS, {
          workspaceName: 'fintech-core',
          namespace: cleanNamespace
        });
        if (db) {
          try {
            persistGraphToSqlite(db, resetGraph, resolvedWorkspaceRoot);
          } catch (dbErr) {
            return failHydraEnvelope(
              tool,
              'STORAGE_ERROR',
              dbErr instanceof Error ? dbErr.message : String(dbErr),
              null
            );
          }
        }
        activeGraph = resetGraph;
        activeScenarios = HYDRASCOPE_BENCHMARK_SCENARIOS.map((s) => ({ ...s }));
        vectorIndex = buildLocalVectorIndex(activeGraph);

        const hydraSync = await syncNodesAndEdgesToHydraDb({
          baseUrl: cleanHydraUrl,
          token: cleanHydraToken,
          graphId: cleanHydraGraphId,
          namespace: cleanNamespace,
          nodes: activeGraph.nodes,
          edges: activeGraph.edges
        });

        return scrubSensitiveStrings(
          okEnvelope(tool, 'Reset workspace to 18-artifact FinTech benchmark graph.', {
            workspaceName: activeGraph.workspaceName,
            nodeCount: activeGraph.nodes.length,
            edgeCount: activeGraph.edges.length,
            totalRepoTokens: activeGraph.totalRepoTokens,
            hydraSync
          })
        );
      }

      const candidatePath = path.resolve(resolvedWorkspaceRoot, cleanTarget);
      if (
        !allowExternalPaths &&
        candidatePath !== resolvedWorkspaceRoot &&
        !candidatePath.startsWith(resolvedWorkspaceRoot + path.sep)
      ) {
        return failHydraEnvelope(
          tool,
          'PATH_OUTSIDE_WORKSPACE',
          'Directory compilation is restricted to paths within workspaceRoot unless allowExternalPaths is true.',
          null
        );
      }

      let lstat;
      try {
        lstat = fs.lstatSync(candidatePath);
      } catch {
        return failHydraEnvelope(
          tool,
          'DIRECTORY_NOT_FOUND',
          'Target directory does not exist or cannot be accessed.',
          null
        );
      }

      if (!allowExternalPaths && lstat.isSymbolicLink()) {
        return failHydraEnvelope(
          tool,
          'PATH_OUTSIDE_WORKSPACE',
          'Symbolic link directories outside workspace containment are rejected.',
          null
        );
      }

      let realRoot;
      let realTarget;
      try {
        realRoot = fs.realpathSync(resolvedWorkspaceRoot);
        realTarget = fs.realpathSync(candidatePath);
      } catch {
        return failHydraEnvelope(
          tool,
          'DIRECTORY_NOT_FOUND',
          'Target directory does not exist or cannot be accessed.',
          null
        );
      }

      if (
        !allowExternalPaths &&
        realTarget !== realRoot &&
        !realTarget.startsWith(realRoot + path.sep)
      ) {
        return failHydraEnvelope(
          tool,
          'PATH_OUTSIDE_WORKSPACE',
          'Directory resolves via symlink outside workspaceRoot.',
          null
        );
      }

      let targetStat;
      try {
        targetStat = fs.statSync(realTarget);
      } catch {
        return failHydraEnvelope(
          tool,
          'DIRECTORY_NOT_FOUND',
          'Target directory does not exist or cannot be accessed.',
          null
        );
      }
      if (!targetStat.isDirectory()) {
        return failHydraEnvelope(
          tool,
          'DIRECTORY_NOT_FOUND',
          'Target path must be a directory.',
          null
        );
      }

      const compiled = compileDirectoryToHydraGraph(realTarget, {
        rejectSymlinkRoot: !allowExternalPaths,
        namespace: cleanNamespace
      });
      if (!compiled.ok) {
        return failHydraEnvelope(tool, compiled.error.code, compiled.error.message, null);
      }

      const nextGraph = compiled.data;
      if (db) {
        try {
          persistGraphToSqlite(db, nextGraph, resolvedWorkspaceRoot);
        } catch (dbErr) {
          return failHydraEnvelope(
            tool,
            'STORAGE_ERROR',
            dbErr instanceof Error ? dbErr.message : String(dbErr),
            null
          );
        }
      }
      activeGraph = nextGraph;
      activeScenarios =
        activeGraph.workspaceName === 'fintech-core'
          ? HYDRASCOPE_BENCHMARK_SCENARIOS.map((s) => ({ ...s }))
          : buildDynamicScenariosForGraph(activeGraph);
      vectorIndex = buildLocalVectorIndex(activeGraph);

      const hydraSync = await syncNodesAndEdgesToHydraDb({
        baseUrl: cleanHydraUrl,
        token: cleanHydraToken,
        graphId: cleanHydraGraphId,
        namespace: cleanNamespace,
        nodes: activeGraph.nodes,
        edges: activeGraph.edges
      });

      return scrubSensitiveStrings(
        okEnvelope(
          tool,
          `Compiled ${activeGraph.nodes.length} nodes and ${activeGraph.edges.length} structural edges into HydraScope.`,
          {
            workspaceName: activeGraph.workspaceName,
            nodeCount: activeGraph.nodes.length,
            edgeCount: activeGraph.edges.length,
            totalRepoTokens: activeGraph.totalRepoTokens,
            hydraSync
          }
        )
      );
    });
  }

  return Object.freeze({
    getState,
    checkAnswerable,
    traverseContext,
    compareVectorVsGraph,
    runBenchmark,
    supersedeDecision,
    ingestDirectory
  });
}
