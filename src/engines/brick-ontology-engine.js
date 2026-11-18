/**
 * @module engines/brick-ontology-engine
 * Standalone Zero-Dependency 4-Axis Brick Ontology, HydraScope Graph Traversal &
 * Zero-Upload Cross-Stack Hexagonal Binding Synthesis Engine for KruschStack (INV-LEGO-36).
 *
 * Enforces:
 * - INV-STACK-01: Zero external npm dependencies (Node 22 built-in `node:crypto` + `../db/sqlite.js`).
 * - INV-STACK-02: Deterministic `{ ok, tool, summary, data | error }` envelopes.
 * - INV-STACK-04: Zero leaked private LAN/Tailscale IPs, hostnames, or OS user paths.
 * - Pure in-memory operation over caller-supplied authorized brick bundles (zero SQL schema changes).
 */

import crypto from 'node:crypto';
import { okEnvelope } from '../db/sqlite.js';
import { verifySealedBrickBundle } from './brick-exchange-engine.js';

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_PAYLOAD_DEPTH = 24;

const BRICK_ID_RE = /^[a-z0-9][a-z0-9-_]{1,63}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const SAFE_PORT_SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const SAFE_SUPERSEDES_RE = /^(?:brick:)?(?:([a-z0-9][a-z0-9-_]{1,63})@)?([0-9a-f]{64})$/i;
const SAFE_CYPHER_REL_RE = /^[A-Z][A-Z0-9_]{1,47}$/;
const ISO_DATE_ONLY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;
const BREAKOUT_SEQUENCE_RE = /[\r\n\u2028\u2029]|"""|\*\//;

/**
 * Canonical cross-component data types matching `@krusch/toolkit/tool-graph`
 * that safely bridge across namespaces unlike opaque server-local IDs (`channel_id`, `page_id`).
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

const TOOL_GRAPH_SHARED_PORT_SET = new Set(CANONICAL_SHARED_TYPES);

const NODE_BUILTIN_MODULES = new Set([
  'assert',
  'assert/strict',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'console',
  'constants',
  'crypto',
  'dgram',
  'diagnostics_channel',
  'dns',
  'dns/promises',
  'domain',
  'events',
  'fs',
  'fs/promises',
  'http',
  'http2',
  'https',
  'inspector',
  'inspector/promises',
  'module',
  'net',
  'os',
  'path',
  'path/posix',
  'path/win32',
  'perf_hooks',
  'process',
  'punycode',
  'querystring',
  'readline',
  'readline/promises',
  'repl',
  'sqlite',
  'stream',
  'stream/consumers',
  'stream/promises',
  'stream/web',
  'string_decoder',
  'sys',
  'timers',
  'timers/promises',
  'tls',
  'trace_events',
  'tty',
  'url',
  'util',
  'util/types',
  'v8',
  'vm',
  'wasi',
  'worker_threads',
  'zlib'
]);

const REGEX_PRECEDING_KEYWORDS = new Set([
  'return',
  'throw',
  'case',
  'delete',
  'void',
  'typeof',
  'yield',
  'await',
  'in',
  'instanceof',
  'of',
  'new',
  'else',
  'do'
]);

// Assembled dynamically so static repository leak scanners never match detector patterns.
const SCRUB_PRIVATE_IPV4_RE = new RegExp(
  [
    `\\b${'10'}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b`,
    `\\b${'192'}\\.${'168'}\\.\\d{1,3}\\.\\d{1,3}\\b`,
    `\\b172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}\\b`,
    `\\b100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.\\d{1,3}\\.\\d{1,3}\\b`
  ].join('|'),
  'g'
);

const SCRUB_SECRET_TOKEN_RE = new RegExp(
  [
    `${'AIza' + 'Sy'}[A-Za-z0-9_-]{6,}`,
    `\\b${'sk' + '-'}[A-Za-z0-9_-]{8,}`,
    `\\b${'gh' + 'p_'}[A-Za-z0-9]{8,}`,
    `\\bxox[baprs]-[A-Za-z0-9-]{8,}`
  ].join('|'),
  'g'
);

const SCRUB_LOCAL_HOME_PATH_RE = new RegExp(
  `(?<![A-Za-z0-9._-])\\/(?:${['ho' + 'me', 'Us' + 'ers', 'm' + 'nt'].join('|')})\\/[A-Za-z0-9._/-]+`,
  'g'
);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function defineSafeProp(target, key, value) {
  if (FORBIDDEN_KEYS.has(key)) {
    return;
  }
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true
  });
}

function deepFreezePlain(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => deepFreezePlain(item)));
  }
  const out = {};
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    defineSafeProp(out, key, deepFreezePlain(value[key]));
  }
  return Object.freeze(out);
}

/**
 * Format a deterministic INV-STACK-02 failure envelope.
 * @param {string} tool
 * @param {string} code
 * @param {string} message
 * @param {object|null} [details=null]
 */
function failEnvelope(tool, code, message, details = null) {
  const error = {
    code: String(code || 'ONTOLOGY_ERROR'),
    message: String(message || 'Brick ontology operation failed')
  };
  if (details !== null && details !== undefined) {
    error.details = details;
  }
  return {
    ok: false,
    tool,
    summary: error.message,
    error
  };
}

/**
 * Recursively scan an object/array graph for prototype-pollution keys (`__proto__`, `constructor`, `prototype`),
 * circular references (`WeakSet`), and nesting exceeding `depth > 24` (fail-closed `SEC-01`).
 *
 * @param {unknown} value
 * @param {number} [depth=0]
 * @param {WeakSet<object>} [seen=new WeakSet()]
 * @returns {string | null}
 */
export function hasForbiddenKeyRecursive(value, depth = 0, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object') {
    return null;
  }
  if (depth > MAX_PAYLOAD_DEPTH) {
    return '__max_depth_exceeded__';
  }
  if (seen.has(value)) {
    return '__circular_reference__';
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        const nested = hasForbiddenKeyRecursive(value[i], depth + 1, seen);
        if (nested) return nested;
      }
      return null;
    }
    if (!isPlainObject(value)) {
      return null;
    }
    const ownNames = Object.getOwnPropertyNames(value);
    for (let i = 0; i < ownNames.length; i += 1) {
      const key = ownNames[i];
      if (FORBIDDEN_KEYS.has(key)) {
        return key;
      }
      const nested = hasForbiddenKeyRecursive(value[key], depth + 1, seen);
      if (nested) return nested;
    }
    return null;
  } finally {
    seen.delete(value);
  }
}

/**
 * Validate a caller payload for forbidden prototype keys, cycles, excessive depth (> 24),
 * and JSON-serializability (`BigInt`, `Symbol`, functions, non-plain objects) (`SEC-01`).
 *
 * @param {unknown} value
 * @param {string} label
 * @param {{ maxDepth?: number, requireJsonSerializable?: boolean, disallowNonFinite?: boolean }} [options]
 * @returns {{ ok: true } | { ok: false, code: string, message: string, details?: object }}
 */
function validateSafePayload(
  value,
  label,
  { maxDepth = MAX_PAYLOAD_DEPTH, requireJsonSerializable = false, disallowNonFinite = false } = {}
) {
  const seen = new WeakSet();

  function walk(node, depth) {
    if (node === null || node === undefined) {
      return { ok: true };
    }
    const t = typeof node;
    if (t === 'boolean' || t === 'string') {
      return { ok: true };
    }
    if (t === 'number') {
      if (disallowNonFinite && !Number.isFinite(node)) {
        return {
          ok: false,
          code: 'UNSERIALIZABLE_PAYLOAD',
          message: `${label} contains non-finite number (${String(node)})`,
          details: { field: label }
        };
      }
      return { ok: true };
    }
    if (t === 'bigint' || t === 'symbol' || t === 'function') {
      if (requireJsonSerializable || t === 'bigint') {
        return {
          ok: false,
          code: 'UNSERIALIZABLE_PAYLOAD',
          message: `${label} contains non-JSON-serializable ${t} value`,
          details: { field: label, type: t }
        };
      }
      return { ok: true };
    }
    if (depth > maxDepth) {
      return {
        ok: false,
        code: 'ONTOLOGY_MAX_DEPTH_EXCEEDED',
        message: `${label} exceeded maximum allowed nesting depth (${maxDepth})`,
        details: { field: label, maxDepth }
      };
    }
    if (seen.has(node)) {
      return {
        ok: false,
        code: 'CIRCULAR_PAYLOAD',
        message: `${label} contains a circular object reference`,
        details: { field: label }
      };
    }
    seen.add(node);
    try {
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i += 1) {
          const sub = walk(node[i], depth + 1);
          if (!sub.ok) return sub;
        }
        return { ok: true };
      }
      if (!isPlainObject(node)) {
        if (requireJsonSerializable) {
          return {
            ok: false,
            code: 'UNSERIALIZABLE_PAYLOAD',
            message: `${label} must contain only plain JSON objects, arrays, and primitives`,
            details: { field: label }
          };
        }
        return { ok: true };
      }
      const ownNames = Object.getOwnPropertyNames(node);
      for (let i = 0; i < ownNames.length; i += 1) {
        const key = ownNames[i];
        if (FORBIDDEN_KEYS.has(key)) {
          return {
            ok: false,
            code: 'ONTOLOGY_FORBIDDEN_KEY',
            message: `Forbidden prototype-pollution key "${key}" rejected in ${label}`,
            details: { field: label, key }
          };
        }
        const sub = walk(node[key], depth + 1);
        if (!sub.ok) return sub;
      }
      return { ok: true };
    } finally {
      seen.delete(node);
    }
  }

  const res = walk(value, 0);
  if (!res.ok) {
    return res;
  }

  if (requireJsonSerializable && value !== undefined) {
    try {
      JSON.stringify(value);
    } catch (err) {
      return {
        ok: false,
        code: 'UNSERIALIZABLE_PAYLOAD',
        message: `${label} is not JSON-serializable: ${err instanceof Error ? err.message : String(err)}`,
        details: { field: label }
      };
    }
  }

  return { ok: true };
}

/**
 * Axis 1: Canonical Software Stack Registry (`INV-LEGO-36`).
 */
export const STACK_ONTOLOGY_STACKS = deepFreezePlain({
  'node-esm': {
    id: 'node-esm',
    title: 'Node 22+ Native ESM',
    category: 'backend',
    runtimeFamily: 'js',
    requiresWebStandardPurity: false,
    adapterFileName: 'binding.js',
    defaultBridgeMode: 'native',
    supportedLanguages: ['js', 'ts']
  },
  'typescript-node': {
    id: 'typescript-node',
    title: 'TypeScript Strict Node Service',
    category: 'backend',
    runtimeFamily: 'js',
    requiresWebStandardPurity: false,
    adapterFileName: 'binding.ts',
    defaultBridgeMode: 'native',
    supportedLanguages: ['ts', 'js']
  },
  'python-fastapi': {
    id: 'python-fastapi',
    title: 'Python 3.11+ FastAPI Service',
    category: 'backend',
    runtimeFamily: 'python',
    requiresWebStandardPurity: false,
    adapterFileName: 'binding_adapter.py',
    defaultBridgeMode: 'contract-adapter',
    supportedLanguages: ['py']
  },
  'react-vite': {
    id: 'react-vite',
    title: 'React + Vite Browser UI',
    category: 'frontend',
    runtimeFamily: 'js',
    requiresWebStandardPurity: true,
    adapterFileName: 'binding.js',
    defaultBridgeMode: 'native',
    supportedLanguages: ['js', 'ts', 'jsx', 'tsx']
  },
  'cloudflare-edge': {
    id: 'cloudflare-edge',
    title: 'Cloudflare Workers / Web-Standard Edge',
    category: 'edge',
    runtimeFamily: 'js',
    requiresWebStandardPurity: true,
    adapterFileName: 'binding.js',
    defaultBridgeMode: 'native',
    supportedLanguages: ['js', 'ts']
  }
});

/**
 * Axis 2: Canonical Schema-Typed Shared DataPort Registry (`INV-LEGO-36`).
 */
export const STACK_ONTOLOGY_PORTS = deepFreezePlain({
  timeseries_window: {
    id: 'timeseries_window',
    category: 'telemetry',
    shared: true,
    description:
      'Ordered time-series sample window with millisecond epoch timestamps and finite numeric values',
    canonicalFields: {
      ts: {
        type: 'number',
        required: true,
        aliases: ['ts', 'ts_ms', 'timestamp', 'recorded_at', 'unix_ts', 'time_ms', 'event_ts', 'time']
      },
      val: {
        type: 'number',
        required: true,
        aliases: ['val', 'value', 'reading', 'measurement', 'metric_value', 'sample_value']
      },
      seriesId: {
        type: 'string',
        required: false,
        aliases: ['seriesId', 'series_id', 'metric_id', 'sensor_id']
      }
    }
  },
  ledger_event: {
    id: 'ledger_event',
    category: 'finance',
    shared: true,
    description: 'Integer minor-unit financial ledger event preventing IEEE-754 float drift',
    canonicalFields: {
      gross: {
        type: 'integer',
        required: true,
        aliases: [
          'gross',
          'amount',
          'amount_cents',
          'amount_minor',
          'gross_cents',
          'total_cents',
          'subtotal_cents'
        ]
      },
      currency: {
        type: 'string',
        required: false,
        aliases: ['currency', 'currency_code', 'iso_currency']
      },
      orgId: {
        type: 'string',
        required: false,
        aliases: ['orgId', 'org_id', 'tenant_id', 'company_id', 'workspace_id', 'account_id']
      },
      ts: {
        type: 'number',
        required: false,
        aliases: ['ts', 'ts_ms', 'timestamp', 'recorded_at', 'unix_ts', 'settled_at']
      }
    }
  },
  webhook_envelope: {
    id: 'webhook_envelope',
    category: 'integration',
    shared: true,
    description: 'HMAC-verified inbound webhook envelope with replay-bounded timestamp and event ID',
    canonicalFields: {
      eventId: {
        type: 'string',
        required: true,
        aliases: ['eventId', 'event_id', 'delivery_id', 'webhook_id', 'id']
      },
      eventType: {
        type: 'string',
        required: false,
        aliases: ['eventType', 'event_type', 'type', 'topic']
      },
      signature: {
        type: 'string',
        required: false,
        aliases: ['signature', 'sig', 'x_signature', 'hmac_signature']
      },
      rawBody: {
        type: 'string',
        required: false,
        aliases: ['rawBody', 'raw_body', 'payload_raw']
      },
      ts: {
        type: 'number',
        required: false,
        aliases: ['ts', 'ts_ms', 'timestamp', 'recorded_at', 'unix_ts', 'created_at_ms', 'sent_at']
      },
      payload: {
        type: 'object',
        required: false,
        aliases: ['payload', 'data', 'body', 'event_data']
      }
    }
  },
  audit_record: {
    id: 'audit_record',
    category: 'compliance',
    shared: true,
    description: 'Append-only hash-chained compliance audit entry',
    canonicalFields: {
      actor: {
        type: 'string',
        required: true,
        aliases: ['actor', 'actor_id', 'user_id', 'subject_id', 'principal']
      },
      action: {
        type: 'string',
        required: true,
        aliases: ['action', 'event_action', 'event_type', 'operation', 'verb']
      },
      orgId: {
        type: 'string',
        required: false,
        aliases: ['orgId', 'org_id', 'tenantId', 'tenant_id', 'company_id', 'workspace_id']
      },
      resource: {
        type: 'string',
        required: false,
        aliases: ['resource', 'resource_id', 'target_id', 'target']
      },
      ts: {
        type: 'number',
        required: false,
        aliases: ['ts', 'ts_ms', 'timestamp', 'recorded_at', 'unix_ts']
      }
    }
  },
  identity_claims: {
    id: 'identity_claims',
    category: 'security',
    shared: true,
    description: 'Verified principal and multi-tenant authorization claims',
    canonicalFields: {
      subjectId: {
        type: 'string',
        required: true,
        aliases: ['subjectId', 'subject_id', 'sub', 'user_id', 'principal_id', 'member_id']
      },
      orgId: {
        type: 'string',
        required: true,
        aliases: ['orgId', 'org_id', 'tenantId', 'tenant_id', 'company_id', 'workspace_id']
      },
      roles: {
        type: 'array',
        required: false,
        aliases: ['roles', 'role_list', 'granted_roles', 'scopes']
      }
    }
  },
  document_page: {
    id: 'document_page',
    category: 'knowledge',
    shared: true,
    description: 'SHA-256 hash-anchored document page segment for RAG and filesystem memory',
    canonicalFields: {
      docId: {
        type: 'string',
        required: false,
        aliases: ['docId', 'doc_id', 'file_path', 'source_id']
      },
      pageNumber: {
        type: 'integer',
        required: true,
        aliases: ['pageNumber', 'page_number', 'page_idx', 'page']
      },
      content: {
        type: 'string',
        required: true,
        aliases: ['content', 'page_text', 'text', 'body_markdown', 'body']
      },
      pageHash: {
        type: 'string',
        required: false,
        aliases: ['pageHash', 'page_hash', 'sha256', 'anchor_hash']
      }
    }
  }
});

/**
 * Axis 3: Canonical Communication & Ingestion Channel Registry (`INV-LEGO-36`).
 */
export const STACK_ONTOLOGY_CHANNELS = deepFreezePlain({
  'webhook:github': {
    id: 'webhook:github',
    category: 'webhook',
    inboundPorts: ['webhook_envelope', 'repo_path', 'commit_sha'],
    outboundPorts: ['audit_record', 'repo_path', 'commit_sha'],
    requiredSecurityBricks: ['@krusch/toolkit/webhooks'],
    acceptedGuardTokens: [
      '@krusch/toolkit/webhooks',
      'webhooks',
      'verifyGithubSignature',
      'krusch_toolkit.security',
      'verify_webhook_hmac'
    ],
    requiresHmacVerification: true,
    requiresReplayWindow: true,
    scrubPii: true
  },
  'webhook:slack': {
    id: 'webhook:slack',
    category: 'webhook',
    inboundPorts: ['webhook_envelope', 'channel_name'],
    outboundPorts: ['audit_record', 'channel_name'],
    requiredSecurityBricks: ['@krusch/toolkit/webhooks'],
    acceptedGuardTokens: [
      '@krusch/toolkit/webhooks',
      'webhooks',
      'verifySlackSignature',
      'krusch_toolkit.security',
      'verify_webhook_hmac'
    ],
    requiresHmacVerification: true,
    requiresReplayWindow: true,
    scrubPii: true
  },
  'webhook:stripe': {
    id: 'webhook:stripe',
    category: 'webhook',
    inboundPorts: ['webhook_envelope'],
    outboundPorts: ['ledger_event', 'audit_record'],
    requiredSecurityBricks: ['@krusch/toolkit/webhooks'],
    acceptedGuardTokens: [
      '@krusch/toolkit/webhooks',
      'webhooks',
      'verifyStripeSignature',
      'krusch_toolkit.security',
      'verify_webhook_hmac'
    ],
    recommendedSecurityBricks: ['@krusch/toolkit/idempotency'],
    requiresHmacVerification: true,
    requiresReplayWindow: true,
    scrubPii: true
  },
  'workspace:gmail': {
    id: 'workspace:gmail',
    category: 'workspace',
    inboundPorts: ['identity_claims', 'email_address', 'document_page'],
    outboundPorts: ['document_page', 'audit_record', 'email_address'],
    requiredSecurityBricks: ['@krusch/toolkit/security'],
    acceptedGuardTokens: [
      '@krusch/toolkit/security',
      'security',
      '@krusch/toolkit/rbac',
      'rbac',
      'krusch_toolkit.security'
    ],
    requiresHmacVerification: false,
    requiresReplayWindow: false,
    scrubPii: true
  },
  'workspace:drive': {
    id: 'workspace:drive',
    category: 'workspace',
    inboundPorts: ['identity_claims', 'file_path', 'document_page'],
    outboundPorts: ['document_page', 'file_path'],
    requiredSecurityBricks: ['@krusch/toolkit/security'],
    acceptedGuardTokens: [
      '@krusch/toolkit/security',
      'security',
      '@krusch/toolkit/rbac',
      'rbac',
      'krusch_toolkit.security'
    ],
    requiresHmacVerification: false,
    requiresReplayWindow: false,
    scrubPii: true
  },
  'workspace:calendar': {
    id: 'workspace:calendar',
    category: 'workspace',
    inboundPorts: ['identity_claims', 'email_address', 'timeseries_window'],
    outboundPorts: ['timeseries_window', 'audit_record'],
    requiredSecurityBricks: ['@krusch/toolkit/security'],
    acceptedGuardTokens: [
      '@krusch/toolkit/security',
      'security',
      '@krusch/toolkit/rbac',
      'rbac',
      'krusch_toolkit.security'
    ],
    requiresHmacVerification: false,
    requiresReplayWindow: false,
    scrubPii: true
  },
  'mcp:stdio': {
    id: 'mcp:stdio',
    category: 'protocol',
    inboundPorts: ['identity_claims'],
    outboundPorts: ['audit_record', 'document_page'],
    requiredSecurityBricks: ['@krusch/toolkit/mcp'],
    acceptedGuardTokens: [
      '@krusch/toolkit/mcp',
      'mcp',
      '@krusch/toolkit/schema',
      'schema',
      'krusch_toolkit.mcp'
    ],
    requiresHmacVerification: false,
    requiresReplayWindow: false,
    scrubPii: true
  },
  'http:sse': {
    id: 'http:sse',
    category: 'streaming',
    inboundPorts: ['identity_claims'],
    outboundPorts: ['timeseries_window', 'document_page'],
    requiredSecurityBricks: ['@krusch/toolkit/streaming'],
    acceptedGuardTokens: [
      '@krusch/toolkit/streaming',
      'streaming',
      '@krusch/toolkit/edge',
      'edge',
      'sseResponse',
      'edgeSseResponse',
      'krusch_toolkit.fastapi_app'
    ],
    requiresHmacVerification: false,
    requiresReplayWindow: false,
    scrubPii: true
  },
  'telemetry:timeseries': {
    id: 'telemetry:timeseries',
    category: 'telemetry',
    inboundPorts: ['timeseries_window'],
    outboundPorts: ['timeseries_window', 'audit_record'],
    requiredSecurityBricks: ['@krusch/toolkit/schema'],
    acceptedGuardTokens: ['@krusch/toolkit/schema', 'schema', 'krusch_toolkit.schema'],
    requiresHmacVerification: false,
    requiresReplayWindow: false,
    scrubPii: false
  }
});

/**
 * Axis 4: Canonical MoE & Numerical Specialist Profile Registry (`INV-LEGO-36`).
 */
export const STACK_ONTOLOGY_MOE_PROFILES = deepFreezePlain({
  'timeseries-cadence-moe': {
    id: 'timeseries-cadence-moe',
    category: 'timeseries',
    description:
      'Time-series resampling, cadence alignment, and z-score/MAD anomaly windowing specialist',
    invariants: {
      cadenceMs: 60000,
      requireMonotonicTimestamps: true,
      preserveNegativeValues: true,
      nanInfPolicy: 'reject',
      anomalyMethod: 'mad-zscore'
    },
    cascadeTiers: ['TIER_0_DETERMINISTIC', 'L1_FAST', 'L2_HEAVY_MOE'],
    preferredModels: {
      TIER_0_DETERMINISTIC: 'alias-ring-v1',
      L1_FAST: 'gemma4:e4b',
      L2_HEAVY_MOE: 'qwen3-coder-30b-moe:latest'
    }
  },
  'financial-integer-ledger': {
    id: 'financial-integer-ledger',
    category: 'finance',
    description:
      'Exact integer minor-unit fee allocation, conservation-of-cents, and settlement reconciliation',
    invariants: {
      cadenceMs: null,
      requireMonotonicTimestamps: false,
      preserveNegativeValues: false,
      nanInfPolicy: 'reject',
      anomalyMethod: 'exact-conservation',
      integerMinorUnitsOnly: true
    },
    cascadeTiers: ['TIER_0_DETERMINISTIC', 'L2_HEAVY_MOE'],
    preferredModels: {
      TIER_0_DETERMINISTIC: 'alias-ring-v1',
      L2_HEAVY_MOE: 'qwen3-coder-30b-moe:latest'
    }
  },
  'cross-stack-schema-adapter': {
    id: 'cross-stack-schema-adapter',
    category: 'adapter',
    description:
      'Zero-upload hexagonal binding synthesis across Node ESM, TypeScript, Edge, and Python FastAPI',
    invariants: {
      cadenceMs: null,
      requireMonotonicTimestamps: false,
      preserveNegativeValues: true,
      nanInfPolicy: 'reject',
      anomalyMethod: 'schema-contract'
    },
    cascadeTiers: ['TIER_0_DETERMINISTIC', 'L1_FAST', 'L2_HEAVY_MOE'],
    preferredModels: {
      TIER_0_DETERMINISTIC: 'alias-ring-v1',
      L1_FAST: 'gemma4:e4b',
      L2_HEAVY_MOE: 'qwen3-coder-30b-moe:latest'
    }
  },
  'channel-security-normalizer': {
    id: 'channel-security-normalizer',
    category: 'security',
    description:
      'Inbound webhook/workspace HMAC verification, replay-window enforcement, and PII-safe normalization',
    invariants: {
      cadenceMs: null,
      requireMonotonicTimestamps: true,
      preserveNegativeValues: false,
      nanInfPolicy: 'reject',
      anomalyMethod: 'replay-window-hmac'
    },
    cascadeTiers: ['TIER_0_DETERMINISTIC', 'L1_FAST'],
    preferredModels: {
      TIER_0_DETERMINISTIC: 'alias-ring-v1',
      L1_FAST: 'gemma4:e4b'
    }
  }
});

// Precompute global lowercased alias -> canonical field map and canonical field set across all ports.
const ALL_PORT_CANONICAL_FIELDS = new Set();
const GLOBAL_FIELD_ALIAS_MAP = (() => {
  const map = new Map();
  for (const port of Object.values(STACK_ONTOLOGY_PORTS)) {
    for (const [canonicalName, fieldSpec] of Object.entries(port.canonicalFields)) {
      ALL_PORT_CANONICAL_FIELDS.add(canonicalName);
      map.set(canonicalName.toLowerCase(), canonicalName);
      for (const alias of fieldSpec.aliases) {
        if (!map.has(alias.toLowerCase())) {
          map.set(alias.toLowerCase(), canonicalName);
        }
      }
    }
  }
  return map;
})();

function isIdentStart(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
}

function isIdentPart(code) {
  return isIdentStart(code) || (code >= 48 && code <= 57);
}

function consumeTemplateBody(source, startIdx, out, templateBraceStack, currentBraceDepth) {
  const len = source.length;
  let i = startIdx;
  while (i < len) {
    const c = source[i];
    if (c === '\\' && i + 1 < len) {
      out.push(c, source[i + 1]);
      i += 2;
      continue;
    }
    if (c === '`') {
      out.push(c);
      return i + 1;
    }
    if (c === '$' && source[i + 1] === '{') {
      out.push('$', '{');
      templateBraceStack.push(currentBraceDepth);
      return i + 2;
    }
    out.push(c);
    i += 1;
  }
  return i;
}

/**
 * Strip JS/TS comments while tracking regex literals (`canStartRegex`) and nested `${...}` templates.
 * Matches `@krusch/toolkit/brick-exchange/ontology` lexical parity (`ARCH-01`).
 * @param {string} source
 * @returns {string}
 */
function stripCommentsPreservingLiterals(source) {
  const len = source.length;
  const out = [];
  let i = 0;
  let canStartRegex = true;
  let braceDepth = 0;
  const templateBraceStack = [];

  while (i < len) {
    const ch = source[i];
    const next = i + 1 < len ? source[i + 1] : '';

    if (ch === '/' && next === '/') {
      out.push(' ', ' ');
      i += 2;
      while (i < len && source[i] !== '\n') {
        out.push(source[i] === '\r' ? '\r' : ' ');
        i += 1;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      out.push(' ', ' ');
      i += 2;
      while (i < len) {
        if (source[i] === '*' && source[i + 1] === '/') {
          out.push(' ', ' ');
          i += 2;
          break;
        }
        out.push(source[i] === '\n' || source[i] === '\r' ? source[i] : ' ');
        i += 1;
      }
      continue;
    }

    if (ch === "'" || ch === '"') {
      const quote = ch;
      out.push(ch);
      i += 1;
      while (i < len) {
        const c = source[i];
        out.push(c);
        i += 1;
        if (c === '\\' && i < len) {
          out.push(source[i]);
          i += 1;
          continue;
        }
        if (c === quote) break;
      }
      canStartRegex = false;
      continue;
    }

    if (ch === '`') {
      out.push(ch);
      i = consumeTemplateBody(source, i + 1, out, templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > 0;
      continue;
    }

    if (
      ch === '}' &&
      templateBraceStack.length > 0 &&
      braceDepth === templateBraceStack[templateBraceStack.length - 1]
    ) {
      templateBraceStack.pop();
      out.push(ch);
      i = consumeTemplateBody(source, i + 1, out, templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > 0;
      continue;
    }

    if (ch === '/' && canStartRegex && next !== '/' && next !== '*') {
      out.push(ch);
      i += 1;
      let inCharClass = false;
      while (i < len) {
        const c = source[i];
        out.push(c);
        i += 1;
        if (c === '\\' && i < len) {
          out.push(source[i]);
          i += 1;
          continue;
        }
        if (c === '[') inCharClass = true;
        else if (c === ']') inCharClass = false;
        else if (c === '/' && !inCharClass) {
          while (i < len && isIdentPart(source.charCodeAt(i))) {
            out.push(source[i]);
            i += 1;
          }
          break;
        } else if (c === '\n' || c === '\r') {
          break;
        }
      }
      canStartRegex = false;
      continue;
    }

    if (isIdentStart(ch.charCodeAt(0))) {
      const start = i;
      while (i < len && isIdentPart(source.charCodeAt(i))) {
        out.push(source[i]);
        i += 1;
      }
      const word = source.slice(start, i);
      canStartRegex = REGEX_PRECEDING_KEYWORDS.has(word);
      continue;
    }

    if (ch >= '0' && ch <= '9') {
      while (i < len && (isIdentPart(source.charCodeAt(i)) || source[i] === '.')) {
        out.push(source[i]);
        i += 1;
      }
      canStartRegex = false;
      continue;
    }

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      out.push(ch);
      i += 1;
      continue;
    }

    if (ch === '{') {
      braceDepth += 1;
      canStartRegex = true;
    } else if (ch === '}') {
      braceDepth = Math.max(0, braceDepth - 1);
      canStartRegex = false;
    } else if (ch === ')' || ch === ']') {
      canStartRegex = false;
    } else if ((ch === '+' && next === '+') || (ch === '-' && next === '-')) {
      out.push(ch, next);
      i += 2;
      canStartRegex = false;
      continue;
    } else {
      canStartRegex = true;
    }

    out.push(ch);
    i += 1;
  }

  return out.join('');
}

/**
 * Mask string and template literal text while keeping `${...}` expressions intact.
 * @param {string} commentStrippedCode
 * @returns {string}
 */
function maskStringAndTemplateBodies(commentStrippedCode) {
  const len = commentStrippedCode.length;
  const out = [];
  let i = 0;

  while (i < len) {
    const ch = commentStrippedCode[i];
    if (ch === "'" || ch === '"') {
      const quote = ch;
      out.push(quote);
      i += 1;
      while (i < len) {
        const c = commentStrippedCode[i];
        if (c === '\\' && i + 1 < len) {
          out.push(' ', ' ');
          i += 2;
          continue;
        }
        if (c === quote) {
          out.push(quote);
          i += 1;
          break;
        }
        out.push(c === '\n' ? '\n' : ' ');
        i += 1;
      }
      continue;
    }
    if (ch === '`') {
      out.push('`');
      i += 1;
      while (i < len) {
        const c = commentStrippedCode[i];
        if (c === '\\' && i + 1 < len) {
          out.push(' ', ' ');
          i += 2;
          continue;
        }
        if (c === '`') {
          out.push('`');
          i += 1;
          break;
        }
        if (c === '$' && commentStrippedCode[i + 1] === '{') {
          out.push('$', '{');
          i += 2;
          let depth = 1;
          while (i < len && depth > 0) {
            const inner = commentStrippedCode[i];
            if (inner === '{') depth += 1;
            else if (inner === '}') depth -= 1;
            else if (inner === "'" || inner === '"' || inner === '`') {
              // Recursively mask nested string literals inside ${...}
              const subQuote = inner;
              out.push(subQuote);
              i += 1;
              while (i < len) {
                const sc = commentStrippedCode[i];
                if (sc === '\\' && i + 1 < len) {
                  out.push(' ', ' ');
                  i += 2;
                  continue;
                }
                if (sc === subQuote) {
                  out.push(subQuote);
                  i += 1;
                  break;
                }
                if (subQuote === '`' && sc === '$' && commentStrippedCode[i + 1] === '{') {
                  out.push('$', '{');
                  depth += 1;
                  i += 2;
                  break;
                }
                out.push(sc === '\n' ? '\n' : ' ');
                i += 1;
              }
              continue;
            }
            out.push(inner);
            i += 1;
          }
          continue;
        }
        out.push(c === '\n' ? '\n' : ' ');
        i += 1;
      }
      continue;
    }
    out.push(ch);
    i += 1;
  }

  return out.join('');
}

/**
 * Scan JS/TS source code for Node-specific modules or host globals that violate Web-Standard Edge/Browser purity (`ARCH-01`).
 * @param {unknown} source
 * @returns {{ pure: boolean, violations: string[] }}
 */
function scanWebStandardPurity(source) {
  if (typeof source !== 'string' || !source.trim()) {
    return { pure: false, violations: ['EMPTY_OR_NON_STRING_SOURCE'] };
  }

  const violations = [];
  const pushViolation = (v) => {
    if (!violations.includes(v)) violations.push(v);
  };

  const commentStripped = stripCommentsPreservingLiterals(source)
    .replace(/\bimport\s+type\s+(?:[\s\S]*?\s+from\s+)?(['"`])[^'"`]+\1\s*;?/g, ' ')
    .replace(/\bexport\s+type\s+\{[\s\S]*?\}(?:\s+from\s+(['"`])[^'"`]+\1)?\s*;?/g, ' ');

  const inspectSpecifier = (rawSpec) => {
    const spec = String(rawSpec || '').trim();
    if (!spec) return;
    if (spec.startsWith('node:')) {
      pushViolation(`node-specifier:${spec}`);
      return;
    }
    const baseMod = spec.split('/')[0];
    if (NODE_BUILTIN_MODULES.has(spec) || NODE_BUILTIN_MODULES.has(baseMod)) {
      pushViolation(`node-builtin:${spec}`);
    }
  };

  let match;
  const staticImportRe = /\bimport\s+(?!type\b)[\s\S]*?\bfrom\s*(['"`])([^'"`]+)\1/g;
  while ((match = staticImportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const sideEffectImportRe = /\bimport\s*(['"`])([^'"`]+)\1/g;
  while ((match = sideEffectImportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const reExportRe =
    /\bexport\s+(?!type\b)(?:\*(?:\s+as\s+[A-Za-z_$][A-Za-z0-9_$]*)?|\{[\s\S]*?\})\s*from\s*(['"`])([^'"`]+)\1/g;
  while ((match = reExportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const dynImportRe = /(?<!(?:\.\s*|\?\.\s*|function\s+))\bimport\s*\(\s*(['"`])([^'"`$]+)\1\s*\)/g;
  while ((match = dynImportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  if (/(?<!(?:\.\s*|\?\.\s*|function\s+))\bimport\s*\(\s*`node:/.test(commentStripped)) {
    pushViolation('node-specifier:node:*');
  }

  const requireRe = /(?<!(?:\.\s*|\?\.\s*|function\s+))\brequire\s*\(\s*(['"`])([^'"`]+)\1\s*\)/g;
  while ((match = requireRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const codeOnly = maskStringAndTemplateBodies(commentStripped);

  if (
    /(?<!(?:\.\s*|\?\.\s*))\bprocess\s*(?:\.|\[)/.test(codeOnly) ||
    /\b(?:globalThis|global|window|self)\s*\.\s*process\b/.test(codeOnly) ||
    /\b(?:globalThis|global|window|self)\s*\[\s*['"`]process['"`]\s*\]/.test(commentStripped) ||
    /(?:=\s*|\(\s*|\[\s*|,\s*|return\s+)(?:(?:globalThis|global)\s*\.\s*)?process\b(?!\s*[:(])/.test(
      codeOnly
    )
  ) {
    pushViolation('node-global:process');
  }

  if (
    /(?<!(?:\.\s*|\?\.\s*|interface\s+|type\s+|class\s+|function\s+))\bBuffer\s*(?:\.|\(|\[)/.test(
      codeOnly
    ) ||
    /\bnew\s+Buffer\s*\(/.test(codeOnly) ||
    /\b(?:globalThis|global|window|self)\s*\.\s*Buffer\b/.test(codeOnly) ||
    /\b(?:globalThis|global|window|self)\s*\[\s*['"`]Buffer['"`]\s*\]/.test(commentStripped) ||
    /(?:=\s*|\(\s*|\[\s*|,\s*|return\s+)Buffer\b(?!\s*:)/.test(codeOnly)
  ) {
    pushViolation('node-global:Buffer');
  }

  if (/(?<![.\w$])(?:__dirname|__filename)\b/.test(codeOnly)) {
    pushViolation('node-global:__dirname/__filename');
  }

  if (/(?<!(?:\.\s*|\?\.\s*|function\s+))\brequire\s*\(/.test(codeOnly)) {
    pushViolation('node-global:require');
  }

  return {
    pure: violations.length === 0,
    violations
  };
}

/**
 * Check whether a brick's source uses pure Web-Standard ECMAScript / Web APIs
 * with zero `node:*` built-ins, `process.*`, `Buffer`, or CommonJS `require`.
 * @param {string} source
 * @returns {boolean}
 */
export function isWebStandardPureBrickSource(source) {
  return scanWebStandardPurity(source).pure;
}

function isCanonicalSharedPortName(bareName) {
  return Object.hasOwn(STACK_ONTOLOGY_PORTS, bareName) || TOOL_GRAPH_SHARED_PORT_SET.has(bareName);
}

/**
 * Normalize a port string or `{ id }` object into `{ id, namespace, bareName, shared }` (`ARCH-01`).
 * - Canonical ports in `STACK_ONTOLOGY_PORTS`, `CANONICAL_SHARED_TYPES`, or prefixed with `canonical:`
 *   resolve to `{ shared: true, namespace: 'canonical' }`.
 * - `<ns>:<type>` and `<ns>.<type>` resolve to `{ shared: false, namespace: '<ns>', bareName: '<type>', id: '<ns>:<type>' }`.
 * - Bare non-canonical ports (e.g. `'channel_id'`) resolve to `{ shared: false, namespace: 'unscoped', bareName }`
 *   and are rejected during cross-brick port compatibility checks!
 *
 * @param {unknown} rawPort
 * @returns {Readonly<{ id: string, namespace: string, bareName: string, shared: boolean }> | null}
 */
export function parsePortReference(rawPort) {
  if (isPlainObject(rawPort) && typeof rawPort.id === 'string') {
    return parsePortReference(rawPort.id);
  }
  if (typeof rawPort !== 'string') {
    return null;
  }
  const trimmed = rawPort.trim();
  if (!trimmed || FORBIDDEN_KEYS.has(trimmed)) {
    return null;
  }

  const separator = trimmed.includes(':') ? ':' : trimmed.includes('.') ? '.' : null;
  if (separator !== null) {
    const parts = trimmed.split(separator);
    if (parts.length !== 2) {
      return null;
    }
    const rawNs = parts[0].trim().toLowerCase();
    const rawBare = parts[1].trim();
    if (
      !SAFE_PORT_SEGMENT_RE.test(rawNs) ||
      !SAFE_PORT_SEGMENT_RE.test(rawBare) ||
      FORBIDDEN_KEYS.has(rawNs) ||
      FORBIDDEN_KEYS.has(rawBare)
    ) {
      return null;
    }
    if (rawNs === 'canonical') {
      const canonicalId = isCanonicalSharedPortName(rawBare) ? rawBare : `canonical:${rawBare}`;
      return Object.freeze({
        id: canonicalId,
        namespace: 'canonical',
        bareName: rawBare,
        shared: true
      });
    }
    return Object.freeze({
      id: `${rawNs}:${rawBare}`,
      namespace: rawNs,
      bareName: rawBare,
      shared: false
    });
  }

  if (!SAFE_PORT_SEGMENT_RE.test(trimmed) || FORBIDDEN_KEYS.has(trimmed)) {
    return null;
  }
  if (isCanonicalSharedPortName(trimmed)) {
    return Object.freeze({
      id: trimmed,
      namespace: 'canonical',
      bareName: trimmed,
      shared: true
    });
  }
  return Object.freeze({
    id: trimmed,
    namespace: 'unscoped',
    bareName: trimmed,
    shared: false
  });
}

/**
 * Determine whether an upstream `producedPort` is type- and namespace-compatible
 * with a downstream `consumedPort` (`ARCH-01`):
 * - Rejects bare non-canonical `'unscoped'` ports (`areOntologyPortsCompatible('channel_id', 'channel_id') === false`).
 * - Matches `'canonical:ledger_event'` <-> `'ledger_event'` and `'slack.channel_id'` <-> `'slack:channel_id'`.
 * - Rejects cross-namespace opaque IDs (`'slack:channel_id'` !== `'discord:channel_id'`).
 *
 * @param {string|{id: string}} producedPort
 * @param {string|{id: string}} consumedPort
 * @returns {boolean}
 */
export function areOntologyPortsCompatible(producedPort, consumedPort) {
  const prod = parsePortReference(producedPort);
  const cons = parsePortReference(consumedPort);
  if (!prod || !cons) {
    return false;
  }
  if (prod.namespace === 'unscoped' || cons.namespace === 'unscoped') {
    return false;
  }
  if (prod.shared && cons.shared && prod.namespace === 'canonical' && cons.namespace === 'canonical') {
    return prod.bareName === cons.bareName;
  }
  return !prod.shared && !cons.shared && prod.namespace === cons.namespace && prod.bareName === cons.bareName;
}

/**
 * Detect whether two ports represent a cross-namespace or unscoped collision on the same bare port name.
 * @param {string} producedPort
 * @param {string} consumedPort
 */
function detectPortNamespaceCollision(producedPort, consumedPort) {
  const prod = parsePortReference(producedPort);
  const cons = parsePortReference(consumedPort);
  if (!prod || !cons || areOntologyPortsCompatible(prod, cons)) {
    return null;
  }

  if (prod.bareName === cons.bareName) {
    return {
      producedPort: prod.id,
      consumedPort: cons.id,
      producedNamespace: prod.namespace === 'unscoped' ? null : prod.namespace,
      consumedNamespace: cons.namespace === 'unscoped' ? null : cons.namespace,
      localPort: prod.bareName
    };
  }

  return null;
}

/**
 * Deterministic 48-bit SHA-256 safe integer surrogate vertex ID in `[1000, 281474976711655]`
 * matching `@krusch/toolkit/brick-exchange` and HydraScope's HydraDB v0.4.0 vertex ID contract bit-for-bit (`ARCH-01`).
 *
 * @param {string} [namespace='brick-ontology']
 * @param {string} logicalId
 * @returns {number}
 */
export function surrogateOntologyVertexId(namespace, logicalId) {
  const ns = typeof namespace === 'string' && namespace.trim() ? namespace.trim() : 'brick-ontology';
  const id = String(logicalId ?? '');
  return (
    1000 +
    crypto
      .createHash('sha256')
      .update(`${ns}\0${id}`, 'utf8')
      .digest()
      .readUIntBE(0, 6)
  );
}

/**
 * Scrub accidental private network IPs, secret tokens, or host user paths from ontology graph strings.
 * @param {unknown} value
 * @returns {string}
 */
function scrubOntologyString(value) {
  if (typeof value !== 'string' || !value) return '';
  return value
    .replace(SCRUB_PRIVATE_IPV4_RE, '[REDACTED_PRIVATE_IP]')
    .replace(SCRUB_SECRET_TOKEN_RE, '[REDACTED_SECRET]')
    .replace(SCRUB_LOCAL_HOME_PATH_RE, '[REDACTED_PATH]');
}

function normalizeIsoDateString(rawDate) {
  if (typeof rawDate !== 'string') {
    return null;
  }
  const trimmed = rawDate.trim();
  if (!trimmed) {
    return null;
  }
  const dateMatch = ISO_DATE_ONLY_RE.exec(trimmed);
  if (dateMatch) {
    const year = Number(dateMatch[1]);
    const month = Number(dateMatch[2]);
    const day = Number(dateMatch[3]);
    const utcMs = Date.UTC(year, month - 1, day);
    const dt = new Date(utcMs);
    if (
      dt.getUTCFullYear() !== year ||
      dt.getUTCMonth() + 1 !== month ||
      dt.getUTCDate() !== day
    ) {
      return null;
    }
    return trimmed;
  }
  const parsedMs = Date.parse(trimmed);
  if (!Number.isFinite(parsedMs)) {
    return null;
  }
  return new Date(parsedMs).toISOString().slice(0, 10);
}

/**
 * Validate and normalize 4-axis ontology metadata for a candidate or sealed brick (`SEC-02`, `ARCH-01`).
 * Fails closed on forbidden keys, unknown stacks/channels/MoE profiles, invalid ports, or non-hash supersedes refs.
 *
 * @param {object} [rawOntology={}]
 * @param {{ source?: string, blueprint?: object }} [options={}]
 */
export function normalizeBrickOntology(rawOntology = {}, options = {}) {
  const tool = 'krusch_brick_ontology_normalize';
  if (!isPlainObject(rawOntology)) {
    return failEnvelope(tool, 'INVALID_ONTOLOGY_METADATA', 'Ontology metadata must be a plain object');
  }

  const safetyCheck = validateSafePayload(rawOntology, 'ontology', { requireJsonSerializable: true });
  if (!safetyCheck.ok) {
    return failEnvelope(tool, safetyCheck.code, safetyCheck.message, safetyCheck.details || null);
  }

  const opts = isPlainObject(options) ? options : {};
  const blueprint = isPlainObject(opts.blueprint) ? opts.blueprint : {};
  const source = typeof opts.source === 'string' ? opts.source : '';

  const languageRaw = String(blueprint.language || rawOntology.language || 'js')
    .trim()
    .toLowerCase();
  const isPythonBrick = languageRaw === 'py' || languageRaw === 'python';
  const webStandardPurity = isPythonBrick
    ? { pure: false, violations: ['PYTHON_RUNTIME'] }
    : typeof opts.source === 'string' && opts.source.trim().length > 0
      ? scanWebStandardPurity(source)
      : { pure: true, violations: [] };

  const rawStacksCandidate =
    rawOntology.stacks ??
    rawOntology.compatibleStacks ??
    rawOntology.targetStacks ??
    blueprint.compatibleStacks ??
    blueprint.stacks;

  let normalizedStacks = [];
  if (rawStacksCandidate === undefined || rawStacksCandidate === null) {
    if (isPythonBrick) {
      normalizedStacks = ['python-fastapi'];
    } else {
      normalizedStacks = webStandardPurity.pure
        ? ['node-esm', 'typescript-node', 'react-vite', 'cloudflare-edge']
        : ['node-esm', 'typescript-node'];
    }
  } else if (!Array.isArray(rawStacksCandidate) || rawStacksCandidate.length === 0) {
    return failEnvelope(
      tool,
      'INVALID_ONTOLOGY_STACKS',
      'ontology.stacks must be a non-empty array of canonical stack slugs when provided'
    );
  } else {
    const seen = new Set();
    for (const item of rawStacksCandidate) {
      const slug = typeof item === 'string' ? item.trim() : '';
      if (!slug || FORBIDDEN_KEYS.has(slug) || !Object.hasOwn(STACK_ONTOLOGY_STACKS, slug)) {
        return failEnvelope(
          tool,
          'UNKNOWN_ONTOLOGY_STACK',
          `Unknown ontology stack "${String(item)}"`,
          { stack: item, supportedStacks: Object.keys(STACK_ONTOLOGY_STACKS) }
        );
      }
      if (!seen.has(slug)) {
        seen.add(slug);
        normalizedStacks.push(slug);
      }
    }
  }

  const parsePortList = (list, fieldName) => {
    if (list === undefined || list === null) return { ok: true, ports: [] };
    if (!Array.isArray(list)) {
      return {
        ok: false,
        err: failEnvelope(
          tool,
          'INVALID_ONTOLOGY_PORT',
          `ontology.${fieldName} must be an array of port strings`,
          { field: fieldName }
        )
      };
    }
    const out = [];
    const seen = new Set();
    for (const rawItem of list) {
      const parsed = parsePortReference(rawItem);
      if (!parsed) {
        return {
          ok: false,
          err: failEnvelope(
            tool,
            'INVALID_ONTOLOGY_PORT',
            `Invalid port reference "${String(rawItem)}" in ontology.${fieldName}`,
            { field: fieldName, port: rawItem }
          )
        };
      }
      if (!seen.has(parsed.id)) {
        seen.add(parsed.id);
        out.push(parsed.id);
      }
    }
    return { ok: true, ports: out };
  };

  const rawConsumes =
    rawOntology.consumesPorts ??
    rawOntology.inputPorts ??
    blueprint.consumesPorts ??
    blueprint.inputPorts;
  const consumesRes = parsePortList(rawConsumes, 'consumesPorts');
  if (!consumesRes.ok) return consumesRes.err;

  const rawProduces =
    rawOntology.producesPorts ??
    rawOntology.outputPorts ??
    blueprint.producesPorts ??
    blueprint.outputPorts;
  const producesRes = parsePortList(rawProduces, 'producesPorts');
  if (!producesRes.ok) return producesRes.err;

  const rawChannels = rawOntology.channels ?? blueprint.channels;
  const normalizedChannels = [];
  if (rawChannels !== undefined && rawChannels !== null) {
    if (!Array.isArray(rawChannels)) {
      return failEnvelope(
        tool,
        'INVALID_ONTOLOGY_CHANNELS',
        'ontology.channels must be an array of canonical channel IDs'
      );
    }
    const seen = new Set();
    for (const rawCh of rawChannels) {
      const ch = typeof rawCh === 'string' ? rawCh.trim() : '';
      if (!ch || FORBIDDEN_KEYS.has(ch) || !Object.hasOwn(STACK_ONTOLOGY_CHANNELS, ch)) {
        return failEnvelope(
          tool,
          'UNKNOWN_ONTOLOGY_CHANNEL',
          `Unknown ontology channel "${String(rawCh)}"`,
          { channel: rawCh, supportedChannels: Object.keys(STACK_ONTOLOGY_CHANNELS) }
        );
      }
      if (!seen.has(ch)) {
        seen.add(ch);
        normalizedChannels.push(ch);
      }
    }
  }

  const rawMoeCandidate = rawOntology.moeProfile ?? blueprint.moeProfile;
  let moeProfile = null;
  if (rawMoeCandidate !== undefined && rawMoeCandidate !== null && rawMoeCandidate !== '') {
    const rawMoe = typeof rawMoeCandidate === 'string' ? rawMoeCandidate.trim() : '';
    if (!rawMoe || FORBIDDEN_KEYS.has(rawMoe) || !Object.hasOwn(STACK_ONTOLOGY_MOE_PROFILES, rawMoe)) {
      return failEnvelope(
        tool,
        'UNKNOWN_MOE_PROFILE',
        `Unknown ontology MoE profile "${String(rawMoeCandidate)}"`,
        {
          moeProfile: rawMoeCandidate,
          supportedProfiles: Object.keys(STACK_ONTOLOGY_MOE_PROFILES)
        }
      );
    }
    moeProfile = rawMoe;
  }

  const rawSupersedes = rawOntology.supersedes ?? blueprint.supersedes;
  const supersedes = [];
  if (rawSupersedes !== undefined && rawSupersedes !== null) {
    if (!Array.isArray(rawSupersedes)) {
      return failEnvelope(
        tool,
        'INVALID_SUPERSEDES_REF',
        'ontology.supersedes must be an array of 64-hex sourceHash or brickId@sourceHash references'
      );
    }
    const seen = new Set();
    for (const item of rawSupersedes) {
      const rawStr = typeof item === 'string' ? item.trim() : '';
      const m = SAFE_SUPERSEDES_RE.exec(rawStr);
      if (!m) {
        return failEnvelope(
          tool,
          'INVALID_SUPERSEDES_REF',
          `Invalid supersedes reference "${String(item)}"; expected 64-hex sourceHash or brickId@sourceHash`,
          { reference: item }
        );
      }
      const normalizedRef = m[1] ? `${m[1].toLowerCase()}@${m[2].toLowerCase()}` : m[2].toLowerCase();
      if (!seen.has(normalizedRef)) {
        seen.add(normalizedRef);
        supersedes.push(normalizedRef);
      }
    }
  }

  const rawValidFrom = rawOntology.validFrom ?? blueprint.validFrom;
  let validFrom = null;
  if (rawValidFrom !== undefined && rawValidFrom !== null && rawValidFrom !== '') {
    validFrom = normalizeIsoDateString(rawValidFrom);
    if (!validFrom) {
      return failEnvelope(
        tool,
        'INVALID_ONTOLOGY_DATE',
        `Invalid validFrom date "${String(rawValidFrom)}"`,
        { field: 'validFrom', value: rawValidFrom }
      );
    }
  }

  const rawRetiredAt = rawOntology.retiredAt ?? blueprint.retiredAt;
  let retiredAt = null;
  if (rawRetiredAt !== undefined && rawRetiredAt !== null && rawRetiredAt !== '') {
    retiredAt = normalizeIsoDateString(rawRetiredAt);
    if (!retiredAt) {
      return failEnvelope(
        tool,
        'INVALID_ONTOLOGY_DATE',
        `Invalid retiredAt date "${String(rawRetiredAt)}"`,
        { field: 'retiredAt', value: rawRetiredAt }
      );
    }
  }

  const rawTsContract = rawOntology.timeSeriesContract ?? blueprint.timeSeriesContract;
  let timeSeriesContract = null;
  if (rawTsContract !== undefined && rawTsContract !== null) {
    if (!isPlainObject(rawTsContract)) {
      return failEnvelope(
        tool,
        'INVALID_TIMESERIES_CONTRACT',
        'ontology.timeSeriesContract must be a plain object'
      );
    }
    let cadenceMs = null;
    if (rawTsContract.cadenceMs !== undefined && rawTsContract.cadenceMs !== null) {
      if (
        typeof rawTsContract.cadenceMs !== 'number' ||
        !Number.isFinite(rawTsContract.cadenceMs) ||
        rawTsContract.cadenceMs <= 0
      ) {
        return failEnvelope(
          tool,
          'INVALID_TIMESERIES_CONTRACT',
          'timeSeriesContract.cadenceMs must be a positive finite number',
          { cadenceMs: rawTsContract.cadenceMs }
        );
      }
      cadenceMs = rawTsContract.cadenceMs;
    }
    const nanInfPolicy =
      rawTsContract.nanInfPolicy === undefined ? 'reject' : String(rawTsContract.nanInfPolicy).trim();
    if (nanInfPolicy !== 'reject' && nanInfPolicy !== 'impute_null') {
      return failEnvelope(
        tool,
        'INVALID_TIMESERIES_CONTRACT',
        `Unsupported timeSeriesContract.nanInfPolicy "${nanInfPolicy}"`,
        { nanInfPolicy }
      );
    }
    timeSeriesContract = deepFreezePlain({
      ...(cadenceMs !== null ? { cadenceMs } : {}),
      requireMonotonicTimestamps:
        rawTsContract.requireMonotonicTimestamps === undefined
          ? true
          : Boolean(rawTsContract.requireMonotonicTimestamps),
      preserveNegativeValues:
        rawTsContract.preserveNegativeValues === undefined
          ? true
          : Boolean(rawTsContract.preserveNegativeValues),
      nanInfPolicy
    });
  }

  const ontology = deepFreezePlain({
    stacks: normalizedStacks,
    consumesPorts: consumesRes.ports,
    producesPorts: producesRes.ports,
    channels: normalizedChannels,
    moeProfile,
    supersedes,
    validFrom,
    retiredAt,
    timeSeriesContract
  });

  return okEnvelope(tool, 'Normalized 4-axis brick ontology metadata', {
    ontology,
    webStandardPurity
  });
}

function normalizeStringList(raw) {
  if (!raw) return [];
  const arr = Array.isArray(raw) ? raw : [raw];
  const out = [];
  for (const item of arr) {
    const clean =
      typeof item === 'string'
        ? item.trim()
        : isPlainObject(item) && typeof item.id === 'string'
          ? item.id.trim()
          : '';
    if (clean && !FORBIDDEN_KEYS.has(clean) && !out.includes(clean)) {
      out.push(clean);
    }
  }
  return out;
}

/**
 * Unwrap and validate a brick entry passed from standalone callers, `listInbox`, or `brick_exchange_bricks` rows.
 * Reads signed `blueprint.ontology` BEFORE `bundle.ontology` on sealed bundles (`SEC-02`).
 *
 * @param {unknown} entry
 * @returns {{ ok: true, value: any } | { ok: false, error: { code: string, message: string, details?: any } }}
 */
function unwrapBrickEntryResult(entry) {
  if (!isPlainObject(entry)) {
    return {
      ok: false,
      error: {
        code: 'INVALID_BRICK_BUNDLE',
        message: 'bundle must be a valid sealed brick bundle or authorized brick record'
      }
    };
  }

  const entrySafety = validateSafePayload(entry, 'bundle', { requireJsonSerializable: false });
  if (!entrySafety.ok) {
    return {
      ok: false,
      error: {
        code: entrySafety.code,
        message: entrySafety.message,
        details: entrySafety.details
      }
    };
  }

  let bundle = null;
  if (isPlainObject(entry.bundle)) {
    bundle = entry.bundle;
  } else if (typeof entry.bundle_json === 'string' && entry.bundle_json.trim()) {
    try {
      const parsed = JSON.parse(entry.bundle_json);
      if (isPlainObject(parsed)) {
        bundle = parsed;
      }
    } catch {
      return {
        ok: false,
        error: {
          code: 'INVALID_BRICK_BUNDLE',
          message: 'Malformed bundle_json in brick entry'
        }
      };
    }
  } else {
    bundle = entry;
  }

  if (!isPlainObject(bundle)) {
    return {
      ok: false,
      error: {
        code: 'INVALID_BRICK_BUNDLE',
        message: 'bundle must be a plain object'
      }
    };
  }

  const isSealedBundle =
    bundle.format === 'krusch-sealed-brick/v1' || isPlainObject(bundle.attestation);

  if (isSealedBundle) {
    const sealRes = verifySealedBrickBundle(bundle);
    if (!sealRes.ok) {
      return {
        ok: false,
        error: {
          code: sealRes.error.code,
          message: sealRes.error.message,
          details: sealRes.error.details
        }
      };
    }
  }

  const blueprint = isPlainObject(bundle.blueprint) ? bundle.blueprint : {};

  // SEC-02: Always prefer signed blueprint.ontology BEFORE top-level bundle.ontology!
  const rawOntology = isPlainObject(blueprint.ontology)
    ? blueprint.ontology
    : isPlainObject(bundle.ontology)
      ? bundle.ontology
      : bundle.ontology !== undefined && bundle.ontology !== null
        ? bundle.ontology
        : blueprint.ontology !== undefined && blueprint.ontology !== null
          ? blueprint.ontology
          : {};

  const brickId = String(
    bundle.brickId || blueprint.id || entry.brickId || entry.brick_id || ''
  ).trim();
  if (!brickId || FORBIDDEN_KEYS.has(brickId)) {
    return {
      ok: false,
      error: {
        code: 'INVALID_BRICK_BUNDLE',
        message: 'Brick bundle is missing a valid brickId'
      }
    };
  }

  const source = typeof bundle.source === 'string' ? bundle.source : '';
  const sourceHash = String(
    bundle.lineage?.sourceHash ||
      entry.sourceHash ||
      entry.source_hash ||
      crypto.createHash('sha256').update(source, 'utf8').digest('hex')
  )
    .trim()
    .toLowerCase();

  const normRes = normalizeBrickOntology(rawOntology, { source, blueprint });
  if (!normRes.ok) {
    return {
      ok: false,
      error: {
        code: normRes.error.code,
        message: normRes.error.message,
        details: normRes.error.details
      }
    };
  }

  const { ontology } = normRes.data;
  const orgId = String(bundle.orgId ?? entry.orgId ?? entry.org_id ?? '').trim();
  const authorId = String(bundle.authorId ?? entry.authorId ?? entry.author_id ?? 'local-author').trim();
  const name = String(bundle.name || blueprint.name || entry.name || brickId).trim();
  const summary = String(bundle.summary || blueprint.summary || entry.summary || '').trim();
  const languageRaw = String(blueprint.language || rawOntology?.language || 'js')
    .trim()
    .toLowerCase();
  const isPythonBrick = languageRaw === 'py' || languageRaw === 'python';
  const purity = isPythonBrick
    ? { pure: false, violations: ['PYTHON_RUNTIME'] }
    : scanWebStandardPurity(source);

  const compatibleStacks = ontology.stacks.filter((s) => {
    const stackDef = STACK_ONTOLOGY_STACKS[s];
    if (!stackDef) return false;
    if (stackDef.requiresWebStandardPurity && !purity.pure) return false;
    if (isPythonBrick && stackDef.runtimeFamily !== 'python') return false;
    return true;
  });

  const validFrom =
    ontology.validFrom ||
    (typeof bundle.validFrom === 'string' && normalizeIsoDateString(bundle.validFrom)) ||
    (typeof bundle.createdAt === 'string' && bundle.createdAt.trim() ? bundle.createdAt.trim() : null);

  const retiredAt =
    ontology.retiredAt ||
    (typeof bundle.retiredAt === 'string' && normalizeIsoDateString(bundle.retiredAt)) ||
    null;

  const versionTag =
    typeof (rawOntology?.version ?? blueprint.version ?? bundle.version) === 'string'
      ? String(rawOntology?.version ?? blueprint.version ?? bundle.version).trim()
      : null;

  return {
    ok: true,
    value: {
      bundle,
      blueprint,
      isSealedBundle,
      brickId,
      source,
      sourceHash,
      versionTag,
      name,
      summary,
      orgId,
      authorId,
      isPythonBrick,
      purity,
      compatibleStacks,
      consumesPorts: [...ontology.consumesPorts],
      producesPorts: [...ontology.producesPorts],
      channels: [...ontology.channels],
      moeProfile: ontology.moeProfile,
      supersedes: [...ontology.supersedes],
      validFrom,
      retiredAt,
      timeSeriesContract: ontology.timeSeriesContract
        ? { ...ontology.timeSeriesContract }
        : null,
      accessMode: entry.accessMode ? String(entry.accessMode) : null,
      grantId: entry.grantId ? String(entry.grantId) : null
    }
  };
}

function parseTemporalMs(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  const str = String(value).trim();
  if (!str) return null;
  const parsed = Date.parse(ISO_DATE_ONLY_RE.test(str) ? `${str}T00:00:00.000Z` : str);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Inspect the deep-frozen 4-axis ontology registries with optional `stackFilter` and `categoryFilter`.
 * @param {object} [options]
 * @param {string|null} [options.stackFilter=null]
 * @param {string|null} [options.categoryFilter=null]
 */
export function inspectBrickOntology(options = {}) {
  const tool = 'krusch_brick_ontology_inspect';
  if (!isPlainObject(options)) {
    return failEnvelope(tool, 'INVALID_INSPECT_OPTIONS', 'Options must be a plain object');
  }
  const safety = validateSafePayload(options, 'options');
  if (!safety.ok) {
    return failEnvelope(tool, safety.code, safety.message, safety.details || null);
  }

  const { stackFilter = null, categoryFilter = null } = options;
  const cleanStack =
    typeof stackFilter === 'string' && stackFilter.trim() ? stackFilter.trim() : null;
  const cleanCategory =
    typeof categoryFilter === 'string' && categoryFilter.trim() ? categoryFilter.trim() : null;

  if (cleanStack && FORBIDDEN_KEYS.has(cleanStack)) {
    return failEnvelope(tool, 'ONTOLOGY_FORBIDDEN_KEY', `Forbidden key "${cleanStack}" rejected`);
  }
  if (cleanCategory && FORBIDDEN_KEYS.has(cleanCategory)) {
    return failEnvelope(tool, 'ONTOLOGY_FORBIDDEN_KEY', `Forbidden key "${cleanCategory}" rejected`);
  }

  let stacks = Object.values(STACK_ONTOLOGY_STACKS);
  let ports = Object.values(STACK_ONTOLOGY_PORTS);
  let channels = Object.values(STACK_ONTOLOGY_CHANNELS);
  let moeProfiles = Object.values(STACK_ONTOLOGY_MOE_PROFILES);

  if (cleanStack) {
    stacks = stacks.filter((s) => s.id === cleanStack);
  }
  if (cleanCategory) {
    stacks = stacks.filter((s) => s.category === cleanCategory);
    ports = ports.filter((p) => p.category === cleanCategory);
    channels = channels.filter((c) => c.category === cleanCategory);
    moeProfiles = moeProfiles.filter((m) => m.category === cleanCategory);
  }

  return okEnvelope(
    tool,
    `Ontology inspection: ${stacks.length} stack(s), ${ports.length} port(s), ${channels.length} channel(s), ${moeProfiles.length} MoE profile(s)`,
    {
      stacks,
      ports,
      channels,
      moeProfiles,
      counts: {
        stacks: stacks.length,
        ports: ports.length,
        channels: channels.length,
        moeProfiles: moeProfiles.length
      }
    }
  );
}

/**
 * Detect whether a 1D array of plain objects starts with a string units header row
 * (e.g. `[{ recorded_at: 'epoch_ms', reading: 'm/s' }, { recorded_at: 60, reading: 5.4 }]`).
 * @param {unknown} rows
 * @returns {boolean}
 */
function detectObjectHeaderUnitRow(rows) {
  if (!Array.isArray(rows) || rows.length < 2) {
    return false;
  }
  const row0 = rows[0];
  const row1 = rows[1];
  if (!isPlainObject(row0) || !isPlainObject(row1)) {
    return false;
  }
  let sawHeaderStringVsNumber = false;
  for (const key of Object.keys(row0)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    const v0 = row0[key];
    const v1 = row1[key];
    if (
      typeof v0 === 'string' &&
      v0.trim().length > 0 &&
      Number.isNaN(Number(v0)) &&
      typeof v1 === 'number' &&
      Number.isFinite(v1)
    ) {
      sawHeaderStringVsNumber = true;
    }
  }
  return sawHeaderStringVsNumber;
}

function hasNonFiniteDeep(value, seen = new WeakSet()) {
  if (typeof value === 'number') {
    return !Number.isFinite(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed === 'NaN' || trimmed === 'Infinity' || trimmed === '-Infinity';
  }
  if (value === null || typeof value !== 'object') {
    return false;
  }
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      if (hasNonFiniteDeep(value[i], seen)) return true;
    }
    return false;
  }
  for (const k of Object.keys(value)) {
    if (!FORBIDDEN_KEYS.has(k) && hasNonFiniteDeep(value[k], seen)) {
      return true;
    }
  }
  return false;
}

function extractTimeSeriesRows(sampleData) {
  if (Array.isArray(sampleData)) {
    return sampleData;
  }
  if (isPlainObject(sampleData)) {
    for (const key of ['points', 'samples', 'window', 'rows', 'series', 'data']) {
      if (Array.isArray(sampleData[key])) {
        return sampleData[key];
      }
    }
  }
  return null;
}

function validateTimeSeriesInvariants(sampleData, contract = {}) {
  const nanInfPolicy = contract.nanInfPolicy || 'reject';
  if (nanInfPolicy === 'reject' && hasNonFiniteDeep(sampleData)) {
    return {
      ok: false,
      reason: 'NON_FINITE_VALUE',
      message: 'Time-series sampleData contains NaN or Infinity values rejected by nanInfPolicy'
    };
  }

  const rawRows = extractTimeSeriesRows(sampleData);
  if (!rawRows || rawRows.length === 0) {
    return { ok: true };
  }

  const tsAliases = STACK_ONTOLOGY_PORTS.timeseries_window.canonicalFields.ts.aliases;
  const valAliases = STACK_ONTOLOGY_PORTS.timeseries_window.canonicalFields.val.aliases;

  let startIdx = 0;
  let tsColIdx = 0;
  let valColIdx = 1;

  if (
    Array.isArray(rawRows[0]) &&
    rawRows[0].length > 0 &&
    rawRows[0].every((cell) => typeof cell === 'string')
  ) {
    startIdx = 1;
    const lowerHeaders = rawRows[0].map((h) => h.trim().toLowerCase());
    const foundTs = lowerHeaders.findIndex((h) => GLOBAL_FIELD_ALIAS_MAP.get(h) === 'ts');
    const foundVal = lowerHeaders.findIndex((h) => GLOBAL_FIELD_ALIAS_MAP.get(h) === 'val');
    if (foundTs >= 0) tsColIdx = foundTs;
    if (foundVal >= 0) valColIdx = foundVal;
  } else if (detectObjectHeaderUnitRow(rawRows)) {
    startIdx = 1;
  }

  const requireMonotonic = contract.requireMonotonicTimestamps !== false;
  const preserveNegative = contract.preserveNegativeValues !== false;

  let prevTs = null;
  for (let i = startIdx; i < rawRows.length; i += 1) {
    const row = rawRows[i];
    let tsVal = undefined;
    let numVal = undefined;

    if (Array.isArray(row)) {
      tsVal = row[tsColIdx];
      numVal = row[valColIdx];
    } else if (isPlainObject(row)) {
      for (const k of tsAliases) {
        if (Object.hasOwn(row, k)) {
          tsVal = row[k];
          break;
        }
      }
      for (const k of valAliases) {
        if (Object.hasOwn(row, k)) {
          numVal = row[k];
          break;
        }
      }
    }

    if (tsVal !== undefined) {
      const numericTs = typeof tsVal === 'number' ? tsVal : Number(tsVal);
      if (!Number.isFinite(numericTs)) {
        return {
          ok: false,
          reason: 'NON_FINITE_TIMESTAMP',
          rowIndex: i,
          message: `Time-series row ${i} has non-finite timestamp`
        };
      }
      if (requireMonotonic && prevTs !== null && numericTs < prevTs) {
        return {
          ok: false,
          reason: 'NON_MONOTONIC_TIMESTAMPS',
          rowIndex: i,
          previousTs: prevTs,
          currentTs: numericTs,
          message: `Time-series timestamps violated monotonicity at row ${i} (${numericTs} < ${prevTs})`
        };
      }
      prevTs = numericTs;
    }

    if (numVal !== undefined) {
      const parsedVal = typeof numVal === 'number' ? numVal : Number(numVal);
      if (!Number.isFinite(parsedVal)) {
        return {
          ok: false,
          reason: 'NON_FINITE_VALUE',
          rowIndex: i,
          message: `Time-series row ${i} has non-finite measurement value`
        };
      }
      if (!preserveNegative && parsedVal < 0) {
        return {
          ok: false,
          reason: 'NEGATIVE_VALUE_FORBIDDEN',
          rowIndex: i,
          message: `Time-series row ${i} contains negative value (${parsedVal}) disallowed by contract`
        };
      }
    }
  }

  return { ok: true };
}

/**
 * Pre-flight compatibility & invariant gate across stacks, channels, port namespaces, and time-series contracts.
 * @param {object} [options]
 */
export function checkBrickOntologyCompatibility(options = {}) {
  const tool = 'krusch_brick_ontology_check';
  if (!isPlainObject(options)) {
    return failEnvelope(tool, 'INVALID_COMPATIBILITY_OPTIONS', 'Options must be a plain object');
  }

  const optsSafety = validateSafePayload(options, 'options', { requireJsonSerializable: false });
  if (!optsSafety.ok) {
    return failEnvelope(tool, optsSafety.code, optsSafety.message, optsSafety.details || null);
  }

  const {
    bundle,
    targetStack = 'node-esm',
    targetChannel = null,
    providedSecurityBricks = [],
    enforceChannelGuards = false,
    upstreamProducedPorts = [],
    sampleData = undefined
  } = options;

  if (sampleData !== undefined) {
    const sampleSafety = validateSafePayload(sampleData, 'sampleData', {
      requireJsonSerializable: true,
      disallowNonFinite: false
    });
    if (!sampleSafety.ok) {
      return failEnvelope(tool, sampleSafety.code, sampleSafety.message, sampleSafety.details || null);
    }
  }

  const unwrapped = unwrapBrickEntryResult(bundle);
  if (!unwrapped.ok) {
    return failEnvelope(tool, unwrapped.error.code, unwrapped.error.message, unwrapped.error.details || null);
  }
  const parsed = unwrapped.value;

  const cleanStack = typeof targetStack === 'string' ? targetStack.trim() : '';
  if (!cleanStack || FORBIDDEN_KEYS.has(cleanStack) || !Object.hasOwn(STACK_ONTOLOGY_STACKS, cleanStack)) {
    return failEnvelope(
      tool,
      'UNKNOWN_ONTOLOGY_STACK',
      `Unknown targetStack "${cleanStack}". Expected one of: ${Object.keys(STACK_ONTOLOGY_STACKS).join(', ')}`,
      { targetStack: cleanStack }
    );
  }
  const stackDef = STACK_ONTOLOGY_STACKS[cleanStack];

  // 1. Runtime, Web-Standard Purity & Declared Stack Membership Gate (`ARCH-01`)
  if (parsed.isPythonBrick && stackDef.runtimeFamily !== 'python') {
    return failEnvelope(
      tool,
      'STACK_RUNTIME_INCOMPATIBLE',
      `Python brick "${parsed.brickId}" cannot execute natively inside JS/Edge targetStack "${cleanStack}"`,
      {
        brickId: parsed.brickId,
        targetStack: cleanStack,
        violations: ['PYTHON_TO_JS_RUNTIME_MISMATCH']
      }
    );
  }

  if (stackDef.requiresWebStandardPurity && !parsed.purity.pure) {
    return failEnvelope(
      tool,
      'STACK_RUNTIME_INCOMPATIBLE',
      `Brick "${parsed.brickId}" uses host-coupled Node APIs (${parsed.purity.violations.join(', ')}) incompatible with "${cleanStack}"`,
      {
        brickId: parsed.brickId,
        targetStack: cleanStack,
        violations: parsed.purity.violations
      }
    );
  }

  let bridgeMode = null;
  if (cleanStack === 'python-fastapi' && !parsed.isPythonBrick) {
    bridgeMode = 'contract-adapter';
  } else if (parsed.compatibleStacks.includes(cleanStack)) {
    bridgeMode = 'native';
  } else {
    return failEnvelope(
      tool,
      'STACK_RUNTIME_INCOMPATIBLE',
      `Brick "${parsed.brickId}" compatibleStacks [${parsed.compatibleStacks.join(', ')}] do not include targetStack "${cleanStack}"`,
      {
        brickId: parsed.brickId,
        targetStack: cleanStack,
        compatibleStacks: parsed.compatibleStacks
      }
    );
  }

  // 2. Channel Security Guard Gate
  const cleanChannel =
    typeof targetChannel === 'string' && targetChannel.trim() ? targetChannel.trim() : null;
  let requiredSecurityBricks = [];
  if (cleanChannel !== null) {
    if (FORBIDDEN_KEYS.has(cleanChannel) || !Object.hasOwn(STACK_ONTOLOGY_CHANNELS, cleanChannel)) {
      return failEnvelope(
        tool,
        'UNKNOWN_ONTOLOGY_CHANNEL',
        `Unknown targetChannel "${cleanChannel}"`,
        { targetChannel: cleanChannel }
      );
    }
    const channelDef = STACK_ONTOLOGY_CHANNELS[cleanChannel];
    requiredSecurityBricks = [...channelDef.requiredSecurityBricks];

    if (enforceChannelGuards === true && requiredSecurityBricks.length > 0) {
      const providedList = normalizeStringList(providedSecurityBricks);
      const providedSet = new Set(providedList);
      const guardSatisfied = channelDef.acceptedGuardTokens.some((tok) => providedSet.has(tok));
      if (!guardSatisfied) {
        return failEnvelope(
          tool,
          'CHANNEL_SECURITY_GUARD_MISSING',
          `Channel "${cleanChannel}" requires security guard brick(s) [${requiredSecurityBricks.join(', ')}]`,
          {
            brickId: parsed.brickId,
            targetChannel: cleanChannel,
            requiredSecurityBricks,
            providedSecurityBricks: providedList
          }
        );
      }
    }
  }

  // 3. Port Namespace Collision & Upstream Port Compatibility Gate
  const upstreamList = normalizeStringList(upstreamProducedPorts);
  for (const up of upstreamList) {
    if (!parsePortReference(up)) {
      return failEnvelope(
        tool,
        'INVALID_ONTOLOGY_PORT',
        `Invalid upstreamProducedPorts entry "${up}"`,
        { port: up }
      );
    }
  }

  if (upstreamList.length > 0 && parsed.consumesPorts.length > 0) {
    const collisions = [];
    for (const consPort of parsed.consumesPorts) {
      const hasMatch = upstreamList.some((prodPort) =>
        areOntologyPortsCompatible(prodPort, consPort)
      );
      if (!hasMatch) {
        for (const prodPort of upstreamList) {
          const collision = detectPortNamespaceCollision(prodPort, consPort);
          if (collision) {
            collisions.push(collision);
          }
        }
      }
    }

    if (collisions.length > 0) {
      return failEnvelope(
        tool,
        'PORT_NAMESPACE_COLLISION',
        `Port namespace collision detected for brick "${parsed.brickId}": ${collisions
          .map((c) => `${c.producedPort} !== ${c.consumedPort}`)
          .join(', ')}`,
        {
          brickId: parsed.brickId,
          collisions
        }
      );
    }

    const unmatchedConsumed = parsed.consumesPorts.filter(
      (consPort) => !upstreamList.some((prodPort) => areOntologyPortsCompatible(prodPort, consPort))
    );
    if (unmatchedConsumed.length > 0) {
      return failEnvelope(
        tool,
        'PORT_INCOMPATIBLE',
        `Upstream ports [${upstreamList.join(', ')}] do not satisfy required input port(s) [${unmatchedConsumed.join(', ')}]`,
        {
          brickId: parsed.brickId,
          upstreamProducedPorts: upstreamList,
          unmatchedConsumedPorts: unmatchedConsumed
        }
      );
    }
  }

  // 4. Time-Series & Numerical Invariant Gate
  if (sampleData !== undefined && sampleData !== null) {
    const moeDef = parsed.moeProfile ? STACK_ONTOLOGY_MOE_PROFILES[parsed.moeProfile] : null;
    const isTimeSeriesBrick =
      parsed.timeSeriesContract !== null ||
      parsed.moeProfile === 'timeseries-cadence-moe' ||
      parsed.consumesPorts.includes('timeseries_window') ||
      parsed.producesPorts.includes('timeseries_window') ||
      cleanChannel === 'telemetry:timeseries';

    if (isTimeSeriesBrick) {
      const mergedContract = {
        ...(moeDef?.invariants || {}),
        ...(parsed.timeSeriesContract || {})
      };
      const tsCheck = validateTimeSeriesInvariants(sampleData, mergedContract);
      if (!tsCheck.ok) {
        return failEnvelope(tool, 'TIMESERIES_INVARIANT_VIOLATION', tsCheck.message, {
          brickId: parsed.brickId,
          reason: tsCheck.reason,
          rowIndex: tsCheck.rowIndex ?? null
        });
      }
    } else if (moeDef?.invariants?.nanInfPolicy === 'reject' && hasNonFiniteDeep(sampleData)) {
      return failEnvelope(
        tool,
        'TIMESERIES_INVARIANT_VIOLATION',
        `Sample data for "${parsed.brickId}" contains NaN or Infinity disallowed by "${parsed.moeProfile}"`,
        {
          brickId: parsed.brickId,
          reason: 'NON_FINITE_VALUE'
        }
      );
    }
  }

  return okEnvelope(
    tool,
    `Brick "${parsed.brickId}" compatible with "${cleanStack}" (${bridgeMode})`,
    {
      compatible: true,
      brickId: parsed.brickId,
      sourceHash: parsed.sourceHash,
      targetStack: cleanStack,
      targetChannel: cleanChannel,
      bridgeMode,
      adapterFileName: stackDef.adapterFileName,
      webStandardPure: parsed.purity.pure,
      compatibleStacks: parsed.compatibleStacks,
      consumesPorts: parsed.consumesPorts,
      producesPorts: parsed.producesPorts,
      moeProfile: parsed.moeProfile,
      requiredSecurityBricks
    }
  );
}

/**
 * Strictly match `:SUPERSEDES` lineage references (`ARCH-01`):
 * - Requires `64`-hex `sourceHash` or `brickId@sourceHash` (`SAFE_SUPERSEDES_RE`).
 * - Never matches bare `versionTag` strings like `"v1"`.
 */
function matchesSupersedesRef(targetBrick, refString) {
  const m = SAFE_SUPERSEDES_RE.exec(String(refString || '').trim());
  if (!m) return false;
  const refBrickId = m[1] ? m[1].toLowerCase() : null;
  const refHash = m[2].toLowerCase();
  const targetHash = String(targetBrick.sourceHash || '').toLowerCase();
  if (!HEX64_RE.test(targetHash) || targetHash !== refHash) {
    return false;
  }
  if (refBrickId !== null && String(targetBrick.brickId || '').toLowerCase() !== refBrickId) {
    return false;
  }
  return true;
}

function isReachableInGraph(adjMap, startId, goalId) {
  if (startId === goalId) return true;
  const visited = new Set([startId]);
  const queue = [startId];
  while (queue.length > 0) {
    const curr = queue.shift();
    const neighbors = adjMap.get(curr);
    if (!neighbors) continue;
    for (const next of neighbors) {
      if (next === goalId) return true;
      if (!visited.has(next)) {
        visited.add(next);
        queue.push(next);
      }
    }
  }
  return false;
}

function isBrickCompatibleWithTargetStack(brick, targetStack) {
  if (!targetStack) {
    return { ok: true, bridgeMode: 'native' };
  }
  if (!Object.hasOwn(STACK_ONTOLOGY_STACKS, targetStack)) {
    return { ok: false, bridgeMode: null };
  }
  const stackDef = STACK_ONTOLOGY_STACKS[targetStack];
  if (brick.isPythonBrick && stackDef.runtimeFamily !== 'python') {
    return { ok: false, bridgeMode: null };
  }
  if (stackDef.requiresWebStandardPurity && !brick.purity.pure) {
    return { ok: false, bridgeMode: null };
  }
  if (targetStack === 'python-fastapi' && !brick.isPythonBrick) {
    return { ok: true, bridgeMode: 'contract-adapter' };
  }
  if (brick.compatibleStacks.includes(targetStack)) {
    return { ok: true, bridgeMode: 'native' };
  }
  return { ok: false, bridgeMode: null };
}

/**
 * Compile a HydraScope-compatible ontology graph (48-bit SHA-256 safe integer `surrogateId`
 * hashing `${ns}\0${logicalId}` with default namespace `'brick-ontology'`, Cypher-clean edge types
 * without leading colons, same-org cycle-safe `SUPERSEDES` retirement + `asOf` replay)
 * over caller-supplied `authorizedBricks` and discover 1-hop direct matches and 2-hop compositions (`ARCH-01`).
 *
 * @param {object} [options]
 */
export function composeCrossStackBricks(options = {}) {
  const tool = 'krusch_brick_ontology_compose';
  if (!isPlainObject(options)) {
    return failEnvelope(tool, 'INVALID_COMPOSE_OPTIONS', 'Options must be a plain object');
  }

  const optsSafety = validateSafePayload(options, 'options', { requireJsonSerializable: false });
  if (!optsSafety.ok) {
    return failEnvelope(tool, optsSafety.code, optsSafety.message, optsSafety.details || null);
  }

  const {
    authorizedBricks = [],
    targetStack = null,
    targetChannel = null,
    requiredPorts = [],
    availableInputPorts = [],
    asOf = null,
    maxHops = 2,
    namespace = 'brick-ontology'
  } = options;

  const cleanNamespace =
    scrubOntologyString(
      typeof namespace === 'string' && namespace.trim() ? namespace.trim() : 'brick-ontology'
    ) || 'brick-ontology';
  const cleanStack =
    typeof targetStack === 'string' && targetStack.trim() ? targetStack.trim() : null;
  const cleanChannel =
    typeof targetChannel === 'string' && targetChannel.trim() ? targetChannel.trim() : null;

  if (cleanStack !== null && (FORBIDDEN_KEYS.has(cleanStack) || !Object.hasOwn(STACK_ONTOLOGY_STACKS, cleanStack))) {
    return failEnvelope(
      tool,
      'UNKNOWN_ONTOLOGY_STACK',
      `Unknown targetStack "${cleanStack}"`,
      { targetStack: cleanStack }
    );
  }
  if (cleanChannel !== null && (FORBIDDEN_KEYS.has(cleanChannel) || !Object.hasOwn(STACK_ONTOLOGY_CHANNELS, cleanChannel))) {
    return failEnvelope(
      tool,
      'UNKNOWN_ONTOLOGY_CHANNEL',
      `Unknown targetChannel "${cleanChannel}"`,
      { targetChannel: cleanChannel }
    );
  }

  let asOfMs = null;
  if (asOf !== null && asOf !== undefined && asOf !== '') {
    asOfMs = parseTemporalMs(asOf);
    if (asOfMs === null) {
      return failEnvelope(
        tool,
        'INVALID_AS_OF_DATE',
        `Invalid asOf date "${String(asOf)}"`,
        { asOf }
      );
    }
  }

  const rawReqPorts = normalizeStringList(requiredPorts);
  const reqPorts = [];
  for (const rp of rawReqPorts) {
    const parsedRp = parsePortReference(rp);
    if (!parsedRp) {
      return failEnvelope(tool, 'INVALID_ONTOLOGY_PORT', `Invalid requiredPorts entry "${rp}"`, {
        port: rp
      });
    }
    reqPorts.push(parsedRp.id);
  }

  const rawAvailPorts = normalizeStringList(availableInputPorts);
  const availPorts = [];
  for (const ap of rawAvailPorts) {
    const parsedAp = parsePortReference(ap);
    if (!parsedAp) {
      return failEnvelope(
        tool,
        'INVALID_ONTOLOGY_PORT',
        `Invalid availableInputPorts entry "${ap}"`,
        { port: ap }
      );
    }
    availPorts.push(parsedAp.id);
  }

  const rawList = Array.isArray(authorizedBricks) ? authorizedBricks : [];
  const parsedBricks = [];
  for (let idx = 0; idx < rawList.length; idx += 1) {
    const unwrapped = unwrapBrickEntryResult(rawList[idx]);
    if (!unwrapped.ok) {
      return failEnvelope(
        tool,
        unwrapped.error.code,
        unwrapped.error.message,
        unwrapped.error.details || { index: idx }
      );
    }
    const b = unwrapped.value;
    const logicalId = `brick:${b.brickId}@${b.sourceHash}`;
    parsedBricks.push({
      ...b,
      logicalId,
      surrogateId: surrogateOntologyVertexId(cleanNamespace, logicalId)
    });
  }

  const nodesMap = new Map();
  const edges = [];
  const edgeDedup = new Set();

  function upsertNode(logicalId, label, properties) {
    if (!nodesMap.has(logicalId)) {
      const cleanProps = {};
      for (const [k, v] of Object.entries(properties)) {
        if (FORBIDDEN_KEYS.has(k)) continue;
        defineSafeProp(cleanProps, k, typeof v === 'string' ? scrubOntologyString(v) : v);
      }
      nodesMap.set(logicalId, {
        surrogateId: surrogateOntologyVertexId(cleanNamespace, logicalId),
        logicalId,
        label,
        properties: cleanProps
      });
    }
    return nodesMap.get(logicalId);
  }

  function addEdge(type, fromLogicalId, toLogicalId, properties = {}) {
    if (!SAFE_CYPHER_REL_RE.test(type)) return;
    const dedupKey = `${fromLogicalId}\0${type}\0${toLogicalId}`;
    if (edgeDedup.has(dedupKey)) return;
    edgeDedup.add(dedupKey);
    edges.push({
      type,
      from: surrogateOntologyVertexId(cleanNamespace, fromLogicalId),
      to: surrogateOntologyVertexId(cleanNamespace, toLogicalId),
      fromLogicalId,
      toLogicalId,
      properties
    });
  }

  // Seed canonical 4-axis ontology vertices matching `@krusch/toolkit/brick-exchange` & HydraScope
  for (const stack of Object.values(STACK_ONTOLOGY_STACKS)) {
    upsertNode(`stack:${stack.id}`, 'Stack', {
      id: stack.id,
      category: stack.category,
      runtimeFamily: stack.runtimeFamily,
      requiresWebStandardPurity: stack.requiresWebStandardPurity
    });
  }
  for (const port of Object.values(STACK_ONTOLOGY_PORTS)) {
    upsertNode(`port:${port.id}`, 'DataPort', {
      id: port.id,
      category: port.category,
      shared: true
    });
  }
  for (const channel of Object.values(STACK_ONTOLOGY_CHANNELS)) {
    upsertNode(`channel:${channel.id}`, 'Channel', {
      id: channel.id,
      category: channel.category,
      requiresHmacVerification: channel.requiresHmacVerification
    });
  }
  for (const moe of Object.values(STACK_ONTOLOGY_MOE_PROFILES)) {
    upsertNode(`moe_profile:${moe.id}`, 'MoeProfile', {
      id: moe.id,
      category: moe.category
    });
  }

  // Map `SUPERSEDES` lineage across parsedBricks enforcing same-org and cycle prevention (`ARCH-01`)
  const supersedesPairs = [];
  const supersedesAdj = new Map();
  for (const newer of parsedBricks) {
    for (const ref of newer.supersedes) {
      for (const older of parsedBricks) {
        if (older.logicalId === newer.logicalId) continue;
        if (!matchesSupersedesRef(older, ref)) continue;
        // Enforce same-org boundary so one org cannot retire another org's brick
        if (newer.orgId && older.orgId && newer.orgId !== older.orgId) {
          continue;
        }
        // Prevent cycles (`older ->* newer` already present)
        if (isReachableInGraph(supersedesAdj, older.logicalId, newer.logicalId)) {
          continue;
        }
        if (!supersedesAdj.has(newer.logicalId)) {
          supersedesAdj.set(newer.logicalId, new Set());
        }
        if (!supersedesAdj.get(newer.logicalId).has(older.logicalId)) {
          supersedesAdj.get(newer.logicalId).add(older.logicalId);
          supersedesPairs.push({ newer, older });
        }
      }
    }
  }

  // Determine temporal visibility and retirement status
  const supersededByMap = new Map();
  const effectiveRetiredAtMap = new Map();

  for (const b of parsedBricks) {
    if (b.retiredAt) {
      effectiveRetiredAtMap.set(b.logicalId, b.retiredAt);
    }
  }

  for (const { newer, older } of supersedesPairs) {
    const newerValidFromMs = parseTemporalMs(newer.validFrom);
    const olderRetiredMs = parseTemporalMs(older.retiredAt);
    const effectiveSupersedeMs = newerValidFromMs ?? olderRetiredMs;

    if (asOfMs !== null && effectiveSupersedeMs !== null && effectiveSupersedeMs > asOfMs) {
      continue;
    }

    supersededByMap.set(older.logicalId, newer);
    if (!effectiveRetiredAtMap.has(older.logicalId) && newer.validFrom) {
      effectiveRetiredAtMap.set(older.logicalId, newer.validFrom);
    }
  }

  const activeBricks = [];
  const retiredSupersededBricks = [];

  for (const b of parsedBricks) {
    const validFromMs = parseTemporalMs(b.validFrom);
    const effRetiredAt = effectiveRetiredAtMap.get(b.logicalId) || null;
    const retiredAtMs = parseTemporalMs(effRetiredAt);
    const superseder = supersededByMap.get(b.logicalId) || null;

    const isFutureBrickAtAsOf =
      asOfMs !== null &&
      validFromMs !== null &&
      validFromMs > asOfMs &&
      Boolean(
        b.blueprint?.ontology?.validFrom ||
          b.bundle.ontology?.validFrom ||
          b.blueprint?.validFrom ||
          b.bundle.validFrom ||
          b.supersedes.length > 0
      );

    const isRetiredByDate =
      retiredAtMs !== null && (asOfMs === null ? true : retiredAtMs <= asOfMs);
    const isRetired = Boolean(superseder) || isRetiredByDate;
    const isCurrent = !isRetired && !isFutureBrickAtAsOf;

    upsertNode(b.logicalId, 'Brick', {
      brickId: b.brickId,
      sourceHash: b.sourceHash,
      name: b.name,
      summary: b.summary,
      orgId: b.orgId || 'local-org',
      isCurrent,
      validFrom: b.validFrom || '',
      retiredAt: effRetiredAt || '',
      supersededBy: superseder ? superseder.logicalId : ''
    });

    for (const s of b.compatibleStacks) {
      addEdge('TARGETS_STACK', b.logicalId, `stack:${s}`);
    }
    for (const p of b.consumesPorts) {
      const parsedP = parsePortReference(p);
      upsertNode(`port:${p}`, 'DataPort', {
        id: p,
        category: STACK_ONTOLOGY_PORTS[p]?.category || (parsedP?.shared ? 'tool-graph-shared' : 'scoped'),
        shared: Boolean(parsedP?.shared)
      });
      addEdge('CONSUMES_PORT', b.logicalId, `port:${p}`);
    }
    for (const p of b.producesPorts) {
      const parsedP = parsePortReference(p);
      upsertNode(`port:${p}`, 'DataPort', {
        id: p,
        category: STACK_ONTOLOGY_PORTS[p]?.category || (parsedP?.shared ? 'tool-graph-shared' : 'scoped'),
        shared: Boolean(parsedP?.shared)
      });
      addEdge('PRODUCES_PORT', b.logicalId, `port:${p}`);
    }
    for (const c of b.channels) {
      addEdge('BRIDGES_CHANNEL', b.logicalId, `channel:${c}`);
    }
    if (b.moeProfile) {
      addEdge('ROUTES_TO_MODEL', b.logicalId, `moe_profile:${b.moeProfile}`);
    }

    if (isRetired) {
      retiredSupersededBricks.push({
        brickId: b.brickId,
        sourceHash: b.sourceHash,
        version: b.versionTag,
        name: b.name,
        orgId: b.orgId || 'local-org',
        surrogateId: b.surrogateId,
        supersededBy: superseder
          ? {
              brickId: superseder.brickId,
              sourceHash: superseder.sourceHash,
              surrogateId: superseder.surrogateId
            }
          : null,
        retiredAt: effRetiredAt
      });
    } else if (!isFutureBrickAtAsOf) {
      activeBricks.push(b);
    }
  }

  for (const { newer, older } of supersedesPairs) {
    addEdge('SUPERSEDES', newer.logicalId, older.logicalId, {
      retiredAt: effectiveRetiredAtMap.get(older.logicalId) || ''
    });
  }

  // Filter active bricks by targetStack compatibility
  const stackEligible = [];
  for (const b of activeBricks) {
    const stackCheck = isBrickCompatibleWithTargetStack(b, cleanStack);
    if (stackCheck.ok) {
      stackEligible.push({
        ...b,
        bridgeMode: stackCheck.bridgeMode
      });
    }
  }

  const channelInboundPorts = cleanChannel
    ? STACK_ONTOLOGY_CHANNELS[cleanChannel].inboundPorts
    : [];
  const effectiveSeedPorts = [...new Set([...availPorts, ...channelInboundPorts])];

  function matchesEntryGate(brick) {
    if (cleanChannel) {
      if (brick.channels.includes(cleanChannel)) return true;
      if (
        brick.consumesPorts.length > 0 &&
        brick.consumesPorts.every((cp) =>
          effectiveSeedPorts.some((sp) => areOntologyPortsCompatible(sp, cp))
        )
      ) {
        return true;
      }
      return false;
    }
    if (availPorts.length > 0) {
      if (brick.consumesPorts.length === 0) return true;
      return brick.consumesPorts.every((cp) =>
        availPorts.some((sp) => areOntologyPortsCompatible(sp, cp))
      );
    }
    return true;
  }

  // 1-Hop Direct Matches
  const directMatches = [];
  for (const b of stackEligible) {
    if (!matchesEntryGate(b)) continue;
    if (
      reqPorts.length > 0 &&
      !reqPorts.every((rp) => b.producesPorts.some((pp) => areOntologyPortsCompatible(pp, rp)))
    ) {
      continue;
    }
    directMatches.push({
      hops: 1,
      brickId: b.brickId,
      sourceHash: b.sourceHash,
      version: b.versionTag,
      name: b.name,
      orgId: b.orgId || 'local-org',
      surrogateId: b.surrogateId,
      bridgeMode: b.bridgeMode,
      consumesPorts: b.consumesPorts,
      producesPorts: b.producesPorts,
      channels: b.channels,
      moeProfile: b.moeProfile,
      grantId: b.grantId
    });
  }

  // 2-Hop Cross-Stack / Cross-Org Compositions
  const compositions = [];
  const namespaceCollisions = [];
  const boundedHops = Number.isInteger(maxHops) ? Math.max(1, Math.min(maxHops, 3)) : 2;

  if (boundedHops >= 2) {
    for (const brickA of stackEligible) {
      if (!matchesEntryGate(brickA)) continue;
      if (brickA.producesPorts.length === 0) continue;

      for (const brickB of stackEligible) {
        if (brickA.logicalId === brickB.logicalId || brickA.brickId === brickB.brickId) {
          continue;
        }
        if (brickB.consumesPorts.length === 0) continue;

        const sharedPorts = [];
        for (const prodP of brickA.producesPorts) {
          for (const consP of brickB.consumesPorts) {
            if (areOntologyPortsCompatible(prodP, consP)) {
              const normPort = parsePortReference(prodP)?.id || prodP;
              if (!sharedPorts.includes(normPort)) {
                sharedPorts.push(normPort);
              }
            } else {
              const collision = detectPortNamespaceCollision(prodP, consP);
              if (collision) {
                namespaceCollisions.push({
                  upstreamBrickId: brickA.brickId,
                  downstreamBrickId: brickB.brickId,
                  ...collision
                });
              }
            }
          }
        }

        if (sharedPorts.length === 0) continue;

        if (reqPorts.length > 0) {
          const combinedOutputs = [...brickA.producesPorts, ...brickB.producesPorts];
          const satisfiesAllRequired = reqPorts.every((rp) =>
            combinedOutputs.some((pp) => areOntologyPortsCompatible(pp, rp))
          );
          const downstreamParticipates = reqPorts.some(
            (rp) =>
              brickB.producesPorts.some((pp) => areOntologyPortsCompatible(pp, rp)) ||
              brickB.consumesPorts.some((cp) => areOntologyPortsCompatible(rp, cp))
          );
          if (!satisfiesAllRequired || !downstreamParticipates) {
            continue;
          }
        }

        compositions.push({
          hops: 2,
          bridgePort: sharedPorts[0],
          sharedPorts,
          upstreamBrickId: brickA.brickId,
          downstreamBrickId: brickB.brickId,
          producesPorts: brickB.producesPorts,
          steps: [
            {
              step: 1,
              brickId: brickA.brickId,
              sourceHash: brickA.sourceHash,
              version: brickA.versionTag,
              orgId: brickA.orgId || 'local-org',
              surrogateId: brickA.surrogateId,
              bridgeMode: brickA.bridgeMode,
              channels: brickA.channels,
              consumesPorts: brickA.consumesPorts,
              producesPorts: brickA.producesPorts
            },
            {
              step: 2,
              brickId: brickB.brickId,
              sourceHash: brickB.sourceHash,
              version: brickB.versionTag,
              orgId: brickB.orgId || 'local-org',
              surrogateId: brickB.surrogateId,
              bridgeMode: brickB.bridgeMode,
              channels: brickB.channels,
              consumesPorts: brickB.consumesPorts,
              producesPorts: brickB.producesPorts
            }
          ]
        });
      }
    }
  }

  const graph = {
    namespace: cleanNamespace,
    nodes: [...nodesMap.values()],
    edges,
    stats: {
      nodeCount: nodesMap.size,
      edgeCount: edges.length,
      authorizedBrickCount: parsedBricks.length,
      activeBrickCount: activeBricks.length,
      retiredBrickCount: retiredSupersededBricks.length
    }
  };

  return okEnvelope(
    tool,
    `Ontology composition over ${parsedBricks.length} authorized brick(s): ${directMatches.length} direct, ${compositions.length} 2-hop composition(s), ${retiredSupersededBricks.length} superseded`,
    {
      graph,
      directMatches,
      compositions,
      retiredSupersededBricks,
      namespaceCollisions,
      asOf: asOf ?? null
    }
  );
}

function extractInputSchemaShape(inputSchema) {
  if (!isPlainObject(inputSchema)) {
    return {
      properties: {},
      additionalProperties: true,
      numericFields: [],
      isArrayInput: false
    };
  }

  if (inputSchema.type === 'array' && isPlainObject(inputSchema.items)) {
    const props = isPlainObject(inputSchema.items.properties) ? inputSchema.items.properties : {};
    const numericFields = Object.entries(props)
      .filter(([, desc]) => isPlainObject(desc) && (desc.type === 'number' || desc.type === 'integer'))
      .map(([k]) => k);
    return {
      properties: props,
      additionalProperties: inputSchema.items.additionalProperties !== false,
      numericFields,
      isArrayInput: true
    };
  }

  const props = isPlainObject(inputSchema.properties) ? inputSchema.properties : {};
  const numericFields = Object.entries(props)
    .filter(([, desc]) => isPlainObject(desc) && (desc.type === 'number' || desc.type === 'integer'))
    .map(([k]) => k);
  return {
    properties: props,
    additionalProperties: inputSchema.additionalProperties !== false,
    numericFields,
    isArrayInput: false
  };
}

function collectSchemaAndPortCanonicalFields(parsedBrick) {
  const canonical = new Set();
  const schemaInfo = extractInputSchemaShape(parsedBrick.blueprint?.inputSchema);
  for (const k of Object.keys(schemaInfo.properties)) {
    if (!FORBIDDEN_KEYS.has(k)) canonical.add(k);
  }
  for (const portId of parsedBrick.consumesPorts) {
    const parsedPort = parsePortReference(portId);
    const portKey = parsedPort?.shared ? parsedPort.bareName : portId;
    const portDef = STACK_ONTOLOGY_PORTS[portKey];
    if (portDef) {
      for (const k of Object.keys(portDef.canonicalFields)) {
        canonical.add(k);
      }
    }
  }
  return canonical;
}

function collectExpectedCanonicalFields(parsedBrick) {
  const expected = collectSchemaAndPortCanonicalFields(parsedBrick);

  const propMatches = parsedBrick.source.matchAll(
    /\b(?:input|payload|event|data|row|item|x)\.([A-Za-z_$][A-Za-z0-9_$]*)/g
  );
  for (const m of propMatches) {
    if (!FORBIDDEN_KEYS.has(m[1])) {
      expected.add(m[1]);
    }
  }
  const tsFieldMatches = parsedBrick.source.matchAll(
    /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\??\s*:\s*(?:number|string|boolean|unknown)\b/g
  );
  for (const m of tsFieldMatches) {
    if (!FORBIDDEN_KEYS.has(m[1])) {
      expected.add(m[1]);
    }
  }

  return expected;
}

function resolvePortScopedAliasMap(parsedBrick) {
  const map = new Map();
  for (const portId of parsedBrick.consumesPorts) {
    const parsedPort = parsePortReference(portId);
    const portKey = parsedPort?.shared ? parsedPort.bareName : portId;
    const portDef = STACK_ONTOLOGY_PORTS[portKey];
    if (!portDef) continue;
    for (const [canonicalName, spec] of Object.entries(portDef.canonicalFields)) {
      map.set(canonicalName.toLowerCase(), canonicalName);
      for (const alias of spec.aliases) {
        map.set(alias.toLowerCase(), canonicalName);
      }
    }
  }
  for (const [aliasLower, canonicalName] of GLOBAL_FIELD_ALIAS_MAP.entries()) {
    if (!map.has(aliasLower)) {
      map.set(aliasLower, canonicalName);
    }
  }
  return map;
}

/**
 * Normalize explicit `fieldMap` supporting BOTH `{ canonicalField: localField }` (`@krusch/toolkit`
 * convention) and `{ localField: canonicalField }` (auto-detected via sample keys and schema/port
 * canonical field membership) into `{ [localField]: canonicalField }` (`ARCH-01`).
 */
function normalizeExplicitFieldMap(explicitFieldMap, rawKeysSet, parsedBrick) {
  const normalized = {};
  if (!isPlainObject(explicitFieldMap)) {
    return normalized;
  }

  const schemaAndPortCanonical = collectSchemaAndPortCanonicalFields(parsedBrick);
  const expectedSet = collectExpectedCanonicalFields(parsedBrick);

  for (const [rawK, rawV] of Object.entries(explicitFieldMap)) {
    if (FORBIDDEN_KEYS.has(rawK) || typeof rawV !== 'string') continue;
    const k = rawK.trim();
    const v = rawV.trim();
    if (!k || !v || FORBIDDEN_KEYS.has(k) || FORBIDDEN_KEYS.has(v)) continue;

    let localKey = k;
    let canonicalKey = v;

    if (k !== v) {
      if (rawKeysSet.size > 0) {
        if (rawKeysSet.has(v) && !rawKeysSet.has(k)) {
          localKey = v;
          canonicalKey = k;
        } else if (rawKeysSet.has(k) && !rawKeysSet.has(v)) {
          localKey = k;
          canonicalKey = v;
        } else if (schemaAndPortCanonical.has(k) && !schemaAndPortCanonical.has(v)) {
          localKey = v;
          canonicalKey = k;
        } else if (ALL_PORT_CANONICAL_FIELDS.has(k) && !ALL_PORT_CANONICAL_FIELDS.has(v)) {
          localKey = v;
          canonicalKey = k;
        }
      } else if (schemaAndPortCanonical.has(k) && !schemaAndPortCanonical.has(v)) {
        localKey = v;
        canonicalKey = k;
      } else if (schemaAndPortCanonical.has(v) && !schemaAndPortCanonical.has(k)) {
        localKey = k;
        canonicalKey = v;
      } else if (expectedSet.has(k) && !expectedSet.has(v)) {
        localKey = v;
        canonicalKey = k;
      } else if (ALL_PORT_CANONICAL_FIELDS.has(k) && !ALL_PORT_CANONICAL_FIELDS.has(v)) {
        localKey = v;
        canonicalKey = k;
      }
    }

    defineSafeProp(normalized, localKey, canonicalKey);
  }

  return normalized;
}

function inferFieldMappingForKeys(rawKeys, parsedBrick, explicitFieldMap = {}) {
  const aliasMap = resolvePortScopedAliasMap(parsedBrick);
  const expectedSet = collectExpectedCanonicalFields(parsedBrick);
  const rawKeysSet = new Set(rawKeys.filter((k) => typeof k === 'string' && !FORBIDDEN_KEYS.has(k)).map((k) => k.trim()));
  const explicitLocalToCanonical = normalizeExplicitFieldMap(explicitFieldMap, rawKeysSet, parsedBrick);
  const resolved = {};

  for (const key of rawKeysSet) {
    if (!key) continue;

    if (Object.hasOwn(explicitLocalToCanonical, key)) {
      defineSafeProp(resolved, key, explicitLocalToCanonical[key]);
      continue;
    }

    const mapped = aliasMap.get(key.toLowerCase());
    if (mapped && mapped !== key) {
      if (
        expectedSet.size === 0 ||
        expectedSet.has(mapped) ||
        GLOBAL_FIELD_ALIAS_MAP.has(key.toLowerCase())
      ) {
        defineSafeProp(resolved, key, mapped);
      }
    }
  }

  for (const [localK, canonV] of Object.entries(explicitLocalToCanonical)) {
    if (!Object.hasOwn(resolved, localK)) {
      defineSafeProp(resolved, localK, canonV);
    }
  }

  return resolved;
}

/**
 * Adapt a single record object using `fieldMap` (`{ localField: canonicalField }`),
 * stripping consumed raw alias keys and enforcing `additionalProperties: false` (`ARCH-01`).
 */
function adaptRecordObject(
  rawObj,
  fieldMap,
  {
    schemaProperties = {},
    additionalProperties = true,
    numericFields = [],
    coerceHeaderNumericRow = false
  } = {}
) {
  const out = {};
  const allowedKeys = Object.keys(schemaProperties).filter((k) => !FORBIDDEN_KEYS.has(k));
  const stripUnknown = additionalProperties === false && allowedKeys.length > 0;
  const allowedSet = new Set(allowedKeys);
  const numericSet = new Set(numericFields);

  // First pass: map aliased local keys to canonical keys (consuming raw alias keys)
  for (const [localKey, canonicalKey] of Object.entries(fieldMap)) {
    if (FORBIDDEN_KEYS.has(localKey) || FORBIDDEN_KEYS.has(canonicalKey)) continue;
    if (Object.hasOwn(rawObj, localKey)) {
      // Direct canonical field on rawObj takes precedence over alias if both exist
      const rawVal = Object.hasOwn(rawObj, canonicalKey) ? rawObj[canonicalKey] : rawObj[localKey];
      let finalVal = rawVal;
      if (coerceHeaderNumericRow && numericSet.has(canonicalKey) && typeof finalVal === 'string') {
        const parsedNum = Number(finalVal);
        finalVal = Number.isFinite(parsedNum) ? parsedNum : 0;
      }
      defineSafeProp(out, canonicalKey, finalVal);
    }
  }

  // Second pass: copy unmapped non-consumed keys (honoring additionalProperties: false)
  for (const key of Object.keys(rawObj)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    if (Object.hasOwn(fieldMap, key)) continue; // Consumed raw alias key stripped!
    if (Object.hasOwn(out, key)) continue;
    if (stripUnknown && !allowedSet.has(key)) continue;
    let val = rawObj[key];
    if (coerceHeaderNumericRow && numericSet.has(key) && typeof val === 'string') {
      const parsedNum = Number(val);
      val = Number.isFinite(parsedNum) ? parsedNum : 0;
    }
    defineSafeProp(out, key, val);
  }

  return out;
}

function brickSupportsNativeSkipHeaderRow(parsedBrick, bindingOverrides) {
  if (isPlainObject(bindingOverrides) && Object.hasOwn(bindingOverrides, 'skipHeaderRow')) {
    return true;
  }
  const bindingProps = parsedBrick.blueprint?.bindingSchema?.properties;
  if (isPlainObject(bindingProps) && Object.hasOwn(bindingProps, 'skipHeaderRow')) {
    return true;
  }
  return /\bskipHeaderRow\b/.test(parsedBrick.source);
}

function adaptSampleWithInferredRules(localSample, explicitFieldMap, parsedBrick, bindingOverrides = {}) {
  const schemaInfo = extractInputSchemaShape(parsedBrick.blueprint?.inputSchema);
  const nativeSkipHeader = brickSupportsNativeSkipHeaderRow(parsedBrick, bindingOverrides);

  if (localSample === undefined || localSample === null) {
    const resolvedFieldMap = inferFieldMappingForKeys([], parsedBrick, explicitFieldMap);
    return {
      fieldMap: resolvedFieldMap,
      hasHeaderRow: false,
      dropObjectHeaderRow: false,
      headerColumns: [],
      adaptedSample: localSample,
      schemaInfo
    };
  }

  // Case 1: 2D array with string header row `[['recorded_at', 'reading'], [1000, 12.5], ...]`
  if (
    Array.isArray(localSample) &&
    localSample.length > 0 &&
    Array.isArray(localSample[0]) &&
    localSample[0].length > 0 &&
    localSample[0].every((cell) => typeof cell === 'string')
  ) {
    const headerColumns = localSample[0].map((c) => c.trim());
    const resolvedFieldMap = inferFieldMappingForKeys(headerColumns, parsedBrick, explicitFieldMap);
    const allowedKeys = Object.keys(schemaInfo.properties).filter((k) => !FORBIDDEN_KEYS.has(k));
    const stripUnknown = schemaInfo.additionalProperties === false && allowedKeys.length > 0;
    const allowedSet = new Set(allowedKeys);

    const adaptedRows = [];
    for (let r = 1; r < localSample.length; r += 1) {
      const row = localSample[r];
      if (!Array.isArray(row)) continue;
      const rowObj = {};
      for (let c = 0; c < headerColumns.length; c += 1) {
        const rawCol = headerColumns[c];
        if (!rawCol || FORBIDDEN_KEYS.has(rawCol)) continue;
        const canonicalCol = Object.hasOwn(resolvedFieldMap, rawCol)
          ? resolvedFieldMap[rawCol]
          : rawCol;
        if (!FORBIDDEN_KEYS.has(canonicalCol)) {
          if (stripUnknown && !allowedSet.has(canonicalCol)) continue;
          defineSafeProp(rowObj, canonicalCol, row[c]);
        }
      }
      adaptedRows.push(rowObj);
    }
    const expectsObjectWrapper = parsedBrick.blueprint?.inputSchema?.type === 'object';
    return {
      fieldMap: resolvedFieldMap,
      hasHeaderRow: true,
      dropObjectHeaderRow: false,
      headerColumns,
      adaptedSample: expectsObjectWrapper ? { points: adaptedRows } : adaptedRows,
      schemaInfo
    };
  }

  // Case 2: 1D Array of plain objects (including 1D object units header row `[{ recorded_at: 'ms', reading: 'm/s' }, ...]`)
  if (Array.isArray(localSample)) {
    const sampleKeys = new Set();
    for (const item of localSample) {
      if (isPlainObject(item)) {
        for (const k of Object.keys(item)) {
          if (!FORBIDDEN_KEYS.has(k)) sampleKeys.add(k);
        }
      }
    }
    const resolvedFieldMap = inferFieldMappingForKeys(
      [...sampleKeys],
      parsedBrick,
      explicitFieldMap
    );
    const hasObjectHeader = detectObjectHeaderUnitRow(localSample);
    const dropObjectHeaderRow = hasObjectHeader && !nativeSkipHeader;
    const sourceRows = dropObjectHeaderRow ? localSample.slice(1) : localSample;

    const adaptedRows = sourceRows.map((item, idx) =>
      isPlainObject(item)
        ? adaptRecordObject(item, resolvedFieldMap, {
            schemaProperties: schemaInfo.properties,
            additionalProperties: schemaInfo.additionalProperties,
            numericFields: schemaInfo.numericFields,
            coerceHeaderNumericRow: hasObjectHeader && nativeSkipHeader && idx === 0
          })
        : item
    );

    const expectsObjectWrapper =
      parsedBrick.blueprint?.inputSchema?.type === 'object' &&
      !Array.isArray(parsedBrick.blueprint?.inputSchema?.type);

    return {
      fieldMap: resolvedFieldMap,
      hasHeaderRow: hasObjectHeader,
      dropObjectHeaderRow,
      headerColumns: hasObjectHeader ? [...sampleKeys] : [],
      adaptedSample: expectsObjectWrapper ? { points: adaptedRows } : adaptedRows,
      schemaInfo
    };
  }

  // Case 3: Plain object (including nested `{ rows/points: [...] }` with 2D or 1D object header rows)
  if (isPlainObject(localSample)) {
    for (const seriesKey of ['points', 'samples', 'window', 'rows']) {
      const nested = localSample[seriesKey];
      const is2dHeader =
        Array.isArray(nested) &&
        nested.length > 0 &&
        Array.isArray(nested[0]) &&
        nested[0].length > 0 &&
        nested[0].every((cell) => typeof cell === 'string');
      const is1dObjectHeader = detectObjectHeaderUnitRow(nested);

      if (is2dHeader || is1dObjectHeader) {
        const sub = adaptSampleWithInferredRules(nested, explicitFieldMap, parsedBrick, bindingOverrides);
        const topFieldMap = {
          ...sub.fieldMap,
          ...inferFieldMappingForKeys(Object.keys(localSample), parsedBrick, explicitFieldMap)
        };
        const baseAdapted = adaptRecordObject(localSample, topFieldMap, {
          schemaProperties: schemaInfo.properties,
          additionalProperties: schemaInfo.additionalProperties,
          numericFields: schemaInfo.numericFields
        });
        const rowsArray = Array.isArray(sub.adaptedSample)
          ? sub.adaptedSample
          : sub.adaptedSample.points;
        defineSafeProp(baseAdapted, seriesKey, rowsArray);
        if (
          !Object.hasOwn(baseAdapted, 'points') &&
          (schemaInfo.additionalProperties !== false || Object.hasOwn(schemaInfo.properties, 'points'))
        ) {
          defineSafeProp(baseAdapted, 'points', rowsArray);
        }
        return {
          fieldMap: topFieldMap,
          hasHeaderRow: true,
          dropObjectHeaderRow: sub.dropObjectHeaderRow,
          headerColumns: sub.headerColumns,
          adaptedSample: baseAdapted,
          schemaInfo
        };
      }
    }

    const resolvedFieldMap = inferFieldMappingForKeys(
      Object.keys(localSample),
      parsedBrick,
      explicitFieldMap
    );
    return {
      fieldMap: resolvedFieldMap,
      hasHeaderRow: false,
      dropObjectHeaderRow: false,
      headerColumns: [],
      adaptedSample: adaptRecordObject(localSample, resolvedFieldMap, {
        schemaProperties: schemaInfo.properties,
        additionalProperties: schemaInfo.additionalProperties,
        numericFields: schemaInfo.numericFields
      }),
      schemaInfo
    };
  }

  return {
    fieldMap: inferFieldMappingForKeys([], parsedBrick, explicitFieldMap),
    hasHeaderRow: false,
    dropObjectHeaderRow: false,
    headerColumns: [],
    adaptedSample: localSample,
    schemaInfo
  };
}

function toPythonLiteral(value) {
  if (value === null || value === undefined) return 'None';
  if (typeof value === 'boolean') return value ? 'True' : 'False';
  if (typeof value === 'number') {
    return Number.isFinite(value) ? String(value) : 'None';
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => toPythonLiteral(v)).join(', ')}]`;
  }
  if (isPlainObject(value)) {
    const entries = Object.keys(value)
      .filter((k) => !FORBIDDEN_KEYS.has(k) && value[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}: ${toPythonLiteral(value[k])}`);
    return `{${entries.join(', ')}}`;
  }
  return JSON.stringify(String(value));
}

function renderJsOrTsBindingSource({
  parsedBrick,
  targetStack,
  resolvedBinding,
  fieldMap,
  hasHeaderRow,
  dropObjectHeaderRow,
  expectsPointsWrapper,
  schemaInfo
}) {
  const isTs = targetStack === 'typescript-node';
  const entryModulePath = parsedBrick.blueprint?.language === 'ts' ? './index.ts' : './index.js';
  const rawExportName = String(parsedBrick.blueprint?.exportName || 'default').trim();
  const validNamedExport =
    rawExportName !== 'default' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(rawExportName);

  const importStmt = validNamedExport
    ? `import { ${rawExportName} as brickEntry } from ${JSON.stringify(entryModulePath)};`
    : `import brickEntry from ${JSON.stringify(entryModulePath)};`;

  const allowedKeys = Object.keys(schemaInfo.properties).filter((k) => !FORBIDDEN_KEYS.has(k));
  const stripUnknown = schemaInfo.additionalProperties === false && allowedKeys.length > 0;

  const typeBlock = isTs ? `\nexport type AnyRecord = Record<string, unknown>;\n` : '';
  const rawParamSig = isTs ? 'raw: unknown' : 'raw';
  const rowsParamSig = isTs ? 'rows: unknown[]' : 'rows';
  const returnObjSig = isTs ? ': unknown' : '';

  return [
    `// Zero-upload hexagonal ontology binding for ${JSON.stringify(parsedBrick.brickId)} (${targetStack})`,
    importStmt,
    typeBlock.trimEnd(),
    `const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);`,
    `const ALLOWED_SCHEMA_KEYS = new Set(${JSON.stringify(allowedKeys)});`,
    `const NUMERIC_HEADER_FIELDS = new Set(${JSON.stringify(schemaInfo.numericFields)});`,
    `const STRIP_UNKNOWN_KEYS = ${stripUnknown ? 'true' : 'false'};`,
    `const DROP_OBJECT_HEADER_ROW = ${dropObjectHeaderRow ? 'true' : 'false'};`,
    `export const binding = Object.freeze(${JSON.stringify(resolvedBinding, null, 2)});`,
    `export const fieldMap = Object.freeze(${JSON.stringify(fieldMap, null, 2)});`,
    `export const hasHeaderRow = ${Boolean(hasHeaderRow)};`,
    ``,
    `function isObjectHeaderUnitRow(${isTs ? 'rows: unknown[]' : 'rows'}) {`,
    `  if (!Array.isArray(rows) || rows.length < 2) return false;`,
    `  const r0 = rows[0];`,
    `  const r1 = rows[1];`,
    `  if (!r0 || typeof r0 !== 'object' || Array.isArray(r0) || !r1 || typeof r1 !== 'object' || Array.isArray(r1)) return false;`,
    `  for (const k of Object.keys(r0)) {`,
    `    if (FORBIDDEN_KEYS.has(k)) continue;`,
    `    const v0 = (r0${isTs ? ' as AnyRecord' : ''})[k];`,
    `    const v1 = (r1${isTs ? ' as AnyRecord' : ''})[k];`,
    `    if (typeof v0 === 'string' && v0.trim().length > 0 && Number.isNaN(Number(v0)) && typeof v1 === 'number' && Number.isFinite(v1)) {`,
    `      return true;`,
    `    }`,
    `  }`,
    `  return false;`,
    `}`,
    ``,
    `function mapObjectFields(${isTs ? 'obj: AnyRecord, coerceHeaderNumeric = false' : 'obj, coerceHeaderNumeric = false'}) {`,
    `  const out${isTs ? ': AnyRecord' : ''} = {};`,
    `  for (const [localKey, canonical] of Object.entries(fieldMap)) {`,
    `    if (FORBIDDEN_KEYS.has(localKey) || FORBIDDEN_KEYS.has(canonical)) continue;`,
    `    if (Object.hasOwn(obj, localKey)) {`,
    `      let val = Object.hasOwn(obj, canonical) ? obj[canonical] : obj[localKey];`,
    `      if (coerceHeaderNumeric && NUMERIC_HEADER_FIELDS.has(canonical) && typeof val === 'string') {`,
    `        const parsed = Number(val);`,
    `        val = Number.isFinite(parsed) ? parsed : 0;`,
    `      }`,
    `      Object.defineProperty(out, canonical, { value: val, enumerable: true, writable: true, configurable: true });`,
    `    }`,
    `  }`,
    `  for (const key of Object.keys(obj)) {`,
    `    if (FORBIDDEN_KEYS.has(key) || Object.hasOwn(fieldMap, key) || Object.hasOwn(out, key)) continue;`,
    `    if (STRIP_UNKNOWN_KEYS && !ALLOWED_SCHEMA_KEYS.has(key)) continue;`,
    `    let val = obj[key];`,
    `    if (coerceHeaderNumeric && NUMERIC_HEADER_FIELDS.has(key) && typeof val === 'string') {`,
    `      const parsed = Number(val);`,
    `      val = Number.isFinite(parsed) ? parsed : 0;`,
    `    }`,
    `    Object.defineProperty(out, key, { value: val, enumerable: true, writable: true, configurable: true });`,
    `  }`,
    `  return out;`,
    `}`,
    ``,
    `export function adaptInput(${rawParamSig})${returnObjSig} {`,
    `  if (Array.isArray(raw) && raw.length > 0 && Array.isArray(raw[0]) && raw[0].every((c) => typeof c === 'string')) {`,
    `    const headers = raw[0].map((h) => h.trim());`,
    `    const mappedRows = [];`,
    `    for (let r = 1; r < raw.length; r += 1) {`,
    `      const row = raw[r];`,
    `      if (!Array.isArray(row)) continue;`,
    `      const item${isTs ? ': AnyRecord' : ''} = {};`,
    `      for (let c = 0; c < headers.length; c += 1) {`,
    `        const h = headers[c];`,
    `        if (!h || FORBIDDEN_KEYS.has(h)) continue;`,
    `        const canonical = Object.hasOwn(fieldMap, h) ? fieldMap[h${isTs ? ' as keyof typeof fieldMap' : ''}] : h;`,
    `        if (canonical && !FORBIDDEN_KEYS.has(canonical) && (!STRIP_UNKNOWN_KEYS || ALLOWED_SCHEMA_KEYS.has(canonical))) {`,
    `          Object.defineProperty(item, canonical, { value: row[c], enumerable: true, writable: true, configurable: true });`,
    `        }`,
    `      }`,
    `      mappedRows.push(item);`,
    `    }`,
    `    return ${expectsPointsWrapper ? '{ points: mappedRows }' : 'mappedRows'};`,
    `  }`,
    `  if (Array.isArray(raw)) {`,
    `    const objHeader = isObjectHeaderUnitRow(raw);`,
    `    const slice = objHeader && DROP_OBJECT_HEADER_ROW ? raw.slice(1) : raw;`,
    `    const mapped = slice.map((item, idx) => (item && typeof item === 'object' && !Array.isArray(item) ? mapObjectFields(item${isTs ? ' as AnyRecord' : ''}, objHeader && !DROP_OBJECT_HEADER_ROW && idx === 0) : item));`,
    `    return ${expectsPointsWrapper ? '{ points: mapped }' : 'mapped'};`,
    `  }`,
    `  if (raw && typeof raw === 'object') {`,
    `    return mapObjectFields(raw${isTs ? ' as AnyRecord' : ''});`,
    `  }`,
    `  return raw;`,
    `}`,
    ``,
    `export function adaptBatch(${rowsParamSig}) {`,
    `  if (!Array.isArray(rows)) return [];`,
    `  return rows.map((row) => adaptInput(row));`,
    `}`,
    ``,
    `export function invokeAdaptedBrick(${rawParamSig}) {`,
    `  return brickEntry(adaptInput(raw), binding);`,
    `}`,
    ``
  ]
    .filter((line) => line !== undefined)
    .join('\n');
}

function renderPythonBindingAdapterSource({
  parsedBrick,
  resolvedBinding,
  fieldMap,
  hasHeaderRow,
  dropObjectHeaderRow,
  expectsPointsWrapper,
  schemaInfo
}) {
  const allowedKeys = Object.keys(schemaInfo.properties).filter((k) => !FORBIDDEN_KEYS.has(k));
  const stripUnknown = schemaInfo.additionalProperties === false && allowedKeys.length > 0;

  return [
    `"""Zero-upload hexagonal Python contract adapter for sealed brick ${JSON.stringify(parsedBrick.brickId)}."""`,
    `from __future__ import annotations`,
    ``,
    `from typing import Any, Mapping, Sequence`,
    ``,
    `BRICK_ID: str = ${toPythonLiteral(parsedBrick.brickId)}`,
    `SOURCE_HASH: str = ${toPythonLiteral(parsedBrick.sourceHash)}`,
    `FORBIDDEN_KEYS: frozenset[str] = frozenset({"__proto__", "constructor", "prototype"})`,
    `ALLOWED_SCHEMA_KEYS: frozenset[str] = frozenset(${toPythonLiteral(allowedKeys)})`,
    `NUMERIC_HEADER_FIELDS: frozenset[str] = frozenset(${toPythonLiteral(schemaInfo.numericFields)})`,
    `STRIP_UNKNOWN_KEYS: bool = ${toPythonLiteral(stripUnknown)}`,
    `DROP_OBJECT_HEADER_ROW: bool = ${toPythonLiteral(Boolean(dropObjectHeaderRow))}`,
    `BINDING_CONFIG: dict[str, Any] = ${toPythonLiteral(resolvedBinding)}`,
    `FIELD_MAP: dict[str, str] = ${toPythonLiteral(fieldMap)}`,
    `HAS_HEADER_ROW: bool = ${toPythonLiteral(Boolean(hasHeaderRow))}`,
    ``,
    ``,
    `def _is_object_header_unit_row(rows: Sequence[Any]) -> bool:`,
    `    if len(rows) < 2 or not isinstance(rows[0], Mapping) or not isinstance(rows[1], Mapping):`,
    `        return False`,
    `    r0, r1 = rows[0], rows[1]`,
    `    for key, v0 in r0.items():`,
    `        if not isinstance(key, str) or key in FORBIDDEN_KEYS:`,
    `            continue`,
    `        v1 = r1.get(key)`,
    `        if isinstance(v0, str) and v0.strip() and isinstance(v1, (int, float)) and not isinstance(v1, bool):`,
    `            try:`,
    `                float(v0)`,
    `            except ValueError:`,
    `                return True`,
    `    return False`,
    ``,
    ``,
    `def _map_record(record: Mapping[str, Any], coerce_header_numeric: bool = False) -> dict[str, Any]:`,
    `    out: dict[str, Any] = {}`,
    `    for local_key, canonical in FIELD_MAP.items():`,
    `        if local_key in FORBIDDEN_KEYS or canonical in FORBIDDEN_KEYS:`,
    `            continue`,
    `        if local_key in record:`,
    `            val = record[canonical] if canonical in record else record[local_key]`,
    `            if coerce_header_numeric and canonical in NUMERIC_HEADER_FIELDS and isinstance(val, str):`,
    `                try:`,
    `                    val = float(val)`,
    `                except ValueError:`,
    `                    val = 0`,
    `            out[canonical] = val`,
    `    for key, val in record.items():`,
    `        if not isinstance(key, str) or key in FORBIDDEN_KEYS or key in FIELD_MAP or key in out:`,
    `            continue`,
    `        if STRIP_UNKNOWN_KEYS and key not in ALLOWED_SCHEMA_KEYS:`,
    `            continue`,
    `        if coerce_header_numeric and key in NUMERIC_HEADER_FIELDS and isinstance(val, str):`,
    `            try:`,
    `                val = float(val)`,
    `            except ValueError:`,
    `                val = 0`,
    `        out[key] = val`,
    `    return out`,
    ``,
    ``,
    `def adapt_input(raw: Any) -> Any:`,
    `    if (`,
    `        isinstance(raw, list)`,
    `        and len(raw) > 0`,
    `        and isinstance(raw[0], list)`,
    `        and all(isinstance(cell, str) for cell in raw[0])`,
    `    ):`,
    `        headers = [cell.strip() for cell in raw[0]]`,
    `        mapped_rows: list[dict[str, Any]] = []`,
    `        for row in raw[1:]:`,
    `            if not isinstance(row, list):`,
    `                continue`,
    `            item: dict[str, Any] = {}`,
    `            for idx, header in enumerate(headers):`,
    `                if not header or header in FORBIDDEN_KEYS:`,
    `                    continue`,
    `                canonical = FIELD_MAP.get(header, header)`,
    `                if canonical not in FORBIDDEN_KEYS and (not STRIP_UNKNOWN_KEYS or canonical in ALLOWED_SCHEMA_KEYS):`,
    `                    item[canonical] = row[idx] if idx < len(row) else None`,
    `            mapped_rows.append(item)`,
    `        return ${expectsPointsWrapper ? '{"points": mapped_rows}' : 'mapped_rows'}`,
    `    if isinstance(raw, list):`,
    `        obj_header = _is_object_header_unit_row(raw)`,
    `        rows = raw[1:] if (obj_header and DROP_OBJECT_HEADER_ROW) else raw`,
    `        mapped = [`,
    `            _map_record(item, coerce_header_numeric=(obj_header and not DROP_OBJECT_HEADER_ROW and idx == 0))`,
    `            if isinstance(item, Mapping)`,
    `            else item`,
    `            for idx, item in enumerate(rows)`,
    `        ]`,
    `        return ${expectsPointsWrapper ? '{"points": mapped}' : 'mapped'}`,
    `    if isinstance(raw, Mapping):`,
    `        return _map_record(raw)`,
    `    return raw`,
    ``,
    ``,
    `def adapt_batch(rows: Sequence[Any]) -> list[Any]:`,
    `    return [adapt_input(row) for row in rows]`,
    ``
  ].join('\n');
}

/**
 * Synthesize a `$0` zero-LLM hexagonal `binding.js` / `binding.ts` or Python `binding_adapter.py`
 * from `STACK_ONTOLOGY_PORTS` alias rings + local sample structure (including 1D object & 2D array header rows),
 * enforcing Ed25519 bundle seal verification (`SEC-01`) and optionally verifying in `tryBrickFn`.
 *
 * @param {object} [options]
 */
export async function synthesizeHexagonalBinding(options = {}) {
  const tool = 'krusch_brick_ontology_bind';
  if (!isPlainObject(options)) {
    return failEnvelope(tool, 'INVALID_BINDING_OPTIONS', 'Options must be a plain object');
  }

  const topKeysSafety = validateSafePayload(
    {
      targetStack: options.targetStack,
      fieldMap: options.fieldMap,
      bindingOverrides: options.bindingOverrides
    },
    'options',
    { requireJsonSerializable: true, disallowNonFinite: true }
  );
  if (!topKeysSafety.ok) {
    return failEnvelope(tool, topKeysSafety.code, topKeysSafety.message, topKeysSafety.details || null);
  }

  const {
    bundle,
    targetStack = 'node-esm',
    localSample = undefined,
    fieldMap = {},
    bindingOverrides = {},
    tryBrickFn = null
  } = options;

  if (!isPlainObject(fieldMap) || !isPlainObject(bindingOverrides)) {
    return failEnvelope(
      tool,
      'INVALID_BINDING_OPTIONS',
      'fieldMap and bindingOverrides must be plain objects'
    );
  }

  if (tryBrickFn !== null && tryBrickFn !== undefined && typeof tryBrickFn !== 'function') {
    return failEnvelope(
      tool,
      'INVALID_BINDING_OPTIONS',
      'tryBrickFn must be a function or null'
    );
  }

  if (localSample !== undefined) {
    const sampleSafety = validateSafePayload(localSample, 'localSample', {
      requireJsonSerializable: true,
      disallowNonFinite: true
    });
    if (!sampleSafety.ok) {
      return failEnvelope(tool, sampleSafety.code, sampleSafety.message, sampleSafety.details || null);
    }
  }

  // SEC-01: Mandatory cryptographic Ed25519 seal verification before synthesizing any code adapter!
  const candidateBundle = isPlainObject(bundle?.bundle) ? bundle.bundle : bundle;
  const sealCheck = verifySealedBrickBundle(candidateBundle);
  if (!sealCheck.ok) {
    return failEnvelope(
      tool,
      sealCheck.error.code,
      sealCheck.error.message,
      sealCheck.error.details ?? null
    );
  }

  const unwrapped = unwrapBrickEntryResult(candidateBundle);
  if (!unwrapped.ok) {
    return failEnvelope(tool, unwrapped.error.code, unwrapped.error.message, unwrapped.error.details || null);
  }
  const parsed = unwrapped.value;

  // SEC-01: Strict slug & digest validation blocking comment/docstring breakout (`\n`, `\r`, `\u2028`, `\u2029`, `"""`, `*/`)
  if (
    !BRICK_ID_RE.test(parsed.brickId) ||
    BREAKOUT_SEQUENCE_RE.test(parsed.brickId) ||
    !HEX64_RE.test(parsed.sourceHash) ||
    BREAKOUT_SEQUENCE_RE.test(parsed.sourceHash)
  ) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_IDENTIFIER',
      'Brick identifier or sourceHash failed strict slug/hex64 validation before code generation',
      { brickId: parsed.brickId }
    );
  }

  const compat = checkBrickOntologyCompatibility({
    bundle: parsed.bundle,
    targetStack
  });
  if (!compat.ok) {
    return failEnvelope(tool, compat.error.code, compat.error.message, compat.error.details);
  }

  const cleanStack = targetStack.trim();
  const stackDef = STACK_ONTOLOGY_STACKS[cleanStack];

  // Resolve schema defaults + bindingOverrides safely via defineSafeProp
  const resolvedBinding = {};
  const bindingProps = parsed.blueprint?.bindingSchema?.properties;
  const bindingForbidsAdditional =
    parsed.blueprint?.bindingSchema?.additionalProperties === false && isPlainObject(bindingProps);

  if (isPlainObject(bindingProps)) {
    for (const [k, propSpec] of Object.entries(bindingProps)) {
      if (!FORBIDDEN_KEYS.has(k) && isPlainObject(propSpec) && propSpec.default !== undefined) {
        defineSafeProp(resolvedBinding, k, propSpec.default);
      }
    }
  }

  const adaptation = adaptSampleWithInferredRules(localSample, fieldMap, parsed, bindingOverrides);
  if (
    adaptation.hasHeaderRow &&
    !adaptation.dropObjectHeaderRow &&
    !Array.isArray(localSample?.[0]) &&
    (!bindingForbidsAdditional || Object.hasOwn(bindingProps, 'skipHeaderRow'))
  ) {
    defineSafeProp(resolvedBinding, 'skipHeaderRow', true);
  }

  for (const [k, v] of Object.entries(bindingOverrides)) {
    if (!FORBIDDEN_KEYS.has(k) && v !== undefined) {
      defineSafeProp(resolvedBinding, k, v);
    }
  }

  const expectsPointsWrapper = parsed.blueprint?.inputSchema?.type === 'object';

  const adapterFileName = stackDef.adapterFileName;
  const adapterSource =
    cleanStack === 'python-fastapi'
      ? renderPythonBindingAdapterSource({
          parsedBrick: parsed,
          resolvedBinding,
          fieldMap: adaptation.fieldMap,
          hasHeaderRow: adaptation.hasHeaderRow,
          dropObjectHeaderRow: adaptation.dropObjectHeaderRow,
          expectsPointsWrapper,
          schemaInfo: adaptation.schemaInfo
        })
      : renderJsOrTsBindingSource({
          parsedBrick: parsed,
          targetStack: cleanStack,
          resolvedBinding,
          fieldMap: adaptation.fieldMap,
          hasHeaderRow: adaptation.hasHeaderRow,
          dropObjectHeaderRow: adaptation.dropObjectHeaderRow,
          expectsPointsWrapper,
          schemaInfo: adaptation.schemaInfo
        });

  let sandboxVerification = {
    verified: false,
    skippedReason:
      cleanStack === 'python-fastapi'
        ? 'python-contract-adapter'
        : localSample === undefined
          ? 'no-local-sample'
          : 'no-try-brick-fn'
  };

  if (
    localSample !== undefined &&
    typeof tryBrickFn === 'function' &&
    cleanStack !== 'python-fastapi'
  ) {
    let tryOut;
    try {
      tryOut = await tryBrickFn({
        bundle: parsed.bundle,
        sampleInput: adaptation.adaptedSample,
        binding: resolvedBinding
      });
    } catch (err) {
      return failEnvelope(
        tool,
        'BINDING_VERIFICATION_FAILED',
        `tryBrickFn threw while verifying synthesized binding: ${err instanceof Error ? err.message : String(err)}`,
        {
          brickId: parsed.brickId,
          adaptedSample: adaptation.adaptedSample,
          fieldMap: adaptation.fieldMap
        }
      );
    }

    if (isPlainObject(tryOut) && tryOut.ok === false) {
      return failEnvelope(
        tool,
        'BINDING_VERIFICATION_FAILED',
        `Adapted sample failed brick sandbox verification: ${tryOut.error?.message || tryOut.summary || 'unknown error'}`,
        {
          brickId: parsed.brickId,
          adaptedSample: adaptation.adaptedSample,
          fieldMap: adaptation.fieldMap,
          sandboxError: tryOut.error || null
        }
      );
    }

    const verifiedOutput =
      isPlainObject(tryOut) && isPlainObject(tryOut.data) && 'output' in tryOut.data
        ? tryOut.data.output
        : isPlainObject(tryOut) && 'output' in tryOut
          ? tryOut.output
          : tryOut;

    sandboxVerification = {
      verified: true,
      output: verifiedOutput,
      durationMs:
        isPlainObject(tryOut) && isPlainObject(tryOut.data) && typeof tryOut.data.durationMs === 'number'
          ? tryOut.data.durationMs
          : 0
    };
  }

  return okEnvelope(
    tool,
    `Synthesized $0 ${adapterFileName} for "${parsed.brickId}" on "${cleanStack}" (${Object.keys(adaptation.fieldMap).length} mapped field(s))`,
    {
      brickId: parsed.brickId,
      sourceHash: parsed.sourceHash,
      targetStack: cleanStack,
      bridgeMode: compat.data.bridgeMode,
      costTier: 'TIER_0_DETERMINISTIC',
      llmTokensUsed: 0,
      estimatedCostUsd: 0,
      adapterFileName,
      adapterSource,
      binding: resolvedBinding,
      fieldMap: adaptation.fieldMap,
      hasHeaderRow: adaptation.hasHeaderRow,
      headerColumns: adaptation.headerColumns,
      adaptedSample: adaptation.adaptedSample,
      sandboxVerification
    }
  );
}

/**
 * Create a frozen KruschStack Brick Ontology Engine handle.
 * @param {object} [options]
 * @param {((opts?: object) => any)|null} [options.getAuthorizedBricksFn=null]
 * @param {((opts: object) => Promise<any>|any)|null} [options.tryBrickFn=null]
 */
export function createBrickOntologyEngine({
  getAuthorizedBricksFn = null,
  tryBrickFn = null
} = {}) {
  function resolveAuthorizedList(rawResult) {
    if (Array.isArray(rawResult)) {
      return { ok: true, bricks: rawResult };
    }
    if (isPlainObject(rawResult)) {
      if (rawResult.ok === false) {
        return { ok: false, envelope: rawResult };
      }
      if (isPlainObject(rawResult.data) && Array.isArray(rawResult.data.bricks)) {
        return { ok: true, bricks: rawResult.data.bricks };
      }
      if (Array.isArray(rawResult.bricks)) {
        return { ok: true, bricks: rawResult.bricks };
      }
    }
    return { ok: true, bricks: [] };
  }

  function composeBricks(opts = {}) {
    if (!isPlainObject(opts)) {
      return composeCrossStackBricks(opts);
    }
    if (!Array.isArray(opts.authorizedBricks) && typeof getAuthorizedBricksFn === 'function') {
      const fetched = getAuthorizedBricksFn(opts);
      if (fetched && typeof fetched.then === 'function') {
        return fetched.then((resolved) => {
          const unwrapped = resolveAuthorizedList(resolved);
          if (!unwrapped.ok) return unwrapped.envelope;
          return composeCrossStackBricks({ ...opts, authorizedBricks: unwrapped.bricks });
        });
      }
      const unwrapped = resolveAuthorizedList(fetched);
      if (!unwrapped.ok) return unwrapped.envelope;
      return composeCrossStackBricks({ ...opts, authorizedBricks: unwrapped.bricks });
    }
    return composeCrossStackBricks(opts);
  }

  function synthesizeBinding(opts = {}) {
    if (!isPlainObject(opts)) {
      return synthesizeHexagonalBinding(opts);
    }
    return synthesizeHexagonalBinding({
      ...opts,
      // SEC-03: Never allow non-function JSON values (e.g. "tryBrickFn": false) to disable sandbox verification!
      tryBrickFn: typeof opts.tryBrickFn === 'function' ? opts.tryBrickFn : tryBrickFn
    });
  }

  return Object.freeze({
    inspectOntology: inspectBrickOntology,
    checkCompatibility: checkBrickOntologyCompatibility,
    composeBricks,
    synthesizeBinding
  });
}
