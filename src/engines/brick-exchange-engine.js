/**
 * @module engines/brick-exchange-engine
 * Standalone Zero-Dependency Validated Brick Exchange & Deadbolt 2-Hop Blast-Radius Engine
 * for KruschStack (INV-STACK-12).
 *
 * Enforces INV-STACK-01 (zero external npm dependencies, Node 22 built-ins + node:sqlite),
 * INV-STACK-02 (deterministic okEnvelope return contract), and INV-STACK-04 (sanitized
 * public defaults with zero private network literals, hostnames, or OS home paths).
 *
 * Attribution & License Notice:
 * Multi-organization permission-before-discovery evaluation, scoped federated grant
 * issuance/revocation, and byte-exact lineage sealing concepts are adapted from
 * `0xANUSHKA/common-ground-8090` (MIT License, Copyright (c) 2026 Anushka Jogalekar
 * and Common Ground contributors), fused with Deadbolt 2-hop AST blast-radius cones,
 * policy-floor workaround blocking, and conflict-free parallel fan-out wave planning.
 */

import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import * as nodeModule from 'node:module';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { okEnvelope, openStackDatabase } from '../db/sqlite.js';
import {
  CANONICAL_SHARED_TYPES,
  STACK_ONTOLOGY_STACKS,
  STACK_ONTOLOGY_PORTS,
  STACK_ONTOLOGY_CHANNELS,
  STACK_ONTOLOGY_MOE_PROFILES,
  hasForbiddenKeyRecursive,
  parsePortReference,
  isWebStandardPureBrickSource,
  areOntologyPortsCompatible,
  surrogateOntologyVertexId,
  normalizeBrickOntology,
  inspectBrickOntology,
  checkBrickOntologyCompatibility,
  composeCrossStackBricks,
  synthesizeHexagonalBinding,
  createBrickOntologyEngine
} from './brick-ontology-engine.js';

export {
  CANONICAL_SHARED_TYPES,
  STACK_ONTOLOGY_STACKS,
  STACK_ONTOLOGY_PORTS,
  STACK_ONTOLOGY_CHANNELS,
  STACK_ONTOLOGY_MOE_PROFILES,
  hasForbiddenKeyRecursive,
  parsePortReference,
  isWebStandardPureBrickSource,
  areOntologyPortsCompatible,
  surrogateOntologyVertexId,
  normalizeBrickOntology,
  inspectBrickOntology,
  checkBrickOntologyCompatibility,
  composeCrossStackBricks,
  synthesizeHexagonalBinding,
  createBrickOntologyEngine
};

export const BRICK_EXCHANGE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS brick_exchange_bricks (
  brick_key TEXT PRIMARY KEY,
  brick_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  brick_class TEXT NOT NULL DEFAULT 'general',
  author_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  capabilities_json TEXT NOT NULL DEFAULT '[]',
  bundle_json TEXT NOT NULL,
  estimated_hours_saved REAL NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_brick_exchange_bricks_org
  ON brick_exchange_bricks(org_id, brick_id);

CREATE TABLE IF NOT EXISTS brick_exchange_grants (
  grant_id TEXT PRIMARY KEY,
  brick_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  issuer_id TEXT NOT NULL,
  issuer_org_id TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'federated',
  recipients_json TEXT NOT NULL DEFAULT '[]',
  revoked INTEGER NOT NULL DEFAULT 0,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_brick_exchange_grants_brick
  ON brick_exchange_grants(brick_id, source_hash);

CREATE TABLE IF NOT EXISTS brick_exchange_adoptions (
  adoption_id TEXT PRIMARY KEY,
  brick_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  grant_id TEXT NOT NULL DEFAULT '',
  binding_hash TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_brick_exchange_adoptions_brick
  ON brick_exchange_adoptions(brick_id, created_at_ms);
`;

const SEAL_DOMAIN_PREFIX = 'krusch-brick-seal-v1:';
const SEAL_ATTESTATION_DOMAIN = 'krusch-brick-seal-v1';
const SEALED_BUNDLE_FORMAT = 'krusch-sealed-brick/v1';
const LINEAGE_STANDARD = 'krusch-brick-exchange-v1';

const DEFAULT_SANDBOX_TIMEOUT_MS = 800;
const DEFAULT_SANDBOX_MAX_MEMORY_MB = 32;
const MAX_BRICK_SOURCE_BYTES = 65536;
const MAX_STDIN_PAYLOAD_BYTES = 2 * 1024 * 1024;
const MAX_CHILD_STREAM_BYTES = 2 * 1024 * 1024;
const DEFAULT_GRANT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const BRICK_ID_RE = /^[a-z0-9][a-z0-9-_]{1,63}$/;
const SAFE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const BANNED_HOST_MODULES = new Set([
  'fs',
  'fs/promises',
  'net',
  'tls',
  'http',
  'https',
  'http2',
  'dgram',
  'dns',
  'dns/promises',
  'child_process',
  'worker_threads',
  'cluster',
  'os',
  'v8',
  'vm',
  'inspector',
  'inspector/promises',
  'module',
  'process',
  'readline',
  'repl',
  'tty',
  'wasi',
  'sqlite'
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

const DEFAULT_CHOKE_POINT_FILES = Object.freeze([
  'server.js',
  'src/server.js',
  'app.js',
  'src/app.js',
  'index.js',
  'src/index.js',
  'main.js',
  'src/main.js',
  'tools.js',
  'src/tools.js',
  'App.jsx',
  'src/App.jsx',
  'client/src/App.jsx',
  'App.tsx',
  'src/App.tsx',
  'client/src/App.tsx',
  'package.json'
]);

const SCANNABLE_CODE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.jsx',
  '.ts',
  '.tsx',
  '.py'
]);

const RESOLVE_CANDIDATE_SUFFIXES = [
  '',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '/index.js',
  '/index.mjs',
  '/index.ts',
  '/index.tsx'
];

const SKIP_SCAN_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'out',
  '.next',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.cache'
]);

const SENSITIVE_SYSTEM_PREFIXES = [
  '/etc',
  '/private/etc',
  '/root',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/var/run'
];

// Dynamically assembled so static repository leak scanners never match detector patterns.
const SECRET_LEAK_RE = new RegExp(
  [
    `${'AIza' + 'Sy'}[A-Za-z0-9_-]{3,}`,
    `\\b${'sk' + '-'}[A-Za-z0-9_-]{4,}`,
    `\\b${'gh' + 'p_'}[A-Za-z0-9]{4,}`,
    `\\bgh[ousr]_[A-Za-z0-9]{6,}`,
    `\\bgithub_pat_[A-Za-z0-9_]{6,}`,
    `\\bxox[baprs]-[A-Za-z0-9-]{6,}`,
    `${'-----' + 'BEGIN'}\\b`
  ].join('|')
);

const LOCAL_FS_DIR_LEAK_RE = new RegExp(
  `(?<![A-Za-z0-9._-])\\/(?:${['ho' + 'me', 'Us' + 'ers', 'm' + 'nt'].join('|')})\\/[A-Za-z0-9._-]+`
);

const PRIVATE_DOMAIN_LEAK_RE = new RegExp(
  `\\.(?:${['l' + 'an', 'lo' + 'cal', 'inter' + 'nal', 'ts\\.' + 'net'].join('|')})\\b`,
  'i'
);

const SANDBOX_JSON_MARKER_PREFIX = '__KRUSCHSTACK_PERM_SANDBOX_JSON__:';

const WORKER_BOOTSTRAP_CODE = `
'use strict';
const vm = require('node:vm');
const realSetTimeout = setTimeout;
const realClearTimeout = clearTimeout;
const realStdoutWrite = process.stdout.write.bind(process.stdout);
const realExit = process.exit.bind(process);

try { delete globalThis.fetch; } catch {}
try { delete globalThis.WebSocket; } catch {}

function writeResultAndExit(payload) {
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch (err) {
    serialized = JSON.stringify({
      ok: false,
      code: 'SANDBOX_EXECUTION_ERROR',
      message: 'Brick output is not JSON-serializable: ' + (err && err.message ? err.message : String(err))
    });
  }
  realStdoutWrite(serialized + '\\n', () => realExit(0));
}

let chunks = [];
let totalBytes = 0;
const maxBytes = ${MAX_STDIN_PAYLOAD_BYTES};

process.stdin.on('data', (chunk) => {
  totalBytes += chunk.length;
  if (totalBytes > maxBytes) {
    writeResultAndExit({
      ok: false,
      code: 'SANDBOX_EXECUTION_ERROR',
      message: 'Sandbox stdin payload exceeded limit'
    });
    return;
  }
  chunks.push(chunk);
});

process.stdin.on('end', async () => {
  let req;
  try {
    req = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    chunks = null;
  } catch {
    writeResultAndExit({
      ok: false,
      code: 'SANDBOX_EXECUTION_ERROR',
      message: 'Malformed sandbox request payload'
    });
    return;
  }

  const vmTimeoutMs = Math.max(5, Number(req.vmTimeoutMs) || ${DEFAULT_SANDBOX_TIMEOUT_MS});
  const exportName = String(req.exportName || 'default');
  const cjsCode = String(req.cjsCode || '');

  const sandboxGlobals = {
    TextEncoder,
    TextDecoder,
    URL,
    URLSearchParams,
    structuredClone,
    fetch: undefined,
    process: undefined,
    require: undefined,
    WebSocket: undefined,
    setTimeout: undefined,
    setInterval: undefined,
    clearTimeout: undefined,
    clearInterval: undefined,
    setImmediate: undefined,
    clearImmediate: undefined,
    __rawInputJson: JSON.stringify(req.hasUndefinedInput ? null : req.input),
    __hasUndefinedInput: Boolean(req.hasUndefinedInput),
    __rawBindingJson: JSON.stringify(req.bindingData ?? {}),
    __exportName: exportName
  };

  const ctx = vm.createContext(sandboxGlobals, {
    codeGeneration: { strings: false, wasm: false }
  });

  const runnerSource =
    '(function () {\\n' +
    '  const module = { exports: {} };\\n' +
    '  const exports = module.exports;\\n' +
    '  const __input = __hasUndefinedInput ? undefined : JSON.parse(__rawInputJson);\\n' +
    '  const __binding = JSON.parse(__rawBindingJson);\\n' +
    cjsCode + '\\n;\\n' +
    '  const __modOut = module.exports;\\n' +
    '  let __fn = undefined;\\n' +
    '  if (__exportName === "default") {\\n' +
    '    if (typeof __modOut === "function") { __fn = __modOut; }\\n' +
    '    else if (__modOut && (typeof __modOut === "object" || typeof __modOut === "function") && typeof __modOut.default === "function") { __fn = __modOut.default; }\\n' +
    '  } else if (__modOut && (typeof __modOut === "object" || typeof __modOut === "function") && typeof __modOut[__exportName] === "function") {\\n' +
    '    __fn = __modOut[__exportName];\\n' +
    '  }\\n' +
    '  if (typeof __fn !== "function") {\\n' +
    '    throw new TypeError("Export " + __exportName + " is not a function on brick module");\\n' +
    '  }\\n' +
    '  return __fn(__input, __binding);\\n' +
    '})()';

  let timer = null;
  try {
    const script = new vm.Script(runnerSource, { filename: 'brick.sandbox.cjs' });
    const rawOut = script.runInContext(ctx, { timeout: vmTimeoutMs });

    if (rawOut !== null && (typeof rawOut === 'object' || typeof rawOut === 'function') && typeof rawOut.then === 'function') {
      const timeoutPromise = new Promise((_, reject) => {
        timer = realSetTimeout(() => {
          const err = new Error('Async brick execution timed out after ' + vmTimeoutMs + 'ms');
          err.code = 'ERR_SCRIPT_EXECUTION_TIMEOUT';
          reject(err);
        }, vmTimeoutMs);
      });
      const awaited = await Promise.race([rawOut, timeoutPromise]);
      if (timer) realClearTimeout(timer);
      writeResultAndExit({
        ok: true,
        hasUndefined: awaited === undefined,
        output: awaited === undefined ? null : awaited
      });
      return;
    }

    writeResultAndExit({
      ok: true,
      hasUndefined: rawOut === undefined,
      output: rawOut === undefined ? null : rawOut
    });
  } catch (err) {
    if (timer) realClearTimeout(timer);
    const msg = err && err.message ? String(err.message) : String(err);
    const code = (err && err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') || /Script execution timed out/i.test(msg)
      ? 'SANDBOX_TIMEOUT'
      : 'SANDBOX_EXECUTION_ERROR';
    writeResultAndExit({ ok: false, code, message: msg });
  }
});
`;

/**
 * Format a structured failure envelope conforming to INV-STACK-02 error contracts.
 * @param {string} tool
 * @param {string} code
 * @param {string} message
 * @param {object|null} [details=null]
 */
function failEnvelope(tool, code, message, details = null) {
  const error = {
    code: String(code || 'BRICK_EXCHANGE_ERROR'),
    message: String(message || 'Brick exchange operation failed')
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

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isSafeIdentifier(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed || trimmed !== value) return false;
  if (FORBIDDEN_KEYS.has(trimmed) || trimmed.includes('..')) return false;
  return SAFE_ID_RE.test(trimmed);
}

function isIdentStart(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
}

function isIdentPart(code) {
  return isIdentStart(code) || (code >= 48 && code <= 57);
}

function constantTimeHexEqual(actual, expectedHex) {
  if (typeof expectedHex !== 'string' || expectedHex.length === 0) {
    return false;
  }
  const expectedBuf = Buffer.from(expectedHex, 'utf8');
  if (typeof actual !== 'string') {
    crypto.timingSafeEqual(expectedBuf, expectedBuf);
    return false;
  }
  const actualBuf = Buffer.from(actual, 'utf8');
  if (actualBuf.length !== expectedBuf.length) {
    crypto.timingSafeEqual(expectedBuf, expectedBuf);
    return false;
  }
  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}

function constantTimeStringEqual(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') {
    return false;
  }
  const aBuf = Buffer.from(actual, 'utf8');
  const bBuf = Buffer.from(expected, 'utf8');
  if (aBuf.length !== bBuf.length) {
    if (bBuf.length > 0) crypto.timingSafeEqual(bBuf, bBuf);
    return false;
  }
  if (bBuf.length === 0) return true;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function hasLoneSurrogate(str) {
  if (typeof str.isWellFormed === 'function') {
    return !str.isWellFormed();
  }
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= str.length) return true;
      const next = str.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/**
 * Deterministic RFC-8785-compatible canonical JSON serializer matching @krusch/toolkit/audit-log.
 * @param {unknown} value
 * @param {number} [maxDepth=64]
 * @returns {{ ok: true, json: string } | { ok: false, message: string }}
 */
function canonicalJsonResult(value, maxDepth = 64) {
  const ancestors = new Set();

  function serializeNode(node, depth) {
    if (node === null || node === undefined) {
      return { ok: true, json: 'null' };
    }
    let current = node;
    if (current instanceof Boolean || current instanceof Number || current instanceof String) {
      current = current.valueOf();
    }
    const t = typeof current;
    if (t === 'boolean') {
      return { ok: true, json: current ? 'true' : 'false' };
    }
    if (t === 'number') {
      if (!Number.isFinite(current)) {
        return { ok: false, message: 'Non-finite number in canonical payload' };
      }
      if (Object.is(current, -0) || current === 0) {
        return { ok: true, json: '0' };
      }
      return { ok: true, json: JSON.stringify(current) };
    }
    if (t === 'string') {
      if (hasLoneSurrogate(current)) {
        return { ok: false, message: 'Lone UTF-16 surrogate in canonical payload' };
      }
      return { ok: true, json: JSON.stringify(current) };
    }
    if (t === 'bigint' || t === 'symbol' || t === 'function') {
      return { ok: false, message: `Unsupported ${t} value in canonical payload` };
    }
    if (current instanceof Date) {
      const ms = current.getTime();
      if (!Number.isFinite(ms)) {
        return { ok: false, message: 'Invalid Date in canonical payload' };
      }
      return { ok: true, json: JSON.stringify(current.toISOString()) };
    }
    if (depth > maxDepth) {
      return { ok: false, message: 'Maximum canonicalization depth exceeded' };
    }
    if (ancestors.has(current)) {
      return { ok: false, message: 'Circular reference in canonical payload' };
    }
    ancestors.add(current);
    try {
      if (Array.isArray(current)) {
        const parts = [];
        for (let i = 0; i < current.length; i += 1) {
          const item = current[i] === undefined ? null : current[i];
          const sub = serializeNode(item, depth + 1);
          if (!sub.ok) return sub;
          parts.push(sub.json);
        }
        return { ok: true, json: `[${parts.join(',')}]` };
      }
      const keys = Object.keys(current).sort();
      const entries = [];
      for (let i = 0; i < keys.length; i += 1) {
        const k = keys[i];
        if (FORBIDDEN_KEYS.has(k)) {
          return { ok: false, message: `Forbidden prototype key "${k}" in canonical payload` };
        }
        if (current[k] === undefined) continue;
        if (hasLoneSurrogate(k)) {
          return { ok: false, message: 'Lone UTF-16 surrogate in object key' };
        }
        const sub = serializeNode(current[k], depth + 1);
        if (!sub.ok) return sub;
        entries.push(`${JSON.stringify(k)}:${sub.json}`);
      }
      return { ok: true, json: `{${entries.join(',')}}` };
    } finally {
      ancestors.delete(current);
    }
  }

  return serializeNode(value, 0);
}

function fallbackCanonicalJson(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) return JSON.stringify(String(value));
    return Object.is(value, -0) || value === 0 ? '0' : JSON.stringify(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (t === 'bigint' || t === 'symbol' || t === 'function') return JSON.stringify(String(value));
  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? JSON.stringify(value.toISOString()) : 'null';
  }
  if (seen.has(value)) return '"[Circular]"';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((v) => (v === undefined ? 'null' : fallbackCanonicalJson(v, seen))).join(',')}]`;
    }
    const keys = Object.keys(value)
      .filter((k) => !FORBIDDEN_KEYS.has(k) && value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${fallbackCanonicalJson(value[k], seen)}`).join(',')}}`;
  } finally {
    seen.delete(value);
  }
}

function computeCanonicalHash(value) {
  if (typeof value === 'string') {
    return crypto.createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex');
  }
  const canon = canonicalJsonResult(value);
  const serialized = canon.ok ? canon.json : fallbackCanonicalJson(value);
  return crypto.createHash('sha256').update(Buffer.from(serialized, 'utf8')).digest('hex');
}

function deepFreezeClone(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'number') return Object.is(value, -0) ? 0 : value;
  if (typeof value !== 'object') return value;
  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? value.toISOString() : null;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => (item === undefined ? null : deepFreezeClone(item))));
  }
  const cloned = {};
  const keys = Object.keys(value).sort();
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    if (!FORBIDDEN_KEYS.has(key) && value[key] !== undefined) {
      Object.defineProperty(cloned, key, {
        value: deepFreezeClone(value[key]),
        enumerable: true,
        writable: true,
        configurable: true
      });
    }
  }
  return Object.freeze(cloned);
}

function extractContractShape(blueprint) {
  return {
    inputSchema: blueprint?.inputSchema ?? {},
    outputSchema: blueprint?.outputSchema ?? {},
    bindingSchema: blueprint?.bindingSchema ?? {}
  };
}

function derivePublicKeyId(publicKeyPem) {
  const pubKey = crypto.createPublicKey(String(publicKeyPem || '').trim());
  const spkiDer = pubKey.export({ type: 'spki', format: 'der' });
  const digest = crypto.createHash('sha256').update(spkiDer).digest('hex');
  return `key_${digest.slice(0, 16)}`;
}

/**
 * Generate a fresh Ed25519 signing keypair for sealing verified bricks.
 * @returns {{ ok: true, tool: 'krusch_brick_keygen', summary: string, data: { keyId: string, publicKeyPem: string, privateKeyPem: string, algorithm: 'ed25519' } }}
 */
export function generateEd25519BrickKeys() {
  const { publicKey: publicKeyPem, privateKey: privateKeyPem } = crypto.generateKeyPairSync(
    'ed25519',
    {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }
  );
  const keyId = derivePublicKeyId(publicKeyPem);
  return okEnvelope('krusch_brick_keygen', 'Generated Ed25519 brick signing keypair', {
    keyId,
    publicKeyPem,
    privateKeyPem,
    algorithm: 'ed25519'
  });
}

/**
 * Verify a sealed brick bundle's format (`krusch-sealed-brick/v1`), canonical SHA-256 digests,
 * adversarial fault-injection qualification, optional pinned public key, and Ed25519 signature.
 *
 * @param {unknown} bundle
 * @param {{ trustedPublicKeyPem?: string | null }} [options={}]
 */
export function verifySealedBrickBundle(bundle, { trustedPublicKeyPem = null } = {}) {
  const tool = 'krusch_brick_verify';

  if (!isPlainObject(bundle) || bundle.format !== SEALED_BUNDLE_FORMAT) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      'Bundle must be an object with format "krusch-sealed-brick/v1"'
    );
  }

  const forbiddenInBundle = hasForbiddenKeyRecursive(bundle);
  if (forbiddenInBundle) {
    return failEnvelope(
      tool,
      forbiddenInBundle.startsWith('__') ? 'INVALID_BRICK_BUNDLE' : 'ONTOLOGY_FORBIDDEN_KEY',
      `Rejected unsafe key or depth/cycle violation (${forbiddenInBundle}) in brick bundle`,
      { key: forbiddenInBundle }
    );
  }

  if (typeof bundle.brickId !== 'string' || !BRICK_ID_RE.test(bundle.brickId)) {
    return failEnvelope(tool, 'INVALID_BRICK_BUNDLE', 'Bundle brickId is missing or invalid', {
      field: 'brickId'
    });
  }

  if (!isSafeIdentifier(bundle.authorId) || !isSafeIdentifier(bundle.orgId)) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      'Bundle authorId and orgId must be valid safe identifiers'
    );
  }

  if (typeof bundle.brickClass !== 'string' || !isSafeIdentifier(bundle.brickClass)) {
    return failEnvelope(tool, 'INVALID_BRICK_BUNDLE', 'Bundle brickClass is missing or invalid', {
      field: 'brickClass'
    });
  }

  if (typeof bundle.source !== 'string' || bundle.source.trim().length === 0) {
    return failEnvelope(tool, 'INVALID_BRICK_BUNDLE', 'Bundle source must be a non-empty string', {
      field: 'source'
    });
  }

  if (!isPlainObject(bundle.blueprint) || bundle.blueprint.id !== bundle.brickId) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      'Bundle blueprint is missing or blueprint.id does not match brickId',
      { field: 'blueprint' }
    );
  }

  if (
    !Array.isArray(bundle.checks) ||
    bundle.checks.length < 2 ||
    !bundle.checks.every(
      (c) =>
        isPlainObject(c) &&
        typeof c.name === 'string' &&
        c.name.trim().length > 0 &&
        typeof c.kind === 'string' &&
        c.kind.trim().length > 0 &&
        c.passed === true
    ) ||
    !bundle.checks.some((c) => c.kind === 'fault')
  ) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      'Bundle checks must include >= 2 passed checks including at least 1 fault challenge',
      { field: 'checks' }
    );
  }

  const { lineage, attestation } = bundle;
  if (
    !isPlainObject(lineage) ||
    lineage.standard !== LINEAGE_STANDARD ||
    lineage.brickId !== bundle.brickId ||
    lineage.authorId !== bundle.authorId ||
    lineage.orgId !== bundle.orgId ||
    !HEX64_RE.test(String(lineage.sourceHash || '')) ||
    !HEX64_RE.test(String(lineage.blueprintHash || '')) ||
    !HEX64_RE.test(String(lineage.contractHash || '')) ||
    !HEX64_RE.test(String(lineage.checksHash || ''))
  ) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      'Bundle lineage metadata is missing, inconsistent, or malformed',
      { field: 'lineage' }
    );
  }

  if (
    !isPlainObject(attestation) ||
    attestation.algorithm !== 'ed25519' ||
    attestation.domain !== SEAL_ATTESTATION_DOMAIN ||
    typeof attestation.publicKeyPem !== 'string' ||
    attestation.publicKeyPem.trim().length === 0 ||
    typeof attestation.keyId !== 'string' ||
    attestation.keyId.trim().length === 0
  ) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      'Bundle attestation metadata is missing or unsupported',
      { field: 'attestation' }
    );
  }

  const actualSourceHash = computeCanonicalHash(bundle.source);
  if (!constantTimeHexEqual(actualSourceHash, lineage.sourceHash)) {
    return failEnvelope(
      tool,
      'BRICK_HASH_MISMATCH',
      'Brick source hash mismatch; bundle source was modified after sealing',
      { field: 'sourceHash' }
    );
  }

  const actualBlueprintHash = computeCanonicalHash(bundle.blueprint);
  if (!constantTimeHexEqual(actualBlueprintHash, lineage.blueprintHash)) {
    return failEnvelope(
      tool,
      'BRICK_HASH_MISMATCH',
      'Brick blueprint hash mismatch; blueprint was modified after sealing',
      { field: 'blueprintHash' }
    );
  }

  // SEC-02: Verify top-level bundle.ontology (when present) matches normalized signed blueprint.ontology!
  if (bundle.ontology !== undefined) {
    if (!isPlainObject(bundle.ontology) || !isPlainObject(bundle.blueprint.ontology)) {
      return failEnvelope(
        tool,
        'TAMPERED_ONTOLOGY',
        'Unsigned or invalid top-level bundle.ontology detected; ontology must match signed blueprint.ontology',
        { field: 'ontology' }
      );
    }
    const normSignedOnt = normalizeBrickOntology(bundle.blueprint.ontology, {
      source: bundle.source,
      blueprint: bundle.blueprint
    });
    if (!normSignedOnt.ok) {
      return failEnvelope(
        tool,
        'TAMPERED_ONTOLOGY',
        `Signed blueprint.ontology failed normalization: ${normSignedOnt.error.message}`,
        { field: 'ontology' }
      );
    }
    const canonTopOnt = canonicalJsonResult(bundle.ontology);
    const canonSignedOnt = canonicalJsonResult(normSignedOnt.data.ontology);
    if (
      !canonTopOnt.ok ||
      !canonSignedOnt.ok ||
      !constantTimeStringEqual(canonTopOnt.json, canonSignedOnt.json)
    ) {
      return failEnvelope(
        tool,
        'TAMPERED_ONTOLOGY',
        'Top-level bundle.ontology does not match signed blueprint.ontology',
        { field: 'ontology' }
      );
    }
  }

  const actualContractHash = computeCanonicalHash(extractContractShape(bundle.blueprint));
  if (!constantTimeHexEqual(actualContractHash, lineage.contractHash)) {
    return failEnvelope(tool, 'BRICK_HASH_MISMATCH', 'Brick contract schema hash mismatch', {
      field: 'contractHash'
    });
  }

  const actualChecksHash = computeCanonicalHash(bundle.checks);
  if (!constantTimeHexEqual(actualChecksHash, lineage.checksHash)) {
    return failEnvelope(tool, 'BRICK_HASH_MISMATCH', 'Brick verification checks hash mismatch', {
      field: 'checksHash'
    });
  }

  const actualFaultCount = bundle.checks.filter((c) => c.kind === 'fault').length;
  if (lineage.faultChallengeCount !== actualFaultCount) {
    return failEnvelope(
      tool,
      'BRICK_HASH_MISMATCH',
      'Lineage faultChallengeCount does not match bundle checks',
      { field: 'faultChallengeCount' }
    );
  }

  let pubKey;
  let derivedBundleKeyId;
  try {
    pubKey = crypto.createPublicKey(attestation.publicKeyPem.trim());
    if (pubKey.asymmetricKeyType !== 'ed25519') {
      return failEnvelope(
        tool,
        'BRICK_SIGNATURE_INVALID',
        'Attestation public key is not an Ed25519 key'
      );
    }
    derivedBundleKeyId = derivePublicKeyId(attestation.publicKeyPem);
  } catch {
    return failEnvelope(
      tool,
      'BRICK_SIGNATURE_INVALID',
      'Attestation publicKeyPem could not be parsed'
    );
  }

  if (!constantTimeStringEqual(attestation.keyId, derivedBundleKeyId)) {
    return failEnvelope(
      tool,
      'BRICK_SIGNATURE_INVALID',
      'Attestation keyId does not match attestation publicKeyPem',
      { expectedKeyId: derivedBundleKeyId, actualKeyId: attestation.keyId }
    );
  }

  if (
    trustedPublicKeyPem !== null &&
    trustedPublicKeyPem !== undefined &&
    trustedPublicKeyPem !== ''
  ) {
    let trustedKeyId;
    try {
      if (typeof trustedPublicKeyPem !== 'string') {
        throw new TypeError('trustedPublicKeyPem must be a PEM string');
      }
      const trustedKeyObj = crypto.createPublicKey(trustedPublicKeyPem.trim());
      if (trustedKeyObj.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('trustedPublicKeyPem must be an Ed25519 key');
      }
      trustedKeyId = derivePublicKeyId(trustedPublicKeyPem);
    } catch {
      return failEnvelope(
        tool,
        'UNTRUSTED_SIGNING_KEY',
        'Provided trustedPublicKeyPem is invalid or unsupported'
      );
    }

    if (!constantTimeStringEqual(trustedKeyId, derivedBundleKeyId)) {
      return failEnvelope(
        tool,
        'UNTRUSTED_SIGNING_KEY',
        'Bundle signing key does not match trusted public key',
        { expectedKeyId: trustedKeyId, actualKeyId: derivedBundleKeyId }
      );
    }
  }

  if (typeof attestation.signature !== 'string' || !HEX128_RE.test(attestation.signature)) {
    return failEnvelope(
      tool,
      'BRICK_SIGNATURE_INVALID',
      'Attestation signature must be a 128-character lowercase hex Ed25519 signature'
    );
  }

  const lineageCanon = canonicalJsonResult(lineage);
  if (!lineageCanon.ok) {
    return failEnvelope(
      tool,
      'INVALID_BRICK_BUNDLE',
      `Bundle lineage failed canonical serialization: ${lineageCanon.message}`
    );
  }

  const payloadBuf = Buffer.from(`${SEAL_DOMAIN_PREFIX}${lineageCanon.json}`, 'utf8');
  const signatureBuf = Buffer.from(attestation.signature, 'hex');

  let signatureValid = false;
  try {
    signatureValid = crypto.verify(null, payloadBuf, pubKey, signatureBuf);
  } catch {
    signatureValid = false;
  }

  if (!signatureValid) {
    return failEnvelope(
      tool,
      'BRICK_SIGNATURE_INVALID',
      'Ed25519 attestation signature verification failed',
      { brickId: bundle.brickId, keyId: derivedBundleKeyId }
    );
  }

  return okEnvelope(
    tool,
    `Verified Ed25519 seal for "${bundle.brickId}"@${lineage.sourceHash.slice(0, 8)}`,
    {
      valid: true,
      brickId: bundle.brickId,
      sourceHash: lineage.sourceHash,
      blueprintHash: lineage.blueprintHash,
      keyId: attestation.keyId,
      lineage
    }
  );
}

// ============================================================================
// Gate 1-3 Sandbox, Safety Scanner, Schema Validator & ESM-to-CJS Transpiler
// ============================================================================

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

function stripJsCommentsPreservingLiterals(source) {
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

function stripTypeOnlyDeclarationsForScan(commentStrippedSource) {
  if (typeof nodeModule.stripTypeScriptTypes === 'function') {
    try {
      return nodeModule.stripTypeScriptTypes(commentStrippedSource, { mode: 'strip' });
    } catch {
      // Fallback if source has syntax errors caught later
    }
  }
  return commentStrippedSource
    .replace(/\bimport\s+type\s+(?:[\s\S]*?\s+from\s+)?['"][^'"]+['"]\s*;?/g, ' ')
    .replace(/\bexport\s+type\s+\{[\s\S]*?\}(?:\s+from\s+['"][^'"]+['"])?\s*;?/g, ' ')
    .replace(/\bexport\s+type\s+[A-Za-z_$][A-Za-z0-9_$]*[\s\S]*?;/g, ' ');
}

function containsPrivateIpv4Literal(text) {
  const ipv4Re = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
  for (const match of text.matchAll(ipv4Re)) {
    const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])];
    if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) continue;
    const [o1, o2] = octets;
    const isClassA = o1 === 10;
    const isClassB = o1 === 172 && o2 >= 16 && o2 <= 31;
    const isClassC = o1 === 192 && o2 === 168;
    const isCgnat = o1 === 100 && o2 >= 64 && o2 <= 127;
    if (isClassA || isClassB || isClassC || isCgnat) {
      return true;
    }
  }
  return false;
}

function scanBrickSourceSafety(source) {
  if (typeof source !== 'string' || source.trim().length === 0) {
    return {
      ok: false,
      findings: [{ ruleId: 'INVALID_BRICK_SOURCE', message: 'Brick source must be a non-empty string' }]
    };
  }

  const byteLength = Buffer.byteLength(source, 'utf8');
  if (byteLength > MAX_BRICK_SOURCE_BYTES) {
    return {
      ok: false,
      findings: [
        {
          ruleId: 'SOURCE_TOO_LARGE',
          message: `Brick source (${byteLength} bytes) exceeds ${MAX_BRICK_SOURCE_BYTES} byte limit`
        }
      ]
    };
  }

  const findings = [];
  const pushFinding = (ruleId, message) => {
    if (!findings.some((f) => f.ruleId === ruleId && f.message === message)) {
      findings.push({ ruleId, message });
    }
  };

  const commentStripped = stripJsCommentsPreservingLiterals(source);
  const runtimeCode = stripTypeOnlyDeclarationsForScan(commentStripped);

  const checkSpecifier = (specifier, syntaxKind) => {
    const clean = String(specifier || '').trim();
    const bare = clean.startsWith('node:') ? clean.slice(5) : clean;
    if (clean.startsWith('node:') || BANNED_HOST_MODULES.has(bare)) {
      pushFinding(
        'AMBIENT_IMPORT_FORBIDDEN',
        `Forbidden host capability ${syntaxKind} of "${clean}"; inject capability ports via binding`
      );
      return;
    }
    pushFinding(
      'AMBIENT_IMPORT_FORBIDDEN',
      `External runtime ${syntaxKind} of "${clean}" is forbidden in sealed bricks`
    );
  };

  for (const m of runtimeCode.matchAll(/\bimport\s+(?!type\b)[\s\S]*?\bfrom\s*(['"`])([^'"`]+)\1/g)) {
    checkSpecifier(m[2], 'import');
  }
  for (const m of runtimeCode.matchAll(/\bimport\s*(['"`])([^'"`]+)\1/g)) {
    checkSpecifier(m[2], 'import');
  }
  for (const m of runtimeCode.matchAll(
    /\bexport\s+(?!type\b)(?:\*(?:\s+as\s+[A-Za-z_$][A-Za-z0-9_$]*)?|\{[\s\S]*?\})\s*from\s*(['"`])([^'"`]+)\1/g
  )) {
    checkSpecifier(m[2], 're-export');
  }
  for (const m of runtimeCode.matchAll(/(?<!(?:\.\s*|\?\.\s*|function\s+))\bimport\s*\(\s*(?:(['"`])([^'"`]*)\1)?/g)) {
    if (m[2] !== undefined) checkSpecifier(m[2], 'dynamic import()');
    else pushFinding('AMBIENT_IMPORT_FORBIDDEN', 'Computed dynamic import() expression is forbidden in sealed bricks');
  }
  for (const m of runtimeCode.matchAll(/(?<!(?:\.\s*|\?\.\s*|function\s+))\brequire\s*\(\s*(?:(['"`])([^'"`]*)\1)?/g)) {
    if (m[2] !== undefined) checkSpecifier(m[2], 'require()');
    else pushFinding('AMBIENT_IMPORT_FORBIDDEN', 'Dynamic require() call is forbidden in sealed bricks');
  }

  if (
    /\bprocess\s*\.\s*(?:env|exit|binding|dlopen|kill|mainModule|chdir|umask|cwd|argv)\b/.test(runtimeCode) ||
    /\bprocess\s*\[\s*['"`](?:env|exit|binding|dlopen|kill|mainModule)['"`]\s*\]/.test(runtimeCode) ||
    /\b(?:globalThis|global)\s*(?:\.\s*process\b|\[\s*['"`]process['"`]\s*\])/.test(runtimeCode)
  ) {
    pushFinding(
      'AMBIENT_PROCESS_FORBIDDEN',
      'Direct process access (process.env, process.exit, process.binding) is forbidden; inject configuration via binding'
    );
  }

  if (
    /\b(?:globalThis|global|window|self)\s*(?:\.\s*fetch\b|\[\s*['"`]fetch['"`]\s*\])/.test(runtimeCode) ||
    /(?<!(?:\.\s*|\?\.\s*|function\s+))\bfetch\s*\(/.test(runtimeCode) ||
    /\bXMLHttpRequest\b/.test(runtimeCode) ||
    /\b(?:globalThis|global|window|self)\s*\.\s*WebSocket\b/.test(runtimeCode) ||
    /(?<!(?:\.\s*|\?\.\s*|function\s+|class\s+))\bWebSocket\b/.test(runtimeCode)
  ) {
    pushFinding(
      'AMBIENT_NETWORK_FORBIDDEN',
      'Ambient network I/O (fetch, XMLHttpRequest, WebSocket) is forbidden; inject network ports via binding'
    );
  }

  if (
    /(?<!(?:\.\s*|\?\.\s*|function\s+))\beval\s*\(/.test(runtimeCode) ||
    /\b(?:globalThis|global|window|self)\s*\.\s*eval\b/.test(runtimeCode) ||
    /\(\s*0\s*,\s*eval\s*\)/.test(runtimeCode) ||
    /\bnew\s+Function\s*\(/.test(runtimeCode) ||
    /(?<!(?:\.\s*|\?\.\s*|function\s+))\bFunction\s*\(/.test(runtimeCode) ||
    /\.\s*constructor\s*\.\s*constructor\b/.test(runtimeCode)
  ) {
    pushFinding(
      'DYNAMIC_CODE_FORBIDDEN',
      'Dynamic code evaluation (eval, Function constructor) is forbidden inside sealed bricks'
    );
  }

  if (SECRET_LEAK_RE.test(source)) {
    pushFinding(
      'ZERO_LEAK_VIOLATION',
      'Source contains embedded API key prefix, token material, or PEM key header'
    );
  }

  if (LOCAL_FS_DIR_LEAK_RE.test(source)) {
    pushFinding(
      'ZERO_LEAK_VIOLATION',
      'Source contains hardcoded host user or mount filesystem path'
    );
  }

  if (containsPrivateIpv4Literal(source) || PRIVATE_DOMAIN_LEAK_RE.test(source)) {
    pushFinding(
      'ZERO_LEAK_VIOLATION',
      'Source contains hardcoded private network IPv4 or internal domain literal'
    );
  }

  return { ok: findings.length === 0, byteLength, findings };
}

function skipWhitespaceAndComments(code, startIdx) {
  const len = code.length;
  let i = startIdx;
  while (i < len) {
    const ch = code[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      i += 1;
      continue;
    }
    if (ch === '/' && code[i + 1] === '/') {
      i += 2;
      while (i < len && code[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && code[i + 1] === '*') {
      i += 2;
      while (i < len && !(code[i] === '*' && code[i + 1] === '/')) i += 1;
      i = Math.min(len, i + 2);
      continue;
    }
    break;
  }
  return i;
}

function readIdentifierAt(code, idx) {
  if (idx >= code.length || !isIdentStart(code.charCodeAt(idx))) {
    return null;
  }
  let end = idx + 1;
  while (end < code.length && isIdentPart(code.charCodeAt(end))) {
    end += 1;
  }
  return { name: code.slice(idx, end), end };
}

function extractDeclaredBindingNames(code, startIdx) {
  const names = [];
  const len = code.length;
  let i = skipWhitespaceAndComments(code, startIdx);

  const skipLiteral = (idx) => {
    const ch = code[idx];
    if (ch === "'" || ch === '"') {
      let p = idx + 1;
      while (p < len) {
        if (code[p] === '\\') {
          p += 2;
          continue;
        }
        if (code[p] === ch) return p + 1;
        p += 1;
      }
      return len;
    }
    if (ch === '`') {
      let p = idx + 1;
      let depth = 0;
      while (p < len) {
        if (code[p] === '\\') {
          p += 2;
          continue;
        }
        if (code[p] === '`' && depth === 0) return p + 1;
        if (code[p] === '$' && code[p + 1] === '{') {
          depth += 1;
          p += 2;
          continue;
        }
        if (code[p] === '{' && depth > 0) depth += 1;
        else if (code[p] === '}' && depth > 0) depth -= 1;
        p += 1;
      }
      return len;
    }
    return idx + 1;
  };

  const skipInitializer = (fromIdx, insidePattern) => {
    let p = fromIdx;
    let depth = 0;
    while (p < len) {
      p = skipWhitespaceAndComments(code, p);
      if (p >= len) break;
      const ch = code[p];
      if (ch === "'" || ch === '"' || ch === '`') {
        p = skipLiteral(p);
        continue;
      }
      if (ch === '(' || ch === '{' || ch === '[') {
        depth += 1;
        p += 1;
        continue;
      }
      if (ch === ')' || ch === '}' || ch === ']') {
        if (depth === 0) return p;
        depth -= 1;
        p += 1;
        continue;
      }
      if (depth === 0 && (ch === ',' || (!insidePattern && ch === ';'))) {
        return p;
      }
      if (depth === 0 && !insidePattern && ch === '\n') {
        const nextTok = skipWhitespaceAndComments(code, p + 1);
        const nextWord = readIdentifierAt(code, nextTok);
        if (
          nextWord &&
          ['export', 'const', 'let', 'var', 'function', 'async', 'class', 'return'].includes(
            nextWord.name
          )
        ) {
          return p;
        }
      }
      p += 1;
    }
    return p;
  };

  const collectPatternIds = (fromIdx) => {
    let p = skipWhitespaceAndComments(code, fromIdx);
    if (p >= len) return p;
    if (code[p] === '{') {
      p += 1;
      while (p < len) {
        p = skipWhitespaceAndComments(code, p);
        if (code[p] === '}') return p + 1;
        if (code.slice(p, p + 3) === '...') {
          p = collectPatternIds(p + 3);
          continue;
        }
        const keyIdent = readIdentifierAt(code, p);
        if (!keyIdent) {
          p = skipLiteral(p);
          continue;
        }
        p = skipWhitespaceAndComments(code, keyIdent.end);
        if (code[p] === ':') {
          p = collectPatternIds(p + 1);
        } else {
          names.push(keyIdent.name);
        }
        p = skipWhitespaceAndComments(code, p);
        if (code[p] === '=') p = skipInitializer(p + 1, true);
        p = skipWhitespaceAndComments(code, p);
        if (code[p] === ',') p += 1;
      }
      return p;
    }
    if (code[p] === '[') {
      p += 1;
      while (p < len) {
        p = skipWhitespaceAndComments(code, p);
        if (code[p] === ']') return p + 1;
        if (code[p] === ',') {
          p += 1;
          continue;
        }
        if (code.slice(p, p + 3) === '...') {
          p = collectPatternIds(p + 3);
          continue;
        }
        p = collectPatternIds(p);
        p = skipWhitespaceAndComments(code, p);
        if (code[p] === '=') p = skipInitializer(p + 1, true);
        p = skipWhitespaceAndComments(code, p);
        if (code[p] === ',') p += 1;
      }
      return p;
    }
    const id = readIdentifierAt(code, p);
    if (id) {
      names.push(id.name);
      return id.end;
    }
    return p;
  };

  while (i < len) {
    i = collectPatternIds(i);
    i = skipWhitespaceAndComments(code, i);
    if (code[i] === '=') {
      i = skipInitializer(i + 1, false);
    }
    i = skipWhitespaceAndComments(code, i);
    if (code[i] === ',') {
      i = skipWhitespaceAndComments(code, i + 1);
      continue;
    }
    break;
  }

  return names;
}

/**
 * Strip TypeScript types (`module.stripTypeScriptTypes`) and convert top-level ESM `export`
 * declarations into CommonJS `module.exports` / `exports` assignments.
 * @param {string} source
 * @returns {string}
 */
function transpileBrickSourceToCjs(source) {
  let code = String(source ?? '');
  if (typeof nodeModule.stripTypeScriptTypes === 'function') {
    code = nodeModule.stripTypeScriptTypes(code, { mode: 'strip' });
  }

  const len = code.length;
  const edits = [];
  const exportedBindings = [];

  let i = 0;
  let canStartRegex = true;
  let braceDepth = 0;
  let parenDepth = 0;
  let bracketDepth = 0;
  const templateBraceStack = [];

  while (i < len) {
    const ch = code[i];
    const next = i + 1 < len ? code[i + 1] : '';

    if (ch === '/' && next === '/') {
      i += 2;
      while (i < len && code[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len && !(code[i] === '*' && code[i + 1] === '/')) i += 1;
      i = Math.min(len, i + 2);
      continue;
    }
    if (ch === "'" || ch === '"') {
      const q = ch;
      i += 1;
      while (i < len) {
        if (code[i] === '\\') {
          i += 2;
          continue;
        }
        if (code[i] === q) {
          i += 1;
          break;
        }
        i += 1;
      }
      canStartRegex = false;
      continue;
    }
    if (ch === '`') {
      i = consumeTemplateBody(code, i + 1, [], templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > 0;
      continue;
    }
    if (
      ch === '}' &&
      templateBraceStack.length > 0 &&
      braceDepth === templateBraceStack[templateBraceStack.length - 1]
    ) {
      templateBraceStack.pop();
      i = consumeTemplateBody(code, i + 1, [], templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > 0;
      continue;
    }
    if (ch === '/' && canStartRegex && next !== '/' && next !== '*') {
      i += 1;
      let inCharClass = false;
      while (i < len) {
        const c = code[i];
        i += 1;
        if (c === '\\') {
          i += 1;
          continue;
        }
        if (c === '[') inCharClass = true;
        else if (c === ']') inCharClass = false;
        else if (c === '/' && !inCharClass) {
          while (i < len && isIdentPart(code.charCodeAt(i))) i += 1;
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
      while (i < len && isIdentPart(code.charCodeAt(i))) i += 1;
      const word = code.slice(start, i);
      const prevChar = start > 0 ? code[start - 1] : '';

      if (
        word === 'export' &&
        braceDepth === 0 &&
        parenDepth === 0 &&
        bracketDepth === 0 &&
        templateBraceStack.length === 0 &&
        prevChar !== '.'
      ) {
        const afterExport = skipWhitespaceAndComments(code, i);
        if (code[afterExport] === '{') {
          let closeBrace = afterExport + 1;
          while (closeBrace < len && code[closeBrace] !== '}') closeBrace += 1;
          if (closeBrace < len) {
            const rawSpecifiers = stripJsCommentsPreservingLiterals(
              code.slice(afterExport + 1, closeBrace)
            );
            for (const rawPart of rawSpecifiers.split(',')) {
              const part = rawPart.trim();
              if (!part || part.startsWith('type ')) continue;
              const specMatch = /^([A-Za-z_$][A-Za-z0-9_$]*)(?:\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*|default))?$/.exec(
                part
              );
              if (specMatch) {
                exportedBindings.push({
                  localSymbol: specMatch[1],
                  exportedSymbol: specMatch[2] || specMatch[1]
                });
              }
            }
            let stmtEnd = skipWhitespaceAndComments(code, closeBrace + 1);
            if (code[stmtEnd] === ';') stmtEnd += 1;
            edits.push({ start, end: stmtEnd, replacement: '' });
            i = stmtEnd;
            canStartRegex = true;
            continue;
          }
        } else {
          const kw = readIdentifierAt(code, afterExport);
          if (kw?.name === 'default') {
            const afterDefault = skipWhitespaceAndComments(code, kw.end);
            const nextId = readIdentifierAt(code, afterDefault);
            let namedDecl = null;

            if (nextId?.name === 'async') {
              const afterAsync = skipWhitespaceAndComments(code, nextId.end);
              const fnKw = readIdentifierAt(code, afterAsync);
              if (fnKw?.name === 'function') {
                let afterFn = skipWhitespaceAndComments(code, fnKw.end);
                if (code[afterFn] === '*') afterFn = skipWhitespaceAndComments(code, afterFn + 1);
                const fnName = readIdentifierAt(code, afterFn);
                if (fnName) namedDecl = fnName.name;
              }
            } else if (nextId?.name === 'function') {
              let afterFn = skipWhitespaceAndComments(code, nextId.end);
              if (code[afterFn] === '*') afterFn = skipWhitespaceAndComments(code, afterFn + 1);
              const fnName = readIdentifierAt(code, afterFn);
              if (fnName) namedDecl = fnName.name;
            } else if (nextId?.name === 'class') {
              const afterClass = skipWhitespaceAndComments(code, nextId.end);
              const clsName = readIdentifierAt(code, afterClass);
              if (clsName && clsName.name !== 'extends') namedDecl = clsName.name;
            }

            if (namedDecl) {
              edits.push({ start, end: afterDefault, replacement: '' });
              exportedBindings.push({ localSymbol: namedDecl, exportedSymbol: 'default' });
            } else {
              edits.push({ start, end: kw.end, replacement: '__brickCjsTarget.default =' });
            }
            i = kw.end;
            canStartRegex = true;
            continue;
          }

          if (kw?.name === 'async') {
            const afterAsync = skipWhitespaceAndComments(code, kw.end);
            const fnKw = readIdentifierAt(code, afterAsync);
            if (fnKw?.name === 'function') {
              let afterFn = skipWhitespaceAndComments(code, fnKw.end);
              if (code[afterFn] === '*') afterFn = skipWhitespaceAndComments(code, afterFn + 1);
              const fnName = readIdentifierAt(code, afterFn);
              if (fnName) {
                edits.push({ start, end: afterExport, replacement: '' });
                exportedBindings.push({ localSymbol: fnName.name, exportedSymbol: fnName.name });
              }
            }
          } else if (kw?.name === 'function') {
            let afterFn = skipWhitespaceAndComments(code, kw.end);
            if (code[afterFn] === '*') afterFn = skipWhitespaceAndComments(code, afterFn + 1);
            const fnName = readIdentifierAt(code, afterFn);
            if (fnName) {
              edits.push({ start, end: afterExport, replacement: '' });
              exportedBindings.push({ localSymbol: fnName.name, exportedSymbol: fnName.name });
            }
          } else if (kw?.name === 'class') {
            const afterClass = skipWhitespaceAndComments(code, kw.end);
            const clsName = readIdentifierAt(code, afterClass);
            if (clsName) {
              edits.push({ start, end: afterExport, replacement: '' });
              exportedBindings.push({ localSymbol: clsName.name, exportedSymbol: clsName.name });
            }
          } else if (kw?.name === 'const' || kw?.name === 'let' || kw?.name === 'var') {
            const boundNames = extractDeclaredBindingNames(code, kw.end);
            edits.push({ start, end: afterExport, replacement: '' });
            for (const bName of boundNames) {
              exportedBindings.push({ localSymbol: bName, exportedSymbol: bName });
            }
          }
        }
      }

      canStartRegex = REGEX_PRECEDING_KEYWORDS.has(word);
      continue;
    }

    if (ch >= '0' && ch <= '9') {
      while (i < len && (isIdentPart(code.charCodeAt(i)) || code[i] === '.')) i += 1;
      canStartRegex = false;
      continue;
    }

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      i += 1;
      continue;
    }

    if (ch === '{') {
      braceDepth += 1;
      canStartRegex = true;
    } else if (ch === '}') {
      braceDepth = Math.max(0, braceDepth - 1);
      canStartRegex = false;
    } else if (ch === '(') {
      parenDepth += 1;
      canStartRegex = true;
    } else if (ch === ')') {
      parenDepth = Math.max(0, parenDepth - 1);
      canStartRegex = false;
    } else if (ch === '[') {
      bracketDepth += 1;
      canStartRegex = true;
    } else if (ch === ']') {
      bracketDepth = Math.max(0, bracketDepth - 1);
      canStartRegex = false;
    } else if ((ch === '+' && next === '+') || (ch === '-' && next === '-')) {
      i += 2;
      canStartRegex = false;
      continue;
    } else {
      canStartRegex = true;
    }

    i += 1;
  }

  if (edits.length === 0 && exportedBindings.length === 0) {
    return code;
  }

  let cursor = 0;
  const chunks = [
    'const __brickCjsTarget = typeof module !== "undefined" && module && typeof module.exports === "object" ? module.exports : exports;\n'
  ];
  for (const edit of edits) {
    if (edit.start >= cursor) {
      chunks.push(code.slice(cursor, edit.start));
      chunks.push(edit.replacement);
      cursor = edit.end;
    }
  }
  chunks.push(code.slice(cursor));
  chunks.push('\n');
  for (const item of exportedBindings) {
    chunks.push(`__brickCjsTarget[${JSON.stringify(item.exportedSymbol)}] = ${item.localSymbol};\n`);
  }

  return chunks.join('');
}

const VALID_JSON_SCHEMA_TYPES = new Set([
  'object',
  'array',
  'number',
  'integer',
  'string',
  'boolean',
  'null'
]);

function validateJsonSchemaDefinition(schema, label, issues) {
  if (schema === undefined || schema === null) return;
  if (!isPlainObject(schema)) {
    issues.push(`Blueprint ${label} must be a plain JSON Schema object`);
    return;
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (types.length === 0 || types.some((t) => !VALID_JSON_SCHEMA_TYPES.has(String(t)))) {
      issues.push(
        `Blueprint ${label}.type must be one of: ${[...VALID_JSON_SCHEMA_TYPES].join(', ')}`
      );
    }
  }
  if (schema.required !== undefined && !Array.isArray(schema.required)) {
    issues.push(`Blueprint ${label}.required must be an array of property names`);
  }
}

function matchesSchemaType(value, expectedType) {
  if (expectedType === 'null') return value === null;
  if (expectedType === 'boolean') return typeof value === 'boolean';
  if (expectedType === 'string') return typeof value === 'string';
  if (expectedType === 'number') return typeof value === 'number' && Number.isFinite(value);
  if (expectedType === 'integer') return typeof value === 'number' && Number.isInteger(value);
  if (expectedType === 'array') return Array.isArray(value);
  if (expectedType === 'object') return isPlainObject(value);
  return false;
}

function validateMinimalJsonSchema(schema, value, pathLabel = '$') {
  if (!isPlainObject(schema) || Object.keys(schema).length === 0) {
    return { ok: true, issues: [] };
  }
  const issues = [];

  if (schema.type !== undefined) {
    const allowedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!allowedTypes.some((t) => matchesSchemaType(value, t))) {
      issues.push(`${pathLabel} expected type ${allowedTypes.join('|')}`);
      return { ok: false, issues };
    }
  }

  if (Array.isArray(schema.enum)) {
    const targetHash = computeCanonicalHash(value);
    if (!schema.enum.some((item) => computeCanonicalHash(item) === targetHash)) {
      issues.push(`${pathLabel} did not match allowed enum values`);
    }
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    if (typeof schema.minimum === 'number' && value < schema.minimum) {
      issues.push(`${pathLabel} (${value}) is less than minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === 'number' && value > schema.maximum) {
      issues.push(`${pathLabel} (${value}) exceeds maximum ${schema.maximum}`);
    }
  }

  if (typeof value === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) {
      issues.push(`${pathLabel} length (${value.length}) is less than minLength ${schema.minLength}`);
    }
    if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) {
      issues.push(`${pathLabel} length (${value.length}) exceeds maxLength ${schema.maxLength}`);
    }
  }

  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) {
      issues.push(`${pathLabel} item count (${value.length}) is less than minItems ${schema.minItems}`);
    }
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) {
      issues.push(`${pathLabel} item count (${value.length}) exceeds maxItems ${schema.maxItems}`);
    }
    if (isPlainObject(schema.items)) {
      for (let idx = 0; idx < value.length; idx += 1) {
        const sub = validateMinimalJsonSchema(schema.items, value[idx], `${pathLabel}[${idx}]`);
        if (!sub.ok) issues.push(...sub.issues);
      }
    }
  }

  if (isPlainObject(value)) {
    if (Array.isArray(schema.required)) {
      for (const reqKey of schema.required) {
        if (typeof reqKey === 'string' && (!Object.hasOwn(value, reqKey) || value[reqKey] === undefined)) {
          issues.push(`${pathLabel}.${reqKey} is required`);
        }
      }
    }
    if (isPlainObject(schema.properties)) {
      for (const [propKey, propSchema] of Object.entries(schema.properties)) {
        if (Object.hasOwn(value, propKey) && value[propKey] !== undefined) {
          const sub = validateMinimalJsonSchema(propSchema, value[propKey], `${pathLabel}.${propKey}`);
          if (!sub.ok) issues.push(...sub.issues);
        }
      }
    }
    if (schema.additionalProperties === false && isPlainObject(schema.properties)) {
      const allowedProps = new Set(Object.keys(schema.properties));
      for (const actualKey of Object.keys(value)) {
        if (!allowedProps.has(actualKey)) {
          issues.push(`${pathLabel}.${actualKey} is not allowed by additionalProperties: false`);
        }
      }
    }
  }

  return { ok: issues.length === 0, issues };
}

function matchesExpectedSubset(actual, subset) {
  if (!isPlainObject(subset)) {
    return computeCanonicalHash(actual) === computeCanonicalHash(subset);
  }
  if (!isPlainObject(actual)) return false;
  for (const [key, expectedVal] of Object.entries(subset)) {
    if (!Object.hasOwn(actual, key)) return false;
    if (isPlainObject(expectedVal)) {
      if (!matchesExpectedSubset(actual[key], expectedVal)) return false;
    } else if (computeCanonicalHash(actual[key]) !== computeCanonicalHash(expectedVal)) {
      return false;
    }
  }
  return true;
}

function isMemoryExhaustionSignal(stderrText, exitCode, signal) {
  if (
    /heap out of memory|Fatal process out of memory|Allocation failed|zone out of memory|ArrayBuffer allocation failed/i.test(
      stderrText
    )
  ) {
    return true;
  }
  return signal === 'SIGABRT' || exitCode === 134;
}

/**
 * Execute transpiled CJS brick code inside a hermetic `node --permission` subprocess
 * with locked `vm.createContext` (`codeGeneration: { strings: false, wasm: false }`) and `SIGKILL` timeout.
 */
function executeInPermissionSubprocess({
  cjsCode,
  exportName = 'default',
  input,
  binding = {},
  timeoutMs = DEFAULT_SANDBOX_TIMEOUT_MS,
  maxMemoryMb = DEFAULT_SANDBOX_MAX_MEMORY_MB
}) {
  const safeTimeoutMs = Math.max(10, Math.min(30_000, Math.trunc(Number(timeoutMs) || DEFAULT_SANDBOX_TIMEOUT_MS)));
  const safeMaxMemoryMb = Math.max(
    16,
    Math.min(512, Math.trunc(Number(maxMemoryMb) || DEFAULT_SANDBOX_MAX_MEMORY_MB))
  );
  const startNs = process.hrtime.bigint();

  let stdinPayload;
  try {
    stdinPayload = JSON.stringify({
      cjsCode,
      exportName,
      hasUndefinedInput: input === undefined,
      input: input === undefined ? null : input,
      bindingData: binding ?? {},
      vmTimeoutMs: safeTimeoutMs
    });
  } catch (err) {
    return Promise.resolve({
      ok: false,
      code: 'SANDBOX_EXECUTION_ERROR',
      message: `Sandbox input/binding must be JSON-serializable: ${err instanceof Error ? err.message : String(err)}`,
      durationMs: 0
    });
  }

  if (Buffer.byteLength(stdinPayload, 'utf8') > MAX_STDIN_PAYLOAD_BYTES) {
    return Promise.resolve({
      ok: false,
      code: 'SANDBOX_EXECUTION_ERROR',
      message: `Sandbox stdin payload exceeds ${MAX_STDIN_PAYLOAD_BYTES} byte limit`,
      durationMs: 0
    });
  }

  return new Promise((resolve) => {
    let settled = false;
    let killedByWallClock = false;
    let streamOverflow = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const child = spawn(
      process.execPath,
      [
        '--no-warnings',
        '--permission',
        '--disallow-code-generation-from-strings',
        `--max-old-space-size=${safeMaxMemoryMb}`,
        '-e',
        WORKER_BOOTSTRAP_CODE
      ],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { PATH: '' }
      }
    );

    const killTimer = setTimeout(() => {
      killedByWallClock = true;
      try {
        child.kill('SIGKILL');
      } catch {
        // Ignore if exited
      }
    }, safeTimeoutMs + 250);
    killTimer.unref?.();

    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      resolve(outcome);
    };

    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_CHILD_STREAM_BYTES) {
        streamOverflow = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // Ignore
        }
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_CHILD_STREAM_BYTES) {
        stderrChunks.push(chunk);
      }
    });

    child.on('error', (err) => {
      const durationMs = Number((Number(process.hrtime.bigint() - startNs) / 1e6).toFixed(2));
      finish({
        ok: false,
        code: 'SANDBOX_EXECUTION_ERROR',
        message: `Failed to spawn permission sandbox: ${err?.message || String(err)}`,
        durationMs
      });
    });

    child.on('close', (exitCode, signal) => {
      const durationMs = Number((Number(process.hrtime.bigint() - startNs) / 1e6).toFixed(2));
      const stderrText = Buffer.concat(stderrChunks).toString('utf8').trim();
      const stdoutText = Buffer.concat(stdoutChunks).toString('utf8').trim();

      if (streamOverflow || isMemoryExhaustionSignal(stderrText, exitCode, signal)) {
        finish({
          ok: false,
          code: 'SANDBOX_MEMORY_LIMIT',
          message: `Brick execution exceeded memory limit (${safeMaxMemoryMb}MB)`,
          durationMs
        });
        return;
      }

      if (killedByWallClock) {
        finish({
          ok: false,
          code: 'SANDBOX_TIMEOUT',
          message: `Brick execution exceeded sandbox wall-clock timeout (${safeTimeoutMs}ms)`,
          durationMs
        });
        return;
      }

      if (stdoutText.length > 0) {
        const lines = stdoutText.split('\n');
        const lastLine = lines[lines.length - 1];
        try {
          const parsed = JSON.parse(lastLine);
          if (parsed && parsed.ok === true) {
            finish({
              ok: true,
              output: parsed.hasUndefined ? undefined : parsed.output,
              durationMs
            });
            return;
          }
          if (parsed && parsed.ok === false) {
            const code =
              parsed.code === 'SANDBOX_TIMEOUT'
                ? 'SANDBOX_TIMEOUT'
                : parsed.code === 'SANDBOX_MEMORY_LIMIT'
                  ? 'SANDBOX_MEMORY_LIMIT'
                  : 'SANDBOX_EXECUTION_ERROR';
            finish({
              ok: false,
              code,
              message: String(parsed.message || 'Brick execution failed'),
              durationMs
            });
            return;
          }
        } catch {
          // Fall through
        }
      }

      finish({
        ok: false,
        code: 'SANDBOX_EXECUTION_ERROR',
        message:
          stderrText ||
          `Sandbox process exited unexpectedly (code=${String(exitCode)}, signal=${String(signal)})`,
        durationMs
      });
    });

    child.stdin.on('error', () => {
      // Child may exit early before consuming stdin
    });
    child.stdin.end(stdinPayload);
  });
}

function sanitizeBindingForHashing(value, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === 'boolean' || t === 'string') return value;
  if (t === 'number') return Number.isFinite(value) ? (Object.is(value, -0) ? 0 : value) : String(value);
  if (t === 'function') return `[Function:${value.name || 'anonymous'}]`;
  if (t !== 'object') return String(value);
  if (depth > 16) return '[MaxDepth]';
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => sanitizeBindingForHashing(item, depth + 1, seen));
    }
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      if (FORBIDDEN_KEYS.has(key) || value[key] === undefined) continue;
      sorted[key] = sanitizeBindingForHashing(value[key], depth + 1, seen);
    }
    return sorted;
  } finally {
    seen.delete(value);
  }
}

function computeBindingHash(binding) {
  if (binding === null || binding === undefined) return computeCanonicalHash({});
  if (typeof binding === 'string') return computeCanonicalHash(binding);
  if (typeof binding !== 'object') return computeCanonicalHash(String(binding));
  return computeCanonicalHash(sanitizeBindingForHashing(binding));
}

function isPathStrictlyInside(realChild, realParent) {
  return realChild === realParent || realChild.startsWith(`${realParent}${path.sep}`);
}

// ============================================================================
// Deadbolt 2-Hop AST Blast-Radius & Conflict-Free Wave Helpers
// ============================================================================

function normalizeRelativeCodePath(rawPath) {
  const clean = String(rawPath ?? '')
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/+|\/+)+/, '')
    .trim();
  if (!clean || clean === '.' || clean.includes('\0')) return '';
  const normalized = path.posix.normalize(clean);
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../')) {
    return '';
  }
  return normalized;
}

function isSensitiveHostDirectory(absPath) {
  const normalized = path.resolve(absPath).replace(/\\/g, '/');
  return SENSITIVE_SYSTEM_PREFIXES.some(
    (prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`)
  );
}

function isChokePointPath(relPath, chokeSet) {
  if (!relPath) return false;
  if (chokeSet.has(relPath)) return true;
  const base = path.posix.basename(relPath);
  return (base === 'package.json' || base === 'App.jsx' || base === 'App.tsx') && chokeSet.has(base);
}

function stripCommentsPreservingStrings(source) {
  let out = '';
  let i = 0;
  const len = source.length;
  while (i < len) {
    const ch = source[i];
    const next = source[i + 1];
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      out += ch;
      i += 1;
      while (i < len) {
        const c = source[i];
        out += c;
        if (c === '\\' && i + 1 < len) {
          out += source[i + 1];
          i += 2;
          continue;
        }
        i += 1;
        if (c === quote) break;
      }
      continue;
    }
    if (ch === '/' && next === '/') {
      while (i < len && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len && !(source[i] === '*' && source[i + 1] === '/')) {
        if (source[i] === '\n') out += '\n';
        i += 1;
      }
      i += 2;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function parseFileSymbolsAndImports(source, relPath) {
  const ext = path.posix.extname(relPath).toLowerCase();
  const exportsSet = new Set();
  let hasDefaultExport = false;
  const imports = [];

  if (ext === '.py') {
    for (const rawLine of source.split('\n')) {
      const line = rawLine.replace(/#.*$/, '').trim();
      if (!line) continue;
      const defMatch = /^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(line);
      if (defMatch && !defMatch[1].startsWith('_')) exportsSet.add(defMatch[1]);
      const clsMatch = /^class\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
      if (clsMatch && !clsMatch[1].startsWith('_')) exportsSet.add(clsMatch[1]);
      const fromMatch = /^from\s+(\.+[A-Za-z0-9_.]*)\s+import\s+(.+)$/.exec(line);
      if (fromMatch) {
        const names = fromMatch[2]
          .split(',')
          .map((t) => t.trim().split(/\s+as\s+/)[0].trim())
          .filter((t) => t && t !== '*');
        imports.push({ specifier: fromMatch[1], importedNames: names });
      }
    }
    return { exports: [...exportsSet].sort(), hasDefaultExport: false, imports };
  }

  const cleaned = stripCommentsPreservingStrings(source);

  for (const m of cleaned.matchAll(
    /\bexport\s+(?:async\s+)?(?:function\*?|class|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g
  )) {
    exportsSet.add(m[1]);
  }

  if (/\bexport\s+default\b/.test(cleaned) || /\bmodule\.exports\s*=/.test(cleaned)) {
    hasDefaultExport = true;
    exportsSet.add('default');
  }

  for (const m of cleaned.matchAll(/\bexport\s*\{([^}]+)\}(?:\s*from\s*['"]([^'"]+)['"])?/g)) {
    const rawList = m[1];
    const reExportSpec = m[2] || '';
    const importedFromReExport = [];
    for (const part of rawList.split(',')) {
      const trimmed = part.replace(/^\s*type\s+/, '').trim();
      if (!trimmed) continue;
      const segments = trimmed.split(/\s+as\s+/);
      const localName = segments[0].trim();
      const exportedAs = (segments[1] || segments[0]).trim();
      if (exportedAs === 'default') hasDefaultExport = true;
      if (exportedAs) exportsSet.add(exportedAs);
      if (reExportSpec && localName) importedFromReExport.push(localName);
    }
    if (reExportSpec) {
      imports.push({ specifier: reExportSpec, importedNames: importedFromReExport });
    }
  }

  for (const m of cleaned.matchAll(
    /\bexport\s*\*\s*(?:as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+)?from\s*['"]([^'"]+)['"]/g
  )) {
    if (m[1]) exportsSet.add(m[1]);
    imports.push({ specifier: m[2], importedNames: [] });
  }

  for (const m of cleaned.matchAll(/\b(?:module\.)?exports\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=/g)) {
    exportsSet.add(m[1]);
  }

  for (const m of cleaned.matchAll(/\bimport\s+(?!type\b)([\s\S]*?)\s+from\s*['"]([^'"]+)['"]/g)) {
    const clause = m[1].trim();
    const specifier = m[2].trim();
    const names = [];
    const braceMatch = /\{([^}]+)\}/.exec(clause);
    if (braceMatch) {
      for (const item of braceMatch[1].split(',')) {
        const token = item.trim();
        if (!token || /^type\s+/.test(token)) continue;
        const origName = token.split(/\s+as\s+/)[0].trim();
        if (origName) names.push(origName);
      }
    }
    const beforeBrace = clause.replace(/\{[^}]*\}/, '').replace(/,/g, '').trim();
    if (beforeBrace && !beforeBrace.startsWith('*')) {
      names.push('default');
    }
    imports.push({ specifier, importedNames: names });
  }

  for (const m of cleaned.matchAll(/\bimport\s*['"]([^'"]+)['"]/g)) {
    imports.push({ specifier: m[1].trim(), importedNames: [] });
  }
  for (const m of cleaned.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    imports.push({ specifier: m[1].trim(), importedNames: [] });
  }

  return {
    exports: [...exportsSet].sort(),
    hasDefaultExport,
    imports
  };
}

function resolveRelativeImportTarget(importerRelPath, specifier, repoFileSet) {
  if (!specifier) return null;

  if (importerRelPath.endsWith('.py') && specifier.startsWith('.')) {
    const dotsMatch = /^(\.+)(.*)$/.exec(specifier);
    if (!dotsMatch) return null;
    const dotCount = dotsMatch[1].length;
    const modRest = dotsMatch[2].replace(/\./g, '/');
    let baseDir = path.posix.dirname(importerRelPath);
    for (let d = 1; d < dotCount; d += 1) {
      baseDir = path.posix.dirname(baseDir);
    }
    const candidateBase = normalizeRelativeCodePath(path.posix.join(baseDir, modRest));
    for (const cand of [`${candidateBase}.py`, `${candidateBase}/__init__.py`]) {
      if (repoFileSet.has(cand)) return cand;
    }
    return null;
  }

  if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
    return null;
  }

  const importerDir = path.posix.dirname(importerRelPath);
  const rawJoined = normalizeRelativeCodePath(path.posix.join(importerDir, specifier));
  if (!rawJoined) return null;
  if (repoFileSet.has(rawJoined)) return rawJoined;

  if (rawJoined.endsWith('.js')) {
    const stem = rawJoined.slice(0, -3);
    for (const tsExt of ['.ts', '.tsx', '.mjs', '.jsx']) {
      if (repoFileSet.has(`${stem}${tsExt}`)) return `${stem}${tsExt}`;
    }
  }

  for (const suffix of RESOLVE_CANDIDATE_SUFFIXES) {
    const candidate = `${rawJoined}${suffix}`;
    if (repoFileSet.has(candidate)) return candidate;
  }

  return null;
}

function extractRepoAstGraph(realRepoDir, { overlayEdits = {}, maxFiles = 500 } = {}) {
  const fileContents = new Map();

  const walk = (currentDir) => {
    if (fileContents.size >= maxFiles) return;
    const entries = fs
      .readdirSync(currentDir, { withFileTypes: true })
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      if (fileContents.size >= maxFiles) break;
      if (SKIP_SCAN_DIRECTORIES.has(entry.name)) continue;

      const candidateAbs = path.join(currentDir, entry.name);
      let realCandidate;
      try {
        realCandidate = fs.realpathSync(candidateAbs);
      } catch {
        continue;
      }
      if (!isPathStrictlyInside(realCandidate, realRepoDir)) continue;

      let st;
      try {
        st = fs.statSync(realCandidate);
      } catch {
        continue;
      }

      if (st.isDirectory()) {
        walk(realCandidate);
      } else if (st.isFile() && st.size <= 524_288) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!SCANNABLE_CODE_EXTENSIONS.has(ext)) continue;
        const relPath = normalizeRelativeCodePath(path.relative(realRepoDir, realCandidate));
        if (!relPath) continue;
        fileContents.set(relPath, fs.readFileSync(realCandidate, 'utf8'));
      }
    }
  };

  walk(realRepoDir);

  for (const [rawEditPath, newContent] of Object.entries(overlayEdits)) {
    const norm = normalizeRelativeCodePath(rawEditPath);
    if (norm && typeof newContent === 'string') {
      fileContents.set(norm, newContent);
    }
  }

  const repoFileSet = new Set(fileContents.keys());
  const symbolsByFile = {};
  const edges = [];
  const seenEdgeKey = new Set();

  for (const [relPath, content] of fileContents.entries()) {
    const parsed = parseFileSymbolsAndImports(content, relPath);
    symbolsByFile[relPath] = {
      exports: parsed.exports,
      hasDefaultExport: parsed.hasDefaultExport
    };

    for (const imp of parsed.imports) {
      const target = resolveRelativeImportTarget(relPath, imp.specifier, repoFileSet);
      if (!target || target === relPath) continue;
      const key = `${relPath}=>${target}`;
      if (seenEdgeKey.has(key)) {
        const existing = edges.find((e) => e.from === relPath && e.to === target);
        if (existing) {
          existing.importedNames = [...new Set([...existing.importedNames, ...imp.importedNames])].sort();
        }
        continue;
      }
      seenEdgeKey.add(key);
      edges.push({
        from: relPath,
        to: target,
        importedNames: [...new Set(imp.importedNames)].sort()
      });
    }
  }

  edges.sort((a, b) => (a.from !== b.from ? a.from.localeCompare(b.from) : a.to.localeCompare(b.to)));

  return {
    files: [...repoFileSet].sort(),
    symbolsByFile,
    edges
  };
}

function buildCausalHopChains(changedFiles, edges, chokeSet) {
  const inbound = new Map();
  for (const edge of edges) {
    if (!inbound.has(edge.to)) inbound.set(edge.to, new Set());
    inbound.get(edge.to).add(edge.from);
  }

  const hop0Set = new Set(changedFiles.map(normalizeRelativeCodePath).filter(Boolean));
  const hop1Set = new Set();
  const hop2Set = new Set();
  const hopPaths = [];

  for (const h0 of hop0Set) {
    const callers1 = [...(inbound.get(h0) || [])].sort();
    for (const h1 of callers1) {
      if (hop0Set.has(h1)) continue;
      hop1Set.add(h1);
      const callers2 = [...(inbound.get(h1) || [])].sort();
      let pushedTwoHop = false;
      if (!isChokePointPath(h1, chokeSet)) {
        for (const h2 of callers2) {
          if (hop0Set.has(h2) || hop1Set.has(h2)) continue;
          hop2Set.add(h2);
          hopPaths.push(`${h0} -> ${h1} -> ${h2}`);
          pushedTwoHop = true;
        }
      }
      if (!pushedTwoHop) {
        hopPaths.push(`${h0} -> ${h1}`);
      }
    }
  }

  return {
    hop0Files: [...hop0Set].sort(),
    hop1Dependents: [...hop1Set].sort(),
    hop2Dependents: [...hop2Set].sort(),
    hopPaths: [...new Set(hopPaths)]
  };
}

function planDisjointWaves({ tasks, edges, chokeSet }) {
  const inboundCallers = new Map();
  for (const edge of edges) {
    if (!inboundCallers.has(edge.to)) inboundCallers.set(edge.to, new Set());
    inboundCallers.get(edge.to).add(edge.from);
  }

  const reservedOrchestratorFiles = new Set();
  const leases = tasks.map((task, idx) => {
    const taskId = String(task?.id ?? task?.workOrderId ?? `TASK-${idx + 1}`).trim() || `TASK-${idx + 1}`;
    const title = String(task?.title ?? taskId).trim() || taskId;
    const rawTargets = Array.isArray(task?.targetFiles)
      ? task.targetFiles
      : Array.isArray(task?.files)
        ? task.files
        : [];

    const targetFiles = [];
    const seenTarget = new Set();
    for (const rawFile of rawTargets) {
      const norm = normalizeRelativeCodePath(rawFile);
      if (norm && !seenTarget.has(norm)) {
        seenTarget.add(norm);
        targetFiles.push(norm);
      }
    }

    const coneSet = new Set(targetFiles);
    const hop1Dependents = new Set();
    const hop2Dependents = new Set();
    const touchedChokePoints = new Set();

    for (const tf of targetFiles) {
      if (isChokePointPath(tf, chokeSet)) {
        touchedChokePoints.add(tf);
        reservedOrchestratorFiles.add(tf);
      }

      for (const c1 of inboundCallers.get(tf) || []) {
        if (isChokePointPath(c1, chokeSet)) {
          touchedChokePoints.add(c1);
          reservedOrchestratorFiles.add(c1);
          continue;
        }
        coneSet.add(c1);
        if (!seenTarget.has(c1)) hop1Dependents.add(c1);

        for (const c2 of inboundCallers.get(c1) || []) {
          if (isChokePointPath(c2, chokeSet)) {
            touchedChokePoints.add(c2);
            reservedOrchestratorFiles.add(c2);
          } else if (c2 !== tf && !seenTarget.has(c2) && !hop1Dependents.has(c2)) {
            hop2Dependents.add(c2);
            coneSet.add(c2);
          }
        }
      }
    }

    for (const cp of touchedChokePoints) {
      if (!seenTarget.has(cp)) coneSet.delete(cp);
    }

    return {
      taskId,
      title,
      targetFiles,
      hop1Dependents: [...hop1Dependents].sort(),
      hop2Dependents: [...hop2Dependents].sort(),
      leaseCone: [...coneSet].sort(),
      reservedChokePoints: [...touchedChokePoints].sort(),
      wave: 1
    };
  });

  const waveBuckets = [];
  for (const lease of leases) {
    let assignedIdx = -1;
    for (let w = 0; w < waveBuckets.length; w += 1) {
      if (!lease.leaseCone.some((f) => waveBuckets[w].files.has(f))) {
        assignedIdx = w;
        break;
      }
    }
    if (assignedIdx === -1) {
      assignedIdx = waveBuckets.length;
      waveBuckets.push({ wave: assignedIdx + 1, taskIds: [], files: new Set() });
    }
    lease.wave = assignedIdx + 1;
    waveBuckets[assignedIdx].taskIds.push(lease.taskId);
    for (const f of lease.leaseCone) waveBuckets[assignedIdx].files.add(f);
  }

  const collisions = [];
  for (let i = 0; i < leases.length; i += 1) {
    const setA = new Set(leases[i].leaseCone);
    for (let j = i + 1; j < leases.length; j += 1) {
      const sharedFiles = leases[j].leaseCone.filter((f) => setA.has(f));
      if (sharedFiles.length > 0) {
        collisions.push({
          tasks: [leases[i].taskId, leases[j].taskId],
          sharedFiles
        });
      }
    }
  }

  const waves = waveBuckets.map((b) => ({
    wave: b.wave,
    taskIds: b.taskIds,
    parallelizable: b.taskIds.length > 1,
    leasedFileCount: b.files.size
  }));

  return {
    taskCount: leases.length,
    waveCount: waves.length,
    fullyParallelSingleWave: waves.length <= 1 && collisions.length === 0,
    waves,
    leases,
    collisions,
    reservedOrchestratorFiles: [...reservedOrchestratorFiles].sort()
  };
}

/**
 * Run an inline ESM invariant script inside `node --permission --allow-fs-read=<stageDir>`
 * with zero write, child-process, or network access and hard `SIGKILL` timeout.
 */
function runStagedPermissionScript({ stageDir, script, timeoutMs = 5000 }) {
  const realStageDir = fs.realpathSync(path.resolve(stageDir));
  const safeTimeoutMs = Math.max(50, Math.min(60_000, Math.trunc(Number(timeoutMs) || 5000)));
  const permFlag = process.allowedNodeEnvironmentFlags?.has('--permission')
    ? '--permission'
    : '--experimental-permission';
  const marker = `${SANDBOX_JSON_MARKER_PREFIX}${crypto.randomBytes(12).toString('hex')}:`;

  const wrappedScript = [
    'const __rawStdoutWrite = process.stdout.write.bind(process.stdout);',
    `const __MARKER = ${JSON.stringify(marker)};`,
    'globalThis.__emitResult = (payload) => {',
    '  __rawStdoutWrite(`\\n${__MARKER}${JSON.stringify(payload ?? null)}\\n`);',
    '};',
    script
  ].join('\n');

  const execArgs = [
    permFlag,
    `--allow-fs-read=${realStageDir}`,
    `--allow-fs-read=${path.dirname(process.execPath)}`,
    '--input-type=module',
    '-e',
    wrappedScript
  ];

  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const child = spawn(process.execPath, execArgs, {
      cwd: realStageDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: '',
        CI: 'true',
        FORCE_COLOR: '0',
        NODE_NO_WARNINGS: '1'
      }
    });

    const killTimer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGKILL');
      } catch {
        // Ignore
      }
    }, safeTimeoutMs);
    killTimer.unref?.();

    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      resolve(outcome);
    };

    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes <= MAX_CHILD_STREAM_BYTES) stdoutChunks.push(chunk);
    });

    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAX_CHILD_STREAM_BYTES) stderrChunks.push(chunk);
    });

    child.on('error', (err) => {
      finish({
        passed: false,
        exitCode: -1,
        timedOut: false,
        stdout: '',
        stderr: String(err?.message || err)
      });
    });

    child.on('close', (exitCode) => {
      const rawStdout = Buffer.concat(stdoutChunks).toString('utf8');
      const rawStderr = Buffer.concat(stderrChunks).toString('utf8').trim();
      let resultPayload = undefined;
      let cleanStdout = rawStdout;

      const markerIdx = rawStdout.lastIndexOf(marker);
      if (markerIdx !== -1) {
        const afterMarker = rawStdout.slice(markerIdx + marker.length);
        const nlIdx = afterMarker.indexOf('\n');
        const jsonLine = (nlIdx === -1 ? afterMarker : afterMarker.slice(0, nlIdx)).trim();
        try {
          resultPayload = JSON.parse(jsonLine);
        } catch {
          resultPayload = undefined;
        }
        cleanStdout = rawStdout.slice(0, markerIdx).trim();
      } else {
        cleanStdout = rawStdout.trim();
      }

      finish({
        passed: !timedOut && exitCode === 0,
        exitCode: typeof exitCode === 'number' ? exitCode : -1,
        timedOut,
        stdout: cleanStdout,
        stderr: rawStderr,
        ...(resultPayload !== undefined ? { result: resultPayload } : {})
      });
    });
  });
}

function normalizeStringArray(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const item of raw) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function parseJsonArraySafe(rawJson) {
  if (typeof rawJson !== 'string' || !rawJson.trim()) return [];
  try {
    const parsed = JSON.parse(rawJson);
    return Array.isArray(parsed) ? parsed.filter((v) => typeof v === 'string') : [];
  } catch {
    return [];
  }
}

// ============================================================================
// Brick Exchange & Deadbolt 2-Hop Blast-Radius Engine Factory
// ============================================================================

/**
 * Create the standalone SQLite-backed Validated Brick Exchange & Deadbolt 2-Hop Blast-Radius Engine.
 * @param {object} [options={}]
 * @param {import('node:sqlite').DatabaseSync} [options.db]
 * @param {string} [options.workspaceRoot=process.cwd()]
 */
export function createBrickExchangeEngine({ db, workspaceRoot = process.cwd() } = {}) {
  const activeDb = db || openStackDatabase({ ephemeral: true });
  const defaultRoot = path.resolve(workspaceRoot || process.cwd());

  activeDb.exec(BRICK_EXCHANGE_SCHEMA_SQL);

  function persistVerifiedBundle(bundle) {
    const brickKey = `${bundle.brickId}:${bundle.lineage.sourceHash}`;
    const parsedCreatedMs = Date.parse(bundle.createdAt);
    const createdAtMs = Number.isFinite(parsedCreatedMs) ? Math.trunc(parsedCreatedMs) : Date.now();
    const capabilitiesJson = JSON.stringify(
      Array.isArray(bundle.capabilities) ? bundle.capabilities.map(String) : []
    );
    const hoursSaved = Number.isFinite(Number(bundle.estimatedHoursSaved))
      ? Math.max(0, Number(bundle.estimatedHoursSaved))
      : 0;

    activeDb
      .prepare(
        `INSERT INTO brick_exchange_bricks (
          brick_key, brick_id, source_hash, name, summary, brick_class,
          author_id, org_id, key_id, capabilities_json, bundle_json,
          estimated_hours_saved, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(brick_key) DO UPDATE SET
          name = excluded.name,
          summary = excluded.summary,
          brick_class = excluded.brick_class,
          author_id = excluded.author_id,
          org_id = excluded.org_id,
          key_id = excluded.key_id,
          capabilities_json = excluded.capabilities_json,
          bundle_json = excluded.bundle_json,
          estimated_hours_saved = excluded.estimated_hours_saved,
          created_at_ms = excluded.created_at_ms`
      )
      .run(
        brickKey,
        bundle.brickId,
        bundle.lineage.sourceHash,
        bundle.name || bundle.brickId,
        bundle.summary || '',
        bundle.brickClass || 'general',
        bundle.authorId,
        bundle.orgId,
        bundle.attestation.keyId,
        capabilitiesJson,
        JSON.stringify(bundle),
        hoursSaved,
        createdAtMs
      );

    return { brickKey, createdAtMs };
  }

  /**
   * 4-gate pre-seal verification + Ed25519 lineage sealing (optionally publishing into SQLite).
   */
  async function sealBrick({
    blueprint,
    ontology = undefined,
    source,
    positiveChecks = [],
    faultChecks = [],
    authorId = 'local-author',
    orgId = 'local-team',
    brickClass = 'general',
    capabilities = [],
    replacesBoilerplate = '',
    estimatedHoursSaved = 4,
    privateKeyPem = '',
    publish = false,
    timeoutMs = DEFAULT_SANDBOX_TIMEOUT_MS,
    maxMemoryMb = DEFAULT_SANDBOX_MAX_MEMORY_MB
  } = {}) {
    const tool = 'krusch_brick_seal';

    // Gate 1: Zero-Ambient-I/O & Zero-Leak Safety Scan
    const safety = scanBrickSourceSafety(source);
    if (!safety.ok) {
      const repairHints = safety.findings.map((f) => ({
        gate: 'safety',
        checkName: f.ruleId,
        message: f.message,
        counterexample: null
      }));
      return failEnvelope(tool, 'BRICK_SAFETY_FAILED', safety.findings[0].message, {
        gates: {
          safety: { passed: false, findings: safety.findings },
          contract: { passed: false, skipped: true },
          checks_and_fault_challenges: { passed: false, skipped: true }
        },
        checks: [],
        repairHints
      });
    }

    // Gate 2: Blueprint, Ontology & JSON Schema Contract Check
    if (isPlainObject(blueprint)) {
      const badBpKey = hasForbiddenKeyRecursive(blueprint);
      if (badBpKey) {
        return failEnvelope(
          tool,
          badBpKey.startsWith('__') ? 'BRICK_VERIFICATION_FAILED' : 'ONTOLOGY_FORBIDDEN_KEY',
          `Blueprint rejected unsafe key or depth/cycle violation (${badBpKey})`,
          { key: badBpKey }
        );
      }
    }

    let normalizedSealOntology = null;
    if (ontology !== undefined || (isPlainObject(blueprint) && blueprint.ontology !== undefined)) {
      if (ontology !== undefined && ontology !== null && !isPlainObject(ontology)) {
        return failEnvelope(
          tool,
          'INVALID_ONTOLOGY_METADATA',
          'ontology option must be a plain object when provided'
        );
      }
      if (
        isPlainObject(blueprint) &&
        blueprint.ontology !== undefined &&
        blueprint.ontology !== null &&
        !isPlainObject(blueprint.ontology)
      ) {
        return failEnvelope(
          tool,
          'INVALID_ONTOLOGY_METADATA',
          'blueprint.ontology must be a plain object when provided'
        );
      }
      const mergedRawOntology = {
        ...(isPlainObject(blueprint?.ontology) ? blueprint.ontology : {}),
        ...(isPlainObject(ontology) ? ontology : {})
      };
      const normOntRes = normalizeBrickOntology(mergedRawOntology, {
        source,
        blueprint: isPlainObject(blueprint) ? blueprint : {}
      });
      if (!normOntRes.ok) {
        return failEnvelope(
          tool,
          normOntRes.error.code,
          normOntRes.error.message,
          normOntRes.error.details || null
        );
      }
      normalizedSealOntology = normOntRes.data.ontology;
    }
    const contractIssues = [];
    if (!isPlainObject(blueprint)) {
      contractIssues.push('blueprint must be a plain object');
    } else if (typeof blueprint.id !== 'string' || !BRICK_ID_RE.test(blueprint.id.trim())) {
      contractIssues.push(
        'blueprint.id must match /^[a-z0-9][a-z0-9-_]{1,63}$/'
      );
    }
    if (!isSafeIdentifier(authorId)) {
      contractIssues.push('authorId must be a valid safe identifier');
    }
    if (!isSafeIdentifier(orgId)) {
      contractIssues.push('orgId must be a valid safe identifier');
    }
    if (!isSafeIdentifier(String(brickClass || '').trim())) {
      contractIssues.push('brickClass must be a valid safe identifier');
    }
    if (isPlainObject(blueprint)) {
      validateJsonSchemaDefinition(blueprint.inputSchema, 'inputSchema', contractIssues);
      validateJsonSchemaDefinition(blueprint.outputSchema, 'outputSchema', contractIssues);
      validateJsonSchemaDefinition(blueprint.bindingSchema, 'bindingSchema', contractIssues);
    }
    if (!Array.isArray(positiveChecks) || positiveChecks.length < 1) {
      contractIssues.push('At least one positive verification check (positiveChecks) is required');
    }

    if (contractIssues.length > 0) {
      const repairHints = contractIssues.map((msg) => ({
        gate: 'contract',
        checkName: 'blueprint',
        message: msg,
        counterexample: null
      }));
      return failEnvelope(tool, 'BRICK_VERIFICATION_FAILED', contractIssues[0], {
        gates: {
          safety: { passed: true, byteLength: safety.byteLength, findings: [] },
          contract: { passed: false, issues: contractIssues },
          checks_and_fault_challenges: { passed: false, skipped: true }
        },
        checks: [],
        repairHints
      });
    }

    if (!Array.isArray(faultChecks) || faultChecks.length < 1) {
      const faultMsg =
        'At least one adversarial fault-injection check (faultChecks) is required to seal a brick';
      return failEnvelope(tool, 'MISSING_FAULT_CHALLENGE', faultMsg, {
        gates: {
          safety: { passed: true, byteLength: safety.byteLength, findings: [] },
          contract: { passed: true, issues: [] },
          checks_and_fault_challenges: {
            passed: false,
            code: 'MISSING_FAULT_CHALLENGE',
            message: faultMsg
          }
        },
        checks: [],
        faultChallengeCount: 0,
        repairHints: [
          {
            gate: 'checks_and_fault_challenges',
            checkName: 'faultChecks',
            message: `${faultMsg}; include corrupted, missing-field, or out-of-range fault inputs.`,
            counterexample: { faultChecksCount: 0 }
          }
        ]
      });
    }

    let cjsCode;
    try {
      cjsCode = transpileBrickSourceToCjs(source);
      // Pre-validate transpiled syntax deterministically before spawning child processes
      new vm.Script(cjsCode, { filename: 'brick.syntax-check.cjs' });
    } catch (syntaxErr) {
      const synMsg = `Brick source failed TypeScript/ESM syntax compilation: ${
        syntaxErr instanceof Error ? syntaxErr.message : String(syntaxErr)
      }`;
      return failEnvelope(tool, 'BRICK_SYNTAX_ERROR', synMsg, {
        repairHints: [
          {
            gate: 'contract',
            checkName: 'syntax',
            message: synMsg,
            counterexample: null
          }
        ]
      });
    }

    // Gate 3: Positive Checks + Adversarial Fault-Injection Challenges in `--permission` Sandbox
    const exportName =
      typeof blueprint.exportName === 'string' && blueprint.exportName.trim()
        ? blueprint.exportName.trim()
        : 'default';

    const checks = [];
    const repairHints = [];

    for (let idx = 0; idx < positiveChecks.length; idx += 1) {
      const check = isPlainObject(positiveChecks[idx]) ? positiveChecks[idx] : {};
      const checkName =
        typeof check.name === 'string' && check.name.trim() ? check.name.trim() : `positive_${idx + 1}`;

      if (blueprint.inputSchema && !check.skipInputSchema) {
        const inValid = validateMinimalJsonSchema(blueprint.inputSchema, check.input, 'input');
        if (!inValid.ok) {
          const detail = `Check input failed blueprint.inputSchema: ${inValid.issues.join('; ')}`;
          checks.push({ name: checkName, kind: 'positive', passed: false, durationMs: 0, detail });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: check.input, schemaIssues: inValid.issues }
          });
          continue;
        }
      }

      const execRes = await executeInPermissionSubprocess({
        cjsCode,
        exportName,
        input: check.input,
        binding: check.binding ?? {},
        timeoutMs: check.timeoutMs ?? timeoutMs,
        maxMemoryMb
      });

      if (!execRes.ok) {
        const detail = `Execution failed (${execRes.code}): ${execRes.message}`;
        checks.push({
          name: checkName,
          kind: 'positive',
          passed: false,
          durationMs: execRes.durationMs,
          detail
        });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: { input: check.input, errorCode: execRes.code, errorMessage: execRes.message }
        });
        continue;
      }

      const targetOutputSchema = check.outputSchemaOverride || blueprint.outputSchema;
      if (targetOutputSchema) {
        const outValid = validateMinimalJsonSchema(targetOutputSchema, execRes.output, 'output');
        if (!outValid.ok) {
          const detail = `Output failed outputSchema validation: ${outValid.issues.join('; ')}`;
          checks.push({
            name: checkName,
            kind: 'positive',
            passed: false,
            durationMs: execRes.durationMs,
            detail,
            actualOutput: execRes.output
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: check.input, actualOutput: execRes.output, schemaIssues: outValid.issues }
          });
          continue;
        }
      }

      if (
        check.expectedOutput !== undefined &&
        computeCanonicalHash(execRes.output) !== computeCanonicalHash(check.expectedOutput)
      ) {
        const detail = 'Output did not match expectedOutput';
        checks.push({
          name: checkName,
          kind: 'positive',
          passed: false,
          durationMs: execRes.durationMs,
          detail,
          actualOutput: execRes.output
        });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: {
            input: check.input,
            expectedOutput: check.expectedOutput,
            actualOutput: execRes.output
          }
        });
        continue;
      }

      if (isPlainObject(check.expectedSubset) && !matchesExpectedSubset(execRes.output, check.expectedSubset)) {
        const detail = 'Output did not match expectedSubset';
        checks.push({
          name: checkName,
          kind: 'positive',
          passed: false,
          durationMs: execRes.durationMs,
          detail,
          actualOutput: execRes.output
        });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: {
            input: check.input,
            expectedSubset: check.expectedSubset,
            actualOutput: execRes.output
          }
        });
        continue;
      }

      if (typeof check.assertFn === 'function') {
        let passedAssert = false;
        let assertErrMsg = '';
        try {
          passedAssert = Boolean(await check.assertFn(execRes.output));
        } catch (err) {
          assertErrMsg = err instanceof Error ? err.message : String(err);
        }
        if (!passedAssert) {
          const detail = assertErrMsg ? `Custom assertFn threw: ${assertErrMsg}` : 'Custom assertFn returned false';
          checks.push({
            name: checkName,
            kind: 'positive',
            passed: false,
            durationMs: execRes.durationMs,
            detail,
            actualOutput: execRes.output
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: check.input, actualOutput: execRes.output }
          });
          continue;
        }
      }

      checks.push({
        name: checkName,
        kind: 'positive',
        passed: true,
        durationMs: execRes.durationMs,
        actualOutput: execRes.output
      });
    }

    for (let idx = 0; idx < faultChecks.length; idx += 1) {
      const fault = isPlainObject(faultChecks[idx]) ? faultChecks[idx] : {};
      const checkName =
        typeof fault.name === 'string' && fault.name.trim() ? fault.name.trim() : `fault_${idx + 1}`;

      const hasStructuredExpectation =
        fault.expectedOutput !== undefined ||
        isPlainObject(fault.expectedSubset) ||
        typeof fault.assertFn === 'function';

      const expectThrow =
        fault.expectThrow === true ||
        fault.shouldThrow === true ||
        (typeof fault.expectedErrorSubstring === 'string' &&
          fault.expectedErrorSubstring.length > 0 &&
          !hasStructuredExpectation) ||
        (fault.expectThrow === undefined &&
          fault.shouldThrow === undefined &&
          !hasStructuredExpectation);

      if (!expectThrow && !hasStructuredExpectation) {
        const detail =
          'Fault check must specify expectThrow: true or expectedOutput / expectedSubset / assertFn';
        checks.push({ name: checkName, kind: 'fault', passed: false, durationMs: 0, detail });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: { input: fault.input }
        });
        continue;
      }

      const execRes = await executeInPermissionSubprocess({
        cjsCode,
        exportName,
        input: fault.input,
        binding: fault.binding ?? {},
        timeoutMs: fault.timeoutMs ?? timeoutMs,
        maxMemoryMb
      });

      if (expectThrow) {
        if (execRes.ok) {
          const detail =
            'Fault challenge expected brick to reject/throw on corrupted input, but execution succeeded silently';
          checks.push({
            name: checkName,
            kind: 'fault',
            passed: false,
            durationMs: execRes.durationMs,
            detail,
            actualOutput: execRes.output
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: fault.input, actualOutput: execRes.output, expectedThrow: true }
          });
          continue;
        }

        if (execRes.code === 'SANDBOX_TIMEOUT' || execRes.code === 'SANDBOX_MEMORY_LIMIT') {
          const detail = `Fault challenge triggered ${execRes.code} instead of cleanly rejecting corrupted input: ${execRes.message}`;
          checks.push({
            name: checkName,
            kind: 'fault',
            passed: false,
            durationMs: execRes.durationMs,
            detail
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: fault.input, errorCode: execRes.code }
          });
          continue;
        }

        if (
          typeof fault.expectedErrorSubstring === 'string' &&
          fault.expectedErrorSubstring.length > 0 &&
          !String(execRes.message || '')
            .toLowerCase()
            .includes(fault.expectedErrorSubstring.toLowerCase())
        ) {
          const detail = `Thrown error "${execRes.message}" did not include expected substring "${fault.expectedErrorSubstring}"`;
          checks.push({
            name: checkName,
            kind: 'fault',
            passed: false,
            durationMs: execRes.durationMs,
            detail
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: {
              input: fault.input,
              expectedErrorSubstring: fault.expectedErrorSubstring,
              actualErrorMessage: execRes.message
            }
          });
          continue;
        }

        checks.push({
          name: checkName,
          kind: 'fault',
          passed: true,
          durationMs: execRes.durationMs,
          detail: `Cleanly rejected corrupted input: ${execRes.message}`
        });
        continue;
      }

      if (!execRes.ok) {
        const detail = `Fault challenge threw unexpectedly (${execRes.code}): ${execRes.message}`;
        checks.push({
          name: checkName,
          kind: 'fault',
          passed: false,
          durationMs: execRes.durationMs,
          detail
        });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: { input: fault.input, errorCode: execRes.code, errorMessage: execRes.message }
        });
        continue;
      }

      const targetOutputSchema = fault.outputSchemaOverride || blueprint.outputSchema;
      if (targetOutputSchema) {
        const outValid = validateMinimalJsonSchema(targetOutputSchema, execRes.output, 'output');
        if (!outValid.ok) {
          const detail = `Fault challenge output violated outputSchema: ${outValid.issues.join('; ')}`;
          checks.push({
            name: checkName,
            kind: 'fault',
            passed: false,
            durationMs: execRes.durationMs,
            detail,
            actualOutput: execRes.output
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: fault.input, actualOutput: execRes.output, schemaIssues: outValid.issues }
          });
          continue;
        }
      }

      if (
        fault.expectedOutput !== undefined &&
        computeCanonicalHash(execRes.output) !== computeCanonicalHash(fault.expectedOutput)
      ) {
        const detail = 'Fault challenge output did not match expectedOutput';
        checks.push({
          name: checkName,
          kind: 'fault',
          passed: false,
          durationMs: execRes.durationMs,
          detail,
          actualOutput: execRes.output
        });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: {
            input: fault.input,
            expectedOutput: fault.expectedOutput,
            actualOutput: execRes.output
          }
        });
        continue;
      }

      if (isPlainObject(fault.expectedSubset) && !matchesExpectedSubset(execRes.output, fault.expectedSubset)) {
        const detail = 'Fault challenge output did not match expectedSubset';
        checks.push({
          name: checkName,
          kind: 'fault',
          passed: false,
          durationMs: execRes.durationMs,
          detail,
          actualOutput: execRes.output
        });
        repairHints.push({
          gate: 'checks_and_fault_challenges',
          checkName,
          message: detail,
          counterexample: {
            input: fault.input,
            expectedSubset: fault.expectedSubset,
            actualOutput: execRes.output
          }
        });
        continue;
      }

      if (typeof fault.assertFn === 'function') {
        let passedAssert = false;
        let assertErrMsg = '';
        try {
          passedAssert = Boolean(await fault.assertFn(execRes.output));
        } catch (err) {
          assertErrMsg = err instanceof Error ? err.message : String(err);
        }
        if (!passedAssert) {
          const detail = assertErrMsg
            ? `Fault check assertFn threw: ${assertErrMsg}`
            : 'Fault check assertFn returned false';
          checks.push({
            name: checkName,
            kind: 'fault',
            passed: false,
            durationMs: execRes.durationMs,
            detail,
            actualOutput: execRes.output
          });
          repairHints.push({
            gate: 'checks_and_fault_challenges',
            checkName,
            message: detail,
            counterexample: { input: fault.input, actualOutput: execRes.output }
          });
          continue;
        }
      }

      checks.push({
        name: checkName,
        kind: 'fault',
        passed: true,
        durationMs: execRes.durationMs,
        actualOutput: execRes.output
      });
    }

    const passedCount = checks.filter((c) => c.passed).length;
    if (passedCount !== checks.length || repairHints.length > 0) {
      return failEnvelope(
        tool,
        'BRICK_VERIFICATION_FAILED',
        `${passedCount} of ${checks.length} verification check(s) passed`,
        {
          gates: {
            safety: { passed: true, byteLength: safety.byteLength, findings: [] },
            contract: { passed: true, issues: [] },
            checks_and_fault_challenges: {
              passed: false,
              passedCount,
              totalCount: checks.length,
              positiveCount: positiveChecks.length,
              faultChallengeCount: faultChecks.length
            }
          },
          checks,
          passedCount,
          totalCount: checks.length,
          faultChallengeCount: faultChecks.length,
          repairHints
        }
      );
    }

    // Gate 4: Ed25519 Lineage Sealing
    let activePrivateKeyPem = typeof privateKeyPem === 'string' ? privateKeyPem.trim() : '';
    let keyPairGenerated = false;
    if (!activePrivateKeyPem) {
      const keyRes = generateEd25519BrickKeys();
      activePrivateKeyPem = keyRes.data.privateKeyPem;
      keyPairGenerated = true;
    }

    let privKey;
    let publicKeyPem;
    let keyId;
    try {
      privKey = crypto.createPrivateKey(activePrivateKeyPem);
      if (privKey.asymmetricKeyType !== 'ed25519') {
        return failEnvelope(
          tool,
          'INVALID_SIGNING_KEY',
          'Signing privateKeyPem must be an Ed25519 key'
        );
      }
      const exportedPub = crypto.createPublicKey(privKey).export({ type: 'spki', format: 'pem' });
      publicKeyPem = typeof exportedPub === 'string' ? exportedPub : exportedPub.toString('utf8');
      keyId = derivePublicKeyId(publicKeyPem);
    } catch (err) {
      return failEnvelope(
        tool,
        'INVALID_SIGNING_KEY',
        `Invalid Ed25519 privateKeyPem: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // SEC-02: Embed normalized ontology into blueprint.ontology BEFORE computing blueprintHash & mirror on bundle.ontology!
    const normalizedBlueprint = {
      ...blueprint,
      id: blueprint.id.trim(),
      ...(normalizedSealOntology ? { ontology: normalizedSealOntology } : {})
    };
    const frozenBlueprint = deepFreezeClone(normalizedBlueprint);
    const sourceHash = computeCanonicalHash(source);
    const blueprintHash = computeCanonicalHash(frozenBlueprint);
    const contractHash = computeCanonicalHash(extractContractShape(frozenBlueprint));
    const checksSummary = Object.freeze(
      checks.map((c) =>
        Object.freeze({
          name: String(c.name),
          kind: String(c.kind),
          passed: Boolean(c.passed)
        })
      )
    );
    const checksHash = computeCanonicalHash(checksSummary);
    const faultChallengeCount = checksSummary.filter((c) => c.kind === 'fault').length;
    const createdAt = new Date().toISOString();

    const lineage = Object.freeze({
      standard: LINEAGE_STANDARD,
      brickId: frozenBlueprint.id,
      requirementId: null,
      blueprintHash,
      contractHash,
      sourceHash,
      checksHash,
      faultChallengeCount,
      provenance: 'agent-verified',
      authorId,
      orgId,
      sealedAt: createdAt
    });

    const lineageCanon = canonicalJsonResult(lineage);
    if (!lineageCanon.ok) {
      return failEnvelope(
        tool,
        'BRICK_SEAL_FAILED',
        `Failed to canonicalize brick lineage: ${lineageCanon.message}`
      );
    }

    const payloadBuf = Buffer.from(`${SEAL_DOMAIN_PREFIX}${lineageCanon.json}`, 'utf8');
    const signature = crypto.sign(null, payloadBuf, privKey).toString('hex');

    const safeHoursSaved = Number.isFinite(Number(estimatedHoursSaved))
      ? Math.max(0, Number(estimatedHoursSaved))
      : 0;
    const normalizedCapabilities = Object.freeze(normalizeStringArray(capabilities));

    const bundle = Object.freeze({
      format: SEALED_BUNDLE_FORMAT,
      brickId: frozenBlueprint.id,
      name:
        typeof frozenBlueprint.name === 'string' && frozenBlueprint.name.trim()
          ? frozenBlueprint.name.trim()
          : frozenBlueprint.id,
      summary: typeof frozenBlueprint.summary === 'string' ? frozenBlueprint.summary : '',
      brickClass: String(brickClass).trim(),
      authorId,
      orgId,
      capabilities: normalizedCapabilities,
      replacesBoilerplate: String(replacesBoilerplate || ''),
      estimatedHoursSaved: safeHoursSaved,
      blueprint: frozenBlueprint,
      ...(isPlainObject(frozenBlueprint.ontology) ? { ontology: frozenBlueprint.ontology } : {}),
      source,
      checks: checksSummary,
      lineage,
      attestation: Object.freeze({
        algorithm: 'ed25519',
        domain: SEAL_ATTESTATION_DOMAIN,
        keyId,
        publicKeyPem,
        signature
      }),
      createdAt
    });

    let publishedBrickKey = null;
    if (publish === true) {
      const pubOut = persistVerifiedBundle(bundle);
      publishedBrickKey = pubOut.brickKey;
    }

    return okEnvelope(
      tool,
      `Sealed brick "${bundle.brickId}"@${sourceHash.slice(0, 8)} (${checks.length} checks passed)`,
      {
        bundle,
        verification: {
          passedCount,
          totalCount: checks.length,
          faultChallengeCount,
          sourceHash,
          blueprintHash,
          contractHash,
          checksHash,
          checks,
          repairHints: []
        },
        keyPairGenerated,
        published: publish === true,
        ...(publishedBrickKey ? { brickKey: publishedBrickKey } : {})
      }
    );
  }

  function verifyBrick(options = {}) {
    if (isPlainObject(options) && options.format === SEALED_BUNDLE_FORMAT) {
      return verifySealedBrickBundle(options);
    }
    const { bundle, trustedPublicKeyPem = null } = isPlainObject(options) ? options : {};
    return verifySealedBrickBundle(bundle, { trustedPublicKeyPem });
  }

  function publishBrick({ bundle } = {}) {
    const tool = 'krusch_brick_publish';
    const sealCheck = verifySealedBrickBundle(bundle);
    if (!sealCheck.ok) {
      return failEnvelope(tool, sealCheck.error.code, sealCheck.error.message, sealCheck.error.details);
    }

    const { brickKey, createdAtMs } = persistVerifiedBundle(bundle);
    return okEnvelope(
      tool,
      `Published sealed brick "${bundle.brickId}" (${brickKey})`,
      {
        brickKey,
        brickId: bundle.brickId,
        sourceHash: bundle.lineage.sourceHash,
        orgId: bundle.orgId,
        authorId: bundle.authorId,
        keyId: bundle.attestation.keyId,
        createdAtMs
      }
    );
  }

  function issueGrant({
    brickId,
    sourceHash,
    issuerId,
    issuerOrgId,
    scope = 'federated',
    recipients = [],
    expiresAtMs
  } = {}) {
    const tool = 'krusch_brick_grant';
    if (typeof brickId !== 'string' || !BRICK_ID_RE.test(brickId)) {
      return failEnvelope(tool, 'INVALID_BRICK_ID', 'Valid brickId is required to issue a grant');
    }
    if (!isSafeIdentifier(issuerId) || !isSafeIdentifier(issuerOrgId)) {
      return failEnvelope(
        tool,
        'INVALID_GRANT_ISSUER',
        'issuerId and issuerOrgId must be non-empty safe identifiers'
      );
    }
    if (!Array.isArray(recipients)) {
      return failEnvelope(tool, 'INVALID_GRANT_RECIPIENTS', 'recipients must be an array of viewer IDs');
    }

    const row =
      typeof sourceHash === 'string' && sourceHash.trim()
        ? activeDb
            .prepare(
              'SELECT * FROM brick_exchange_bricks WHERE brick_id = ? AND source_hash = ?'
            )
            .get(brickId, sourceHash.trim())
        : activeDb
            .prepare(
              'SELECT * FROM brick_exchange_bricks WHERE brick_id = ? ORDER BY created_at_ms DESC LIMIT 1'
            )
            .get(brickId);

    if (!row) {
      return failEnvelope(tool, 'BRICK_NOT_FOUND', `Published brick "${brickId}" not found`, {
        brickId,
        sourceHash: sourceHash || null
      });
    }

    if (String(row.org_id) !== issuerOrgId) {
      return failEnvelope(
        tool,
        'GRANT_ISSUER_FORBIDDEN',
        `Issuer org "${issuerOrgId}" cannot issue grants for brick owned by "${row.org_id}"`,
        { brickId, brickOrgId: row.org_id, issuerOrgId }
      );
    }

    const createdAtMs = Date.now();
    const resolvedExpiresAtMs =
      expiresAtMs === undefined || expiresAtMs === null
        ? createdAtMs + DEFAULT_GRANT_TTL_MS
        : Math.trunc(Number(expiresAtMs));

    if (!Number.isFinite(resolvedExpiresAtMs) || resolvedExpiresAtMs <= 0) {
      return failEnvelope(
        tool,
        'INVALID_GRANT_EXPIRY',
        'expiresAtMs must be a positive epoch millisecond timestamp'
      );
    }

    const cleanRecipients = normalizeStringArray(recipients);
    const resolvedScope = typeof scope === 'string' && scope.trim() ? scope.trim() : 'federated';
    const grantId = `grant_${crypto.randomBytes(8).toString('hex')}`;

    activeDb
      .prepare(
        `INSERT INTO brick_exchange_grants (
          grant_id, brick_id, source_hash, issuer_id, issuer_org_id,
          scope, recipients_json, revoked, expires_at_ms, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
      )
      .run(
        grantId,
        String(row.brick_id),
        String(row.source_hash),
        issuerId,
        issuerOrgId,
        resolvedScope,
        JSON.stringify(cleanRecipients),
        resolvedExpiresAtMs,
        createdAtMs
      );

    const grantRecord = Object.freeze({
      grant_id: grantId,
      id: grantId,
      grantId,
      brick_id: String(row.brick_id),
      brickId: String(row.brick_id),
      source_hash: String(row.source_hash),
      sourceHash: String(row.source_hash),
      issuer_id: issuerId,
      issuerId,
      issuer_org_id: issuerOrgId,
      issuerOrgId,
      scope: resolvedScope,
      recipients: cleanRecipients,
      revoked: false,
      expires_at_ms: resolvedExpiresAtMs,
      expiresAtMs: resolvedExpiresAtMs,
      created_at_ms: createdAtMs,
      createdAtMs
    });

    return okEnvelope(
      tool,
      `Issued ${resolvedScope} grant "${grantId}" for "${row.brick_id}" to ${cleanRecipients.length} recipient(s)`,
      {
        grant: grantRecord,
        grantId,
        brickId: String(row.brick_id),
        sourceHash: String(row.source_hash),
        issuerId,
        issuerOrgId,
        scope: resolvedScope,
        recipients: cleanRecipients,
        revoked: false,
        expiresAtMs: resolvedExpiresAtMs,
        createdAtMs
      }
    );
  }

  function revokeGrant({ actorId, grantId } = {}) {
    const tool = 'krusch_brick_revoke_grant';
    if (typeof grantId !== 'string' || !grantId.trim()) {
      return failEnvelope(tool, 'INVALID_GRANT_ID', 'grantId is required');
    }
    if (!isSafeIdentifier(actorId)) {
      return failEnvelope(tool, 'INVALID_ACTOR_ID', 'actorId must be a valid safe identifier');
    }

    const row = activeDb
      .prepare('SELECT * FROM brick_exchange_grants WHERE grant_id = ?')
      .get(grantId.trim());

    if (!row) {
      return failEnvelope(tool, 'GRANT_NOT_FOUND', `Grant "${grantId}" not found`, { grantId });
    }

    if (String(row.issuer_id) !== actorId) {
      return failEnvelope(
        tool,
        'GRANT_REVOKE_FORBIDDEN',
        `Actor "${actorId}" is not the issuer of grant "${grantId}"`,
        { grantId, actorId }
      );
    }

    activeDb
      .prepare('UPDATE brick_exchange_grants SET revoked = 1 WHERE grant_id = ?')
      .run(grantId.trim());

    return okEnvelope(tool, `Revoked grant "${grantId}"`, {
      grantId: String(row.grant_id),
      brickId: String(row.brick_id),
      sourceHash: String(row.source_hash),
      revoked: true,
      grant: {
        grant_id: String(row.grant_id),
        id: String(row.grant_id),
        grantId: String(row.grant_id),
        brick_id: String(row.brick_id),
        source_hash: String(row.source_hash),
        revoked: true
      }
    });
  }

  /**
   * Permission-before-discovery inbox: returns ONLY bricks in the viewer's org (`team-commons`)
   * OR bricks with an active unrevoked non-expired grant explicitly naming `viewerId` (`scoped-grant`).
   */
  function listInbox({ viewerId = '', viewerOrgId = '', nowMs = Date.now() } = {}) {
    const tool = 'krusch_brick_inbox';
    const cleanViewerId = typeof viewerId === 'string' ? viewerId.trim() : '';
    const cleanOrgId = typeof viewerOrgId === 'string' ? viewerOrgId.trim() : '';
    const evalNowMs = Number.isFinite(Number(nowMs)) ? Math.trunc(Number(nowMs)) : Date.now();

    if (!cleanViewerId && !cleanOrgId) {
      return failEnvelope(
        tool,
        'INVALID_VIEWER',
        'viewerId or viewerOrgId is required to list inbox bricks'
      );
    }

    const brickRows = activeDb
      .prepare(
        'SELECT * FROM brick_exchange_bricks ORDER BY created_at_ms DESC, brick_key ASC'
      )
      .all();

    const activeGrantStmt = activeDb.prepare(
      `SELECT grant_id, recipients_json, scope, expires_at_ms
       FROM brick_exchange_grants
       WHERE brick_id = ? AND source_hash = ? AND revoked = 0 AND expires_at_ms > ?
       ORDER BY created_at_ms DESC`
    );

    const visible = [];
    for (const row of brickRows) {
      let accessMode = null;
      let matchedGrantId = null;

      if (cleanOrgId && String(row.org_id) === cleanOrgId) {
        accessMode = 'team-commons';
      } else if (cleanViewerId) {
        const grants = activeGrantStmt.all(
          String(row.brick_id),
          String(row.source_hash),
          evalNowMs
        );
        for (const g of grants) {
          const recipients = parseJsonArraySafe(g.recipients_json);
          if (
            recipients.includes(cleanViewerId) ||
            (cleanOrgId && recipients.includes(`${cleanOrgId}:${cleanViewerId}`))
          ) {
            accessMode = 'scoped-grant';
            matchedGrantId = String(g.grant_id);
            break;
          }
        }
      }

      if (!accessMode) continue;

      let parsedBundle = null;
      try {
        parsedBundle = JSON.parse(String(row.bundle_json));
      } catch {
        continue;
      }

      visible.push({
        brickKey: String(row.brick_key),
        brickId: String(row.brick_id),
        sourceHash: String(row.source_hash),
        name: String(row.name),
        summary: String(row.summary),
        brickClass: String(row.brick_class),
        authorId: String(row.author_id),
        orgId: String(row.org_id),
        keyId: String(row.key_id),
        capabilities: parseJsonArraySafe(row.capabilities_json),
        estimatedHoursSaved: Number(row.estimated_hours_saved || 0),
        accessMode,
        grantId: matchedGrantId,
        createdAtMs: Number(row.created_at_ms),
        bundle: parsedBundle
      });
    }

    return okEnvelope(
      tool,
      `Listed ${visible.length} authorized brick(s) for viewer "${cleanViewerId || cleanOrgId}"`,
      {
        viewerId: cleanViewerId,
        viewerOrgId: cleanOrgId,
        count: visible.length,
        bricks: visible
      }
    );
  }

  async function tryBrick({
    bundle,
    sampleInput,
    binding = {},
    timeoutMs = DEFAULT_SANDBOX_TIMEOUT_MS,
    maxMemoryMb = DEFAULT_SANDBOX_MAX_MEMORY_MB
  } = {}) {
    const tool = 'krusch_brick_try';
    const sealCheck = verifySealedBrickBundle(bundle);
    if (!sealCheck.ok) {
      return failEnvelope(tool, sealCheck.error.code, sealCheck.error.message, sealCheck.error.details);
    }

    if (bundle.blueprint?.inputSchema) {
      const inValid = validateMinimalJsonSchema(bundle.blueprint.inputSchema, sampleInput, 'sampleInput');
      if (!inValid.ok) {
        return failEnvelope(
          tool,
          'SAMPLE_INPUT_INVALID',
          `sampleInput failed blueprint.inputSchema validation: ${inValid.issues.join('; ')}`,
          { issues: inValid.issues }
        );
      }
    }

    let cjsCode;
    try {
      cjsCode = transpileBrickSourceToCjs(bundle.source);
    } catch (err) {
      return failEnvelope(
        tool,
        'BRICK_SYNTAX_ERROR',
        `Failed to transpile sealed brick source: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    const execRes = await executeInPermissionSubprocess({
      cjsCode,
      exportName: bundle.blueprint?.exportName || 'default',
      input: sampleInput,
      binding,
      timeoutMs,
      maxMemoryMb
    });

    if (!execRes.ok) {
      return failEnvelope(tool, execRes.code, execRes.message, {
        durationMs: execRes.durationMs
      });
    }

    if (bundle.blueprint?.outputSchema) {
      const outValid = validateMinimalJsonSchema(
        bundle.blueprint.outputSchema,
        execRes.output,
        'output'
      );
      if (!outValid.ok) {
        return failEnvelope(
          tool,
          'SAMPLE_OUTPUT_INVALID',
          `Sandbox output failed blueprint.outputSchema validation: ${outValid.issues.join('; ')}`,
          { issues: outValid.issues, output: execRes.output }
        );
      }
    }

    const bindingHash = computeBindingHash(binding);
    return okEnvelope(
      tool,
      `Executed sealed brick "${bundle.brickId}" in isolated permission sandbox`,
      {
        brickId: bundle.brickId,
        sourceHash: bundle.lineage.sourceHash,
        bindingHash,
        output: execRes.output,
        durationMs: execRes.durationMs
      }
    );
  }

  async function adoptBrick({
    bundle,
    targetRepoDir = defaultRoot,
    bindingSource = null,
    adapterFileName = null,
    targetStack = null,
    grantId = '',
    userId = 'local-dev',
    orgId = 'local-team'
  } = {}) {
    const tool = 'krusch_brick_adopt';
    const sealCheck = verifySealedBrickBundle(bundle);
    if (!sealCheck.ok) {
      return failEnvelope(tool, sealCheck.error.code, sealCheck.error.message, sealCheck.error.details);
    }

    const ALLOWED_ADAPTER_FILENAMES = new Set(['binding.js', 'binding.ts', 'binding_adapter.py']);
    let resolvedAdapterFileName = 'binding.js';
    if (adapterFileName !== null && adapterFileName !== undefined && adapterFileName !== '') {
      const cleanAdapter = typeof adapterFileName === 'string' ? adapterFileName.trim() : '';
      if (!ALLOWED_ADAPTER_FILENAMES.has(cleanAdapter)) {
        return failEnvelope(
          tool,
          'INVALID_ADAPTER_FILENAME',
          `adapterFileName must be one of: ${[...ALLOWED_ADAPTER_FILENAMES].join(', ')}`,
          { adapterFileName }
        );
      }
      resolvedAdapterFileName = cleanAdapter;
    } else if (typeof targetStack === 'string' && targetStack.trim()) {
      const cleanTargetStack = targetStack.trim();
      if (!Object.hasOwn(STACK_ONTOLOGY_STACKS, cleanTargetStack)) {
        return failEnvelope(
          tool,
          'UNKNOWN_ONTOLOGY_STACK',
          `Unknown targetStack "${cleanTargetStack}"`,
          { targetStack: cleanTargetStack }
        );
      }
      resolvedAdapterFileName = STACK_ONTOLOGY_STACKS[cleanTargetStack].adapterFileName;
    }

    if (typeof targetRepoDir !== 'string' || !targetRepoDir.trim()) {
      return failEnvelope(tool, 'INVALID_TARGET_REPO', 'targetRepoDir must be a non-empty directory path');
    }

    const resolvedTarget = path.resolve(targetRepoDir);
    if (isSensitiveHostDirectory(resolvedTarget)) {
      return failEnvelope(tool, 'BRICK_PATH_ESCAPE', 'Refusing to vendor brick into sensitive system directory');
    }
    if (fs.existsSync(resolvedTarget) && fs.lstatSync(resolvedTarget).isSymbolicLink()) {
      return failEnvelope(
        tool,
        'BRICK_PATH_ESCAPE',
        'Refusing to vendor brick through symbolic link targetRepoDir'
      );
    }

    fs.mkdirSync(resolvedTarget, { recursive: true });
    const realRepoDir = fs.realpathSync(resolvedTarget);
    if (isSensitiveHostDirectory(realRepoDir)) {
      return failEnvelope(tool, 'BRICK_PATH_ESCAPE', 'Resolved targetRepoDir is a sensitive system directory');
    }

    const bricksRootDir = path.join(realRepoDir, 'bricks');
    if (fs.existsSync(bricksRootDir) && fs.lstatSync(bricksRootDir).isSymbolicLink()) {
      return failEnvelope(tool, 'BRICK_PATH_ESCAPE', 'Refusing to vendor into symbolic link bricks/');
    }
    fs.mkdirSync(bricksRootDir, { recursive: true });

    const brickDir = path.join(bricksRootDir, bundle.brickId);
    if (fs.existsSync(brickDir) && fs.lstatSync(brickDir).isSymbolicLink()) {
      return failEnvelope(
        tool,
        'BRICK_PATH_ESCAPE',
        `Refusing to vendor into symbolic link bricks/${bundle.brickId}`
      );
    }
    fs.mkdirSync(brickDir, { recursive: true });

    const realBrickDir = fs.realpathSync(brickDir);
    if (!isPathStrictlyInside(realBrickDir, realRepoDir)) {
      return failEnvelope(tool, 'BRICK_PATH_ESCAPE', 'Resolved brick directory escapes targetRepoDir');
    }

    const entryFileName = bundle.blueprint?.language === 'ts' ? 'index.ts' : 'index.js';
    const entryPath = path.join(realBrickDir, entryFileName);
    const bundleSealPath = path.join(realBrickDir, 'bundle.seal.json');
    const bindingPath = path.join(realBrickDir, resolvedAdapterFileName);
    const lockfilePath = path.join(realRepoDir, '.brick-lock.json');

    for (const candidateFile of [entryPath, bundleSealPath, bindingPath, lockfilePath]) {
      if (fs.existsSync(candidateFile) && fs.lstatSync(candidateFile).isSymbolicLink()) {
        return failEnvelope(
          tool,
          'BRICK_PATH_ESCAPE',
          `Refusing to write through symbolic link: ${path.basename(candidateFile)}`
        );
      }
    }

    fs.writeFileSync(entryPath, bundle.source, 'utf8');
    fs.writeFileSync(bundleSealPath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');

    let bindingExisted = false;
    if (fs.existsSync(bindingPath)) {
      bindingExisted = true;
    } else {
      const defaultStarter =
        resolvedAdapterFileName === 'binding_adapter.py'
          ? `# Local Python contract adapter for ${bundle.brickId}\nBINDING_CONFIG: dict = {}\n`
          : resolvedAdapterFileName === 'binding.ts'
            ? `// Local adapter binding for ${bundle.brickId}\nexport const binding: Record<string, unknown> = {};\n`
            : `// Local adapter binding for ${bundle.brickId}\nexport const binding = {};\n`;
      const starterBinding =
        typeof bindingSource === 'string' && bindingSource.length > 0
          ? bindingSource
          : defaultStarter;
      fs.writeFileSync(bindingPath, starterBinding, 'utf8');
    }

    const actualBindingContent = fs.readFileSync(bindingPath, 'utf8');
    const bindingHash = computeCanonicalHash(actualBindingContent);

    let lockData = { version: 1, bricks: {} };
    if (fs.existsSync(lockfilePath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
        if (isPlainObject(parsed) && isPlainObject(parsed.bricks)) {
          lockData = {
            version: Number.isInteger(parsed.version) ? parsed.version : 1,
            bricks: { ...parsed.bricks }
          };
        }
      } catch {
        return failEnvelope(
          tool,
          'BRICK_LOCKFILE_CORRUPT',
          'Existing .brick-lock.json contains malformed JSON',
          { lockfilePath }
        );
      }
    }

    const adoptedAtMs = Date.now();
    lockData.bricks[bundle.brickId] = {
      brickId: bundle.brickId,
      relativePath: `bricks/${bundle.brickId}/${entryFileName}`,
      bundlePath: `bricks/${bundle.brickId}/bundle.seal.json`,
      sourceHash: bundle.lineage.sourceHash,
      blueprintHash: bundle.lineage.blueprintHash,
      contractHash: bundle.lineage.contractHash,
      keyId: bundle.attestation.keyId,
      publicKeyPem: bundle.attestation.publicKeyPem,
      signature: bundle.attestation.signature,
      authorId: bundle.authorId,
      orgId: bundle.orgId,
      grantId: grantId ? String(grantId) : null,
      adoptedBy: String(userId || 'local-dev'),
      adoptedAt: new Date(adoptedAtMs).toISOString()
    };

    const sortedBricks = {};
    for (const key of Object.keys(lockData.bricks).sort()) {
      if (!FORBIDDEN_KEYS.has(key)) {
        sortedBricks[key] = lockData.bricks[key];
      }
    }
    fs.writeFileSync(
      lockfilePath,
      `${JSON.stringify({ version: lockData.version, bricks: sortedBricks }, null, 2)}\n`,
      'utf8'
    );

    const adoptionId = `adopt_${crypto.randomBytes(8).toString('hex')}`;
    activeDb
      .prepare(
        `INSERT INTO brick_exchange_adoptions (
          adoption_id, brick_id, source_hash, user_id, org_id,
          grant_id, binding_hash, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        adoptionId,
        bundle.brickId,
        bundle.lineage.sourceHash,
        String(userId || 'local-dev'),
        String(orgId || 'local-team'),
        String(grantId || ''),
        bindingHash,
        adoptedAtMs
      );

    return okEnvelope(
      tool,
      `Vendored sealed brick "${bundle.brickId}" into bricks/${bundle.brickId}`,
      {
        adoptionId,
        brickId: bundle.brickId,
        sourceHash: bundle.lineage.sourceHash,
        adapterFileName: resolvedAdapterFileName,
        entryPath,
        bindingPath,
        bundlePath: bundleSealPath,
        lockfilePath,
        bindingHash,
        preservedExistingBinding: bindingExisted
      }
    );
  }

  function auditBrickLocks({ targetRepoDir = defaultRoot } = {}) {
    const tool = 'krusch_brick_audit_locks';
    if (typeof targetRepoDir !== 'string' || !targetRepoDir.trim()) {
      return failEnvelope(tool, 'INVALID_TARGET_REPO', 'targetRepoDir must be a non-empty path');
    }

    const resolvedInput = path.resolve(targetRepoDir);
    if (!fs.existsSync(resolvedInput)) {
      return okEnvelope(tool, 'No .brick-lock.json present (0 vendored bricks)', {
        lockfilePresent: false,
        lockedBrickCount: 0,
        clean: true,
        findings: []
      });
    }

    const realRepoDir = fs.realpathSync(resolvedInput);
    const lockfilePath = path.join(realRepoDir, '.brick-lock.json');

    let lockLstat = null;
    try {
      lockLstat = fs.lstatSync(lockfilePath);
    } catch {
      lockLstat = null;
    }

    if (!lockLstat) {
      return okEnvelope(tool, 'No .brick-lock.json present (0 vendored bricks)', {
        lockfilePresent: false,
        lockedBrickCount: 0,
        clean: true,
        findings: []
      });
    }

    if (lockLstat.isSymbolicLink()) {
      return okEnvelope(tool, 'Brick lock audit found 1 integrity violation(s)', {
        lockfilePresent: true,
        lockedBrickCount: 0,
        clean: false,
        findings: [
          {
            ruleId: 'BRICK_PATH_ESCAPE',
            brickId: null,
            file: '.brick-lock.json',
            message: '.brick-lock.json must not be a symbolic link'
          }
        ]
      });
    }

    let parsedLock;
    try {
      parsedLock = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
    } catch {
      return okEnvelope(tool, 'Brick lock audit found 1 integrity violation(s)', {
        lockfilePresent: true,
        lockedBrickCount: 0,
        clean: false,
        findings: [
          {
            ruleId: 'BRICK_LOCKFILE_CORRUPT',
            brickId: null,
            file: '.brick-lock.json',
            message: 'Failed to parse .brick-lock.json as valid JSON'
          }
        ]
      });
    }

    if (!isPlainObject(parsedLock) || !isPlainObject(parsedLock.bricks)) {
      return okEnvelope(tool, 'Brick lock audit found 1 integrity violation(s)', {
        lockfilePresent: true,
        lockedBrickCount: 0,
        clean: false,
        findings: [
          {
            ruleId: 'BRICK_LOCKFILE_CORRUPT',
            brickId: null,
            file: '.brick-lock.json',
            message: '.brick-lock.json must contain a plain "bricks" object'
          }
        ]
      });
    }

    const findings = [];
    const brickKeys = Object.keys(parsedLock.bricks)
      .filter((k) => !FORBIDDEN_KEYS.has(k))
      .sort();

    for (const key of brickKeys) {
      const entry = parsedLock.bricks[key];
      const brickId = isPlainObject(entry) && typeof entry.brickId === 'string' ? entry.brickId : key;

      if (!isPlainObject(entry) || typeof entry.relativePath !== 'string' || !entry.relativePath.trim()) {
        findings.push({
          ruleId: 'BRICK_LOCK_ENTRY_INVALID',
          brickId,
          file: '.brick-lock.json',
          message: `Lock entry for "${brickId}" is missing relativePath`
        });
        continue;
      }

      const relSource = entry.relativePath;
      const candidateSourceAbs = path.resolve(realRepoDir, relSource);
      if (path.isAbsolute(relSource) || !isPathStrictlyInside(candidateSourceAbs, realRepoDir)) {
        findings.push({
          ruleId: 'BRICK_PATH_ESCAPE',
          brickId,
          file: relSource,
          message: `Vendored brick "${brickId}" path escapes repository root`
        });
        continue;
      }

      let sourceLstat = null;
      try {
        sourceLstat = fs.lstatSync(candidateSourceAbs);
      } catch {
        sourceLstat = null;
      }

      if (!sourceLstat) {
        findings.push({
          ruleId: 'BRICK_SOURCE_MISSING',
          brickId,
          file: relSource,
          message: `Vendored brick source file "${relSource}" is missing`
        });
        continue;
      }

      let realSourceAbs = '';
      try {
        realSourceAbs = fs.realpathSync(candidateSourceAbs);
      } catch {
        realSourceAbs = '';
      }

      if (
        sourceLstat.isSymbolicLink() ||
        !realSourceAbs ||
        !isPathStrictlyInside(realSourceAbs, realRepoDir)
      ) {
        findings.push({
          ruleId: 'BRICK_PATH_ESCAPE',
          brickId,
          file: relSource,
          message: `Vendored brick "${brickId}" traverses a symbolic link or escapes repository root`
        });
        continue;
      }

      const diskSource = fs.readFileSync(realSourceAbs, 'utf8');
      const actualHash = computeCanonicalHash(diskSource);
      if (actualHash !== entry.sourceHash) {
        findings.push({
          ruleId: 'BRICK_SOURCE_DRIFT',
          brickId,
          file: relSource,
          expectedHash: entry.sourceHash,
          actualHash,
          message: `Vendored brick "${brickId}" source drifted from sealed SHA-256 digest`
        });
      }

      const relBundle =
        typeof entry.bundlePath === 'string' && entry.bundlePath.trim()
          ? entry.bundlePath
          : `bricks/${brickId}/bundle.seal.json`;
      const candidateBundleAbs = path.resolve(realRepoDir, relBundle);

      if (path.isAbsolute(relBundle) || !isPathStrictlyInside(candidateBundleAbs, realRepoDir)) {
        findings.push({
          ruleId: 'BRICK_PATH_ESCAPE',
          brickId,
          file: relBundle,
          message: `Vendored brick "${brickId}" bundlePath escapes repository root`
        });
        continue;
      }

      if (fs.existsSync(candidateBundleAbs)) {
        const bundleLstat = fs.lstatSync(candidateBundleAbs);
        let realBundleAbs = '';
        try {
          realBundleAbs = fs.realpathSync(candidateBundleAbs);
        } catch {
          realBundleAbs = '';
        }

        if (
          bundleLstat.isSymbolicLink() ||
          !realBundleAbs ||
          !isPathStrictlyInside(realBundleAbs, realRepoDir)
        ) {
          findings.push({
            ruleId: 'BRICK_PATH_ESCAPE',
            brickId,
            file: relBundle,
            message: `Vendored brick "${brickId}" bundle.seal.json traverses a symbolic link`
          });
          continue;
        }

        let parsedBundle;
        try {
          parsedBundle = JSON.parse(fs.readFileSync(realBundleAbs, 'utf8'));
        } catch {
          findings.push({
            ruleId: 'BRICK_SEAL_INVALID',
            brickId,
            file: relBundle,
            message: `Vendored bundle.seal.json for "${brickId}" contains invalid JSON`
          });
          continue;
        }

        const sealRes = verifySealedBrickBundle(parsedBundle, {
          trustedPublicKeyPem: entry.publicKeyPem || null
        });
        if (
          !sealRes.ok ||
          parsedBundle?.lineage?.sourceHash !== entry.sourceHash ||
          (entry.signature && parsedBundle?.attestation?.signature !== entry.signature)
        ) {
          findings.push({
            ruleId: 'BRICK_SEAL_INVALID',
            brickId,
            file: relBundle,
            message:
              sealRes?.error?.message || `Cryptographic seal mismatch for vendored brick "${brickId}"`
          });
        }
      }
    }

    const clean = findings.length === 0;
    return okEnvelope(
      tool,
      clean
        ? `Verified ${brickKeys.length} locked brick(s) with 0 drift findings`
        : `Brick lock audit found ${findings.length} integrity violation(s) across ${brickKeys.length} locked brick(s)`,
      {
        lockfilePresent: true,
        lockedBrickCount: brickKeys.length,
        clean,
        findings
      }
    );
  }

  function analyzeBlastRadius({
    repoDir = defaultRoot,
    changedFiles = [],
    protectedFiles = []
  } = {}) {
    const tool = 'krusch_brick_blast_radius';
    if (!repoDir || typeof repoDir !== 'string') {
      return failEnvelope(tool, 'INVALID_REPO_DIR', 'repoDir is required to analyze AST blast radius');
    }

    const resolvedDir = path.resolve(repoDir);
    if (isSensitiveHostDirectory(resolvedDir)) {
      return failEnvelope(tool, 'PATH_BLOCKED', 'Scanning sensitive host directories is forbidden');
    }
    if (!fs.existsSync(resolvedDir)) {
      return failEnvelope(tool, 'ENOENT', `Repository directory does not exist: ${resolvedDir}`);
    }

    const realRepoDir = fs.realpathSync(resolvedDir);
    if (isSensitiveHostDirectory(realRepoDir) || !fs.statSync(realRepoDir).isDirectory()) {
      return failEnvelope(tool, 'INVALID_REPO_DIR', 'repoDir must be a valid non-sensitive directory');
    }

    const normalizedChanged = (Array.isArray(changedFiles) ? changedFiles : [changedFiles])
      .map(normalizeRelativeCodePath)
      .filter(Boolean);

    const chokeSet = new Set(DEFAULT_CHOKE_POINT_FILES.map(normalizeRelativeCodePath).filter(Boolean));
    const protectedSet = new Set(
      (Array.isArray(protectedFiles) ? protectedFiles : [])
        .map(normalizeRelativeCodePath)
        .filter(Boolean)
    );

    const graph = extractRepoAstGraph(realRepoDir);
    const chains = buildCausalHopChains(normalizedChanged, graph.edges, chokeSet);
    const impactedProtectedFiles = [...chains.hop1Dependents, ...chains.hop2Dependents].filter((f) =>
      protectedSet.has(f)
    );
    const directlyMutatedProtectedFiles = normalizedChanged.filter((f) => protectedSet.has(f));

    return okEnvelope(
      tool,
      `Mapped 2-hop AST blast radius across ${graph.files.length} file(s): ${chains.hop1Dependents.length} hop-1, ${chains.hop2Dependents.length} hop-2 dependent(s)`,
      {
        scannedFileCount: graph.files.length,
        edgeCount: graph.edges.length,
        hop0Files: chains.hop0Files,
        hop1Dependents: chains.hop1Dependents,
        hop2Dependents: chains.hop2Dependents,
        hopPaths: chains.hopPaths,
        impactedProtectedFiles,
        directlyMutatedProtectedFiles,
        edges: graph.edges,
        symbolsByFile: graph.symbolsByFile
      }
    );
  }

  function planFanOut({
    repoDir = defaultRoot,
    tasks = [],
    protectedFiles = []
  } = {}) {
    const tool = 'krusch_brick_fanout_plan';
    if (!Array.isArray(tasks) || tasks.length === 0) {
      return failEnvelope(tool, 'EMPTY_TASKS', 'At least one subagent or engineer task is required');
    }

    const blastRes = analyzeBlastRadius({
      repoDir,
      changedFiles: tasks.flatMap((t) => t?.targetFiles || t?.files || []),
      protectedFiles
    });

    if (!blastRes.ok) {
      return failEnvelope(tool, blastRes.error.code, blastRes.error.message, blastRes.error.details);
    }

    const chokeSet = new Set(DEFAULT_CHOKE_POINT_FILES.map(normalizeRelativeCodePath).filter(Boolean));
    const protectedSet = new Set(
      (Array.isArray(protectedFiles) ? protectedFiles : [])
        .map(normalizeRelativeCodePath)
        .filter(Boolean)
    );

    const wavePlan = planDisjointWaves({
      tasks,
      edges: blastRes.data.edges,
      chokeSet
    });

    const policyViolations = [];
    for (const lease of wavePlan.leases) {
      for (const tf of lease.targetFiles) {
        if (protectedSet.has(tf)) {
          policyViolations.push({
            taskId: lease.taskId,
            file: tf,
            reason:
              'Target file is protected by the Deadbolt Policy Floor and cannot be mutated by worker agents'
          });
        }
      }
    }

    if (policyViolations.length > 0) {
      return failEnvelope(
        tool,
        'WORKAROUND_REJECTED',
        `Fan-out blocked: ${policyViolations.length} task(s) target Policy-Floor protected file(s)`,
        { policyViolations, wavePlan }
      );
    }

    const enrichedLeases = wavePlan.leases.map((lease) => {
      const subChains = buildCausalHopChains(
        lease.targetFiles,
        blastRes.data.edges,
        new Set(wavePlan.reservedOrchestratorFiles)
      );
      return {
        ...lease,
        hopPaths: subChains.hopPaths,
        forbiddenFiles: [...new Set([...wavePlan.reservedOrchestratorFiles, ...protectedSet])]
          .filter((f) => !lease.targetFiles.includes(f))
          .sort()
      };
    });

    return okEnvelope(
      tool,
      `Planned ${enrichedLeases.length} task(s) into ${wavePlan.waveCount} conflict-free wave(s) (${wavePlan.collisions.length} 2-hop cone collision(s))`,
      {
        taskCount: wavePlan.taskCount,
        waveCount: wavePlan.waveCount,
        fullyParallelSingleWave: wavePlan.fullyParallelSingleWave,
        waves: wavePlan.waves,
        leases: enrichedLeases,
        agentLeases: enrichedLeases,
        collisions: wavePlan.collisions,
        reservedOrchestratorFiles: wavePlan.reservedOrchestratorFiles,
        protectedFiles: [...protectedSet].sort()
      }
    );
  }

  async function verifyBlastRadius({
    repoDir = defaultRoot,
    candidateEdits = {},
    lease = null,
    protectedFiles = [],
    invariantScript = '',
    timeoutMs = 5000
  } = {}) {
    const tool = 'krusch_brick_verify_blast_radius';
    if (!repoDir || typeof repoDir !== 'string' || !fs.existsSync(path.resolve(repoDir))) {
      return failEnvelope(tool, 'INVALID_REPO_DIR', 'Existing repoDir is required');
    }
    if (!isPlainObject(candidateEdits) || Object.keys(candidateEdits).length === 0) {
      return failEnvelope(
        tool,
        'EMPTY_EDITS',
        'candidateEdits must contain at least one modified file'
      );
    }

    const realRepoDir = fs.realpathSync(path.resolve(repoDir));
    if (isSensitiveHostDirectory(realRepoDir)) {
      return failEnvelope(tool, 'PATH_BLOCKED', 'Sensitive host directory blocked');
    }

    const normalizedEdits = {};
    for (const [rawPath, content] of Object.entries(candidateEdits)) {
      const norm = normalizeRelativeCodePath(rawPath);
      if (!norm || typeof content !== 'string') {
        return failEnvelope(tool, 'INVALID_EDIT_PATH', `Invalid candidate edit path: ${String(rawPath)}`);
      }
      normalizedEdits[norm] = content;
    }

    const editedPaths = Object.keys(normalizedEdits).sort();
    const protectedSet = new Set(
      (Array.isArray(protectedFiles) ? protectedFiles : [])
        .map(normalizeRelativeCodePath)
        .filter(Boolean)
    );
    const chokeSet = new Set(DEFAULT_CHOKE_POINT_FILES.map(normalizeRelativeCodePath).filter(Boolean));

    // Gate A: Subagent Lease Boundary
    if (lease && typeof lease === 'object') {
      const allowedTargets = new Set(
        (Array.isArray(lease.targetFiles) ? lease.targetFiles : [])
          .map(normalizeRelativeCodePath)
          .filter(Boolean)
      );
      const unleasedEdits = editedPaths.filter((p) => !allowedTargets.has(p));
      if (unleasedEdits.length > 0) {
        return failEnvelope(
          tool,
          'LEASE_BOUNDARY_VIOLATION',
          `Subagent "${lease.taskId || 'worker'}" modified file(s) outside its assigned lease: ${unleasedEdits.join(', ')}`,
          {
            taskId: lease.taskId || null,
            allowedTargets: [...allowedTargets],
            unleasedEdits
          }
        );
      }
    }

    // Gate B: Deadbolt Policy Floor
    const touchedProtected = editedPaths.filter((p) => protectedSet.has(p));
    if (touchedProtected.length > 0) {
      return failEnvelope(
        tool,
        'WORKAROUND_REJECTED',
        `Policy floor violation: candidate edit attempted to modify protected file(s): ${touchedProtected.join(', ')}`,
        {
          touchedProtected,
          protectedFiles: [...protectedSet]
        }
      );
    }

    // Gate C: Static 2-Hop AST Export Contract Compatibility
    const beforeGraph = extractRepoAstGraph(realRepoDir);
    const afterGraph = extractRepoAstGraph(realRepoDir, { overlayEdits: normalizedEdits });
    const chains = buildCausalHopChains(editedPaths, beforeGraph.edges, chokeSet);

    const brokenExports = [];
    for (const edge of afterGraph.edges) {
      if (!editedPaths.includes(edge.to)) continue;
      const targetSymbols = new Set(afterGraph.symbolsByFile[edge.to]?.exports || []);
      for (const importedSym of edge.importedNames) {
        if (!targetSymbols.has(importedSym)) {
          brokenExports.push({
            changedFile: edge.to,
            callerFile: edge.from,
            missingSymbol: importedSym,
            hopPath:
              chains.hopPaths.find((p) => p.startsWith(`${edge.to} -> ${edge.from}`)) ||
              `${edge.to} -> ${edge.from}`
          });
        }
      }
    }

    if (brokenExports.length > 0) {
      return failEnvelope(
        tool,
        'BROKEN_AST_EXPORT',
        `Candidate edit removed ${brokenExports.length} exported symbol(s) required by downstream AST caller(s)`,
        {
          brokenExports,
          hop1Dependents: chains.hop1Dependents,
          hop2Dependents: chains.hop2Dependents,
          hopPaths: chains.hopPaths
        }
      );
    }

    // Gate D: Out-of-process `node --permission --allow-fs-read=<stageDir>` 2-hop invariant script
    if (!invariantScript || typeof invariantScript !== 'string' || !invariantScript.trim()) {
      return okEnvelope(
        tool,
        `Verified static 2-hop AST blast radius (${chains.hop1Dependents.length} hop-1, ${chains.hop2Dependents.length} hop-2; 0 broken exports)`,
        {
          editedPaths,
          hop1Dependents: chains.hop1Dependents,
          hop2Dependents: chains.hop2Dependents,
          hopPaths: chains.hopPaths,
          dynamicCheckExecuted: false
        }
      );
    }

    const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kruschstack-blast-stage-'));
    try {
      for (const relFile of beforeGraph.files) {
        const srcAbs = path.join(realRepoDir, relFile);
        const destAbs = path.join(stageDir, relFile);
        fs.mkdirSync(path.dirname(destAbs), { recursive: true });
        fs.copyFileSync(srcAbs, destAbs);
      }
      const pkgJsonAbs = path.join(realRepoDir, 'package.json');
      if (fs.existsSync(pkgJsonAbs)) {
        fs.copyFileSync(pkgJsonAbs, path.join(stageDir, 'package.json'));
      }
      for (const [relEdit, content] of Object.entries(normalizedEdits)) {
        const destAbs = path.join(stageDir, relEdit);
        fs.mkdirSync(path.dirname(destAbs), { recursive: true });
        fs.writeFileSync(destAbs, content, 'utf8');
      }

      const sandboxOut = await runStagedPermissionScript({
        stageDir,
        script: invariantScript,
        timeoutMs
      });

      const markerResult = sandboxOut.result;
      const invariantFailed =
        !sandboxOut.passed ||
        (markerResult && typeof markerResult === 'object' && markerResult.passed === false);

      if (invariantFailed) {
        return failEnvelope(
          tool,
          'TWO_HOP_INVARIANT_BROKEN',
          `Downstream 2-hop verification failed across [${chains.hopPaths.join('; ') || editedPaths.join(', ')}]`,
          {
            editedPaths,
            hop1Dependents: chains.hop1Dependents,
            hop2Dependents: chains.hop2Dependents,
            hopPaths: chains.hopPaths,
            sandboxOutcome: markerResult ?? sandboxOut
          }
        );
      }

      return okEnvelope(
        tool,
        `Passed 2-hop AST blast-radius and downstream invariant verification (${chains.hopPaths.join('; ') || editedPaths.join(', ')})`,
        {
          editedPaths,
          hop1Dependents: chains.hop1Dependents,
          hop2Dependents: chains.hop2Dependents,
          hopPaths: chains.hopPaths,
          dynamicCheckExecuted: true,
          invariantResult: markerResult ?? { exitCode: 0 }
        }
      );
    } finally {
      fs.rmSync(stageDir, { recursive: true, force: true });
    }
  }

  function stats({ nowMs = Date.now() } = {}) {
    const tool = 'krusch_brick_stats';
    const evalNowMs = Number.isFinite(Number(nowMs)) ? Math.trunc(Number(nowMs)) : Date.now();

    const brickRow = activeDb
      .prepare(
        'SELECT COUNT(*) AS cnt, COALESCE(SUM(estimated_hours_saved), 0) AS sum_hours FROM brick_exchange_bricks'
      )
      .get();
    const activeGrantRow = activeDb
      .prepare(
        'SELECT COUNT(*) AS cnt FROM brick_exchange_grants WHERE revoked = 0 AND expires_at_ms > ?'
      )
      .get(evalNowMs);
    const totalGrantRow = activeDb
      .prepare('SELECT COUNT(*) AS cnt FROM brick_exchange_grants')
      .get();
    const adoptionRow = activeDb
      .prepare('SELECT COUNT(*) AS cnt FROM brick_exchange_adoptions')
      .get();
    const adoptedHoursRow = activeDb
      .prepare(
        `SELECT COALESCE(SUM(b.estimated_hours_saved), 0) AS total_hours
         FROM brick_exchange_adoptions a
         JOIN brick_exchange_bricks b
           ON b.brick_id = a.brick_id AND b.source_hash = a.source_hash`
      )
      .get();

    const brickCount = Number(brickRow?.cnt || 0);
    const activeGrantCount = Number(activeGrantRow?.cnt || 0);
    const totalGrantCount = Number(totalGrantRow?.cnt || 0);
    const adoptionCount = Number(adoptionRow?.cnt || 0);
    const catalogHoursSaved = Number(Number(brickRow?.sum_hours || 0).toFixed(2));
    const adoptedHoursSaved = Number(Number(adoptedHoursRow?.total_hours || 0).toFixed(2));
    const estimatedHoursSaved = Number(Math.max(catalogHoursSaved, adoptedHoursSaved).toFixed(2));

    return okEnvelope(
      tool,
      `Brick Exchange stats: ${brickCount} brick(s), ${activeGrantCount} active grant(s), ${adoptionCount} adoption(s), ${estimatedHoursSaved}h saved`,
      {
        brickCount,
        activeGrantCount,
        totalGrantCount,
        adoptionCount,
        estimatedHoursSaved,
        catalogHoursSaved,
        adoptedHoursSaved
      }
    );
  }

  const ontologyEngine = createBrickOntologyEngine({
    getAuthorizedBricksFn: (opts = {}) =>
      listInbox({
        viewerId: opts.viewerId,
        viewerOrgId: opts.viewerOrgId,
        nowMs: opts.nowMs
      }),
    tryBrickFn: tryBrick
  });

  return Object.freeze({
    keygen: generateEd25519BrickKeys,
    sealBrick,
    verifyBrick,
    publishBrick,
    issueGrant,
    revokeGrant,
    listInbox,
    tryBrick,
    adoptBrick,
    auditBrickLocks,
    analyzeBlastRadius,
    planFanOut,
    verifyBlastRadius,
    inspectOntology: ontologyEngine.inspectOntology,
    checkOntologyCompatibility: ontologyEngine.checkCompatibility,
    composeCrossStack: ontologyEngine.composeBricks,
    synthesizeBinding: ontologyEngine.synthesizeBinding,
    stats
  });
}
