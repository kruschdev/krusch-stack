/**
 * @module engines/brick-exchange/seal-crypto
 * Zero-Dependency Canonical JSON Hashing, SQLite Schema DDL, Ed25519 Key Generation,
 * Metadata Attestation Digesting, and Sealed Brick Bundle Verification for KruschStack.
 *
 * Breaks circular ESM dependency between `brick-ontology-engine.js` and `brick-exchange-engine.js` (`ARCH-02`).
 * Enforces:
 * - INV-STACK-01: Zero external npm dependencies (Node 22 `node:crypto` + internal `../../db/sqlite.js`).
 * - INV-STACK-02: Deterministic `{ ok, tool, summary, data | error }` envelopes.
 * - SEC-04: Bidirectional `bundle.ontology` <-> `bundle.blueprint.ontology` parity, `bundle.createdAt === lineage.sealedAt`,
 *   and constant-time `lineage.metadataHash` verification over top-level bundle metadata.
 */

import crypto from 'node:crypto';
import { okEnvelope, BRICK_EXCHANGE_SCHEMA_SQL } from '../../db/sqlite.js';
import {
  FORBIDDEN_KEYS,
  isPlainObject,
  hasForbiddenKeyRecursive
} from '../shared/js-code-scanner.js';

export { BRICK_EXCHANGE_SCHEMA_SQL };

export const SEAL_DOMAIN_PREFIX = 'krusch-brick-seal-v1:';
export const SEAL_ATTESTATION_DOMAIN = 'krusch-brick-seal-v1';
export const SEALED_BUNDLE_FORMAT = 'krusch-sealed-brick/v1';
export const LINEAGE_STANDARD = 'krusch-brick-exchange-v1';

const BRICK_ID_RE = /^[a-z0-9][a-z0-9-_]{1,63}$/;
const SAFE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

let defaultOntologyNormalizer = null;

/**
 * Register an optional 4-axis ontology normalizer without introducing a static circular import (`ARCH-02`).
 * @param {((rawOntology: object, options?: object) => any) | null} fn
 */
export function registerDefaultOntologyNormalizer(fn) {
  if (typeof fn === 'function' || fn === null) {
    defaultOntologyNormalizer = fn;
  }
}

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

function isSafeIdentifier(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed || trimmed !== value) return false;
  if (FORBIDDEN_KEYS.has(trimmed) || trimmed.includes('..')) return false;
  return SAFE_ID_RE.test(trimmed);
}

/**
 * Constant-time SHA-256/Ed25519 hex digest comparison.
 * @param {unknown} actual
 * @param {string} expectedHex
 * @returns {boolean}
 */
export function constantTimeHexEqual(actual, expectedHex) {
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

/**
 * Constant-time UTF-8 string comparison.
 * @param {unknown} actual
 * @param {unknown} expected
 * @returns {boolean}
 */
export function constantTimeStringEqual(actual, expected) {
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
 * Deterministic RFC-8785-compatible canonical JSON serializer matching `@krusch/toolkit/audit-log`.
 * @param {unknown} value
 * @param {number} [maxDepth=64]
 * @returns {{ ok: true, json: string } | { ok: false, message: string }}
 */
export function canonicalJsonResult(value, maxDepth = 64) {
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

/**
 * Compute a SHA-256 hex digest over UTF-8 strings or RFC-8785 canonicalized JSON values.
 * @param {unknown} value
 * @returns {string}
 */
export function computeCanonicalHash(value) {
  if (typeof value === 'string') {
    return crypto.createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex');
  }
  const canon = canonicalJsonResult(value);
  const serialized = canon.ok ? canon.json : fallbackCanonicalJson(value);
  return crypto.createHash('sha256').update(Buffer.from(serialized, 'utf8')).digest('hex');
}

/**
 * Extract the canonical JSON Schema contract shape (`inputSchema`, `outputSchema`, `bindingSchema`) from a blueprint.
 * @param {Record<string, any> | undefined | null} blueprint
 */
export function extractContractShape(blueprint) {
  return {
    inputSchema: blueprint?.inputSchema ?? {},
    outputSchema: blueprint?.outputSchema ?? {},
    bindingSchema: blueprint?.bindingSchema ?? {}
  };
}

/**
 * Compute the canonical SHA-256 `metadataHash` binding top-level bundle fields (`SEC-04`):
 * `{ brickClass, capabilities, estimatedHoursSaved, name, replacesBoilerplate, summary }`.
 *
 * @param {Record<string, any>} [meta={}]
 * @returns {string}
 */
export function computeBrickMetadataHash(meta = {}) {
  const src = isPlainObject(meta) ? meta : {};
  const rawHours = Number(src.estimatedHoursSaved ?? 0);
  const safeHoursSaved = Number.isFinite(rawHours) ? Math.max(0, rawHours) : 0;
  const capabilities = Array.isArray(src.capabilities)
    ? src.capabilities.map((item) => String(item))
    : [];
  const fallbackName = typeof src.brickId === 'string' ? src.brickId : '';

  return computeCanonicalHash({
    brickClass:
      typeof src.brickClass === 'string'
        ? src.brickClass.trim()
        : String(src.brickClass ?? 'general').trim(),
    capabilities,
    estimatedHoursSaved: safeHoursSaved,
    name: typeof src.name === 'string' ? src.name : fallbackName,
    replacesBoilerplate:
      typeof src.replacesBoilerplate === 'string'
        ? src.replacesBoilerplate
        : String(src.replacesBoilerplate ?? ''),
    summary: typeof src.summary === 'string' ? src.summary : ''
  });
}

/**
 * Derive a deterministic SPKI SHA-256 `key_<16hex>` key identifier from an Ed25519 public key PEM.
 * @param {string} publicKeyPem
 * @returns {string}
 */
export function derivePublicKeyId(publicKeyPem) {
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
 * bidirectional ontology parity (`SEC-04`), `createdAt === lineage.sealedAt`, optional `metadataHash`,
 * adversarial fault-injection qualification, optional pinned public key, and Ed25519 signature.
 *
 * @param {unknown} bundle
 * @param {{ trustedPublicKeyPem?: string | null, normalizeOntologyFn?: ((rawOntology: object, options?: object) => any) | null }} [options={}]
 */
export function verifySealedBrickBundle(
  bundle,
  { trustedPublicKeyPem = null, normalizeOntologyFn = null } = {}
) {
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

  // SEC-04: Bidirectional ontology parity (`bundle.blueprint.ontology` <-> `bundle.ontology`)!
  const hasSignedBlueprintOntology = isPlainObject(bundle.blueprint.ontology);
  if (
    bundle.blueprint.ontology !== undefined &&
    bundle.blueprint.ontology !== null &&
    !hasSignedBlueprintOntology
  ) {
    return failEnvelope(
      tool,
      'TAMPERED_ONTOLOGY',
      'Signed blueprint.ontology must be a plain object when present',
      { field: 'ontology' }
    );
  }

  if (hasSignedBlueprintOntology && !isPlainObject(bundle.ontology)) {
    return failEnvelope(
      tool,
      'TAMPERED_ONTOLOGY',
      'Top-level bundle.ontology was stripped from an ontology-attested sealed brick',
      { field: 'ontology' }
    );
  }

  if (bundle.ontology !== undefined) {
    if (!isPlainObject(bundle.ontology) || !hasSignedBlueprintOntology) {
      return failEnvelope(
        tool,
        'TAMPERED_ONTOLOGY',
        'Unsigned or invalid top-level bundle.ontology detected; ontology must match signed blueprint.ontology',
        { field: 'ontology' }
      );
    }

    const activeNormalizer =
      typeof normalizeOntologyFn === 'function' ? normalizeOntologyFn : defaultOntologyNormalizer;
    let normalizedSignedOntology = null;
    if (typeof activeNormalizer === 'function') {
      const normSignedOnt = activeNormalizer(bundle.blueprint.ontology, {
        source: bundle.source,
        blueprint: bundle.blueprint
      });
      if (!normSignedOnt || !normSignedOnt.ok) {
        return failEnvelope(
          tool,
          'TAMPERED_ONTOLOGY',
          `Signed blueprint.ontology failed normalization: ${normSignedOnt?.error?.message || 'invalid ontology'}`,
          { field: 'ontology' }
        );
      }
      normalizedSignedOntology = normSignedOnt.data.ontology;
    }

    const canonTopOnt = canonicalJsonResult(bundle.ontology);
    const canonRawSignedOnt = canonicalJsonResult(bundle.blueprint.ontology);
    const canonNormSignedOnt = normalizedSignedOntology
      ? canonicalJsonResult(normalizedSignedOntology)
      : null;

    const matchesSignedDirect =
      canonTopOnt.ok &&
      canonRawSignedOnt.ok &&
      constantTimeStringEqual(canonTopOnt.json, canonRawSignedOnt.json);
    const matchesSignedNormalized =
      canonTopOnt.ok &&
      canonNormSignedOnt !== null &&
      canonNormSignedOnt.ok &&
      constantTimeStringEqual(canonTopOnt.json, canonNormSignedOnt.json);

    if (!matchesSignedDirect && !matchesSignedNormalized) {
      return failEnvelope(
        tool,
        'TAMPERED_ONTOLOGY',
        'Top-level bundle.ontology does not match signed blueprint.ontology',
        { field: 'ontology' }
      );
    }
  }

  // SEC-04: Enforce `bundle.createdAt === lineage.sealedAt` whenever both are strings (or `createdAt` is non-string).
  if (bundle.createdAt !== undefined && typeof bundle.createdAt !== 'string') {
    return failEnvelope(
      tool,
      'BRICK_HASH_MISMATCH',
      'Bundle createdAt must be an ISO timestamp string matching signed lineage.sealedAt',
      { field: 'createdAt' }
    );
  }
  if (
    typeof bundle.createdAt === 'string' &&
    typeof lineage.sealedAt === 'string' &&
    !constantTimeStringEqual(bundle.createdAt, lineage.sealedAt)
  ) {
    return failEnvelope(
      tool,
      'BRICK_HASH_MISMATCH',
      'Brick createdAt timestamp does not match signed lineage.sealedAt',
      { field: 'createdAt' }
    );
  }

  // SEC-04: Verify `lineage.metadataHash` in constant time whenever present.
  if (typeof lineage.metadataHash === 'string' && lineage.metadataHash.length > 0) {
    if (
      !HEX64_RE.test(lineage.metadataHash) ||
      (bundle.capabilities !== undefined && !Array.isArray(bundle.capabilities)) ||
      (bundle.capabilities || []).some((cap) => typeof cap !== 'string')
    ) {
      return failEnvelope(
        tool,
        'BRICK_HASH_MISMATCH',
        'Brick metadataHash or capabilities array is malformed or modified after sealing',
        { field: 'metadataHash' }
      );
    }
    const actualMetadataHash = computeBrickMetadataHash(bundle);
    if (!constantTimeHexEqual(actualMetadataHash, lineage.metadataHash)) {
      return failEnvelope(
        tool,
        'BRICK_HASH_MISMATCH',
        'Brick metadata hash mismatch; top-level bundle metadata was modified after sealing',
        { field: 'metadataHash' }
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
