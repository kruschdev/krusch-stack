/**
 * @module engines/git-alignment-engine
 * Zero-LLM deterministic Git alignment, companion-file co-change, causal blame,
 * superseded stale-code, and Lego boilerplate guards for KruschStack (INV-STACK-14).
 *
 * Enforces INV-STACK-01 (zero external npm dependencies; Node 22 built-ins only)
 * and INV-STACK-04 (strict public sanitization).
 */

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope, isSqliteCorruptionError } from '../db/sqlite.js';

const DEFAULT_BLAME_TIMEOUT_MS = 1500;
const MAX_BLAME_FILES = 5;
const MAX_HUNK_LINES = 200;
const MAX_SNIPPET_OCCURRENCES = 3;
const MAX_STALE_FILES_PER_DECISION = 10;
const MAX_BLAMEABLE_FILE_BYTES = 262_144;
const MAX_INSPECT_CHARS = 262_144;
const MAX_ALIGNMENT_MEMORY_SCAN = 5000;
const MAX_GLOB_PATTERN_LENGTH = 256;
const MAX_GLOB_DOUBLE_STARS = 3;
const MAX_SUBPATH_SEGMENTS = 24;

const UNCOMMITTED_ZERO_SHA_RE = /^0{40}$/;
const HEX_SHA_TOKEN_RE = /\b([0-9a-f]{7,40})\b/gi;
const ENGLISH_HEX_WORDS = new Set([
  'acceded',
  'beaded',
  'bedded',
  'cabbaged',
  'dabbed',
  'decafed',
  'defaced',
  'effaced',
  'facade',
  'facaded'
]);

const LOCKFILE_NAMES = new Set([
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'cargo.lock',
  'gemfile.lock',
  'poetry.lock',
  'uv.lock',
  'composer.lock',
  'go.sum'
]);

const MECHANICAL_COMMIT_SUBJECT_RE = /^(?:style|docs|chore|ci|build|test)(?:\([^)]*\))?!?:\s/i;

const explicitlyReanchoredMap = new WeakMap();
const alignmentDbStmtCache = new WeakMap();

function getAlignmentStmtCache(db) {
  if (!db || (typeof db !== 'object' && typeof db !== 'function')) return null;
  let cache = alignmentDbStmtCache.get(db);
  if (!cache) {
    cache = {
      reanchorUpdateStmt: null,
      blameSelectStmt: null,
      staleSelectStmt: null,
      staleSelectFallbackStmt: null
    };
    alignmentDbStmtCache.set(db, cache);
  }
  return cache;
}

function isMissingReanchorColumnError(err) {
  const msg = String(err?.message || '');
  return /no such column:\s*provenance_reanchored|has no column named\s+provenance_reanchored/i.test(
    msg
  );
}

/**
 * Record that a replacement memory ID in `db` was created with an explicit provenance update
 * during `revise({ action: 'supersede', provenance: {...} })`.
 * Persists `provenance_reanchored = 1` in SQLite so re-ratification survives cold restarts,
 * while preserving the in-memory `WeakMap` cache for unmigrated raw test databases.
 *
 * @param {object} db
 * @param {number} memoryId
 */
export function recordExplicitProvenanceReanchor(db, memoryId) {
  if (!db || (typeof db !== 'object' && typeof db !== 'function')) return;
  const numId = Number(memoryId);
  if (!Number.isInteger(numId) || numId <= 0) return;

  if (typeof db.prepare === 'function') {
    const cache = getAlignmentStmtCache(db);
    try {
      if (!cache.reanchorUpdateStmt) {
        cache.reanchorUpdateStmt = db.prepare(
          'UPDATE context_memories SET provenance_reanchored = 1 WHERE id = ?'
        );
      }
      cache.reanchorUpdateStmt.run(numId);
    } catch (err) {
      if (isSqliteCorruptionError(err)) {
        throw err;
      }
      if (!isMissingReanchorColumnError(err)) {
        throw err;
      }
      cache.reanchorUpdateStmt = null;
    }
  }

  let set = explicitlyReanchoredMap.get(db);
  if (!set) {
    set = new Set();
    explicitlyReanchoredMap.set(db, set);
  }
  set.add(numId);
}

function wasExplicitlyReanchored(db, memoryId) {
  if (!db || (typeof db !== 'object' && typeof db !== 'function')) return false;
  const set = explicitlyReanchoredMap.get(db);
  return Boolean(set && set.has(Number(memoryId)));
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
    return value;
  }
  if (seen.has(value)) return value;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const prop = value[key];
    if (prop !== null && (typeof prop === 'object' || typeof prop === 'function')) {
      deepFreeze(prop, seen);
    }
  }
  return Object.freeze(value);
}

/**
 * Default deterministic co-change companion-file invariants (`INV-ALIGN-COCHANGE-03`).
 */
export const DEFAULT_COCHANGE_RULES = deepFreeze([
  {
    id: 'COCHANGE-OPENAPI-DOCS',
    severity: 'CRITICAL',
    whenGlobs: ['openapi/**'],
    requireGlobs: ['docs/changelog.md', 'CHANGELOG.md'],
    description: 'Every OpenAPI contract update must include a changelog entry in the same change.'
  },
  {
    id: 'COCHANGE-DB-MIGRATION-SCHEMA',
    severity: 'CRITICAL',
    whenGlobs: ['db/migrations/**'],
    requireGlobs: ['db/schema.sql', 'src/db/schema.sql'],
    description: 'Database migrations must stay synchronized with the canonical schema snapshot.'
  }
]);

function sha256(input) {
  return crypto.createHash('sha256').update(String(input ?? ''), 'utf8').digest('hex');
}

function unquoteGitPath(raw) {
  const trimmed = String(raw || '').trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    const inner = trimmed.slice(1, -1);
    const bytes = [];
    for (let i = 0; i < inner.length; i += 1) {
      const ch = inner[i];
      if (ch === '\\' && i + 1 < inner.length) {
        const next = inner[i + 1];
        if (/[0-7]{3}/.test(inner.slice(i + 1, i + 4))) {
          bytes.push(Number.parseInt(inner.slice(i + 1, i + 4), 8));
          i += 3;
          continue;
        }
        const escMap = { n: 10, t: 9, r: 13, '\\': 92, '"': 34 };
        if (Object.hasOwn(escMap, next)) {
          bytes.push(escMap[next]);
          i += 1;
          continue;
        }
      }
      const encoded = Buffer.from(ch, 'utf8');
      for (const b of encoded) bytes.push(b);
    }
    return Buffer.from(bytes).toString('utf8');
  }
  if (trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function normalizeRepoRelativePath(rawPath, { stripDiffPrefix = true } = {}) {
  if (!rawPath || typeof rawPath !== 'string' || rawPath.length > 2048) return null;
  const tabIdx = rawPath.indexOf('\t');
  const untabbed = tabIdx === -1 ? rawPath : rawPath.slice(0, tabIdx);
  let cleaned = unquoteGitPath(untabbed);
  if (!cleaned || cleaned.length > 1024 || cleaned === '/dev/null' || cleaned.includes('\0')) return null;
  cleaned = cleaned.replace(/\\/g, '/');
  if (cleaned === 'a/dev/null' || cleaned === 'b/dev/null' || cleaned === '/dev/null') return null;
  if (stripDiffPrefix && /^[ab]\//.test(cleaned)) {
    cleaned = cleaned.slice(2);
  }
  cleaned = cleaned.replace(/^(?:\.\/)+/, '').replace(/^\/+/, '');
  if (!cleaned || cleaned.length > 1024) return null;
  const segments = cleaned.split('/');
  if (segments.some((seg) => !seg || seg === '.' || seg === '..')) return null;
  return cleaned;
}

function splitDiffGitHeaderPair(rest) {
  const s = String(rest || '').trim();
  if (!s) return null;
  if (s.startsWith('"')) {
    let i = 1;
    while (i < s.length) {
      if (s[i] === '\\') {
        i += 2;
        continue;
      }
      if (s[i] === '"') break;
      i += 1;
    }
    if (i >= s.length) return null;
    const first = s.slice(0, i + 1);
    const second = s.slice(i + 1).trim();
    return second ? [first, second] : null;
  }
  const bIdx = s.indexOf(' b/');
  if (bIdx !== -1) return [s.slice(0, bIdx), s.slice(bIdx + 1)];
  const qIdx = s.indexOf(' "b/');
  if (qIdx !== -1) return [s.slice(0, qIdx), s.slice(qIdx + 1)];
  const ws = /^(\S+)\s+(\S+)$/.exec(s);
  return ws ? [ws[1], ws[2]] : null;
}

/**
 * Checks whether raw text contains unified git diff structure.
 *
 * @param {string} text
 * @returns {boolean}
 */
export function isUnifiedDiffText(text) {
  if (!text || typeof text !== 'string') return false;
  return /^(?:diff --git\s|---\s+(?:[ab]\/|"?[ab]\/|\/dev\/null)|\+\+\+\s+(?:[ab]\/|"?[ab]\/|\/dev\/null)|@@\s+-\d+)/m.test(
    text
  );
}

/**
 * Parses a unified diff into per-file change descriptors, supporting C-quoted paths,
 * `git mv` renames, `git cp` copies, new/deleted files, added lines, and modified hunks
 * with 1-indexed old-side line ranges.
 *
 * @param {string} diffText
 * @param {{ maxHunkLines?: number }} [options]
 * @returns {Array<{
 *   filePath: string,
 *   path: string,
 *   oldPath: string | null,
 *   newPath: string | null,
 *   status: 'modified' | 'added' | 'deleted' | 'renamed' | 'copied',
 *   isRename: boolean,
 *   isCopy: boolean,
 *   isNew: boolean,
 *   isDeleted: boolean,
 *   oldHunks: Array<{ startLine: number, endLine: number, count: number, rewrittenLines: number[] }>,
 *   addedLines: string[]
 * }>}
 */
export function parseUnifiedDiffFiles(diffText, options = {}) {
  if (!diffText || typeof diffText !== 'string') return [];
  const maxHunkLines =
    Number.isFinite(options?.maxHunkLines) && options.maxHunkLines > 0
      ? Math.floor(options.maxHunkLines)
      : MAX_HUNK_LINES;

  const lines = diffText.split(/\r?\n/);
  const entries = [];
  let current = null;
  let activeHunk = null;
  let oldLineCursor = 0;

  const finalizeCurrent = () => {
    if (!current) return;
    const primaryPath = current.newPath || current.oldPath;
    if (!primaryPath) {
      current = null;
      activeHunk = null;
      return;
    }
    current.filePath = primaryPath;
    current.path = primaryPath;
    if (current.isRename) {
      current.status = 'renamed';
    } else if (current.isCopy) {
      current.status = 'copied';
    } else if (current.isNew || (!current.oldPath && current.newPath)) {
      current.isNew = true;
      current.status = 'added';
    } else if (current.isDeleted || (current.oldPath && !current.newPath)) {
      current.isDeleted = true;
      current.status = 'deleted';
    } else {
      current.status = 'modified';
    }
    entries.push(current);
    current = null;
    activeHunk = null;
  };

  const createBlankEntry = (oldPath = null, newPath = null) => ({
    filePath: newPath || oldPath || '',
    path: newPath || oldPath || '',
    oldPath,
    newPath,
    status: 'modified',
    isRename: false,
    isCopy: false,
    isNew: false,
    isDeleted: false,
    oldHunks: [],
    addedLines: []
  });

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];

    if (line.startsWith('diff --git ')) {
      finalizeCurrent();
      const pair = splitDiffGitHeaderPair(line.slice(11));
      const oldP = pair ? normalizeRepoRelativePath(pair[0], { stripDiffPrefix: true }) : null;
      const newP = pair ? normalizeRepoRelativePath(pair[1], { stripDiffPrefix: true }) : null;
      current = createBlankEntry(oldP, newP);
      continue;
    }

    if (!activeHunk && line.startsWith('new file mode ')) {
      if (!current) current = createBlankEntry(null, null);
      current.isNew = true;
      continue;
    }

    if (!activeHunk && line.startsWith('deleted file mode ')) {
      if (!current) current = createBlankEntry(null, null);
      current.isDeleted = true;
      continue;
    }

    const renameFrom = /^rename from\s+(.+)$/.exec(line);
    if (!activeHunk && renameFrom) {
      if (!current) current = createBlankEntry(null, null);
      const p = normalizeRepoRelativePath(renameFrom[1], { stripDiffPrefix: false });
      if (p) current.oldPath = p;
      current.isRename = true;
      continue;
    }

    const renameTo = /^rename to\s+(.+)$/.exec(line);
    if (!activeHunk && renameTo) {
      if (!current) current = createBlankEntry(null, null);
      const p = normalizeRepoRelativePath(renameTo[1], { stripDiffPrefix: false });
      if (p) current.newPath = p;
      current.isRename = true;
      continue;
    }

    const copyFrom = /^copy from\s+(.+)$/.exec(line);
    if (!activeHunk && copyFrom) {
      if (!current) current = createBlankEntry(null, null);
      const p = normalizeRepoRelativePath(copyFrom[1], { stripDiffPrefix: false });
      if (p) current.oldPath = p;
      current.isCopy = true;
      continue;
    }

    const copyTo = /^copy to\s+(.+)$/.exec(line);
    if (!activeHunk && copyTo) {
      if (!current) current = createBlankEntry(null, null);
      const p = normalizeRepoRelativePath(copyTo[1], { stripDiffPrefix: false });
      if (p) current.newPath = p;
      current.isCopy = true;
      continue;
    }

    // Plain `diff -u` header pair (`--- ...` followed by `+++ ...`) without `diff --git`
    if (
      /^---\s+([^\t\r\n]+)/.test(line) &&
      i + 1 < lines.length &&
      /^\+\+\+\s+([^\t\r\n]+)/.test(lines[i + 1])
    ) {
      if (current && (current.oldHunks.length > 0 || current.addedLines.length > 0)) {
        finalizeCurrent();
      }
      if (!current) {
        current = createBlankEntry(null, null);
      }
      activeHunk = null;
      const rawOld = /^---\s+([^\t\r\n]+)/.exec(line)[1].trim();
      const rawNew = /^\+\+\+\s+([^\t\r\n]+)/.exec(lines[i + 1])[1].trim();
      if (rawOld === '/dev/null' || unquoteGitPath(rawOld) === '/dev/null') {
        current.oldPath = null;
        current.isNew = true;
      } else {
        const parsedOld = normalizeRepoRelativePath(rawOld, { stripDiffPrefix: true });
        if (parsedOld) current.oldPath = parsedOld;
      }
      if (rawNew === '/dev/null' || unquoteGitPath(rawNew) === '/dev/null') {
        current.newPath = null;
        current.isDeleted = true;
      } else {
        const parsedNew = normalizeRepoRelativePath(rawNew, { stripDiffPrefix: true });
        if (parsedNew) current.newPath = parsedNew;
      }
      i += 1;
      continue;
    }

    const hunkMatch = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/.exec(line);
    if (hunkMatch) {
      if (!current) {
        current = createBlankEntry(null, null);
      }
      const oldStart = Number(hunkMatch[1]);
      const oldCount = hunkMatch[2] === undefined ? 1 : Number(hunkMatch[2]);
      oldLineCursor = oldStart;
      if (current.oldPath && Number.isInteger(oldStart) && oldStart >= 1 && oldCount > 0) {
        const boundedEnd = oldStart + Math.min(oldCount, maxHunkLines) - 1;
        activeHunk = {
          startLine: oldStart,
          endLine: boundedEnd,
          count: oldCount,
          rewrittenLines: []
        };
        current.oldHunks.push(activeHunk);
      } else {
        activeHunk = {
          startLine: oldStart,
          endLine: oldStart,
          count: 0,
          rewrittenLines: []
        };
      }
      continue;
    }

    if (activeHunk && current) {
      if (line.startsWith('+') && !line.startsWith('+++')) {
        current.addedLines.push(line.slice(1));
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        if (
          current.oldPath &&
          oldLineCursor >= 1 &&
          activeHunk.rewrittenLines.length < maxHunkLines
        ) {
          activeHunk.rewrittenLines.push(oldLineCursor);
        }
        oldLineCursor += 1;
      } else if (line.startsWith(' ')) {
        oldLineCursor += 1;
      }
    }
  }

  finalizeCurrent();
  return entries;
}

function extractTouchedFilesFromDiff(diffText) {
  const parsed = parseUnifiedDiffFiles(diffText);
  const seen = new Set();
  for (const item of parsed) {
    if (item.oldPath) seen.add(item.oldPath);
    if (item.newPath) seen.add(item.newPath);
  }
  return [...seen];
}

/**
 * Compiles a bounded glob supporting `*`, `**`, and `?` only.
 * Explicitly rejects unsupported `{a,b}`, `[abc]`, `!`, and `\` syntax so rules never fail silently.
 *
 * @param {string} pattern
 * @returns {{ valid: boolean, pattern: string, regex: RegExp | null, error: string | null }}
 */
export function compileSafeCoChangeGlob(pattern) {
  if (typeof pattern === 'string' && pattern.length > MAX_GLOB_PATTERN_LENGTH) {
    return {
      ok: false,
      valid: false,
      pattern,
      regex: null,
      error: 'Glob pattern exceeds 256-character limit'
    };
  }
  const raw = typeof pattern === 'string' ? pattern.trim() : '';
  if (!raw) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: 'Glob pattern must be non-empty.'
    };
  }
  if (raw.length > MAX_GLOB_PATTERN_LENGTH) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: 'Glob pattern exceeds 256-character limit'
    };
  }
  if (/[{}[\]!\\]/.test(raw)) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: `Unsupported glob syntax in "${raw}": only *, **, and ? are allowed.`
    };
  }
  if (/\*{3,}/.test(raw)) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: `Invalid glob pattern "${raw}": consecutive *** wildcards are forbidden.`
    };
  }
  const stripped = raw
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '')
    .replace(/\/{2,}/g, '/');
  if (!stripped || stripped.split('/').includes('..')) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: `Invalid relative glob "${raw}".`
    };
  }

  const doubleStarMatches = stripped.match(/\*\*/g);
  if (doubleStarMatches && doubleStarMatches.length > MAX_GLOB_DOUBLE_STARS) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: 'Glob pattern exceeds maximum ** wildcard segments (3)'
    };
  }

  const normalized = stripped
    .replace(/(?:\*\*\/)+/g, '**/')
    .replace(/(?:\/\*\*)+$/g, '/**')
    .replace(/([^/*])\*{2,}([^/*])/g, '$1*$2');

  const singleStarCount = (normalized.replace(/\*\*/g, '').match(/\*/g) || []).length;
  if (singleStarCount > 10) {
    return {
      ok: false,
      valid: false,
      pattern: raw,
      regex: null,
      error: 'Glob pattern exceeds maximum single * wildcard count (10)'
    };
  }

  // Tokenize normalized glob for deterministic O(M * L) linear-time DP evaluation (zero backtracking).
  const tokens = [];
  let i = 0;
  while (i < normalized.length) {
    const ch = normalized[i];
    if (ch === '*' && normalized[i + 1] === '*') {
      const prevBoundary = i === 0 || normalized[i - 1] === '/';
      if (prevBoundary && normalized[i + 2] === '/') {
        tokens.push({ kind: 'GLOBSTAR_DIR' });
        i += 3;
        continue;
      }
      tokens.push({ kind: 'GLOBSTAR' });
      i += 2;
      continue;
    }
    if (ch === '*') {
      if (tokens.length === 0 || tokens[tokens.length - 1].kind !== 'STAR') {
        tokens.push({ kind: 'STAR' });
      }
      i += 1;
      continue;
    }
    if (ch === '?') {
      tokens.push({ kind: 'QMARK' });
      i += 1;
      continue;
    }
    tokens.push({ kind: 'CHAR', ch });
    i += 1;
  }

  const linearTest = (candidate) => {
    if (typeof candidate !== 'string' || candidate.length > 1024) return false;
    const len = candidate.length;
    let dp = new Uint8Array(len + 1);
    dp[0] = 1;

    for (let t = 0; t < tokens.length; t += 1) {
      const tok = tokens[t];
      const next = new Uint8Array(len + 1);
      if (tok.kind === 'CHAR') {
        for (let j = 1; j <= len; j += 1) {
          if (dp[j - 1] && candidate[j - 1] === tok.ch) next[j] = 1;
        }
      } else if (tok.kind === 'QMARK') {
        for (let j = 1; j <= len; j += 1) {
          if (dp[j - 1] && candidate[j - 1] !== '/') next[j] = 1;
        }
      } else if (tok.kind === 'STAR') {
        next[0] = dp[0];
        for (let j = 1; j <= len; j += 1) {
          if (dp[j] || (candidate[j - 1] !== '/' && next[j - 1])) next[j] = 1;
        }
      } else if (tok.kind === 'GLOBSTAR') {
        let seen = 0;
        for (let j = 0; j <= len; j += 1) {
          if (dp[j]) seen = 1;
          next[j] = seen;
        }
      } else if (tok.kind === 'GLOBSTAR_DIR') {
        const inSeg = new Uint8Array(len + 1);
        next[0] = dp[0];
        for (let j = 1; j <= len; j += 1) {
          if (candidate[j - 1] !== '/') {
            inSeg[j] = next[j - 1] || inSeg[j - 1] ? 1 : 0;
            next[j] = dp[j];
          } else {
            inSeg[j] = 0;
            next[j] = dp[j] || inSeg[j - 1] ? 1 : 0;
          }
        }
      }
      dp = next;
    }
    return dp[len] === 1;
  };

  const safeMatcher = new RegExp('^$');
  Object.defineProperty(safeMatcher, 'test', {
    value: linearTest,
    writable: false,
    configurable: true
  });

  return { ok: true, valid: true, pattern: normalized, regex: safeMatcher, error: null };
}

function splitCommaOutsideBraces(rawSpec) {
  const s = String(rawSpec || '').trim();
  if (!s) return [];
  const parts = [];
  let buf = '';
  let braceDepth = 0;
  let bracketDepth = 0;

  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (ch === '{') braceDepth += 1;
    else if (ch === '}' && braceDepth > 0) braceDepth -= 1;
    else if (ch === '[') bracketDepth += 1;
    else if (ch === ']' && bracketDepth > 0) bracketDepth -= 1;

    if (ch === ',' && braceDepth === 0 && bracketDepth === 0) {
      parts.push(buf.trim());
      buf = '';
    } else {
      buf += ch;
    }
  }
  parts.push(buf.trim());
  return parts.map((p) => p.replace(/^['"`]+|['"`]+$/g, '').trim());
}

function cleanUnquotedFlagValue(rawToken) {
  let token = String(rawToken || '').trim();
  if (!token) return '';
  // Strip trailing sentence punctuation when directive appears at end of prose
  if (token.endsWith(').') && !token.includes('(')) {
    token = token.slice(0, -2);
  } else if (token.endsWith(')') && !token.includes('(')) {
    token = token.slice(0, -1);
  } else if (token.endsWith('.') && !token.endsWith('..')) {
    // Preserve file extensions like `.md`, only strip trailing period after `**` or `*` or quote
    if (/\*\.?$/.test(token.slice(0, -1))) {
      token = token.slice(0, -1);
    }
  }
  return token.trim();
}

function scanCliDirectiveFlagValues(text, flagName) {
  const re = new RegExp(
    `(?:^|[\\s\`('"\\[])--${flagName}(?=\\s|$)(?:\\s+(?:"([^"]*)"|'([^']*)'|\`([^\`]*)\`|([^\\s;\`|]+)))?`,
    'gi'
  );
  let sawFlag = false;
  let sawMissingArg = false;
  const values = [];

  for (const match of String(text || '').matchAll(re)) {
    sawFlag = true;
    const quotedVal = match[1] ?? match[2] ?? match[3];
    const unquotedVal = match[4];
    if (quotedVal !== undefined) {
      const split = splitCommaOutsideBraces(quotedVal);
      if (split.length === 0 || split.some((g) => !g)) {
        sawMissingArg = true;
      } else {
        values.push(...split);
      }
      continue;
    }
    if (unquotedVal === undefined || /^--[a-z]/i.test(unquotedVal)) {
      sawMissingArg = true;
      continue;
    }
    const cleaned = cleanUnquotedFlagValue(unquotedVal);
    if (!cleaned) {
      sawMissingArg = true;
      continue;
    }
    const split = splitCommaOutsideBraces(cleaned);
    if (split.length === 0 || split.some((g) => !g)) {
      sawMissingArg = true;
    } else {
      values.push(...split);
    }
  }

  return { sawFlag, sawMissingArg, values };
}

/**
 * Parses `--when <glob[,glob]>` and `--require <glob[,glob]>` directives in memory content
 * (or metadata), returning `null` when content is not a co-change directive, or a structured
 * `{ valid, id, category, severity, whenGlobs, requireGlobs, description, provenance, error }`
 * object flagging malformed syntax cleanly.
 *
 * @param {string} content
 * @param {object} [metadata={}]
 * @returns {object | null}
 */
export function parseCoChangeRuleDirective(content, metadata = {}) {
  const text = typeof content === 'string' ? content.trim() : '';
  const meta = metadata && typeof metadata === 'object' ? metadata : {};
  const ruleId = meta.id !== undefined && meta.id !== null ? meta.id : 'cochange-rule';
  const category = meta.category || 'invariant';
  const severity = meta.severity || 'CRITICAL';
  const provenance = meta.provenance || null;

  const metaWhen = Array.isArray(meta.whenGlobs || meta.when)
    ? (meta.whenGlobs || meta.when).flatMap((g) => splitCommaOutsideBraces(g))
    : meta.when
      ? splitCommaOutsideBraces(meta.when)
      : [];
  const metaReq = Array.isArray(meta.requireGlobs || meta.require)
    ? (meta.requireGlobs || meta.require).flatMap((g) => splitCommaOutsideBraces(g))
    : meta.require
      ? splitCommaOutsideBraces(meta.require)
      : [];

  const whenScan = scanCliDirectiveFlagValues(text, 'when');
  const reqScan = scanCliDirectiveFlagValues(text, 'require');

  let pipeMode = false;
  const pipeWhen = [];
  const pipeReq = [];
  if (!whenScan.sawFlag && !reqScan.sawFlag && /\bcochange:/i.test(text)) {
    pipeMode = true;
    const stripped = text.replace(/^.*?cochange:[^\s|]*\s*:?\s*/i, '');
    for (const seg of stripped.split('|').map((s) => s.trim()).filter(Boolean)) {
      if (/^when\s*:/i.test(seg)) {
        pipeWhen.push(...splitCommaOutsideBraces(seg.replace(/^when\s*:/i, '')));
      } else if (/^require(?:s)?\s*:/i.test(seg)) {
        pipeReq.push(...splitCommaOutsideBraces(seg.replace(/^require(?:s)?\s*:/i, '')));
      }
    }
  }

  const isDirective =
    whenScan.sawFlag ||
    reqScan.sawFlag ||
    pipeMode ||
    metaWhen.length > 0 ||
    metaReq.length > 0;

  if (!isDirective) {
    return null;
  }

  const rawWhen = [
    ...metaWhen,
    ...whenScan.values,
    ...pipeWhen
  ];
  const rawReq = [
    ...metaReq,
    ...reqScan.values,
    ...pipeReq
  ];

  if (whenScan.sawMissingArg) {
    return {
      valid: false,
      id: ruleId,
      category,
      severity,
      whenGlobs: rawWhen,
      requireGlobs: rawReq,
      description: text,
      provenance,
      error: 'Malformed --when directive: expected one or more comma-separated globs.'
    };
  }

  if (reqScan.sawMissingArg) {
    return {
      valid: false,
      id: ruleId,
      category,
      severity,
      whenGlobs: rawWhen,
      requireGlobs: rawReq,
      description: text,
      provenance,
      error: 'Malformed --require directive: expected one or more comma-separated globs.'
    };
  }

  if (rawWhen.length === 0 || rawReq.length === 0) {
    return {
      valid: false,
      id: ruleId,
      category,
      severity,
      whenGlobs: rawWhen,
      requireGlobs: rawReq,
      description: text,
      provenance,
      error: 'Co-change directive requires both --when <glob> and --require <glob>.'
    };
  }

  const compiledWhen = rawWhen.map((g) => compileSafeCoChangeGlob(g));
  const compiledReq = rawReq.map((g) => compileSafeCoChangeGlob(g));
  const badGlob = [...compiledWhen, ...compiledReq].find((c) => !c.valid);

  if (badGlob) {
    return {
      valid: false,
      id: ruleId,
      category,
      severity,
      whenGlobs: rawWhen,
      requireGlobs: rawReq,
      description: text,
      provenance,
      error: badGlob.error
    };
  }

  const boundedText = text.length > 4096 ? text.slice(0, 4096) : text;
  const cleanDesc = boundedText
    .replace(/(?<![`\s])`?\s*--(?:when|require)\s+(?:"[^"]*"|'[^']*'|`[^`]*`|[^\s;`|]+)`?|^`?\s*--(?:when|require)\s+(?:"[^"]*"|'[^']*'|`[^`]*`|[^\s;`|]+)`?/gi, ' ')
    .replace(/\s+/g, ' ')
    .replace(/^[\s:;-]+|[\s:;-]+$/g, '')
    .trim();

  return {
    valid: true,
    id: ruleId,
    category,
    severity,
    whenGlobs: compiledWhen.map((c) => c.pattern),
    requireGlobs: compiledReq.map((c) => c.pattern),
    description: cleanDesc || text,
    provenance,
    error: null
  };
}

/**
 * Scans active `context_memories` rows for `--when` / `--require` directives,
 * returning `{ rules, malformedRules }`.
 *
 * @param {Array<object>} activeRows
 * @returns {{ rules: Array<object>, malformedRules: Array<object> }}
 */
export function extractMemoryCoChangeRules(activeRows) {
  if (!Array.isArray(activeRows) || activeRows.length === 0) {
    return { rules: [], malformedRules: [] };
  }

  const rules = [];
  const malformedRules = [];

  for (const row of activeRows) {
    if (!row || typeof row !== 'object') continue;
    if (row.status && String(row.status).toLowerCase() !== 'active') continue;

    const provenance =
      row.provenance ||
      (row.provenance_file
        ? {
            file: row.provenance_file,
            locator: row.provenance_locator || null,
            quoted_sentence: row.quoted_sentence || null
          }
        : null);

    const parsed = parseCoChangeRuleDirective(row.content, {
      id: row.id,
      category: row.category || 'invariant',
      provenance
    });
    if (!parsed) continue;

    const numericId = Number.isInteger(Number(row.id)) ? Number(row.id) : null;
    if (parsed.valid) {
      rules.push({
        id: row.id,
        memory_id: numericId,
        category: parsed.category,
        severity: parsed.severity,
        whenGlobs: parsed.whenGlobs,
        requireGlobs: parsed.requireGlobs,
        description: parsed.description,
        rule: String(row.content || ''),
        provenance: parsed.provenance
      });
    } else {
      malformedRules.push({
        id: row.id,
        memory_id: numericId,
        category: parsed.category,
        rule: String(row.content || ''),
        error: parsed.error
      });
    }
  }

  return { rules, malformedRules };
}

function touchedMatchesSubpathGlob(file, compiledGlob) {
  if (!file || file.length > 1024) return false;
  const parts = file.split('/');
  if (parts.length <= 1) return false;
  const startIdx = Math.max(1, parts.length - MAX_SUBPATH_SEGMENTS);
  for (let i = startIdx; i < parts.length; i += 1) {
    const sub = parts.slice(i).join('/');
    if (sub && compiledGlob.regex.test(sub)) return true;
  }
  return false;
}

/**
 * Evaluates deterministic co-change rules (`whenGlobs` -> `requireGlobs`) against
 * a unified diff and/or explicit `changedFiles` list.
 *
 * @param {{ diff?: string, changedFiles?: string[], rules?: Array<object>, matchSubpaths?: boolean }} [params]
 * @returns {{
 *   ok: boolean,
 *   passed: boolean,
 *   touchedFiles: string[],
 *   evaluatedCount: number,
 *   violations: Array<object>,
 *   invalidRules: Array<object>
 * }}
 */
export function evaluateCoChangeRules({
  diff = '',
  changedFiles = [],
  rules = [],
  matchSubpaths = true
} = {}) {
  const touchedSet = new Set(extractTouchedFilesFromDiff(diff));
  if (Array.isArray(changedFiles)) {
    for (const rawFile of changedFiles) {
      const norm = normalizeRepoRelativePath(rawFile, { stripDiffPrefix: true });
      if (norm) touchedSet.add(norm);
    }
  }
  const touchedFiles = [...touchedSet];
  const violations = [];
  const invalidRules = [];
  const effectiveRules = Array.isArray(rules) ? rules : [];

  for (const rule of effectiveRules) {
    if (!rule || typeof rule !== 'object') continue;
    const ruleId = String(rule.id ?? rule.key ?? 'cochange-rule');
    const rawWhen = Array.isArray(rule.whenGlobs || rule.when)
      ? rule.whenGlobs || rule.when
      : rule.when
        ? [rule.when]
        : [];
    const rawReq = Array.isArray(rule.requireGlobs || rule.require)
      ? rule.requireGlobs || rule.require
      : rule.require
        ? [rule.require]
        : [];

    if (rawWhen.length === 0 || rawReq.length === 0) {
      invalidRules.push({
        id: ruleId,
        memory_id: rule.memory_id ?? (Number.isInteger(Number(rule.id)) ? Number(rule.id) : null),
        error: 'Both whenGlobs and requireGlobs must be non-empty.'
      });
      continue;
    }

    const compiledWhen = rawWhen.map((g) => compileSafeCoChangeGlob(g));
    const compiledReq = rawReq.map((g) => compileSafeCoChangeGlob(g));
    const bad = [...compiledWhen, ...compiledReq].find((c) => !c.valid);
    if (bad) {
      invalidRules.push({
        id: ruleId,
        memory_id: rule.memory_id ?? (Number.isInteger(Number(rule.id)) ? Number(rule.id) : null),
        error: bad.error
      });
      continue;
    }

    if (touchedFiles.length === 0) continue;

    const matchesGlob = (file, compiled) =>
      Boolean(file && file.length <= 1024) &&
      (compiled.regex.test(file) || (matchSubpaths && touchedMatchesSubpathGlob(file, compiled)));

    const triggeredBy = touchedFiles.filter((file) => compiledWhen.some((c) => matchesGlob(file, c)));
    if (triggeredBy.length === 0) continue;

    const satisfied = touchedFiles.some((file) => compiledReq.some((c) => matchesGlob(file, c)));
    if (!satisfied) {
      const missingAnyOf = compiledReq.map((c) => c.pattern);
      const description = String(
        rule.description ||
          rule.content ||
          `Changes matching ${compiledWhen.map((c) => c.pattern).join(', ')} require updating ${missingAnyOf.join(' or ')}.`
      );
      violations.push({
        id: rule.id ?? ruleId,
        memory_id: rule.memory_id ?? (Number.isInteger(Number(rule.id)) ? Number(rule.id) : null),
        category: rule.category || 'invariant',
        severity: rule.severity || 'error',
        description,
        rule: rule.rule || description,
        triggeredBy,
        missingAnyOf,
        provenance: rule.provenance || null
      });
    }
  }

  const passed = violations.length === 0 && invalidRules.length === 0;
  return {
    ok: passed,
    passed,
    touchedFiles,
    evaluatedCount: effectiveRules.length,
    violations,
    invalidRules
  };
}

// ============================================================================
// Git Blame & Causal Commit Rationale Helpers
// ============================================================================

function findNearestGitMarker(startDir) {
  let curr = path.resolve(startDir);
  while (true) {
    try {
      if (fs.existsSync(path.join(curr, '.git'))) {
        return curr;
      }
    } catch {
      return null;
    }
    const parent = path.dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return null;
}

function resolveCanonicalWorkspace(workspaceRoot) {
  if (!workspaceRoot || typeof workspaceRoot !== 'string') return null;
  const resolved = path.resolve(workspaceRoot);
  let realRoot;
  try {
    if (!fs.existsSync(resolved)) return null;
    realRoot = fs.realpathSync(resolved);
  } catch {
    return null;
  }
  const gitRoot = findNearestGitMarker(realRoot) || (process.env.GIT_DIR ? realRoot : null);
  if (!gitRoot) return null;
  return { resolvedRoot: resolved, realRoot, gitRoot };
}

function isLockfilePath(filePath) {
  const base = path.basename(String(filePath || '')).toLowerCase();
  return !base || LOCKFILE_NAMES.has(base) || base.endsWith('.lock');
}

/**
 * Safely resolves `candidatePath` strictly inside `workspaceCtx.realRoot` (preventing `..`
 * path traversal, symlink escape, lockfiles, oversized files, and binary NUL-byte blobs).
 */
function resolveSafeWorkspaceRepoFile(candidatePath, workspaceCtx, { fromDiffHeader = false } = {}) {
  if (!candidatePath || typeof candidatePath !== 'string' || candidatePath.includes('\0')) {
    return null;
  }
  const trimmed = candidatePath.trim();
  if (!trimmed || trimmed === '/dev/null') return null;

  const candidates = [];
  if (path.isAbsolute(trimmed)) {
    const abs = path.resolve(trimmed);
    if (
      abs !== workspaceCtx.resolvedRoot &&
      !abs.startsWith(workspaceCtx.resolvedRoot + path.sep) &&
      abs !== workspaceCtx.realRoot &&
      !abs.startsWith(workspaceCtx.realRoot + path.sep)
    ) {
      return null;
    }
    candidates.push(abs);
  } else {
    const rawUnquoted = unquoteGitPath(trimmed).replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');
    if (!rawUnquoted || rawUnquoted.startsWith('/')) return null;
    const rawParts = rawUnquoted.split('/');
    if (rawParts.some((p) => !p || p === '.' || p === '..')) return null;

    if (fromDiffHeader) {
      const stripped = rawUnquoted.replace(/^[ab]\//, '');
      if (stripped) candidates.push(path.resolve(workspaceCtx.realRoot, stripped));
      if (stripped !== rawUnquoted) {
        candidates.push(path.resolve(workspaceCtx.realRoot, rawUnquoted));
      }
    } else {
      candidates.push(path.resolve(workspaceCtx.realRoot, rawUnquoted));
      if (/^[ab]\//.test(rawUnquoted)) {
        candidates.push(path.resolve(workspaceCtx.realRoot, rawUnquoted.slice(2)));
      }
    }

    // If diff paths are relative to a parent monorepo gitRoot while workspaceRoot is a sub-folder
    if (workspaceCtx.gitRoot && workspaceCtx.realRoot.startsWith(workspaceCtx.gitRoot + path.sep)) {
      const wsSubPrefix =
        path.relative(workspaceCtx.gitRoot, workspaceCtx.realRoot).replace(/\\/g, '/') + '/';
      const strippedDiff = rawUnquoted.replace(/^[ab]\//, '');
      if (strippedDiff.startsWith(wsSubPrefix)) {
        const subRel = strippedDiff.slice(wsSubPrefix.length);
        if (subRel && !subRel.split('/').some((p) => !p || p === '.' || p === '..')) {
          candidates.push(path.resolve(workspaceCtx.realRoot, subRel));
        }
      }
    }
  }

  for (const candAbs of candidates) {
    try {
      if (!fs.existsSync(candAbs)) continue;
      const realAbs = fs.realpathSync(candAbs);
      if (realAbs === workspaceCtx.realRoot || !realAbs.startsWith(workspaceCtx.realRoot + path.sep)) {
        continue;
      }
      const wsRelPath = path.relative(workspaceCtx.realRoot, realAbs).replace(/\\/g, '/');
      if (!wsRelPath || wsRelPath.startsWith('..') || path.isAbsolute(wsRelPath)) continue;
      if (isLockfilePath(wsRelPath)) continue;

      const st = fs.statSync(realAbs);
      if (!st.isFile() || st.size === 0 || st.size > MAX_BLAMEABLE_FILE_BYTES) continue;

      const buf = fs.readFileSync(realAbs);
      if (buf.indexOf(0) !== -1) continue;

      const text = buf.toString('utf8');
      const totalLines = text.split(/\r?\n/).length;
      return { absPath: realAbs, wsRelPath, text, totalLines };
    } catch {
      continue;
    }
  }

  return null;
}

function coalesceLineRanges(lines) {
  if (!Array.isArray(lines) || lines.length === 0) return [];
  const sorted = [...new Set(lines.filter((n) => Number.isInteger(n) && n >= 1))].sort(
    (a, b) => a - b
  );
  if (sorted.length === 0) return [];

  const ranges = [];
  let start = sorted[0];
  let prev = sorted[0];
  for (let i = 1; i < sorted.length; i += 1) {
    const cur = sorted[i];
    if (cur === prev + 1) {
      prev = cur;
    } else {
      ranges.push([start, prev]);
      start = cur;
      prev = cur;
    }
  }
  ranges.push([start, prev]);
  return ranges;
}

function formatLineRangesLabel(filePath, ranges) {
  if (!ranges || ranges.length === 0) return filePath;
  const shown = ranges.slice(0, 3).map(([s, e]) => (s === e ? `L${s}` : `L${s}-L${e}`));
  const extra = ranges.length > 3 ? ` (+${ranges.length - 3} more)` : '';
  return `${filePath}#${shown.join(',')}${extra}`;
}

function resolvePreEditSnippetRanges(currentFileText, snippetText) {
  if (!currentFileText || !snippetText) return [];
  const cur = String(currentFileText).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const snip = String(snippetText).replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\n+$/, '');
  const trimmed = snip.trim();
  if (!trimmed) return [];

  const lineNumberAt = (text, charOffset) => {
    let line = 1;
    for (
      let idx = text.indexOf('\n');
      idx !== -1 && idx < charOffset;
      idx = text.indexOf('\n', idx + 1)
    ) {
      line += 1;
    }
    return line;
  };

  const exactRanges = [];
  for (const needle of [snip, trimmed]) {
    if (!needle) continue;
    const lineSpan = needle.split('\n').length - 1;
    let pos = cur.indexOf(needle);
    while (pos !== -1 && exactRanges.length < MAX_SNIPPET_OCCURRENCES) {
      const startLine = lineNumberAt(cur, pos);
      exactRanges.push([startLine, Math.min(startLine + lineSpan, startLine + MAX_HUNK_LINES - 1)]);
      pos = cur.indexOf(needle, pos + needle.length);
    }
    if (exactRanges.length > 0) return exactRanges;
  }

  const curLines = cur.replace(/\n+$/, '').split('\n');
  const nextLines = snip.split('\n');
  if (nextLines.length >= 2 && curLines.length >= 2) {
    let head = 0;
    while (
      head < curLines.length &&
      head < nextLines.length &&
      curLines[head] === nextLines[head]
    ) {
      head += 1;
    }
    let tail = 0;
    while (
      tail < curLines.length - head &&
      tail < nextLines.length - head &&
      curLines[curLines.length - 1 - tail] === nextLines[nextLines.length - 1 - tail]
    ) {
      tail += 1;
    }
    if (head > 0 || tail > 0) {
      const endLine = curLines.length - tail;
      if (endLine >= head + 1) {
        return [[head + 1, Math.min(endLine, head + MAX_HUNK_LINES)]];
      }
    }
  }

  const matchedLineNums = [];
  const curTrimmedMap = new Map();
  for (let i = 0; i < curLines.length; i += 1) {
    const t = curLines[i].trim();
    if (t.length >= 12 && !curTrimmedMap.has(t)) {
      curTrimmedMap.set(t, i + 1);
    }
  }
  for (const rawLine of nextLines) {
    const t = rawLine.trim();
    if (t.length >= 12 && curTrimmedMap.has(t)) {
      matchedLineNums.push(curTrimmedMap.get(t));
      if (matchedLineNums.length >= MAX_HUNK_LINES) break;
    }
  }
  return coalesceLineRanges(matchedLineNums).slice(0, MAX_SNIPPET_OCCURRENCES);
}

function clampRangesToFileLength(ranges, totalLines) {
  if (!Array.isArray(ranges) || totalLines < 1) return [];
  const out = [];
  for (const [rawStart, rawEnd] of ranges) {
    if (!Number.isInteger(rawStart) || rawStart > totalLines) continue;
    const s = Math.max(1, rawStart);
    const e = Math.min(totalLines, Math.max(s, Number.isInteger(rawEnd) ? rawEnd : s));
    out.push([s, e]);
  }
  return out;
}

function runGitExec(args, cwd, timeoutMs = DEFAULT_BLAME_TIMEOUT_MS) {
  return execFileSync('git', args, {
    cwd,
    timeout: Math.max(100, Math.min(DEFAULT_BLAME_TIMEOUT_MS, Math.floor(timeoutMs))),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    maxBuffer: 4 * 1024 * 1024
  });
}

function parseGitBlamePorcelain(porcelainOutput) {
  const commits = new Map();
  const lineCommits = [];
  if (!porcelainOutput || typeof porcelainOutput !== 'string') {
    return { commits, lineCommits };
  }

  let currentSha = null;
  let currentFinalLine = null;

  for (const line of porcelainOutput.split('\n')) {
    const header = /^([0-9a-f]{40})\s+\d+\s+(\d+)(?:\s+\d+)?$/.exec(line);
    if (header) {
      currentSha = header[1].toLowerCase();
      currentFinalLine = Number(header[2]);
      if (!UNCOMMITTED_ZERO_SHA_RE.test(currentSha)) {
        if (!commits.has(currentSha)) {
          commits.set(currentSha, {
            sha: currentSha,
            summary: '',
            isMechanical: false,
            prNumbers: [],
            lines: []
          });
        }
        commits.get(currentSha).lines.push(currentFinalLine);
        lineCommits.push({ line: currentFinalLine, sha: currentSha });
      }
      continue;
    }

    if (
      currentSha &&
      !UNCOMMITTED_ZERO_SHA_RE.test(currentSha) &&
      line.startsWith('summary ')
    ) {
      const summary = line.slice(8).trim();
      const entry = commits.get(currentSha);
      if (entry && !entry.summary) {
        entry.summary = summary;
        entry.isMechanical = MECHANICAL_COMMIT_SUBJECT_RE.test(summary);
        const prs = new Set();
        for (const m of summary.matchAll(
          /(?:\(#(\d+)\)\s*$|^Merge pull request #(\d+)\b|\bPR\s*#(\d+)\b)/gi
        )) {
          const num = m[1] || m[2] || m[3];
          if (num) prs.add(num);
        }
        entry.prNumbers = [...prs];
      }
    }
  }

  return { commits, lineCommits };
}

function extractHexShaCandidates(text) {
  if (!text || typeof text !== 'string') return [];
  const found = [];
  for (const m of text.matchAll(HEX_SHA_TOKEN_RE)) {
    const lower = m[1].toLowerCase();
    if (ENGLISH_HEX_WORDS.has(lower)) continue;
    found.push(lower);
  }
  return found;
}

function extractLineRangeFromLocator(locator) {
  if (!locator || typeof locator !== 'string') return null;
  const trimmed = locator.trim();
  const direct = /^L?(\d+)(?:\s*-\s*L?(\d+))?$/i.exec(trimmed);
  if (direct) {
    const s = Number.parseInt(direct[1], 10);
    const e = direct[2] ? Number.parseInt(direct[2], 10) : s;
    if (s >= 1 && e >= s) return { startLine: s, endLine: e };
  }
  const embedded = /(?:^|[\s#@:])L(\d+)(?:\s*-\s*L?(\d+))?(?:$|[\s@,;])/i.exec(trimmed);
  if (embedded) {
    const s = Number.parseInt(embedded[1], 10);
    const e = embedded[2] ? Number.parseInt(embedded[2], 10) : s;
    if (s >= 1 && e >= s) return { startLine: s, endLine: e };
  }
  return null;
}

function shaMatchesPrefix(fullSha, candidatePrefix) {
  if (!fullSha || !candidatePrefix) return false;
  const a = String(fullSha).trim().toLowerCase();
  const b = String(candidatePrefix).trim().toLowerCase();
  if (b.length < 7 || !/^[0-9a-f]+$/.test(b)) return false;
  return a.startsWith(b) || b.startsWith(a);
}

// Causal commit rationale extraction (supports explicit Constraint:/Invariant:/Warning:/Reason:/Why: labels + prose markers)
const TRAILER_LINE_RE =
  /^\s*(?:co-authored-by|signed-off-by|reviewed-by|reviewed-on|acked-by|tested-by|reported-by|suggested-by|helped-by|change-id|pr-url|cc|bug|ticket|tracker|issue)\s*:/i;
const FIXES_ONLY_RE =
  /^\s*(?:fix(?:e[sd])?|close[sd]?|resolve[sd]?|refs?|see|related to|part of)\b:?\s*(?:#\d+|gh-\d+|[\w.-]+\/[\w.-]+#\d+|https?:\/\/\S+)(?:[\s,;&]+(?:and\s+)?(?:#\d+|gh-\d+|[\w.-]+\/[\w.-]+#\d+|https?:\/\/\S+))*\s*[.]?\s*$/i;
const BUMP_BODY_RE =
  /^\s*(?:bumps?|updates?|upgrades?)\s+(?:\[?`?[\w@/.-]+`?\]?(?:\([^)]*\))?\s+)?(?:from|to)\b|this pr contains the following updates|^\s*dependabot will resolve/im;
const DUMP_HEADING_RE =
  /^\s{0,3}(?:#{1,6}\s*)?(?:\*\*)?(?:what'?s changed|release notes?|changelog|full changelog|commits|sourced from)\b/im;
const EXPLICIT_DIRECTIVE_LABEL_RE =
  /^((?:constraint|invariant|warning|caution|reason|why|rationale|motivation)\s*:\s*)(.+)$/i;
const EMPTY_LABEL_RE = /^(?:n\/?a|none|see\b|tbd|todo|-)\b/i;
const NEGATED_BECAUSE_RE = /(?:\bnot|\bnever|n't)\s+(?:just\s+|only\s+|simply\s+)?because\b/i;
const CONVENTIONAL_SUBJECT_RE = /^[a-z]+(?:\([^)]*\))?!?:\s+/i;

const STRONG_CAUSAL_MARKERS = [
  /\bbecause\b/i,
  /\bso that\b/i,
  /\bin order to\b/i,
  /\bto avoid\b/i,
  /\bto prevent\b/i,
  /\bdue to\b/i,
  /\bas a result\b/i,
  /\bwas causing\b/i,
  /\bcaused by\b/i,
  /\bsince\s+(?:(?:the|it|its|this|that|there|a|an|these|those|all|both|each|every|no|not|only)\b(?!\s+(?:last|first|previous|beginning|start|release|version|v?\d))|[\w.:/#-]+\s+(?:is|are|was|were|has|have|had|does|do|can|could|will|would|must|should|may|might|needs?|uses?|stores?|ignores?|supports?|reads?|runs?|returns?|calls?|requires?|handles?|caches?)\b)/i
];

const MEDIUM_CAUSAL_MARKERS = [
  /\binstead of\b/i,
  /\brather than\b/i,
  /\bpreviously\b/i,
  /\bno longer\b/i,
  /\botherwise\b/i,
  /\bto fix\b/i,
  /\bregression\b/i
];

const PROBLEM_NOUN_RE =
  /\b(?:break(?:s|ing)?|broke|broken|fail(?:s|ed|ing|ure)?|crash(?:es|ed|ing)?|leak(?:s|ed|ing)?|corrupt(?:s|ed|ion)?|deadlock(?:s|ed)?|race\b|timeout(?:s)?|hang(?:s|ing)?|bug(?:s)?|error(?:s)?|wrong(?:ly)?|incorrect(?:ly)?|vulnerab\w*|cache[sd]?)\b/i;

function stripInlineMarkup(text) {
  return String(text || '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/<\/?[a-z][a-z0-9]*\b[^>]*>/gi, ' ')
    .replace(/(\*\*|__)(.+?)\1/g, '$2')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

function contentWordList(text) {
  return String(text || '').toLowerCase().match(/[a-z0-9]{3,}/g) || [];
}

function repeatsCommitTitle(sentence, titleWordSet) {
  if (titleWordSet.size < 3) return false;
  const words = contentWordList(sentence);
  if (words.length === 0) return true;
  let overlap = 0;
  for (const w of words) {
    if (titleWordSet.has(w)) overlap += 1;
  }
  return overlap / words.length >= 0.8 && words.length <= titleWordSet.size + 3;
}

function capAtWordBoundary(sentence, maxChars) {
  if (sentence.length <= maxChars) return sentence;
  const cut = sentence.slice(0, maxChars - 3);
  const lastSpace = cut.lastIndexOf(' ');
  return (lastSpace > Math.floor(maxChars * 0.5) ? cut.slice(0, lastSpace) : cut).trimEnd() + '...';
}

function extractCommitCausalRationale(title, body, { maxSentences = 2, maxChars = 200 } = {}) {
  if (!body || typeof body !== 'string') return null;

  let text = body.replace(/\r\n?/g, '\n').slice(0, 6000);
  if (BUMP_BODY_RE.test(text)) return null;

  const dumpMatch = DUMP_HEADING_RE.exec(text);
  if (dumpMatch) text = text.slice(0, dumpMatch.index);

  text = text
    .replace(/<!--[\s\S]*?(?:-->|$)/g, '\n')
    .replace(/^\s*(```|~~~)[\s\S]*?(?:^\s*\1|$(?![\s\S]))/gm, '\n');

  const flatTitle = String(title || '').replace(/\s+/g, ' ').trim();
  const titleWords = new Set(contentWordList(flatTitle.replace(CONVENTIONAL_SUBJECT_RE, '')));

  const paragraphs = [];
  let buf = [];
  for (const rawLine of text.split('\n')) {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      if (buf.length > 0) {
        paragraphs.push(buf.join(' '));
        buf = [];
      }
      continue;
    }
    if (TRAILER_LINE_RE.test(trimmed) || FIXES_ONLY_RE.test(trimmed) || /^\|.*\|$/.test(trimmed)) {
      if (buf.length > 0) {
        paragraphs.push(buf.join(' '));
        buf = [];
      }
      continue;
    }
    const strippedBullet = trimmed.replace(/^(?:[-*+]|\d+[.)])\s+/, '');
    if (EXPLICIT_DIRECTIVE_LABEL_RE.test(strippedBullet)) {
      if (buf.length > 0) {
        paragraphs.push(buf.join(' '));
        buf = [];
      }
      paragraphs.push(strippedBullet);
      continue;
    }
    if (strippedBullet !== trimmed) {
      if (buf.length > 0) {
        paragraphs.push(buf.join(' '));
        buf = [];
      }
      paragraphs.push(strippedBullet);
      continue;
    }
    buf.push(trimmed);
  }
  if (buf.length > 0) paragraphs.push(buf.join(' '));

  const candidates = [];
  let pos = 0;

  for (const para of paragraphs) {
    const cleaned = stripInlineMarkup(para);
    if (!cleaned || cleaned === flatTitle) continue;

    const labelMatch = EXPLICIT_DIRECTIVE_LABEL_RE.exec(cleaned);
    if (labelMatch) {
      const rawPrefix = labelMatch[1].trim();
      const rest = labelMatch[2].trim();
      if (!rest || EMPTY_LABEL_RE.test(rest)) continue;
      const restWords = rest.split(/\s+/).filter(Boolean);
      if (restWords.length >= 2) {
        pos += 1;
        const preservePrefix = /^(?:constraint|invariant|warning|caution|reason)\s*:/i.test(
          rawPrefix
        );
        const formatted = preservePrefix ? `${rawPrefix} ${rest}` : rest;
        candidates.push({
          pos,
          score: 5,
          text: capAtWordBoundary(formatted, maxChars)
        });
      }
      continue;
    }

    const sentences = cleaned.split(/(?<=[.!?])\s+(?=[A-Z0-9"'([])/);
    for (let idx = 0; idx < sentences.length; idx += 1) {
      const s = sentences[idx].trim();
      pos += 1;
      const words = s.split(/\s+/).filter(Boolean);
      if (words.length < 5 || /\?$/.test(s)) continue;
      if (repeatsCommitTitle(s, titleWords)) continue;

      const unquoted = s.replace(/"[^"]*"/g, ' ');
      if (NEGATED_BECAUSE_RE.test(unquoted)) continue;

      let score = 0;
      if (STRONG_CAUSAL_MARKERS.some((rx) => rx.test(unquoted))) {
        score = 3;
      } else if (MEDIUM_CAUSAL_MARKERS.some((rx) => rx.test(unquoted)) && PROBLEM_NOUN_RE.test(unquoted)) {
        score = 2;
      }

      if (score >= 2) {
        candidates.push({ pos, score, text: capAtWordBoundary(s, maxChars) });
      }
    }
  }

  if (candidates.length === 0) return null;
  const top = [...candidates]
    .sort((a, b) => b.score - a.score || a.pos - b.pos)
    .slice(0, maxSentences)
    .sort((a, b) => a.pos - b.pos);
  return top.map((c) => c.text).join(' ');
}

function filesMatchRelative(pathA, pathB) {
  if (!pathA || !pathB) return false;
  const a = normalizeRepoRelativePath(pathA, { stripDiffPrefix: true });
  const b = normalizeRepoRelativePath(pathB, { stripDiffPrefix: true });
  if (!a || !b) return false;
  return a === b || a.endsWith('/' + b) || b.endsWith('/' + a);
}

/**
 * Runs `git blame -w -M --porcelain` on rewritten old diff hunks (or `filePath` for `pre_edit`),
 * safely verifying `filePath` stays inside `workspaceRoot` and failing gracefully (`[]`) when
 * `workspaceRoot` is not a git repo or `git` errors.
 *
 * Matches blamed commit SHAs (full or >=7-char prefix in active `context_memories.content` or
 * `provenance_locator`), overlapping `provenance_file` + line-range anchors, and causal commit
 * rationale (`Constraint:` / `Invariant:` / `Warning:` / `Reason:` / `because`...) from `git show`.
 *
 * @param {string} diffOrSnippet
 * @param {{ filePath?: string, workspaceRoot?: string, db?: any }} [options]
 * @returns {Array<object>}
 */
export function findBlamedDiffMemories(
  diffOrSnippet,
  { filePath = '', workspaceRoot = process.cwd(), db = null } = {}
) {
  const rawInput = typeof diffOrSnippet === 'string' ? diffOrSnippet : '';
  const callerFile = typeof filePath === 'string' ? filePath.trim() : '';
  if (!rawInput && !callerFile) return [];

  const wsCtx = resolveCanonicalWorkspace(workspaceRoot);
  if (!wsCtx) return [];

  /** @type {Array<{ resolved: { absPath: string, wsRelPath: string, text: string, totalLines: number }, blameRanges: Array<[number, number]>, overlapRanges: Array<[number, number]> }>} */
  const targets = [];

  if (rawInput && isUnifiedDiffText(rawInput)) {
    const parsedFiles = parseUnifiedDiffFiles(rawInput);
    for (const pf of parsedFiles) {
      if (targets.length >= MAX_BLAME_FILES) break;
      if (!pf.oldPath || pf.oldHunks.length === 0) continue;
      const resolved = resolveSafeWorkspaceRepoFile(pf.oldPath, wsCtx, { fromDiffHeader: true });
      if (!resolved) continue;

      const hunkRanges = pf.oldHunks.map((h) => [h.startLine, h.endLine]);
      const rewritten = pf.oldHunks.flatMap((h) => h.rewrittenLines);
      const preferredRanges =
        rewritten.length > 0 ? coalesceLineRanges(rewritten) : hunkRanges;
      const clampedBlame = clampRangesToFileLength(preferredRanges, resolved.totalLines);
      const clampedOverlap = clampRangesToFileLength(hunkRanges, resolved.totalLines);
      if (clampedBlame.length === 0 && clampedOverlap.length === 0) continue;

      targets.push({
        resolved,
        blameRanges: clampedBlame.length > 0 ? clampedBlame : clampedOverlap,
        overlapRanges: clampedOverlap.length > 0 ? clampedOverlap : clampedBlame
      });
    }
  } else if (callerFile) {
    const resolved = resolveSafeWorkspaceRepoFile(callerFile, wsCtx, { fromDiffHeader: false });
    if (!resolved) return [];

    let snippetRanges = rawInput ? resolvePreEditSnippetRanges(resolved.text, rawInput) : [];
    if (snippetRanges.length === 0 && !rawInput) {
      snippetRanges = [[1, Math.min(resolved.totalLines, MAX_HUNK_LINES)]];
    }
    const clamped = clampRangesToFileLength(snippetRanges, resolved.totalLines);
    if (clamped.length > 0) {
      targets.push({
        resolved,
        blameRanges: clamped,
        overlapRanges: clamped
      });
    }
  }

  if (targets.length === 0) return [];

  const deadline = Date.now() + DEFAULT_BLAME_TIMEOUT_MS;
  const blamedEntries = [];

  for (const target of targets) {
    const remaining = deadline - Date.now();
    if (remaining <= 40) break;

    let commits = new Map();
    try {
      const rangeArgs = target.blameRanges.flatMap(([s, e]) => ['-L', `${s},${e}`]);
      const stdout = runGitExec(
        ['blame', '-w', '-M', '--porcelain', ...rangeArgs, '--', target.resolved.wsRelPath],
        wsCtx.realRoot,
        remaining
      );
      commits = parseGitBlamePorcelain(stdout).commits;
    } catch {
      // Fail gracefully if file is untracked in HEAD or git blame errors
    }

    blamedEntries.push({
      wsRelPath: target.resolved.wsRelPath,
      overlapRanges: target.overlapRanges,
      commits
    });
  }

  if (blamedEntries.length === 0) return [];

  let allRows = [];
  if (db) {
    try {
      const cache = getAlignmentStmtCache(db);
      if (cache && typeof db.prepare === 'function') {
        if (!cache.blameSelectStmt) {
          cache.blameSelectStmt = db.prepare(
            `SELECT
               id,
               category,
               status,
               content,
               provenance_file,
               provenance_locator,
               quoted_sentence,
               anchor_hash
             FROM context_memories
             ORDER BY id DESC
             LIMIT ${MAX_ALIGNMENT_MEMORY_SCAN}`
          );
        }
        allRows = cache.blameSelectStmt.all();
      }
    } catch (err) {
      if (isSqliteCorruptionError(err)) {
        throw err;
      }
      allRows = [];
    }
  }

  // Track commits already represented by ANY memory row (including superseded/invalidated)
  // so raw commit-body fallback never resurrects retired decisions.
  const trackedCommitShas = new Set();
  const findings = [];
  const matchedRowIds = new Set();

  for (const row of allRows) {
    const rowHexShas = [
      ...extractHexShaCandidates(row.provenance_locator),
      ...extractHexShaCandidates(row.content)
    ];
    if (rowHexShas.length > 0) {
      for (const entry of blamedEntries) {
        for (const blamedSha of entry.commits.keys()) {
          if (rowHexShas.some((cand) => shaMatchesPrefix(blamedSha, cand))) {
            trackedCommitShas.add(blamedSha);
          }
        }
      }
    }

    if (String(row.status || '').toLowerCase() !== 'active') continue;

    const content = String(row.content || '');
    const locatorStr = String(row.provenance_locator || '');
    let matchedCitation = null;
    let matchedSha = null;
    let matchedFile = null;

    for (const entry of blamedEntries) {
      // 1. Blamed commit SHA or explicit PR number match
      for (const [sha, commitInfo] of entry.commits.entries()) {
        const commitHit = rowHexShas.some((cand) => shaMatchesPrefix(sha, cand));
        const prHit =
          !commitInfo.isMechanical &&
          commitInfo.prNumbers.some(
            (prNum) =>
              new RegExp(`(?:\\bPR\\s*#|/pull/)${prNum}\\b`, 'i').test(content) ||
              new RegExp(`(?:^|\\bPR\\s*#|/pull/|#)${prNum}\\b`, 'i').test(locatorStr)
          );

        if (commitHit || prHit) {
          trackedCommitShas.add(sha);
          const ranges = coalesceLineRanges(commitInfo.lines);
          matchedSha = sha;
          matchedFile = entry.wsRelPath;
          matchedCitation = `${formatLineRangesLabel(entry.wsRelPath, ranges)} @ ${sha.slice(0, 7)}`;
          break;
        }
      }
      if (matchedCitation) break;

      // 2. Overlapping provenance_file + line-range anchor on rewritten hunk
      if (row.provenance_file && filesMatchRelative(row.provenance_file, entry.wsRelPath)) {
        const range = extractLineRangeFromLocator(locatorStr);
        if (range) {
          const overlaps = entry.overlapRanges.some(
            ([hStart, hEnd]) => range.startLine <= hEnd && range.endLine >= hStart
          );
          if (overlaps) {
            matchedFile = entry.wsRelPath;
            matchedCitation =
              range.startLine === range.endLine
                ? `${entry.wsRelPath}#L${range.startLine}`
                : `${entry.wsRelPath}#L${range.startLine}-L${range.endLine}`;
            break;
          }
        }
      }
    }

    if (matchedCitation && !matchedRowIds.has(Number(row.id))) {
      matchedRowIds.add(Number(row.id));
      const shortSha = matchedSha ? matchedSha.slice(0, 7) : null;
      findings.push({
        memory_id: Number(row.id),
        id: Number(row.id),
        category: row.category,
        severity: row.category === 'invariant' || row.category === 'blocker' ? 'error' : 'warning',
        source: 'memory_blame',
        commit: shortSha,
        file: matchedFile,
        citation: matchedCitation,
        matched_token: shortSha || matchedCitation,
        rule: content,
        content,
        message: `Blamed ${row.category} #${row.id} (${matchedCitation}): ${content}`
      });
    }
  }

  // 3. Causal commit message rationale fallback (Constraint:/Invariant:/Warning:/Reason:/because...)
  if (findings.length < 3) {
    const inspectedShas = new Set();
    for (const entry of blamedEntries) {
      if (findings.length >= 3) break;
      for (const [sha, commitInfo] of entry.commits.entries()) {
        if (findings.length >= 3) break;
        if (commitInfo.isMechanical || trackedCommitShas.has(sha) || inspectedShas.has(sha)) {
          continue;
        }
        inspectedShas.add(sha);

        const remaining = deadline - Date.now();
        if (remaining <= 40) break;

        try {
          const showOut = runGitExec(
            ['show', '-s', '--format=%s%n%n%b', sha],
            wsCtx.realRoot,
            remaining
          );
          const splitIdx = showOut.indexOf('\n\n');
          const subject = (splitIdx === -1 ? showOut : showOut.slice(0, splitIdx)).trim();
          const body = splitIdx === -1 ? '' : showOut.slice(splitIdx + 2);
          const rationale = extractCommitCausalRationale(subject, body);
          if (rationale) {
            const shortSha = sha.slice(0, 7);
            const ranges = coalesceLineRanges(commitInfo.lines);
            const citation = `${formatLineRangesLabel(entry.wsRelPath, ranges)} @ ${shortSha}`;
            const isStrictConstraint = /^(?:constraint|invariant|warning|caution)\s*:/i.test(
              rationale
            );
            findings.push({
              memory_id: null,
              id: `git:${shortSha}`,
              category: isStrictConstraint ? 'invariant' : 'decision',
              severity: isStrictConstraint ? 'error' : 'warning',
              source: 'commit_rationale',
              commit: shortSha,
              file: entry.wsRelPath,
              citation,
              matched_token: shortSha,
              rationale,
              rule: `${subject} (${rationale})`,
              content: `${subject} (${rationale})`,
              message: `Causal commit rationale @ ${shortSha} (${citation}): ${subject} (${rationale})`
            });
          }
        } catch {
          // Fail gracefully when commit object is unavailable
        }
      }
    }
  }

  return findings;
}

// ============================================================================
// Superseded Stale-Code Scanner (`INV-ALIGN-STALE-02`)
// ============================================================================

function resolveTerminalActiveReplacement(rowId, byIdMap) {
  let cur = byIdMap.get(Number(rowId));
  const visited = new Set([Number(rowId)]);
  let hops = 0;
  while (cur && cur.superseded_by && !visited.has(Number(cur.superseded_by)) && hops < 8) {
    const nextId = Number(cur.superseded_by);
    visited.add(nextId);
    const next = byIdMap.get(nextId);
    if (!next) break;
    cur = next;
    hops += 1;
  }
  if (!cur || Number(cur.id) === Number(rowId)) return null;
  return String(cur.status || '').toLowerCase() === 'active' ? cur : null;
}

function isReRatifiedByActiveReplacement(oldRow, replRow, oldSha, db) {
  if (!replRow) return false;

  const replShas = [
    ...extractHexShaCandidates(replRow.provenance_locator),
    ...extractHexShaCandidates(replRow.content)
  ];

  // If the active replacement explicitly cites the exact same commit SHA, it re-ratifies that commit.
  if (oldSha && replShas.some((cand) => shaMatchesPrefix(cand, oldSha))) {
    return true;
  }

  if (!oldRow.provenance_file || !replRow.provenance_file) {
    return false;
  }
  if (!filesMatchRelative(oldRow.provenance_file, replRow.provenance_file)) {
    return false;
  }

  const sameAnchor =
    (oldRow.anchor_hash &&
      replRow.anchor_hash &&
      oldRow.anchor_hash === replRow.anchor_hash) ||
    (oldRow.quoted_sentence &&
      replRow.quoted_sentence &&
      String(oldRow.quoted_sentence).trim() === String(replRow.quoted_sentence).trim());

  if (!sameAnchor) return false;

  // Note: `context-engine.js` `revise()` copies `existing.provenance_*` by default when
  // `provenance` is omitted. Treat same-anchor replacement as an intentional re-ratification
  // ONLY when:
  //   (a) `revise` was called with an explicit `provenance` object (`provenance_reanchored = 1` or `wasExplicitlyReanchored`), OR
  //   (b) replacement explicitly cites a new commit SHA alongside the preserved anchor, OR
  //   (c) replacement updated `provenance_locator` while preserving the quote/hash.
  if (Number(replRow.provenance_reanchored) === 1 || wasExplicitlyReanchored(db, replRow.id)) {
    return true;
  }
  if (replShas.length > 0) {
    return true;
  }
  if (
    String(oldRow.provenance_locator || '').trim() !==
    String(replRow.provenance_locator || '').trim()
  ) {
    return true;
  }

  return false;
}

function extractSpanLines(fileContent, startLine, endLine) {
  const lines = String(fileContent || '').split(/\r?\n/);
  return lines.slice(startLine - 1, endLine).join('\n');
}

/**
 * Inspects `status = 'superseded'` rows in `context_memories` that cite a 7-40 hex commit SHA
 * (or `provenance_file` + `L<start>-L<end>`) and checks via `git blame --porcelain` whether
 * lines on `HEAD` are still owned by that superseded commit / anchor (unless re-ratified by
 * the replacement active memory `#superseded_by`).
 *
 * Fails gracefully with `{ findings: [], totalStaleLines: 0 }` outside git repositories.
 *
 * @param {{ workspaceRoot?: string, db?: any }} [options]
 * @returns {{ findings: Array<object>, totalStaleLines: number }}
 */
export function scanSupersededStaleCode({ workspaceRoot = process.cwd(), db = null } = {}) {
  if (!db) {
    return { findings: [], totalStaleLines: 0 };
  }

  const wsCtx = resolveCanonicalWorkspace(workspaceRoot);
  if (!wsCtx) {
    return { findings: [], totalStaleLines: 0 };
  }

  let rows = [];
  const cache = getAlignmentStmtCache(db);
  if (!cache || typeof db.prepare !== 'function') {
    return { findings: [], totalStaleLines: 0 };
  }
  try {
    if (!cache.staleSelectStmt) {
      cache.staleSelectStmt = db.prepare(
        `SELECT
           id,
           category,
           content,
           status,
           superseded_by,
           provenance_file,
           provenance_locator,
           quoted_sentence,
           anchor_hash,
           provenance_reanchored
         FROM context_memories
         ORDER BY id DESC
         LIMIT ${MAX_ALIGNMENT_MEMORY_SCAN}`
      );
    }
    rows = cache.staleSelectStmt.all();
  } catch (err) {
    if (isSqliteCorruptionError(err)) {
      throw err;
    }
    if (isMissingReanchorColumnError(err)) {
      cache.staleSelectStmt = null;
      try {
        if (!cache.staleSelectFallbackStmt) {
          cache.staleSelectFallbackStmt = db.prepare(
            `SELECT
               id,
               category,
               content,
               status,
               superseded_by,
               provenance_file,
               provenance_locator,
               quoted_sentence,
               anchor_hash
             FROM context_memories
             ORDER BY id DESC
             LIMIT ${MAX_ALIGNMENT_MEMORY_SCAN}`
          );
        }
        rows = cache.staleSelectFallbackStmt.all();
      } catch (fallbackErr) {
        if (isSqliteCorruptionError(fallbackErr)) {
          throw fallbackErr;
        }
        return { findings: [], totalStaleLines: 0 };
      }
    } else {
      return { findings: [], totalStaleLines: 0 };
    }
  }

  rows.reverse();

  const byId = new Map();
  for (const r of rows) {
    byId.set(Number(r.id), r);
  }

  const deadline = Date.now() + DEFAULT_BLAME_TIMEOUT_MS;
  const blameCache = new Map();
  const findings = [];
  let totalStaleLines = 0;

  for (const row of rows) {
    if (String(row.status || '').toLowerCase() !== 'superseded') continue;
    if (Date.now() >= deadline) break;

    const replacement = row.superseded_by
      ? resolveTerminalActiveReplacement(row.id, byId)
      : null;
    if (row.superseded_by && !replacement) {
      // Superseded chain terminated in an invalidated row rather than an active replacement
      continue;
    }

    const rowShas = [
      ...extractHexShaCandidates(row.provenance_locator),
      ...extractHexShaCandidates(row.content)
    ];
    const oldSha = rowShas[0] || null;
    const locatorRange = extractLineRangeFromLocator(row.provenance_locator);

    if (!oldSha && !(row.provenance_file && (locatorRange || row.quoted_sentence))) {
      continue;
    }

    if (isReRatifiedByActiveReplacement(row, replacement, oldSha, db)) {
      continue;
    }

    /** @type {Array<{ wsRelPath: string, scopedRanges: Array<[number, number]> | null, requireCommitMatch: string | null }>} */
    const candidateTargets = [];

    if (row.provenance_file) {
      const resolved = resolveSafeWorkspaceRepoFile(row.provenance_file, wsCtx, {
        fromDiffHeader: false
      });
      if (!resolved) continue;

      let scopedRanges = null;
      const quoted = row.quoted_sentence ? String(row.quoted_sentence).trim() : '';

      if (quoted) {
        const quoteRanges = resolvePreEditSnippetRanges(resolved.text, quoted);
        if (quoteRanges.length === 0) {
          // Quoted span was already removed or rewritten on disk
          continue;
        }
        scopedRanges = clampRangesToFileLength(quoteRanges, resolved.totalLines);
        if (scopedRanges.length === 0) continue;
      } else if (locatorRange) {
        scopedRanges = clampRangesToFileLength(
          [[locatorRange.startLine, locatorRange.endLine]],
          resolved.totalLines
        );
        if (scopedRanges.length === 0) continue;

        // When anchored purely by provenance_file + L<start>-L<end> without an explicit commit SHA,
        // verify the on-disk span still matches `anchor_hash` before flagging stale lines.
        if (!oldSha && row.anchor_hash) {
          const currentSpan = extractSpanLines(
            resolved.text,
            scopedRanges[0][0],
            scopedRanges[0][1]
          ).trim();
          if (sha256(currentSpan) !== row.anchor_hash) {
            continue;
          }
        }
      }

      candidateTargets.push({
        wsRelPath: resolved.wsRelPath,
        scopedRanges,
        requireCommitMatch: oldSha
      });
    } else if (oldSha) {
      const remaining = deadline - Date.now();
      if (remaining <= 40) break;
      try {
        const treeOut = runGitExec(
          ['diff-tree', '--no-commit-id', '--name-only', '-r', oldSha],
          wsCtx.realRoot,
          remaining
        );
        for (const rawLine of treeOut.split(/\r?\n/)) {
          if (candidateTargets.length >= MAX_STALE_FILES_PER_DECISION) break;
          const resolved = resolveSafeWorkspaceRepoFile(rawLine, wsCtx, {
            fromDiffHeader: false
          });
          if (resolved) {
            candidateTargets.push({
              wsRelPath: resolved.wsRelPath,
              scopedRanges: null,
              requireCommitMatch: oldSha
            });
          }
        }
      } catch {
        continue;
      }
    }

    if (candidateTargets.length === 0) continue;

    const replShas = replacement
      ? [
          ...extractHexShaCandidates(replacement.provenance_locator),
          ...extractHexShaCandidates(replacement.content)
        ]
      : [];

    const fileHits = [];
    let memoryStaleLines = 0;
    let detectedCommitShort = oldSha ? oldSha.slice(0, 7) : null;

    for (const target of candidateTargets) {
      const remaining = deadline - Date.now();
      if (remaining <= 40) break;

      const cacheKey = target.scopedRanges
        ? `${target.wsRelPath}::${target.scopedRanges.map(([s, e]) => `${s}-${e}`).join(',')}`
        : target.wsRelPath;

      let parsedBlame = blameCache.get(cacheKey);
      if (!parsedBlame) {
        try {
          const rangeArgs = target.scopedRanges
            ? target.scopedRanges.flatMap(([s, e]) => ['-L', `${s},${e}`])
            : [];
          const blameOut = runGitExec(
            ['blame', '-w', '-M', '--porcelain', ...rangeArgs, 'HEAD', '--', target.wsRelPath],
            wsCtx.realRoot,
            remaining
          );
          parsedBlame = parseGitBlamePorcelain(blameOut);
          blameCache.set(cacheKey, parsedBlame);
        } catch {
          continue;
        }
      }

      const matchingLines = [];
      for (const [sha, info] of parsedBlame.commits.entries()) {
        if (target.requireCommitMatch) {
          if (shaMatchesPrefix(sha, target.requireCommitMatch)) {
            matchingLines.push(...info.lines);
            if (!detectedCommitShort) detectedCommitShort = sha.slice(0, 7);
          }
        } else {
          // Span-anchored (`provenance_file` + `L<start>-L<end>`) with verified surviving span:
          // count lines still blamed on HEAD unless owned by a commit cited in the replacement.
          if (replShas.some((rSha) => shaMatchesPrefix(sha, rSha))) continue;
          matchingLines.push(...info.lines);
          if (!detectedCommitShort) detectedCommitShort = sha.slice(0, 7);
        }
      }

      if (matchingLines.length > 0) {
        const ranges = coalesceLineRanges(matchingLines);
        const uniqueCount = ranges.reduce((acc, [s, e]) => acc + (e - s + 1), 0);
        memoryStaleLines += uniqueCount;
        fileHits.push({
          file: target.wsRelPath,
          lines: uniqueCount,
          ranges,
          citation: formatLineRangesLabel(target.wsRelPath, ranges)
        });
      }
    }

    if (fileHits.length > 0) {
      totalStaleLines += memoryStaleLines;
      findings.push({
        memory_id: Number(row.id),
        supersededId: Number(row.id),
        supersededContent: String(row.content || ''),
        replacedById: replacement
          ? Number(replacement.id)
          : row.superseded_by
            ? Number(row.superseded_by)
            : null,
        replacedByContent: replacement ? String(replacement.content || '') : '',
        commit: detectedCommitShort,
        totalLines: memoryStaleLines,
        files: fileHits
      });
    }
  }

  return { findings, totalStaleLines };
}

// ============================================================================
// Deterministic Lego Boilerplate Reinvention Guard (`INV-LEGO-01`)
// ============================================================================

const NON_CODE_DOC_PATH_RE = /\.(?:md|mdx|markdown|txt|rst|json|ya?ml|toml|lock|sql|svg|css)$/i;

const JS_REGEX_PREFIX_KEYWORDS = new Set([
  'return',
  'throw',
  'case',
  'typeof',
  'void',
  'delete',
  'in',
  'of',
  'instanceof',
  'yield',
  'await',
  'else',
  'do'
]);

function tryScanJsRegexLiteral(text, startIdx) {
  const len = text.length;
  let j = startIdx + 1;
  let inCharClass = false;
  while (j < len) {
    const c = text[j];
    if (c === '\n' || c === '\r') return -1;
    if (c === '\\') {
      if (j + 1 >= len || text[j + 1] === '\n' || text[j + 1] === '\r') return -1;
      j += 2;
      continue;
    }
    if (c === '[') {
      inCharClass = true;
      j += 1;
      continue;
    }
    if (c === ']' && inCharClass) {
      inCharClass = false;
      j += 1;
      continue;
    }
    if (c === '/' && !inCharClass) {
      j += 1;
      while (j < len && /[dgimsuvy]/.test(text[j])) j += 1;
      return j;
    }
    j += 1;
  }
  return -1;
}

function stripJsComments(source = '') {
  const text = String(source || '');
  if (!text) return '';
  let out = '';
  const len = text.length;
  let i = 0;
  let lastSigChar = '';
  let lastWord = '';
  let wordBuf = '';

  const flushWord = () => {
    if (wordBuf) {
      lastWord = wordBuf;
      wordBuf = '';
    }
  };

  while (i < len) {
    const ch = text[i];
    const next = text[i + 1] || '';

    if (ch === '/' && next === '*') {
      flushWord();
      i += 2;
      while (i < len && !(text[i] === '*' && text[i + 1] === '/')) {
        if (text[i] === '\n') out += '\n';
        i += 1;
      }
      if (i < len) i += 2;
      continue;
    }

    if (ch === '/' && next === '/') {
      flushWord();
      i += 2;
      while (i < len && text[i] !== '\n') i += 1;
      continue;
    }

    if (i === 0 && ch === '#' && next === '!') {
      i += 2;
      while (i < len && text[i] !== '\n') i += 1;
      continue;
    }

    if (ch === '/' && next !== '/' && next !== '*' && (i === 0 || text[i - 1] !== '<')) {
      flushWord();
      const canStartRegex =
        lastSigChar === '' ||
        '(,[=:{;!&|?+-*~^%>'.includes(lastSigChar) ||
        (/[a-zA-Z_$]/.test(lastSigChar) && JS_REGEX_PREFIX_KEYWORDS.has(lastWord));
      if (canStartRegex) {
        const regexEnd = tryScanJsRegexLiteral(text, i);
        if (regexEnd > i) {
          out += text.slice(i, regexEnd);
          lastSigChar = '/';
          lastWord = '';
          i = regexEnd;
          continue;
        }
      }
    }

    if (ch === "'" || ch === '"' || ch === '`') {
      flushWord();
      const quote = ch;
      out += quote;
      i += 1;
      while (i < len) {
        if (text[i] === '\\' && i + 1 < len) {
          out += text[i] + text[i + 1];
          i += 2;
          continue;
        }
        if (quote !== '`' && text[i] === '\n') break;
        out += text[i];
        i += 1;
        if (text[i - 1] === quote) break;
      }
      lastSigChar = quote;
      lastWord = '';
      continue;
    }

    if (/[a-zA-Z0-9_$.]/.test(ch)) {
      wordBuf += ch;
      lastSigChar = ch;
    } else {
      flushWord();
      if (!/\s/.test(ch)) lastSigChar = ch;
    }

    out += ch;
    i += 1;
  }

  return out;
}

function extractInspectableSegments(codeText) {
  const bounded =
    codeText.length > MAX_INSPECT_CHARS ? codeText.slice(0, MAX_INSPECT_CHARS) : codeText;

  if (!isUnifiedDiffText(bounded)) {
    // Handle standalone `+ ...` single-line patch snippets gracefully as well
    const strippedPlus = bounded
      .split(/\r?\n/)
      .filter((ln) => !ln.startsWith('-') || ln.startsWith('---'))
      .map((ln) => (ln.startsWith('+') && !ln.startsWith('+++') ? ln.slice(1) : ln))
      .join('\n');
    return [
      {
        filePath: null,
        addedCode: strippedPlus,
        survivingCode: strippedPlus
      }
    ];
  }

  const lines = bounded.split(/\r?\n/);
  const segments = [];
  let current = null;
  let pendingDeleted = false;
  let inHunk = false;

  const ensureCurrent = (fp = null) => {
    if (!current) {
      current = { filePath: fp, addedLines: [], survivingLines: [] };
      segments.push(current);
    } else if (fp && !current.filePath) {
      current.filePath = fp;
    }
    return current;
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];

    if (line.startsWith('diff --git ')) {
      current = null;
      pendingDeleted = false;
      inHunk = false;
      const pair = splitDiffGitHeaderPair(line.slice(11));
      const newP = pair ? normalizeRepoRelativePath(pair[1], { stripDiffPrefix: true }) : null;
      const oldP = pair ? normalizeRepoRelativePath(pair[0], { stripDiffPrefix: true }) : null;
      ensureCurrent(newP || oldP);
      continue;
    }

    if (!inHunk && /^\+\+\+\s+([^\t\r\n]+)/.test(line)) {
      const rawTarget = /^\+\+\+\s+([^\t\r\n]+)/.exec(line)[1].trim();
      if (rawTarget === '/dev/null' || unquoteGitPath(rawTarget) === '/dev/null') {
        pendingDeleted = true;
      } else {
        pendingDeleted = false;
        const norm = normalizeRepoRelativePath(rawTarget, { stripDiffPrefix: true });
        if (norm) ensureCurrent(norm);
      }
      continue;
    }

    if (/^@@\s+-\d+/.test(line)) {
      inHunk = true;
      if (!pendingDeleted) ensureCurrent(null);
      continue;
    }

    if (!inHunk || pendingDeleted) continue;

    if (line.startsWith('+') && !line.startsWith('+++')) {
      const seg = ensureCurrent(null);
      const body = line.slice(1);
      seg.addedLines.push(body);
      seg.survivingLines.push(body);
    } else if (line.startsWith(' ')) {
      const seg = ensureCurrent(null);
      seg.survivingLines.push(line.slice(1));
    }
  }

  return segments
    .filter((s) => s.addedLines.length > 0)
    .map((s) => ({
      filePath: s.filePath,
      addedCode: s.addedLines.join('\n'),
      survivingCode: s.survivingLines.join('\n')
    }));
}

const LEGO_VIOLATION_RULES = [
  {
    id: 'INV-LEGO-HTTP',
    matchedToken: 'http.createServer(',
    rule: "INV-LEGO-01 (@krusch/toolkit/http): Use createApiServer or createExpressBricks from '@krusch/toolkit/http' instead of hand-rolled http.createServer().",
    matches(cleanAdded, cleanSurviving) {
      const hasHttpCreate =
        /\bhttps?\s*\.\s*createServer\s*\(/.test(cleanAdded) ||
        (/\bcreateServer\s*\(/.test(cleanAdded) &&
          /(?:from\s+['"](?:node:)?https?['"]|require\(\s*['"](?:node:)?https?['"]\s*\))/.test(
            cleanSurviving
          ));
      if (!hasHttpCreate) return false;
      return !/@krusch\/toolkit\/http\b|\b(?:createApiServer|createExpressBricks)\b/.test(
        cleanSurviving
      );
    }
  },
  {
    id: 'INV-LEGO-EXPRESS',
    matchedToken: 'express()',
    rule: "INV-LEGO-01 (@krusch/toolkit/http): Use createApiServer or createExpressBricks from '@krusch/toolkit/http' instead of raw express().",
    matches(cleanAdded, cleanSurviving) {
      if (!/\bexpress\s*\(\s*\)/.test(cleanAdded)) return false;
      return !/@krusch\/toolkit\/http\b|\b(?:createApiServer|createExpressBricks)\b/.test(
        cleanSurviving
      );
    }
  },
  {
    id: 'INV-LEGO-SQLITE',
    matchedToken: 'new DatabaseSync(',
    rule: "INV-LEGO-01 (@krusch/toolkit/sqlite | @krusch/toolkit/db): Use openSqliteDb or initDb from '@krusch/toolkit/sqlite' instead of raw new DatabaseSync().",
    matches(cleanAdded, cleanSurviving) {
      if (!/\bnew\s+DatabaseSync\s*\(/.test(cleanAdded)) return false;
      return !/@krusch\/toolkit\/(?:sqlite|db)\b|\b(?:openSqliteDb|initDb)\b/.test(cleanSurviving);
    }
  },
  {
    id: 'INV-LEGO-SSE',
    matchedToken: 'text/event-stream',
    rule: "INV-LEGO-03 (@krusch/toolkit/streaming): Use sseResponse, streamChat, or edgeSseResponse instead of raw text/event-stream headers.",
    matches(cleanAdded, cleanSurviving) {
      if (!/text\/event-stream/i.test(cleanAdded)) return false;
      return !/@krusch\/toolkit\/(?:streaming|edge)\b|\b(?:sseResponse|streamChat|edgeSseResponse)\b/.test(
        cleanSurviving
      );
    }
  },
  {
    id: 'INV-LEGO-DB-POOL',
    matchedToken: 'new pg.Pool(',
    rule: "INV-LEGO-01 (@krusch/toolkit/pg): Use createPgPool or runSqlMigrations from '@krusch/toolkit/pg' instead of raw pg.Pool instantiation.",
    matches(cleanAdded, cleanSurviving) {
      const hasRawPg =
        /\bnew\s+pg\.Pool\s*\(/.test(cleanAdded) ||
        (/\bnew\s+Pool\s*\(/.test(cleanAdded) &&
          /(?:from\s+['"]pg['"]|require\(\s*['"]pg['"]\s*\))/.test(cleanSurviving));
      if (!hasRawPg) return false;
      return !/@krusch\/toolkit\/(?:pg|polygres)\b|\b(?:createPgPool|createPolygresClient)\b/.test(
        cleanSurviving
      );
    }
  }
];

/**
 * Scans added diff lines (or raw code snippets) for hand-rolled `http.createServer(`,
 * `express()`, `new DatabaseSync(`, `new pg.Pool(`, or raw `text/event-stream` headers
 * when `@krusch/toolkit` bricks should be used.
 *
 * @param {string} codeText
 * @returns {Array<{
 *   id: string,
 *   memory_id: null,
 *   category: 'invariant',
 *   severity: 'error',
 *   matched_token: string,
 *   rule: string,
 *   message: string,
 *   file: string | null
 * }>}
 */
export function detectLegoBoilerplateViolations(codeText) {
  if (typeof codeText !== 'string' || !codeText.trim()) {
    return [];
  }

  const segments = extractInspectableSegments(codeText)
    .filter((seg) => !seg.filePath || !NON_CODE_DOC_PATH_RE.test(seg.filePath))
    .map((seg) => {
      const cleanAdded = stripJsComments(seg.addedCode);
      const cleanSurviving =
        seg.survivingCode === seg.addedCode ? cleanAdded : stripJsComments(seg.survivingCode);
      return {
        filePath: seg.filePath,
        cleanAdded,
        cleanSurviving
      };
    })
    .filter((seg) => seg.cleanAdded.trim().length > 0);

  if (segments.length === 0) return [];

  const violations = [];
  for (const rule of LEGO_VIOLATION_RULES) {
    for (const seg of segments) {
      if (rule.matches(seg.cleanAdded, seg.cleanSurviving)) {
        violations.push({
          id: rule.id,
          memory_id: null,
          category: 'invariant',
          severity: 'error',
          matched_token: rule.matchedToken,
          rule: rule.rule,
          message: `Lego boilerplate violation (${rule.id}): found "${rule.matchedToken}". ${rule.rule}`,
          file: seg.filePath || null
        });
        break;
      }
    }
  }

  return violations;
}

/**
 * Optional engine wrapper returning INV-STACK-02 `okEnvelope` responses.
 *
 * @param {{ db?: any, workspaceRoot?: string }} [options]
 */
export function createGitAlignmentEngine({ db = null, workspaceRoot = process.cwd() } = {}) {
  const root = path.resolve(workspaceRoot);

  return {
    evaluateCoChange({ diff = '', changedFiles = [], rules = DEFAULT_COCHANGE_RULES } = {}) {
      const res = evaluateCoChangeRules({ diff, changedFiles, rules });
      return okEnvelope(
        'krusch_git_alignment_cochange',
        res.passed
          ? `Co-change check passed across ${res.touchedFiles.length} touched file(s).`
          : `Co-change check flagged ${res.violations.length} violation(s).`,
        res,
        true
      );
    },
    blameDiff({ code = '', file_path = '' } = {}) {
      const matches = findBlamedDiffMemories(code, {
        filePath: file_path,
        workspaceRoot: root,
        db
      });
      return okEnvelope(
        'krusch_git_alignment_blame',
        `Resolved ${matches.length} blamed memory/commit rationale match(es).`,
        { matches },
        true
      );
    },
    scanStaleCode() {
      const scan = scanSupersededStaleCode({ workspaceRoot: root, db });
      return okEnvelope(
        'krusch_git_alignment_stale_code',
        `Scanned superseded memories: ${scan.findings.length} stale finding(s) across ${scan.totalStaleLines} line(s).`,
        scan,
        true
      );
    },
    detectBoilerplate({ code = '' } = {}) {
      const violations = detectLegoBoilerplateViolations(code);
      return okEnvelope(
        'krusch_git_alignment_lego_guard',
        violations.length === 0
          ? 'No hand-rolled Lego boilerplate violations detected.'
          : `Detected ${violations.length} Lego boilerplate violation(s).`,
        { passed: violations.length === 0, violations },
        true
      );
    }
  };
}
