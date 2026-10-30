/**
 * @module engines/context-engine
 * Tier 1: Working Memory, Architectural Invariants & Lineage (krusch-context-mcp).
 * Implements retrieve, remember, revise, nudge, and health with:
 * - INV-12 span-grounded drift detection
 * - Optional 1024-dim dense vector embeddings (synchronous `_embedding` + async Ollama hydration)
 * - RM3 pseudo-relevance feedback & in-session episode kernel smoothing
 * - 3-Tier `prunePreSynthesis` (680 / 440 / 320 char) progressive condensation & session timelines
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope, ensureStackSchemaMigrations } from '../db/sqlite.js';
import {
  CHARS_PER_ESTIMATED_TOKEN,
  fnv1a32,
  STOP_WORDS,
  TEMPORAL_CUE_WORDS,
  GENERIC_INFRA_WORDS,
  META_QUERY_WORDS,
  DIRECTIVE_REGEX,
  stemToken,
  isTemporalOrLineageQuery,
  isSyntheticConstantVector,
  cosineSimilarity,
  parseEmbeddingVector,
  serializeEmbeddingVector,
  fetchOptionalEmbedding,
  extractQueryTokens,
  estimateTokens
} from './context-lexical.js';
import {
  buildStackLineageChain,
  detectStackConflicts,
  computeUnattestedQueryTerms
} from './context-epistemic.js';
import {
  prunePreRetrieval,
  prunePostRetrieval,
  prunePreSynthesis
} from './context-prune.js';

const VALID_CATEGORIES = new Set(['decision', 'invariant', 'bug', 'lesson', 'blocker']);
const VALID_REVISE_ACTIONS = new Set(['supersede', 'invalidate']);
const DECAY_RATE = 0.01;
const MAX_FEAT_CACHE_ENTRIES = 10000;
const dbRowFeatureCache = new WeakMap();

/**
 * Compute SHA-256 hex digest of a string.
 * @param {string} input
 * @returns {string}
 */
function sha256(input) {
  return crypto.createHash('sha256').update(String(input ?? ''), 'utf8').digest('hex');
}

/**
 * Parse a line-range locator such as "L10-L20", "10-20", or "L15".
 * @param {string} [locator]
 * @returns {{ startLine: number, endLine: number } | null}
 */
function parseLineLocator(locator) {
  if (!locator || typeof locator !== 'string') return null;
  const match = locator.trim().match(/^L?(\d+)(?:\s*-\s*L?(\d+))?$/i);
  if (!match) return null;
  const startLine = Number.parseInt(match[1], 10);
  const endLine = match[2] ? Number.parseInt(match[2], 10) : startLine;
  if (Number.isNaN(startLine) || startLine < 1 || endLine < startLine) return null;
  return { startLine, endLine };
}

/**
 * Extract slice of file lines (1-indexed inclusive).
 * @param {string} fileContent
 * @param {{ startLine: number, endLine: number } | null} range
 * @returns {string}
 */
function extractLocatorSpan(fileContent, range) {
  const lines = String(fileContent).split(/\r?\n/);
  if (!range) return lines.join('\n');
  const slice = lines.slice(range.startLine - 1, range.endLine);
  return slice.join('\n');
}

/**
 * Safely resolve a relative or absolute provenance file path inside workspaceRoot.
 * Returns null if the resolved path escapes workspaceRoot.
 * @param {string} relFile
 * @param {string} workspaceRoot
 * @returns {string | null}
 */
function resolveSafeWorkspacePath(relFile, workspaceRoot) {
  if (!relFile || typeof relFile !== 'string') return null;
  const rootResolved = path.resolve(workspaceRoot);
  const absPath = path.isAbsolute(relFile)
    ? path.resolve(relFile)
    : path.resolve(rootResolved, relFile);
  if (absPath !== rootResolved && !absPath.startsWith(rootResolved + path.sep)) {
    return null;
  }
  return absPath;
}

/**
 * Compute initial anchor hash for a memory's provenance.
 * @param {object} provenance
 * @param {string} workspaceRoot
 * @returns {string | null}
 */
function computeProvenanceAnchorHash(provenance, workspaceRoot) {
  if (!provenance || typeof provenance !== 'object') return null;
  if (provenance.anchor_hash && typeof provenance.anchor_hash === 'string') {
    return provenance.anchor_hash;
  }

  const quoted = typeof provenance.quoted_sentence === 'string'
    ? provenance.quoted_sentence.trim()
    : '';
  const relFile = typeof provenance.file === 'string' ? provenance.file.trim() : '';
  const locator = typeof provenance.locator === 'string' ? provenance.locator.trim() : '';

  if (relFile) {
    const absPath = resolveSafeWorkspacePath(relFile, workspaceRoot);
    if (absPath && fs.existsSync(absPath) && fs.statSync(absPath).isFile()) {
      const fileContent = fs.readFileSync(absPath, 'utf8');
      if (quoted) {
        return sha256(quoted);
      }
      const range = parseLineLocator(locator);
      const spanText = extractLocatorSpan(fileContent, range).trim();
      return sha256(spanText);
    }
    return sha256(quoted || `${relFile}:${locator}`);
  }

  if (quoted) {
    return sha256(quoted);
  }

  return null;
}

const MAX_RELOC_FILE_BYTES = 524288;
const MAX_WORKSPACE_SCAN_FILES = 200;
const MAX_AMBIGUOUS_CANDIDATES = 5;

const RELOC_IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  '.agent',
  '.krusch-stack',
  'dist',
  'build',
  'coverage',
  '__pycache__',
  '.venv',
  'venv',
  '.next',
  'benchmarks',
  '.cache'
]);

const SAFE_ENV_TEMPLATE_SUFFIXES = ['.example', '.sample', '.template', '.schema', '.dist'];

const BINARY_SKIP_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.tar',
  '.gz',
  '.tgz',
  '.bz2',
  '.xz',
  '.7z',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.eot',
  '.mp3',
  '.mp4',
  '.wav',
  '.avi',
  '.mov',
  '.wasm',
  '.pyc',
  '.pyo',
  '.class',
  '.o',
  '.so',
  '.dylib',
  '.dll',
  '.exe',
  '.sqlite',
  '.sqlite3',
  '.db'
]);

const TRIVIAL_GENERIC_QUOTE_RE =
  /^(?:['"]use strict['"]\s*;?|return(?:\s+(?:true|false|null|undefined|this|0|1|-1|''|""|``|\{\}|\[\]))?\s*;?|break\s*;?|continue\s*;?|export\s*\{\s*\}\s*;?|module\.exports\s*=\s*\{\s*\}\s*;?|[{}();]+)$/i;

const DECL_KEYWORD_SYMBOL_RE =
  /(?:^|[\s;{])(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:public\s+|private\s+|protected\s+|static\s+|final\s+|abstract\s+)*(?:function\s*\*?|class|interface|type|enum|def|fn|struct|record)\s+([A-Za-z_$][A-Za-z0-9_$]{2,})\b/;

const DECL_BINDING_SYMBOL_RE =
  /(?:^|[\s;{])(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{2,})\s*=/;

function escapeRegExpLiteral(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractDeclarationSymbol(normalizedQuoted) {
  if (!normalizedQuoted) return null;
  const kwMatch = normalizedQuoted.match(DECL_KEYWORD_SYMBOL_RE);
  if (kwMatch && kwMatch[1]) return kwMatch[1];
  const bindMatch = normalizedQuoted.match(DECL_BINDING_SYMBOL_RE);
  if (bindMatch && bindMatch[1]) return bindMatch[1];
  return null;
}

function containsIdentifierToken(text, identifier) {
  if (!text || !identifier) return false;
  const re = new RegExp(`(?<![A-Za-z0-9_$])${escapeRegExpLiteral(identifier)}(?![A-Za-z0-9_$])`);
  return re.test(text);
}

function hasIgnoredRelocationSegment(relPosix) {
  const parts = String(relPosix ?? '').split('/');
  for (const part of parts) {
    if (RELOC_IGNORED_DIRS.has(part)) return true;
  }
  return false;
}

function isSensitiveRelocationFile(filePath) {
  const base = path.basename(String(filePath ?? '')).toLowerCase();
  if (!base) return true;
  if (base === '.env' || base.startsWith('.env.')) {
    return !SAFE_ENV_TEMPLATE_SUFFIXES.some((sfx) => base.endsWith(sfx));
  }
  if (
    base.endsWith('.pem') ||
    base.endsWith('.key') ||
    base.startsWith('id_rsa') ||
    base.startsWith('id_ed25519') ||
    base.startsWith('id_ecdsa') ||
    base.startsWith('id_dsa') ||
    base === 'credentials.json' ||
    base === '.npmrc' ||
    base === '.pypirc' ||
    base === '.netrc'
  ) {
    return true;
  }
  return false;
}

function isKnownBinaryExtension(filePath) {
  const ext = path.extname(String(filePath ?? '')).toLowerCase();
  return ext ? BINARY_SKIP_EXTENSIONS.has(ext) : false;
}

function countNewlines(str, start, end) {
  let count = 0;
  for (let i = start; i < end; i += 1) {
    if (str.charCodeAt(i) === 10) count += 1;
  }
  return count;
}

function computeExactQuoteLineRange(normalizedText, normalizedQuoted) {
  const idx = normalizedText.indexOf(normalizedQuoted);
  if (idx < 0) return null;
  const startLine = 1 + countNewlines(normalizedText, 0, idx);
  const endLine = startLine + countNewlines(normalizedQuoted, 0, normalizedQuoted.length);
  const locator = startLine === endLine ? `L${startLine}` : `L${startLine}-L${endLine}`;
  return { start_line: startLine, end_line: endLine, locator };
}

function computePathProximityMetrics(origRel, candRel) {
  if (!origRel) {
    return { sameDir: 0, commonPrefixLen: 0, treeDistance: 0 };
  }
  const origDirRaw = path.posix.dirname(origRel);
  const candDirRaw = path.posix.dirname(candRel);
  const origDir = origDirRaw === '.' ? '' : origDirRaw;
  const candDir = candDirRaw === '.' ? '' : candDirRaw;
  const origSegs = origDir ? origDir.split('/') : [];
  const candSegs = candDir ? candDir.split('/') : [];

  let commonPrefixLen = 0;
  const minLen = Math.min(origSegs.length, candSegs.length);
  while (commonPrefixLen < minLen && origSegs[commonPrefixLen] === candSegs[commonPrefixLen]) {
    commonPrefixLen += 1;
  }
  const treeDistance = (origSegs.length - commonPrefixLen) + (candSegs.length - commonPrefixLen);
  return {
    sameDir: origDir === candDir ? 1 : 0,
    commonPrefixLen,
    treeDistance
  };
}

function compareCandidateProximity(origRel, fileA, fileB) {
  const mA = computePathProximityMetrics(origRel, fileA);
  const mB = computePathProximityMetrics(origRel, fileB);
  if (mB.sameDir !== mA.sameDir) return mB.sameDir - mA.sameDir;
  if (mB.commonPrefixLen !== mA.commonPrefixLen) return mB.commonPrefixLen - mA.commonPrefixLen;
  if (mA.treeDistance !== mB.treeDistance) return mA.treeDistance - mB.treeDistance;
  return fileA.localeCompare(fileB);
}

/**
 * Resolve a deterministic zero-LLM cross-file relocation hint when INV-12 STALE_DRIFT fires.
 * Waterfall: Tier 1a/1b (`git_symbols`) -> Tier 2 (`fs_pages`) -> Tier 3 (`workspace_scan`).
 * Enforces INV-RELOC-01..04 (specificity, <=5 non-ambiguity, realpath containment, secret exclusion).
 * @param {object} [params]
 * @param {import('node:sqlite').DatabaseSync | null} [params.db]
 * @param {string} [params.relFile]
 * @param {string} [params.quoted]
 * @param {string} [params.workspaceRoot]
 * @returns {object | null}
 */
export function findCrossFileRelocationCandidate({
  db = null,
  relFile = '',
  quoted = '',
  workspaceRoot = ''
} = {}) {
  if (!workspaceRoot || typeof workspaceRoot !== 'string') return null;

  const normalizedQuoted = String(quoted ?? '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim();
  if (!normalizedQuoted || TRIVIAL_GENERIC_QUOTE_RE.test(normalizedQuoted)) {
    return null;
  }

  const nonWsLen = normalizedQuoted.replace(/\s+/g, '').length;
  const declSymbol = extractDeclarationSymbol(normalizedQuoted);
  if (nonWsLen < 10 && !declSymbol) {
    return null;
  }

  const rootResolved = path.resolve(workspaceRoot);
  let canonicalRoot;
  try {
    canonicalRoot = fs.realpathSync(rootResolved);
  } catch {
    return null;
  }

  let origRel = '';
  let origRealRel = '';
  const rawRel = typeof relFile === 'string' ? relFile.trim() : '';
  if (rawRel) {
    const resolvedOrigAbs = resolveSafeWorkspacePath(rawRel, rootResolved);
    if (!resolvedOrigAbs) {
      return null;
    }
    origRel = path.relative(rootResolved, resolvedOrigAbs).replace(/\\/g, '/');
    try {
      const origRealAbs = fs.realpathSync(resolvedOrigAbs);
      if (origRealAbs !== canonicalRoot && origRealAbs.startsWith(canonicalRoot + path.sep)) {
        origRealRel = path.relative(canonicalRoot, origRealAbs).replace(/\\/g, '/');
      } else {
        origRealRel = origRel;
      }
    } catch {
      origRealRel = origRel;
    }
  }

  const diskCache = new Map();

  function readEligibleCandidateFile(candidatePath) {
    if (!candidatePath || typeof candidatePath !== 'string') return null;
    const trimmedCand = candidatePath.trim();
    if (!trimmedCand) return null;

    let absCandidate;
    if (path.isAbsolute(trimmedCand)) {
      const resolved = path.resolve(trimmedCand);
      if (
        resolved !== rootResolved &&
        !resolved.startsWith(rootResolved + path.sep) &&
        resolved !== canonicalRoot &&
        !resolved.startsWith(canonicalRoot + path.sep)
      ) {
        return null;
      }
      absCandidate = resolved;
    } else {
      const normInput = trimmedCand.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');
      if (
        !normInput ||
        normInput === '..' ||
        normInput.startsWith('../') ||
        normInput.includes('/../') ||
        normInput.endsWith('/..')
      ) {
        return null;
      }
      absCandidate = path.resolve(rootResolved, normInput);
      if (absCandidate === rootResolved || !absCandidate.startsWith(rootResolved + path.sep)) {
        return null;
      }
    }

    const relPosix = (
      absCandidate.startsWith(rootResolved + path.sep)
        ? path.relative(rootResolved, absCandidate)
        : path.relative(canonicalRoot, absCandidate)
    ).replace(/\\/g, '/');

    if (!relPosix || relPosix.startsWith('..') || relPosix === origRel) {
      return null;
    }
    if (
      hasIgnoredRelocationSegment(relPosix) ||
      isSensitiveRelocationFile(relPosix) ||
      isKnownBinaryExtension(relPosix)
    ) {
      return null;
    }

    if (diskCache.has(relPosix)) {
      return diskCache.get(relPosix);
    }

    let realPath;
    try {
      realPath = fs.realpathSync(absCandidate);
    } catch {
      diskCache.set(relPosix, null);
      return null;
    }

    if (realPath === canonicalRoot || !realPath.startsWith(canonicalRoot + path.sep)) {
      diskCache.set(relPosix, null);
      return null;
    }

    const realRelPosix = path.relative(canonicalRoot, realPath).replace(/\\/g, '/');
    if (
      !realRelPosix ||
      realRelPosix.startsWith('..') ||
      realRelPosix === origRel ||
      (origRealRel && realRelPosix === origRealRel) ||
      hasIgnoredRelocationSegment(realRelPosix) ||
      isSensitiveRelocationFile(realRelPosix) ||
      isKnownBinaryExtension(realRelPosix)
    ) {
      diskCache.set(relPosix, null);
      return null;
    }

    let stat;
    try {
      stat = fs.statSync(realPath);
    } catch {
      diskCache.set(relPosix, null);
      return null;
    }

    if (!stat.isFile() || stat.size > MAX_RELOC_FILE_BYTES) {
      diskCache.set(relPosix, null);
      return null;
    }

    let buf;
    try {
      buf = fs.readFileSync(realPath);
    } catch {
      diskCache.set(relPosix, null);
      return null;
    }

    if (buf.indexOf(0) !== -1) {
      diskCache.set(relPosix, null);
      return null;
    }

    const normalizedText = buf.toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const entry = { file: relPosix, realFile: realRelPosix, normalizedText };
    diskCache.set(relPosix, entry);
    return entry;
  }

  // Waterfall Tier 1: git_symbols AST table
  if (db) {
    // Step 1a: Exact quote match in git_symbols
    if (nonWsLen >= 10) {
      let rows = null;
      try {
        const snippetProbe = normalizedQuoted.split('\n').slice(0, 20).join('\n');
        rows = db
          .prepare(`
            SELECT
              file_path,
              symbol_name,
              symbol_type,
              signature,
              start_line,
              end_line
            FROM git_symbols
            WHERE file_path != ?
              AND (
                INSTR(REPLACE(REPLACE(COALESCE(snippet, ''), CHAR(13) || CHAR(10), CHAR(10)), CHAR(13), CHAR(10)), ?) > 0
                OR INSTR(REPLACE(REPLACE(COALESCE(signature, ''), CHAR(13) || CHAR(10), CHAR(10)), CHAR(13), CHAR(10)), ?) > 0
              )
            ORDER BY (end_line - start_line) ASC, start_line ASC
            LIMIT 60
          `)
          .all(origRel, snippetProbe, normalizedQuoted);
      } catch {
        rows = null;
      }

      if (rows && rows.length > 0) {
        const byRealFile = new Map();
        for (const r of rows) {
          const diskEntry = readEligibleCandidateFile(r.file_path);
          if (!diskEntry) continue;
          if (!diskEntry.normalizedText.includes(normalizedQuoted)) continue;
          if (!byRealFile.has(diskEntry.realFile)) {
            byRealFile.set(diskEntry.realFile, {
              file: diskEntry.file,
              normalizedText: diskEntry.normalizedText,
              symbol_name: r.symbol_name,
              symbol_type: r.symbol_type
            });
            if (byRealFile.size > MAX_AMBIGUOUS_CANDIDATES) {
              return null;
            }
          }
        }

        if (byRealFile.size >= 1 && byRealFile.size <= MAX_AMBIGUOUS_CANDIDATES) {
          const candidates = [...byRealFile.values()].sort((a, b) =>
            compareCandidateProximity(origRel, a.file, b.file)
          );
          const winner = candidates[0];
          const range = computeExactQuoteLineRange(winner.normalizedText, normalizedQuoted);
          if (range) {
            return {
              file: winner.file,
              locator: range.locator,
              start_line: range.start_line,
              end_line: range.end_line,
              citation: `${winner.file}#${range.locator}`,
              symbol_name: winner.symbol_name,
              symbol_type: winner.symbol_type,
              source: 'git_symbols',
              match_kind: 'ast_exact_quote',
              candidate_count: byRealFile.size
            };
          }
        }
      }
    }

    // Step 1b: Declaration symbol name match in git_symbols (handles reformatted signatures)
    if (declSymbol) {
      let symRows = null;
      try {
        symRows = db
          .prepare(`
            SELECT
              file_path,
              symbol_name,
              symbol_type,
              signature,
              start_line,
              end_line
            FROM git_symbols
            WHERE symbol_name = ?
              AND file_path != ?
            ORDER BY (end_line - start_line) ASC, start_line ASC
            LIMIT 60
          `)
          .all(declSymbol, origRel);
      } catch {
        symRows = null;
      }

      if (symRows && symRows.length > 0) {
        const byRealFile = new Map();
        let symAmbiguous = false;
        for (const r of symRows) {
          const diskEntry = readEligibleCandidateFile(r.file_path);
          if (!diskEntry) continue;
          if (!containsIdentifierToken(diskEntry.normalizedText, declSymbol)) continue;
          if (!byRealFile.has(diskEntry.realFile)) {
            byRealFile.set(diskEntry.realFile, {
              file: diskEntry.file,
              normalizedText: diskEntry.normalizedText,
              symbol_name: r.symbol_name,
              symbol_type: r.symbol_type,
              start_line: Number(r.start_line) || 1,
              end_line: Number(r.end_line) || 1
            });
            if (byRealFile.size > MAX_AMBIGUOUS_CANDIDATES) {
              symAmbiguous = true;
              break;
            }
          }
        }

        if (!symAmbiguous && byRealFile.size >= 1 && byRealFile.size <= MAX_AMBIGUOUS_CANDIDATES) {
          const candidates = [...byRealFile.values()].sort((a, b) =>
            compareCandidateProximity(origRel, a.file, b.file)
          );
          const winner = candidates[0];
          const diskLines = winner.normalizedText.split('\n');
          let startLine = winner.start_line;
          let endLine = Math.max(startLine, Math.min(winner.end_line, diskLines.length));
          const indexedSlice =
            startLine >= 1 && startLine <= diskLines.length
              ? diskLines.slice(startLine - 1, endLine).join('\n')
              : '';
          if (!containsIdentifierToken(indexedSlice, declSymbol)) {
            const foundIdx = diskLines.findIndex((ln) => containsIdentifierToken(ln, declSymbol));
            startLine = foundIdx >= 0 ? foundIdx + 1 : 1;
            endLine = startLine;
          }
          const locator = startLine === endLine ? `L${startLine}` : `L${startLine}-L${endLine}`;
          return {
            file: winner.file,
            locator,
            start_line: startLine,
            end_line: endLine,
            citation: `${winner.file}#${locator}`,
            symbol_name: winner.symbol_name,
            symbol_type: winner.symbol_type,
            source: 'git_symbols',
            match_kind: 'ast_symbol_name',
            candidate_count: byRealFile.size
          };
        }
      }
    }
  }

  if (nonWsLen < 10) {
    return null;
  }

  // Waterfall Tier 2: fs_pages table
  if (db) {
    let pageRows = null;
    try {
      const firstLine = normalizedQuoted.split('\n')[0].trim();
      const pageProbe =
        normalizedQuoted.includes('\n') && firstLine.replace(/\s+/g, '').length >= 10
          ? firstLine
          : normalizedQuoted;
      pageRows = db
        .prepare(`
          SELECT DISTINCT file_path
          FROM fs_pages
          WHERE file_path != ?
            AND INSTR(REPLACE(REPLACE(COALESCE(page_text, ''), CHAR(13) || CHAR(10), CHAR(10)), CHAR(13), CHAR(10)), ?) > 0
          ORDER BY file_path ASC
          LIMIT 30
        `)
        .all(origRel, pageProbe);
    } catch {
      pageRows = null;
    }

    if (pageRows && pageRows.length > 0) {
      const byRealFile = new Map();
      for (const r of pageRows) {
        const diskEntry = readEligibleCandidateFile(r.file_path);
        if (!diskEntry) continue;
        if (!diskEntry.normalizedText.includes(normalizedQuoted)) continue;
        if (!byRealFile.has(diskEntry.realFile)) {
          byRealFile.set(diskEntry.realFile, diskEntry);
          if (byRealFile.size > MAX_AMBIGUOUS_CANDIDATES) {
            return null;
          }
        }
      }

      if (byRealFile.size >= 1 && byRealFile.size <= MAX_AMBIGUOUS_CANDIDATES) {
        const candidates = [...byRealFile.values()].sort((a, b) =>
          compareCandidateProximity(origRel, a.file, b.file)
        );
        const winner = candidates[0];
        const range = computeExactQuoteLineRange(winner.normalizedText, normalizedQuoted);
        if (range) {
          return {
            file: winner.file,
            locator: range.locator,
            start_line: range.start_line,
            end_line: range.end_line,
            citation: `${winner.file}#${range.locator}`,
            source: 'fs_pages',
            match_kind: 'fs_exact_quote',
            candidate_count: byRealFile.size
          };
        }
      }
    }
  }

  // Waterfall Tier 3: bounded workspace_scan fallback (<= 200 files, sibling-first)
  let scannedFiles = 0;
  let ambiguous = false;
  const visitedRealDirs = new Set();
  const seenRelPaths = new Set();
  const matchesByRealFile = new Map();

  function scanDirectory(dirAbs) {
    if (scannedFiles >= MAX_WORKSPACE_SCAN_FILES || ambiguous) return;

    let realDir;
    try {
      realDir = fs.realpathSync(dirAbs);
    } catch {
      return;
    }
    if (realDir !== canonicalRoot && !realDir.startsWith(canonicalRoot + path.sep)) {
      return;
    }
    if (visitedRealDirs.has(realDir)) {
      return;
    }
    visitedRealDirs.add(realDir);

    let entries;
    try {
      entries = fs.readdirSync(dirAbs, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    const subdirs = [];
    for (const entry of entries) {
      if (scannedFiles >= MAX_WORKSPACE_SCAN_FILES || ambiguous) return;
      if (RELOC_IGNORED_DIRS.has(entry.name)) continue;

      const fullAbs = path.join(dirAbs, entry.name);
      if (entry.isDirectory()) {
        subdirs.push(fullAbs);
        continue;
      }

      if (entry.isSymbolicLink()) {
        let linkReal;
        try {
          linkReal = fs.realpathSync(fullAbs);
        } catch {
          continue;
        }
        if (linkReal === canonicalRoot || !linkReal.startsWith(canonicalRoot + path.sep)) {
          continue;
        }
        const linkRealRel = path.relative(canonicalRoot, linkReal).replace(/\\/g, '/');
        if (hasIgnoredRelocationSegment(linkRealRel)) {
          continue;
        }
        let linkStat;
        try {
          linkStat = fs.statSync(linkReal);
        } catch {
          continue;
        }
        if (linkStat.isDirectory()) {
          subdirs.push(fullAbs);
          continue;
        }
        if (!linkStat.isFile()) {
          continue;
        }
      } else if (!entry.isFile()) {
        continue;
      }

      const relPosix = path.relative(rootResolved, fullAbs).replace(/\\/g, '/');
      if (!relPosix || relPosix.startsWith('..') || relPosix === origRel) continue;
      if (seenRelPaths.has(relPosix)) continue;
      seenRelPaths.add(relPosix);

      const diskEntry = readEligibleCandidateFile(relPosix);
      if (!diskEntry) continue;

      scannedFiles += 1;
      if (diskEntry.normalizedText.includes(normalizedQuoted)) {
        if (!matchesByRealFile.has(diskEntry.realFile)) {
          matchesByRealFile.set(diskEntry.realFile, diskEntry);
          if (matchesByRealFile.size > MAX_AMBIGUOUS_CANDIDATES) {
            ambiguous = true;
            return;
          }
        }
      }
    }

    for (const subdirAbs of subdirs) {
      if (scannedFiles >= MAX_WORKSPACE_SCAN_FILES || ambiguous) return;
      scanDirectory(subdirAbs);
    }
  }

  if (origRel) {
    let currDirRel = path.posix.dirname(origRel);
    while (currDirRel && currDirRel !== '.') {
      const ancestorAbs = path.resolve(rootResolved, currDirRel);
      if (ancestorAbs.startsWith(rootResolved + path.sep)) {
        scanDirectory(ancestorAbs);
      }
      const nextDirRel = path.posix.dirname(currDirRel);
      if (nextDirRel === currDirRel) break;
      currDirRel = nextDirRel;
    }
  }
  scanDirectory(rootResolved);

  if (ambiguous || matchesByRealFile.size === 0 || matchesByRealFile.size > MAX_AMBIGUOUS_CANDIDATES) {
    return null;
  }

  const candidates = [...matchesByRealFile.values()].sort((a, b) =>
    compareCandidateProximity(origRel, a.file, b.file)
  );
  const winner = candidates[0];
  const range = computeExactQuoteLineRange(winner.normalizedText, normalizedQuoted);
  if (!range) return null;

  return {
    file: winner.file,
    locator: range.locator,
    start_line: range.start_line,
    end_line: range.end_line,
    citation: `${winner.file}#${range.locator}`,
    source: 'workspace_scan',
    match_kind: 'workspace_exact_quote',
    candidate_count: matchesByRealFile.size
  };
}

/**
 * Evaluate INV-12 span-grounded drift for a context memory record.
 * Returns 'VALID', 'HEALED_LINE_SHIFT', or 'STALE_DRIFT' (with optional cross-file `moved_candidate`).
 * @param {object} row
 * @param {string} workspaceRoot
 * @param {import('node:sqlite').DatabaseSync | null} [db=null]
 * @returns {{ status: 'VALID' | 'HEALED_LINE_SHIFT' | 'STALE_DRIFT', current_locator?: string, moved_candidate?: object }}
 */
export function evaluateSpanDrift(row, workspaceRoot, db = null) {
  const relFile = row.provenance_file;
  const locator = row.provenance_locator;
  const quoted = row.quoted_sentence ? row.quoted_sentence.trim() : '';
  const anchorHash = row.anchor_hash;

  if (!relFile && !quoted && !anchorHash) {
    return { status: 'VALID' };
  }

  if (relFile) {
    const absPath = resolveSafeWorkspacePath(relFile, workspaceRoot);
    if (!absPath) {
      return { status: 'STALE_DRIFT' };
    }

    let canonicalRoot;
    try {
      canonicalRoot = fs.realpathSync(path.resolve(workspaceRoot));
    } catch {
      return { status: 'STALE_DRIFT' };
    }

    let existsAsContainedFile = false;
    let realAbsPath = null;
    try {
      const lstat = fs.lstatSync(absPath);
      realAbsPath = fs.realpathSync(absPath);
      if (
        realAbsPath !== canonicalRoot &&
        realAbsPath.startsWith(canonicalRoot + path.sep) &&
        (lstat.isFile() || fs.statSync(realAbsPath).isFile())
      ) {
        existsAsContainedFile = true;
      } else if (lstat.isSymbolicLink()) {
        return { status: 'STALE_DRIFT' };
      }
    } catch {
      existsAsContainedFile = false;
    }

    if (!existsAsContainedFile) {
      const movedCandidate = quoted
        ? findCrossFileRelocationCandidate({ db, relFile, quoted, workspaceRoot })
        : null;
      return movedCandidate
        ? { status: 'STALE_DRIFT', moved_candidate: movedCandidate }
        : { status: 'STALE_DRIFT' };
    }

    const fileContent = fs.readFileSync(realAbsPath, 'utf8');
    const normalizedFileContent = fileContent.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const normalizedQuoted = quoted.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const range = parseLineLocator(locator);

    if (normalizedQuoted) {
      if (range) {
        const spanText = extractLocatorSpan(normalizedFileContent, range);
        if (spanText.includes(normalizedQuoted)) {
          return { status: 'VALID' };
        }
      }
      if (normalizedFileContent.includes(normalizedQuoted)) {
        if (range) {
          const healedRange = computeExactQuoteLineRange(normalizedFileContent, normalizedQuoted);
          const healedLocator = healedRange ? healedRange.locator : locator;
          return { status: 'HEALED_LINE_SHIFT', current_locator: healedLocator };
        }
        return { status: 'VALID' };
      }
      const movedCandidate = findCrossFileRelocationCandidate({
        db,
        relFile,
        quoted: normalizedQuoted,
        workspaceRoot
      });
      return movedCandidate
        ? { status: 'STALE_DRIFT', moved_candidate: movedCandidate }
        : { status: 'STALE_DRIFT' };
    }

    if (anchorHash) {
      const spanText = extractLocatorSpan(fileContent, range).trim();
      const currentHash = sha256(spanText);
      if (currentHash === anchorHash) {
        return { status: 'VALID' };
      }
      return { status: 'STALE_DRIFT' };
    }

    return { status: 'VALID' };
  }

  if (quoted && anchorHash) {
    return sha256(quoted) === anchorHash
      ? { status: 'VALID' }
      : { status: 'STALE_DRIFT' };
  }

  return { status: 'VALID' };
}

/**
 * Extract forbidden tokens or patterns from an active invariant/decision statement.
 * @param {string} ruleText
 * @returns {string[]}
 */
function extractForbiddenPatterns(ruleText) {
  const patterns = new Set();
  const text = String(ruleText || '');
  const hasNegativeIntent = /\b(never|forbid|forbidden|prohibit|prohibited|must\s+not|do\s+not|don't|no|ban|banned|disallow|avoid)\b/i.test(text);

  if (hasNegativeIntent) {
    const backtickMatches = text.matchAll(/`([^`]{2,64})`/g);
    for (const match of backtickMatches) {
      const token = match[1].trim();
      if (token) patterns.add(token);
    }

    const verbMatches = text.matchAll(/\b(?:never\s+use|do\s+not\s+use|don't\s+use|forbid|prohibit|disallow|avoid|no)\s+([a-zA-Z0-9_.:/()-]{3,40})/gi);
    for (const match of verbMatches) {
      const token = match[1].trim().replace(/[.,;:]$/, '');
      const stopWords = new Set(['the', 'any', 'all', 'raw', 'direct', 'internal', 'private', 'local', 'code', 'file', 'files']);
      if (token && !stopWords.has(token.toLowerCase())) {
        patterns.add(token);
        const strippedParens = token.replace(/\(\)$/, '');
        if (strippedParens.length >= 3) {
          patterns.add(`${strippedParens}(`);
        }
      }
    }
  }

  return [...patterns];
}

/**
 * Packs ranked context items within a token budget using multi-arm candidate pooling,
 * conflict-preserving Jaccard deduplication, 2-round submodular query-facet & session diversity,
 * and 3-tier `prunePreSynthesis` (`680 / 440 / 320` char) progressive condensation.
 * @param {Array<object>} items
 * @param {number} limitTokens
 * @param {string[]} [queryTerms=[]]
 * @param {object} [options={}]
 * @param {boolean|null} [options.condense=null]
 * @param {boolean} [options.markdownAccounting=false]
 * @param {boolean} [options.preserveOrder=false]
 */
export function packStackTokenBudget(items, limitTokens = 4000, queryTerms = [], options = {}) {
  const sorted = options.preserveOrder
    ? [...items]
    : [...items].sort((a, b) => b.score - a.score);
  const maxCandidates = Math.min(sorted.length, Math.max(160, Math.ceil(limitTokens / 20)));

  const poolSet = new Set(sorted.slice(0, maxCandidates));
  if (!options.preserveOrder && sorted.length > maxCandidates) {
    const bySem = [...sorted].sort((a, b) => (b.semanticScore || 0) - (a.semanticScore || 0));
    const byIdf = [...sorted].sort((a, b) => (b.idfOverlap || 0) - (a.idfOverlap || 0));
    const byUserIdf = [...sorted].sort((a, b) => (b.userOverlap || 0) - (a.userOverlap || 0));
    for (const it of bySem.slice(0, 24)) poolSet.add(it);
    for (const it of byIdf.slice(0, 24)) poolSet.add(it);
    for (const it of byUserIdf.slice(0, 28)) poolSet.add(it);
  }
  const topSlice = [...poolSet];

  // Ensure items involved in active value/polarity conflicts are never collapsed by prunePostRetrieval
  const conflictPairs = options.preserveOrder ? [] : detectStackConflicts(topSlice, queryTerms);
  const conflictedIds = new Set();
  for (const c of conflictPairs) {
    for (const cid of c.memory_ids) conflictedIds.add(Number(cid));
  }

  const deduped = options.preserveOrder
    ? topSlice
    : (() => {
        const nonConflicted = topSlice.filter((cand) => !conflictedIds.has(Number(cand.id)));
        const keptNonConflicted = new Set(
          prunePostRetrieval(nonConflicted, { similarityThreshold: 0.92 })
        );
        return topSlice.filter(
          (cand) => conflictedIds.has(Number(cand.id)) || keptNonConflicted.has(cand)
        );
      })();

  let orderedCandidates = deduped;
  if (!options.preserveOrder && Array.isArray(queryTerms) && queryTerms.length >= 2 && deduped.length > 1) {
    const queryStems = [...new Set(queryTerms.map((t) => stemToken(t)))];
    const remaining = [...deduped];
    const reordered = [];

    for (let round = 0; round < 2 && remaining.length > 0; round++) {
      const uncovered = new Set(queryStems);
      const seenSessions = new Set();

      while (remaining.length > 0 && uncovered.size > 0) {
        let bestIdx = -1;
        let bestEffectiveScore = -Infinity;
        let bestNewCovered = [];
        let bestSessionTag = null;

        for (let i = 0; i < remaining.length; i++) {
          const cand = remaining[i];
          if (cand.score < 0.50) continue;
          const textLower = `${cand.content || ''} ${cand.lineageText || ''}`.toLowerCase();
          const candStems =
            cand._stems ||
            new Set(
              textLower
                .split(/[^a-z0-9_]+/)
                .filter((w) => w.length >= 2)
                .map(stemToken)
            );
          const newlyCovered = [...uncovered].filter(
            (t) => candStems.has(t) || textLower.includes(t)
          );
          if (newlyCovered.length === 0) continue;
          const sessionMatch = textLower.match(/\bsession\s+(\d+)\b/);
          const sessionTag = sessionMatch ? sessionMatch[1] : null;
          const sessionBonus = sessionTag && !seenSessions.has(sessionTag) ? 0.08 : 0;
          const coverageBonus =
            (newlyCovered.length / Math.max(1, uncovered.size)) * 0.32 + sessionBonus;
          const effective = cand.score + coverageBonus;
          if (effective > bestEffectiveScore) {
            bestEffectiveScore = effective;
            bestIdx = i;
            bestNewCovered = newlyCovered;
            bestSessionTag = sessionTag;
          }
        }

        if (bestIdx === -1) break;
        const [picked] = remaining.splice(bestIdx, 1);
        reordered.push(picked);
        for (const t of bestNewCovered) uncovered.delete(t);
        if (bestSessionTag) seenSessions.add(bestSessionTag);
      }
    }

    if (deduped.length > 4 && limitTokens >= 2000) {
      const isBroad = deduped.some((x) => x._isBroad);
      const bySess = new Map();
      for (const x of deduped) {
        const sKey = x._sessionId ?? 0;
        if (!bySess.has(sKey)) bySess.set(sKey, []);
        bySess.get(sKey).push(x);
      }
      const sessStratified = [];
      const sessLists = [...bySess.entries()]
        .sort((a, b) => a[0] - b[0])
        .map((e) => e[1]);
      const maxSessLen = Math.max(0, ...sessLists.map((l) => l.length));
      for (let r = 0; r < maxSessLen; r++) {
        for (const list of sessLists) {
          if (r < list.length) sessStratified.push(list[r]);
        }
      }

      const topDirectives = [...deduped]
        .filter((x) => x._isStandingDirective)
        .sort(
          (a, b) =>
            (b.userOverlap || 0) * 0.55 +
            (b.semanticScore || 0) * 0.45 -
            ((a.userOverlap || 0) * 0.55 + (a.semanticScore || 0) * 0.45)
        );
      const topSessOpeners = deduped.filter(
        (x) => x._sessionPos !== undefined && x._sessionPos <= 2
      );
      const topUserIdf = [...deduped]
        .sort((a, b) => (b.userOverlap || 0) - (a.userOverlap || 0))
        .slice(0, 20);
      const topSemRem = [...deduped]
        .sort((a, b) => (b.semanticScore || 0) - (a.semanticScore || 0))
        .slice(0, 20);
      const topIdfRem = [...deduped]
        .sort((a, b) => (b.idfOverlap || 0) - (a.idfOverlap || 0))
        .slice(0, 16);
      const boundedSessStratified = sessStratified.slice(0, Math.max(15, sessLists.length * 3));
      const prioritySet = isBroad
        ? new Set([
            ...deduped.slice(0, 16),
            ...reordered.slice(0, 10),
            ...topSessOpeners.slice(0, 8),
            ...boundedSessStratified,
            ...topUserIdf,
            ...topSemRem,
            ...deduped
          ])
        : new Set([
            ...deduped.slice(0, 12),
            ...reordered.slice(0, 8),
            ...topDirectives.slice(0, 8),
            ...deduped.slice(12, 24),
            ...topUserIdf,
            ...topSemRem,
            ...topIdfRem,
            ...topDirectives,
            ...boundedSessStratified,
            ...deduped
          ]);
      orderedCandidates = [...prioritySet];
    } else {
      orderedCandidates = [...reordered, ...remaining];
    }
  }

  const isLargeEpisodic =
    options.condense === true ||
    (options.condense !== false && items.length >= 30 && limitTokens >= 2000);
  const useMarkdownAccounting = Boolean(options.markdownAccounting || isLargeEpisodic);

  let currentTokens = 0;
  const packedEntries = [];
  const packedItems = [];

  for (const item of orderedCandidates) {
    const maxBodyChars = isLargeEpisodic
      ? packedEntries.length < 8
        ? 680
        : packedEntries.length < 20
          ? 440
          : 320
      : 4000;

    let bodyText = isLargeEpisodic
      ? prunePreSynthesis(item.content || '', { maxChars: maxBodyChars }).trim()
      : String(item.content || '');

    let markdownBody = bodyText;
    if (item.lineage && item.lineage.length > 1) {
      const chainSummary = item.lineage
        .map((step) => {
          const stepBody = prunePreSynthesis(String(step.content || ''), { maxChars: 240 }).trim();
          return `Step ${step.step} [#${step.id} ${String(step.status || '').toUpperCase()}${step.created_at ? ` @ ${step.created_at}` : ''}]: ${stepBody}`;
        })
        .join(' → ');
      markdownBody += `\n> **Lineage History (${item.lineage.length} versions)**: ${chainSummary}`;
    }

    const statusBadge =
      item.status && String(item.status).toLowerCase() !== 'active'
        ? ` [${String(item.status).toUpperCase()}]`
        : '';
    const title = `Memory #${item.id} (${item.category})${statusBadge}`;
    let entryText = `### [MEMORY] ${title} (Score: ${(item.score * 100).toFixed(1)}%)\n${markdownBody}\n\n---\n`;

    let itemTokens;
    if (useMarkdownAccounting) {
      itemTokens = estimateTokens(entryText);
    } else {
      const lineageChars = item.lineage
        ? item.lineage.reduce((acc, s) => acc + String(s.content || '').length + 16, 0)
        : 0;
      itemTokens = Math.max(1, estimateTokens(bodyText) + Math.ceil(lineageChars / 4));
    }

    if (currentTokens + itemTokens > limitTokens) {
      if (packedItems.length > 0) {
        break;
      }
      if (limitTokens < 250 && itemTokens > limitTokens) {
        continue;
      }
      const maxAllowedChars = Math.max(
        80,
        Math.floor(Math.max(20, limitTokens - 25) * CHARS_PER_ESTIMATED_TOKEN)
      );
      bodyText = bodyText.slice(0, maxAllowedChars);
      markdownBody = bodyText;
      entryText = `### [MEMORY] ${title} (Score: ${(item.score * 100).toFixed(1)}%)\n${markdownBody}\n\n---\n`;
      itemTokens = useMarkdownAccounting ? estimateTokens(entryText) : estimateTokens(bodyText);
      if (currentTokens + itemTokens > limitTokens) {
        continue;
      }
    }

    packedEntries.push(entryText);
    currentTokens += itemTokens;
    packedItems.push({
      ...item,
      condensedContent: bodyText,
      isCondensed: bodyText.length < String(item.content || '').length
    });
  }

  return {
    contextText: packedEntries.join(''),
    packedCount: packedItems.length,
    totalTokens: currentTokens,
    packedItems,
    conflicts: conflictPairs,
    isLargeEpisodic
  };
}

/**
 * Create a Tier 1 Context Engine instance.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 * @param {boolean} [options.ephemeral]
 * @param {string} [options.embedEndpoint]
 * @param {string} [options.embedModel]
 * @param {boolean} [options.autoEmbed]
 */
export function createContextEngine({
  db,
  workspaceRoot = process.cwd(),
  ephemeral = false,
  embedEndpoint = null,
  embedModel = null,
  autoEmbed = undefined
}) {
  const root = path.resolve(workspaceRoot);
  try {
    ensureStackSchemaMigrations(db);
  } catch {
    // Allow graceful STORAGE_ERROR handling if context_memories table was intentionally dropped
  }

  const embedOptions = {
    endpoint: embedEndpoint,
    model: embedModel,
    ephemeral: Boolean(ephemeral || process.env.KRUSCH_EPHEMERAL === '1'),
    autoEmbed
  };

  const insertMemoryStmt = db.prepare(`
    INSERT INTO context_memories (
      category,
      content,
      status,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash,
      embedding
    ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?)
  `);

  const selectActiveStmt = db.prepare(`
    SELECT
      id,
      category,
      content,
      status,
      superseded_by,
      revocation_reason,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash,
      embedding,
      created_at,
      updated_at
    FROM context_memories
    WHERE status = 'active'
    ORDER BY id DESC
    LIMIT 250
  `);

  const selectActivePoolStmt = db.prepare(`
    SELECT
      id,
      category,
      content,
      status,
      superseded_by,
      revocation_reason,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash,
      embedding,
      created_at,
      updated_at
    FROM context_memories
    WHERE status = 'active'
    ORDER BY id DESC
    LIMIT ?
  `);

  const selectActivePoolByCatStmt = db.prepare(`
    SELECT
      id,
      category,
      content,
      status,
      superseded_by,
      revocation_reason,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash,
      embedding,
      created_at,
      updated_at
    FROM context_memories
    WHERE status = 'active' AND category = ?
    ORDER BY id DESC
    LIMIT ?
  `);

  const selectActiveCountsByCatStmt = db.prepare(`
    SELECT category, COUNT(*) AS cnt
    FROM context_memories
    WHERE status = 'active'
    GROUP BY category
  `);

  const hasSupersededStmt = db.prepare(`
    SELECT 1 FROM context_memories WHERE status = 'superseded' LIMIT 1
  `);

  const selectAllSupersededStmt = db.prepare(`
    SELECT
      id,
      category,
      content,
      status,
      superseded_by,
      revocation_reason,
      provenance_file,
      provenance_locator,
      quoted_sentence,
      anchor_hash,
      embedding,
      created_at,
      updated_at
    FROM context_memories
    WHERE status = 'superseded'
    ORDER BY id ASC
    LIMIT 2000
  `);

  const selectByIdStmt = db.prepare(`
    SELECT * FROM context_memories WHERE id = ?
  `);

  const selectParentBySupersededByStmt = db.prepare(`
    SELECT * FROM context_memories WHERE superseded_by = ? ORDER BY id ASC LIMIT 1
  `);

  const markSupersededStmt = db.prepare(`
    UPDATE context_memories
    SET status = 'superseded',
        superseded_by = ?,
        revocation_reason = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `);

  const markInvalidatedStmt = db.prepare(`
    UPDATE context_memories
    SET status = 'invalidated',
        revocation_reason = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `);

  const maxScanLimit = Math.max(400, Number(process.env.KRUSCH_MAX_ACTIVE_SCAN) || 5000);

  function isWildcardQuery(q) {
    const trimmed = String(q ?? '*').trim();
    return !trimmed || trimmed === '*';
  }

  /**
   * Persist a durable decision, invariant, bug, lesson, or blocker (synchronous).
   * @param {object} [params]
   * @param {string} [params.category='decision']
   * @param {string} params.content
   * @param {object} [params.provenance={}]
   * @param {Array<number>|Float64Array|string|null} [params._embedding=null]
   */
  function remember({ category = 'decision', content, provenance = {}, _embedding = null } = {}) {
    const normalizedCategory = String(category || 'decision').trim().toLowerCase();
    if (!VALID_CATEGORIES.has(normalizedCategory)) {
      return okEnvelope(
        'krusch_context_remember',
        `Invalid category "${category}". Expected decision|invariant|bug|lesson|blocker.`,
        { error: `Invalid category: ${category}` },
        false
      );
    }

    const trimmedContent = String(content ?? '').trim();
    if (!trimmedContent) {
      return okEnvelope(
        'krusch_context_remember',
        'Memory content cannot be empty.',
        { error: 'content is required' },
        false
      );
    }

    const prov = provenance && typeof provenance === 'object' ? provenance : {};
    const provenanceFile = prov.file ? String(prov.file).trim() : null;
    const provenanceLocator = prov.locator ? String(prov.locator).trim() : null;
    const quotedSentence = prov.quoted_sentence ? String(prov.quoted_sentence).trim() : null;
    const anchorHash = computeProvenanceAnchorHash(
      {
        file: provenanceFile,
        locator: provenanceLocator,
        quoted_sentence: quotedSentence,
        anchor_hash: prov.anchor_hash
      },
      root
    );
    const serializedEmbedding = serializeEmbeddingVector(_embedding);

    const result = insertMemoryStmt.run(
      normalizedCategory,
      trimmedContent,
      provenanceFile,
      provenanceLocator,
      quotedSentence,
      anchorHash,
      serializedEmbedding
    );

    const id = Number(result.lastInsertRowid);
    const normalizedProvenance = {
      file: provenanceFile,
      locator: provenanceLocator,
      quoted_sentence: quotedSentence,
      anchor_hash: anchorHash
    };

    return okEnvelope(
      'krusch_context_remember',
      `Stored ${normalizedCategory} memory #${id}.`,
      {
        id,
        category: normalizedCategory,
        content: trimmedContent,
        status: 'active',
        has_embedding: Boolean(serializedEmbedding),
        provenance: normalizedProvenance
      },
      true
    );
  }

  /**
   * Async wrapper for `remember` that auto-hydrates an optional dense embedding when Ollama is available.
   * @param {object} [params]
   */
  async function rememberAsync(params = {}) {
    let emb = params?._embedding || null;
    if (!emb && params?.content && String(params.content).trim()) {
      emb = await fetchOptionalEmbedding(String(params.content), embedOptions);
    }
    return remember({ ...params, _embedding: emb });
  }

  /**
   * Retrieve active working memories, state briefing, progressive condensation, and INV-12 drift telemetry.
   * @param {object} [params]
   * @param {string} [params.query='*']
   * @param {string} [params.category]
   * @param {boolean} [params.include_state=true]
   * @param {boolean|null} [params.include_lineage=null]
   * @param {number} [params.limit_tokens=4000]
   * @param {boolean|null} [params.condense=null]
   * @param {boolean} [params.include_markdown=false]
   * @param {Array<number>|Float64Array|string|null} [params._embedding=null]
   */
  function retrieve({
    query = '*',
    category,
    include_state = true,
    include_lineage = null,
    limit_tokens = 4000,
    condense = null,
    include_markdown = false,
    _embedding = null
  } = {}) {
    const rawQuery = String(query ?? '*').trim();
    const isWildcard = isWildcardQuery(rawQuery);
    const cleanQuery = isWildcard ? '*' : prunePreRetrieval(rawQuery);
    const lowerQuery = cleanQuery.toLowerCase();
    const normalizedCat =
      category && category !== 'all' ? String(category).trim().toLowerCase() : null;
    const tokenBudget =
      Number.isFinite(Number(limit_tokens)) && Number(limit_tokens) > 0
        ? Math.min(Number(limit_tokens), 32000)
        : 4000;

    const queryVec = !isWildcard && _embedding ? parseEmbeddingVector(_embedding) : null;
    const hasRealQueryEmbedding = Boolean(queryVec && !isSyntheticConstantVector(queryVec));

    const { queryTerms, domainTerms, distinctiveTerms } = !isWildcard
      ? extractQueryTokens(lowerQuery)
      : { queryTerms: [], domainTerms: [], distinctiveTerms: [] };

    const evalTerms = domainTerms.length > 0 ? domainTerms : queryTerms;
    const evalStems = [...new Set(evalTerms.map(stemToken))];
    const distinctiveStems = [...new Set(distinctiveTerms.map(stemToken))];
    const temporalMode =
      include_lineage === true ||
      (include_lineage !== false && !isWildcard && isTemporalOrLineageQuery(rawQuery));

    const catCounts = {
      invariant: 0,
      decision: 0,
      blocker: 0,
      bug: 0,
      lesson: 0
    };
    let totalActive = 0;
    const rowMap = new Map();
    const parentByChildId = new Map();
    const candidateRowMap = new Map();

    try {
      for (const cRow of selectActiveCountsByCatStmt.all()) {
        const cnt = Number(cRow.cnt) || 0;
        totalActive += cnt;
        if (cRow.category in catCounts) {
          catCounts[cRow.category] = cnt;
        }
      }

      if (isWildcard) {
        const activeRows = selectActiveStmt.all();
        for (const r of activeRows) {
          if (!normalizedCat || r.category === normalizedCat) {
            candidateRowMap.set(Number(r.id), r);
            rowMap.set(Number(r.id), r);
          }
        }
      } else {
        const activePool = normalizedCat
          ? selectActivePoolByCatStmt.all(normalizedCat, maxScanLimit)
          : selectActivePoolStmt.all(maxScanLimit);

        let minVecId = Infinity;
        for (const row of activePool) {
          const numId = Number(row.id);
          if (numId < minVecId) minVecId = numId;
          rowMap.set(numId, row);
          candidateRowMap.set(numId, row);
        }

        const hasSuperseded = Boolean(hasSupersededStmt.get());
        if (hasSuperseded) {
          for (const sRow of selectAllSupersededStmt.all()) {
            const sId = Number(sRow.id);
            rowMap.set(sId, sRow);
            if (sRow.superseded_by) {
              const childId = Number(sRow.superseded_by);
              if (
                !parentByChildId.has(childId) ||
                sId < Number(parentByChildId.get(childId).id)
              ) {
                parentByChildId.set(childId, sRow);
              }
            }
          }
        }

        if (evalTerms.length > 0 && (hasSuperseded || activePool.length === maxScanLimit)) {
          const matchExprs = [];
          const matchParams = [];
          const likeClauses = [];
          const whereParams = [];
          for (const term of evalTerms.slice(0, 12)) {
            const rootTerm = stemToken(term);
            const escaped = rootTerm.replace(/[\\%_]/g, '\\$&');
            const pat = `%${escaped}%`;
            const clause = `(LOWER(content) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(provenance_file, '')) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(quoted_sentence, '')) LIKE ? ESCAPE '\\')`;
            matchExprs.push(`(CASE WHEN ${clause} THEN 1 ELSE 0 END)`);
            matchParams.push(pat, pat, pat);
            likeClauses.push(clause);
            whereParams.push(pat, pat, pat);
          }
          const scopeClause =
            activePool.length === maxScanLimit
              ? `(status = 'superseded' OR (status = 'active' AND id < ${Number.isFinite(minVecId) ? minVecId : 0}))`
              : `status = 'superseded'`;
          let lexSql = `
            SELECT
              id, category, content, status, superseded_by, revocation_reason,
              provenance_file, provenance_locator, quoted_sentence, anchor_hash,
              embedding, created_at, updated_at,
              (${matchExprs.join(' + ')}) AS _lex_hits
            FROM context_memories
            WHERE ${scopeClause}
          `;
          const sqlParams = [...matchParams];
          if (normalizedCat) {
            lexSql += ` AND category = ?`;
            sqlParams.push(normalizedCat);
          }
          sqlParams.push(...whereParams);
          lexSql += ` AND (${likeClauses.join(' OR ')}) ORDER BY _lex_hits DESC, id DESC LIMIT 300`;

          for (const row of db.prepare(lexSql).all(...sqlParams)) {
            const numId = Number(row.id);
            rowMap.set(numId, row);
            if (row.status === 'active') {
              if (!candidateRowMap.has(numId)) {
                candidateRowMap.set(numId, row);
              }
            } else if (row.status === 'superseded') {
              const { chain, terminalActive } = buildStackLineageChain(
                row,
                rowMap,
                parentByChildId,
                (id) => selectByIdStmt.get(id) || null,
                (childId) => selectParentBySupersededByStmt.get(childId) || null
              );
              if (terminalActive && (!normalizedCat || terminalActive.category === normalizedCat)) {
                const termId = Number(terminalActive.id);
                const mergedTarget = candidateRowMap.get(termId) || terminalActive;
                mergedTarget._lineageChain = chain;
                rowMap.set(termId, mergedTarget);
                candidateRowMap.set(termId, mergedTarget);
              } else if (temporalMode) {
                row._lineageChain = chain;
                candidateRowMap.set(numId, row);
              }
            }
          }
        }
      }
    } catch (storageErr) {
      return okEnvelope(
        'krusch_context_retrieve',
        `Context storage error: ${storageErr.message}`,
        {
          items: [],
          state: null,
          drift_summary: { valid: 0, healed_line_shift: 0, stale_drift: 0 },
          total_active: 0,
          epistemic_status: 'STORAGE_ERROR',
          storage_error: storageErr.message,
          conflicts: [],
          chronological_order: [],
          unattested_query_terms: []
        },
        false
      );
    }

    const allCandidateRows = isWildcard
      ? [...candidateRowMap.values()].sort((a, b) => Number(b.id) - Number(a.id))
      : [...candidateRowMap.values()].sort((a, b) => Number(a.id) - Number(b.id));

    const nowMs = Date.now();
    const isBroadQuery =
      !isWildcard &&
      /\b(order|sequence|chronological|timeline|summary|summarize|comprehensive|throughout|across|progressed|progress)\b/i.test(
        rawQuery
      );
    const isEpisodicStore = !isWildcard && allCandidateRows.length >= 20;

    // Extract contiguous 2-word and 3-word content phrases (and stemmed equivalents)
    const queryPhrases = [];
    const queryStemPhrases = [];
    if (!isWildcard && evalTerms.length >= 2) {
      const rawWords = lowerQuery
        .split(/[^a-z0-9_.-]+/)
        .filter((w) => w.length >= 3 && !STOP_WORDS.has(w) && !META_QUERY_WORDS.has(w));
      const rawStemWords = rawWords.map(stemToken);
      for (let k = 0; k + 1 < rawWords.length; k++) {
        queryPhrases.push(`${rawWords[k]} ${rawWords[k + 1]}`);
        queryStemPhrases.push(`${rawStemWords[k]} ${rawStemWords[k + 1]}`);
        if (k + 2 < rawWords.length) {
          queryPhrases.push(`${rawWords[k]} ${rawWords[k + 1]} ${rawWords[k + 2]}`);
          queryStemPhrases.push(`${rawStemWords[k]} ${rawStemWords[k + 1]} ${rawStemWords[k + 2]}`);
        }
      }
    }

    let featCache = dbRowFeatureCache.get(db);
    if (!featCache) {
      featCache = new Map();
      dbRowFeatureCache.set(db, featCache);
    }

    const sessionCounters = new Map();
    const dfMap = new Map();

    for (const r of allCandidateRows) {
      let lineage = r._lineageChain || null;
      if (
        !lineage &&
        !isWildcard &&
        (r.superseded_by || r.status === 'superseded' || parentByChildId.has(Number(r.id)))
      ) {
        lineage = buildStackLineageChain(
          r,
          rowMap,
          parentByChildId,
          (id) => selectByIdStmt.get(id) || null,
          (childId) => selectParentBySupersededByStmt.get(childId) || null
        ).chain;
        r._lineageChain = lineage;
      }
      r._lineageText =
        lineage && lineage.length > 1 ? lineage.map((step) => step.content).join(' ') : '';

      const provMeta = `${r.provenance_file || ''} ${r.quoted_sentence || ''}`.trim();
      const cacheKey = `${r.id}:${r.category || ''}:${r.updated_at || ''}:${fnv1a32(`${r.content || ''}|${provMeta}|${r._lineageText || ''}`)}`;
      let cachedFeat = featCache.get(cacheKey);
      if (!cachedFeat) {
        const lowerContent = String(r.content || '').toLowerCase();
        const lowerProv = provMeta.toLowerCase();
        const lowerLineage = r._lineageText.toLowerCase();
        const combinedText = `${lowerContent} ${lowerProv} ${lowerLineage}`;
        const rowStems = new Set(
          combinedText
            .split(/[^a-z0-9_]+/)
            .filter((w) => w.length >= 2)
            .map(stemToken)
        );
        const userMatch = lowerContent.match(/\buser:\s*([\s\S]*?)(?:\|\s*assistant:|$)/i);
        const hasDialogueTurn = Boolean(userMatch);
        const userRaw = userMatch ? userMatch[1] : lowerContent;
        const userStemsArr = userRaw
          .split(/[^a-z0-9_]+/)
          .filter((w) => w.length >= 2)
          .map(stemToken);
        const userStems = new Set(userStemsArr);
        const userStemSeq = userStemsArr.join(' ');
        const isStandingDirective =
          r.category === 'invariant' ||
          (hasDialogueTurn ? DIRECTIVE_REGEX.test(userRaw) : DIRECTIVE_REGEX.test(lowerContent));
        const sessMatch = lowerContent.match(/\[[^\]]*\bsession[\s_-]+(\d+)\b/i);
        const sessionId = sessMatch ? Number(sessMatch[1]) : null;
        cachedFeat = {
          lowerContent,
          lowerProv,
          lowerLineage,
          combinedText,
          rowStems,
          userStems,
          userStemSeq,
          userRaw,
          hasDialogueTurn,
          isStandingDirective,
          sessionId
        };
        if (featCache.size >= MAX_FEAT_CACHE_ENTRIES) {
          const oldestKey = featCache.keys().next().value;
          if (oldestKey !== undefined) featCache.delete(oldestKey);
        }
        featCache.set(cacheKey, cachedFeat);
      }

      r._stems = cachedFeat.rowStems;
      r._userStems = cachedFeat.userStems;
      r._userStemSeq = cachedFeat.userStemSeq;
      r._userRaw = cachedFeat.userRaw;
      r._hasDialogueTurn = cachedFeat.hasDialogueTurn;
      r._lowerContent = cachedFeat.lowerContent;
      r._lowerProv = cachedFeat.lowerProv;
      r._combinedText = cachedFeat.combinedText;
      r._isStandingDirective = cachedFeat.isStandingDirective;
      r._sessionId = cachedFeat.sessionId;
      if (r._sessionId !== null) {
        const sPos = sessionCounters.get(r._sessionId) || 0;
        r._sessionPos = sPos;
        sessionCounters.set(r._sessionId, sPos + 1);
      } else {
        r._sessionPos = 999;
      }

      if (!isWildcard) {
        for (const s of evalStems) {
          if (cachedFeat.rowStems.has(s) || cachedFeat.combinedText.includes(s)) {
            dfMap.set(s, (dfMap.get(s) || 0) + 1);
          }
        }
      }
    }

    const corpusN = Math.max(1, allCandidateRows.length);
    let totalQueryIdf = 0;
    const idfWeights = new Map();
    for (const s of evalStems) {
      const w = Math.log(1 + corpusN / (1 + (dfMap.get(s) || 0)));
      idfWeights.set(s, w);
      totalQueryIdf += w;
    }

    const rawScoredItems = [];
    for (const r of allCandidateRows) {
      const lineage = r._lineageChain || null;
      const lineageText = r._lineageText || '';

      let score = 0;
      let semanticScore = 0;
      let idfOverlap = 0;
      let userOverlap = 0;

      if (isWildcard) {
        score = 0.85;
      } else {
        if (hasRealQueryEmbedding) {
          const rowsToScore = [r];
          if (lineage && lineage.length > 1) {
            for (const step of lineage) {
              const cachedStepRow = rowMap.get(Number(step.id));
              if (cachedStepRow && cachedStepRow !== r) rowsToScore.push(cachedStepRow);
            }
          }
          for (const scoreRow of rowsToScore) {
            if (scoreRow.embedding) {
              const vec = parseEmbeddingVector(scoreRow.embedding);
              if (vec && !isSyntheticConstantVector(vec)) {
                const sim = cosineSimilarity(queryVec, vec);
                if (sim > semanticScore) semanticScore = sim;
              }
            }
          }
        }

        const lowerContent = r._lowerContent;
        const lowerProv = r._lowerProv;
        const combinedHaystack = r._combinedText;
        const rowStems = r._stems;
        const userStems = r._userStems;

        const matchesTerm = (term, stem) =>
          rowStems.has(stem) || combinedHaystack.includes(term);

        let directMatches = evalTerms.filter(
          (t, idx) =>
            rowStems.has(evalStems[idx]) || lowerContent.includes(t) || lowerProv.includes(t)
        ).length;
        if (lineage && lineage.length > 1) {
          for (const step of lineage) {
            const stepLower = String(step.content || '').toLowerCase();
            const stepMatches = evalTerms.filter(
              (t, idx) => stepLower.includes(t) || stepLower.includes(evalStems[idx])
            ).length;
            if (stepMatches > directMatches) directMatches = stepMatches;
          }
        }
        const totalMatches = evalTerms.filter((t, idx) => matchesTerm(t, evalStems[idx])).length;
        const distinctiveMatches = distinctiveTerms.filter((t, idx) =>
          matchesTerm(t, distinctiveStems[idx])
        ).length;

        let matchedIdf = 0;
        let matchedUserIdf = 0;
        for (const s of evalStems) {
          const w = idfWeights.get(s) || 0;
          if (rowStems.has(s) || combinedHaystack.includes(s)) {
            matchedIdf += w;
          }
          if (userStems && userStems.has(s)) {
            matchedUserIdf += w;
          }
        }
        const fullOverlap = totalQueryIdf > 0 ? matchedIdf / totalQueryIdf : 0;
        userOverlap = totalQueryIdf > 0 ? matchedUserIdf / totalQueryIdf : 0;
        idfOverlap =
          isEpisodicStore && r._hasDialogueTurn
            ? 0.68 * userOverlap + 0.32 * fullOverlap
            : fullOverlap;

        if (lowerContent.includes(lowerQuery)) {
          score = Math.max(semanticScore, 0.92);
        } else if (totalMatches > 0 && evalTerms.length > 0) {
          const directOverlap = directMatches / evalTerms.length;
          const totalOverlap = totalMatches / evalTerms.length;
          const blendedOverlap = Math.max(
            0.65 * directOverlap + 0.35 * totalOverlap,
            idfOverlap
          );

          if (distinctiveTerms.length > 0 && distinctiveMatches === 0 && semanticScore < 0.68) {
            score = Math.min(0.35, semanticScore * 0.5);
          } else if (
            distinctiveTerms.length >= 4 &&
            distinctiveMatches === 1 &&
            semanticScore < 0.66
          ) {
            score = Math.min(0.38, semanticScore * 0.55);
          } else if (
            evalTerms.length >= 4 &&
            totalMatches === 1 &&
            totalOverlap < 0.25 &&
            semanticScore < 0.66
          ) {
            score = Math.min(0.38, semanticScore * 0.55);
          } else {
            const lexicalScore = 0.50 + blendedOverlap * 0.42;
            const hybridScore =
              semanticScore > 0
                ? semanticScore * 0.48 +
                  idfOverlap * 0.52 +
                  0.16 * Math.min(semanticScore, idfOverlap)
                : lexicalScore;
            score = Math.min(0.99, Math.max(semanticScore, lexicalScore, hybridScore));
          }
        } else {
          score = r._hasDialogueTurn
            ? semanticScore
            : semanticScore >= 0.68
              ? semanticScore
              : semanticScore * 0.45;
        }

        if (r._hasDialogueTurn && semanticScore > score) {
          score = semanticScore;
        }

        if (queryPhrases.length > 0 && score > 0.42) {
          const phraseHits = queryPhrases.filter((p) => lowerContent.includes(p)).length;
          const stemPhraseHits = r._userStemSeq
            ? queryStemPhrases.filter((sp) => r._userStemSeq.includes(sp)).length
            : 0;
          const bestPhraseHits = Math.max(phraseHits, stemPhraseHits);
          if (bestPhraseHits > 0) {
            score = Math.min(0.99, score + Math.min(0.12, bestPhraseHits * 0.05));
          }
        }

        if (hasRealQueryEmbedding && !isBroadQuery && !temporalMode && r._isStandingDirective) {
          if ((r.category === 'invariant' || r._isStandingDirective) && score > 0.42) {
            const invBoost =
              allCandidateRows.length < 30 || idfOverlap >= 0.25 || semanticScore >= 0.66
                ? 0.14
                : 0.06;
            score = Math.min(0.98, score + invBoost);
          }
          if (isEpisodicStore && r._hasDialogueTurn && semanticScore >= 0.38) {
            score = Math.max(score, semanticScore + 0.22, 0.66);
          }
        } else if (!hasRealQueryEmbedding && !temporalMode && r._isStandingDirective && score >= 0.5) {
          score = Math.min(0.98, score + 0.08);
        }

        if (r._hasDialogueTurn && r._sessionPos <= 2 && score > 0.30) {
          const openerBoost = isBroadQuery ? (r._sessionPos === 0 ? 0.14 : 0.11) : 0.06;
          score = Math.min(0.99, score + openerBoost);
        }

        if (temporalMode && lineage && lineage.length > 1 && score > 0.45) {
          score = Math.min(0.99, score + 0.06);
        }

        if (score > 0.4 && r.created_at) {
          const ageDays = Math.max(
            0,
            (nowMs - new Date(r.created_at).getTime()) / 86_400_000
          );
          if (Number.isFinite(ageDays)) {
            const recencyBoost = 0.02 * Math.exp(-DECAY_RATE * ageDays);
            score = Math.min(1.0, score + recencyBoost);
          }
        }
      }

      rawScoredItems.push({
        row: r,
        id: Number(r.id),
        category: r.category,
        status: r.status || 'active',
        content: r.content,
        lineage: lineage && lineage.length > 1 ? lineage : null,
        lineageText,
        created_at: r.created_at || null,
        updated_at: r.updated_at || null,
        rawScore: score,
        score,
        semanticScore,
        idfOverlap,
        userOverlap,
        _stems: r._stems,
        _userStems: r._userStems,
        _userRaw: r._userRaw,
        _hasDialogueTurn: r._hasDialogueTurn,
        _isStandingDirective: r._isStandingDirective,
        _sessionId: r._sessionId,
        _sessionPos: r._sessionPos,
        _isBroad: isBroadQuery
      });
    }

    // RM3 / Rocchio Pseudo-Relevance Feedback (PRF) over top first-pass episodic turns
    if (isEpisodicStore && rawScoredItems.length >= 20 && evalStems.length > 0) {
      const evalStemSet = new Set(evalStems);
      const topSeeds = [...rawScoredItems]
        .sort((a, b) => b.rawScore - a.rawScore)
        .slice(0, 8)
        .filter((x) => x.rawScore >= 0.52);

      if (topSeeds.length >= 2) {
        const seedFreq = new Map();
        for (const seed of topSeeds) {
          const stems = seed._userStems || seed._stems;
          if (!stems) continue;
          for (const st of stems) {
            if (
              st.length < 3 ||
              evalStemSet.has(st) ||
              STOP_WORDS.has(st) ||
              TEMPORAL_CUE_WORDS.has(st) ||
              GENERIC_INFRA_WORDS.has(st) ||
              META_QUERY_WORDS.has(st)
            ) {
              continue;
            }
            seedFreq.set(st, (seedFreq.get(st) || 0) + 1);
          }
        }

        const prfCandidates = [];
        for (const [st, sCount] of seedFreq.entries()) {
          if (sCount < 2) continue;
          let docFreq = 0;
          for (const r of allCandidateRows) {
            if (r._stems && r._stems.has(st)) docFreq++;
          }
          if (docFreq > corpusN * 0.50) continue;
          const idf = Math.log(1 + corpusN / (1 + docFreq));
          prfCandidates.push({ stem: st, weight: sCount * idf });
        }

        prfCandidates.sort((a, b) => b.weight - a.weight);
        const topPrf = prfCandidates.slice(0, 6);
        const totalPrfWeight = topPrf.reduce((acc, x) => acc + x.weight, 0);

        if (totalPrfWeight > 0) {
          for (const item of rawScoredItems) {
            let matchedPrf = 0;
            for (const { stem, weight } of topPrf) {
              if (
                (item._userStems && item._userStems.has(stem)) ||
                (item._stems && item._stems.has(stem))
              ) {
                matchedPrf += weight;
              }
            }
            if (matchedPrf > 0) {
              const prfOverlap = matchedPrf / totalPrfWeight;
              item.rawScore = Math.min(0.99, item.rawScore + 0.14 * prfOverlap);
              item.score = item.rawScore;
            }
          }
        }
      }
    }

    // In-session Episode Kernel Smoothing for multi-turn episodic stores with explicit session tags
    if (isEpisodicStore && rawScoredItems.length >= 20) {
      const radius = isBroadQuery ? 8 : 2;
      const CONTINUATION_CUE =
        /^(?:thanks|thank\s+you|sounds\s+good|got\s+it|yeah|yes|no,\s*i\s*think|sure|hmm|that\s+(?:plan|sounds|makes)|these\s+exercises|okay|ok\b|great|perfect|i\s+see|makes\s+sense|no\s+further)/i;
      for (let i = 0; i < rawScoredItems.length; i++) {
        const curr = rawScoredItems[i];
        if (curr._sessionId === null) continue;
        const isContinuationTurn = Boolean(
          curr._userRaw && CONTINUATION_CUE.test(curr._userRaw.trim())
        );
        let neighborMax = 0;
        let forwardAnchorMax = 0;
        let neighborSum = 0;
        let neighborCount = 0;
        for (let d = -radius; d <= radius; d++) {
          if (d === 0) continue;
          const j = i + d;
          if (
            j >= 0 &&
            j < rawScoredItems.length &&
            rawScoredItems[j]._sessionId === curr._sessionId
          ) {
            const dist = Math.abs(d);
            const decay = Math.max(0.68, 0.94 - dist * 0.035);
            const candRaw = rawScoredItems[j].rawScore;
            if (candRaw * decay > neighborMax) neighborMax = candRaw * decay;
            if (d < 0 && dist <= 2 && candRaw >= 0.62 && isContinuationTurn) {
              const contScore = candRaw * (dist === 1 ? 0.91 : 0.87);
              if (contScore > forwardAnchorMax) forwardAnchorMax = contScore;
            }
            neighborSum += candRaw;
            neighborCount++;
          }
        }
        const localAvg = neighborCount > 0 ? neighborSum / neighborCount : 0;
        curr.score = Math.max(
          curr.rawScore,
          forwardAnchorMax,
          0.50 * curr.rawScore + 0.50 * neighborMax,
          0.58 * curr.rawScore + 0.42 * localAvg
        );
      }
    }

    const filteredCandidates = [];
    for (const mItem of rawScoredItems) {
      const minKeep = hasRealQueryEmbedding && mItem._hasDialogueTurn ? 0.25 : 0.4;
      if (isWildcard || mItem.score > minKeep) {
        filteredCandidates.push(mItem);
      }
    }

    // Budget reservation for state header & temporal macro progression on large episodic stores
    const isPureDialogueTranscript =
      !isWildcard &&
      allCandidateRows.length >= 30 &&
      allCandidateRows.every((r) => r._hasDialogueTurn);

    let stateHeader = '';
    if (include_state && !isWildcard && tokenBudget >= 400) {
      if (isPureDialogueTranscript) {
        stateHeader = `# 🧠 Compiled Project State: krusch-stack (Active Invariants & Preferences inline below)\n`;
      } else {
        stateHeader = `# 🧠 Compiled Project State: krusch-stack (Invariants: ${catCounts.invariant}, Decisions: ${catCounts.decision}, Bugs: ${catCounts.bug}, Blockers: ${catCounts.blocker}, Lessons: ${catCounts.lesson})\n\n---\n\n`;
      }
    }

    const stateDeduction = estimateTokens(stateHeader);
    let headerAndTimelineReserve = 0;
    const isLargeEpisodicStore =
      condense === true ||
      (condense !== false && !isWildcard && allCandidateRows.length >= 30 && tokenBudget >= 2000);

    if (!isWildcard && tokenBudget >= 2000 && allCandidateRows.length >= 30) {
      headerAndTimelineReserve = Math.max(0, (temporalMode ? 1550 : 220) - stateDeduction);
    } else if (!isWildcard && tokenBudget >= 400 && tokenBudget < 2000 && isLargeEpisodicStore) {
      const targetReserve = temporalMode
        ? Math.min(450, Math.floor(tokenBudget * 0.28))
        : Math.min(120, Math.floor(tokenBudget * 0.12));
      headerAndTimelineReserve = Math.max(0, targetReserve - stateDeduction);
    }

    const availableTokens = isLargeEpisodicStore
      ? Math.max(100, tokenBudget - stateDeduction - headerAndTimelineReserve)
      : tokenBudget;

    const packed = packStackTokenBudget(filteredCandidates, availableTokens, evalTerms, {
      condense,
      markdownAccounting: isLargeEpisodicStore || Boolean(include_markdown && tokenBudget >= 400),
      preserveOrder: isWildcard
    });

    const driftSummary = {
      valid: 0,
      healed_line_shift: 0,
      stale_drift: 0
    };

    const items = [];
    for (const cand of packed.packedItems) {
      const { row, score, lineage, condensedContent } = cand;
      const drift = evaluateSpanDrift(row, root, db);
      if (drift.status === 'VALID') driftSummary.valid += 1;
      else if (drift.status === 'HEALED_LINE_SHIFT') driftSummary.healed_line_shift += 1;
      else driftSummary.stale_drift += 1;

      items.push({
        id: Number(row.id),
        category: row.category,
        content: packed.isLargeEpisodic ? condensedContent : row.content,
        status: row.status,
        score: Number(score.toFixed(3)),
        drift_status: drift.status,
        ...(drift.moved_candidate ? { moved_candidate: drift.moved_candidate } : {}),
        ...(lineage ? { lineage } : {}),
        provenance: {
          file: row.provenance_file || null,
          locator: drift.current_locator || row.provenance_locator || null,
          quoted_sentence: row.quoted_sentence || null,
          anchor_hash: row.anchor_hash || null,
          ...(drift.moved_candidate ? { moved_candidate: drift.moved_candidate } : {})
        },
        created_at: row.created_at,
        updated_at: row.updated_at
      });
    }

    const packedIdSet = new Set(items.map((it) => Number(it.id)));
    const conflicts = !isWildcard
      ? (packed.conflicts || []).filter((c) =>
          c.memory_ids.every((id) => packedIdSet.has(Number(id)))
        )
      : [];

    const userStemSets = allCandidateRows.map((r) => r._userStems || r._stems);
    const unattestedTerms = !isWildcard
      ? computeUnattestedQueryTerms(distinctiveTerms, items, userStemSets)
      : [];

    const maxScore = items.length > 0 ? Math.max(...items.map((it) => it.score)) : 0;
    let epistemicStatus = 'SUPPORTED';
    if (!isWildcard && (items.length === 0 || maxScore < 0.5)) {
      epistemicStatus = 'NO_KNOWN_SUPPORT';
    } else if (conflicts.length > 0) {
      epistemicStatus = 'CONFLICTED';
    }

    const chronologicalEvents = [];
    const seenChrono = new Set();
    for (const cand of packed.packedItems) {
      if (cand.lineage && cand.lineage.length > 1) {
        for (const step of cand.lineage) {
          if (!seenChrono.has(step.id)) {
            seenChrono.add(step.id);
            chronologicalEvents.push({
              id: Number(step.id),
              status: String(step.status || 'active').toUpperCase(),
              category: step.category,
              created_at: step.created_at,
              content: step.content,
              score: cand.score || 0,
              sessionId: cand._sessionId || 1,
              sessionPos: cand._sessionPos ?? 999
            });
          }
        }
      } else if (!seenChrono.has(Number(cand.id))) {
        seenChrono.add(Number(cand.id));
        chronologicalEvents.push({
          id: Number(cand.id),
          status: String(cand.status || 'active').toUpperCase(),
          category: cand.category,
          created_at: cand.created_at || null,
          content: cand.content,
          score: cand.score || 0,
          sessionId: cand._sessionId || 1,
          sessionPos: cand._sessionPos ?? 999
        });
      }
    }
    chronologicalEvents.sort((a, b) => a.id - b.id);
    const chronologicalIds = chronologicalEvents.map((e) => e.id);

    let statusSection = '';
    if (epistemicStatus === 'NO_KNOWN_SUPPORT' && !isWildcard) {
      statusSection += `> 🛑 **ABSTENTION (NO_KNOWN_SUPPORT)**: No grounded memory supports this query. Do not guess or fabricate unrecorded facts.\n\n`;
    } else if (epistemicStatus === 'CONFLICTED') {
      const conflictLines = conflicts
        .slice(0, 5)
        .map(
          (c) =>
            `- **Conflict between Memory #${c.older_id} and Memory #${c.newer_id}** (subject: \`${c.shared_subject.join(', ')}\`): ${c.resolution_hint}`
        )
        .join('\n');
      statusSection += `### ⚠️ Contradiction Resolution Alert (\`CONFLICTED\`)\n${conflictLines}\n\n`;
    }

    const unattestedBadge =
      unattestedTerms.length > 0
        ? ` | **Unattested Query Terms**: \`${unattestedTerms.join(', ')}\``
        : '';
    const stateBadge = include_state ? ' (State Included)' : '';
    const fixedHeaderSample =
      `# 🔍 Unified Context Retrieval: "${rawQuery}"${stateBadge}\n` +
      `**Epistemic Status**: ${epistemicStatus} | **Tokens**: ~9999 / Budget: ${tokenBudget} | ` +
      `**Items Packed**: ${packed.packedCount} / ${filteredCandidates.length} candidates${unattestedBadge}\n\n`;

    const remainingTimelineTokens =
      tokenBudget -
      (packed.totalTokens +
        estimateTokens(stateHeader) +
        estimateTokens(statusSection) +
        estimateTokens(fixedHeaderSample) +
        3);

    let timelineSection = '';
    if (temporalMode && chronologicalEvents.length > 1 && remainingTimelineTokens >= 45) {
      const bySess = new Map();
      for (const ev of chronologicalEvents) {
        const sKey = ev.sessionId || 1;
        if (!bySess.has(sKey)) bySess.set(sKey, []);
        bySess.get(sKey).push(ev);
      }
      for (const list of bySess.values()) {
        list.sort((a, b) => (b.score || 0) - (a.score || 0));
      }
      const sortedSessEntries = [...bySess.entries()].sort((a, b) => a[0] - b[0]);
      const sessLists = sortedSessEntries.map((e) => e[1]);
      const selectedTimeline = [];
      for (let r = 0; r < 6 && selectedTimeline.length < 15; r++) {
        for (const list of sessLists) {
          if (r < list.length && selectedTimeline.length < 15) {
            selectedTimeline.push(list[r]);
          }
        }
      }
      selectedTimeline.sort((a, b) => a.id - b.id);

      let macroSessionHeader = '';
      if (sortedSessEntries.length >= 2 && remainingTimelineTokens >= 320) {
        const sessionFocusLines = sortedSessEntries
          .map(([sKey, list]) => {
            const openers = list.filter(
              (ev) => ev.sessionPos <= 2 && String(ev.content || '').length >= 320
            );
            const pool = openers.length > 0 ? openers : list;
            const rep = [...pool].sort(
              (a, b) =>
                b.score + (b.sessionPos === 0 ? 0.04 : 0) -
                (a.score + (a.sessionPos === 0 ? 0.04 : 0))
            )[0];
            return `- **Session ${sKey} Primary Focus (#${rep.id})**: ${prunePreSynthesis(String(rep.content || ''), { maxChars: 340 })}`;
          })
          .join('\n');
        macroSessionHeader = `#### 🧭 Session-by-Session Macro Progression\n${sessionFocusLines}\n\n`;
      }

      const lineMaxChars = remainingTimelineTokens < 320 ? 120 : 280;
      const orderedLines = selectedTimeline.map(
        (ev, idx) =>
          `${idx + 1}. **#${ev.id}** [${ev.status}]: ${prunePreSynthesis(String(ev.content || ''), { maxChars: lineMaxChars })}`
      );
      const candidateFull = `${macroSessionHeader}### 📅 Chronological Event Sequence (Oldest → Newest)\n${orderedLines.join('\n')}\n\n`;
      if (estimateTokens(candidateFull) <= remainingTimelineTokens) {
        timelineSection = candidateFull;
      } else {
        const seqHeader = `### 📅 Chronological Event Sequence (Oldest → Newest)\n`;
        const fittedLines = [];
        for (const line of orderedLines) {
          const nextCandidate = `${seqHeader}${[...fittedLines, line].join('\n')}\n\n`;
          if (estimateTokens(nextCandidate) > remainingTimelineTokens) break;
          fittedLines.push(line);
        }
        if (fittedLines.length > 0) {
          timelineSection = `${seqHeader}${fittedLines.join('\n')}\n\n`;
        }
      }
    }

    const totalMarkdownTokens =
      packed.totalTokens +
      estimateTokens(stateHeader) +
      estimateTokens(statusSection) +
      estimateTokens(timelineSection) +
      estimateTokens(fixedHeaderSample);

    const reportedTokensUsed = packed.isLargeEpisodic
      ? Math.min(tokenBudget, totalMarkdownTokens)
      : packed.totalTokens;

    const retrievalBody =
      `# 🔍 Unified Context Retrieval: "${rawQuery}"${stateBadge}\n` +
      `**Epistemic Status**: ${epistemicStatus} | **Tokens**: ~${reportedTokensUsed} / Budget: ${tokenBudget} | ` +
      `**Items Packed**: ${packed.packedCount} / ${filteredCandidates.length} candidates${unattestedBadge}\n\n` +
      statusSection +
      packed.contextText +
      (timelineSection ? `\n---\n${timelineSection}` : '');

    const renderedMarkdown =
      isPureDialogueTranscript && stateHeader
        ? `${retrievalBody}\n---\n${stateHeader}`
        : `${stateHeader}${retrievalBody}`;

    const state = include_state
      ? {
          invariants: catCounts.invariant,
          decisions: catCounts.decision,
          blockers: catCounts.blocker,
          bugs: catCounts.bug,
          lessons: catCounts.lesson,
          token_budget: tokenBudget,
          tokens_used: reportedTokensUsed
        }
      : null;

    const dataPayload = {
      items,
      state,
      drift_summary: driftSummary,
      total_active: totalActive,
      epistemic_status: epistemicStatus,
      conflicts,
      chronological_order: chronologicalIds,
      unattested_query_terms: unattestedTerms,
      ...(timelineSection ? { timeline_markdown: timelineSection.trim() } : {})
    };

    Object.defineProperty(dataPayload, 'rendered_context', {
      value: renderedMarkdown,
      enumerable: Boolean(include_markdown),
      configurable: true
    });

    return okEnvelope(
      'krusch_context_retrieve',
      `Retrieved ${items.length} active memory item(s) (${driftSummary.stale_drift} drifted, status: ${epistemicStatus}).`,
      dataPayload,
      true
    );
  }

  /**
   * Async wrapper for `retrieve` that auto-hydrates an optional query embedding when Ollama is available.
   * @param {object} [params]
   */
  async function retrieveAsync(params = {}) {
    let emb = params?._embedding || null;
    const rawQ = String(params?.query ?? '*').trim();
    if (!emb && !isWildcardQuery(rawQ)) {
      const cleaned = prunePreRetrieval(rawQ);
      emb = await fetchOptionalEmbedding(cleaned, embedOptions);
    }
    return retrieve({ ...params, _embedding: emb });
  }

  /**
   * Supersede or invalidate an existing context memory record with full lineage (synchronous).
   * @param {object} [params]
   * @param {'supersede'|'invalidate'} [params.action='invalidate']
   * @param {number} params.target_id
   * @param {string} [params.new_content]
   * @param {string} [params.reason='Revised']
   * @param {object} [params.provenance]
   * @param {Array<number>|Float64Array|string|null} [params._embedding=null]
   */
  function revise({
    action = 'invalidate',
    target_id,
    new_content,
    reason = 'Revised',
    provenance = null,
    _embedding = null
  } = {}) {
    const normalizedAction = String(action || 'invalidate').trim().toLowerCase();
    if (!VALID_REVISE_ACTIONS.has(normalizedAction)) {
      return okEnvelope(
        'krusch_context_revise',
        `Invalid revise action "${action}". Expected supersede or invalidate.`,
        { error: `Invalid action: ${action}` },
        false
      );
    }

    const numericId = Number(target_id);
    if (!Number.isInteger(numericId) || numericId <= 0) {
      return okEnvelope(
        'krusch_context_revise',
        'Valid target_id is required.',
        { error: 'target_id is required' },
        false
      );
    }

    const existing = selectByIdStmt.get(numericId);
    if (!existing) {
      return okEnvelope(
        'krusch_context_revise',
        `Memory #${numericId} not found.`,
        { target_id: numericId, error: 'not_found' },
        false
      );
    }

    const revocationReason = String(reason || 'Revised').trim();

    if (normalizedAction === 'supersede') {
      const hasProvenanceUpdate =
        provenance !== null &&
        typeof provenance === 'object' &&
        !Array.isArray(provenance) &&
        Object.keys(provenance).length > 0;
      const replacementText =
        new_content === undefined && hasProvenanceUpdate
          ? String(existing.content ?? '').trim()
          : String(new_content ?? '').trim();
      if (!replacementText) {
        return okEnvelope(
          'krusch_context_revise',
          'new_content is required when action is "supersede".',
          { target_id: numericId, error: 'new_content_required' },
          false
        );
      }

      const provFile =
        provenance && provenance.file !== undefined
          ? provenance.file
            ? String(provenance.file).trim()
            : null
          : existing.provenance_file;
      const provLocator =
        provenance && provenance.locator !== undefined
          ? provenance.locator
            ? String(provenance.locator).trim()
            : null
          : existing.provenance_locator;
      const provQuoted =
        provenance && provenance.quoted_sentence !== undefined
          ? provenance.quoted_sentence
            ? String(provenance.quoted_sentence).trim()
            : null
          : existing.quoted_sentence;
      const provAnchor = provenance
        ? computeProvenanceAnchorHash(
            {
              file: provFile,
              locator: provLocator,
              quoted_sentence: provQuoted,
              anchor_hash: provenance.anchor_hash
            },
            root
          )
        : existing.anchor_hash;
      const serializedEmbedding =
        _embedding !== null && _embedding !== undefined
          ? serializeEmbeddingVector(_embedding)
          : new_content === undefined && hasProvenanceUpdate
            ? existing.embedding || null
            : null;

      let newId;
      db.exec('BEGIN IMMEDIATE');
      try {
        const insertResult = insertMemoryStmt.run(
          existing.category,
          replacementText,
          provFile,
          provLocator,
          provQuoted,
          provAnchor,
          serializedEmbedding
        );
        newId = Number(insertResult.lastInsertRowid);
        markSupersededStmt.run(newId, revocationReason, numericId);
        db.exec('COMMIT');
      } catch (err) {
        try {
          db.exec('ROLLBACK');
        } catch {}
        throw err;
      }

      return okEnvelope(
        'krusch_context_revise',
        `Superseded memory #${numericId} with memory #${newId}.`,
        {
          action: 'supersede',
          target_id: numericId,
          new_id: newId,
          superseded_by: newId,
          status: 'superseded',
          has_embedding: Boolean(serializedEmbedding),
          reason: revocationReason
        },
        true
      );
    }

    markInvalidatedStmt.run(revocationReason, numericId);
    return okEnvelope(
      'krusch_context_revise',
      `Invalidated memory #${numericId}.`,
      {
        action: 'invalidate',
        target_id: numericId,
        status: 'invalidated',
        reason: revocationReason
      },
      true
    );
  }

  /**
   * Async wrapper for `revise` that auto-hydrates an optional embedding on `supersede` when Ollama is available.
   * @param {object} [params]
   */
  async function reviseAsync(params = {}) {
    let emb = params?._embedding || null;
    if (
      !emb &&
      String(params?.action || '').trim().toLowerCase() === 'supersede' &&
      params?.new_content &&
      String(params.new_content).trim()
    ) {
      emb = await fetchOptionalEmbedding(String(params.new_content), embedOptions);
    }
    return revise({ ...params, _embedding: emb });
  }

  /**
   * Audit staged code or diffs against active invariants and decisions (max 3 findings).
   * @param {object} [params]
   * @param {string} [params.trigger='pre_commit']
   * @param {string} [params.code='']
   */
  function nudge({ trigger = 'pre_commit', code = '' } = {}) {
    const codeText = String(code ?? '');
    const activeRows = selectActivePoolStmt
      .all(maxScanLimit)
      .filter((row) => row.category === 'invariant' || row.category === 'decision');

    const findings = [];

    for (const row of activeRows) {
      if (findings.length >= 3) break;

      const forbiddenTokens = extractForbiddenPatterns(row.content);
      for (const token of forbiddenTokens) {
        if (codeText.includes(token)) {
          findings.push({
            memory_id: Number(row.id),
            category: row.category,
            severity: row.category === 'invariant' ? 'error' : 'warning',
            matched_token: token,
            rule: row.content,
            message: `Violation of ${row.category} #${row.id}: found forbidden pattern "${token}".`
          });
          break;
        }
      }
    }

    // Built-in sanitization check if code contains RFC1918 / CGNAT IP literals when invariant rules exist
    if (findings.length < 3 && codeText) {
      const privateIpRegex = new RegExp(
        '\\b(?:192\\.168\\.\\d{1,3}\\.\\d{1,3}|10\\.10\\.10\\.\\d{1,3}|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.\\d{1,3}\\.\\d{1,3})\\b'
      );
      const ipMatch = codeText.match(privateIpRegex);
      if (ipMatch) {
        findings.push({
          memory_id: null,
          category: 'invariant',
          severity: 'error',
          matched_token: ipMatch[0],
          rule: 'INV-STACK-04: Public Sanitization (no private LAN or mesh IP literals).',
          message: `Found private IP literal "${ipMatch[0]}" violating INV-STACK-04.`
        });
      }
    }

    const cappedFindings = findings.slice(0, 3);
    const passed = cappedFindings.length === 0;

    return okEnvelope(
      'krusch_context_nudge',
      passed
        ? `Audit (${trigger}) passed with 0 findings across ${activeRows.length} active rule(s).`
        : `Audit (${trigger}) flagged ${cappedFindings.length} finding(s).`,
      {
        trigger,
        passed,
        rules_checked: activeRows.length,
        findings: cappedFindings
      },
      true
    );
  }

  /**
   * Return store health counts and INV-12 drift statistics.
   */
  function health() {
    const countsRows = db
      .prepare(`
      SELECT status, COUNT(*) AS count
      FROM context_memories
      GROUP BY status
    `)
      .all();

    const counts = {
      active: 0,
      superseded: 0,
      invalidated: 0
    };

    for (const row of countsRows) {
      if (row.status in counts) {
        counts[row.status] = Number(row.count);
      }
    }

    const activeRows = selectActiveStmt.all();
    let driftedCount = 0;
    let relocatedCandidatesCount = 0;
    let healedCount = 0;
    let embeddedCount = 0;
    for (const row of activeRows) {
      if (row.embedding) embeddedCount += 1;
      const drift = evaluateSpanDrift(row, root, db);
      if (drift.status === 'STALE_DRIFT') {
        driftedCount += 1;
        if (drift.moved_candidate) {
          relocatedCandidatesCount += 1;
        }
      } else if (drift.status === 'HEALED_LINE_SHIFT') {
        healedCount += 1;
      }
    }

    return okEnvelope(
      'krusch_context_health',
      `Context store healthy: ${counts.active} active, ${counts.superseded} superseded, ${counts.invalidated} invalidated, ${driftedCount} drifted.`,
      {
        active: counts.active,
        superseded: counts.superseded,
        invalidated: counts.invalidated,
        embedded_count: embeddedCount,
        drifted_count: driftedCount,
        relocated_candidates_count: relocatedCandidatesCount,
        healed_count: healedCount,
        total: counts.active + counts.superseded + counts.invalidated
      },
      true
    );
  }

  return {
    retrieve,
    retrieveAsync,
    remember,
    rememberAsync,
    revise,
    reviseAsync,
    nudge,
    health
  };
}
