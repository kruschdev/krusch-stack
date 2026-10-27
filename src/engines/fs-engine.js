/**
 * @module engines/fs-engine
 * Tier 2B: OS Filesystem & Page-Anchored Memory Engine (krusch-fs).
 * Splits files into bounded structural pages (~80 lines or Markdown heading boundaries),
 * enforces .env KEYS_ONLY redaction & pre-write secret shielding (INV-STACK-08),
 * computes SHA-256 page hashes, evaluates anchored notes for VALID vs STALE_DRIFT,
 * and executes external-content Porter FTS5 + lazy Top-K page_text hydration (INV-STACK-07 & INV-STACK-09).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';
import {
  stemToken,
  estimateTokens,
  splitIdentifierSubtokens,
  extractCodeShapeIdentifiers,
  buildFts5MatchQuery,
  STOP_WORDS
} from './context-lexical.js';

const MAX_LINES_PER_PAGE = 80;
const DEFAULT_SNIPPET_MAX_CHARS = 300;

const SAFE_ENV_SUFFIXES = ['.example', '.sample', '.template', '.schema', '.dist'];

const SECRET_LEAK_PATTERNS = [
  { regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/, reason: 'Anthropic API key' },
  { regex: /\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b/, reason: 'API secret key (sk-...)' },
  { regex: /\bxai-[A-Za-z0-9_-]{20,}\b/, reason: 'xAI API key' },
  { regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/, reason: 'Stripe live secret key' },
  {
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})\b/,
    reason: 'GitHub access token'
  },
  { regex: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/, reason: 'Slack token' },
  { regex: /\bAIza[0-9A-Za-z_-]{35}\b/, reason: 'Google API key' },
  { regex: /\bAKIA[0-9A-Z]{16}\b/, reason: 'AWS access key ID' },
  {
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PRIVATE )?PRIVATE KEY-----/,
    reason: 'PEM private key'
  }
];

const INLINE_URL_CREDENTIAL_REGEX = /:\/\/([^/\s:@]+):([^/\s:@]{8,})@/g;

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  '.krusch-stack',
  'dist',
  'build',
  'coverage',
  '.next',
  '.cache',
  '__pycache__'
]);

const TEXT_EXTENSIONS = new Set([
  '.md',
  '.markdown',
  '.txt',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.py',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.sql',
  '.sh',
  '.css',
  '.html',
  '.env',
  '.conf',
  '.service'
]);

/**
 * Determine whether a file path targets a sensitive .env file whose values must be redacted.
 * Excludes safe template suffixes (.example, .sample, .template, .schema, .dist).
 * @param {string} filePath
 * @returns {boolean}
 */
export function isSensitiveEnvFile(filePath) {
  const base = path.basename(String(filePath ?? '')).toLowerCase();
  if (!base) return false;
  if (SAFE_ENV_SUFFIXES.some((suffix) => base.endsWith(suffix))) {
    return false;
  }
  return base === '.env' || base.startsWith('.env.');
}

/**
 * Scan arbitrary text for raw secret keys, access tokens, PEM private keys, or inline URL passwords.
 * Returns null when clean (including `[REDACTED]` placeholders) or a short reason string when matched.
 * @param {string} text
 * @returns {string | null}
 */
export function scanForSecretLeak(text) {
  const input = String(text ?? '');
  if (!input) return null;

  for (const { regex, reason } of SECRET_LEAK_PATTERNS) {
    if (regex.test(input)) {
      return reason;
    }
  }

  for (const match of input.matchAll(INLINE_URL_CREDENTIAL_REGEX)) {
    const pwd = match[2] || '';
    if (
      !/redacted/i.test(pwd) &&
      !pwd.includes('***') &&
      !pwd.includes('<') &&
      !pwd.includes('>')
    ) {
      return 'Inline URL password';
    }
  }

  return null;
}

/**
 * Check whether an assignment RHS opens a quote (`"` or `'`) without closing it on the same line.
 * @param {string} rhs
 * @returns {'"' | "'" | null}
 */
function detectUnclosedQuote(rhs) {
  if (!rhs || (rhs[0] !== '"' && rhs[0] !== "'")) return null;
  const quoteChar = rhs[0];
  for (let i = 1; i < rhs.length; i += 1) {
    if (rhs[i] === '\\' && quoteChar === '"') {
      i += 1;
      continue;
    }
    if (rhs[i] === quoteChar) {
      return null;
    }
  }
  return quoteChar;
}

/**
 * Check whether a matching closing quote appears on a subsequent line.
 * @param {string[]} lines
 * @param {number} startIndex
 * @param {'"' | "'"} quoteChar
 * @returns {boolean}
 */
function hasClosingQuoteOnSubsequentLine(lines, startIndex, quoteChar) {
  for (let i = startIndex; i < lines.length; i += 1) {
    const line = lines[i];
    for (let j = 0; j < line.length; j += 1) {
      if (line[j] === '\\' && quoteChar === '"') {
        j += 1;
        continue;
      }
      if (line[j] === quoteChar) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Redact `.env` secret values in-memory (`KEY=[REDACTED]`) while preserving line count,
 * empty values, safe comments, and variable names (`KEYS_ONLY` policy, INV-STACK-08).
 * @param {string} content
 * @returns {string}
 */
export function redactEnvSecrets(content) {
  const raw = String(content ?? '');
  if (!raw) return '';

  const lines = raw.split(/\r?\n/);
  const out = [];
  let inPemBlock = false;
  let multilineQuote = null;

  for (let idx = 0; idx < lines.length; idx += 1) {
    const line = lines[idx];
    const trimmed = line.trim();

    if (inPemBlock) {
      if (/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(line)) {
        inPemBlock = false;
        multilineQuote = null;
      }
      out.push('[REDACTED]');
      continue;
    }

    if (multilineQuote) {
      for (let j = 0; j < line.length; j += 1) {
        if (line[j] === '\\' && multilineQuote === '"') {
          j += 1;
          continue;
        }
        if (line[j] === multilineQuote) {
          multilineQuote = null;
          break;
        }
      }
      out.push('[REDACTED]');
      continue;
    }

    if (trimmed === '') {
      out.push(line);
      continue;
    }

    if (trimmed.startsWith('#') || trimmed.startsWith(';')) {
      if (scanForSecretLeak(line)) {
        out.push('# [REDACTED_SECRET_COMMENT]');
      } else {
        out.push(line);
      }
      continue;
    }

    const assignMatch = line.match(/^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*)(.*)$/);
    if (assignMatch) {
      const lhs = assignMatch[1];
      const rhs = assignMatch[2].trim();

      if (
        /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PRIVATE )?PRIVATE KEY-----/.test(rhs) &&
        !/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(rhs)
      ) {
        inPemBlock = true;
      } else {
        const unclosed = detectUnclosedQuote(rhs);
        if (unclosed && hasClosingQuoteOnSubsequentLine(lines, idx + 1, unclosed)) {
          multilineQuote = unclosed;
        }
      }

      if (rhs === '' || rhs === '""' || rhs === "''") {
        out.push(lhs);
      } else if (rhs === '[REDACTED]') {
        out.push(`${lhs}[REDACTED]`);
      } else {
        out.push(`${lhs}[REDACTED]`);
      }
      continue;
    }

    if (
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PRIVATE )?PRIVATE KEY-----/.test(line) &&
      !/-----END [A-Z0-9 ]*PRIVATE KEY-----/.test(line)
    ) {
      inPemBlock = true;
      out.push('[REDACTED]');
      continue;
    }

    if (scanForSecretLeak(line)) {
      out.push('[REDACTED]');
      continue;
    }

    out.push(line);
  }

  return out.join('\n');
}

/**
 * Compute SHA-256 hex digest of a string.
 * @param {string} text
 * @returns {string}
 */
function sha256(text) {
  return crypto.createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex');
}

/**
 * Classify a file path into a category ('docs', 'config', 'code', 'other').
 * @param {string} filePath
 * @returns {'docs' | 'config' | 'code' | 'other'}
 */
function classifyFileCategory(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();
  if (ext === '.md' || ext === '.markdown' || ext === '.txt') {
    return 'docs';
  }
  if (
    ext === '.json' ||
    ext === '.yaml' ||
    ext === '.yml' ||
    ext === '.toml' ||
    ext === '.env' ||
    ext === '.conf' ||
    ext === '.service' ||
    base.startsWith('.env') ||
    base === 'dockerfile' ||
    base.startsWith('docker-compose')
  ) {
    return 'config';
  }
  if (
    ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.sql', '.sh', '.css', '.html'].includes(
      ext
    )
  ) {
    return 'code';
  }
  return 'other';
}

/**
 * Convert a glob pattern (e.g. "*.js", "*.md", "*engine*") into a RegExp.
 * @param {string} pattern
 * @returns {RegExp}
 */
function globToRegExp(pattern) {
  const trimmed = String(pattern || '*').trim();
  if (!trimmed || trimmed === '*') {
    return /^.*$/i;
  }
  let regexStr = '';
  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i];
    if (ch === '*') {
      if (trimmed[i + 1] === '*') {
        regexStr += '.*';
        i += 1;
      } else {
        regexStr += '[^/]*';
      }
    } else if (ch === '?') {
      regexStr += '.';
    } else if ('+^$()[]{}|\\'.includes(ch)) {
      regexStr += `\\${ch}`;
    } else {
      regexStr += ch;
    }
  }
  return new RegExp(regexStr, 'i');
}

/**
 * Split file content into bounded structural pages (~80 lines per page or top-level Markdown headings).
 * @param {string} content
 * @param {string} filePath
 * @returns {Array<{ page_number: number, section_title: string, start_line: number, end_line: number, page_hash: string, page_text: string }>}
 */
function splitIntoStructuralPages(content, filePath) {
  const text = String(content ?? '');
  const lines = text.split(/\r?\n/);
  const ext = path.extname(filePath).toLowerCase();
  const isMarkdown = ext === '.md' || ext === '.markdown';

  if (lines.length === 0 || (lines.length === 1 && lines[0] === '')) {
    return [
      {
        page_number: 1,
        section_title: path.basename(filePath) || 'Page 1',
        start_line: 1,
        end_line: 1,
        page_hash: sha256(''),
        page_text: ''
      }
    ];
  }

  const rawChunks = [];
  let currentLines = [];
  let currentStartLine = 1;
  let currentTitle = path.basename(filePath);

  function flushChunk(endLine) {
    if (currentLines.length === 0) return;
    const pageText = currentLines.join('\n');
    rawChunks.push({
      page_number: rawChunks.length + 1,
      section_title:
        currentTitle || `Page ${rawChunks.length + 1} (L${currentStartLine}-L${endLine})`,
      start_line: currentStartLine,
      end_line: endLine,
      page_hash: sha256(pageText),
      page_text: pageText
    });
    currentLines = [];
  }

  for (let i = 0; i < lines.length; i += 1) {
    const lineNum = i + 1;
    const line = lines[i];

    if (isMarkdown) {
      const headingMatch = line.match(/^(#{1,2})\s+(.+?)\s*$/);
      if (headingMatch) {
        if (currentLines.length > 0) {
          flushChunk(lineNum - 1);
          currentStartLine = lineNum;
        }
        currentTitle = headingMatch[2].trim();
      }
    }

    if (currentLines.length === 0) {
      currentStartLine = lineNum;
      if (!isMarkdown) {
        currentTitle = `${path.basename(filePath)} (L${lineNum})`;
      }
    }

    currentLines.push(line);

    if (currentLines.length >= MAX_LINES_PER_PAGE) {
      flushChunk(lineNum);
      if (!isMarkdown) {
        currentTitle = '';
      }
    }
  }

  if (currentLines.length > 0) {
    flushChunk(lines.length);
  }

  return rawChunks;
}

/**
 * Build a bounded snippet (up to maxLen chars) centered around matched query identifiers/terms.
 * @param {string} pageText
 * @param {string[]} priorityTerms
 * @param {number} [maxLen=300]
 * @returns {string}
 */
function buildPageSnippet(pageText, priorityTerms, maxLen = DEFAULT_SNIPPET_MAX_CHARS) {
  const text = String(pageText ?? '');
  if (maxLen <= 0) return '';
  if (text.length <= maxLen || !Array.isArray(priorityTerms) || priorityTerms.length === 0) {
    return text.slice(0, maxLen);
  }

  const lower = text.toLowerCase();
  const matchedSpans = [];
  for (const rawTerm of priorityTerms) {
    const term = String(rawTerm ?? '').toLowerCase();
    if (!term) continue;
    const idx = lower.indexOf(term);
    if (idx !== -1) {
      matchedSpans.push({ idx, len: term.length });
    }
  }

  if (matchedSpans.length === 0) {
    return text.slice(0, maxLen);
  }

  const first = matchedSpans[0];
  if (first.idx + first.len <= maxLen) {
    const baseSlice = text.slice(0, maxLen);
    if (matchedSpans.length <= 1 || maxLen < 90) {
      return baseSlice;
    }
    const uncovered = matchedSpans.find((sp) => sp.idx + sp.len > maxLen);
    if (!uncovered) {
      return baseSlice;
    }
    const sep = ' ... ';
    const halfLen = Math.floor((maxLen - sep.length) / 2);
    if (halfLen >= first.len && halfLen >= uncovered.len) {
      const lead1 = Math.min(24, Math.max(0, Math.floor((halfLen - first.len) / 2)));
      const start1 = Math.max(0, Math.min(first.idx - lead1, text.length - halfLen));
      const lead2 = Math.min(24, Math.max(0, Math.floor((halfLen - uncovered.len) / 2)));
      const start2 = Math.max(0, Math.min(uncovered.idx - lead2, text.length - halfLen));
      if (start2 >= start1 + halfLen) {
        return `${text.slice(start1, start1 + halfLen)}${sep}${text.slice(start2, start2 + halfLen)}`.slice(
          0,
          maxLen
        );
      }
    }
    return baseSlice;
  }

  const leadIn = Math.min(60, Math.max(0, Math.floor((maxLen - first.len) / 2)));
  const start = Math.max(0, Math.min(first.idx - leadIn, text.length - maxLen));
  return text.slice(start, start + maxLen);
}

/**
 * Estimate token cost of a single search result row (`snippet` + `section_title` + `memories`).
 * @param {{ snippet?: string, section_title?: string, memories?: Array<{ note?: string }> }} item
 * @returns {number}
 */
function estimateSearchHitTokens(item) {
  const memTokens = Array.isArray(item.memories)
    ? item.memories.reduce((sum, m) => sum + estimateTokens(m.note || ''), 0)
    : 0;
  return (
    estimateTokens(item.snippet || '') + estimateTokens(item.section_title || '') + memTokens
  );
}

/**
 * Tokenize lowercase text into stem set for metadata morphological matching.
 * @param {string} text
 * @returns {Set<string>}
 */
function extractMetadataStems(text) {
  const stems = new Set();
  const parts = String(text ?? '')
    .toLowerCase()
    .split(/[^a-z0-9]+/);
  for (const part of parts) {
    if (part.length >= 2) {
      stems.add(stemToken(part));
    }
  }
  return stems;
}

/**
 * Create a Tier 2B Filesystem & Page-Anchored Memory Engine instance.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 */
export function createFsEngine({ db, workspaceRoot = process.cwd() }) {
  const root = path.resolve(workspaceRoot);

  const upsertPageStmt = db.prepare(`
    INSERT INTO fs_pages (
      file_path,
      page_number,
      section_title,
      start_line,
      end_line,
      page_hash,
      page_text,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(file_path, page_number) DO UPDATE SET
      section_title = excluded.section_title,
      start_line = excluded.start_line,
      end_line = excluded.end_line,
      page_hash = excluded.page_hash,
      page_text = excluded.page_text,
      updated_at = datetime('now')
  `);

  const pruneTrailingPagesStmt = db.prepare(`
    DELETE FROM fs_pages WHERE file_path = ? AND page_number > ?
  `);

  const selectSinglePageStmt = db.prepare(`
    SELECT
      file_path,
      page_number,
      section_title,
      start_line,
      end_line,
      page_hash,
      page_text,
      updated_at
    FROM fs_pages
    WHERE file_path = ? AND page_number = ?
  `);

  const selectAllPagesMetaStmt = db.prepare(`
    SELECT
      id,
      file_path,
      page_number,
      section_title,
      start_line,
      end_line,
      page_hash
    FROM fs_pages
  `);

  const selectPageTextByIdStmt = db.prepare(`
    SELECT page_text FROM fs_pages WHERE id = ?
  `);

  const likeFallbackPageIdsStmt = db.prepare(`
    SELECT id FROM fs_pages WHERE lower(page_text) LIKE ? ESCAPE '\\'
  `);

  const countPagesStmt = db.prepare(`
    SELECT COUNT(*) AS cnt FROM fs_pages
  `);

  const insertPageMemoryStmt = db.prepare(`
    INSERT INTO fs_page_memories (
      file_path,
      page_number,
      category,
      note,
      anchored_page_hash
    ) VALUES (?, ?, ?, ?, ?)
  `);

  const selectPageMemoriesStmt = db.prepare(`
    SELECT
      id,
      file_path,
      page_number,
      category,
      note,
      anchored_page_hash,
      created_at
    FROM fs_page_memories
    WHERE file_path = ? AND page_number = ?
    ORDER BY id ASC
  `);

  const selectAllMemoriesStmt = db.prepare(`
    SELECT
      id,
      file_path,
      page_number,
      category,
      note,
      anchored_page_hash
    FROM fs_page_memories
    ORDER BY id ASC
  `);

  let cachedFtsPagesStmt = null;
  let cachedFtsMemoriesStmt = null;

  /**
   * Resolve a user-supplied path to both an absolute filesystem path and a canonical key.
   * @param {string} inputPath
   * @returns {{ absPath: string, keyPath: string }}
   */
  function resolveTargetFile(inputPath) {
    const raw = String(inputPath ?? '').trim();
    const absPath = path.isAbsolute(raw) ? path.resolve(raw) : path.resolve(root, raw);
    const relToRoot = path.relative(root, absPath).replace(/\\/g, '/');
    const keyPath = relToRoot && !relToRoot.startsWith('..') ? relToRoot : absPath;
    return { absPath, keyPath };
  }

  /**
   * Index a single file into fs_pages and return its computed pages.
   * Sensitive .env files are redacted (`KEYS_ONLY`) prior to page splitting and hashing (INV-STACK-08).
   * @param {string} inputPath
   * @returns {{ ok: boolean, absPath: string, keyPath: string, pages: Array<object>, redacted?: boolean, error?: string }}
   */
  function indexFilePages(inputPath) {
    const { absPath, keyPath } = resolveTargetFile(inputPath);
    if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
      return { ok: false, absPath, keyPath, pages: [], error: `File not found: ${inputPath}` };
    }

    let content = fs.readFileSync(absPath, 'utf8');
    const redacted = isSensitiveEnvFile(absPath);
    if (redacted) {
      content = redactEnvSecrets(content);
    }

    const pages = splitIntoStructuralPages(content, absPath);

    for (const p of pages) {
      upsertPageStmt.run(
        keyPath,
        p.page_number,
        p.section_title,
        p.start_line,
        p.end_line,
        p.page_hash,
        p.page_text
      );
    }
    pruneTrailingPagesStmt.run(keyPath, pages.length);

    return { ok: true, absPath, keyPath, pages, redacted };
  }

  /**
   * Walk directory and locate files matching glob pattern, category, and minimum size.
   * @param {object} [params]
   * @param {string} [params.pattern='*']
   * @param {string} [params.category='all']
   * @param {number} [params.min_size_bytes=0]
   */
  function locate({ pattern = '*', category = 'all', min_size_bytes = 0 } = {}) {
    const regex = globToRegExp(pattern);
    const normalizedCat = String(category || 'all').trim().toLowerCase();
    const minSize = Number.isFinite(Number(min_size_bytes))
      ? Math.max(0, Number(min_size_bytes))
      : 0;
    const files = [];

    function walk(currentDir) {
      let entries;
      try {
        entries = fs.readdirSync(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
          continue;
        }
        if (!entry.isFile()) continue;

        let stat;
        try {
          stat = fs.statSync(fullPath);
        } catch {
          continue;
        }

        if (stat.size < minSize) continue;

        const relPath = path.relative(root, fullPath).replace(/\\/g, '/');
        const fileCat = classifyFileCategory(relPath);
        if (normalizedCat !== 'all' && fileCat !== normalizedCat) {
          continue;
        }

        const matchesPattern =
          regex.test(entry.name) ||
          regex.test(relPath) ||
          relPath.toLowerCase().includes(String(pattern || '').replace(/\*/g, '').toLowerCase());

        if (!matchesPattern) continue;

        files.push({
          path: relPath,
          file_path: relPath,
          abs_path: fullPath,
          name: entry.name,
          category: fileCat,
          size_bytes: stat.size,
          modified_at: stat.mtime.toISOString()
        });
      }
    }

    walk(root);
    files.sort((a, b) => a.path.localeCompare(b.path));

    return okEnvelope(
      'krusch_fs_locate',
      `Located ${files.length} file(s) matching pattern "${pattern}".`,
      {
        pattern,
        category: normalizedCat,
        min_size_bytes: minSize,
        count: files.length,
        files
      },
      true
    );
  }

  /**
   * Inspect the structural table of contents (pages, line ranges, SHA-256 hashes) for a file.
   * @param {object} [params]
   * @param {string} params.path
   */
  function pageTree({ path: targetPath } = {}) {
    if (!targetPath) {
      return okEnvelope(
        'krusch_fs_page_tree',
        'path is required.',
        { error: 'path_required', pages: [] },
        false
      );
    }

    const indexed = indexFilePages(targetPath);
    if (!indexed.ok) {
      return okEnvelope(
        'krusch_fs_page_tree',
        indexed.error,
        { path: String(targetPath), error: 'not_found', pages: [] },
        false
      );
    }

    const tocPages = indexed.pages.map((p) => ({
      page_number: p.page_number,
      section_title: p.section_title,
      start_line: p.start_line,
      end_line: p.end_line,
      page_hash: p.page_hash
    }));

    return okEnvelope(
      'krusch_fs_page_tree',
      `Generated page tree for ${indexed.keyPath} (${tocPages.length} page(s)).`,
      {
        path: indexed.keyPath,
        file_path: indexed.keyPath,
        total_pages: tocPages.length,
        pages: tocPages
      },
      true
    );
  }

  /**
   * Read a bounded structural page along with its anchored PageMemory notes and SHA-256 drift status.
   * @param {object} [params]
   * @param {string} params.path
   * @param {number} [params.page_number=1]
   */
  function readPage({ path: targetPath, page_number = 1 } = {}) {
    if (!targetPath) {
      return okEnvelope(
        'krusch_fs_read_page',
        'path is required.',
        { error: 'path_required' },
        false
      );
    }

    const indexed = indexFilePages(targetPath);
    if (!indexed.ok) {
      return okEnvelope(
        'krusch_fs_read_page',
        indexed.error,
        { path: String(targetPath), error: 'not_found' },
        false
      );
    }

    const pageNum =
      Number.isInteger(Number(page_number)) && Number(page_number) >= 1 ? Number(page_number) : 1;

    const page = selectSinglePageStmt.get(indexed.keyPath, pageNum);
    if (!page) {
      return okEnvelope(
        'krusch_fs_read_page',
        `Page ${pageNum} out of range for ${indexed.keyPath} (total pages: ${indexed.pages.length}).`,
        {
          path: indexed.keyPath,
          page_number: pageNum,
          total_pages: indexed.pages.length,
          error: 'page_out_of_range'
        },
        false
      );
    }

    const rawMemories = selectPageMemoriesStmt.all(indexed.keyPath, pageNum);
    const memories = rawMemories.map((m) => {
      const driftStatus = m.anchored_page_hash === page.page_hash ? 'VALID' : 'STALE_DRIFT';
      return {
        id: Number(m.id),
        file_path: m.file_path,
        page_number: Number(m.page_number),
        category: m.category,
        note: m.note,
        anchored_page_hash: m.anchored_page_hash,
        current_page_hash: page.page_hash,
        drift_status: driftStatus,
        status: driftStatus,
        created_at: m.created_at
      };
    });

    const pageDriftStatus = memories.some((m) => m.drift_status === 'STALE_DRIFT')
      ? 'STALE_DRIFT'
      : 'VALID';

    return okEnvelope(
      'krusch_fs_read_page',
      `Read page ${pageNum}/${indexed.pages.length} of ${indexed.keyPath} (${memories.length} anchored note(s), status: ${pageDriftStatus}).`,
      {
        path: indexed.keyPath,
        file_path: indexed.keyPath,
        page_number: Number(page.page_number),
        total_pages: indexed.pages.length,
        section_title: page.section_title,
        start_line: Number(page.start_line),
        end_line: Number(page.end_line),
        page_hash: page.page_hash,
        page_text: page.page_text,
        content: page.page_text,
        drift_status: pageDriftStatus,
        memories
      },
      true
    );
  }

  /**
   * Pin a durable operational note to a specific page of a file, anchored to its current SHA-256 page_hash.
   * Rejects notes containing unredacted secrets prior to database persistence (INV-STACK-08).
   * @param {object} [params]
   * @param {string} params.path
   * @param {number} [params.page_number=1]
   * @param {string} params.note
   * @param {string} [params.category='annotation']
   */
  function rememberOnPage({
    path: targetPath,
    page_number = 1,
    note,
    category = 'annotation'
  } = {}) {
    if (!targetPath) {
      return okEnvelope(
        'krusch_fs_remember_on_page',
        'path is required.',
        { error: 'path_required' },
        false
      );
    }

    const trimmedNote = String(note ?? '').trim();
    if (!trimmedNote) {
      return okEnvelope(
        'krusch_fs_remember_on_page',
        'note is required.',
        { error: 'note_required' },
        false
      );
    }

    const leakReason = scanForSecretLeak(trimmedNote);
    if (leakReason) {
      return okEnvelope(
        'krusch_fs_remember_on_page',
        `Refused to persist note containing potential secret material (${leakReason}). Redact sensitive values before anchoring.`,
        { error: 'secret_leak_blocked', reason: leakReason },
        false
      );
    }

    const indexed = indexFilePages(targetPath);
    if (!indexed.ok) {
      return okEnvelope(
        'krusch_fs_remember_on_page',
        indexed.error,
        { path: String(targetPath), error: 'not_found' },
        false
      );
    }

    const pageNum =
      Number.isInteger(Number(page_number)) && Number(page_number) >= 1 ? Number(page_number) : 1;

    const page = selectSinglePageStmt.get(indexed.keyPath, pageNum);
    if (!page) {
      return okEnvelope(
        'krusch_fs_remember_on_page',
        `Page ${pageNum} does not exist in ${indexed.keyPath}.`,
        { path: indexed.keyPath, page_number: pageNum, error: 'page_out_of_range' },
        false
      );
    }

    const normalizedCat = String(category || 'annotation').trim().toLowerCase();
    const result = insertPageMemoryStmt.run(
      indexed.keyPath,
      pageNum,
      normalizedCat,
      trimmedNote,
      page.page_hash
    );
    const id = Number(result.lastInsertRowid);

    return okEnvelope(
      'krusch_fs_remember_on_page',
      `Anchored ${normalizedCat} note #${id} to ${indexed.keyPath} page ${pageNum}.`,
      {
        id,
        path: indexed.keyPath,
        file_path: indexed.keyPath,
        page_number: pageNum,
        category: normalizedCat,
        note: trimmedNote,
        anchored_page_hash: page.page_hash,
        drift_status: 'VALID'
      },
      true
    );
  }

  /**
   * Incrementally index local files or directories into fs_pages.
   * @param {object} [params]
   * @param {string[]} [params.paths=[]]
   */
  function sync({ paths = [] } = {}) {
    const targetPaths = Array.isArray(paths) && paths.length > 0 ? paths : [root];
    let filesSynced = 0;
    let pagesSynced = 0;

    function syncTarget(entryPath) {
      const absTarget = path.isAbsolute(entryPath)
        ? path.resolve(entryPath)
        : path.resolve(root, entryPath);
      if (!fs.existsSync(absTarget)) return;

      const stat = fs.statSync(absTarget);
      if (stat.isFile()) {
        const ext = path.extname(absTarget).toLowerCase();
        const base = path.basename(absTarget).toLowerCase();
        if (
          TEXT_EXTENSIONS.has(ext) ||
          base === 'dockerfile' ||
          isSensitiveEnvFile(absTarget) ||
          base.startsWith('.env.')
        ) {
          const res = indexFilePages(absTarget);
          if (res.ok) {
            filesSynced += 1;
            pagesSynced += res.pages.length;
          }
        }
        return;
      }

      if (stat.isDirectory()) {
        let entries;
        try {
          entries = fs.readdirSync(absTarget, { withFileTypes: true });
        } catch {
          return;
        }
        for (const entry of entries) {
          if (IGNORED_DIRS.has(entry.name)) continue;
          syncTarget(path.join(absTarget, entry.name));
        }
      }
    }

    for (const p of targetPaths) {
      syncTarget(p);
    }

    return okEnvelope(
      'krusch_fs_sync',
      `Synced ${filesSynced} file(s) (${pagesSynced} page(s)) into fs_pages.`,
      {
        files_synced: filesSynced,
        pages_synced: pagesSynced,
        paths: targetPaths.map((p) => String(p))
      },
      true
    );
  }

  /**
   * Hybrid Porter FTS5 + metadata search across indexed OS pages and anchored PageMemory notes,
   * with lazy Top-K `page_text` hydration, optional `limit_tokens` budgeting, and `unattested_query_terms`.
   * @param {object} [params]
   * @param {string} [params.query='']
   * @param {string} [params.category='all']
   * @param {number} [params.limit=10]
   * @param {number} [params.limit_tokens]
   */
  function search({ query = '', category = 'all', limit = 10, limit_tokens } = {}) {
    const countRow = countPagesStmt.get();
    if (!countRow || Number(countRow.cnt) === 0) {
      sync({ paths: [root] });
    }

    const trimmedQuery = String(query ?? '').trim();
    const isWildcard = !trimmedQuery || trimmedQuery === '*';
    const normalizedCat = String(category || 'all').trim().toLowerCase();
    const maxResults =
      Number.isFinite(Number(limit)) && Number(limit) > 0 ? Math.min(50, Number(limit)) : 10;

    const rawTerms = isWildcard
      ? []
      : trimmedQuery
          .toLowerCase()
          .split(/\s+/)
          .map((t) => t.trim())
          .filter((t) => t.length > 0 && t !== '*');

    const termSet = new Set();
    const stemSet = new Set();
    if (!isWildcard) {
      for (const rawTerm of rawTerms) {
        const cleaned = rawTerm.replace(/^[^a-z0-9_.-]+|[^a-z0-9_.-]+$/gi, '').toLowerCase();
        if (cleaned && !STOP_WORDS.has(cleaned)) {
          termSet.add(cleaned);
          if (cleaned.length >= 2) stemSet.add(stemToken(cleaned));
        }
        for (const sub of splitIdentifierSubtokens(rawTerm)) {
          const lowSub = String(sub || '').toLowerCase();
          if (lowSub && !STOP_WORDS.has(lowSub)) {
            termSet.add(lowSub);
            if (lowSub.length >= 2) stemSet.add(stemToken(lowSub));
          }
        }
      }
      for (const sub of splitIdentifierSubtokens(trimmedQuery)) {
        const lowSub = String(sub || '').toLowerCase();
        if (lowSub && !STOP_WORDS.has(lowSub)) {
          termSet.add(lowSub);
          if (lowSub.length >= 2) stemSet.add(stemToken(lowSub));
        }
      }
      if (termSet.size === 0 && rawTerms.length > 0) {
        for (const rawTerm of rawTerms) {
          termSet.add(rawTerm);
          if (rawTerm.length >= 2) stemSet.add(stemToken(rawTerm));
        }
      }
    }
    const terms = [...termSet];

    const allPagesMeta = selectAllPagesMetaStmt.all();
    const allRawMemories = selectAllMemoriesStmt.all();

    const memoryById = new Map();
    const memoriesByPageKey = new Map();
    for (const m of allRawMemories) {
      const memId = Number(m.id);
      const pageNum = Number(m.page_number);
      const memObj = {
        id: memId,
        file_path: m.file_path,
        page_number: pageNum,
        category: m.category,
        note: m.note,
        anchored_page_hash: m.anchored_page_hash
      };
      memoryById.set(memId, memObj);
      const pageKey = `${m.file_path}\0${pageNum}`;
      const list = memoriesByPageKey.get(pageKey);
      if (list) {
        list.push(memObj);
      } else {
        memoriesByPageKey.set(pageKey, [memObj]);
      }
    }

    const ftsPageScores = new Map();
    const ftsMemoryBoostByPageKey = new Map();
    let ftsAvailable = true;

    const ftsQuery = !isWildcard ? buildFts5MatchQuery(trimmedQuery) : null;
    if (ftsQuery) {
      try {
        if (!cachedFtsPagesStmt) {
          cachedFtsPagesStmt = db.prepare(
            'SELECT rowid, bm25(fs_pages_fts, 6.0, 5.0, 3.0) AS rank FROM fs_pages_fts WHERE fs_pages_fts MATCH ? ORDER BY rank ASC'
          );
        }
        const ftsPageRows = cachedFtsPagesStmt.all(ftsQuery);
        for (let idx = 0; idx < ftsPageRows.length; idx += 1) {
          const row = ftsPageRows[idx];
          const rawBm25 = Math.abs(Number(row.rank) || 0);
          const bm25Norm = rawBm25 > 0 ? rawBm25 / (1 + rawBm25) : 0;
          const scoreBoost = 3 + 8 * bm25Norm + 2 * (1 / (1 + idx));
          ftsPageScores.set(Number(row.rowid), scoreBoost);
        }
      } catch {
        ftsAvailable = false;
        cachedFtsPagesStmt = null;
      }

      try {
        if (!cachedFtsMemoriesStmt) {
          cachedFtsMemoriesStmt = db.prepare(
            'SELECT rowid, bm25(fs_page_memories_fts, 2.0, 8.0, 4.0) AS rank FROM fs_page_memories_fts WHERE fs_page_memories_fts MATCH ? ORDER BY rank ASC'
          );
        }
        const ftsMemRows = cachedFtsMemoriesStmt.all(ftsQuery);
        for (let idx = 0; idx < ftsMemRows.length; idx += 1) {
          const row = ftsMemRows[idx];
          const mem = memoryById.get(Number(row.rowid));
          if (!mem) continue;
          const rawBm25 = Math.abs(Number(row.rank) || 0);
          const bm25Norm = rawBm25 > 0 ? rawBm25 / (1 + rawBm25) : 0;
          const memBoost = 4 + 8 * bm25Norm + 2 * (1 / (1 + idx));
          const pageKey = `${mem.file_path}\0${mem.page_number}`;
          ftsMemoryBoostByPageKey.set(
            pageKey,
            (ftsMemoryBoostByPageKey.get(pageKey) || 0) + memBoost
          );
        }
      } catch {
        cachedFtsMemoriesStmt = null;
      }
    }

    const runLikeFallback = () => {
      const fallbackScores = new Map();
      for (const term of terms) {
        if (!term) continue;
        const escaped = term.replace(/[\\%_]/g, '\\$&');
        const rows = likeFallbackPageIdsStmt.all(`%${escaped}%`);
        for (const r of rows) {
          const pid = Number(r.id);
          fallbackScores.set(pid, (fallbackScores.get(pid) || 0) + 3);
        }
      }
      return fallbackScores;
    };

    let likeFallbackScores =
      !isWildcard && !ftsAvailable && terms.length > 0 ? runLikeFallback() : new Map();

    const scoreCandidatePages = (fallbackMap) => {
      const matched = [];
      for (const page of allPagesMeta) {
        const pageId = Number(page.id);
        const pageNum = Number(page.page_number);
        const pageKey = `${page.file_path}\0${pageNum}`;
        const fileCat = classifyFileCategory(page.file_path);
        const rawPageMemories = memoriesByPageKey.get(pageKey) || [];
        const memories = rawPageMemories.map((m) => ({
          id: m.id,
          category: m.category,
          note: m.note,
          anchored_page_hash: m.anchored_page_hash,
          drift_status: m.anchored_page_hash === page.page_hash ? 'VALID' : 'STALE_DRIFT'
        }));

        if (normalizedCat !== 'all') {
          const matchesFileCat = fileCat === normalizedCat;
          const matchesMemCat = memories.some((m) => m.category === normalizedCat);
          if (!matchesFileCat && !matchesMemCat) continue;
        }

        let score = 0;
        if (isWildcard) {
          score = 1;
        } else {
          score += ftsPageScores.get(pageId) || 0;
          score += ftsMemoryBoostByPageKey.get(pageKey) || 0;
          score += fallbackMap.get(pageId) || 0;

          const pathLower = page.file_path.toLowerCase();
          const titleLower = page.section_title.toLowerCase();
          const notesLower = memories.map((m) => m.note.toLowerCase()).join(' ');

          let matchedTitle = false;
          let matchedPath = false;
          let matchedNotes = false;

          for (const term of terms) {
            if (titleLower.includes(term)) {
              score += 6;
              matchedTitle = true;
            }
            if (pathLower.includes(term)) {
              score += 5;
              matchedPath = true;
            }
            if (notesLower.includes(term)) {
              score += 8;
              matchedNotes = true;
            }
          }

          if (stemSet.size > 0) {
            if (!matchedTitle) {
              const titleStems = extractMetadataStems(titleLower);
              for (const st of stemSet) {
                if (titleStems.has(st)) score += 3;
              }
            }
            if (!matchedPath) {
              const pathStems = extractMetadataStems(pathLower);
              for (const st of stemSet) {
                if (pathStems.has(st)) score += 2.5;
              }
            }
            if (!matchedNotes && notesLower) {
              const noteStems = extractMetadataStems(notesLower);
              for (const st of stemSet) {
                if (noteStems.has(st)) score += 4;
              }
            }
          }
        }

        if (score > 0) {
          matched.push({
            id: pageId,
            path: page.file_path,
            file_path: page.file_path,
            page_number: pageNum,
            section_title: page.section_title,
            start_line: Number(page.start_line),
            end_line: Number(page.end_line),
            page_hash: page.page_hash,
            category: fileCat,
            score: Math.round(score * 1000) / 1000,
            memories
          });
        }
      }
      return matched;
    };

    let candidates = scoreCandidatePages(likeFallbackScores);
    if (!isWildcard && candidates.length === 0 && ftsAvailable && terms.length > 0) {
      likeFallbackScores = runLikeFallback();
      if (likeFallbackScores.size > 0) {
        candidates = scoreCandidatePages(likeFallbackScores);
      }
    }

    candidates.sort(
      (a, b) =>
        b.score - a.score ||
        a.file_path.localeCompare(b.file_path) ||
        a.page_number - b.page_number
    );
    const topCandidates = candidates.slice(0, maxResults);

    const queryIdentifiers = !isWildcard ? extractCodeShapeIdentifiers(trimmedQuery) : [];
    const snippetPriorityTerms = [
      ...new Set([
        ...queryIdentifiers.map((id) => id.toLowerCase()),
        ...rawTerms,
        ...terms
      ])
    ];

    // Lazy Top-K page_text hydration: query page_text ONLY for winning Top-K candidates.
    const hydrated = topCandidates.map((cand) => {
      const textRow = selectPageTextByIdStmt.get(cand.id);
      const pageText = String(textRow?.page_text ?? '');
      const snippet = buildPageSnippet(pageText, snippetPriorityTerms, DEFAULT_SNIPPET_MAX_CHARS);
      return {
        path: cand.path,
        file_path: cand.file_path,
        page_number: cand.page_number,
        section_title: cand.section_title,
        start_line: cand.start_line,
        end_line: cand.end_line,
        page_hash: cand.page_hash,
        category: cand.category,
        score: cand.score,
        snippet,
        memories: cand.memories,
        _pageText: pageText
      };
    });

    const hasTokenBudget = Number.isFinite(Number(limit_tokens)) && Number(limit_tokens) > 0;
    const budget = hasTokenBudget ? Math.floor(Number(limit_tokens)) : null;

    const results = [];
    let tokensUsed = 0;

    if (!hasTokenBudget) {
      for (const item of hydrated) {
        const { _pageText, ...publicRow } = item;
        tokensUsed += estimateSearchHitTokens(publicRow);
        results.push(publicRow);
      }
    } else {
      for (let idx = 0; idx < hydrated.length; idx += 1) {
        const item = hydrated[idx];
        const { _pageText: pageText, ...publicRow } = item;
        const fullCost = estimateSearchHitTokens(publicRow);
        const remaining = budget - tokensUsed;

        if (fullCost <= remaining) {
          tokensUsed += fullCost;
          results.push(publicRow);
          continue;
        }

        let trimmedMemories = publicRow.memories;
        const titleCost = estimateTokens(publicRow.section_title || '');
        let memCost = trimmedMemories.reduce((sum, m) => sum + estimateTokens(m.note || ''), 0);

        if (idx === 0 && titleCost + memCost >= remaining) {
          // Ensure at least 1 hit fits cleanly within tight budgets by trimming memory notes if needed
          const memAllowance = Math.max(0, remaining - titleCost - 4);
          let usedMem = 0;
          const fittedMems = [];
          for (const m of trimmedMemories) {
            const c = estimateTokens(m.note || '');
            if (usedMem + c <= memAllowance) {
              fittedMems.push(m);
              usedMem += c;
            } else if (memAllowance - usedMem >= 2) {
              const maxNoteChars = (memAllowance - usedMem) * 4;
              fittedMems.push({ ...m, note: String(m.note || '').slice(0, maxNoteChars) });
              usedMem = memAllowance;
              break;
            }
          }
          trimmedMemories = fittedMems;
          memCost = trimmedMemories.reduce((sum, m) => sum + estimateTokens(m.note || ''), 0);
        }

        const availSnippetTokens = remaining - (titleCost + memCost);
        if (idx === 0) {
          const maxChars = Math.max(0, availSnippetTokens * 4);
          const trimmedSnippet = buildPageSnippet(
            pageText,
            snippetPriorityTerms,
            Math.min(DEFAULT_SNIPPET_MAX_CHARS, maxChars)
          );
          const fittedRow = {
            ...publicRow,
            snippet: trimmedSnippet,
            memories: trimmedMemories
          };
          tokensUsed += estimateSearchHitTokens(fittedRow);
          results.push(fittedRow);
          if (tokensUsed >= budget) break;
        } else if (availSnippetTokens >= 8) {
          const maxChars = Math.min(DEFAULT_SNIPPET_MAX_CHARS, availSnippetTokens * 4);
          const trimmedSnippet = buildPageSnippet(pageText, snippetPriorityTerms, maxChars);
          const fittedRow = {
            ...publicRow,
            snippet: trimmedSnippet,
            memories: trimmedMemories
          };
          tokensUsed += estimateSearchHitTokens(fittedRow);
          results.push(fittedRow);
          break;
        } else {
          break;
        }
      }
    }

    const attestedCorpusLower = results
      .map((r) => {
        const memNotes = Array.isArray(r.memories)
          ? r.memories.map((m) => m.note || '').join('\n')
          : '';
        return `${r.file_path || ''}\n${r.section_title || ''}\n${r.snippet || ''}\n${memNotes}`;
      })
      .join('\n')
      .toLowerCase();

    const unattested_query_terms = [];
    const seenIdents = new Set();
    for (const ident of queryIdentifiers) {
      const rawIdent = String(ident ?? '').trim();
      if (!rawIdent) continue;
      const lowIdent = rawIdent.toLowerCase();
      if (seenIdents.has(lowIdent)) continue;
      seenIdents.add(lowIdent);
      if (!attestedCorpusLower.includes(lowIdent)) {
        unattested_query_terms.push(rawIdent);
      }
    }

    return okEnvelope(
      'krusch_fs_search',
      `Found ${results.length} page hit(s) for query "${trimmedQuery || '*'}".`,
      {
        query: trimmedQuery,
        category: normalizedCat,
        results,
        unattested_query_terms,
        tokens_used: tokensUsed
      },
      true
    );
  }

  return {
    locate,
    search,
    pageTree,
    readPage,
    rememberOnPage,
    sync
  };
}

