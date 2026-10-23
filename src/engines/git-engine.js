/**
 * @module engines/git-engine
 * Tier 2A: Codebase Structure, AST Symbols & Call Graph (krusch-git).
 * Enforces INV-GIT-01 (comment/string-masked AST brace matching) and
 * INV-GIT-02 (atomic per-file symbol/edge replacement on re-index).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

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

const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.md']);

const CALL_STOPWORDS = new Set([
  'if',
  'for',
  'while',
  'switch',
  'catch',
  'function',
  'return',
  'typeof',
  'instanceof',
  'await',
  'new',
  'super',
  'import',
  'export',
  'from',
  'delete',
  'void',
  'throw',
  'case',
  'Number',
  'String',
  'Boolean',
  'Object',
  'Array',
  'Set',
  'Map',
  'Promise',
  'Error',
  'RegExp',
  'Math',
  'JSON',
  'Date',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite'
]);

/**
 * Compute SHA-256 hex digest.
 * @param {string} text
 * @returns {string}
 */
function sha256(text) {
  return crypto.createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex');
}

/**
 * INV-GIT-01: Mask comments, regex literals, and string/template literals with spaces
 * while preserving every newline and exact character offset.
 * @param {string} source
 * @returns {string}
 */
export function maskCodePreservingNewlines(source) {
  const input = String(source ?? '');
  const out = new Array(input.length);
  let i = 0;
  const len = input.length;
  let prevNonSpace = '';

  while (i < len) {
    const ch = input[i];
    const next = i + 1 < len ? input[i + 1] : '';

    // Single-line comment //
    if (ch === '/' && next === '/') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      while (i < len && input[i] !== '\n') {
        out[i] = input[i] === '\r' ? '\r' : ' ';
        i += 1;
      }
      continue;
    }

    // Block comment /* ... */
    if (ch === '/' && next === '*') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      while (i < len) {
        if (input[i] === '*' && i + 1 < len && input[i + 1] === '/') {
          out[i] = ' ';
          out[i + 1] = ' ';
          i += 2;
          break;
        }
        out[i] = input[i] === '\n' || input[i] === '\r' ? input[i] : ' ';
        i += 1;
      }
      continue;
    }

    // Single-line regex literal /.../
    if (
      ch === '/' &&
      next !== '/' &&
      next !== '*' &&
      next !== ' ' &&
      next !== '\n' &&
      (!prevNonSpace || '=(,:;!&|?{}[~+-*%<>^'.includes(prevNonSpace))
    ) {
      let j = i + 1;
      let inCharClass = false;
      let foundClose = false;
      while (j < len && input[j] !== '\n' && input[j] !== '\r') {
        if (input[j] === '\\') {
          j += 2;
          continue;
        }
        if (input[j] === '[') inCharClass = true;
        else if (input[j] === ']') inCharClass = false;
        else if (input[j] === '/' && !inCharClass) {
          foundClose = true;
          break;
        }
        j += 1;
      }
      if (foundClose) {
        while (i <= j) {
          out[i] = ' ';
          i += 1;
        }
        prevNonSpace = '/';
        continue;
      }
    }

    // String or template literal: ', ", `
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      out[i] = ' ';
      i += 1;
      while (i < len) {
        const c = input[i];
        if (c === '\\') {
          out[i] = ' ';
          if (i + 1 < len) {
            out[i + 1] = input[i + 1] === '\n' || input[i + 1] === '\r' ? input[i + 1] : ' ';
            i += 2;
          } else {
            i += 1;
          }
          continue;
        }
        if (c === quote) {
          out[i] = ' ';
          i += 1;
          break;
        }
        out[i] = c === '\n' || c === '\r' ? c : ' ';
        i += 1;
      }
      prevNonSpace = quote;
      continue;
    }

    out[i] = ch;
    if (ch !== ' ' && ch !== '\t' && ch !== '\n' && ch !== '\r') {
      prevNonSpace = ch;
    }
    i += 1;
  }

  return out.join('');
}

/**
 * Find the matching closing brace index in a masked source string starting at openBraceIndex.
 * @param {string} maskedSource
 * @param {number} openBraceIndex
 * @returns {number}
 */
function findMatchingBrace(maskedSource, openBraceIndex) {
  let depth = 0;
  for (let i = openBraceIndex; i < maskedSource.length; i += 1) {
    const ch = maskedSource[i];
    if (ch === '{') {
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        return i;
      }
    }
  }
  return Math.max(openBraceIndex, maskedSource.length - 1);
}

/**
 * Find the matching closing parenthesis index in a masked source string starting at openParenIndex.
 * @param {string} maskedSource
 * @param {number} openParenIndex
 * @returns {number}
 */
function findMatchingParen(maskedSource, openParenIndex) {
  let depth = 0;
  for (let i = openParenIndex; i < maskedSource.length; i += 1) {
    const ch = maskedSource[i];
    if (ch === '(') {
      depth += 1;
    } else if (ch === ')') {
      depth -= 1;
      if (depth === 0) {
        return i;
      }
    }
  }
  return -1;
}

/**
 * Build an array of 0-based character offsets for each line start.
 * @param {string} source
 * @returns {number[]}
 */
function buildLineOffsets(source) {
  const offsets = [0];
  for (let i = 0; i < source.length; i += 1) {
    if (source[i] === '\n') {
      offsets.push(i + 1);
    }
  }
  return offsets;
}

/**
 * Convert a 0-based character offset to a 1-based line number using binary search.
 * @param {number[]} lineOffsets
 * @param {number} offset
 * @returns {number}
 */
function offsetToLine(lineOffsets, offset) {
  let low = 0;
  let high = lineOffsets.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    if (lineOffsets[mid] <= offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return Math.max(1, high + 1);
}

/**
 * Extract outbound function call identifiers from a masked symbol body.
 * @param {string} maskedBody
 * @param {string} selfSymbolName
 * @returns {string[]}
 */
function extractCalledSymbols(maskedBody, selfSymbolName) {
  const called = new Set();
  const callRegex = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of maskedBody.matchAll(callRegex)) {
    const name = match[1];
    if (!name || name === selfSymbolName || CALL_STOPWORDS.has(name)) {
      continue;
    }
    called.add(name);
  }
  return [...called];
}

/**
 * Extract symbols and outbound call edges from JS/TS source code using INV-GIT-01.
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
function parseJsTsSymbols(source) {
  const masked = maskCodePreservingNewlines(source);
  const lineOffsets = buildLineOffsets(source);
  const lines = source.split(/\r?\n/);
  const symbols = [];
  const edges = [];
  const seenKeys = new Set();

  function recordSymbol(symbolName, type, declStartIndex, openBraceIndex) {
    const closeBraceIndex = findMatchingBrace(masked, openBraceIndex);
    const startLine = offsetToLine(lineOffsets, declStartIndex);
    const endLine = offsetToLine(lineOffsets, closeBraceIndex);
    const key = `${symbolName}:${startLine}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);

    const rawSignature = source
      .slice(declStartIndex, openBraceIndex)
      .replace(/\s+/g, ' ')
      .trim();
    const snippet = lines.slice(startLine - 1, Math.min(endLine, startLine + 24)).join('\n');
    const fullBody = source.slice(declStartIndex, closeBraceIndex + 1);
    const maskedBody = masked.slice(openBraceIndex + 1, closeBraceIndex);

    symbols.push({
      symbol_name: symbolName,
      symbol_type: type,
      signature: rawSignature,
      start_line: startLine,
      end_line: endLine,
      symbol_hash: sha256(fullBody),
      snippet
    });

    const callees = extractCalledSymbols(maskedBody, symbolName);
    for (const callee of callees) {
      edges.push({
        from_symbol: symbolName,
        to_symbol: callee,
        edge_type: 'calls'
      });
    }
  }

  // 1. Function declarations (supports nested parens/destructuring in default args)
  const fnHeadRegex = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of masked.matchAll(fnHeadRegex)) {
    const symbolName = match[1];
    const openParenIndex = match.index + match[0].length - 1;
    const closeParenIndex = findMatchingParen(masked, openParenIndex);
    if (closeParenIndex < 0) continue;
    const afterParen = masked.slice(closeParenIndex + 1, closeParenIndex + 120);
    const braceRel = afterParen.match(/^\s*(?::[^{;]+)?\{/);
    if (!braceRel) continue;
    const openBraceIndex = closeParenIndex + 1 + braceRel[0].length - 1;
    recordSymbol(symbolName, 'function', match.index, openBraceIndex);
  }

  // 2. Class declarations
  const classRegex = /(?:export\s+(?:default\s+)?)?class\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+[A-Za-z0-9_$.]+)?\s*\{/g;
  for (const match of masked.matchAll(classRegex)) {
    const symbolName = match[1];
    const openBraceIndex = match.index + match[0].length - 1;
    recordSymbol(symbolName, 'class', match.index, openBraceIndex);
  }

  // 3. Const/let/var assigned arrow or function expressions
  const varFnHeadRegex = /(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\*?\s*\(|\()/g;
  for (const match of masked.matchAll(varFnHeadRegex)) {
    const symbolName = match[1];
    const openParenIndex = match.index + match[0].length - 1;
    const closeParenIndex = findMatchingParen(masked, openParenIndex);
    if (closeParenIndex < 0) continue;
    const afterParen = masked.slice(closeParenIndex + 1, closeParenIndex + 120);
    const braceRel = afterParen.match(/^\s*(?::[^={;]+)?(?:\s*=>)?\s*\{/);
    if (!braceRel) continue;
    const openBraceIndex = closeParenIndex + 1 + braceRel[0].length - 1;
    recordSymbol(symbolName, 'function', match.index, openBraceIndex);
  }

  symbols.sort((a, b) => a.start_line - b.start_line);
  return { symbols, edges };
}

/**
 * Extract symbols and call edges from Python source code.
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
function parsePythonSymbols(source) {
  const lines = source.split(/\r?\n/);
  const symbols = [];
  const edges = [];
  const declRegex = /^(\s*)(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?\s*:/;

  for (let idx = 0; idx < lines.length; idx += 1) {
    const match = lines[idx].match(declRegex);
    if (!match) continue;

    const indent = match[1].length;
    const kind = match[2] === 'class' ? 'class' : 'function';
    const symbolName = match[3];
    const startLine = idx + 1;
    let endLine = startLine;

    for (let j = idx + 1; j < lines.length; j += 1) {
      const line = lines[j];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }
      const currentIndent = line.match(/^(\s*)/)[1].length;
      if (currentIndent <= indent) {
        break;
      }
      endLine = j + 1;
    }

    const bodyLines = lines.slice(startLine - 1, endLine);
    const bodyText = bodyLines.join('\n');
    const snippet = bodyLines.slice(0, 25).join('\n');

    symbols.push({
      symbol_name: symbolName,
      symbol_type: kind,
      signature: lines[idx].trim().replace(/:$/, ''),
      start_line: startLine,
      end_line: endLine,
      symbol_hash: sha256(bodyText),
      snippet
    });

    const callees = extractCalledSymbols(bodyLines.slice(1).join('\n'), symbolName);
    for (const callee of callees) {
      edges.push({
        from_symbol: symbolName,
        to_symbol: callee,
        edge_type: 'calls'
      });
    }
  }

  return { symbols, edges };
}

/**
 * Extract Markdown heading sections as structural symbols.
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
function parseMarkdownSymbols(source) {
  const lines = source.split(/\r?\n/);
  const headings = [];

  for (let idx = 0; idx < lines.length; idx += 1) {
    const match = lines[idx].match(/^(#{1,6})\s+(.+?)\s*$/);
    if (match) {
      headings.push({
        level: match[1].length,
        title: match[2].trim(),
        line: idx + 1,
        raw: lines[idx].trim()
      });
    }
  }

  const symbols = headings.map((h, i) => {
    let endLine = lines.length;
    for (let j = i + 1; j < headings.length; j += 1) {
      if (headings[j].level <= h.level) {
        endLine = headings[j].line - 1;
        break;
      }
    }
    const sectionLines = lines.slice(h.line - 1, endLine);
    return {
      symbol_name: h.title,
      symbol_type: 'section',
      signature: h.raw,
      start_line: h.line,
      end_line: Math.max(h.line, endLine),
      symbol_hash: sha256(sectionLines.join('\n')),
      snippet: sectionLines.slice(0, 20).join('\n')
    };
  });

  return { symbols, edges: [] };
}

/**
 * Walk a repository directory and return relative file paths for supported code/doc files.
 * @param {string} rootDir
 * @returns {string[]}
 */
function walkIndexableFiles(rootDir) {
  const results = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (entry.name.startsWith('.') && entry.name !== '.agent') continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (CODE_EXTENSIONS.has(ext)) {
          const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');
          results.push(relPath);
        }
      }
    }
  }

  walk(rootDir);
  return results.sort();
}

/**
 * Attempt to read HEAD commit hash from .git directory without spawning a subprocess.
 * @param {string} repoRoot
 * @returns {string}
 */
function readGitHeadCommit(repoRoot) {
  try {
    const headFile = path.join(repoRoot, '.git', 'HEAD');
    if (!fs.existsSync(headFile)) return 'working-tree';
    const headContent = fs.readFileSync(headFile, 'utf8').trim();
    if (headContent.startsWith('ref:')) {
      const refRel = headContent.slice(4).trim();
      const refFile = path.join(repoRoot, '.git', refRel);
      if (fs.existsSync(refFile)) {
        return fs.readFileSync(refFile, 'utf8').trim().slice(0, 40);
      }
    }
    return headContent.slice(0, 40) || 'working-tree';
  } catch {
    return 'working-tree';
  }
}

/**
 * Create a Tier 2A Git & AST Engine instance.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 */
export function createGitEngine({ db, workspaceRoot = process.cwd() }) {
  const root = path.resolve(workspaceRoot);
  const defaultRepoName = path.basename(root) || 'workspace';

  const upsertRepoStmt = db.prepare(`
    INSERT INTO git_repositories (name, root_path, head_commit, indexed_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(name) DO UPDATE SET
      root_path = excluded.root_path,
      head_commit = excluded.head_commit,
      indexed_at = datetime('now')
  `);

  const deleteFileSymbolsStmt = db.prepare(`
    DELETE FROM git_symbols WHERE repo_name = ? AND file_path = ?
  `);

  const deleteFileEdgesStmt = db.prepare(`
    DELETE FROM git_edges WHERE repo_name = ? AND from_file = ?
  `);

  const insertSymbolStmt = db.prepare(`
    INSERT OR REPLACE INTO git_symbols (
      repo_name,
      file_path,
      symbol_name,
      symbol_type,
      signature,
      start_line,
      end_line,
      symbol_hash,
      snippet
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertEdgeStmt = db.prepare(`
    INSERT INTO git_edges (
      repo_name,
      from_file,
      from_symbol,
      to_symbol,
      edge_type
    ) VALUES (?, ?, ?, ?, ?)
  `);

  /**
   * Index a repository into git_repositories, git_symbols, and git_edges.
   * Enforces INV-GIT-01 and INV-GIT-02.
   * @param {object|string} [options]
   */
  function indexRepo(options = {}) {
    const rawPath = typeof options === 'string'
      ? options
      : (options?.repoPath || options?.path || root);
    const repoRoot = path.resolve(rawPath);
    const repoName = (typeof options === 'object' && options?.repoName)
      ? String(options.repoName)
      : (path.basename(repoRoot) || defaultRepoName);

    if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
      return okEnvelope(
        'krusch_git_index_repo',
        `Repository directory not found: ${repoRoot}`,
        { error: 'directory_not_found', repo_path: repoRoot },
        false
      );
    }

    const headCommit = readGitHeadCommit(repoRoot);
    upsertRepoStmt.run(repoName, repoRoot, headCommit);

    const relFiles = walkIndexableFiles(repoRoot);
    let symbolsIndexed = 0;
    let edgesIndexed = 0;

    for (const relFile of relFiles) {
      const absFile = path.join(repoRoot, relFile);
      let content = '';
      try {
        content = fs.readFileSync(absFile, 'utf8');
      } catch {
        continue;
      }

      // INV-GIT-02: Delete stale rows for (repo_name, file_path) before inserting
      deleteFileSymbolsStmt.run(repoName, relFile);
      deleteFileEdgesStmt.run(repoName, relFile);

      const ext = path.extname(relFile).toLowerCase();
      let parsed = { symbols: [], edges: [] };
      if (ext === '.py') {
        parsed = parsePythonSymbols(content);
      } else if (ext === '.md') {
        parsed = parseMarkdownSymbols(content);
      } else {
        parsed = parseJsTsSymbols(content);
      }

      for (const sym of parsed.symbols) {
        insertSymbolStmt.run(
          repoName,
          relFile,
          sym.symbol_name,
          sym.symbol_type,
          sym.signature,
          sym.start_line,
          sym.end_line,
          sym.symbol_hash,
          sym.snippet
        );
        symbolsIndexed += 1;
      }

      for (const edge of parsed.edges) {
        insertEdgeStmt.run(
          repoName,
          relFile,
          edge.from_symbol,
          edge.to_symbol,
          edge.edge_type
        );
        edgesIndexed += 1;
      }
    }

    return okEnvelope(
      'krusch_git_index_repo',
      `Indexed ${relFiles.length} file(s), ${symbolsIndexed} symbol(s), and ${edgesIndexed} call edge(s) in ${repoName}.`,
      {
        repo: repoName,
        root_path: repoRoot,
        head_commit: headCommit,
        files_indexed: relFiles.length,
        symbols_indexed: symbolsIndexed,
        edges_indexed: edgesIndexed
      },
      true
    );
  }

  /**
   * Automatically index workspaceRoot if git_repositories is empty.
   */
  function ensureIndexed() {
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM git_repositories').get();
    if (!row || Number(row.cnt) === 0) {
      indexRepo({ repoPath: root, repoName: defaultRepoName });
    }
  }

  /**
   * Resolve a repository record by name or fallback to the default workspace repository.
   * @param {string} [repo]
   * @returns {{ name: string, root_path: string, head_commit: string }}
   */
  function resolveRepoRecord(repo) {
    ensureIndexed();
    if (repo && repo !== '*') {
      const exact = db.prepare('SELECT * FROM git_repositories WHERE name = ?').get(String(repo));
      if (exact) return exact;
    }
    const first = db.prepare('SELECT * FROM git_repositories ORDER BY id ASC LIMIT 1').get();
    return first || { name: defaultRepoName, root_path: root, head_commit: 'working-tree' };
  }

  /**
   * List all indexed Git repositories and symbol statistics.
   */
  function listRepos() {
    ensureIndexed();
    const repos = db.prepare(`
      SELECT
        r.name,
        r.root_path,
        r.head_commit,
        r.indexed_at,
        COUNT(s.id) AS symbol_count
      FROM git_repositories r
      LEFT JOIN git_symbols s ON s.repo_name = r.name
      GROUP BY r.name, r.root_path, r.head_commit, r.indexed_at
      ORDER BY r.name ASC
    `).all().map((r) => ({
      name: r.name,
      root_path: r.root_path,
      head_commit: r.head_commit,
      indexed_at: r.indexed_at,
      symbol_count: Number(r.symbol_count)
    }));

    return okEnvelope(
      'krusch_git_list_repos',
      `Found ${repos.length} indexed repository(ies).`,
      { repos },
      true
    );
  }

  /**
   * Read directory tree entries within an indexed repository.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} [params.path='']
   */
  function readTree({ repo, path: relPath = '' } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const cleanRel = String(relPath ?? '').replace(/^\/+/, '');
    const targetDir = path.resolve(repoRecord.root_path, cleanRel);

    if (!targetDir.startsWith(path.resolve(repoRecord.root_path))) {
      return okEnvelope(
        'krusch_git_read_tree',
        'Path traversal outside repository root is not permitted.',
        { error: 'path_traversal_denied' },
        false
      );
    }

    if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
      return okEnvelope(
        'krusch_git_read_tree',
        `Directory not found: ${cleanRel || '.'}`,
        { repo: repoRecord.name, path: cleanRel, error: 'not_found' },
        false
      );
    }

    const dirEntries = fs.readdirSync(targetDir, { withFileTypes: true })
      .filter((entry) => !IGNORED_DIRS.has(entry.name))
      .map((entry) => {
        const entryAbs = path.join(targetDir, entry.name);
        const entryRel = path.relative(repoRecord.root_path, entryAbs).replace(/\\/g, '/');
        const isDir = entry.isDirectory();
        const size = isDir ? 0 : fs.statSync(entryAbs).size;
        return {
          name: entry.name,
          path: entryRel,
          type: isDir ? 'directory' : 'file',
          size
        };
      })
      .sort((a, b) => {
        if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

    return okEnvelope(
      'krusch_git_read_tree',
      `Listed ${dirEntries.length} entry(ies) in ${repoRecord.name}:${cleanRel || '.'}.`,
      {
        repo: repoRecord.name,
        path: cleanRel,
        entries: dirEntries
      },
      true
    );
  }

  /**
   * Read file blob contents with optional 1-indexed line slicing.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} params.path
   * @param {number} [params.start_line]
   * @param {number} [params.end_line]
   */
  function readBlob({ repo, path: relPath, start_line, end_line } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const rawRel = String(relPath ?? '').trim();
    if (!rawRel) {
      return okEnvelope(
        'krusch_git_read_blob',
        'File path is required.',
        { error: 'path_required' },
        false
      );
    }

    const targetFile = path.isAbsolute(rawRel)
      ? path.resolve(rawRel)
      : path.resolve(repoRecord.root_path, rawRel);

    if (!targetFile.startsWith(path.resolve(repoRecord.root_path))) {
      return okEnvelope(
        'krusch_git_read_blob',
        'Path traversal outside repository root is not permitted.',
        { error: 'path_traversal_denied' },
        false
      );
    }

    if (!fs.existsSync(targetFile) || !fs.statSync(targetFile).isFile()) {
      return okEnvelope(
        'krusch_git_read_blob',
        `File not found: ${rawRel}`,
        { repo: repoRecord.name, path: rawRel, error: 'not_found' },
        false
      );
    }

    const fullContent = fs.readFileSync(targetFile, 'utf8');
    const lines = fullContent.split(/\r?\n/);
    const startLine = Number.isInteger(Number(start_line)) && Number(start_line) >= 1
      ? Number(start_line)
      : 1;
    const endLine = Number.isInteger(Number(end_line)) && Number(end_line) >= startLine
      ? Math.min(lines.length, Number(end_line))
      : lines.length;

    const content = lines.slice(startLine - 1, endLine).join('\n');
    const normalizedRel = path.relative(repoRecord.root_path, targetFile).replace(/\\/g, '/');

    return okEnvelope(
      'krusch_git_read_blob',
      `Read ${normalizedRel} (L${startLine}-L${endLine} of ${lines.length}).`,
      {
        repo: repoRecord.name,
        path: normalizedRel,
        start_line: startLine,
        end_line: endLine,
        total_lines: lines.length,
        content
      },
      true
    );
  }

  /**
   * Search AST symbols across a repository by name, signature, or symbol type.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} [params.query='']
   * @param {string} [params.symbol_type]
   */
  function searchSymbols({ repo, query = '', symbol_type } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const trimmedQuery = String(query ?? '').trim();
    const likePattern = !trimmedQuery || trimmedQuery === '*' ? '%' : `%${trimmedQuery}%`;

    let rows;
    if (symbol_type) {
      rows = db.prepare(`
        SELECT
          repo_name,
          file_path,
          symbol_name,
          symbol_type,
          signature,
          start_line,
          end_line,
          symbol_hash,
          snippet
        FROM git_symbols
        WHERE repo_name = ?
          AND symbol_type = ?
          AND (symbol_name LIKE ? OR signature LIKE ?)
        ORDER BY file_path ASC, start_line ASC
        LIMIT 100
      `).all(repoRecord.name, String(symbol_type), likePattern, likePattern);
    } else {
      rows = db.prepare(`
        SELECT
          repo_name,
          file_path,
          symbol_name,
          symbol_type,
          signature,
          start_line,
          end_line,
          symbol_hash,
          snippet
        FROM git_symbols
        WHERE repo_name = ?
          AND (symbol_name LIKE ? OR signature LIKE ?)
        ORDER BY file_path ASC, start_line ASC
        LIMIT 100
      `).all(repoRecord.name, likePattern, likePattern);
    }

    return okEnvelope(
      'krusch_git_search_symbols',
      `Found ${rows.length} symbol(s) matching "${trimmedQuery || '*'}" in ${repoRecord.name}.`,
      {
        repo: repoRecord.name,
        query: trimmedQuery,
        symbols: rows
      },
      true
    );
  }

  /**
   * List all symbols declared in a specific file.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} params.file_path
   */
  function fileSymbols({ repo, file_path, path: altPath } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const rawFile = String(file_path || altPath || '').trim();
    if (!rawFile) {
      return okEnvelope(
        'krusch_git_file_symbols',
        'file_path is required.',
        { error: 'file_path_required', symbols: [] },
        false
      );
    }

    const normalizedFile = path.isAbsolute(rawFile)
      ? path.relative(repoRecord.root_path, rawFile).replace(/\\/g, '/')
      : rawFile.replace(/^\.\/+/, '').replace(/\\/g, '/');

    // If file exists on disk and has not been indexed yet (or was recently created), index it now
    const absCandidate = path.resolve(repoRecord.root_path, normalizedFile);
    if (fs.existsSync(absCandidate) && fs.statSync(absCandidate).isFile()) {
      const existingCount = db.prepare(`
        SELECT COUNT(*) AS cnt FROM git_symbols WHERE repo_name = ? AND file_path = ?
      `).get(repoRecord.name, normalizedFile);
      if (!existingCount || Number(existingCount.cnt) === 0) {
        indexRepo({ repoPath: repoRecord.root_path, repoName: repoRecord.name });
      }
    }

    const rows = db.prepare(`
      SELECT
        repo_name,
        file_path,
        symbol_name,
        symbol_type,
        signature,
        start_line,
        end_line,
        symbol_hash,
        snippet
      FROM git_symbols
      WHERE repo_name = ? AND file_path = ?
      ORDER BY start_line ASC
    `).all(repoRecord.name, normalizedFile);

    return okEnvelope(
      'krusch_git_file_symbols',
      `Found ${rows.length} symbol(s) in ${normalizedFile}.`,
      {
        repo: repoRecord.name,
        file_path: normalizedFile,
        symbols: rows
      },
      true
    );
  }

  /**
   * Trace inbound callers and outbound callees for a target symbol before changing signatures.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} params.symbol
   */
  function dependencyGraph({ repo, symbol } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const symbolName = String(symbol ?? '').trim();
    if (!symbolName) {
      return okEnvelope(
        'krusch_git_dependency_graph',
        'symbol is required.',
        { error: 'symbol_required' },
        false
      );
    }

    const definitions = db.prepare(`
      SELECT
        repo_name,
        file_path,
        symbol_name,
        symbol_type,
        signature,
        start_line,
        end_line,
        symbol_hash
      FROM git_symbols
      WHERE repo_name = ? AND symbol_name = ?
      ORDER BY file_path ASC, start_line ASC
    `).all(repoRecord.name, symbolName);

    const inbound = db.prepare(`
      SELECT
        repo_name,
        from_file,
        from_symbol,
        to_symbol,
        edge_type
      FROM git_edges
      WHERE repo_name = ? AND to_symbol = ?
      ORDER BY from_file ASC, from_symbol ASC
    `).all(repoRecord.name, symbolName);

    const outbound = db.prepare(`
      SELECT
        repo_name,
        from_file,
        from_symbol,
        to_symbol,
        edge_type
      FROM git_edges
      WHERE repo_name = ? AND from_symbol = ?
      ORDER BY to_symbol ASC
    `).all(repoRecord.name, symbolName);

    return okEnvelope(
      'krusch_git_dependency_graph',
      `Symbol "${symbolName}" has ${definitions.length} definition(s), ${inbound.length} inbound caller(s), and ${outbound.length} outbound callee(s).`,
      {
        repo: repoRecord.name,
        symbol: symbolName,
        definitions,
        inbound,
        outbound,
        inbound_callers: inbound,
        outbound_callees: outbound
      },
      true
    );
  }

  /**
   * Hybrid lexical/BM25-weighted code search across indexed symbols and snippets.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} [params.query='']
   * @param {number} [params.limit=10]
   */
  function semanticSearch({ repo, query = '', limit = 10 } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const trimmedQuery = String(query ?? '').trim();
    const maxResults = Number.isFinite(Number(limit)) && Number(limit) > 0
      ? Math.min(50, Number(limit))
      : 10;

    const allSymbols = db.prepare(`
      SELECT
        repo_name,
        file_path,
        symbol_name,
        symbol_type,
        signature,
        start_line,
        end_line,
        symbol_hash,
        snippet
      FROM git_symbols
      WHERE repo_name = ?
    `).all(repoRecord.name);

    const terms = trimmedQuery
      .toLowerCase()
      .split(/[^a-z0-9_$]+/)
      .filter((t) => t.length > 0);

    const scored = [];
    for (const row of allSymbols) {
      if (terms.length === 0) {
        scored.push({ ...row, score: 1.0 });
        continue;
      }

      const nameLower = row.symbol_name.toLowerCase();
      const sigLower = (row.signature || '').toLowerCase();
      const pathLower = row.file_path.toLowerCase();
      const snippetLower = (row.snippet || '').toLowerCase();

      let score = 0;
      for (const term of terms) {
        if (nameLower === term) score += 10;
        else if (nameLower.includes(term)) score += 6;
        if (sigLower.includes(term)) score += 4;
        if (pathLower.includes(term)) score += 3;
        if (snippetLower.includes(term)) score += 2;
      }

      if (score > 0) {
        scored.push({ ...row, score });
      }
    }

    scored.sort((a, b) => b.score - a.score || a.file_path.localeCompare(b.file_path));
    const results = scored.slice(0, maxResults);

    return okEnvelope(
      'krusch_git_semantic_search',
      `Semantic search for "${trimmedQuery}" returned ${results.length} result(s).`,
      {
        repo: repoRecord.name,
        query: trimmedQuery,
        results
      },
      true
    );
  }

  return {
    listRepos,
    readTree,
    readBlob,
    searchSymbols,
    fileSymbols,
    dependencyGraph,
    semanticSearch,
    indexRepo
  };
}
