/**
 * @module engines/fs-engine
 * Tier 2B: OS Filesystem & Page-Anchored Memory Engine (krusch-fs).
 * Splits files into bounded structural pages (~80 lines or Markdown heading boundaries),
 * computes SHA-256 page hashes, and evaluates anchored notes for VALID vs STALE_DRIFT.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

const MAX_LINES_PER_PAGE = 80;

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
  if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.sql', '.sh', '.css', '.html'].includes(ext)) {
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
      section_title: currentTitle || `Page ${rawChunks.length + 1} (L${currentStartLine}-L${endLine})`,
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

  const selectFilePagesStmt = db.prepare(`
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
    WHERE file_path = ?
    ORDER BY page_number ASC
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
   * @param {string} inputPath
   * @returns {{ ok: boolean, absPath: string, keyPath: string, pages: Array<object>, error?: string }}
   */
  function indexFilePages(inputPath) {
    const { absPath, keyPath } = resolveTargetFile(inputPath);
    if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
      return { ok: false, absPath, keyPath, pages: [], error: `File not found: ${inputPath}` };
    }

    const content = fs.readFileSync(absPath, 'utf8');
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

    return { ok: true, absPath, keyPath, pages };
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
    const minSize = Number.isFinite(Number(min_size_bytes)) ? Math.max(0, Number(min_size_bytes)) : 0;
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

    const pageNum = Number.isInteger(Number(page_number)) && Number(page_number) >= 1
      ? Number(page_number)
      : 1;

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
   * @param {object} [params]
   * @param {string} params.path
   * @param {number} [params.page_number=1]
   * @param {string} params.note
   * @param {string} [params.category='annotation']
   */
  function rememberOnPage({ path: targetPath, page_number = 1, note, category = 'annotation' } = {}) {
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

    const indexed = indexFilePages(targetPath);
    if (!indexed.ok) {
      return okEnvelope(
        'krusch_fs_remember_on_page',
        indexed.error,
        { path: String(targetPath), error: 'not_found' },
        false
      );
    }

    const pageNum = Number.isInteger(Number(page_number)) && Number(page_number) >= 1
      ? Number(page_number)
      : 1;

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
        if (TEXT_EXTENSIONS.has(ext) || base === 'dockerfile') {
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
   * Hybrid search across indexed OS pages and anchored PageMemory notes.
   * @param {object} [params]
   * @param {string} [params.query='']
   * @param {string} [params.category='all']
   * @param {number} [params.limit=10]
   */
  function search({ query = '', category = 'all', limit = 10 } = {}) {
    const countRow = db.prepare('SELECT COUNT(*) AS cnt FROM fs_pages').get();
    if (!countRow || Number(countRow.cnt) === 0) {
      sync({ paths: [root] });
    }

    const trimmedQuery = String(query ?? '').trim();
    const normalizedCat = String(category || 'all').trim().toLowerCase();
    const maxResults = Number.isFinite(Number(limit)) && Number(limit) > 0
      ? Math.min(50, Number(limit))
      : 10;

    const terms = trimmedQuery
      .toLowerCase()
      .split(/\s+/)
      .filter((t) => t.length > 0 && t !== '*');

    const allPages = db.prepare(`
      SELECT
        file_path,
        page_number,
        section_title,
        start_line,
        end_line,
        page_hash,
        page_text
      FROM fs_pages
    `).all();

    const results = [];
    for (const page of allPages) {
      const fileCat = classifyFileCategory(page.file_path);
      const memories = selectPageMemoriesStmt.all(page.file_path, page.page_number).map((m) => ({
        id: Number(m.id),
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
      if (terms.length === 0) {
        score = 1;
      } else {
        const pathLower = page.file_path.toLowerCase();
        const titleLower = page.section_title.toLowerCase();
        const textLower = page.page_text.toLowerCase();
        const notesLower = memories.map((m) => m.note.toLowerCase()).join(' ');

        for (const term of terms) {
          if (titleLower.includes(term)) score += 6;
          if (pathLower.includes(term)) score += 5;
          if (notesLower.includes(term)) score += 8;
          if (textLower.includes(term)) score += 3;
        }
      }

      if (score > 0) {
        results.push({
          path: page.file_path,
          file_path: page.file_path,
          page_number: Number(page.page_number),
          section_title: page.section_title,
          start_line: Number(page.start_line),
          end_line: Number(page.end_line),
          page_hash: page.page_hash,
          category: fileCat,
          score,
          snippet: page.page_text.slice(0, 300),
          memories
        });
      }
    }

    results.sort((a, b) => b.score - a.score || a.file_path.localeCompare(b.file_path));
    const sliced = results.slice(0, maxResults);

    return okEnvelope(
      'krusch_fs_search',
      `Found ${sliced.length} page hit(s) for query "${trimmedQuery || '*'}".`,
      {
        query: trimmedQuery,
        category: normalizedCat,
        results: sliced
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
