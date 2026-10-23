/**
 * @module engines/workspace-engine
 * Workspace Hub & Hybrid RAG (g-krusch) for KruschStack.
 * Enforces INV-14 MIME disambiguation (.md, .gdoc, .gsheet, .slides),
 * stores workspace documents in SQLite (workspace_files), and mirrors under .krusch-stack/workspace/.
 */

import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

const EXTENSION_MIME_MAP = {
  '.md': 'text/markdown',
  '.markdown': 'text/markdown',
  '.gdoc': 'application/vnd.google-apps.document',
  '.gsheet': 'application/vnd.google-apps.spreadsheet',
  '.slides': 'application/vnd.google-apps.presentation',
  '.json': 'application/json',
  '.txt': 'text/plain',
  '.csv': 'text/csv'
};

const DEFAULT_STEERING_CONTENT = `# KruschStack Agent Steering Manifest

1. **Zero-Trust Hydration**: Query Tier 1 working memory before mutating project files.
2. **AST Blast Radius**: Inspect callers and callees via Tier 2A symbol graph prior to signature changes.
3. **Staged 2PC Execution**: Stage edits via Tier 3 harness and verify zero invariant violations before applying diffs.
4. **MIME Disambiguation (INV-14)**: Preserve canonical MIME types for .md, .gdoc, .gsheet, and .slides workspace artifacts.
`;

/**
 * Resolve canonical MIME type per INV-14 based on file extension and optional explicit mime_type.
 * @param {string} filePath
 * @param {string} [explicitMime]
 * @returns {string}
 */
export function resolveWorkspaceMimeType(filePath, explicitMime) {
  const ext = path.extname(String(filePath || '')).toLowerCase();
  if (EXTENSION_MIME_MAP[ext]) {
    return EXTENSION_MIME_MAP[ext];
  }
  if (explicitMime && typeof explicitMime === 'string' && explicitMime.trim()) {
    return explicitMime.trim();
  }
  return 'text/markdown';
}

/**
 * Normalize a workspace-relative path and prevent directory traversal outside .krusch-stack/workspace/.
 * @param {string} mirrorRoot
 * @param {string} candidatePath
 * @returns {{ relPath: string, diskPath: string }}
 */
function resolveSafeWorkspaceMirror(mirrorRoot, candidatePath) {
  const raw = String(candidatePath || '').trim().replace(/^[/\\]+/, '');
  if (!raw) {
    throw new Error('Workspace file path cannot be empty');
  }
  const diskPath = path.resolve(mirrorRoot, raw);
  const relPath = path.relative(mirrorRoot, diskPath);
  if (relPath.startsWith('..') || path.isAbsolute(relPath)) {
    throw new Error(`Workspace path traversal outside mirror directory is forbidden: ${candidatePath}`);
  }
  return {
    relPath: relPath.replace(/\\/g, '/'),
    diskPath
  };
}

/**
 * Create the Workspace Hub & Hybrid RAG Engine.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 */
export function createWorkspaceEngine({ db, workspaceRoot = process.cwd() } = {}) {
  if (!db) {
    throw new Error('createWorkspaceEngine requires a SQLite db instance');
  }

  const rootDir = path.resolve(workspaceRoot);
  const mirrorRoot = path.join(rootDir, '.krusch-stack', 'workspace');

  function persistAndMirror(relPath, content, mimeType) {
    const resolvedMime = resolveWorkspaceMimeType(relPath, mimeType);
    const textContent = String(content ?? '');
    const { relPath: cleanRel, diskPath } = resolveSafeWorkspaceMirror(mirrorRoot, relPath);

    db.prepare(`
      INSERT INTO workspace_files (path, mime_type, content, updated_at)
      VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(path) DO UPDATE SET
        mime_type = excluded.mime_type,
        content = excluded.content,
        updated_at = datetime('now')
    `).run(cleanRel, resolvedMime, textContent);

    fs.mkdirSync(path.dirname(diskPath), { recursive: true });
    fs.writeFileSync(diskPath, textContent, 'utf8');

    return {
      path: cleanRel,
      mime_type: resolvedMime,
      content: textContent,
      mirror_path: diskPath,
      bytes: Buffer.byteLength(textContent, 'utf8')
    };
  }

  /**
   * Retrieve the active agent steering manifest (seeding default STEERING.md if not present).
   */
  function getAgentSteering() {
    let row = db
      .prepare('SELECT path, mime_type, content, updated_at FROM workspace_files WHERE path = ?')
      .get('STEERING.md');

    if (!row) {
      persistAndMirror('STEERING.md', DEFAULT_STEERING_CONTENT, 'text/markdown');
      row = db
        .prepare('SELECT path, mime_type, content, updated_at FROM workspace_files WHERE path = ?')
        .get('STEERING.md');
    }

    return okEnvelope('get_agent_steering', 'Retrieved active workspace agent steering manifest', {
      path: row.path,
      mime_type: row.mime_type,
      content: row.content,
      updated_at: row.updated_at
    });
  }

  /**
   * Write or update a workspace document with INV-14 MIME disambiguation and local mirror sync.
   * @param {object} params
   * @param {string} params.path
   * @param {string} [params.content='']
   * @param {string} [params.mime_type]
   */
  function writeDriveFile({ path: filePath, content = '', mime_type } = {}) {
    try {
      const saved = persistAndMirror(filePath, content, mime_type);
      return okEnvelope(
        'write_drive_file',
        `Saved workspace file '${saved.path}' (${saved.mime_type}, ${saved.bytes} bytes)`,
        saved
      );
    } catch (err) {
      return okEnvelope('write_drive_file', `Failed to write workspace file: ${err.message}`, { error: err.message }, false);
    }
  }

  /**
   * Read a workspace document by relative path from SQLite or mirror directory.
   * @param {object} params
   * @param {string} params.path
   */
  function readDriveFile({ path: filePath } = {}) {
    try {
      const { relPath, diskPath } = resolveSafeWorkspaceMirror(mirrorRoot, filePath);
      let row = db
        .prepare('SELECT path, mime_type, content, updated_at FROM workspace_files WHERE path = ?')
        .get(relPath);

      if (!row && fs.existsSync(diskPath)) {
        const diskText = fs.readFileSync(diskPath, 'utf8');
        persistAndMirror(relPath, diskText);
        row = db
          .prepare('SELECT path, mime_type, content, updated_at FROM workspace_files WHERE path = ?')
          .get(relPath);
      }

      if (!row) {
        return okEnvelope(
          'read_drive_file',
          `Workspace file '${relPath}' not found`,
          { path: relPath, found: false },
          false
        );
      }

      return okEnvelope('read_drive_file', `Read workspace file '${row.path}' (${row.mime_type})`, {
        path: row.path,
        mime_type: row.mime_type,
        content: row.content,
        updated_at: row.updated_at,
        found: true
      });
    } catch (err) {
      return okEnvelope('read_drive_file', `Invalid workspace path: ${err.message}`, { error: err.message }, false);
    }
  }

  /**
   * Hybrid keyword/BM25-style RAG search across workspace_files.
   * @param {object} [params]
   * @param {string} [params.query='']
   * @param {number} [params.limit=10]
   */
  function searchDriveRag({ query = '', limit = 10 } = {}) {
    const rawQuery = String(query || '').trim();
    const maxItems = Math.max(1, Math.min(100, Number(limit) || 10));
    const rows = db
      .prepare('SELECT path, mime_type, content, updated_at FROM workspace_files ORDER BY updated_at DESC, id DESC')
      .all();

    if (!rawQuery || rawQuery === '*') {
      const top = rows.slice(0, maxItems).map((r) => ({
        path: r.path,
        mime_type: r.mime_type,
        score: 1.0,
        snippet: r.content.slice(0, 240),
        updated_at: r.updated_at
      }));
      return okEnvelope('search_drive_rag', `Matched ${top.length} workspace file(s)`, {
        query: rawQuery || '*',
        count: top.length,
        results: top
      });
    }

    const terms = rawQuery
      .toLowerCase()
      .split(/[^a-z0-9_.-]+/)
      .filter(Boolean);

    const scored = [];
    for (const row of rows) {
      const pathLower = row.path.toLowerCase();
      const contentLower = row.content.toLowerCase();
      let score = 0;

      if (pathLower.includes(rawQuery.toLowerCase())) score += 5;
      if (contentLower.includes(rawQuery.toLowerCase())) score += 4;

      for (const term of terms) {
        if (pathLower.includes(term)) score += 2.5;
        if (contentLower.includes(term)) score += 1.5;
      }

      if (score > 0) {
        scored.push({
          path: row.path,
          mime_type: row.mime_type,
          score: Number(score.toFixed(2)),
          snippet: row.content.slice(0, 240),
          updated_at: row.updated_at
        });
      }
    }

    scored.sort((a, b) => b.score - a.score);
    const results = scored.slice(0, maxItems);

    return okEnvelope('search_drive_rag', `Found ${results.length} RAG match(es) for '${rawQuery}'`, {
      query: rawQuery,
      count: results.length,
      results
    });
  }

  /**
   * List files in the workspace hub, optionally scoped to a folder prefix.
   * @param {object} [params]
   * @param {string} [params.folder='']
   */
  function listDriveWorkspace({ folder = '' } = {}) {
    const cleanFolder = String(folder || '')
      .trim()
      .replace(/^[/\\]+|[/\\]+$/g, '')
      .replace(/\\/g, '/');

    const rows = db
      .prepare('SELECT path, mime_type, length(content) AS size_bytes, updated_at FROM workspace_files ORDER BY path ASC')
      .all();

    const filtered = cleanFolder
      ? rows.filter((r) => r.path === cleanFolder || r.path.startsWith(`${cleanFolder}/`))
      : rows;

    return okEnvelope('list_drive_workspace', `Listed ${filtered.length} workspace file(s)`, {
      folder: cleanFolder || '/',
      count: filtered.length,
      files: filtered
    });
  }

  /**
   * Report workspace synchronization and MIME distribution status.
   */
  function getWorkspaceStatus() {
    const rows = db
      .prepare('SELECT mime_type, COUNT(*) AS cnt FROM workspace_files GROUP BY mime_type')
      .all();

    const byMimeType = {};
    let totalFiles = 0;
    for (const r of rows) {
      byMimeType[r.mime_type] = r.cnt;
      totalFiles += r.cnt;
    }

    return okEnvelope('get_workspace_status', `Workspace ready with ${totalFiles} indexed file(s)`, {
      status: 'healthy',
      total_files: totalFiles,
      by_mime_type: byMimeType,
      workspace_dir: mirrorRoot,
      mirror_exists: fs.existsSync(mirrorRoot),
      supported_mime_types: EXTENSION_MIME_MAP
    });
  }

  return {
    getAgentSteering,
    searchDriveRag,
    readDriveFile,
    writeDriveFile,
    listDriveWorkspace,
    getWorkspaceStatus
  };
}
