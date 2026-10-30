/**
 * @module engines/harness-engine
 * Tier 3: 2PC Staged Execution Harness (krusch-harness) for KruschStack.
 * Enforces INV-STACK-02 (okEnvelope), INV-STACK-04 (sanitized public defaults),
 * and INV-STACK-06 (stage unified diffs in SQLite and verify invariants before touching disk).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

/**
 * Compute a deterministic unified diff between two text blobs for a relative file path.
 * @param {string} relPath
 * @param {string} beforeText
 * @param {string} afterText
 * @param {boolean} existedBefore
 * @returns {string}
 */
function buildUnifiedDiff(relPath, beforeText, afterText, existedBefore) {
  const normalizedRel = relPath.replace(/\\/g, '/');
  const beforeLines = existedBefore ? beforeText.split('\n') : [];
  const afterLines = afterText.split('\n');

  if (existedBefore && beforeText === afterText) {
    return '';
  }

  const headerA = existedBefore ? `a/${normalizedRel}` : '/dev/null';
  const headerB = `b/${normalizedRel}`;

  let prefixLen = 0;
  const minLen = Math.min(beforeLines.length, afterLines.length);
  while (prefixLen < minLen && beforeLines[prefixLen] === afterLines[prefixLen]) {
    prefixLen++;
  }

  let suffixLen = 0;
  while (
    suffixLen < beforeLines.length - prefixLen &&
    suffixLen < afterLines.length - prefixLen &&
    beforeLines[beforeLines.length - 1 - suffixLen] === afterLines[afterLines.length - 1 - suffixLen]
  ) {
    suffixLen++;
  }

  const contextStart = Math.max(0, prefixLen - 2);
  const beforeEnd = Math.min(beforeLines.length, beforeLines.length - suffixLen + 2);
  const afterEnd = Math.min(afterLines.length, afterLines.length - suffixLen + 2);

  const oldStart = existedBefore ? contextStart + 1 : 0;
  const oldCount = existedBefore ? beforeEnd - contextStart : 0;
  const newStart = contextStart + 1;
  const newCount = afterEnd - contextStart;

  const hunkLines = [];
  for (let i = contextStart; i < prefixLen; i++) {
    hunkLines.push(` ${beforeLines[i]}`);
  }
  for (let i = prefixLen; i < beforeLines.length - suffixLen; i++) {
    hunkLines.push(`-${beforeLines[i]}`);
  }
  for (let i = prefixLen; i < afterLines.length - suffixLen; i++) {
    hunkLines.push(`+${afterLines[i]}`);
  }
  const trailingStart = afterLines.length - suffixLen;
  for (let i = trailingStart; i < afterEnd; i++) {
    hunkLines.push(` ${afterLines[i]}`);
  }

  return [
    `--- ${headerA}`,
    `+++ ${headerB}`,
    `@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`,
    ...hunkLines
  ].join('\n');
}

/**
 * Resolve a relative file path safely within workspaceRoot, throwing on traversal outside root.
 * @param {string} workspaceRoot
 * @param {string} candidatePath
 * @returns {{ absPath: string, relPath: string }}
 */
function resolveSafeWorkspacePath(workspaceRoot, candidatePath) {
  const root = path.resolve(workspaceRoot);
  const raw = String(candidatePath || '').trim();
  if (!raw) {
    throw new Error('File path cannot be empty');
  }
  const absPath = path.resolve(root, raw);
  const relPath = path.relative(root, absPath);
  if (relPath.startsWith('..') || path.isAbsolute(relPath)) {
    throw new Error(`Path traversal outside workspaceRoot is forbidden: ${raw}`);
  }
  return { absPath, relPath: relPath.replace(/\\/g, '/') };
}

/**
 * Normalize proposed edits and files into a canonical list of { file_path, content } objects.
 * @param {Array} edits
 * @param {Array} files
 * @returns {Array<{ file_path: string, content: string, hasContent: boolean }>}
 */
function normalizeStagedEdits(edits = [], files = []) {
  const combined = [];
  const sourceList = Array.isArray(edits) && edits.length > 0 ? edits : [];
  for (const item of sourceList) {
    if (item && typeof item === 'object') {
      const filePath = item.file_path || item.path || '';
      const hasContent = typeof item.content === 'string';
      combined.push({
        file_path: String(filePath).trim(),
        content: hasContent ? item.content : '',
        hasContent
      });
    }
  }

  if (Array.isArray(files)) {
    for (const item of files) {
      if (typeof item === 'string') {
        const trimmed = item.trim();
        if (trimmed && !combined.some((e) => e.file_path === trimmed)) {
          combined.push({ file_path: trimmed, content: '', hasContent: false });
        }
      } else if (item && typeof item === 'object') {
        const filePath = String(item.file_path || item.path || '').trim();
        const hasContent = typeof item.content === 'string';
        if (filePath && !combined.some((e) => e.file_path === filePath)) {
          combined.push({
            file_path: filePath,
            content: hasContent ? item.content : '',
            hasContent
          });
        }
      }
    }
  }

  return combined;
}

const IGNORED_DIR_FSYNC_CODES = new Set(['EINVAL', 'EBADF', 'EISDIR', 'ENOTSUP', 'EPERM']);

/**
 * Compute SHA-256 hex digest of a UTF-8 string.
 * @param {string} str
 * @returns {string}
 */
function sha256Text(str) {
  return crypto.createHash('sha256').update(String(str ?? ''), 'utf8').digest('hex');
}

/**
 * Flush parent directory metadata after renameSync or unlinkSync (INV-REC-03).
 * Tolerates filesystems/platforms that disallow directory fsync while propagating I/O faults.
 * @param {string} dirPath
 * @param {typeof fs} [fsImpl=fs]
 */
export function fsyncDirectory(dirPath, fsImpl = fs) {
  let fd = null;
  try {
    fd = fsImpl.openSync(dirPath, 'r');
    fsImpl.fsyncSync(fd);
  } catch (err) {
    if (!IGNORED_DIR_FSYNC_CODES.has(err?.code)) {
      throw err;
    }
  } finally {
    if (fd !== null) {
      try {
        fsImpl.closeSync(fd);
      } catch (closeErr) {
        /* ignore directory fd close error */
      }
    }
  }
}

/**
 * Write full UTF-8 buffer to an open file descriptor, handling partial writes.
 * @param {number} fd
 * @param {string} content
 * @param {typeof fs} fsImpl
 */
function writeAllSync(fd, content, fsImpl) {
  const buf = Buffer.from(String(content ?? ''), 'utf8');
  if (buf.length === 0) {
    fsImpl.writeSync(fd, buf, 0, 0);
    return;
  }
  let offset = 0;
  while (offset < buf.length) {
    const written = fsImpl.writeSync(fd, buf, offset, buf.length - offset);
    if (typeof written !== 'number' || written <= 0) {
      const shortErr = new Error('Short or zero-byte writeSync while staging temporary file');
      shortErr.code = 'EIO';
      throw shortErr;
    }
    offset += written;
  }
}

/**
 * Atomically stage and fsync a sibling temporary file before renameSync (INV-REC-03).
 * Closes fd in finally and unlinks partial temp file on write/fsync/close failure.
 * @param {string} absPath
 * @param {string} content
 * @param {typeof fs} [fsImpl=fs]
 * @returns {string}
 */
function atomicWriteTempFile(absPath, content, fsImpl = fs) {
  const dirPath = path.dirname(absPath);
  const baseName = path.basename(absPath);
  fsImpl.mkdirSync(dirPath, { recursive: true });
  const rand = crypto.randomBytes(6).toString('hex');
  const tempPath = path.join(dirPath, `.${baseName}.krusch-tmp-${process.pid}-${rand}`);

  let fd = null;
  let succeeded = false;
  try {
    fd = fsImpl.openSync(tempPath, 'w', 0o600);
    writeAllSync(fd, content, fsImpl);
    fsImpl.fsyncSync(fd);
    succeeded = true;
    return tempPath;
  } finally {
    let closeErr = null;
    if (fd !== null) {
      try {
        fsImpl.closeSync(fd);
      } catch (err) {
        closeErr = err;
      }
    }
      if (!succeeded || closeErr) {
        unlinkBestEffort(tempPath, fsImpl);
      }
      if (succeeded && closeErr) {
        throw closeErr;
      }
    }
  }

/**
 * Read a UTF-8 file without `fs.existsSync` so non-ENOENT OS faults (EIO, EACCES, ENOMEM, EMFILE)
 * propagate to compound-recovery handlers instead of silently masquerading as missing files.
 * @param {string} absPath
 * @param {typeof fs} [fsImpl=fs]
 * @returns {{ exists: boolean, content: string | null }}
 */
function readTextIfExists(absPath, fsImpl = fs) {
  try {
    const content = fsImpl.readFileSync(absPath, 'utf8');
    return { exists: true, content };
  } catch (err) {
    if (err?.code === 'ENOENT') {
      return { exists: false, content: null };
    }
    throw err;
  }
}

/**
 * Best-effort unlink for unrenamed sibling temporary files without `existsSync`.
 * @param {string} filePath
 * @param {typeof fs} [fsImpl=fs]
 */
function unlinkBestEffort(filePath, fsImpl = fs) {
  try {
    fsImpl.unlinkSync(filePath);
  } catch (unlinkErr) {
    /* best-effort cleanup of unrenamed temporary file */
  }
}

/**
 * Crash-atomically restore a file's preimage via temp write + fsync + rename + directory fsync.
 * @param {string} absPath
 * @param {string} baseContent
 * @param {typeof fs} [fsImpl=fs]
 */
function atomicRestoreFile(absPath, baseContent, fsImpl = fs) {
  const dirPath = path.dirname(absPath);
  const tempPath = atomicWriteTempFile(absPath, baseContent, fsImpl);
  try {
    fsImpl.renameSync(tempPath, absPath);
  } catch (renameErr) {
    unlinkBestEffort(tempPath, fsImpl);
    throw renameErr;
  }
  fsyncDirectory(dirPath, fsImpl);
}

/**
 * Remove leftover sibling `.${basename}.krusch-tmp-*` files in parent directory.
 * @param {string} absPath
 * @param {typeof fs} [fsImpl=fs]
 */
function cleanOrphanedTempFiles(absPath, fsImpl = fs) {
  const dirPath = path.dirname(absPath);
  const baseName = path.basename(absPath);
  const prefix = `.${baseName}.krusch-tmp-`;
  let entries = [];
  try {
    entries = fsImpl.readdirSync(dirPath);
  } catch (err) {
    if (err?.code === 'ENOENT') {
      return;
    }
    throw err;
  }
  for (const entry of entries) {
    const entryName = typeof entry === 'string' ? entry : entry?.name;
    if (entryName && entryName.startsWith(prefix)) {
      try {
        fsImpl.unlinkSync(path.join(dirPath, entryName));
      } catch (unlinkErr) {
        if (unlinkErr?.code !== 'ENOENT') {
          throw unlinkErr;
        }
      }
    }
  }
}

/**
 * Execute a synchronous callback inside an atomic SQLite `BEGIN IMMEDIATE ... COMMIT` block.
 * Safely issues `ROLLBACK` if body or `COMMIT` throws so the connection is never left wedged.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {() => any} fn
 */
function runInTransaction(db, fn) {
  let began = false;
  db.exec('BEGIN IMMEDIATE;');
  began = true;
  try {
    const result = fn();
    db.exec('COMMIT;');
    began = false;
    return result;
  } catch (err) {
    if (began) {
      try {
        db.exec('ROLLBACK;');
      } catch (rollbackErr) {
        const rbMsg = String(rollbackErr?.message || '');
        if (!/no transaction is active/i.test(rbMsg) && err && typeof err === 'object') {
          err.rollbackError = rollbackErr;
        }
      }
    }
    throw err;
  }
}

/**
 * Create the Tier 3 2PC Staged Execution Harness engine.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 * @param {object} [options.contextEngine]
 * @param {typeof fs} [options.fsOps]
 */
export function createHarnessEngine({
  db,
  workspaceRoot = process.cwd(),
  contextEngine,
  fsOps = fs
} = {}) {
  if (!db) {
    throw new Error('createHarnessEngine requires a SQLite db instance');
  }
  const fsImpl = fsOps || fs;
  const rootDir = path.resolve(workspaceRoot);

  db.exec(`
    CREATE TABLE IF NOT EXISTS harness_apply_journal (
      task_id TEXT PRIMARY KEY,
      state TEXT NOT NULL CHECK(state IN ('APPLYING', 'APPLIED', 'ROLLED_BACK', 'RECOVERY_PENDING')),
      entries_json TEXT NOT NULL DEFAULT '[]',
      last_error TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  /**
   * Stage a task in the 2PC harness without modifying the working tree (INV-STACK-06).
   * @param {object} params
   * @param {string} params.goal
   * @param {Array<{file_path: string, content: string}>} [params.edits]
   * @param {Array<string|{file_path: string, content?: string}>} [params.files]
   * @param {string} [params.test_command]
   * @param {string} [params.task_id]
   */
  function run({ goal = '', edits = [], files = [], test_command, task_id } = {}) {
    const cleanGoal = String(goal || '').trim();
    if (!cleanGoal) {
      return okEnvelope('krusch_run', 'Goal is required to stage a harness task', { error: 'Missing goal' }, false);
    }

    let normalizedEdits;
    const diffChunks = [];
    const stagedRecords = [];

    try {
      normalizedEdits = normalizeStagedEdits(edits, files);
      for (const edit of normalizedEdits) {
        const { absPath, relPath } = resolveSafeWorkspacePath(rootDir, edit.file_path);
        const { exists: existed, content: rawBeforeText } = readTextIfExists(absPath, fsImpl);
        const beforeText = existed ? rawBeforeText : '';
        const afterText = edit.hasContent ? edit.content : beforeText;

        const fileDiff = edit.hasContent
          ? buildUnifiedDiff(relPath, beforeText, afterText, existed)
          : `--- a/${relPath}\n+++ b/${relPath}\n@@ -1,0 +1,0 @@\n # staged file reference: ${relPath}`;

        if (fileDiff) {
          diffChunks.push(fileDiff);
        }
        stagedRecords.push({
          file_path: relPath,
          content: afterText,
          has_content: edit.hasContent,
          existed_before: existed,
          base_sha256: existed ? sha256Text(beforeText) : null,
          staged_sha256: edit.hasContent ? sha256Text(afterText) : null
        });
      }
    } catch (err) {
      return okEnvelope('krusch_run', `Failed to stage edits: ${err.message}`, { error: err.message }, false);
    }

    const unifiedDiff = diffChunks.join('\n\n');
    const hashInput = JSON.stringify({
      goal: cleanGoal,
      staged: stagedRecords.map((r) => ({ file_path: r.file_path, content: r.content }))
    });
    const taskId =
      typeof task_id === 'string' && task_id.trim()
        ? task_id.trim()
        : `task-${crypto.createHash('sha256').update(hashInput).digest('hex').slice(0, 12)}`;

    let findings = [];
    if (contextEngine && typeof contextEngine.nudge === 'function') {
      const nudgeRes = contextEngine.nudge({
        trigger: 'pre_commit',
        code: unifiedDiff || cleanGoal
      });
      const extracted =
        nudgeRes?.data?.findings ||
        nudgeRes?.data?.violations ||
        nudgeRes?.findings ||
        [];
      if (Array.isArray(extracted)) {
        findings = extracted;
      }
    } else {
      // Fallback invariant check against context_memories if contextEngine is not wired
      const activeInvariants = db
        .prepare("SELECT id, content FROM context_memories WHERE status = 'active' AND category = 'invariant'")
        .all();
      const addedLines = unifiedDiff
        .split('\n')
        .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
        .join('\n');

      const rfc1918Pattern = new RegExp(
        ['192', '168', '\\d+', '\\d+'].join('\\.') +
          '|' +
          ['10', '10', '10', '\\d+'].join('\\.')
      );
      for (const inv of activeInvariants) {
        if (
          rfc1918Pattern.test(addedLines) &&
          /IP|sanitize|INV-STACK-04|hostname/i.test(inv.content)
        ) {
          findings.push({
            invariant_id: inv.id,
            severity: 'error',
            message: `Staged diff violates invariant #${inv.id}: ${inv.content}`
          });
        }
      }
    }

    const status = findings.length > 0 ? 'BLOCKED_INVARIANT' : 'STAGED';
    const explanation =
      status === 'BLOCKED_INVARIANT'
        ? `Task blocked by ${findings.length} invariant violation(s) during pre-commit gate.`
        : `Task staged cleanly with ${stagedRecords.length} file(s) ready for atomic apply.`;

    db.prepare(`
      INSERT INTO harness_tasks (
        task_id, goal, status, unified_diff, files_json, invariant_findings_json, explanation, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      ON CONFLICT(task_id) DO UPDATE SET
        goal = excluded.goal,
        status = excluded.status,
        unified_diff = excluded.unified_diff,
        files_json = excluded.files_json,
        invariant_findings_json = excluded.invariant_findings_json,
        explanation = excluded.explanation,
        updated_at = datetime('now')
    `).run(
      taskId,
      cleanGoal,
      status,
      unifiedDiff,
      JSON.stringify(stagedRecords),
      JSON.stringify(findings),
      explanation
    );

    return okEnvelope(
      'krusch_run',
      explanation,
      {
        task_id: taskId,
        goal: cleanGoal,
        status,
        unified_diff: unifiedDiff,
        findings,
        files: stagedRecords.map((r) => r.file_path),
        test_command: test_command || null
      },
      true
    );
  }

  /**
   * Inspect current status of a harness task.
   * @param {object} params
   * @param {string} params.task_id
   */
  function taskStatus({ task_id } = {}) {
    const row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(String(task_id || ''));
    if (!row) {
      return okEnvelope('krusch_task_status', `Task ${task_id} not found`, { task_id, found: false }, false);
    }
    const files = JSON.parse(row.files_json || '[]');
    const findings = JSON.parse(row.invariant_findings_json || '[]');
    return okEnvelope('krusch_task_status', `Task ${row.task_id} is ${row.status}`, {
      task_id: row.task_id,
      goal: row.goal,
      status: row.status,
      files: files.map((f) => (typeof f === 'string' ? f : f.file_path)),
      findings,
      explanation: row.explanation,
      created_at: row.created_at,
      updated_at: row.updated_at
    });
  }

  /**
   * Retrieve the staged unified diff for a task.
   * @param {object} params
   * @param {string} params.task_id
   */
  function diff({ task_id } = {}) {
    const row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(String(task_id || ''));
    if (!row) {
      return okEnvelope('krusch_diff', `Task ${task_id} not found`, { task_id, found: false }, false);
    }
    const files = JSON.parse(row.files_json || '[]');
    return okEnvelope('krusch_diff', `Unified diff for ${row.task_id} (${row.status})`, {
      task_id: row.task_id,
      status: row.status,
      unified_diff: row.unified_diff,
      files: files.map((f) => (typeof f === 'string' ? f : f.file_path))
    });
  }

  /**
   * Recover in-flight or compound-faulted multi-file applies from `harness_apply_journal`
   * (INV-REC-02 & INV-REC-03). Preserves strict all-or-nothing atomicity even if recovery
   * itself encounters ENOSPC, EIO, EACCES, SQLITE_FULL, SQLITE_BUSY, or SQLITE_NOMEM.
   */
  function recoverInFlight() {
    let journalRows;
    try {
      journalRows = db
        .prepare(
          "SELECT * FROM harness_apply_journal WHERE state IN ('APPLYING', 'RECOVERY_PENDING') ORDER BY created_at ASC"
        )
        .all();
    } catch (queryErr) {
      return okEnvelope(
        'krusch_recover_harness',
        `Failed to query apply journal during recovery: ${queryErr.message}`,
        {
          recovered_count: 0,
          outcomes: [],
          pending_errors: [{ task_id: '*', error: String(queryErr?.message || queryErr) }]
        },
        false
      );
    }

    const outcomes = [];
    const pendingErrors = [];

    for (const journalRow of journalRows) {
      try {
        const rawEntries = JSON.parse(journalRow.entries_json || '[]');
        const allFiles = rawEntries.map((e) => e.file_path || e.rel_path).filter(Boolean);
        const contentEntries = rawEntries.filter((e) => e && e.has_content !== false);

        const inspected = [];
        for (const entry of contentEntries) {
          const targetRel = entry.file_path || entry.rel_path;
          const { absPath, relPath } = resolveSafeWorkspacePath(rootDir, targetRel);
          cleanOrphanedTempFiles(absPath, fsImpl);

          const { exists: diskExists, content: diskText } = readTextIfExists(absPath, fsImpl);
          const diskHash = diskExists ? sha256Text(diskText) : null;

          const isRenamed = Boolean(diskExists && diskHash === entry.staged_sha256);
          const isUntouched = Boolean(
            (!diskExists && !entry.existed_before) ||
              (diskExists && entry.existed_before && diskHash === entry.base_sha256)
          );
          const isDrift = !isRenamed && !isUntouched;

          inspected.push({
            ...entry,
            absPath,
            relPath,
            diskExists,
            diskHash,
            isRenamed,
            isUntouched,
            isDrift
          });
        }

        const anyDrift = inspected.some((item) => item.isDrift);
        const allRenamed = inspected.every((item) => item.isRenamed);
        const allUntouched = inspected.every((item) => item.isUntouched);

        if (anyDrift) {
          // Case C: External working-tree drift — never clobber drifted files on disk
          runInTransaction(db, () => {
            db.prepare(`
              UPDATE harness_tasks
              SET status = 'REJECTED',
                  explanation = 'Working tree drift detected during crash recovery',
                  updated_at = datetime('now')
              WHERE task_id = ?
            `).run(journalRow.task_id);

            db.prepare(`
              UPDATE harness_apply_journal
              SET state = 'ROLLED_BACK',
                  last_error = 'WORKING_TREE_DRIFT_DETECTED',
                  updated_at = datetime('now')
              WHERE task_id = ?
            `).run(journalRow.task_id);
          });
          outcomes.push({
            task_id: journalRow.task_id,
            outcome: 'DRIFT_REJECTED',
            files: allFiles
          });
        } else if (allRenamed) {
          // Case A: All content files match staged_sha256 on disk — promote DB state to APPLIED
          runInTransaction(db, () => {
            db.prepare(`
              UPDATE harness_tasks
              SET status = 'APPLIED',
                  explanation = ?,
                  updated_at = datetime('now')
              WHERE task_id = ?
            `).run(
              `Recovered and finalized ${allFiles.length} applied file(s) atomically to workspace.`,
              journalRow.task_id
            );

            db.prepare(`
              UPDATE harness_apply_journal
              SET state = 'APPLIED',
                  last_error = NULL,
                  updated_at = datetime('now')
              WHERE task_id = ?
            `).run(journalRow.task_id);
          });
          outcomes.push({
            task_id: journalRow.task_id,
            outcome: 'PROMOTED_APPLIED',
            files: allFiles
          });
        } else if (allUntouched) {
          // Case B: Zero files modified on disk — mark journal ROLLED_BACK while keeping task STAGED
          db.prepare(`
            UPDATE harness_apply_journal
            SET state = 'ROLLED_BACK',
                last_error = NULL,
                updated_at = datetime('now')
            WHERE task_id = ?
          `).run(journalRow.task_id);
          outcomes.push({
            task_id: journalRow.task_id,
            outcome: 'REVERTED_STAGED',
            files: allFiles
          });
        } else {
          // Case D: Partial multi-file crash — roll back every renamed file to verified base preimage
          for (let i = inspected.length - 1; i >= 0; i--) {
            const item = inspected[i];
            if (!item.isRenamed || item.isUntouched) {
              continue;
            }
            if (item.existed_before) {
              if (
                typeof item.base_content !== 'string' ||
                sha256Text(item.base_content) !== item.base_sha256
              ) {
                const corruptPreimageErr = new Error(
                  `Corrupt base preimage in apply journal for ${item.relPath} (task ${journalRow.task_id})`
                );
                corruptPreimageErr.code = 'CORRUPT_BASE_PREIMAGE';
                throw corruptPreimageErr;
              }
              atomicRestoreFile(item.absPath, item.base_content, fsImpl);
            } else {
              try {
                fsImpl.unlinkSync(item.absPath);
              } catch (unlinkErr) {
                if (unlinkErr?.code !== 'ENOENT') {
                  throw unlinkErr;
                }
              }
              fsyncDirectory(path.dirname(item.absPath), fsImpl);
            }
          }

          db.prepare(`
            UPDATE harness_apply_journal
            SET state = 'ROLLED_BACK',
                last_error = NULL,
                updated_at = datetime('now')
            WHERE task_id = ?
          `).run(journalRow.task_id);
          outcomes.push({
            task_id: journalRow.task_id,
            outcome: 'ROLLED_BACK_TO_STAGED',
            files: allFiles
          });
        }
      } catch (err) {
        // Compound-Recovery Guard (INV-REC-02): keep journal in active recovery state!
        const errMsg = String(err?.message || err);
        try {
          db.prepare(`
            UPDATE harness_apply_journal
            SET state = 'RECOVERY_PENDING',
                last_error = ?,
                updated_at = datetime('now')
            WHERE task_id = ?
          `).run(errMsg, journalRow.task_id);
        } catch (journalUpdateErr) {
          /* SQLite may be SQLITE_FULL / SQLITE_NOMEM; row stays in APPLYING / RECOVERY_PENDING */
        }
        pendingErrors.push({
          task_id: journalRow.task_id,
          error: errMsg
        });
      }
    }

    const ok = pendingErrors.length === 0;
    const summary = ok
      ? `Recovered ${outcomes.length} in-flight harness task(s) cleanly.`
      : `Recovery deferred for ${pendingErrors.length} task(s) due to compound I/O or storage fault.`;

    return okEnvelope(
      'krusch_recover_harness',
      summary,
      {
        recovered_count: outcomes.length,
        outcomes,
        pending_errors: pendingErrors
      },
      ok
    );
  }

  /**
   * Atomically apply a STAGED task's edits to workspaceRoot (INV-STACK-06, INV-REC-02, INV-REC-03).
   * @param {object} params
   * @param {string} params.task_id
   */
  function applyDiff({ task_id } = {}) {
    const targetTaskId = String(task_id || '');

    // Pre-flight check: resolve any prior in-flight or compound-faulted journal entries first
    let hasPendingJournal = false;
    try {
      hasPendingJournal = Boolean(
        db
          .prepare(
            "SELECT 1 AS pending FROM harness_apply_journal WHERE state IN ('APPLYING', 'RECOVERY_PENDING') LIMIT 1"
          )
          .get()
      );
    } catch (preflightErr) {
      return okEnvelope(
        'krusch_apply_diff',
        `Failed to inspect apply journal before applying ${targetTaskId}: ${preflightErr.message}`,
        {
          task_id: targetTaskId,
          error: preflightErr.message,
          recovery_pending: true
        },
        false
      );
    }

    if (hasPendingJournal) {
      const rec = recoverInFlight();
      if (!rec.ok) {
        return okEnvelope(
          'krusch_apply_diff',
          'Cannot apply diff while prior compound recovery is still pending I/O resolution',
          {
            task_id: targetTaskId,
            recovery_pending: true,
            pending_errors: rec.data.pending_errors
          },
          false
        );
      }

      const promotedThisTask = rec.data.outcomes.some(
        (o) => o.task_id === targetTaskId && o.outcome === 'PROMOTED_APPLIED'
      );
      if (promotedThisTask) {
        const promotedRow = db
          .prepare('SELECT * FROM harness_tasks WHERE task_id = ?')
          .get(targetTaskId);
        const promotedRecords = JSON.parse(promotedRow?.files_json || '[]');
        const promotedFiles = promotedRecords.map((item) =>
          typeof item === 'string' ? item : item.file_path
        );
        return okEnvelope(
          'krusch_apply_diff',
          `Recovered and finalized applied task ${targetTaskId}`,
          {
            task_id: targetTaskId,
            status: 'APPLIED',
            applied_files: promotedFiles,
            recovered: true
          },
          true
        );
      }
    }

    let row;
    try {
      row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(targetTaskId);
    } catch (lookupErr) {
      return okEnvelope(
        'krusch_apply_diff',
        `Failed to load task ${targetTaskId}: ${lookupErr.message}`,
        { task_id: targetTaskId, error: lookupErr.message },
        false
      );
    }

    if (!row) {
      return okEnvelope('krusch_apply_diff', `Task ${task_id} not found`, { task_id, found: false }, false);
    }
    if (row.status !== 'STAGED') {
      return okEnvelope(
        'krusch_apply_diff',
        `Cannot apply task ${row.task_id} because status is ${row.status} (expected STAGED)`,
        {
          task_id: row.task_id,
          status: row.status,
          applied_files: []
        },
        false
      );
    }

    const stagedRecords = JSON.parse(row.files_json || '[]');
    const resolvedTargets = [];

    // Pre-commit working-tree SHA-256 verification (INV-REC-03.1)
    try {
      for (const item of stagedRecords) {
        const filePath = typeof item === 'string' ? item : item.file_path;
        const hasContent =
          typeof item === 'object' &&
          item !== null &&
          item.has_content !== false &&
          typeof item.content === 'string';
        const { absPath, relPath } = resolveSafeWorkspacePath(rootDir, filePath);

        if (hasContent) {
          cleanOrphanedTempFiles(absPath, fsImpl);
        }

        const { exists: diskExists, content: baseContent } = readTextIfExists(absPath, fsImpl);
        const diskHash = diskExists ? sha256Text(baseContent) : null;

        if (
          typeof item === 'object' &&
          item !== null &&
          item.base_sha256 !== undefined &&
          diskHash !== item.base_sha256
        ) {
          return okEnvelope(
            'krusch_apply_diff',
            `Working tree drift detected for ${relPath} before applying ${row.task_id}`,
            {
              task_id: row.task_id,
              status: row.status,
              error: 'WORKING_TREE_DRIFT_DETECTED',
              drifted_file: relPath,
              applied_files: []
            },
            false
          );
        }

        resolvedTargets.push({
          absPath,
          relPath,
          has_content: hasContent,
          content: hasContent ? item.content : null,
          existed_before: diskExists,
          base_content: baseContent,
          base_sha256: diskHash,
          staged_sha256: hasContent
            ? typeof item.staged_sha256 === 'string'
              ? item.staged_sha256
              : sha256Text(item.content)
            : null,
          tempPath: null
        });
      }
    } catch (inspectErr) {
      return okEnvelope(
        'krusch_apply_diff',
        `Failed to inspect workspace for ${row.task_id}: ${inspectErr.message}`,
        { task_id: row.task_id, status: row.status, error: inspectErr.message, applied_files: [] },
        false
      );
    }

    const contentTargets = resolvedTargets.filter((t) => t.has_content);
    const createdTempPaths = [];

    // Phase 1: Stage & fsync all sibling temporary files before any renameSync (INV-REC-03.2)
    try {
      for (const target of contentTargets) {
        target.tempPath = atomicWriteTempFile(target.absPath, target.content, fsImpl);
        createdTempPaths.push(target.tempPath);
      }
    } catch (tempErr) {
      for (const tmp of createdTempPaths) {
        unlinkBestEffort(tmp, fsImpl);
      }
      return okEnvelope(
        'krusch_apply_diff',
        `Failed to stage temporary files for ${row.task_id}: ${tempErr.message}`,
        { task_id: row.task_id, status: row.status, error: tempErr.message, applied_files: [] },
        false
      );
    }

    // Phase 2: Persist durable preimage journal before mutating target paths (INV-REC-03.3)
    const journalEntries = resolvedTargets.map((t) => ({
      file_path: t.relPath,
      has_content: t.has_content,
      existed_before: t.existed_before,
      base_content: t.base_content,
      base_sha256: t.base_sha256,
      staged_sha256: t.staged_sha256
    }));

    try {
      db.prepare(`
        INSERT INTO harness_apply_journal (
          task_id, state, entries_json, last_error, created_at, updated_at
        ) VALUES (?, 'APPLYING', ?, NULL, datetime('now'), datetime('now'))
        ON CONFLICT(task_id) DO UPDATE SET
          state = 'APPLYING',
          entries_json = excluded.entries_json,
          last_error = NULL,
          updated_at = datetime('now')
      `).run(row.task_id, JSON.stringify(journalEntries));
    } catch (journalErr) {
      for (const tmp of createdTempPaths) {
        unlinkBestEffort(tmp, fsImpl);
      }
      return okEnvelope(
        'krusch_apply_diff',
        `Failed to persist apply journal for ${row.task_id}: ${journalErr.message}`,
        { task_id: row.task_id, status: row.status, error: journalErr.message, applied_files: [] },
        false
      );
    }

    // Phase 3: Atomic rename + parent-directory fsync across batch with compound-safe rollback
    const renamedSoFar = [];
    try {
      for (const target of contentTargets) {
        fsImpl.renameSync(target.tempPath, target.absPath);
        target.tempPath = null;
        renamedSoFar.push(target);
        fsyncDirectory(path.dirname(target.absPath), fsImpl);
      }
    } catch (renameOrFsyncErr) {
      for (const target of contentTargets) {
        if (target.tempPath) {
          unlinkBestEffort(target.tempPath, fsImpl);
          target.tempPath = null;
        }
      }

      const rollbackErrors = [];
      for (let r = renamedSoFar.length - 1; r >= 0; r--) {
        const appliedTarget = renamedSoFar[r];
        try {
          if (appliedTarget.existed_before) {
            atomicRestoreFile(appliedTarget.absPath, appliedTarget.base_content, fsImpl);
          } else {
            try {
              fsImpl.unlinkSync(appliedTarget.absPath);
            } catch (unlinkErr) {
              if (unlinkErr?.code !== 'ENOENT') {
                throw unlinkErr;
              }
            }
            fsyncDirectory(path.dirname(appliedTarget.absPath), fsImpl);
          }
        } catch (rbErr) {
          rollbackErrors.push({
            file_path: appliedTarget.relPath,
            error: String(rbErr?.message || rbErr)
          });
        }
      }

      if (rollbackErrors.length === 0) {
        let journalUpdateError = null;
        try {
          db.prepare(`
            UPDATE harness_apply_journal
            SET state = 'ROLLED_BACK',
                last_error = ?,
                updated_at = datetime('now')
            WHERE task_id = ?
          `).run(String(renameOrFsyncErr?.message || renameOrFsyncErr), row.task_id);
        } catch (dbErr) {
          journalUpdateError = String(dbErr?.message || dbErr);
        }

        if (journalUpdateError) {
          return okEnvelope(
            'krusch_apply_diff',
            `Rolled back disk files for ${row.task_id}, but journal update failed: ${journalUpdateError}`,
            {
              task_id: row.task_id,
              status: row.status,
              error: renameOrFsyncErr.message,
              journal_error: journalUpdateError,
              rolled_back: true,
              recovery_pending: true
            },
            false
          );
        }

        return okEnvelope(
          'krusch_apply_diff',
          `Failed to apply diff for ${row.task_id} (rolled back ${renamedSoFar.length} file(s)): ${renameOrFsyncErr.message}`,
          {
            task_id: row.task_id,
            status: row.status,
            error: renameOrFsyncErr.message,
            rolled_back: true
          },
          false
        );
      }

      const compoundSummary = `Primary error: ${renameOrFsyncErr.message}; Rollback errors: ${rollbackErrors
        .map((e) => `${e.file_path}: ${e.error}`)
        .join('; ')}`;
      try {
        db.prepare(`
          UPDATE harness_apply_journal
          SET state = 'RECOVERY_PENDING',
              last_error = ?,
              updated_at = datetime('now')
          WHERE task_id = ?
        `).run(compoundSummary, row.task_id);
      } catch (dbErr) {
        /* Journal remains in 'APPLYING', which recoverInFlight() also processes */
      }

      return okEnvelope(
        'krusch_apply_diff',
        `Compound failure while rolling back ${row.task_id}; recovery pending`,
        {
          task_id: row.task_id,
          status: row.status,
          error: renameOrFsyncErr.message,
          compound_error: true,
          recovery_pending: true,
          rollback_errors: rollbackErrors
        },
        false
      );
    }

    // Phase 4: Commit APPLIED state atomically in SQLite (INV-REC-03.5)
    const appliedFiles = resolvedTargets.map((t) => t.relPath);
    try {
      runInTransaction(db, () => {
        db.prepare(`
          UPDATE harness_tasks
          SET status = 'APPLIED',
              explanation = ?,
              updated_at = datetime('now')
          WHERE task_id = ?
        `).run(`Applied ${appliedFiles.length} file(s) atomically to workspace.`, row.task_id);

        db.prepare(`
          UPDATE harness_apply_journal
          SET state = 'APPLIED',
              last_error = NULL,
              updated_at = datetime('now')
          WHERE task_id = ?
        `).run(row.task_id);
      });
    } catch (dbErr) {
      try {
        db.prepare(`
          UPDATE harness_apply_journal
          SET state = 'RECOVERY_PENDING',
              last_error = ?,
              updated_at = datetime('now')
          WHERE task_id = ?
        `).run(String(dbErr?.message || dbErr), row.task_id);
      } catch (secondaryDbErr) {
        /* Journal remains in 'APPLYING' with staged_sha256 entries intact */
      }

      return okEnvelope(
        'krusch_apply_diff',
        `Files renamed on disk for ${row.task_id}, but SQLite commit failed (${dbErr.message}); recovery pending`,
        {
          task_id: row.task_id,
          status: row.status,
          error: dbErr.message,
          recovery_pending: true
        },
        false
      );
    }

    return okEnvelope('krusch_apply_diff', `Applied ${appliedFiles.length} file(s) for ${row.task_id}`, {
      task_id: row.task_id,
      status: 'APPLIED',
      applied_files: appliedFiles
    });
  }

  /**
   * Explain why a task was staged, blocked, or rejected.
   * @param {object} params
   * @param {string} params.task_id
   */
  function explain({ task_id } = {}) {
    const row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(String(task_id || ''));
    if (!row) {
      return okEnvelope('krusch_explain', `Task ${task_id} not found`, { task_id, found: false }, false);
    }
    const findings = JSON.parse(row.invariant_findings_json || '[]');
    return okEnvelope('krusch_explain', row.explanation || `Task ${row.task_id} is ${row.status}`, {
      task_id: row.task_id,
      goal: row.goal,
      status: row.status,
      explanation: row.explanation,
      findings,
      unified_diff: row.unified_diff
    });
  }

  /**
   * Reject a staged task with an audit reason.
   * @param {object} params
   * @param {string} params.task_id
   * @param {string} [params.reason]
   */
  function reject({ task_id, reason = 'Rejected by operator' } = {}) {
    const row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(String(task_id || ''));
    if (!row) {
      return okEnvelope('krusch_reject', `Task ${task_id} not found`, { task_id, found: false }, false);
    }
    const cleanReason = String(reason || 'Rejected by operator').trim();
    db.prepare(`
      UPDATE harness_tasks
      SET status = 'REJECTED',
          explanation = ?,
          updated_at = datetime('now')
      WHERE task_id = ?
    `).run(cleanReason, row.task_id);

    return okEnvelope('krusch_reject', `Rejected task ${row.task_id}: ${cleanReason}`, {
      task_id: row.task_id,
      status: 'REJECTED',
      reason: cleanReason
    });
  }

  /**
   * Abort a pending or staged task.
   * @param {object} params
   * @param {string} params.task_id
   */
  function abort({ task_id } = {}) {
    const row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(String(task_id || ''));
    if (!row) {
      return okEnvelope('krusch_abort', `Task ${task_id} not found`, { task_id, found: false }, false);
    }
    db.prepare(`
      UPDATE harness_tasks
      SET status = 'ABORTED',
          explanation = 'Aborted by operator',
          updated_at = datetime('now')
      WHERE task_id = ?
    `).run(row.task_id);

    return okEnvelope('krusch_abort', `Aborted task ${row.task_id}`, {
      task_id: row.task_id,
      status: 'ABORTED'
    });
  }

  return {
    run,
    taskStatus,
    diff,
    applyDiff,
    explain,
    reject,
    abort,
    recoverInFlight
  };
}
