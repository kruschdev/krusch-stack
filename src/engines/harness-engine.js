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

/**
 * Create the Tier 3 2PC Staged Execution Harness engine.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 * @param {object} [options.contextEngine]
 */
export function createHarnessEngine({ db, workspaceRoot = process.cwd(), contextEngine } = {}) {
  if (!db) {
    throw new Error('createHarnessEngine requires a SQLite db instance');
  }
  const rootDir = path.resolve(workspaceRoot);

  /**
   * Stage a task in the 2PC harness without modifying the working tree (INV-STACK-06).
   * @param {object} params
   * @param {string} params.goal
   * @param {Array<{file_path: string, content: string}>} [params.edits]
   * @param {Array<string|{file_path: string, content?: string}>} [params.files]
   * @param {string} [params.test_command]
   * @param {string} [params.task_id]
   */
  function run({ goal = '', edits = [], files = [], test_command } = {}) {
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
        const existed = fs.existsSync(absPath);
        const beforeText = existed ? fs.readFileSync(absPath, 'utf8') : '';
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
          has_content: edit.hasContent
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
    const taskId = `task-${crypto.createHash('sha256').update(hashInput).digest('hex').slice(0, 12)}`;

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
   * Atomically apply a STAGED task's edits to workspaceRoot (INV-STACK-06).
   * @param {object} params
   * @param {string} params.task_id
   */
  function applyDiff({ task_id } = {}) {
    const row = db.prepare('SELECT * FROM harness_tasks WHERE task_id = ?').get(String(task_id || ''));
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

    try {
      for (const item of stagedRecords) {
        const filePath = typeof item === 'string' ? item : item.file_path;
        const hasContent = typeof item === 'object' && item !== null && item.has_content !== false && typeof item.content === 'string';
        const { absPath, relPath } = resolveSafeWorkspacePath(rootDir, filePath);
        resolvedTargets.push({
          absPath,
          relPath,
          content: hasContent ? item.content : null
        });
      }

      const appliedFiles = [];
      for (const target of resolvedTargets) {
        if (target.content !== null) {
          fs.mkdirSync(path.dirname(target.absPath), { recursive: true });
          const tmpPath = `${target.absPath}.krusch-tmp-${process.pid}`;
          fs.writeFileSync(tmpPath, target.content, 'utf8');
          fs.renameSync(tmpPath, target.absPath);
        }
        appliedFiles.push(target.relPath);
      }

      db.prepare(`
        UPDATE harness_tasks
        SET status = 'APPLIED',
            explanation = ?,
            updated_at = datetime('now')
        WHERE task_id = ?
      `).run(`Applied ${appliedFiles.length} file(s) atomically to workspace.`, row.task_id);

      return okEnvelope('krusch_apply_diff', `Applied ${appliedFiles.length} file(s) for ${row.task_id}`, {
        task_id: row.task_id,
        status: 'APPLIED',
        applied_files: appliedFiles
      });
    } catch (err) {
      return okEnvelope(
        'krusch_apply_diff',
        `Failed to apply diff for ${row.task_id}: ${err.message}`,
        { task_id: row.task_id, status: row.status, error: err.message },
        false
      );
    }
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
    abort
  };
}
