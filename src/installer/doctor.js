/**
 * @module installer/doctor
 * Diagnostic health check runner for KruschStack (`krusch-stack doctor`).
 * Verifies Node.js >=22 runtime, native `node:sqlite` schema readiness,
 * optional PostgreSQL (`DATABASE_URL`) configuration, local Ollama host defaults,
 * and active stack components.
 * Enforces INV-STACK-02 (return envelope) and INV-STACK-04 (sanitized localhost defaults).
 */

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { openStackDatabase, okEnvelope } from '../db/sqlite.js';

const DOCTOR_DIR = path.dirname(fileURLToPath(import.meta.url));
const STACK_INDEX_URL = pathToFileURL(path.resolve(DOCTOR_DIR, '..', 'index.js')).href;

const REQUIRED_TABLES = [
  'context_memories',
  'git_repositories',
  'git_symbols',
  'git_edges',
  'fs_pages',
  'fs_page_memories',
  'harness_tasks',
  'frontend_design_rules',
  'workspace_files'
];

const ALL_COMPONENTS = [
  {
    id: 'context',
    name: 'krusch-context-mcp',
    tier: 'Tier 1',
    description: 'Working Memory, Invariants & Span-Grounded Drift Detection',
    core: true
  },
  {
    id: 'git',
    name: 'krusch-git',
    tier: 'Tier 2A',
    description: 'Codebase AST Symbols, Call Graph & Hybrid Search',
    core: true
  },
  {
    id: 'fs',
    name: 'krusch-fs',
    tier: 'Tier 2B',
    description: 'OS Filesystem Structural Pages & SHA-256 PageMemory',
    core: true
  },
  {
    id: 'harness',
    name: 'krusch-harness',
    tier: 'Tier 3',
    description: '2PC Staged Execution Harness & Invariant Gate',
    core: true
  },
  {
    id: 'router',
    name: 'krusch-cascade-router',
    tier: 'Router',
    description: 'Cognitive L1-L3 Task & Model Cascade Router',
    core: true
  },
  {
    id: 'frontend',
    name: 'krusch-frontend-mcp',
    tier: 'Tier 4',
    description: 'Frontend Design Rules, Color Palettes & Canonical Templates',
    core: false
  },
  {
    id: 'workspace',
    name: 'g-krusch',
    tier: 'Tier 5',
    description: 'Workspace Hub, Steering & Hybrid Document RAG',
    core: false
  }
];

/**
 * Execute a full diagnostic check across the KruschStack runtime and storage engines.
 * @param {object} [options]
 * @param {string} [options.workspaceRoot=process.cwd()]
 * @param {import('node:sqlite').DatabaseSync} [options.db]
 * @param {'core'|'full'} [options.profile='full']
 * @param {object} [options.engines]
 */
export function runStackDoctor({
  workspaceRoot = process.cwd(),
  db,
  profile = 'full'
} = {}) {
  const resolvedRoot = path.resolve(workspaceRoot);
  const normalizedProfile = profile === 'core' ? 'core' : 'full';

  const nodeVersion = process.versions.node;
  const majorVersion = Number(nodeVersion.split('.')[0] || 0);
  const nodeSupported = majorVersion >= 22;

  let sqliteReady = false;
  let tablesVerified = [];
  let ownedDb = null;

  try {
    const activeDb = db || (ownedDb = openStackDatabase({ workspaceRoot: resolvedRoot }));
    const ping = activeDb.prepare('SELECT 1 AS ok').get();
    const rows = activeDb
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all();
    const existingSet = new Set(rows.map((r) => r.name));
    tablesVerified = REQUIRED_TABLES.filter((t) => existingSet.has(t));
    sqliteReady = Boolean(ping && ping.ok === 1 && tablesVerified.length === REQUIRED_TABLES.length);
  } catch {
    sqliteReady = false;
  } finally {
    if (ownedDb) {
      try {
        ownedDb.close();
      } catch {
        // ignore close errors
      }
    }
  }

  const postgresConfigured = Boolean(
    process.env.DATABASE_URL || process.env.POSTGRES_URL
  );
  const ollamaHost = process.env.OLLAMA_HOST || 'http://127.0.0.1:11434';

  const selectedComponents = ALL_COMPONENTS.filter(
    (comp) => normalizedProfile === 'full' || comp.core
  ).map((comp) => ({
    id: comp.id,
    name: comp.name,
    tier: comp.tier,
    description: comp.description,
    ready: sqliteReady && nodeSupported,
    status: sqliteReady && nodeSupported ? 'ready' : 'degraded'
  }));

  const ok = nodeSupported && sqliteReady;
  const summary = `KruschStack Doctor: ${ok ? 'HEALTHY' : 'DEGRADED'} (Node v${nodeVersion}, SQLite=${sqliteReady ? 'ready' : 'error'}, Postgres=${postgresConfigured ? 'configured' : 'optional-unconfigured'}, profile=${normalizedProfile}, components=${selectedComponents.length}).`;

  const data = {
    node_version: nodeVersion,
    nodeVersion,
    node_supported: nodeSupported,
    nodeSupported,
    sqlite_ready: sqliteReady,
    sqliteReady,
    tables_verified: tablesVerified,
    postgres_configured: postgresConfigured,
    postgresConfigured,
    ollama_host: ollamaHost,
    ollamaHost,
    workspace_root: resolvedRoot,
    profile: normalizedProfile,
    components: selectedComponents
  };

  const envelope = okEnvelope('krusch_stack_doctor', summary, data, ok);

  return {
    ...envelope,
    nodeVersion,
    nodeSupported,
    sqliteReady,
    postgresConfigured,
    ollamaHost,
    profile: normalizedProfile,
    components: selectedComponents
  };
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex');
}

function listOrphanedTempFiles(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return [];
  const orphans = [];
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    if (entry.name === '.krusch-stack') continue;
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      orphans.push(...listOrphanedTempFiles(full));
    } else if (entry.name.includes('.krusch-tmp-')) {
      orphans.push(full);
    }
  }
  return orphans;
}

/**
 * Execute a live 2-process OS `SIGKILL` write-ahead apply-journal recovery self-test (`INV-REC-03`):
 * 1. Stage a 2-file edit in an isolated SQLite WAL database (`drill-stack.db`).
 * 2. Spawn Worker Process 1 running `applyDiff()` and kill it with `SIGKILL` immediately after file 1 is renamed + fsynced.
 * 3. Spawn a cold fresh Recovery Process 2 opening `drill-stack.db` and running `recoverInFlight()` to restore preimages (`halfWrittenFiles === 0`, `orphanedTempCleaned === true`).
 */
export async function runStackCrashRecoveryDrill() {
  const drillRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-crash-drill-'));
  const drillWorkspace = path.join(drillRoot, 'workspace');
  const drillDbPath = path.join(drillRoot, 'drill-stack.db');
  const markerPath = path.join(drillRoot, 'first-rename.marker');
  const workerStageScript = path.join(drillRoot, 'worker-stage.mjs');
  const workerApplyScript = path.join(drillRoot, 'worker-apply.mjs');
  const workerRecoverScript = path.join(drillRoot, 'worker-recover.mjs');

  let workerChild = null;
  try {
    fs.mkdirSync(path.join(drillWorkspace, 'src'), { recursive: true });
    const file1Rel = 'src/fee-engine.js';
    const file2Rel = 'src/settlement-service.js';
    const file1Abs = path.join(drillWorkspace, file1Rel);
    const file2Abs = path.join(drillWorkspace, file2Rel);

    const baseFile1Text =
      'export function computeFeeCents(grossCents, bps) {\n  return Math.round((grossCents * bps) / 10000);\n}\n';
    const baseFile2Text =
      "import { computeFeeCents } from './fee-engine.js';\nexport function settleBatch(items, bps) {\n  return items.map((c) => c - computeFeeCents(c, bps));\n}\n";
    fs.writeFileSync(file1Abs, baseFile1Text, 'utf8');
    fs.writeFileSync(file2Abs, baseFile2Text, 'utf8');

    const baseFile1Hash = sha256Hex(baseFile1Text);
    const baseFile2Hash = sha256Hex(baseFile2Text);
    const stagedFile1Text = `${baseFile1Text}\n// Staged batch fee allocation part 1\n`;
    const stagedFile2Text = `${baseFile2Text}\n// Staged settlement parity check part 2\n`;
    const stagedFile1Hash = sha256Hex(stagedFile1Text);
    const stagedFile2Hash = sha256Hex(stagedFile2Text);
    const taskId = 'drill_sigkill_recovery_01';

    fs.writeFileSync(
      workerStageScript,
      [
        `import { createKruschStack } from ${JSON.stringify(STACK_INDEX_URL)};`,
        'const [ws, dbPath, tId, f1, c1, f2, c2] = process.argv.slice(2);',
        'const stack = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false, recoverOnStartup: false, profile: "core" });',
        'const res = stack.harness.run({ task_id: tId, goal: "Doctor crash drill", edits: [{ file_path: f1, content: c1 }, { file_path: f2, content: c2 }] });',
        'stack.db.close();',
        'if (!res.ok) { process.exit(2); }'
      ].join('\n'),
      'utf8'
    );

    const stageExit = await new Promise((resolve, reject) => {
      const p = spawn(
        process.execPath,
        [workerStageScript, drillWorkspace, drillDbPath, taskId, file1Rel, stagedFile1Text, file2Rel, stagedFile2Text],
        { env: { PATH: process.env.PATH || '/usr/bin:/bin', NODE_NO_WARNINGS: '1' }, stdio: 'ignore' }
      );
      p.once('error', reject);
      p.once('exit', (code) => resolve(code));
    });
    if (stageExit !== 0) {
      return okEnvelope('krusch_stack_crash_drill', 'Failed to stage 2-file drill task', { converged: false }, false);
    }

    fs.writeFileSync(
      workerApplyScript,
      [
        `import { createKruschStack } from ${JSON.stringify(STACK_INDEX_URL)};`,
        'const [ws, dbPath, tId] = process.argv.slice(2);',
        'const stack = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false, recoverOnStartup: false, profile: "core" });',
        'stack.harness.applyDiff({ task_id: tId });'
      ].join('\n'),
      'utf8'
    );

    workerChild = spawn(
      process.execPath,
      [workerApplyScript, drillWorkspace, drillDbPath, taskId],
      {
        env: {
          PATH: process.env.PATH || '/usr/bin:/bin',
          NODE_NO_WARNINGS: '1',
          KRUSCH_ENABLE_TEST_HOOKS: '1',
          KRUSCH_TEST_HOOK_PAUSE_AFTER_FIRST_RENAME: '1',
          KRUSCH_TEST_HOOK_MARKER_FILE: markerPath
        },
        stdio: ['ignore', 'pipe', 'pipe']
      }
    );

    const workerExitPromise = new Promise((resolve, reject) => {
      workerChild.once('error', reject);
      workerChild.once('exit', (code, signal) => resolve({ code, signal }));
    });

    const pollDeadline = Date.now() + 6000;
    let markerContent = '';
    while (Date.now() < pollDeadline) {
      if (fs.existsSync(markerPath)) {
        markerContent = fs.readFileSync(markerPath, 'utf8').trim();
        if (markerContent.length > 0) break;
      }
      if (workerChild.exitCode !== null || workerChild.signalCode !== null) break;
      await new Promise((r) => setTimeout(r, 12));
    }

    if (!markerContent) {
      return okEnvelope(
        'krusch_stack_crash_drill',
        'Apply worker did not reach first-rename checkpoint within timeout.',
        { converged: false },
        false
      );
    }

    const workerPid = Number(markerContent) || workerChild.pid;
    workerChild.kill('SIGKILL');
    const workerExit = await workerExitPromise;
    workerChild = null;

    const crashFile1Hash = sha256Hex(fs.readFileSync(file1Abs, 'utf8'));
    const crashFile2Hash = sha256Hex(fs.readFileSync(file2Abs, 'utf8'));
    const orphansDuringCrash = listOrphanedTempFiles(drillWorkspace);
    const halfWrittenBefore =
      (crashFile1Hash === stagedFile1Hash ? 1 : 0) +
      (crashFile2Hash === stagedFile2Hash ? 1 : 0);

    fs.writeFileSync(
      workerRecoverScript,
      [
        `import { createKruschStack } from ${JSON.stringify(STACK_INDEX_URL)};`,
        'const [ws, dbPath, tId] = process.argv.slice(2);',
        'const stack = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false, recoverOnStartup: false, profile: "core" });',
        'const beforeRow = stack.db.prepare("SELECT state FROM harness_apply_journal WHERE task_id = ?").get(tId);',
        'const recoveryEnvelope = stack.harness.recoverInFlight();',
        'const afterRow = stack.db.prepare("SELECT state FROM harness_apply_journal WHERE task_id = ?").get(tId);',
        'stack.db.close();',
        'process.stdout.write(JSON.stringify({',
        '  pid: process.pid,',
        '  journalStateBefore: beforeRow?.state || "UNKNOWN",',
        '  journalStateAfter: afterRow?.state || "UNKNOWN",',
        '  recoveryEnvelope',
        '}) + "\\n");'
      ].join('\n'),
      'utf8'
    );

    const recoverRes = await new Promise((resolve, reject) => {
      let stdout = '';
      const p = spawn(
        process.execPath,
        [workerRecoverScript, drillWorkspace, drillDbPath, taskId],
        { env: { PATH: process.env.PATH || '/usr/bin:/bin', NODE_NO_WARNINGS: '1' }, stdio: ['ignore', 'pipe', 'pipe'] }
      );
      p.stdout.on('data', (c) => { stdout += c.toString('utf8'); });
      p.once('error', reject);
      p.once('exit', (code) => resolve({ code, stdout }));
    });

    if (recoverRes.code !== 0) {
      return okEnvelope('krusch_stack_crash_drill', 'Recovery worker exited non-zero.', { converged: false }, false);
    }

    const lastJson = recoverRes.stdout
      .trim()
      .split(/\r?\n/)
      .reverse()
      .find((l) => l.trim().startsWith('{'));
    const recoverPayload = JSON.parse(lastJson || '{}');
    const recoveryPid = recoverPayload.pid || null;
    const journalStateBefore = recoverPayload.journalStateBefore || 'UNKNOWN';
    const journalStateAfter = recoverPayload.journalStateAfter || 'UNKNOWN';

    const recoveredFile1Hash = sha256Hex(fs.readFileSync(file1Abs, 'utf8'));
    const recoveredFile2Hash = sha256Hex(fs.readFileSync(file2Abs, 'utf8'));
    const orphansAfterRecovery = listOrphanedTempFiles(drillWorkspace);
    const orphanCleaned = orphansDuringCrash.length >= 1 && orphansAfterRecovery.length === 0;
    const restoredPreimages =
      recoveredFile1Hash === baseFile1Hash && recoveredFile2Hash === baseFile2Hash;
    const halfWrittenFiles = restoredPreimages ? 0 : 1;

    const converged = Boolean(
      workerExit.signal === 'SIGKILL' &&
        recoveryPid &&
        recoveryPid !== workerPid &&
        recoverPayload.recoveryEnvelope?.ok &&
        journalStateBefore === 'APPLYING' &&
        journalStateAfter === 'ROLLED_BACK' &&
        halfWrittenFiles === 0 &&
        orphanCleaned
    );

    return okEnvelope(
      'krusch_stack_crash_drill',
      converged
        ? `Multi-process SIGKILL crash-recovery drill converged (${journalStateBefore} -> ${journalStateAfter}, 0 half-written files, orphaned temp cleaned).`
        : 'Crash-recovery drill failed to converge.',
      {
        converged,
        workerPid,
        recoveryPid,
        workerKilledSignal: workerExit.signal || null,
        journalStateBefore,
        journalStateAfter,
        halfWrittenFilesBeforeRecovery: halfWrittenBefore,
        halfWrittenFiles,
        orphanedTempCleaned: orphanCleaned
      },
      converged
    );
  } finally {
    if (workerChild && workerChild.exitCode === null && workerChild.signalCode === null) {
      try {
        workerChild.kill('SIGKILL');
      } catch {
        // Ignore
      }
    }
    try {
      fs.rmSync(drillRoot, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  }
}
