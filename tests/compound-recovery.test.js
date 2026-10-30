import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  openStackDatabase,
  isSqliteCorruptionError
} from '../src/db/sqlite.js';
import {
  createHarnessEngine,
  fsyncDirectory
} from '../src/engines/harness-engine.js';
import { createKruschStack } from '../src/index.js';

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-compound-rec-'));
}

function makeOsError(code, message) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  return err;
}

function makeSqliteError(errcode, message, code = 'ERR_SQLITE_ERROR') {
  const err = new Error(message);
  err.code = code;
  err.errcode = errcode;
  err.errstr = message;
  return err;
}

function listTempOrphans(dir) {
  const found = [];
  function walk(current) {
    if (!fs.existsSync(current)) return;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== '.krusch-stack') walk(full);
      } else if (entry.name.includes('.krusch-tmp-')) {
        found.push(full);
      }
    }
  }
  walk(dir);
  return found;
}

/**
 * Create an instrumented fsOps wrapper around `node:fs` tracking open file descriptors
 * and allowing deterministic fault injection per operation.
 */
function createFaultFs(hooks = {}) {
  const openFds = new Set();
  return {
    openFds,
    existsSync: (...args) => (hooks.existsSync ? hooks.existsSync(...args) : fs.existsSync(...args)),
    readFileSync: (...args) =>
      hooks.readFileSync ? hooks.readFileSync(...args) : fs.readFileSync(...args),
    mkdirSync: (...args) => (hooks.mkdirSync ? hooks.mkdirSync(...args) : fs.mkdirSync(...args)),
    openSync: (...args) => {
      const fd = hooks.openSync ? hooks.openSync(...args) : fs.openSync(...args);
      openFds.add(fd);
      return fd;
    },
    writeSync: (...args) => (hooks.writeSync ? hooks.writeSync(...args) : fs.writeSync(...args)),
    fsyncSync: (...args) => (hooks.fsyncSync ? hooks.fsyncSync(...args) : fs.fsyncSync(...args)),
    closeSync: (fd, ...rest) => {
      openFds.delete(fd);
      return hooks.closeSync ? hooks.closeSync(fd, ...rest) : fs.closeSync(fd, ...rest);
    },
    renameSync: (...args) =>
      hooks.renameSync ? hooks.renameSync(...args) : fs.renameSync(...args),
    unlinkSync: (...args) =>
      hooks.unlinkSync ? hooks.unlinkSync(...args) : fs.unlinkSync(...args),
    readdirSync: (...args) =>
      hooks.readdirSync ? hooks.readdirSync(...args) : fs.readdirSync(...args)
  };
}

/**
 * Create a lightweight SQLite DatabaseSync proxy for deterministic SQL fault injection.
 */
function createFaultDbProxy(realDb, shouldFailSql) {
  return new Proxy(realDb, {
    get(target, prop) {
      if (prop === 'exec') {
        return (sql) => {
          const injected = shouldFailSql('exec', sql);
          if (injected) throw injected;
          return target.exec(sql);
        };
      }
      if (prop === 'prepare') {
        return (sql) => {
          const prepInjected = shouldFailSql('prepare', sql);
          if (prepInjected) throw prepInjected;
          const stmt = target.prepare(sql);
          return new Proxy(stmt, {
            get(stmtTarget, stmtProp) {
              if (stmtProp === 'run' || stmtProp === 'get' || stmtProp === 'all') {
                return (...params) => {
                  const runInjected = shouldFailSql(stmtProp, sql, params);
                  if (runInjected) throw runInjected;
                  return stmtTarget[stmtProp](...params);
                };
              }
              const val = stmtTarget[stmtProp];
              return typeof val === 'function' ? val.bind(stmtTarget) : val;
            }
          });
        };
      }
      const val = target[prop];
      return typeof val === 'function' ? val.bind(target) : val;
    }
  });
}

describe('SQLite-Style Compound-Fault Recovery Suite (INV-REC-01..05)', () => {
  test('1. INV-REC-01: Startup OOM / Lock / SQLITE_FULL / IOERR never quarantine live stack.db, while genuine corruption rotates and self-heals', () => {
    // Unit verification of isSqliteCorruptionError classifier
    assert.equal(isSqliteCorruptionError(makeSqliteError(11, 'database disk image is malformed')), true);
    assert.equal(isSqliteCorruptionError(makeSqliteError(26, 'file is not a database')), true);
    assert.equal(isSqliteCorruptionError(makeSqliteError(267, 'extended corrupt code')), true);
    assert.equal(isSqliteCorruptionError({ code: 'SQLITE_CORRUPT', message: 'corrupt' }), true);
    assert.equal(isSqliteCorruptionError({ code: 'SQLITE_NOTADB', message: 'not a db' }), true);
    assert.equal(isSqliteCorruptionError(new Error('SQLite quick_check failed: wrong # of entries')), true);

    assert.equal(isSqliteCorruptionError(makeSqliteError(7, 'out of memory')), false);
    assert.equal(isSqliteCorruptionError(makeSqliteError(5, 'database is locked')), false);
    assert.equal(isSqliteCorruptionError(makeSqliteError(6, 'database table is locked')), false);
    assert.equal(isSqliteCorruptionError(makeSqliteError(10, 'disk I/O error')), false);
    assert.equal(isSqliteCorruptionError(makeSqliteError(13, 'database or disk is full')), false);
    assert.equal(isSqliteCorruptionError(makeOsError('ENOSPC', 'no space left on device')), false);
    assert.equal(isSqliteCorruptionError(makeOsError('ENOMEM', 'cannot allocate memory')), false);
    assert.equal(isSqliteCorruptionError(makeOsError('EIO', 'input/output error')), false);
    assert.equal(isSqliteCorruptionError(makeOsError('EACCES', 'permission denied')), false);
    assert.equal(isSqliteCorruptionError(null), false);

    const ws = makeTempDir();
    const dbPath = path.join(ws, '.krusch-stack', 'stack.db');
    try {
      // Seed real data into file-backed stack.db
      const initialStack = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false });
      const mem = initialStack.context.remember({
        category: 'invariant',
        content: 'Preserve durable SQLite state across transient OOM and lock storms'
      });
      assert.equal(mem.ok, true);
      const staged = initialStack.harness.run({
        goal: 'Stage baseline module',
        edits: [{ file_path: 'src/base.js', content: 'export const v = 1;\n' }]
      });
      assert.equal(staged.ok, true);
      initialStack.db.close();

      // Inject transient faults both at constructor time and mid-pragma/quick_check
      const transientFaults = [
        { mode: 'open', err: makeSqliteError(7, 'out of memory') },
        { mode: 'pragma', err: makeSqliteError(7, 'out of memory') },
        { mode: 'pragma', err: makeSqliteError(5, 'database is locked') },
        { mode: 'pragma', err: makeSqliteError(10, 'disk I/O error') },
        { mode: 'pragma', err: makeSqliteError(13, 'database or disk is full') },
        { mode: 'open', err: makeOsError('ENOSPC', 'no space left on device') }
      ];

      let closedHandles = 0;
      for (const fault of transientFaults) {
        assert.throws(
          () =>
            openStackDatabase({
              workspaceRoot: ws,
              dbPath,
              ephemeral: false,
              _sqliteFactory: (filePath) => {
                if (fault.mode === 'open') {
                  throw fault.err;
                }
                const real = new DatabaseSync(filePath);
                let calls = 0;
                return new Proxy(real, {
                  get(target, prop) {
                    if (prop === 'close') {
                      return () => {
                        closedHandles++;
                        return target.close();
                      };
                    }
                    if (prop === 'prepare') {
                      return (sql) => {
                        calls++;
                        if (calls >= 1 && sql.includes('quick_check')) {
                          throw fault.err;
                        }
                        return target.prepare(sql);
                      };
                    }
                    const val = target[prop];
                    return typeof val === 'function' ? val.bind(target) : val;
                  }
                });
              }
            }),
          (thrown) => thrown === fault.err
        );

        const corruptFiles = fs
          .readdirSync(path.dirname(dbPath))
          .filter((name) => name.includes('.corrupt.'));
        assert.equal(
          corruptFiles.length,
          0,
          `Transient fault (${fault.err.message}) must NEVER quarantine stack.db`
        );
      }
      assert.equal(closedHandles, 4, 'Every opened handle that failed mid-pragma must be closed');

      // Reopen cleanly after transient faults clear and verify 100% data survival
      const reopened = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false });
      const health = reopened.context.health();
      assert.equal(health.ok, true);
      assert.equal(health.data.active, 1);
      const retrieved = reopened.context.retrieve({ query: 'transient OOM and lock storms' });
      assert.equal(retrieved.data.items.length, 1);
      const taskInfo = reopened.harness.taskStatus({ task_id: staged.data.task_id });
      assert.equal(taskInfo.ok, true);
      assert.equal(taskInfo.data.status, 'STAGED');
      reopened.db.close();

      // Genuine structural corruption still rotates to .corrupt.* and self-heals
      fs.writeFileSync(dbPath, 'NOT A VALID SQLITE3 HEADER CORRUPT BYTES', 'utf8');
      const healedDb = openStackDatabase({ workspaceRoot: ws, dbPath, ephemeral: false });
      const postHealCount = healedDb.prepare('SELECT COUNT(*) AS cnt FROM context_memories').get().cnt;
      assert.equal(Number(postHealCount), 0);
      const rotated = fs
        .readdirSync(path.dirname(dbPath))
        .filter((name) => name.includes('.corrupt.'));
      assert.ok(rotated.length >= 1, 'Genuine SQLite header corruption must rotate to .corrupt.*');
      healedDb.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('2. Phase 1 Temp-File ENOSPC Mid-Write: 0 files modified on disk, 0 .krusch-tmp-* orphans, and 0 fd leaks', () => {
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      fs.writeFileSync(path.join(ws, 'src', 'one.js'), 'export const one = 1;\n', 'utf8');
      fs.writeFileSync(path.join(ws, 'src', 'three.js'), 'export const three = 3;\n', 'utf8');

      let writeCalls = 0;
      let failWrite = false;
      const faultFs = createFaultFs({
        writeSync: (fd, buf, offset, length) => {
          writeCalls++;
          if (failWrite && writeCalls === 2) {
            throw makeOsError('ENOSPC', 'no space left on device while writing temp file #2');
          }
          return fs.writeSync(fd, buf, offset, length);
        }
      });

      const db = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const harness = createHarnessEngine({ db, workspaceRoot: ws, fsOps: faultFs });

      const staged = harness.run({
        goal: 'Update three modules atomically',
        edits: [
          { file_path: 'src/one.js', content: 'export const one = 10;\n' },
          { file_path: 'src/two.js', content: 'export const two = 20;\n' },
          { file_path: 'src/three.js', content: 'export const three = 30;\n' }
        ]
      });
      assert.equal(staged.ok, true);

      failWrite = true;
      const res = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(res.ok, false);
      assert.match(res.data.error, /ENOSPC/);

      assert.equal(fs.readFileSync(path.join(ws, 'src', 'one.js'), 'utf8'), 'export const one = 1;\n');
      assert.equal(fs.existsSync(path.join(ws, 'src', 'two.js')), false);
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'three.js'), 'utf8'),
        'export const three = 3;\n'
      );
      assert.deepEqual(listTempOrphans(ws), [], 'Must leave 0 .krusch-tmp-* files behind');
      assert.equal(faultFs.openFds.size, 0, 'Must close all file descriptors on ENOSPC');
      assert.equal(harness.taskStatus({ task_id: staged.data.task_id }).data.status, 'STAGED');
      db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('3. Phase 3 Single-Fault Mid-Rename Rollback: restores edited file, unlinks newly created file, marks journal ROLLED_BACK', () => {
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      fs.writeFileSync(path.join(ws, 'src', 'existing1.js'), 'export const a = "base-1";\n', 'utf8');
      fs.writeFileSync(path.join(ws, 'src', 'existing3.js'), 'export const c = "base-3";\n', 'utf8');

      let renameCount = 0;
      let injectRenameFault = false;
      const faultFs = createFaultFs({
        renameSync: (oldPath, newPath) => {
          if (injectRenameFault) {
            renameCount++;
            if (renameCount === 3) {
              throw makeOsError('EIO', 'simulated storage I/O error on 3rd rename');
            }
          }
          return fs.renameSync(oldPath, newPath);
        }
      });

      const db = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const harness = createHarnessEngine({ db, workspaceRoot: ws, fsOps: faultFs });

      const staged = harness.run({
        goal: 'Edit 2 existing files and create 1 new file',
        edits: [
          { file_path: 'src/existing1.js', content: 'export const a = "next-1";\n' },
          { file_path: 'src/created2.js', content: 'export const b = "created-2";\n' },
          { file_path: 'src/existing3.js', content: 'export const c = "next-3";\n' }
        ]
      });
      assert.equal(staged.ok, true);

      injectRenameFault = true;
      const applyRes = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(applyRes.ok, false);
      assert.equal(applyRes.data.rolled_back, true);

      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'existing1.js'), 'utf8'),
        'export const a = "base-1";\n'
      );
      assert.equal(fs.existsSync(path.join(ws, 'src', 'created2.js')), false);
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'existing3.js'), 'utf8'),
        'export const c = "base-3";\n'
      );
      assert.deepEqual(listTempOrphans(ws), []);
      assert.equal(faultFs.openFds.size, 0);

      const journal = db
        .prepare('SELECT state FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.equal(journal.state, 'ROLLED_BACK');
      assert.equal(harness.taskStatus({ task_id: staged.data.task_id }).data.status, 'STAGED');
      db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('4. COMPOUND FAULT #1 (ENOSPC during rollback itself -> RECOVERY_PENDING -> deferred recoverInFlight & clean retry)', () => {
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      const base1 = 'export const alpha = "original-alpha";\n';
      const base2 = 'export const beta = "original-beta";\n';
      fs.writeFileSync(path.join(ws, 'src', 'file1.js'), base1, 'utf8');
      fs.writeFileSync(path.join(ws, 'src', 'file2.js'), base2, 'utf8');

      let diskFull = false;
      let phase3Renames = 0;
      const faultFs = createFaultFs({
        renameSync: (oldPath, newPath) => {
          if (diskFull) {
            phase3Renames++;
            // Rename #1 (file1.js) succeeds; Rename #2 (file2.js) fails with ENOSPC
            if (phase3Renames >= 2) {
              throw makeOsError('ENOSPC', 'no space left on device during rename #2');
            }
          }
          return fs.renameSync(oldPath, newPath);
        },
        writeSync: (fd, buf, offset, length) => {
          // Once rename #2 has tripped ENOSPC, rollback's atomicRestoreFile writeSync ALSO hits ENOSPC!
          if (diskFull && phase3Renames >= 2) {
            throw makeOsError('ENOSPC', 'no space left on device during rollback restore write');
          }
          return fs.writeSync(fd, buf, offset, length);
        }
      });

      const db = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const harness = createHarnessEngine({ db, workspaceRoot: ws, fsOps: faultFs });

      const staged = harness.run({
        goal: 'Compound rollback ENOSPC test',
        edits: [
          { file_path: 'src/file1.js', content: 'export const alpha = "mutated-alpha";\n' },
          { file_path: 'src/file2.js', content: 'export const beta = "mutated-beta";\n' }
        ]
      });
      const secondTask = harness.run({
        goal: 'Unrelated task blocked while compound recovery pending',
        edits: [{ file_path: 'src/other.js', content: 'export const other = 1;\n' }]
      });

      diskFull = true;
      const compoundRes = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(compoundRes.ok, false);
      assert.equal(compoundRes.data.compound_error, true);
      assert.equal(compoundRes.data.recovery_pending, true);
      assert.equal(compoundRes.data.rollback_errors.length, 1);
      assert.equal(faultFs.openFds.size, 0);

      // Journal MUST be RECOVERY_PENDING (NEVER falsely ROLLED_BACK while file1.js is still mutated!)
      const tornJournal = db
        .prepare('SELECT state, last_error FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.equal(tornJournal.state, 'RECOVERY_PENDING');
      assert.match(tornJournal.last_error, /ENOSPC/);
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'file1.js'), 'utf8'),
        'export const alpha = "mutated-alpha";\n'
      );

      // Attempting another applyDiff while ENOSPC persists is blocked by pending recovery
      const blockedApply = harness.applyDiff({ task_id: secondTask.data.task_id });
      assert.equal(blockedApply.ok, false);
      assert.equal(blockedApply.data.recovery_pending, true);
      assert.equal(fs.existsSync(path.join(ws, 'src', 'other.js')), false);

      // Clear ENOSPC fault -> recoverInFlight repairs file1.js byte-for-byte back to base1
      diskFull = false;
      const rec = harness.recoverInFlight();
      assert.equal(rec.ok, true);
      assert.equal(rec.data.recovered_count, 1);
      assert.equal(rec.data.outcomes[0].outcome, 'ROLLED_BACK_TO_STAGED');
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'file1.js'), 'utf8'), base1);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'file2.js'), 'utf8'), base2);

      const healedJournal = db
        .prepare('SELECT state FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.equal(healedJournal.state, 'ROLLED_BACK');

      // Retrying applyDiff now succeeds cleanly
      const retryRes = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(retryRes.ok, true);
      assert.equal(retryRes.data.status, 'APPLIED');
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'file1.js'), 'utf8'),
        'export const alpha = "mutated-alpha";\n'
      );
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'file2.js'), 'utf8'),
        'export const beta = "mutated-beta";\n'
      );
      db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('5. COMPOUND FAULT #2 (SQLITE_FULL on Phase 4 APPLIED commit + SQLITE_NOMEM OOM during 1st recovery -> 2nd recovery promotes APPLIED)', () => {
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      fs.writeFileSync(path.join(ws, 'src', 'svc.js'), 'export const ver = 1;\n', 'utf8');

      let sqlFaultMode = 'none';
      const rawDb = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const faultDb = createFaultDbProxy(rawDb, (op, sql) => {
        if (sqlFaultMode === 'phase4_full' && op === 'run' && sql.includes("SET status = 'APPLIED'")) {
          return makeSqliteError(13, 'database or disk is full');
        }
        if (sqlFaultMode === 'recovery_oom' && (op === 'exec' || op === 'run')) {
          if (sql.includes('BEGIN IMMEDIATE') || sql.includes('UPDATE harness_')) {
            return makeSqliteError(7, 'out of memory');
          }
        }
        return null;
      });

      const harness = createHarnessEngine({ db: faultDb, workspaceRoot: ws });
      const staged = harness.run({
        goal: 'Apply two files then fault SQLite commit',
        edits: [
          { file_path: 'src/svc.js', content: 'export const ver = 2;\n' },
          { file_path: 'src/new-helper.js', content: 'export const helper = true;\n' }
        ]
      });
      assert.equal(staged.ok, true);

      // Trigger SQLITE_FULL right after both files rename cleanly on disk
      sqlFaultMode = 'phase4_full';
      const applyFail = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(applyFail.ok, false);
      assert.equal(applyFail.data.recovery_pending, true);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'svc.js'), 'utf8'), 'export const ver = 2;\n');
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'new-helper.js'), 'utf8'),
        'export const helper = true;\n'
      );

      // Recovery attempt #1 hits SQLITE_NOMEM (OOM during recovery!)
      sqlFaultMode = 'recovery_oom';
      const oomRec = harness.recoverInFlight();
      assert.equal(oomRec.ok, false);
      assert.equal(oomRec.data.pending_errors.length, 1);
      assert.match(oomRec.data.pending_errors[0].error, /out of memory/);

      // Journal must STILL be in APPLYING or RECOVERY_PENDING, and task still STAGED
      const midJournal = rawDb
        .prepare('SELECT state FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.ok(
        midJournal.state === 'APPLYING' || midJournal.state === 'RECOVERY_PENDING',
        `Expected active recovery state, got ${midJournal.state}`
      );
      assert.equal(harness.taskStatus({ task_id: staged.data.task_id }).data.status, 'STAGED');

      // OOM clears -> retrying applyDiff auto-recovers via staged_sha256 and promotes to APPLIED!
      sqlFaultMode = 'none';
      const recoveredApply = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(recoveredApply.ok, true);
      assert.equal(recoveredApply.data.status, 'APPLIED');
      assert.equal(recoveredApply.data.recovered, true);

      const finalJournal = rawDb
        .prepare('SELECT state, last_error FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.equal(finalJournal.state, 'APPLIED');
      assert.equal(finalJournal.last_error, null);
      assert.equal(harness.taskStatus({ task_id: staged.data.task_id }).data.status, 'APPLIED');
      rawDb.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('6. COMPOUND FAULT #3 (EIO halfway through recoverInFlight() of a 3-file partial crash -> 2nd recovery finishes cleanly)', () => {
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      const baseA = 'export const A = "base-A";\n';
      const baseB = 'export const B = "base-B";\n';
      const baseC = 'export const C = "base-C";\n';
      fs.writeFileSync(path.join(ws, 'src', 'a.js'), baseA, 'utf8');
      fs.writeFileSync(path.join(ws, 'src', 'b.js'), baseB, 'utf8');
      fs.writeFileSync(path.join(ws, 'src', 'c.js'), baseC, 'utf8');

      let mode = 'normal';
      let renameCounter = 0;
      let recoveryRestoreCounter = 0;

      const faultFs = createFaultFs({
        renameSync: (oldPath, newPath) => {
          if (mode === 'simulate_partial_crash') {
            renameCounter++;
            // Rename A and B on disk, then simulate abrupt crash before C is renamed
            if (renameCounter === 3) {
              throw makeOsError('EIO', 'abrupt storage drop before renaming file C');
            }
          }
          if (mode === 'fail_rollback_during_crash1' || (mode === 'simulate_partial_crash' && renameCounter >= 3)) {
            // Simulate hard process crash where in-memory rollback never got to complete
            throw makeOsError('EIO', 'storage offline preventing immediate rollback');
          }
          if (mode === 'fail_mid_recovery_1') {
            recoveryRestoreCounter++;
            // In reverse order [B, A], let first file restore succeed and fail on second restore!
            if (recoveryRestoreCounter === 2) {
              throw makeOsError('EIO', 'EIO mid-flight during recoverInFlight second file restore');
            }
          }
          return fs.renameSync(oldPath, newPath);
        }
      });

      const db = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const harness = createHarnessEngine({ db, workspaceRoot: ws, fsOps: faultFs });

      const staged = harness.run({
        goal: 'Three-file atomic update with mid-recovery EIO',
        edits: [
          { file_path: 'src/a.js', content: 'export const A = "staged-A";\n' },
          { file_path: 'src/b.js', content: 'export const B = "staged-B";\n' },
          { file_path: 'src/c.js', content: 'export const C = "staged-C";\n' }
        ]
      });

      // Crash #1: A and B renamed on disk, C untouched, immediate rollback blocked by offline storage
      mode = 'simulate_partial_crash';
      const crash1 = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(crash1.ok, false);
      assert.equal(crash1.data.compound_error, true);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'a.js'), 'utf8'), 'export const A = "staged-A";\n');
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'b.js'), 'utf8'), 'export const B = "staged-B";\n');
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'c.js'), 'utf8'), baseC);

      // Recovery #1: Restores B to baseB, then hits EIO while restoring A!
      mode = 'fail_mid_recovery_1';
      const rec1 = harness.recoverInFlight();
      assert.equal(rec1.ok, false);
      assert.equal(rec1.data.pending_errors.length, 1);

      const midJournal = db
        .prepare('SELECT state, last_error FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.equal(midJournal.state, 'RECOVERY_PENDING');
      assert.match(midJournal.last_error, /EIO/);

      // B was restored in Recovery #1, A is still staged, C is untouched
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'b.js'), 'utf8'), baseB);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'a.js'), 'utf8'), 'export const A = "staged-A";\n');
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'c.js'), 'utf8'), baseC);

      // Recovery #2 (after EIO clears): detects B & C untouched, A renamed -> restores A and finalizes ROLLED_BACK!
      mode = 'normal';
      const rec2 = harness.recoverInFlight();
      assert.equal(rec2.ok, true);
      assert.equal(rec2.data.recovered_count, 1);
      assert.equal(rec2.data.outcomes[0].outcome, 'ROLLED_BACK_TO_STAGED');

      assert.equal(fs.readFileSync(path.join(ws, 'src', 'a.js'), 'utf8'), baseA);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'b.js'), 'utf8'), baseB);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'c.js'), 'utf8'), baseC);
      assert.deepEqual(listTempOrphans(ws), []);
      assert.equal(faultFs.openFds.size, 0);

      const finalJournal = db
        .prepare('SELECT state, last_error FROM harness_apply_journal WHERE task_id = ?')
        .get(staged.data.task_id);
      assert.equal(finalJournal.state, 'ROLLED_BACK');
      assert.equal(finalJournal.last_error, null);
      assert.equal(harness.taskStatus({ task_id: staged.data.task_id }).data.status, 'STAGED');
      db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('7. Pre-commit working-tree drift guard, Case C recovery drift protection, and fsyncDirectory tolerance', () => {
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      fs.writeFileSync(path.join(ws, 'src', 'drift.js'), 'export const x = 1;\n', 'utf8');

      // Verify fsyncDirectory tolerates EINVAL/EISDIR while propagating EIO
      assert.doesNotThrow(() =>
        fsyncDirectory(ws, {
          openSync: () => 99,
          fsyncSync: () => {
            throw makeOsError('EINVAL', 'directory fsync unsupported');
          },
          closeSync: () => {}
        })
      );
      assert.throws(
        () =>
          fsyncDirectory(ws, {
            openSync: () => 99,
            fsyncSync: () => {
              throw makeOsError('EIO', 'hardware I/O failure');
            },
            closeSync: () => {}
          }),
        /EIO/
      );

      const db = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const harness = createHarnessEngine({ db, workspaceRoot: ws });

      // Pre-commit drift detection before applyDiff touches disk
      const staged = harness.run({
        goal: 'Attempt edit on file modified externally',
        edits: [{ file_path: 'src/drift.js', content: 'export const x = 2;\n' }]
      });
      fs.writeFileSync(path.join(ws, 'src', 'drift.js'), 'export const x = 999;\n', 'utf8');

      const driftRes = harness.applyDiff({ task_id: staged.data.task_id });
      assert.equal(driftRes.ok, false);
      assert.equal(driftRes.data.error, 'WORKING_TREE_DRIFT_DETECTED');
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'drift.js'), 'utf8'), 'export const x = 999;\n');

      // Case C: External manual edit while journal row is APPLYING never clobbers user's file
      const staged2 = harness.run({
        goal: 'Crash recovery drift protection',
        edits: [{ file_path: 'src/drift.js', content: 'export const x = 1000;\n' }]
      });
      db.prepare(`
        INSERT INTO harness_apply_journal (task_id, state, entries_json)
        VALUES (?, 'APPLYING', ?)
      `).run(
        staged2.data.task_id,
        JSON.stringify([
          {
            file_path: 'src/drift.js',
            has_content: true,
            existed_before: true,
            base_content: 'export const x = 999;\n',
            base_sha256: '0000000000000000000000000000000000000000000000000000000000000000',
            staged_sha256: '1111111111111111111111111111111111111111111111111111111111111111'
          }
        ])
      );
      fs.writeFileSync(path.join(ws, 'src', 'drift.js'), 'export const x = "user-manual-edit";\n', 'utf8');

      const rec = harness.recoverInFlight();
      assert.equal(rec.ok, true);
      assert.equal(rec.data.outcomes[0].outcome, 'DRIFT_REJECTED');
      assert.equal(
        fs.readFileSync(path.join(ws, 'src', 'drift.js'), 'utf8'),
        'export const x = "user-manual-edit";\n'
      );
      assert.equal(harness.taskStatus({ task_id: staged2.data.task_id }).data.status, 'REJECTED');
      db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('8. Transient EIO/EACCES during recovery inspection defers to RECOVERY_PENDING (never false DRIFT_REJECTED) and isSqliteCorruptionError handles err.cause & index names', () => {
    // Part A: isSqliteCorruptionError edge-case parity with @krusch/toolkit/db
    const diskFullCause = new Error('no space left on device');
    diskFullCause.code = 'ENOSPC';
    const wrappedQuickCheck = new Error('SQLite quick_check failed: unable to allocate temp page', {
      cause: diskFullCause
    });
    assert.equal(isSqliteCorruptionError(wrappedQuickCheck), false);
    assert.equal(
      isSqliteCorruptionError(new Error('SQLite quick_check failed: no space left on device')),
      false
    );
    // Genuine quick_check corruption mentioning an index with 'busy' or 'locked' in its name MUST still be true!
    assert.equal(
      isSqliteCorruptionError(
        new Error('SQLite quick_check failed: wrong # of entries in index idx_busy_locked_queue')
      ),
      true
    );

    // Part B: Transient EACCES on readFileSync during recoverInFlight() must defer to RECOVERY_PENDING, NOT DRIFT_REJECTED!
    const ws = makeTempDir();
    try {
      fs.mkdirSync(path.join(ws, 'src'), { recursive: true });
      const baseA = 'export const a = 1;\n';
      const baseB = 'export const b = 1;\n';
      fs.writeFileSync(path.join(ws, 'src', 'a.js'), baseA, 'utf8');
      fs.writeFileSync(path.join(ws, 'src', 'b.js'), baseB, 'utf8');

      let blockReadWithEacces = false;
      const faultFs = createFaultFs({
        readFileSync: (filePath, encoding) => {
          if (blockReadWithEacces && String(filePath).endsWith('b.js')) {
            throw makeOsError('EACCES', 'transient mount permission error during recovery scan');
          }
          return fs.readFileSync(filePath, encoding);
        }
      });

      const db = openStackDatabase({ workspaceRoot: ws, ephemeral: true });
      const harness = createHarnessEngine({ db, workspaceRoot: ws, fsOps: faultFs });
      const staged = harness.run({
        goal: 'Two-file batch with transient EACCES during recovery inspection',
        edits: [
          { file_path: 'src/a.js', content: 'export const a = 2;\n' },
          { file_path: 'src/b.js', content: 'export const b = 2;\n' }
        ]
      });

      // Simulate crash after a.js was renamed on disk, b.js untouched
      fs.writeFileSync(path.join(ws, 'src', 'a.js'), 'export const a = 2;\n', 'utf8');
      const taskRow = db
        .prepare('SELECT files_json FROM harness_tasks WHERE task_id = ?')
        .get(staged.data.task_id);
      const parsed = JSON.parse(taskRow.files_json);
      db.prepare(`
        INSERT INTO harness_apply_journal (task_id, state, entries_json)
        VALUES (?, 'APPLYING', ?)
      `).run(
        staged.data.task_id,
        JSON.stringify(
          parsed.map((item, idx) => ({
            file_path: item.file_path,
            has_content: true,
            existed_before: true,
            base_content: idx === 0 ? baseA : baseB,
            base_sha256: item.base_sha256,
            staged_sha256: item.staged_sha256
          }))
        )
      );

      // Recovery #1 with transient EACCES on b.js MUST defer to RECOVERY_PENDING, NOT mark task REJECTED!
      blockReadWithEacces = true;
      const rec1 = harness.recoverInFlight();
      assert.equal(rec1.ok, false);
      assert.equal(rec1.data.pending_errors.length, 1);
      assert.match(rec1.data.pending_errors[0].error, /EACCES/);
      assert.equal(harness.taskStatus({ task_id: staged.data.task_id }).data.status, 'STAGED');

      // Recovery #2 after EACCES clears restores a.js to baseA and marks ROLLED_BACK
      blockReadWithEacces = false;
      const rec2 = harness.recoverInFlight();
      assert.equal(rec2.ok, true);
      assert.equal(rec2.data.outcomes[0].outcome, 'ROLLED_BACK_TO_STAGED');
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'a.js'), 'utf8'), baseA);
      assert.equal(fs.readFileSync(path.join(ws, 'src', 'b.js'), 'utf8'), baseB);
      db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });
});
