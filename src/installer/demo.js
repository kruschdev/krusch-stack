/**
 * @module installer/demo
 * Zero-cloud 3-act progressive onboarding walkthrough for KruschStack (`npx krusch-stack demo`).
 * Enforces INV-STACK-01 (zero external npm dependencies, native node:sqlite),
 * INV-STACK-02 (deterministic okEnvelope contract),
 * INV-STACK-04 (sanitized public defaults, zero private IPs or hostnames),
 * and INV-STACK-15 (<1s deterministic local execution with zero network calls).
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { okEnvelope, openStackDatabase } from '../db/sqlite.js';
import { createContextEngine } from '../engines/context-engine.js';
import { createHarnessEngine } from '../engines/harness-engine.js';
import { createGroundedHarnessEngine } from '../engines/grounded-harness-engine.js';

/**
 * Open an isolated KruschStack demo session over a concrete SQLite file path
 * without introducing any circular import on `src/index.js`.
 *
 * @param {object} params
 * @param {string} params.workspaceRoot
 * @param {string} params.dbPath
 * @param {Function} [params.createStackFn]
 */
function openDemoSession({ workspaceRoot, dbPath, createStackFn }) {
  if (typeof createStackFn === 'function') {
    const custom = createStackFn({
      workspaceRoot,
      dbPath,
      ephemeral: false,
      autoEmbed: false
    });
    const db =
      custom?.db ||
      openStackDatabase({
        workspaceRoot,
        dbPath,
        ephemeral: false
      });
    const context =
      custom?.context ||
      createContextEngine({
        db,
        workspaceRoot,
        ephemeral: false,
        autoEmbed: false
      });
    const harness =
      custom?.harness ||
      createHarnessEngine({
        db,
        workspaceRoot,
        contextEngine: context
      });
    const groundedHarness =
      custom?.groundedHarness ||
      createGroundedHarnessEngine({
        db,
        workspaceRoot
      });

    return {
      db,
      context,
      harness,
      groundedHarness,
      close() {
        if (typeof custom?.close === 'function') {
          custom.close();
        } else if (db && typeof db.close === 'function') {
          db.close();
        }
      }
    };
  }

  const db = openStackDatabase({
    workspaceRoot,
    dbPath,
    ephemeral: false
  });
  const context = createContextEngine({
    db,
    workspaceRoot,
    ephemeral: false,
    autoEmbed: false
  });
  const harness = createHarnessEngine({
    db,
    workspaceRoot,
    contextEngine: context
  });
  const groundedHarness = createGroundedHarnessEngine({
    db,
    workspaceRoot
  });

  return {
    db,
    context,
    harness,
    groundedHarness,
    close() {
      db.close();
    }
  };
}

/**
 * Run the deterministic 3-act KruschStack value walkthrough in an isolated temporary workspace.
 *
 * @param {object} [options={}]
 * @param {Function} [options.createStackFn]
 * @returns {{ ok: boolean, tool: string, summary: string, data: object }}
 */
export function runStackDemo({ createStackFn } = {}) {
  const startedAt = Date.now();
  const wsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-demo-'));
  const dbPath = path.join(wsDir, '.krusch-stack', 'stack.db');

  let session1 = null;
  let session2 = null;

  try {
    const srcDir = path.join(wsDir, 'src');
    const payPath = path.join(srcDir, 'pay.js');
    const feePath = path.join(srcDir, 'fee.js');

    fs.mkdirSync(srcDir, { recursive: true });
    fs.writeFileSync(
      payPath,
      'export function chargeCard(cents) {\n  return Math.round(cents);\n}\n',
      'utf8'
    );

    const acts = [];

    // Act 1: Cross-Session Invariant Memory (cold SQLite restart + INV-12 span verification)
    session1 = openDemoSession({ workspaceRoot: wsDir, dbPath, createStackFn });
    const rememberRes = session1.context.remember({
      category: 'invariant',
      content: 'Never use eval() in payment modules',
      provenance: {
        file: 'src/pay.js',
        locator: 'L1-L3',
        quoted_sentence: 'return Math.round(cents);'
      }
    });
    session1.close();
    session1 = null;

    const persistedOnDisk = fs.existsSync(dbPath);
    session2 = openDemoSession({ workspaceRoot: wsDir, dbPath, createStackFn });
    const retrieveRes = session2.context.retrieve({ query: 'payment eval' });
    const retrievedItems = Array.isArray(retrieveRes?.data?.items) ? retrieveRes.data.items : [];
    const topMemory = retrievedItems[0] || null;
    const act1Passed = Boolean(
      rememberRes?.ok &&
        persistedOnDisk &&
        retrieveRes?.ok &&
        retrievedItems.length >= 1 &&
        topMemory?.drift_status === 'VALID'
    );

    acts.push({
      act: 1,
      title: 'Cross-Session Invariant Memory',
      passed: act1Passed,
      details: {
        memory_id: rememberRes?.data?.id ?? null,
        persisted_on_disk: persistedOnDisk,
        retrieved_count: retrievedItems.length,
        drift_status: topMemory?.drift_status ?? null
      }
    });

    // Act 2: Unsafe Edit, Spin-Loop & Output-Defect Refusal
    const unsafeRun = session2.harness.run({
      goal: 'Add dynamic fee parser',
      edits: [
        {
          file_path: 'src/fee.js',
          content: 'export const parseFee = (x) => eval(x);\n'
        }
      ]
    });
    const feeExistsAfterBlock = fs.existsSync(feePath);

    session2.groundedHarness.startSession({
      session_id: 'demo-gh',
      goal: 'Audit fee rate',
      model: 'gemma4:31b'
    });
    const firstRead = session2.groundedHarness.interceptToolCall({
      session_id: 'demo-gh',
      step: 1,
      tool_name: 'read_ledger',
      args: { account_id: 'acct_demo' }
    });
    session2.groundedHarness.recordToolOutcome({
      session_id: 'demo-gh',
      event_id: firstRead?.data?.event_id,
      ok: false,
      result_preview: 'Ledger RPC timeout'
    });
    const repeatRead = session2.groundedHarness.interceptToolCall({
      session_id: 'demo-gh',
      step: 2,
      tool_name: 'read_ledger',
      args: { account_id: 'acct_demo' },
      block_spin_loop: true
    });
    const spinLoopDecision =
      repeatRead?.data?.reason === 'BLOCK_SPIN_LOOP'
        ? 'BLOCK_SPIN_LOOP'
        : repeatRead?.data?.decision || null;

    const defectStop = session2.groundedHarness.verifyStop({
      session_id: 'demo-gh',
      candidate_answer: 'np.float64(0.015)',
      expect_non_empty_answer: true
    });
    const defectDecision = defectStop?.data?.action || defectStop?.data?.decision || null;
    const defectCode = defectStop?.data?.reason || null;

    const act2Passed = Boolean(
      unsafeRun?.data?.status === 'BLOCKED_INVARIANT' &&
        feeExistsAfterBlock === false &&
        repeatRead?.data?.decision === 'BLOCK' &&
        spinLoopDecision === 'BLOCK_SPIN_LOOP' &&
        defectDecision === 'REJECT_OUTPUT_DEFECT' &&
        defectCode === 'RAW_DATAFRAME_OR_NUMPY_REPR'
    );

    acts.push({
      act: 2,
      title: 'Unsafe Edit, Spin-Loop & Output-Defect Refusal',
      passed: act2Passed,
      details: {
        unsafe_task_id: unsafeRun?.data?.task_id ?? null,
        unsafe_status: unsafeRun?.data?.status ?? null,
        fee_written_on_block: feeExistsAfterBlock,
        spin_loop_decision: spinLoopDecision,
        output_defect_decision: defectDecision,
        output_defect_code: defectCode
      }
    });

    // Act 3: Verified 2PC Stage & Atomic Apply
    const stagedRun = session2.harness.run({
      goal: 'Add integer fee helper',
      edits: [
        {
          file_path: 'src/fee.js',
          content: 'export const calcFeeCents = (cents) => Math.floor(cents * 0.015);\n'
        }
      ]
    });
    const feeExistsWhileStaged = fs.existsSync(feePath);
    const applyRes = session2.harness.applyDiff({
      task_id: stagedRun?.data?.task_id
    });
    const feeExistsAfterApply = fs.existsSync(feePath);

    const act3Passed = Boolean(
      stagedRun?.data?.status === 'STAGED' &&
        feeExistsWhileStaged === false &&
        applyRes?.ok &&
        applyRes?.data?.status === 'APPLIED' &&
        feeExistsAfterApply === true
    );

    acts.push({
      act: 3,
      title: 'Verified 2PC Stage & Atomic Apply',
      passed: act3Passed,
      details: {
        task_id: stagedRun?.data?.task_id ?? null,
        staged_status: stagedRun?.data?.status ?? null,
        fee_exists_while_staged: feeExistsWhileStaged,
        applied_status: applyRes?.data?.status ?? null,
        fee_exists_after_apply: feeExistsAfterApply
      }
    });

    const durationMs = Math.max(1, Date.now() - startedAt);
    const allPassed = acts.every((item) => item.passed);
    const passedCount = acts.filter((item) => item.passed).length;
    const summary = allPassed
      ? `KruschStack 3-act local demo passed (${passedCount}/3 acts in ${durationMs}ms, zero cloud calls).`
      : `KruschStack demo completed with failures (${passedCount}/3 acts passed in ${durationMs}ms).`;

    return okEnvelope(
      'krusch_stack_demo',
      summary,
      {
        duration_ms: durationMs,
        zero_cloud_calls: true,
        all_passed: allPassed,
        acts
      },
      allPassed
    );
  } finally {
    try {
      session1?.close?.();
    } catch {
      /* ignore cleanup close error */
    }
    try {
      session2?.close?.();
    } catch {
      /* ignore cleanup close error */
    }
    try {
      fs.rmSync(wsDir, { recursive: true, force: true });
    } catch {
      /* ignore temp workspace removal error */
    }
  }
}

/**
 * Format a concise (<25 lines) terminal report for `npx krusch-stack demo`.
 * Uses ASCII `--` and `->` separators only (zero em dashes or private hostnames).
 *
 * @param {{ ok?: boolean, summary?: string, data?: object }} demoResult
 * @returns {string}
 */
export function formatStackDemoText(demoResult = {}) {
  const data = demoResult?.data || {};
  const acts = Array.isArray(data.acts) ? data.acts : [];
  const act1 = acts[0]?.details || {};
  const act2 = acts[1]?.details || {};
  const act3 = acts[2]?.details || {};
  const badge = (passed) => (passed ? '[PASS]' : '[FAIL]');

  const lines = [
    'KruschStack Local Value Walkthrough (node:sqlite, zero cloud calls)',
    '===================================================================',
    `${badge(acts[0]?.passed)} Act 1 -- Cross-Session Invariant Memory`,
    `  Session 1 stored invariant #${act1.memory_id ?? '?'} -> cold-started Session 2 retrieved ${act1.retrieved_count ?? 0} item(s) (span=${act1.drift_status ?? 'UNKNOWN'})`,
    `${badge(acts[1]?.passed)} Act 2 -- Unsafe Edit, Spin-Loop & Output-Defect Refusal`,
    `  2PC edit eval(x) -> ${act2.unsafe_status ?? 'UNKNOWN'} (src/fee.js untouched=${act2.fee_written_on_block === false})`,
    `  Repeat failing read_ledger -> ${act2.spin_loop_decision ?? 'UNKNOWN'}`,
    `  Stop answer np.float64(0.015) -> ${act2.output_defect_decision ?? 'UNKNOWN'} (${act2.output_defect_code ?? 'UNKNOWN'})`,
    `${badge(acts[2]?.passed)} Act 3 -- Verified 2PC Stage & Atomic Apply`,
    `  Clean integer fee helper -> ${act3.staged_status ?? 'UNKNOWN'} (disk untouched=${act3.fee_exists_while_staged === false}) -> ${act3.applied_status ?? 'UNKNOWN'} (on disk=${Boolean(act3.fee_exists_after_apply)})`,
    '-------------------------------------------------------------------',
    `Result: ${data.all_passed ? 'ALL 3 ACTS PASSED' : 'FAILED'} in ${data.duration_ms ?? 0}ms | Cloud API calls: 0`
  ];

  return lines.join('\n');
}
