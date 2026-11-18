#!/usr/bin/env node
/**
 * @module scripts/reproduce_clean_room
 * Zero-API-key, zero-cloud clean-room verification and reproduction suite (`INV-STACK-15`).
 * Executes 5 deterministic seed-fixed gates across Tier 1, Tier 3A (2PC + SIGKILL journal + Action Harness),
 * and Tier 3B (Turn-0 Grounded Harness + Defect-Only Output Gate), computing an identical SHA-256
 * receipt digest across repeated runs and clean clones.
 * Enforces INV-STACK-04 (sanitized public defaults) and INV-SOLO-VOICE-01 (no plural pronouns or em dashes).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { openStackDatabase, okEnvelope } from '../src/db/sqlite.js';
import { createContextEngine } from '../src/engines/context-engine.js';
import { createHarnessEngine } from '../src/engines/harness-engine.js';
import { createActionHarnessEngine } from '../src/engines/action-harness-engine.js';
import {
  createGroundedHarnessEngine,
  compileTurnZeroGrounding,
  inspectOutputDefects,
  canonicalizeGroundedToolCallKey
} from '../src/engines/grounded-harness-engine.js';
import { runStackCrashRecoveryDrill } from '../src/installer/doctor.js';

function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input ?? ''), 'utf8').digest('hex');
}

function canonicalizeForReceipt(value) {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeForReceipt(item));
  }
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) {
      sorted[key] = canonicalizeForReceipt(value[key]);
    }
  }
  return sorted;
}

/**
 * Gate 1: Tier 1 Working Memory, Lineage Forwarding, INV-12 Span Drift, and Pre-Commit Nudge.
 */
function runGate1MemoryLineageAndDrift(workspaceDir, db) {
  const t0 = performance.now();
  const srcDir = path.join(workspaceDir, 'src');
  fs.mkdirSync(srcDir, { recursive: true });

  const settlementRel = 'src/settlement.js';
  const settlementAbs = path.join(workspaceDir, settlementRel);
  const initialSource = [
    'export function settleCents(amountCents, feeBps) {',
    '  return amountCents - Math.round((amountCents * feeBps) / 10000);',
    '}',
    ''
  ].join('\n');
  fs.writeFileSync(settlementAbs, initialSource, 'utf8');

  const contextEngine = createContextEngine({
    db,
    workspaceRoot: workspaceDir,
    ephemeral: true,
    autoEmbed: false
  });

  const invariantMem = contextEngine.remember({
    category: 'invariant',
    content: 'Never use eval() in settlement math modules.',
    provenance: {
      file: settlementRel,
      locator: 'L1-L3',
      quoted_sentence: 'return amountCents - Math.round((amountCents * feeBps) / 10000);'
    }
  });

  const legacyDecision = contextEngine.remember({
    category: 'decision',
    content: 'Primary cache transport uses Redis on port 6379 without mTLS.'
  });

  const superseded = contextEngine.revise({
    action: 'supersede',
    target_id: legacyDecision.data.id,
    new_content: 'Migrated primary cache transport to Valkey on port 6380 with mTLS enforced.',
    reason: 'Valkey mTLS cutover'
  });

  const lineageLookup = contextEngine.retrieve({
    query: 'Redis cache transport port 6379'
  });
  const topLineageItem = lineageLookup.data.items[0] || null;

  const beforeMutation = contextEngine.retrieve({ query: '*' });
  const invBefore = beforeMutation.data.items.find((it) => it.id === invariantMem.data.id);
  const driftBefore = invBefore ? invBefore.drift_status : 'MISSING';

  const mutatedSource = [
    'export function settleCents(amountCents, feeBps) {',
    '  return amountCents - Math.trunc((amountCents * feeBps) / 10000);',
    '}',
    ''
  ].join('\n');
  fs.writeFileSync(settlementAbs, mutatedSource, 'utf8');

  const afterMutation = contextEngine.retrieve({ query: '*' });
  const invAfter = afterMutation.data.items.find((it) => it.id === invariantMem.data.id);
  const driftAfter = invAfter ? invAfter.drift_status : 'MISSING';

  const nudgeCheck = contextEngine.nudge({
    trigger: 'pre_commit',
    code: [
      '--- a/src/settlement.js',
      '+++ b/src/settlement.js',
      '@@ -1,3 +1,4 @@',
      '+export const unsafeDynamicEval = (expr) => eval(expr);'
    ].join('\n')
  });

  const details = {
    blind_insert_ok: Boolean(invariantMem.ok && legacyDecision.ok),
    superseded_status: superseded.data?.status || null,
    lineage_terminal_id: topLineageItem ? topLineageItem.id : null,
    lineage_chain_length: Array.isArray(topLineageItem?.lineage)
      ? topLineageItem.lineage.length
      : 0,
    chronological_order: lineageLookup.data?.chronological_order || [],
    epistemic_status: lineageLookup.data?.epistemic_status || null,
    span_drift_before: driftBefore,
    span_drift_after: driftAfter,
    nudge_passed_on_violation: Boolean(nudgeCheck.data?.passed),
    nudge_findings_count: Array.isArray(nudgeCheck.data?.findings)
      ? nudgeCheck.data.findings.length
      : 0
  };

  const passed =
    details.blind_insert_ok === true &&
    details.superseded_status === 'superseded' &&
    details.lineage_terminal_id === superseded.data.new_id &&
    details.lineage_chain_length === 2 &&
    JSON.stringify(details.chronological_order) ===
      JSON.stringify([legacyDecision.data.id, superseded.data.new_id]) &&
    details.epistemic_status === 'SUPPORTED' &&
    details.span_drift_before === 'VALID' &&
    details.span_drift_after === 'STALE_DRIFT' &&
    details.nudge_passed_on_violation === false &&
    details.nudge_findings_count >= 1;

  return {
    contextEngine,
    gate: {
      id: 'tier1_memory_lineage_and_drift',
      title: 'Tier 1 Memory Blind Insert, Supersede Lineage, SHA-256 Span Drift & Pre-Commit Nudge',
      passed,
      duration_ms: Number((performance.now() - t0).toFixed(2)),
      details
    }
  };
}

/**
 * Gate 2: Tier 3A 2PC Invariant Gate (`BLOCKED_INVARIANT`), Pre-Disk Staging (`STAGED`), and Atomic Apply (`APPLIED`).
 */
function runGate2TwoPhaseCommitHarness(workspaceDir, db, contextEngine) {
  const t0 = performance.now();
  const harness = createHarnessEngine({
    db,
    workspaceRoot: workspaceDir,
    contextEngine
  });

  const unsafeRel = 'src/unsafe-runner.js';
  const unsafeAbs = path.join(workspaceDir, unsafeRel);
  const blockedRun = harness.run({
    task_id: 'cleanroom_blocked_01',
    goal: 'Attempt unsafe eval helper',
    edits: [
      {
        file_path: unsafeRel,
        content: 'export const runDynamic = (code) => eval(code);\n'
      }
    ]
  });
  const unsafeTouchedDisk = fs.existsSync(unsafeAbs);
  const blockedApplyAttempt = harness.applyDiff({ task_id: 'cleanroom_blocked_01' });

  const safeRel = 'src/bps-math.js';
  const safeAbs = path.join(workspaceDir, safeRel);
  const safeContent = 'export function bpsToDecimal(bps) {\n  return bps / 10000;\n}\n';
  const stagedRun = harness.run({
    task_id: 'cleanroom_staged_01',
    goal: 'Stage safe basis-points helper',
    edits: [{ file_path: safeRel, content: safeContent }]
  });
  const existedBeforeApply = fs.existsSync(safeAbs);

  const appliedRun = harness.applyDiff({ task_id: 'cleanroom_staged_01' });
  const existsAfterApply = fs.existsSync(safeAbs);
  const appliedDiskSha256 = existsAfterApply
    ? sha256Hex(fs.readFileSync(safeAbs, 'utf8'))
    : null;
  const expectedSha256 = sha256Hex(safeContent);

  const details = {
    blocked_status: blockedRun.data?.status || null,
    blocked_disk_untouched: unsafeTouchedDisk === false,
    blocked_apply_rejected: blockedApplyAttempt.ok === false,
    staged_status: stagedRun.data?.status || null,
    staged_has_unified_diff: Boolean(
      stagedRun.data?.unified_diff && stagedRun.data.unified_diff.includes('+export function bpsToDecimal')
    ),
    staged_pre_apply_disk_untouched: existedBeforeApply === false,
    applied_status: appliedRun.data?.status || null,
    applied_disk_exists: existsAfterApply === true,
    applied_sha256_match: appliedDiskSha256 === expectedSha256,
    applied_file_sha256: appliedDiskSha256
  };

  const passed =
    details.blocked_status === 'BLOCKED_INVARIANT' &&
    details.blocked_disk_untouched &&
    details.blocked_apply_rejected &&
    details.staged_status === 'STAGED' &&
    details.staged_has_unified_diff &&
    details.staged_pre_apply_disk_untouched &&
    details.applied_status === 'APPLIED' &&
    details.applied_disk_exists &&
    details.applied_sha256_match;

  return {
    id: 'tier3a_2pc_invariant_and_atomic_apply',
    title: 'Tier 3A 2PC Invariant Block, Unified Diff Staging & Atomic Disk Apply',
    passed,
    duration_ms: Number((performance.now() - t0).toFixed(2)),
    details
  };
}

/**
 * Gate 3: Tier 3A Live 2-Process OS `SIGKILL` Write-Ahead Apply-Journal Crash Recovery Drill.
 */
async function runGate3SigkillCrashRecoveryDrill(includeCrashDrill) {
  const t0 = performance.now();
  if (includeCrashDrill === false) {
    return {
      id: 'tier3a_sigkill_crash_recovery_drill',
      title: 'Tier 3A 2-Process SIGKILL Mid-Apply Journal Rollback Drill (Skipped via Flag)',
      passed: true,
      duration_ms: Number((performance.now() - t0).toFixed(2)),
      details: {
        skipped: true,
        converged: null,
        worker_killed_signal: null,
        journal_state_before: null,
        journal_state_after: null,
        half_written_files: null,
        orphaned_temp_cleaned: null,
        distinct_recovery_process: null
      }
    };
  }

  const drill = await runStackCrashRecoveryDrill();
  const data = drill.data || {};
  const distinctProcesses = Boolean(
    data.workerPid && data.recoveryPid && data.workerPid !== data.recoveryPid
  );

  const details = {
    skipped: false,
    converged: Boolean(drill.ok && data.converged),
    worker_killed_signal: data.workerKilledSignal || null,
    journal_state_before: data.journalStateBefore || null,
    journal_state_after: data.journalStateAfter || null,
    half_written_files_before_recovery:
      typeof data.halfWrittenFilesBeforeRecovery === 'number'
        ? data.halfWrittenFilesBeforeRecovery
        : null,
    half_written_files: typeof data.halfWrittenFiles === 'number' ? data.halfWrittenFiles : null,
    orphaned_temp_cleaned: Boolean(data.orphanedTempCleaned),
    distinct_recovery_process: distinctProcesses
  };

  const passed =
    details.converged === true &&
    details.worker_killed_signal === 'SIGKILL' &&
    details.journal_state_before === 'APPLYING' &&
    details.journal_state_after === 'ROLLED_BACK' &&
    details.half_written_files === 0 &&
    details.orphaned_temp_cleaned === true &&
    details.distinct_recovery_process === true;

  return {
    id: 'tier3a_sigkill_crash_recovery_drill',
    title: 'Tier 3A 2-Process SIGKILL Mid-Apply Write-Ahead Journal Rollback Drill',
    passed,
    duration_ms: Number((performance.now() - t0).toFixed(2)),
    details
  };
}

/**
 * Gate 4: Tier 3A 2PC Tool-Action Harness Trajectory Gate (`INV-STACK-10`).
 */
function runGate4ActionHarnessTrajectoryGate(db, contextEngine) {
  const t0 = performance.now();
  const actionHarness = createActionHarnessEngine({ db, contextEngine });

  const sessionId = 'cleanroom_action_01';
  actionHarness.startSession({
    session_id: sessionId,
    persona: 'ops',
    goal: 'Send verified settlement summary email to finance',
    anchor_date: '2026-11-18',
    max_identical_reads: 1,
    max_duplicate_writes: 1,
    enforce_context_nudge: true
  });

  const read1 = actionHarness.interceptToolCall({
    session_id: sessionId,
    step: 1,
    tool_name: 'mcp__ledger__get_daily_summary',
    args: { date: '2026-11-18', currency: 'USD' },
    is_mutating: false
  });
  actionHarness.recordToolOutcome({
    session_id: sessionId,
    event_id: read1.data.event_id,
    status: 'COMMITTED',
    result_preview: '{"net_cents":482500}'
  });

  const duplicateRead = actionHarness.interceptToolCall({
    session_id: sessionId,
    step: 2,
    tool_name: 'mcp__ledger__get_daily_summary',
    args: { currency: 'USD', date: '2026-11-18' },
    is_mutating: false
  });

  const placeholderMutation = actionHarness.interceptToolCall({
    session_id: sessionId,
    step: 3,
    tool_name: 'mcp__mail__send_message',
    args: {
      to: 'finance@example.com',
      due_date: 'TBD',
      body: 'Summary: <insert settlement total>'
    },
    is_mutating: true
  });

  const syntheticSecret = `${'sk'}-${'cleanroomfixture0123456789'}`;
  const secretMutation = actionHarness.interceptToolCall({
    session_id: sessionId,
    step: 4,
    tool_name: 'mcp__mail__send_message',
    args: {
      to: 'finance@example.com',
      due_date: '2026-11-19',
      body: `Bearer credential ${syntheticSecret}`
    },
    is_mutating: true
  });

  const cleanMutation = actionHarness.interceptToolCall({
    session_id: sessionId,
    step: 5,
    tool_name: 'mcp__mail__send_message',
    args: {
      to: 'finance@example.com',
      due_date: '2026-11-19',
      body: 'Verified daily net settlement: $4,825.00 USD.'
    },
    is_mutating: true
  });
  actionHarness.recordToolOutcome({
    session_id: sessionId,
    event_id: cleanMutation.data.event_id,
    status: 'COMMITTED',
    result_preview: 'sent_msg_01'
  });

  const duplicateWrite = actionHarness.interceptToolCall({
    session_id: sessionId,
    step: 6,
    tool_name: 'mcp__mail__send_message',
    args: {
      body: 'Verified daily net settlement: $4,825.00 USD.',
      due_date: '2026-11-19',
      to: 'finance@example.com'
    },
    is_mutating: true
  });

  const placeholderIssueCodes = (placeholderMutation.data?.issues || [])
    .map((i) => i.code)
    .sort();
  const secretIssueCodes = (secretMutation.data?.issues || []).map((i) => i.code);

  const details = {
    first_read_decision: read1.data?.decision || null,
    duplicate_read_decision: duplicateRead.data?.decision || null,
    duplicate_read_blocked: duplicateRead.data?.allowed === false,
    placeholder_hold_decision: placeholderMutation.data?.decision || null,
    placeholder_issue_codes: placeholderIssueCodes,
    secret_hold_decision: secretMutation.data?.decision || null,
    secret_issue_codes: secretIssueCodes,
    clean_mutation_decision: cleanMutation.data?.decision || null,
    duplicate_write_decision: duplicateWrite.data?.decision || null,
    duplicate_write_blocked: duplicateWrite.data?.allowed === false
  };

  const passed =
    details.first_read_decision === 'ALLOW_READ' &&
    details.duplicate_read_decision === 'BLOCK_SPIN_LOOP' &&
    details.duplicate_read_blocked === true &&
    details.placeholder_hold_decision === 'HOLD_FOR_REVISION' &&
    details.placeholder_issue_codes.includes('UNRESOLVED_PLACEHOLDER') &&
    details.placeholder_issue_codes.includes('MALFORMED_DATE_ARGUMENT') &&
    details.secret_hold_decision === 'HOLD_FOR_REVISION' &&
    details.secret_issue_codes.includes('SECRET_LEAK_BLOCKED') &&
    details.clean_mutation_decision === 'ALLOW_MUTATION' &&
    details.duplicate_write_decision === 'BLOCK_DUPLICATE_WRITE' &&
    details.duplicate_write_blocked === true;

  return {
    id: 'tier3a_action_harness_trajectory_gate',
    title: 'Tier 3A Action Harness Spin-Loop Block, Placeholder/Secret Hold & Duplicate-Write Block',
    passed,
    duration_ms: Number((performance.now() - t0).toFixed(2)),
    details
  };
}

/**
 * Gate 5: Tier 3B Turn-0 Grounded Harness CSV `"NA"` Hazard, `.env` Exclusion, Memoized Hash & Defect Gate (`INV-STACK-11`).
 */
function runGate5GroundedHarnessAndDefectGate(groundedDir, db) {
  const t0 = performance.now();
  fs.mkdirSync(groundedDir, { recursive: true });

  fs.writeFileSync(
    path.join(groundedDir, 'merchants.csv'),
    ['merchant_id,region,fee_bps', 'm_101,NA,25', 'm_102,EU,30', ''].join('\n'),
    'utf8'
  );
  fs.writeFileSync(
    path.join(groundedDir, '.env'),
    'PRIVATE_SIGNING_SECRET=never_expose_in_turn_zero\n',
    'utf8'
  );

  const grounding = compileTurnZeroGrounding({
    workspaceDir: groundedDir,
    goal: 'Compute North America merchant fee bps average',
    model: 'gemini-4-argon'
  });

  const csvFileEntry = (grounding.data?.workspace?.files || []).find(
    (f) => f.relPath === 'merchants.csv'
  );
  const digests = grounding.data?.fileDigests || {};
  const envExcluded =
    !Object.prototype.hasOwnProperty.call(digests, '.env') &&
    !String(grounding.data?.compiledSystemPrompt || '').includes('PRIVATE_SIGNING_SECRET');
  const csvNaFlagged = Boolean(
    csvFileEntry?.hasLiteralNaHazard === true &&
      Array.isArray(csvFileEntry?.naHazardColumns) &&
      csvFileEntry.naHazardColumns.includes('region') &&
      String(grounding.data?.workspace?.schemaSummaryText || '').includes('keep_default_na=False')
  );

  const floorDivKeyA = canonicalizeGroundedToolCallKey('run_python', {
    code: 'bucket = 100 // 3  # comment alpha\nprint(bucket)\n'
  });
  const floorDivKeyB = canonicalizeGroundedToolCallKey('run_python', {
    code: 'bucket = 100 // 3  # comment beta\nprint(bucket)\n'
  });
  const floatDivKey = canonicalizeGroundedToolCallKey('run_python', {
    code: 'bucket = 100 / 3\nprint(bucket)\n'
  });
  const commentNormalizedFloorSafe =
    floorDivKeyA.callSignature === floorDivKeyB.callSignature &&
    floorDivKeyA.callSignature !== floatDivKey.callSignature;

  const groundedHarness = createGroundedHarnessEngine({
    db,
    workspaceRoot: groundedDir
  });
  const sessionId = 'cleanroom_grounded_01';
  groundedHarness.startSession({
    session_id: sessionId,
    goal: 'Compute North America merchant fee bps average',
    model: 'gemini-4-argon',
    prefix_hash: grounding.data.prefixHash,
    file_digests: grounding.data.fileDigests
  });

  const step1Read = groundedHarness.interceptToolCall({
    session_id: sessionId,
    step: 1,
    tool_name: 'run_python',
    args: { code: 'bucket = 100 // 3  # initial pass\nprint(bucket)\n' },
    mutating: false
  });
  groundedHarness.recordToolOutcome({
    session_id: sessionId,
    event_id: step1Read.data.event_id,
    ok: true,
    result_preview: '33'
  });

  const step2Memoized = groundedHarness.interceptToolCall({
    session_id: sessionId,
    step: 2,
    tool_name: 'run_python',
    args: { code: 'bucket = 100 // 3  # different comment same AST semantics\nprint(bucket)\n' },
    mutating: false
  });

  const step3Blocked = groundedHarness.interceptToolCall({
    session_id: sessionId,
    step: 3,
    tool_name: 'run_python',
    args: { code: 'bucket = 100 // 3\nprint(bucket)\n' },
    mutating: false
  });

  const defectNumpy = inspectOutputDefects({
    candidateAnswer: 'np.float64(25.0)',
    expectNonEmptyAnswer: true
  });
  const defectToolLeak = inspectOutputDefects({
    assistantText: '<tool_call>{"name":"run_python","arguments":{"code":"1+1"}}</tool_call>',
    toolCalls: []
  });
  const healthyZero = inspectOutputDefects({
    candidateAnswer: '0',
    expectNonEmptyAnswer: true
  });
  const healthyNa = inspectOutputDefects({
    candidateAnswer: 'N/A',
    expectNonEmptyAnswer: true
  });

  const stopCheckZero = groundedHarness.verifyStop({
    session_id: sessionId,
    candidate_answer: '0',
    expect_non_empty_answer: true
  });
  const summaryAfterHealthy = groundedHarness.sessionSummary({ session_id: sessionId });
  const extraVerifyTurnsOnHealthy = Number(
    summaryAfterHealthy.data?.verify_nudges_used ??
      db
        .prepare('SELECT verify_nudges_used FROM grounded_sessions WHERE session_id = ?')
        .get(sessionId)?.verify_nudges_used ??
      0
  );

  const details = {
    llm_ingestion_calls: grounding.data?.llmIngestionCalls ?? null,
    prefix_hash: grounding.data?.prefixHash || null,
    env_excluded: envExcluded,
    csv_literal_na_hazard_flagged: csvNaFlagged,
    comment_normalized_python_floor_div_safe: commentNormalizedFloorSafe,
    read_progression: [
      step1Read.data?.reason || null,
      step2Memoized.data?.reason || null,
      step3Blocked.data?.reason || null
    ],
    numpy_repr_defect_code: defectNumpy.primaryDefect?.code || null,
    serialized_tool_call_defect_code: defectToolLeak.primaryDefect?.code || null,
    valid_zero_has_defect: healthyZero.hasDefect,
    valid_na_has_defect: healthyNa.hasDefect,
    healthy_stop_action: stopCheckZero.data?.action || null,
    healthy_extra_turns: extraVerifyTurnsOnHealthy
  };

  const passed =
    details.llm_ingestion_calls === 0 &&
    typeof details.prefix_hash === 'string' &&
    details.prefix_hash.length === 64 &&
    details.env_excluded === true &&
    details.csv_literal_na_hazard_flagged === true &&
    details.comment_normalized_python_floor_div_safe === true &&
    JSON.stringify(details.read_progression) ===
      JSON.stringify(['ALLOW_READ', 'MEMOIZED_PRIOR_READ', 'BLOCK_SPIN_LOOP']) &&
    details.numpy_repr_defect_code === 'RAW_DATAFRAME_OR_NUMPY_REPR' &&
    details.serialized_tool_call_defect_code === 'SERIALIZED_TOOL_CALL_IN_TEXT' &&
    details.valid_zero_has_defect === false &&
    details.valid_na_has_defect === false &&
    details.healthy_stop_action === 'ALLOW_STOP' &&
    details.healthy_extra_turns === 0;

  return {
    id: 'tier3b_grounded_harness_turn0_and_defect_gate',
    title: 'Tier 3B Turn-0 CSV "NA" Hazard, .env Exclusion, Memoized Call Hashing & Output Defect Gate',
    passed,
    duration_ms: Number((performance.now() - t0).toFixed(2)),
    details
  };
}

/**
 * Execute all 5 deterministic clean-room verification gates with zero API keys and zero network calls.
 * @param {object} [options]
 * @param {boolean} [options.includeCrashDrill=true]
 */
export async function runCleanRoomReproduction({ includeCrashDrill = true } = {}) {
  const startedAt = performance.now();
  const cleanRoomRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-cleanroom-'));
  const mainWorkspace = path.join(cleanRoomRoot, 'workspace');
  const groundedWorkspace = path.join(cleanRoomRoot, 'grounded-workspace');

  let db = null;
  try {
    fs.mkdirSync(mainWorkspace, { recursive: true });
    db = openStackDatabase({ workspaceRoot: mainWorkspace, ephemeral: true });

    const { contextEngine, gate: gate1 } = runGate1MemoryLineageAndDrift(mainWorkspace, db);
    const gate2 = runGate2TwoPhaseCommitHarness(mainWorkspace, db, contextEngine);
    const gate3 = await runGate3SigkillCrashRecoveryDrill(includeCrashDrill !== false);
    const gate4 = runGate4ActionHarnessTrajectoryGate(db, contextEngine);
    const gate5 = runGate5GroundedHarnessAndDefectGate(groundedWorkspace, db);

    const gates = [gate1, gate2, gate3, gate4, gate5];
    const gatesPassed = gates.filter((g) => g.passed).length;
    const allPassed = gatesPassed === gates.length;

    const canonicalPayload = canonicalizeForReceipt({
      reproducer_schema: 'krusch-stack-clean-room/v1',
      include_crash_drill: Boolean(includeCrashDrill !== false),
      gates: gates.map((g) => ({
        id: g.id,
        passed: g.passed,
        details: g.details
      }))
    });
    const deterministicReceiptSha256 = sha256Hex(JSON.stringify(canonicalPayload));
    const totalDurationMs = Number((performance.now() - startedAt).toFixed(2));

    const summary = `Clean-room reproduction ${allPassed ? 'PASSED' : 'FAILED'} (${gatesPassed}/${gates.length} gates, receipt=${deterministicReceiptSha256.slice(0, 16)}...).`;

    return okEnvelope(
      'krusch_clean_room_reproducer',
      summary,
      {
        all_passed: allPassed,
        gates_passed: gatesPassed,
        gates_total: gates.length,
        include_crash_drill: Boolean(includeCrashDrill !== false),
        zero_network_calls: true,
        zero_api_keys_required: true,
        duration_ms: totalDurationMs,
        deterministic_receipt_sha256: deterministicReceiptSha256,
        gates,
        external_verification: {
          huggingface_dataset: 'https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks',
          router_arena_merged_commit:
            'https://github.com/RouteWorks/RouterArena/commit/844e93b547e6278b01994720de39bfc32ffd18bc',
          router_arena_receipts_sha256:
            'bede6659ebc8513d7f13fb7588b4ca2ec4df91c71d1accad8b9795b60d3db45e'
        }
      },
      allPassed
    );
  } finally {
    if (db) {
      try {
        db.close();
      } catch {
        // Ignore close error
      }
    }
    try {
      fs.rmSync(cleanRoomRoot, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  }
}

function formatReportText(result) {
  const { data } = result;
  const lines = [
    '====================================================================================',
    'KruschStack Clean-Room Deterministic Verification Suite (Zero Cloud / Zero API Keys)',
    '====================================================================================',
    'Status  | Gate ID                                        | Time (ms)',
    '--------+------------------------------------------------+----------'
  ];

  for (const gate of data.gates) {
    const statusLabel = gate.details?.skipped
      ? 'SKIP   '
      : gate.passed
        ? 'PASS   '
        : 'FAIL   ';
    const paddedId = gate.id.padEnd(46, ' ');
    const paddedMs = `${gate.duration_ms.toFixed(2)}ms`.padStart(9, ' ');
    lines.push(`${statusLabel} | ${paddedId} | ${paddedMs}`);
  }

  lines.push('--------+------------------------------------------------+----------');
  lines.push(
    `Result  : ${data.gates_passed}/${data.gates_total} deterministic gates passed in ${data.duration_ms.toFixed(2)}ms`
  );
  lines.push(`Receipt SHA-256: ${data.deterministic_receipt_sha256}`);
  lines.push('');
  lines.push(
    'Independent External Audit Log Verification (Hugging Face + RouteWorks/RouterArena PR #169 @ 844e93b):'
  );
  lines.push(
    'curl -fsSL https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks/resolve/main/data/scorecard_summary.jsonl | sha256sum'
  );
  lines.push(
    'curl -fsSL https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks/resolve/main/README.md | sha256sum'
  );
  lines.push(
    'curl -fsSL https://github.com/RouteWorks/RouterArena/commit/844e93b547e6278b01994720de39bfc32ffd18bc.patch | sha256sum'
  );
  lines.push(
    'curl -fsSL https://raw.githubusercontent.com/RouteWorks/RouterArena/844e93b547e6278b01994720de39bfc32ffd18bc/README.md | sha256sum'
  );

  return `${lines.join('\n')}\n`;
}

const isDirectCliExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectCliExecution) {
  const cliArgs = new Set(process.argv.slice(2));
  const jsonOutput = cliArgs.has('--json');
  const includeCrashDrill = !cliArgs.has('--skip-crash-drill');

  runCleanRoomReproduction({ includeCrashDrill })
    .then((result) => {
      if (jsonOutput) {
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      } else {
        process.stdout.write(formatReportText(result));
      }
      process.exit(result.ok ? 0 : 1);
    })
    .catch((err) => {
      const message = err instanceof Error ? err.stack || err.message : String(err);
      process.stderr.write(`Clean-room reproduction error: ${message}\n`);
      process.exit(1);
    });
}
