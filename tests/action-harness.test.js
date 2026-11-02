import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { STACK_SCHEMA_SQL, ensureStackSchemaMigrations } from '../src/db/sqlite.js';
import { createContextEngine } from '../src/engines/context-engine.js';
import {
  ACTION_HARNESS_SCHEMA_SQL,
  classifyToolMutability,
  canonicalizeToolCallKey,
  createActionHarnessEngine
} from '../src/engines/action-harness-engine.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

function makeInMemoryDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(STACK_SCHEMA_SQL);
  ensureStackSchemaMigrations(db);
  return db;
}

describe('Tier 3 Extension: 2PC Tool-Action Harness Engine (INV-STACK-10)', () => {
  test('classifyToolMutability handles explicit overrides, MCP namespaces, camelCase, and neutral fallbacks', () => {
    assert.equal(classifyToolMutability('get_contacts', true), true);
    assert.equal(classifyToolMutability('delete_contact', false), false);

    // Read-only verbs across snake_case, camelCase, and MCP namespaces
    assert.equal(classifyToolMutability('get_user_profile'), false);
    assert.equal(classifyToolMutability('listMessages'), false);
    assert.equal(classifyToolMutability('mcp__workspace__read_document'), false);
    assert.equal(classifyToolMutability('crm.searchLeads'), false);
    assert.equal(classifyToolMutability('calendar:checkAvailability'), false);
    assert.equal(classifyToolMutability('ping'), false);
    assert.equal(classifyToolMutability('stat_file'), false);

    // Mutating verbs across snake_case, camelCase, and MCP namespaces
    assert.equal(classifyToolMutability('send_email'), true);
    assert.equal(classifyToolMutability('add_crm_row'), true);
    assert.equal(classifyToolMutability('mcp__crm_app__createDeal'), true);
    assert.equal(classifyToolMutability('billing.payInvoice'), true);
    assert.equal(classifyToolMutability('travel/book_flight'), true);
    assert.equal(classifyToolMutability('reschedule_meeting'), true);
    assert.equal(classifyToolMutability('archive_thread'), true);
    assert.equal(classifyToolMutability('refundOrder'), true);

    // Substring non-matches must fall back conservatively to false
    assert.equal(classifyToolMutability('address_book'), false);
    assert.equal(classifyToolMutability('payees'), false);
    assert.equal(classifyToolMutability('unknown_custom_helper'), false);
  });

  test('canonicalizeToolCallKey is invariant to object key order and preserves array order', () => {
    const keyA = canonicalizeToolCallKey('add_crm_row', {
      deal_usd: 50000,
      company: 'Acme',
      meta: { stage: 'qualified', tags: [{ b: 2, a: 1 }, { d: 4, c: 3 }] },
      ignored: undefined
    });
    const keyB = canonicalizeToolCallKey('  add_crm_row  ', {
      meta: { tags: [{ a: 1, b: 2 }, { c: 3, d: 4 }], stage: 'qualified' },
      company: 'Acme',
      deal_usd: 50000
    });

    assert.equal(keyA.canonicalArgsJson, keyB.canonicalArgsJson);
    assert.equal(keyA.callSignature, keyB.callSignature);
    assert.equal(keyA.callSignature.length, 64);

    // Array element permutation MUST change signature
    const keyReorderedArray = canonicalizeToolCallKey('add_crm_row', {
      company: 'Acme',
      deal_usd: 50000,
      meta: { stage: 'qualified', tags: [{ c: 3, d: 4 }, { a: 1, b: 2 }] }
    });
    assert.notEqual(keyA.callSignature, keyReorderedArray.callSignature);
  });

  test('startSession validates goal, persists limits, and supports reset=true counter/event clearing', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    assert.ok(ACTION_HARNESS_SCHEMA_SQL.includes('action_harness_sessions'));
    assert.ok(ACTION_HARNESS_SCHEMA_SQL.includes('action_harness_events'));

    const bad = harness.startSession({ goal: '   ' });
    assert.equal(bad.ok, false);
    assert.equal(bad.tool, 'krusch_action_session_start');
    assert.equal(bad.data.status, 'INVALID_SESSION_ARGS');

    const started = harness.startSession({
      persona: 'alex',
      goal: 'Send weekly metrics summary to leadership',
      anchor_date: '2026-05-14',
      max_identical_reads: 2,
      max_duplicate_writes: 1,
      max_read_streak: 4,
      max_verify_nudges: 2,
      enforce_context_nudge: true
    });
    assert.equal(started.ok, true);
    assert.equal(started.tool, 'krusch_action_session_start');
    assert.equal(started.data.status, 'ACTIVE');
    assert.match(started.data.session_id, /^act_/);
    assert.equal(started.data.limits.max_identical_reads, 2);
    assert.equal(started.data.limits.enforce_context_nudge, true);

    const sid = started.data.session_id;
    const readRes = harness.interceptToolCall({
      session_id: sid,
      step: 1,
      tool_name: 'get_metrics',
      args: { period: 'weekly' }
    });
    assert.equal(readRes.data.allowed, true);
    harness.recordToolOutcome({
      session_id: sid,
      event_id: readRes.data.event_id,
      status: 'COMMITTED'
    });

    const resetRes = harness.startSession({
      session_id: sid,
      persona: 'alex',
      goal: 'Send updated metrics summary',
      reset: true
    });
    assert.equal(resetRes.ok, true);

    const summary = harness.sessionSummary({ session_id: sid });
    assert.equal(summary.ok, true);
    assert.equal(summary.data.counts.total_events, 0);
    assert.equal(summary.data.counts.committed_reads, 0);
    assert.equal(summary.data.counts.committed_mutations, 0);
    db.close();
  });

  test('interceptToolCall blocks duplicate read spin-loops, allows retry after ERROR, and handles auto-start', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    // Missing session without goal fails closed
    const missing = harness.interceptToolCall({
      session_id: 'nonexistent',
      tool_name: 'list_emails',
      args: {}
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.data.status, 'SESSION_NOT_FOUND');
    assert.equal(missing.data.allowed, false);

    // Auto-starts session when non-empty goal is provided
    const firstRead = harness.interceptToolCall({
      session_id: 'sess_spin_1',
      step: 1,
      tool_name: 'list_emails',
      args: { folder: 'inbox', limit: 10 },
      goal: 'Check inbox and reply to urgent billing note'
    });
    assert.equal(firstRead.ok, true);
    assert.equal(firstRead.data.allowed, true);
    assert.equal(firstRead.data.decision, 'ALLOW_READ');

    // Exact duplicate read (with reordered keys) is blocked as a spin-loop
    const dupRead = harness.interceptToolCall({
      session_id: 'sess_spin_1',
      step: 2,
      tool_name: 'list_emails',
      args: { limit: 10, folder: 'inbox' }
    });
    assert.equal(dupRead.ok, true);
    assert.equal(dupRead.data.allowed, false);
    assert.equal(dupRead.data.decision, 'BLOCK_SPIN_LOOP');
    assert.equal(dupRead.data.repeat_count, 2);
    assert.equal(dupRead.data.synthetic_tool_result.code, 'SPIN_LOOP_DUPLICATE_READ');

    // Distinct arguments are allowed
    const secondDistinct = harness.interceptToolCall({
      session_id: 'sess_spin_1',
      step: 3,
      tool_name: 'list_emails',
      args: { folder: 'billing', limit: 10 }
    });
    assert.equal(secondDistinct.data.allowed, true);

    // If that call failed with ERROR, retrying it is permitted
    harness.recordToolOutcome({
      session_id: 'sess_spin_1',
      event_id: secondDistinct.data.event_id,
      status: 'ERROR',
      result_preview: 'Upstream timeout'
    });
    const retryAfterError = harness.interceptToolCall({
      session_id: 'sess_spin_1',
      step: 4,
      tool_name: 'list_emails',
      args: { folder: 'billing', limit: 10 }
    });
    assert.equal(retryAfterError.data.allowed, true);
    assert.equal(retryAfterError.data.decision, 'ALLOW_READ');
    db.close();
  });

  test('interceptToolCall enforces consecutive read streak limit and resets on search_persona_memory or mutation', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    harness.startSession({
      session_id: 'sess_streak',
      goal: 'Find client renewal status and update CRM row',
      max_read_streak: 3
    });

    for (let i = 1; i <= 3; i += 1) {
      const res = harness.interceptToolCall({
        session_id: 'sess_streak',
        step: i,
        tool_name: 'get_crm_page',
        args: { page: i }
      });
      assert.equal(res.data.allowed, true);
      assert.equal(res.data.decision, 'ALLOW_READ');
    }

    // 4th consecutive app read exceeds max_read_streak=3
    const blocked = harness.interceptToolCall({
      session_id: 'sess_streak',
      step: 4,
      tool_name: 'get_crm_page',
      args: { page: 4 }
    });
    assert.equal(blocked.ok, true);
    assert.equal(blocked.data.allowed, false);
    assert.equal(blocked.data.decision, 'BLOCK_READ_STREAK');
    assert.equal(blocked.data.synthetic_tool_result.code, 'READ_STREAK_EXCEEDED');

    // Memory search is allowed even when app read streak is full, and resets streak to 0
    const memSearch = harness.interceptToolCall({
      session_id: 'sess_streak',
      step: 5,
      tool_name: 'search_persona_memory',
      args: { query: 'Acme renewal policy' }
    });
    assert.equal(memSearch.data.allowed, true);
    assert.equal(memSearch.data.decision, 'ALLOW_READ');
    assert.equal(memSearch.data.consecutive_app_reads, 0);

    // App reads succeed again after memory consultation
    const afterMem = harness.interceptToolCall({
      session_id: 'sess_streak',
      step: 6,
      tool_name: 'get_crm_page',
      args: { page: 4 }
    });
    assert.equal(afterMem.data.allowed, true);
    assert.equal(afterMem.data.consecutive_app_reads, 1);

    // Mutating call also resets consecutive_app_reads to 0
    const mut = harness.interceptToolCall({
      session_id: 'sess_streak',
      step: 7,
      tool_name: 'update_crm_row',
      args: { id: 'row_9', status: 'renewed' }
    });
    assert.equal(mut.data.allowed, true);
    assert.equal(mut.data.decision, 'ALLOW_MUTATION');

    const postMutRead = harness.interceptToolCall({
      session_id: 'sess_streak',
      step: 8,
      tool_name: 'get_crm_page',
      args: { page: 5 }
    });
    assert.equal(postMutRead.data.allowed, true);
    assert.equal(postMutRead.data.consecutive_app_reads, 1);
    db.close();
  });

  test('interceptToolCall blocks duplicate mutating side-effects (add_crm_row x2+) while allowing distinct rows', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    harness.startSession({
      session_id: 'sess_dup_write',
      goal: 'Add qualified leads to the CRM'
    });

    const firstAdd = harness.interceptToolCall({
      session_id: 'sess_dup_write',
      step: 1,
      tool_name: 'add_crm_row',
      args: { company: 'Northwind', stage: 'qualified', arr_usd: 24000 }
    });
    assert.equal(firstAdd.data.allowed, true);
    assert.equal(firstAdd.data.staged, true);
    assert.equal(firstAdd.data.decision, 'ALLOW_MUTATION');

    harness.recordToolOutcome({
      session_id: 'sess_dup_write',
      event_id: firstAdd.data.event_id,
      status: 'COMMITTED'
    });

    const duplicateAdd = harness.interceptToolCall({
      session_id: 'sess_dup_write',
      step: 2,
      tool_name: 'add_crm_row',
      args: { arr_usd: 24000, stage: 'qualified', company: 'Northwind' }
    });
    assert.equal(duplicateAdd.ok, true);
    assert.equal(duplicateAdd.data.allowed, false);
    assert.equal(duplicateAdd.data.decision, 'BLOCK_DUPLICATE_WRITE');
    assert.equal(duplicateAdd.data.repeat_count, 2);
    assert.equal(duplicateAdd.data.synthetic_tool_result.code, 'DUPLICATE_SIDE_EFFECT');

    const thirdAttempt = harness.interceptToolCall({
      session_id: 'sess_dup_write',
      step: 3,
      tool_name: 'add_crm_row',
      args: { company: 'Northwind', stage: 'qualified', arr_usd: 24000 }
    });
    assert.equal(thirdAttempt.data.allowed, false);
    assert.equal(thirdAttempt.data.decision, 'BLOCK_DUPLICATE_WRITE');

    const distinctAdd = harness.interceptToolCall({
      session_id: 'sess_dup_write',
      step: 4,
      tool_name: 'add_crm_row',
      args: { company: 'Contoso', stage: 'qualified', arr_usd: 36000 }
    });
    assert.equal(distinctAdd.data.allowed, true);
    assert.equal(distinctAdd.data.decision, 'ALLOW_MUTATION');
    db.close();
  });

  test('2PC pre-commit holds malformed dates & placeholders with anchor_date hints, accepts valid ISO dates, and recovers on retry', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    harness.startSession({
      session_id: 'sess_2pc_soft',
      goal: 'Book hotel and send confirmation note',
      anchor_date: '2026-05-13'
    });

    // 1. Invalid calendar day (Feb 30) + relative word ('tomorrow') -> HOLD_FOR_REVISION
    const badBooking = harness.interceptToolCall({
      session_id: 'sess_2pc_soft',
      step: 1,
      tool_name: 'book_hotel',
      args: {
        guest: 'Morgan',
        check_in: '2026-02-30',
        check_out: 'tomorrow'
      }
    });
    assert.equal(badBooking.ok, true);
    assert.equal(badBooking.data.allowed, false);
    assert.equal(badBooking.data.decision, 'HOLD_FOR_REVISION');
    assert.equal(badBooking.data.issues.length, 2);
    assert.ok(badBooking.data.issues.every((i) => i.code === 'MALFORMED_DATE_ARGUMENT'));
    assert.match(badBooking.data.synthetic_tool_result.message, /2026-05-13/);

    // 2. Fixed valid ISO dates/timestamps pass immediately
    const fixedBooking = harness.interceptToolCall({
      session_id: 'sess_2pc_soft',
      step: 2,
      tool_name: 'book_hotel',
      args: {
        guest: 'Morgan',
        check_in: '2026-05-14',
        check_out: '2026-05-16T11:00:00Z'
      }
    });
    assert.equal(fixedBooking.data.allowed, true);
    assert.equal(fixedBooking.data.decision, 'ALLOW_MUTATION');

    // 3. Unresolved template placeholder holds on first attempt, allows explicit retry escape hatch
    const firstNote = harness.interceptToolCall({
      session_id: 'sess_2pc_soft',
      step: 3,
      tool_name: 'send_message',
      args: {
        recipient: 'morgan@example.com',
        body: 'Hi <insert guest name>, your reservation is confirmed.',
        due_date: '2026-05-14 09:30'
      }
    });
    assert.equal(firstNote.data.allowed, false);
    assert.equal(firstNote.data.decision, 'HOLD_FOR_REVISION');
    assert.ok(firstNote.data.issues.some((i) => i.code === 'UNRESOLVED_PLACEHOLDER' && i.field === 'body'));
    // Valid timestamp '2026-05-14 09:30' must NOT be flagged
    assert.equal(
      firstNote.data.issues.some((i) => i.code === 'MALFORMED_DATE_ARGUMENT'),
      false
    );

    // Explicit retry after soft hold passes through without deadlocking legitimate edge strings
    const retryEdgeString = harness.interceptToolCall({
      session_id: 'sess_2pc_soft',
      step: 4,
      tool_name: 'send_message',
      args: {
        recipient: 'morgan@example.com',
        body: 'Design review note: keep placeholder banner text until launch.',
        due_date: '2026-05-14 09:30'
      }
    });
    assert.equal(retryEdgeString.data.allowed, true);
    assert.equal(retryEdgeString.data.decision, 'ALLOW_MUTATION');
    db.close();
  });

  test('2PC hard blocks (SECRET_LEAK_BLOCKED & CONTEXT_INVARIANT_NUDGE) never bypass on retry', () => {
    const db = makeInMemoryDb();
    const contextEngine = createContextEngine({ db, workspaceRoot: REPO_ROOT, ephemeral: true });
    contextEngine.remember({
      category: 'invariant',
      content: 'Never post external announcements to `#restricted-legal` without counsel sign-off.'
    });

    const harness = createActionHarnessEngine({ db, contextEngine });
    harness.startSession({
      session_id: 'sess_hard_blocks',
      goal: 'Post approved legal summary and send webhook',
      enforce_context_nudge: true
    });

    // Secret leak hard block (constructed dynamically so static secret scanners stay clean)
    const fakeKey = ['sk', 'ant', 'api03_syntheticTestKey9876543210abcdef'].join('-');
    const leakAttempt1 = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 1,
      tool_name: 'post_webhook',
      args: { auth_header: fakeKey }
    });
    assert.equal(leakAttempt1.data.allowed, false);
    assert.equal(leakAttempt1.data.decision, 'HOLD_FOR_REVISION');
    assert.ok(leakAttempt1.data.issues.some((i) => i.code === 'SECRET_LEAK_BLOCKED'));

    // Retrying with the leaked secret STILL blocks (hard issues never bypass)
    const leakAttempt2 = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 2,
      tool_name: 'post_webhook',
      args: { auth_header: fakeKey }
    });
    assert.equal(leakAttempt2.data.allowed, false);
    assert.equal(leakAttempt2.data.decision, 'HOLD_FOR_REVISION');

    // Prior hard hold does NOT consume the soft-hold warning budget when secret is replaced with placeholder
    const softAfterHard = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 3,
      tool_name: 'post_webhook',
      args: { auth_header: '[REDACTED]', note: 'TBD' }
    });
    assert.equal(softAfterHard.data.allowed, false);
    assert.ok(softAfterHard.data.issues.some((i) => i.code === 'UNRESOLVED_PLACEHOLDER'));

    const cleanWebhook = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 4,
      tool_name: 'post_webhook',
      args: { auth_header: '[REDACTED]', note: 'Verified payload' }
    });
    assert.equal(cleanWebhook.data.allowed, true);
    assert.equal(cleanWebhook.data.decision, 'ALLOW_MUTATION');

    // Context invariant nudge hard block
    const nudgeBlock1 = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 5,
      tool_name: 'post_channel_message',
      args: { channel: '#restricted-legal', text: 'Quarterly update' }
    });
    assert.equal(nudgeBlock1.data.allowed, false);
    assert.equal(nudgeBlock1.data.decision, 'HOLD_FOR_REVISION');
    assert.ok(nudgeBlock1.data.issues.some((i) => i.code === 'CONTEXT_INVARIANT_NUDGE'));

    // Retrying same invariant violation STILL blocks
    const nudgeBlock2 = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 6,
      tool_name: 'post_channel_message',
      args: { channel: '#restricted-legal', text: 'Quarterly update retry' }
    });
    assert.equal(nudgeBlock2.data.allowed, false);
    assert.equal(nudgeBlock2.data.decision, 'HOLD_FOR_REVISION');

    // Compliant channel succeeds
    const nudgeClean = harness.interceptToolCall({
      session_id: 'sess_hard_blocks',
      step: 7,
      tool_name: 'post_channel_message',
      args: { channel: '#general-updates', text: 'Quarterly update' }
    });
    assert.equal(nudgeClean.data.allowed, true);
    db.close();
  });

  test('recordToolOutcome is idempotent, bounds result_preview, and updates canonical_args signature', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    harness.startSession({
      session_id: 'sess_outcome',
      goal: 'Create project milestone'
    });

    const staged = harness.interceptToolCall({
      session_id: 'sess_outcome',
      step: 1,
      tool_name: 'create_milestone',
      args: { title: 'v2 Launch' }
    });
    assert.equal(staged.data.allowed, true);

    const longPreview = 'x'.repeat(900);
    const out1 = harness.recordToolOutcome({
      session_id: 'sess_outcome',
      event_id: staged.data.event_id,
      status: 'COMMITTED',
      canonical_args: { title: 'v2 Launch', workspace: 'default' },
      result_preview: longPreview
    });
    assert.equal(out1.ok, true);
    assert.equal(out1.tool, 'krusch_action_outcome');
    assert.equal(out1.data.committed_mutations, 1);
    assert.equal(out1.data.committed_reads, 0);

    // Calling recordToolOutcome a second time on the same event_id is strictly idempotent
    const out2 = harness.recordToolOutcome({
      session_id: 'sess_outcome',
      event_id: staged.data.event_id,
      status: 'COMMITTED',
      canonical_args: { workspace: 'default', title: 'v2 Launch' },
      result_preview: longPreview
    });
    assert.equal(out2.ok, true);
    assert.equal(out2.data.committed_mutations, 1);

    // Future call matching the updated canonical_args is caught as a duplicate write
    const dupWithNormalizedArgs = harness.interceptToolCall({
      session_id: 'sess_outcome',
      step: 2,
      tool_name: 'create_milestone',
      args: { workspace: 'default', title: 'v2 Launch' }
    });
    assert.equal(dupWithNormalizedArgs.data.allowed, false);
    assert.equal(dupWithNormalizedArgs.data.decision, 'BLOCK_DUPLICATE_WRITE');

    const summary = harness.sessionSummary({ session_id: 'sess_outcome' });
    assert.equal(summary.data.events[0].result_preview.length, 512);

    // Missing session/event returns ok=false
    const notFoundEvt = harness.recordToolOutcome({
      session_id: 'sess_outcome',
      event_id: 'evt_missing'
    });
    assert.equal(notFoundEvt.ok, false);
    assert.equal(notFoundEvt.data.status, 'EVENT_NOT_FOUND');
    db.close();
  });

  test('verifyStop catches draft-in-chat, permission-asks, and zero-mutation imperative stops while allowing policy abstentions & questions', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    // Case 1: Permission-ask / formatted draft header triggers CONTINUE_VERIFY, then caps at max_verify_nudges=1
    harness.startSession({
      session_id: 'sess_verify_draft',
      goal: 'Send onboarding welcome email to Riley',
      max_verify_nudges: 1
    });
    const nudge1 = harness.verifyStop({
      session_id: 'sess_verify_draft',
      step: 1,
      final_text: '**Subject:** Welcome aboard!\n\nWould you like me to send this email to Riley now?'
    });
    assert.equal(nudge1.ok, true);
    assert.equal(nudge1.tool, 'krusch_action_verify_stop');
    assert.equal(nudge1.data.decision, 'CONTINUE_VERIFY');
    assert.equal(nudge1.data.allow_stop, false);
    assert.equal(nudge1.data.reason_code, 'UNCOMMITTED_DRAFT_OR_PERMISSION_ASK');
    assert.equal(nudge1.data.verify_nudges_used, 1);
    assert.match(nudge1.data.steer_prompt, /VERIFICATION GATE/);

    // Second stop check respects max_verify_nudges=1 ceiling (no infinite loop)
    const nudgeCap = harness.verifyStop({
      session_id: 'sess_verify_draft',
      step: 2,
      final_text: 'Still waiting for confirmation.'
    });
    assert.equal(nudgeCap.data.decision, 'ALLOW_STOP');
    assert.equal(nudgeCap.data.allow_stop, true);

    // Case 2: Imperative goal with zero mutations and no policy rationale triggers IMPERATIVE_GOAL_ZERO_MUTATION
    harness.startSession({
      session_id: 'sess_verify_imp',
      goal: 'Archive the completed Q1 sprint tasks'
    });
    const impNudge = harness.verifyStop({
      session_id: 'sess_verify_imp',
      step: 1,
      final_text: 'I reviewed all Q1 sprint tasks in the board.'
    });
    assert.equal(impNudge.data.decision, 'CONTINUE_VERIFY');
    assert.equal(impNudge.data.allow_stop, false);
    assert.equal(impNudge.data.reason_code, 'IMPERATIVE_GOAL_ZERO_MUTATION');

    // Case 3: Policy-grounded abstention on an imperative goal is respected (ALLOW_STOP)
    harness.startSession({
      session_id: 'sess_verify_abstain',
      goal: 'Post release announcement to #releases and add lead to CRM'
    });
    const abstainStop = harness.verifyStop({
      session_id: 'sess_verify_abstain',
      step: 2,
      final_text:
        'Per your standing rule, I am holding off on posting because the release checklist is not yet green, and the lead already exists in the CRM.'
    });
    assert.equal(abstainStop.data.decision, 'ALLOW_STOP');
    assert.equal(abstainStop.data.allow_stop, true);
    assert.equal(abstainStop.data.reason_code, 'VERIFIED_COMPLETE');

    // Case 4: Draft-only goal exemption allows formatted draft without nudging
    harness.startSession({
      session_id: 'sess_verify_draft_only',
      goal: 'Draft only an email to finance — do not send it yet'
    });
    const draftOnlyStop = harness.verifyStop({
      session_id: 'sess_verify_draft_only',
      step: 1,
      final_text: 'Subject: Q2 Forecast\n\nHere is the draft for your review.'
    });
    assert.equal(draftOnlyStop.data.decision, 'ALLOW_STOP');
    assert.equal(draftOnlyStop.data.allow_stop, true);

    // Case 5: Pure question containing an action verb allows stop cleanly
    harness.startSession({
      session_id: 'sess_verify_question',
      goal: 'What emails did we send to Acme last week?'
    });
    const questionStop = harness.verifyStop({
      session_id: 'sess_verify_question',
      step: 1,
      final_text: 'Two emails were sent to Acme on Tuesday and Thursday.'
    });
    assert.equal(questionStop.data.decision, 'ALLOW_STOP');
    assert.equal(questionStop.data.allow_stop, true);

    // Case 6: Session with >=1 committed mutation allows stop even if final_text offers follow-up help
    harness.startSession({
      session_id: 'sess_verify_committed',
      goal: 'Send onboarding welcome email to Riley'
    });
    const call = harness.interceptToolCall({
      session_id: 'sess_verify_committed',
      step: 1,
      tool_name: 'send_email',
      args: { to: 'riley@example.com', subject: 'Welcome', body: 'Glad to have you on the team!' }
    });
    harness.recordToolOutcome({
      session_id: 'sess_verify_committed',
      event_id: call.data.event_id,
      status: 'COMMITTED'
    });
    const committedStop = harness.verifyStop({
      session_id: 'sess_verify_committed',
      step: 2,
      final_text: 'Sent the welcome email to Riley. Would you like me to schedule a 1:1 as well?'
    });
    assert.equal(committedStop.data.decision, 'ALLOW_STOP');
    assert.equal(committedStop.data.allow_stop, true);

    const summary = harness.sessionSummary({ session_id: 'sess_verify_committed' });
    assert.equal(summary.ok, true);
    assert.equal(summary.data.status, 'COMPLETED');
    assert.equal(summary.data.counts.committed_mutations, 1);
    db.close();
  });

  test('sessionSummary aggregates all telemetry counters accurately and handles missing sessions', () => {
    const db = makeInMemoryDb();
    const harness = createActionHarnessEngine({ db });

    const missing = harness.sessionSummary({ session_id: 'missing_sid' });
    assert.equal(missing.ok, false);
    assert.equal(missing.data.status, 'SESSION_NOT_FOUND');

    harness.startSession({
      session_id: 'sess_telemetry',
      persona: 'morgan',
      goal: 'Schedule vendor review and update tracker',
      anchor_date: '2026-06-01',
      max_read_streak: 1
    });

    // 1 committed read
    const r1 = harness.interceptToolCall({
      session_id: 'sess_telemetry',
      step: 1,
      tool_name: 'get_calendar',
      args: { day: '2026-06-02' }
    });
    harness.recordToolOutcome({ session_id: 'sess_telemetry', event_id: r1.data.event_id, status: 'COMMITTED' });

    // 1 spin-loop block
    harness.interceptToolCall({
      session_id: 'sess_telemetry',
      step: 2,
      tool_name: 'get_calendar',
      args: { day: '2026-06-02' }
    });

    // 1 read-streak block (max_read_streak=1)
    harness.interceptToolCall({
      session_id: 'sess_telemetry',
      step: 3,
      tool_name: 'get_calendar',
      args: { day: '2026-06-03' }
    });

    // 1 soft hold for revision
    harness.interceptToolCall({
      session_id: 'sess_telemetry',
      step: 4,
      tool_name: 'schedule_event',
      args: { title: 'Vendor Review', start_date: 'tomorrow' }
    });

    // 1 verify nudge before mutation
    harness.verifyStop({
      session_id: 'sess_telemetry',
      step: 5,
      final_text: 'Should I schedule the vendor review for June 2?'
    });

    // 1 committed mutation + 1 duplicate write block
    const m1 = harness.interceptToolCall({
      session_id: 'sess_telemetry',
      step: 6,
      tool_name: 'schedule_event',
      args: { title: 'Vendor Review', start_date: '2026-06-02T14:00:00Z' }
    });
    harness.recordToolOutcome({ session_id: 'sess_telemetry', event_id: m1.data.event_id, status: 'COMMITTED' });

    harness.interceptToolCall({
      session_id: 'sess_telemetry',
      step: 7,
      tool_name: 'schedule_event',
      args: { start_date: '2026-06-02T14:00:00Z', title: 'Vendor Review' }
    });

    harness.verifyStop({
      session_id: 'sess_telemetry',
      step: 8,
      final_text: 'Scheduled the vendor review for 2026-06-02 at 14:00 UTC.'
    });

    const summary = harness.sessionSummary({ session_id: 'sess_telemetry' });
    assert.equal(summary.ok, true);
    assert.equal(summary.tool, 'krusch_action_summary');
    assert.equal(summary.data.status, 'COMPLETED');
    assert.deepEqual(summary.data.counts, {
      total_events: 7,
      committed_reads: 1,
      committed_mutations: 1,
      blocked_spin_loops: 1,
      blocked_read_streaks: 1,
      blocked_duplicate_writes: 1,
      held_for_revision: 1,
      verify_nudges_used: 1
    });
    assert.equal(summary.data.events.length, 7);
    db.close();
  });

  test('INV-STACK-04: Zero private IPs, private hostnames, or local home paths in action-harness files', () => {
    const targetFiles = [
      path.join(REPO_ROOT, 'src', 'engines', 'action-harness-engine.js'),
      __filename
    ];
    const hostTokens = [
      'krusch' + 'serv',
      'krusch' + 'game',
      'krusch' + 'media',
      'krusch' + 'sandbox',
      'crush' + '0',
      'kr1' + 'yoga'
    ];
    const forbiddenRegexes = [
      new RegExp('\\b192' + '\\.168\\.\\d+\\.\\d+\\b'),
      new RegExp('\\b10' + '\\.10\\.\\d+\\.\\d+\\b'),
      new RegExp('\\b100' + '\\.\\d+\\.\\d+\\.\\d+\\b'),
      new RegExp('/home/' + 'krusch', 'i'),
      new RegExp('\\b(' + hostTokens.join('|') + ')\\b', 'i')
    ];

    for (const file of targetFiles) {
      const text = fs.readFileSync(file, 'utf-8');
      for (const re of forbiddenRegexes) {
        assert.equal(re.test(text), false, `Forbidden pattern ${re} matched in ${path.basename(file)}`);
      }
    }
  });
});
