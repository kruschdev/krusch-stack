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
import { startHttpGateway } from '../bin/krusch-stack.js';

describe('Tier 3B Extension: Grounded Harness Engine (INV-STACK-11 / INV-GH-01..10)', () => {
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
});
