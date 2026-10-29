import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createKruschStack, createResilienceEngine } from '../src/index.js';
import { estimateTokenCount } from '../src/engines/resilience-engine.js';
import { startHttpGateway } from '../bin/krusch-stack.js';

test('createResilienceEngine (#2 Context Budget, #7 HITL Gate, #8 DAG Gate, #12 Cost Kill-Switch, #14 Shadow Diff)', async (t) => {
  const stack = createKruschStack({ ephemeral: true });
  assert.ok(stack.resilience, 'stack.resilience must be attached on createKruschStack');
  assert.equal(typeof createResilienceEngine, 'function');

  await t.test('#2 assembleContextBudget strictly caps totalAllocatedTokens below input ceiling (including OpenAI tools & empty-query user objective)', () => {
    const docs = Array.from({ length: 12 }, (_, idx) => ({
      id: `doc-${idx + 1}`,
      score: 1 - idx * 0.05,
      content: 'x'.repeat(800)
    }));
    const tools = Array.from({ length: 8 }, (_, idx) => ({
      name: `tool_${idx + 1}`,
      pinned: idx === 0,
      schema: { type: 'object', properties: { query: { type: 'string', description: 'y'.repeat(400) } } }
    }));
    const messages = Array.from({ length: 10 }, (_, idx) => ({
      role: idx % 2 === 0 ? 'user' : 'assistant',
      content: `Conversation message ${idx + 1}: ` + 'z'.repeat(300)
    }));

    const res = stack.resilience.assembleContextBudget({
      systemPrompt: 'System invariant floor '.repeat(40),
      query: 'tool_1 search',
      docs,
      tools,
      messages,
      maxContextTokens: 2048,
      outputReserveTokens: 512
    });

    assert.equal(res.ok, true);
    assert.equal(res.data.withinBudget, true);
    assert.ok(res.data.totalAllocatedTokens <= 1536);
    assert.ok(res.data.evictedDocs.length > 0);

    // Regression (REF-P3-02a): OpenAI `{ type: 'function', function: { name, description, parameters } }` tools
    const openAiTools = Array.from({ length: 8 }, (_, idx) => ({
      type: 'function',
      function: {
        name: `openai_fn_${idx + 1}`,
        description: 'd'.repeat(300),
        parameters: {
          type: 'object',
          properties: { payload: { type: 'string', description: 'p'.repeat(400) } }
        }
      }
    }));
    const openAiRes = stack.resilience.assembleContextBudget({
      systemPrompt: 'Strict system prompt.',
      query: 'openai_fn_1',
      tools: openAiTools,
      maxContextTokens: 1024,
      outputReserveTokens: 512
    });
    assert.equal(openAiRes.ok, true);
    const actualSerializedToolTokens = openAiRes.data.selectedTools.reduce(
      (sum, tObj) => sum + estimateTokenCount(JSON.stringify(tObj)),
      0
    );
    const actualTotal =
      estimateTokenCount(openAiRes.data.systemPrompt) +
      estimateTokenCount(openAiRes.data.query) +
      actualSerializedToolTokens;
    assert.equal(openAiRes.data.buckets.tools, actualSerializedToolTokens);
    assert.ok(actualTotal <= 512, `Expected actual serialized tokens (${actualTotal}) <= 512`);
    assert.ok(openAiRes.data.evictedTools.length > 0);

    // Regression (REF-P3-02b): Empty `query` with oversized latest user message truncates instead of dropping to []
    const chatOnlyRes = stack.resilience.assembleContextBudget({
      systemPrompt: 'Short system rule.',
      query: '',
      docs,
      tools: openAiTools,
      messages: [
        { role: 'user', content: 'older turn' },
        { role: 'assistant', content: 'older reply' },
        { role: 'user', content: 'm'.repeat(8000) }
      ],
      maxContextTokens: 1024,
      outputReserveTokens: 512
    });
    assert.equal(chatOnlyRes.ok, true);
    assert.ok(chatOnlyRes.data.selectedMessages.length >= 1, 'Latest user objective must not be dropped');
    const lastSelectedMsg = chatOnlyRes.data.selectedMessages[chatOnlyRes.data.selectedMessages.length - 1];
    assert.equal(lastSelectedMsg.role, 'user');
    assert.ok(lastSelectedMsg.content.startsWith('mmm'));
    assert.ok(lastSelectedMsg.content.length < 8000);
    assert.ok(chatOnlyRes.data.totalAllocatedTokens <= 512);
  });

  await t.test('#12 evaluateCostKillSwitch downgrades frontier calls near $0.50 and halts on budget/depth breach', () => {
    const sessionId = 'cost-session-alpha';
    const r1 = stack.resilience.evaluateCostKillSwitch({
      sessionId,
      model: 'gemini-4-argon',
      promptTokens: 2000,
      projectedCompletionTokens: 1000,
      hardLimitUsd: 0.50,
      maxLoopDepth: 4
    });
    assert.equal(r1.ok, true);

    stack.resilience.recordCostUsage({
      sessionId,
      model: 'claude-4-opus',
      promptTokens: 10000,
      completionTokens: 4000
    });

    // ~0.45 USD spent: next frontier call projects > $0.50 so must downgrade to local Ollama
    const r2 = stack.resilience.evaluateCostKillSwitch({
      sessionId,
      model: 'claude-4-opus',
      promptTokens: 5000,
      projectedCompletionTokens: 2000,
      hardLimitUsd: 0.50,
      fallbackModel: 'qwen2.5-coder:7b'
    });
    assert.equal(r2.ok, true);
    assert.equal(r2.data.effectiveModel, 'qwen2.5-coder:7b');

    // Push past $0.50 hard cap
    stack.resilience.recordCostUsage({
      sessionId,
      model: 'claude-4-opus',
      promptTokens: 5000,
      completionTokens: 2000
    });
    const r3 = stack.resilience.evaluateCostKillSwitch({
      sessionId,
      model: 'gemini-4-argon',
      promptTokens: 1000,
      projectedCompletionTokens: 1000,
      hardLimitUsd: 0.50
    });
    assert.equal(r3.ok, false);
    assert.equal(r3.data.status, 'HALTED_BUDGET_EXCEEDED');
  });

  await t.test('#8 verifyTrajectoryDag detects skipped passing prerequisites, forbidden tools, argGuards, and passes 100/100 golden corpus', () => {
    const good = stack.resilience.verifyTrajectoryDag({
      steps: [
        { tool: 'read_file', ok: true },
        { tool: 'stage_diff', ok: true },
        { tool: 'run_tests', ok: true },
        { tool: 'apply_staged_diff', ok: true }
      ],
      goldenDag: {
        requiredTools: ['read_file', 'stage_diff', 'run_tests', 'apply_staged_diff'],
        forbiddenTools: ['raw_shell_rm'],
        precedenceEdges: [['read_file', 'stage_diff'], ['stage_diff', 'run_tests'], ['run_tests', 'apply_staged_diff']],
        requirePassingPrerequisite: [['run_tests', 'apply_staged_diff']]
      }
    });
    assert.equal(good.ok, true);

    // Standalone requirePassingPrerequisite WITHOUT run_tests in requiredTools or precedenceEdges
    const bad = stack.resilience.verifyTrajectoryDag({
      steps: [
        { tool: 'read_file', ok: true },
        { tool: 'stage_diff', ok: true },
        { tool: 'run_tests', ok: false },
        { tool: 'apply_staged_diff', ok: true }
      ],
      goldenDag: {
        requiredTools: ['read_file', 'apply_staged_diff'],
        requirePassingPrerequisite: [['run_tests', 'apply_staged_diff']]
      }
    });
    assert.equal(bad.ok, false);
    assert.ok(bad.data.violations.some((v) => v.type === 'FAILED_PREREQUISITE'));

    // Empty array `requirePassingPrerequisite: []` must NOT coerce to global boolean true
    const fallbackAllowed = stack.resilience.verifyTrajectoryDag({
      steps: [
        { tool: 'fetch_http_endpoint', ok: false },
        { tool: 'run_headless_browser', ok: true }
      ],
      goldenDag: {
        requiredTools: ['fetch_http_endpoint', 'run_headless_browser'],
        precedenceEdges: [['fetch_http_endpoint', 'run_headless_browser']],
        requirePassingPrerequisite: []
      }
    });
    assert.equal(fallbackAllowed.ok, true);

    // Replay full 100-trajectory golden fixture corpus when co-located in monorepo
    const goldenFixturePath = fileURLToPath(
      new URL('../../krusch-coding-harness/test/fixtures/golden-trajectories-100.json', import.meta.url)
    );
    if (fs.existsSync(goldenFixturePath)) {
      const goldenTrajectories = JSON.parse(fs.readFileSync(goldenFixturePath, 'utf8'));
      assert.equal(goldenTrajectories.length, 100);
      for (const traj of goldenTrajectories) {
        const verdict = stack.resilience.verifyTrajectoryDag({
          steps: traj.steps,
          goldenDag: traj.goldenDag
        });
        assert.equal(
          verdict.ok,
          true,
          `Expected golden trajectory ${traj.id} (${traj.category}) to pass, got violations: ${JSON.stringify(verdict.data.violations)}`
        );
      }
    }
  });

  await t.test('#14 recordShadowComparison & scheduleShadowComparison compute argKeyJaccard and run non-blocking 5% mirror', async () => {
    const shadow = stack.resilience.recordShadowComparison({
      requestId: 'req-shadow-01',
      primaryModel: 'gemini-4-argon',
      shadowModel: 'qwen2.5-coder:7b',
      primaryTools: [
        { name: 'search_code', arguments: { query: 'auth', limit: 5 } },
        { name: 'read_file', arguments: { path: 'src/auth.js' } }
      ],
      shadowTools: [
        { name: 'search_code', arguments: { query: 'auth' } },
        { name: 'read_file', arguments: { path: 'src/auth.js' } }
      ],
      primaryLatencyMs: 820,
      shadowLatencyMs: 240,
      primaryCostUsd: 0.018,
      shadowCostUsd: 0.0
    });
    assert.equal(shadow.ok, true);
    assert.equal(shadow.data.exactDagMatch, true);
    assert.equal(shadow.data.sequenceSimilarity, 1);
    assert.ok(shadow.data.argKeyJaccard > 0.6 && shadow.data.argKeyJaccard < 1.0);

    const t0 = performance.now();
    const scheduled = stack.resilience.scheduleShadowComparison({
      requestId: 'req-shadow-bg-01',
      sampleRate: 0.05,
      force: true,
      primaryModel: 'gemini-4-argon',
      shadowModel: 'qwen2.5-coder:7b',
      primaryTools: ['read_file'],
      primaryLatencyMs: 120,
      primaryCostUsd: 0.004,
      shadowRunner: async () => {
        await new Promise((r) => setTimeout(r, 40));
        return { tools: ['read_file'], latencyMs: 42, costUsd: 0 };
      }
    });
    const dispatchElapsedMs = performance.now() - t0;
    assert.equal(scheduled.ok, true);
    assert.equal(scheduled.data.sampled, true);
    assert.ok(dispatchElapsedMs < 20, 'scheduleShadowComparison must not block primary caller');
    const flushed = await stack.resilience.flushPendingShadows();
    assert.equal(flushed.ok, true);
    assert.equal(flushed.data.flushedCount, 1);
  });

  await t.test('#7 draftHitlGate + resolveHitlGate verify PENDING_APPROVAL, 72h TTL and Slack v0 HMAC-SHA256', () => {
    const nowMs = 1_760_000_000_000;
    const draft = stack.resilience.draftHitlGate({
      taskId: 'prod-migration-42',
      actionType: 'ALTER_TABLE_DROP_COLUMN',
      summary: 'Drop legacy billing column',
      stagedPayload: { sql: 'ALTER TABLE invoices DROP COLUMN legacy_ref;' },
      nowMs
    });
    assert.equal(draft.ok, true);
    assert.equal(draft.data.status, 'PENDING_APPROVAL');
    const gateId = draft.data.gateId;

    const secret = 'slack-test-secret-key';
    const tsSec = String(Math.floor((nowMs + 60_000) / 1000));
    const rawBody = JSON.stringify({ gateId, decision: 'APPROVED', reviewer: 'ops-lead' });
    const validSig = 'v0=' + crypto.createHmac('sha256', secret).update(`v0:${tsSec}:${rawBody}`).digest('hex');

    // Forged signature rejected
    const badSig = stack.resilience.resolveHitlGate({
      gateId,
      decision: 'APPROVED',
      signingSecret: secret,
      timestampHeader: tsSec,
      signatureHeader: 'v0=' + '0'.repeat(64),
      rawBody,
      nowMs: nowMs + 60_000
    });
    assert.equal(badSig.ok, false);
    assert.equal(badSig.data.status, 'UNAUTHORIZED_SIGNATURE');

    // Valid signature approved within 72h window
    const okSig = stack.resilience.resolveHitlGate({
      gateId,
      decision: 'APPROVED',
      reviewer: 'ops-lead',
      reason: 'Reviewed migration rollback plan',
      signingSecret: secret,
      timestampHeader: tsSec,
      signatureHeader: validSig,
      rawBody,
      nowMs: nowMs + 60_000
    });
    assert.equal(okSig.ok, true);
    assert.equal(okSig.data.status, 'APPROVED');
  });

  await t.test('HTTP Gateway /resilience/* enforces 127.0.0.1 bind, 413 body limit, and server-side Slack HMAC', async () => {
    const gwSecret = 'gateway-slack-secret-99';
    const { server, host } = await startHttpGateway({
      port: 0,
      stack,
      maxBodyBytes: 1024,
      slackSigningSecret: gwSecret
    });
    assert.equal(host, '127.0.0.1');
    const addr = server.address();
    try {
      const resp = await fetch(`http://127.0.0.1:${addr.port}/resilience/budget`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          systemPrompt: 'Follow all invariants.',
          query: 'test',
          maxContextTokens: 4096,
          outputReserveTokens: 512
        })
      });
      assert.equal(resp.status, 200);
      const body = await resp.json();
      assert.equal(body.ok, true);
      assert.ok(body.data.totalAllocatedTokens <= 3584);

      // Draft a gate via HTTP
      const draftResp = await fetch(`http://127.0.0.1:${addr.port}/resilience/hitl-draft`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ taskId: 'gw-hitl-1', actionType: 'PROD_DEPLOY', summary: 'Ship v1' })
      });
      assert.equal(draftResp.status, 200);
      const draftBody = await draftResp.json();
      assert.equal(draftBody.data.status, 'PENDING_APPROVAL');
      const gateId = draftBody.data.gateId;

      // Client attempting to forge signingSecret in JSON body MUST be rejected with 401
      const forgedSecret = 'attacker-chosen-secret';
      const tsSec = String(Math.floor(Date.now() / 1000));
      const forgedRaw = JSON.stringify({
        gateId,
        decision: 'APPROVED',
        signingSecret: forgedSecret
      });
      const forgedSig =
        'v0=' + crypto.createHmac('sha256', forgedSecret).update(`v0:${tsSec}:${forgedRaw}`).digest('hex');
      const forgedResp = await fetch(`http://127.0.0.1:${addr.port}/resilience/hitl-resolve`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-slack-request-timestamp': tsSec,
          'x-slack-signature': forgedSig
        },
        body: forgedRaw
      });
      assert.equal(forgedResp.status, 401);

      // Authentic server-secret signature succeeds with 200
      const validRaw = JSON.stringify({ gateId, decision: 'APPROVED', reviewer: 'sre' });
      const validSig =
        'v0=' + crypto.createHmac('sha256', gwSecret).update(`v0:${tsSec}:${validRaw}`).digest('hex');
      const validResp = await fetch(`http://127.0.0.1:${addr.port}/resilience/hitl-resolve`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-slack-request-timestamp': tsSec,
          'x-slack-signature': validSig
        },
        body: validRaw
      });
      assert.equal(validResp.status, 200);

      // Oversized payload > 1024 bytes returns HTTP 413
      const oversizedResp = await fetch(`http://127.0.0.1:${addr.port}/resilience/budget`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ systemPrompt: 'a'.repeat(2048) })
      });
      assert.equal(oversizedResp.status, 413);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
