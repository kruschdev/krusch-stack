import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  VERSION,
  VALID_STACK_PROFILES,
  normalizeStackProfile,
  buildDefaultAgentsMd,
  generateIdeConfig,
  writeIdeConfigs,
  runStackDoctor,
  runStackDemo,
  formatStackDemoText,
  createKruschStack,
  formatExplainReportText
} from '../src/index.js';
import { ALL_STACK_TOOLS, getStackTools } from '../src/mcp/server.js';
import { parseCliArgs, startHttpGateway } from '../bin/krusch-stack.js';
import { runCleanRoomReproduction } from '../scripts/reproduce_clean_room.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const CLI_PATH = path.join(REPO_ROOT, 'bin', 'krusch-stack.js');

function rawHttpGet({ port, urlPath = '/telemetry', headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        method: 'GET',
        path: urlPath,
        headers
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, text, json });
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

describe('KruschStack v1.3.0 Progressive Onboarding, Demo, Observability & Clean-Room Repro (INV-STACK-05, INV-STACK-15)', () => {
  test('INV-STACK-05: Progressive profiles filter tools, modular servers, doctor pillars, and AGENTS.md while keeping 39 unified tools intact', () => {
    assert.equal(VERSION, '1.3.1');
    assert.equal(ALL_STACK_TOOLS.length, 39);
    assert.deepEqual([...VALID_STACK_PROFILES], ['memory-only', 'coding-agent', 'core', 'full']);

    // Normalization & backward-compatible fallback
    assert.equal(normalizeStackProfile('memory'), 'memory-only');
    assert.equal(normalizeStackProfile('MEMORY-ONLY'), 'memory-only');
    assert.equal(normalizeStackProfile('coding'), 'coding-agent');
    assert.equal(normalizeStackProfile('coding-agent'), 'coding-agent');
    assert.equal(normalizeStackProfile('core'), 'core');
    assert.equal(normalizeStackProfile(undefined), 'full');
    assert.equal(normalizeStackProfile('unknown-profile'), 'full');

    // Unified MCP tool counts per profile
    assert.equal(getStackTools({ profile: 'memory-only' }).length, 5);
    assert.equal(getStackTools({ profile: 'coding-agent' }).length, 19);
    assert.equal(getStackTools({ profile: 'core' }).length, 27);
    assert.equal(getStackTools({ profile: 'full' }).length, 39);

    // Modular IDE server counts per profile
    const memModular = generateIdeConfig({ mode: 'modular', profile: 'memory-only' });
    assert.deepEqual(Object.keys(memModular.mcpServers), ['krusch-context-mcp']);

    const codingModular = generateIdeConfig({ mode: 'modular', profile: 'coding-agent' });
    assert.deepEqual(Object.keys(codingModular.mcpServers), [
      'krusch-context-mcp',
      'krusch-git',
      'krusch-harness',
      'krusch-grounded-harness'
    ]);

    // CLI default behavior: `init` defaults to lean `coding-agent`, while `mcp` and `serve` remain `full`
    const savedEnvProfile = process.env.KRUSCH_STACK_PROFILE;
    delete process.env.KRUSCH_STACK_PROFILE;
    try {
      const initDefault = parseCliArgs(['init']);
      assert.equal(initDefault.command, 'init');
      assert.equal(initDefault.flags.profile, 'coding-agent');
      assert.equal(initDefault.flags.profileExplicit, false);

      const initExplicit = parseCliArgs(['init', '--profile', 'memory-only']);
      assert.equal(initExplicit.flags.profile, 'memory-only');
      assert.equal(initExplicit.flags.profileExplicit, true);

      const mcpDefault = parseCliArgs(['mcp']);
      assert.equal(mcpDefault.flags.profile, 'full');
      const bareDefault = parseCliArgs([]);
      assert.equal(bareDefault.flags.profile, 'full');
    } finally {
      if (savedEnvProfile !== undefined) {
        process.env.KRUSCH_STACK_PROFILE = savedEnvProfile;
      }
    }

    // Tailored .agent/AGENTS.md per profile + Doctor pillar counts
    const memAgentsMd = buildDefaultAgentsMd({ mode: 'unified', profile: 'memory-only' });
    assert.match(memAgentsMd, /krusch_context_retrieve/);
    assert.doesNotMatch(memAgentsMd, /krusch_git_search_symbols/);
    assert.doesNotMatch(memAgentsMd, /krusch_fs_locate/);
    assert.doesNotMatch(memAgentsMd, /krusch_apply_diff/);

    const codingAgentsMd = buildDefaultAgentsMd({ mode: 'modular', profile: 'coding-agent' });
    assert.match(codingAgentsMd, /krusch_git_search_symbols/);
    assert.match(codingAgentsMd, /krusch_ground_workspace/);
    assert.doesNotMatch(codingAgentsMd, /krusch_fs_locate/);

    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-profile-doc-'));
    try {
      const written = writeIdeConfigs({ targetDir: ws, ide: 'claude', profile: 'memory-only' });
      assert.equal(written.ok, true);
      assert.deepEqual(written.mcpServers['krusch-stack'].args, [
        '-y',
        'krusch-stack',
        'mcp',
        '--profile',
        'memory-only'
      ]);
      assert.equal(runStackDoctor({ workspaceRoot: ws, profile: 'memory-only' }).data.components.length, 1);
      assert.equal(runStackDoctor({ workspaceRoot: ws, profile: 'coding-agent' }).data.components.length, 4);
      assert.equal(runStackDoctor({ workspaceRoot: ws, profile: 'core' }).data.components.length, 8);
      assert.equal(runStackDoctor({ workspaceRoot: ws, profile: 'full' }).data.components.length, 10);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('INV-STACK-15: `npx krusch-stack demo` runs all 3 acts offline in <2s with zero cloud calls', async () => {
    const demoRes = await runStackDemo();
    assert.equal(demoRes.ok, true);
    assert.equal(demoRes.tool, 'krusch_stack_demo');
    assert.equal(demoRes.data.zero_cloud_calls, true);
    assert.equal(demoRes.data.all_passed, true);
    assert.equal(demoRes.data.acts.length, 3);
    for (const act of demoRes.data.acts) {
      assert.equal(act.passed, true, `Demo Act ${act.act} (${act.title}) must pass`);
    }

    const rendered = formatStackDemoText(demoRes);
    assert.equal(rendered.includes('—'), false, 'Demo text must not contain em dashes');
    assert.match(rendered, /Act 1/);
    assert.match(rendered, /Act 2/);
    assert.match(rendered, /Act 3/);

    const cliRaw = execFileSync(process.execPath, [CLI_PATH, 'demo', '--json'], {
      encoding: 'utf8'
    });
    const cliJson = JSON.parse(cliRaw);
    assert.equal(cliJson.ok, true);
    assert.equal(cliJson.data.all_passed, true);
  });

  test('INV-STACK-15: Observability metrics, `explain` decision trace, and HTTP `/telemetry` + `/explain` enforce security perimeter', async () => {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-obs-test-'));
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // Seed 1 invariant, 1 blocked 2PC edit, 1 applied 2PC edit, 1 action-harness spin loop, and 1 grounded defect
      stack.context.remember({
        category: 'invariant',
        content: 'Never use eval() in billing handlers'
      });

      const blockedTask = stack.harness.run({
        goal: 'Inject dynamic eval billing',
        edits: [{ file_path: 'src/bill.js', content: 'export const calc = (x) => eval(x);\n' }]
      });
      assert.equal(blockedTask.data.status, 'BLOCKED_INVARIANT');

      const stagedTask = stack.harness.run({
        goal: 'Add integer billing helper',
        edits: [{ file_path: 'src/bill.js', content: 'export const calc = (x) => Math.trunc(x);\n' }]
      });
      stack.harness.applyDiff({ task_id: stagedTask.data.task_id });

      stack.actionHarness.startSession({ session_id: 'ah-obs-1', goal: 'Read customer invoice' });
      const ah1 = stack.actionHarness.interceptToolCall({
        session_id: 'ah-obs-1',
        step: 1,
        tool_name: 'get_invoice',
        args: { id: 'inv_1' },
        is_mutating: false
      });
      stack.actionHarness.recordToolOutcome({
        session_id: 'ah-obs-1',
        event_id: ah1.data.event_id,
        status: 'COMMITTED'
      });
      const ahSpin = stack.actionHarness.interceptToolCall({
        session_id: 'ah-obs-1',
        step: 2,
        tool_name: 'get_invoice',
        args: { id: 'inv_1' },
        is_mutating: false
      });
      assert.equal(ahSpin.data.decision, 'BLOCK_SPIN_LOOP');

      stack.groundedHarness.startSession({
        session_id: 'gh-obs-1',
        goal: 'Compute fee ratio',
        model: 'gemma4:31b'
      });
      const ghStop = stack.groundedHarness.verifyStop({
        session_id: 'gh-obs-1',
        candidate_answer: 'np.float64(0.025)',
        expect_non_empty_answer: true
      });
      assert.equal(ghStop.data.action, 'REJECT_OUTPUT_DEFECT');

      const metrics = stack.observability.getMetrics();
      assert.equal(metrics.ok, true);
      assert.equal(metrics.data.memory.active, 1);
      assert.equal(metrics.data.harness_2pc.blocked_invariant, 1);
      assert.equal(metrics.data.harness_2pc.applied, 1);
      assert.equal(metrics.data.action_harness.spin_loops_blocked, 1);
      assert.equal(metrics.data.grounded_harness.output_defects_caught, 1);

      const blockedOnly = stack.observability.explainDecisions({ onlyBlocked: true, limit: 10 });
      assert.equal(blockedOnly.ok, true);
      assert.ok(blockedOnly.data.decisions.length >= 3);
      for (const item of blockedOnly.data.decisions) {
        assert.equal(item.blocked, true);
        assert.ok(typeof item.why === 'string' && item.why.length > 5);
      }

      const singleExplain = stack.observability.explainDecisions({ id: blockedTask.data.task_id });
      assert.equal(singleExplain.data.decisions.length, 1);
      assert.equal(singleExplain.data.decisions[0].status, 'BLOCKED_INVARIANT');

      const reportText = formatExplainReportText(blockedOnly, metrics);
      assert.equal(reportText.includes('—'), false);

      // Verify HTTP Gateway /telemetry and /explain honor Host & Bearer auth perimeter
      const gw = await startHttpGateway({
        stack,
        workspaceRoot: ws,
        apiToken: 'obs-secret-token',
        port: 0
      });
      try {
        const unauth = await rawHttpGet({ port: gw.port, urlPath: '/telemetry' });
        assert.equal(unauth.status, 401);

        const spoofHost = await rawHttpGet({
          port: gw.port,
          urlPath: '/telemetry',
          headers: {
            Host: 'evil.attacker.example',
            Authorization: 'Bearer obs-secret-token'
          }
        });
        assert.equal(spoofHost.status, 403);

        const authedMetrics = await rawHttpGet({
          port: gw.port,
          urlPath: '/telemetry',
          headers: { Authorization: 'Bearer obs-secret-token' }
        });
        assert.equal(authedMetrics.status, 200);
        assert.equal(authedMetrics.json?.data?.harness_2pc?.blocked_invariant, 1);

        const authedExplain = await rawHttpGet({
          port: gw.port,
          urlPath: '/explain?blocked=1&limit=5',
          headers: { Authorization: 'Bearer obs-secret-token' }
        });
        assert.equal(authedExplain.status, 200);
        assert.ok(authedExplain.json?.data?.decisions?.length >= 3);
      } finally {
        await new Promise((resolve) => gw.server.close(resolve));
      }
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('INV-STACK-15 & INV-SOLO-VOICE-01: Clean-room reproducer emits deterministic SHA-256 and public docs pass voice/em-dash gates', async () => {
    const runA = await runCleanRoomReproduction({ includeCrashDrill: false });
    const runB = await runCleanRoomReproduction({ includeCrashDrill: false });
    assert.equal(runA.ok, true);
    assert.equal(runB.ok, true);
    assert.equal(
      runA.data.deterministic_receipt_sha256,
      runB.data.deterministic_receipt_sha256,
      'Clean-room receipt SHA-256 must be identical across repeated runs'
    );
    assert.match(runA.data.deterministic_receipt_sha256, /^[0-9a-f]{64}$/);

    const docRelPaths = ['README.md', 'INSTALL.md', 'CONTRIBUTING.md', 'docs/PRODUCTION.md'];
    for (const rel of docRelPaths) {
      const abs = path.join(REPO_ROOT, rel);
      assert.equal(fs.existsSync(abs), true, `Expected documentation file ${rel} to exist`);
      const text = fs.readFileSync(abs, 'utf8');
      assert.equal(text.includes('—'), false, `${rel} must contain zero em dashes (INV-SOLO-VOICE-01)`);
      assert.equal(
        /\b(we|our|us|ours)\b/i.test(text),
        false,
        `${rel} must contain zero plural authorial pronouns (INV-SOLO-VOICE-01)`
      );
    }
  });
});
