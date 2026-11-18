import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  createKruschStack,
  createToolGraphEngine,
  extractGivenTypesFromTask
} from '../src/index.js';
import { startHttpGateway } from '../bin/krusch-stack.js';

describe('INV-STACK-14: Git Alignment Guards, Sovereign ToolGraph & Polyglot Audit', () => {
  test('Tier 1 Git Alignment: --when/--require co-change rules, git blame causal rationale, Lego guard, and superseded stale-code scan', () => {
    const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-git-align-'));
    try {
      execFileSync('git', ['init'], { cwd: repoDir });
      execFileSync('git', ['config', 'user.name', 'Test Developer'], { cwd: repoDir });
      execFileSync('git', ['config', 'user.email', 'dev@example.com'], { cwd: repoDir });

      fs.mkdirSync(path.join(repoDir, 'src'), { recursive: true });
      fs.writeFileSync(
        path.join(repoDir, 'src', 'billing.js'),
        'export function chargeCard(cents) {\n  return Math.trunc(cents);\n}\n',
        'utf8'
      );
      execFileSync('git', ['add', '.'], { cwd: repoDir });
      execFileSync(
        'git',
        [
          'commit',
          '-m',
          'feat(billing): integer cent settlement\n\nConstraint: Never replace Math.trunc(cents) with floating-point division.'
        ],
        { cwd: repoDir }
      );
      const firstSha = execFileSync('git', ['rev-parse', '--short=8', 'HEAD'], {
        cwd: repoDir,
        encoding: 'utf8'
      }).trim();

      const stack = createKruschStack({ workspaceRoot: repoDir, ephemeral: true });

      // 1. Co-change companion rule in context_memories
      stack.context.remember({
        category: 'invariant',
        content:
          'Co-change contract: --when openapi/** --require CHANGELOG.md Update changelog whenever OpenAPI specs change.'
      });

      const badDiff = [
        'diff --git a/openapi/payments.yaml b/openapi/payments.yaml',
        'index 1111111..2222222 100644',
        '--- a/openapi/payments.yaml',
        '+++ b/openapi/payments.yaml',
        '@@ -1,2 +1,3 @@',
        ' openapi: 3.1.0',
        '+info: { version: "2.0" }'
      ].join('\n');

      const coNudgeFail = stack.context.nudge({ trigger: 'pre_commit', code: badDiff });
      assert.equal(coNudgeFail.ok, true);
      assert.equal(coNudgeFail.data.passed, false);
      assert.ok(coNudgeFail.data.cochange_violations_count >= 1);

      const goodDiff = [
        badDiff,
        'diff --git a/CHANGELOG.md b/CHANGELOG.md',
        '--- a/CHANGELOG.md',
        '+++ b/CHANGELOG.md',
        '@@ -1 +1,2 @@',
        ' # Changelog',
        '+- Bumped payments spec to 2.0'
      ].join('\n');

      const coNudgePass = stack.context.nudge({ trigger: 'pre_commit', code: goodDiff });
      assert.equal(coNudgePass.data.cochange_violations_count, 0);

      // 2. Blame attribution on rewritten hunk surfaces causal commit Constraint
      const rewriteBillingDiff = [
        'diff --git a/src/billing.js b/src/billing.js',
        '--- a/src/billing.js',
        '+++ b/src/billing.js',
        '@@ -1,3 +1,3 @@',
        ' export function chargeCard(cents) {',
        '-  return Math.trunc(cents);',
        '+  return cents / 100;',
        ' }'
      ].join('\n');

      const blameNudge = stack.context.nudge({ trigger: 'pre_commit', code: rewriteBillingDiff });
      assert.equal(blameNudge.data.passed, false);
      assert.ok(blameNudge.data.blame_matches_count >= 1);

      // 3. Superseded commit stale-code scan in health()
      const oldMem = stack.context.remember({
        category: 'decision',
        content: `Initial billing logic shipped in commit ${firstSha}.`,
        provenance: {
          file: 'src/billing.js',
          locator: 'L1-L3',
          quoted_sentence: 'return Math.trunc(cents);'
        }
      });
      stack.context.revise({
        action: 'supersede',
        target_id: oldMem.data.id,
        new_content: 'Migrate billing.js to ledger integer allocator v2.',
        reason: 'v2 ledger cutover'
      });

      const health = stack.context.health();
      assert.equal(health.ok, true);
      assert.ok(health.data.stale_code_findings >= 1);
      assert.ok(health.data.stale_code_lines >= 1);

      // 4. Opt-in Lego boilerplate guard
      const legoNudge = stack.context.nudge({
        trigger: 'pre_commit',
        code: '+ const srv = http.createServer((req, res) => res.end("raw"));',
        enable_lego_guard: true
      });
      assert.equal(legoNudge.data.passed, false);
    } finally {
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
  });

  test('Sovereign ToolGraph prerequisite closure, Polyglot Audit 28-rule scanner, subpath exports, and HTTP routes', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-toolgraph-'));
    try {
      const pkg = JSON.parse(
        fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
      );
      for (const subpath of [
        './hydrascope',
        './git-alignment',
        './tool-graph',
        './polyglot-audit',
        './grounded-auth-drift',
        './grounded-trace-synthesizer'
      ]) {
        assert.ok(pkg.exports[subpath], `Missing package.json export ${subpath}`);
      }

      // 1. Sovereign ToolGraph prerequisite closure + channel_id namespace isolation
      const mockTools = [
        {
          name: 'slack.find_channel',
          component: 'slack',
          description: 'Find a Slack channel by channel name and return its channel_id.',
          inputSchema: {
            type: 'object',
            properties: { channel_name: { type: 'string' } },
            required: ['channel_name']
          },
          outputSchema: {
            type: 'object',
            properties: { channel_id: { type: 'string' } }
          }
        },
        {
          name: 'slack.post_message',
          component: 'slack',
          description: 'Post message to a Slack channel using its channel_id.',
          inputSchema: {
            type: 'object',
            required: ['channel_id', 'text'],
            properties: { channel_id: { type: 'string' }, text: { type: 'string' } }
          }
        },
        {
          name: 'discord.find_channel',
          component: 'discord',
          description: 'Find a Discord channel and return its channel_id.',
          inputSchema: { type: 'object', properties: {} },
          outputSchema: {
            type: 'object',
            properties: { channel_id: { type: 'string' } }
          }
        }
      ];

      const tg = createToolGraphEngine(mockTools, { maxReturnedTools: 4 });
      const routed = tg.findTools({ task: 'Post a launch update message to #general on Slack' });
      assert.equal(routed.ok, true);
      const selectedNames = routed.data.tools.map((t) => t.name);
      assert.ok(selectedNames.includes('slack.post_message'));
      assert.ok(selectedNames.includes('slack.find_channel'), 'Must pull Slack prerequisite producer');
      assert.equal(
        selectedNames.includes('discord.find_channel'),
        false,
        'Must isolate slack.channel_id from discord.channel_id'
      );

      const given = extractGivenTypesFromTask('Inspect ./src/engines/index.js and notify ops@example.com');
      assert.ok(given.givenTypes.includes('file_path'));
      assert.ok(given.givenTypes.includes('email_address'));

      // 2. Polyglot Audit across PHP & JS + SSRF repo input normalizer
      const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });
      const phpAudit = stack.polyglotAudit.auditSource(
        '<?php $res = mysql_query("SELECT * FROM users WHERE id = " . $_GET["id"]); echo md5($pw); ?>',
        'legacy/auth.php'
      );
      assert.equal(phpAudit.ok, true);
      assert.ok(phpAudit.data.findings.length >= 1);

      const badUrl = stack.polyglotAudit.normalizeRepoInput('http://169.254.169.254/latest/meta-data');
      assert.equal(badUrl.ok, false);
      assert.equal(badUrl.data.cleanHttpsUrl, null);
      assert.equal(badUrl.data.repoSlug, null);

      // 3. HTTP Gateway /tool-graph/* and /polyglot-audit/*
      const gw = await startHttpGateway({ workspaceRoot: tmpDir, ephemeral: true, port: 0 });
      const baseUrl = `http://127.0.0.1:${gw.port}`;
      try {
        const tgRes = await fetch(`${baseUrl}/tool-graph/find`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ task: 'Search AST symbols and stage a 2PC diff' })
        });
        assert.equal(tgRes.status, 200);
        const tgJson = await tgRes.json();
        assert.equal(tgJson.ok, true);
        assert.ok(tgJson.data.tools.length >= 1);

        const polyEscape = await fetch(`${baseUrl}/polyglot-audit/repository`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ targetDir: '../../etc' })
        });
        assert.equal(polyEscape.status, 403);
      } finally {
        await new Promise((resolve) => gw.server.close(resolve));
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
