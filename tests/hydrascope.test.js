import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  VERSION,
  createKruschStack,
  generateIdeConfig
} from '../src/index.js';
import {
  ALL_STACK_TOOLS,
  MODULAR_EXTENSION_TOOLS,
  createMcpServer,
  dispatchStackTool
} from '../src/mcp/server.js';
import { startHttpGateway } from '../bin/krusch-stack.js';

describe('INV-STACK-13: Tier 2C HydraScope Engine, Modular MCP & HTTP Gateway Parity', () => {
  test('HydraScope seeds 18-artifact FinTech graph in SQLite, traverses multi-hop + asOf SUPERSEDES, and auto-hydrates 4-Axis Brick Ontology', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-hydrascope-'));
    try {
      const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: false });
      try {
        const state = stack.hydrascope.getState();
        assert.equal(state.ok, true);
        assert.equal(state.tool, 'hydrascope_state');
        assert.equal(state.data.workspaceName, 'fintech-core');
        assert.ok(state.data.nodeCount >= 18);
        assert.ok(state.data.edgeCount >= 18);

        // 1. Pre-flight answerability gate: grounded query passes, unattested external subsystem abstains
        const ansOk = stack.hydrascope.checkAnswerable({
          query: 'How does settlement partner fee rounding work with ledger conservation?'
        });
        assert.equal(ansOk.ok, true);
        assert.equal(ansOk.data.answerable, true);

        const ansBlocked = stack.hydrascope.checkAnswerable({
          query: 'How are Kafka consumer groups scaled in our Kubernetes Istio cluster?'
        });
        assert.equal(ansBlocked.ok, true);
        assert.equal(ansBlocked.data.answerable, false);
        assert.ok(ansBlocked.data.ungroundedTerms.length >= 1);

        // 2. Multi-hop traversal + temporal asOf replay
        const currentTrav = await stack.hydrascope.traverseContext({
          query: 'What rounding policy governs calculatePartnerFee and settlement conservation?',
          tokenBudget: 1200,
          maxHops: 3
        });
        assert.equal(currentTrav.ok, true);
        assert.ok(currentTrav.data.selectedNodes.length >= 2);

        // 3. Vector vs. Graph comparison & 8-task Proof-Over-Vectors benchmark
        const cmp = await stack.hydrascope.compareVectorVsGraph({
          query: 'What webhook signature verification policy replaced legacy header checks?',
          tokenBudget: 1000,
          topK: 4
        });
        assert.equal(cmp.ok, true);
        assert.ok(typeof cmp.data.tokenSavingsPct === 'number');

        const bench = await stack.hydrascope.runBenchmark();
        assert.equal(bench.ok, true);
        assert.equal(bench.data.scenarios.length, 8);
        assert.equal(bench.data.metrics.graphSupersededPoisonRate, 0);
        assert.ok(bench.data.metrics.graphRecall >= 0.85);

        // 4. Live ADR supersession persists across SQLite reopen
        const sup = await stack.hydrascope.supersedeDecision({
          oldId: 'adr:ADR-014',
          newId: 'adr:ADR-099',
          title: 'ADR-099 Deterministic Basis-Point Floor Settlement',
          content: 'Enforce strict integer basis-point floor rounding with zero float intermediates.',
          governsIds: ['file:src/ledger/settlement.ts'],
          effectiveAt: '2026-11-01'
        });
        assert.equal(sup.ok, true);

        // 5. Seal & publish a brick, then verify hydrascope_traverse_context auto-hydrates brickOntology
        const sealed = await stack.brickExchange.sealBrick({
          blueprint: {
            id: 'settlement-fee-guard',
            exportName: 'guardFee',
            inputSchema: {
              type: 'object',
              additionalProperties: false,
              required: ['gross'],
              properties: { gross: { type: 'number' } }
            },
            outputSchema: { type: 'object' }
          },
          ontology: {
            consumesPorts: ['ledger_event'],
            producesPorts: ['audit_record'],
            moeProfile: 'financial-integer-ledger'
          },
          source: 'export function guardFee(x) { if (!x || x.gross < 0) throw new Error("neg"); return { net: x.gross }; }',
          positiveChecks: [{ name: 'pos', input: { gross: 500 }, expectedOutput: { net: 500 } }],
          faultChecks: [{ name: 'neg', input: { gross: -1 }, expectThrow: true, expectedErrorSubstring: 'neg' }],
          publish: true
        });
        assert.equal(sealed.ok, true);

        const ontTrav = await stack.hydrascope.traverseContext({
          query: 'calculatePartnerFee',
          viewerId: 'local-author',
          viewerOrgId: 'local-team',
          includeBrickOntology: true,
          requiredPorts: ['ledger_event', 'audit_record']
        });
        assert.equal(ontTrav.ok, true);
        assert.ok(ontTrav.data.brickOntology, 'Expected auto-hydrated brickOntology payload for authorized viewer');
        assert.equal(ontTrav.data.brickOntology.brickCount, 1);

        // SEC-03: Unauthenticated or outsider-org callers must never leak private org bricks
        const outsiderTrav = await stack.hydrascope.traverseContext({
          query: 'calculatePartnerFee',
          viewerId: 'outsider-user',
          viewerOrgId: 'outsider-org',
          includeBrickOntology: true,
          requiredPorts: ['ledger_event', 'audit_record']
        });
        assert.equal(outsiderTrav.ok, true);
        assert.equal(outsiderTrav.data.brickOntology.brickCount, 0);
      } finally {
        stack.db.close();
      }

      // Cold reopen verifies ADR-099 persisted in SQLite
      const reopened = createKruschStack({ workspaceRoot: tmpDir, ephemeral: false });
      try {
        const stateAfter = reopened.hydrascope.getState();
        assert.ok(
          stateAfter.data.decisions.some((d) => d.id === 'adr:ADR-099' && d.isCurrent),
          'ADR-099 must survive cold SQLite restart'
        );
      } finally {
        reopened.db.close();
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('Modular MCP servers (hydrascope, krusch-brick-exchange, krusch-grounded-harness) & HTTP Gateway preserve ALL_STACK_TOOLS.length === 39', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-modular-mcp-'));
    try {
      assert.equal(ALL_STACK_TOOLS.length, 39, 'Default unified ALL_STACK_TOOLS must stay 39');
      assert.equal(MODULAR_EXTENSION_TOOLS.length, 23, 'Expected 6 + 10 + 7 = 23 modular extension tools');

      for (const tool of MODULAR_EXTENSION_TOOLS) {
        for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
          assert.equal(typeof tool.annotations[hint], 'boolean', `${tool.name}.${hint} must be boolean`);
        }
      }

      const hydraMcp = createMcpServer({ workspaceRoot: tmpDir, ephemeral: true, server: 'hydrascope' });
      const brickMcp = createMcpServer({ workspaceRoot: tmpDir, ephemeral: true, server: 'krusch-brick-exchange' });
      const groundedMcp = createMcpServer({ workspaceRoot: tmpDir, ephemeral: true, server: 'krusch-grounded-harness' });
      const unifiedMcp = createMcpServer({ workspaceRoot: tmpDir, ephemeral: true, profile: 'full' });

      assert.equal(hydraMcp.tools.length, 6);
      assert.equal(brickMcp.tools.length, 10);
      assert.equal(groundedMcp.tools.length, 7);
      assert.equal(unifiedMcp.tools.length, 39);

      const modularCfg = generateIdeConfig({ ide: 'antigravity', mode: 'modular', profile: 'full', workspaceRoot: tmpDir });
      assert.ok(modularCfg.mcpServers.hydrascope);
      assert.ok(modularCfg.mcpServers['krusch-brick-exchange']);
      assert.ok(modularCfg.mcpServers['krusch-grounded-harness']);
      assert.ok(modularCfg.mcpServers['krusch-cascade-router']);
      assert.equal(Object.keys(modularCfg.mcpServers).length, 10);

      // Dispatch modular tools directly through dispatchStackTool
      const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });
      const mcpCheck = await dispatchStackTool(stack, 'hydrascope_check_answerable', {
        query: 'calculatePartnerFee'
      });
      assert.equal(mcpCheck.ok, true);

      const mcpScale = await dispatchStackTool(stack, 'krusch_resolve_scale_profile', {
        model: 'gemini-4-argon'
      });
      assert.equal(mcpScale.ok, true);
      assert.equal(mcpScale.data.profile.tier, 'FRONTIER_REASONING');

      const mcpInbox = await dispatchStackTool(stack, 'brick_inbox', { viewerId: 'dev-1' });
      assert.equal(mcpInbox.ok, true);

      // HTTP Gateway /hydrascope/* routes + path traversal block (403)
      fs.mkdirSync(path.join(tmpDir, 'subpkg'), { recursive: true });
      fs.writeFileSync(
        path.join(tmpDir, 'subpkg', 'service.py'),
        'import os\nAPI_TIMEOUT = os.getenv("API_TIMEOUT", "30")\ndef run_job(x):\n    return x\n',
        'utf8'
      );

      const gw = await startHttpGateway({ workspaceRoot: tmpDir, ephemeral: true, port: 0 });
      const baseUrl = `http://127.0.0.1:${gw.port}`;
      try {
        const stateRes = await fetch(`${baseUrl}/hydrascope/state`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: '{}'
        });
        assert.equal(stateRes.status, 200);
        const stateJson = await stateRes.json();
        assert.equal(stateJson.ok, true);
        assert.equal(stateJson.version || VERSION, VERSION);

        const escapeRes = await fetch(`${baseUrl}/hydrascope/ingest`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ targetDir: '../../etc', allowExternalPaths: true })
        });
        assert.equal(escapeRes.status, 403, 'HTTP ingest outside workspaceRoot must return 403');

        const ingestOk = await fetch(`${baseUrl}/hydrascope/ingest`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ targetDir: 'subpkg' })
        });
        assert.equal(ingestOk.status, 200);
        const ingestJson = await ingestOk.json();
        assert.equal(ingestJson.ok, true);
        assert.ok(ingestJson.data.nodeCount >= 2);
      } finally {
        await new Promise((resolve) => gw.server.close(resolve));
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
