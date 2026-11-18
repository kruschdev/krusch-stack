import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { createKruschStack } from '../src/index.js';
import { ALL_STACK_TOOLS } from '../src/mcp/server.js';
import { startHttpGateway } from '../bin/krusch-stack.js';
import {
  CANONICAL_SHARED_TYPES,
  STACK_ONTOLOGY_STACKS,
  STACK_ONTOLOGY_PORTS,
  STACK_ONTOLOGY_CHANNELS,
  STACK_ONTOLOGY_MOE_PROFILES,
  surrogateOntologyVertexId,
  isWebStandardPureBrickSource,
  areOntologyPortsCompatible,
  inspectBrickOntology,
  checkBrickOntologyCompatibility,
  composeCrossStackBricks,
  synthesizeHexagonalBinding,
  createBrickOntologyEngine
} from '../src/engines/brick-ontology-engine.js';

test('INV-LEGO-36 (Axis 1-4): deep-frozen registries, ontology inspection, Web-Standard edge purity, channel guards & time-series invariants', () => {
  assert.equal(ALL_STACK_TOOLS.length, 39, 'ALL_STACK_TOOLS.length must remain 39');

  assert.equal(Object.isFrozen(STACK_ONTOLOGY_STACKS), true);
  assert.equal(Object.isFrozen(STACK_ONTOLOGY_PORTS), true);
  assert.equal(Object.isFrozen(STACK_ONTOLOGY_CHANNELS), true);
  assert.equal(Object.isFrozen(STACK_ONTOLOGY_MOE_PROFILES), true);
  assert.equal(Object.isFrozen(STACK_ONTOLOGY_STACKS['cloudflare-edge']), true);
  assert.equal(Object.isFrozen(STACK_ONTOLOGY_PORTS.ledger_event.canonicalFields.gross.aliases), true);

  const fullInspect = inspectBrickOntology();
  assert.equal(fullInspect.ok, true);
  assert.equal(fullInspect.tool, 'krusch_brick_ontology_inspect');
  assert.equal(fullInspect.data.counts.stacks, 5);
  assert.equal(fullInspect.data.counts.ports, 6);
  assert.equal(fullInspect.data.counts.channels, 9);
  assert.equal(fullInspect.data.counts.moeProfiles, 4);

  const edgeFiltered = inspectBrickOntology({ stackFilter: 'cloudflare-edge', categoryFilter: 'webhook' });
  assert.equal(edgeFiltered.ok, true);
  assert.equal(edgeFiltered.data.stacks.length, 0);
  assert.equal(edgeFiltered.data.channels.length, 3);

  const stackOnly = inspectBrickOntology({ stackFilter: 'cloudflare-edge' });
  assert.equal(stackOnly.data.stacks.length, 1);
  assert.equal(stackOnly.data.stacks[0].requiresWebStandardPurity, true);

  // Pure TypeScript brick (even with comments mentioning node:fs / process.env) passes cloudflare-edge
  const pureTsSource = `
    // Runs in edge runtimes with zero node:fs or process.env coupling
    export function calcMargin(input: { gross: number }): { marginCents: number } {
      return { marginCents: Math.round(input.gross * 0.15) };
    }
  `;
  assert.equal(isWebStandardPureBrickSource(pureTsSource), true);

  const pureBundle = {
    brickId: 'margin-calc',
    source: pureTsSource,
    blueprint: {
      id: 'margin-calc',
      language: 'ts',
      exportName: 'calcMargin',
      ontology: {
        consumesPorts: ['ledger_event'],
        producesPorts: ['audit_record'],
        moeProfile: 'financial-integer-ledger'
      }
    }
  };

  const edgeOk = checkBrickOntologyCompatibility({
    bundle: pureBundle,
    targetStack: 'cloudflare-edge'
  });
  assert.equal(edgeOk.ok, true);
  assert.equal(edgeOk.data.bridgeMode, 'native');
  assert.equal(edgeOk.data.webStandardPure, true);

  // JS/TS brick targeting python-fastapi reports contract-adapter bridge mode
  const pyCompat = checkBrickOntologyCompatibility({
    bundle: pureBundle,
    targetStack: 'python-fastapi'
  });
  assert.equal(pyCompat.ok, true);
  assert.equal(pyCompat.data.bridgeMode, 'contract-adapter');
  assert.equal(pyCompat.data.adapterFileName, 'binding_adapter.py');

  // Bricks using node:fs or process.env fail closed on cloudflare-edge and react-vite
  const nodeFsBundle = {
    brickId: 'disk-reader',
    source: `import fs from 'node:fs';\nexport function readCfg(p) { return fs.readFileSync(p, 'utf8'); }`,
    blueprint: { id: 'disk-reader', exportName: 'readCfg' }
  };
  const procEnvBundle = {
    brickId: 'env-reader',
    source: `export function getMode() { return process.env.NODE_ENV || 'production'; }`,
    blueprint: { id: 'env-reader', exportName: 'getMode' }
  };

  assert.equal(isWebStandardPureBrickSource(nodeFsBundle.source), false);
  assert.equal(isWebStandardPureBrickSource(procEnvBundle.source), false);

  const fsEdgeCheck = checkBrickOntologyCompatibility({
    bundle: nodeFsBundle,
    targetStack: 'cloudflare-edge'
  });
  assert.equal(fsEdgeCheck.ok, false);
  assert.equal(fsEdgeCheck.error.code, 'STACK_RUNTIME_INCOMPATIBLE');

  const envReactCheck = checkBrickOntologyCompatibility({
    bundle: procEnvBundle,
    targetStack: 'react-vite'
  });
  assert.equal(envReactCheck.ok, false);
  assert.equal(envReactCheck.error.code, 'STACK_RUNTIME_INCOMPATIBLE');

  // Channel HMAC security guard enforcement
  const missingGuard = checkBrickOntologyCompatibility({
    bundle: pureBundle,
    targetStack: 'node-esm',
    targetChannel: 'webhook:stripe',
    enforceChannelGuards: true,
    providedSecurityBricks: []
  });
  assert.equal(missingGuard.ok, false);
  assert.equal(missingGuard.error.code, 'CHANNEL_SECURITY_GUARD_MISSING');

  const satisfiedGuard = checkBrickOntologyCompatibility({
    bundle: pureBundle,
    targetStack: 'node-esm',
    targetChannel: 'webhook:stripe',
    enforceChannelGuards: true,
    providedSecurityBricks: ['@krusch/toolkit/webhooks']
  });
  assert.equal(satisfiedGuard.ok, true);

  // Time-series NaN and non-monotonic timestamp invariant violations
  const tsBundle = {
    brickId: 'cadence-window',
    source: `export function rollWindow(input) { return { count: input.points.length }; }`,
    blueprint: {
      id: 'cadence-window',
      exportName: 'rollWindow',
      ontology: {
        consumesPorts: ['timeseries_window'],
        producesPorts: ['timeseries_window'],
        moeProfile: 'timeseries-cadence-moe'
      }
    }
  };

  const nanFail = checkBrickOntologyCompatibility({
    bundle: tsBundle,
    targetStack: 'node-esm',
    sampleData: { points: [{ ts: 1000, val: 12.5 }, { ts: 2000, val: Number.NaN }] }
  });
  assert.equal(nanFail.ok, false);
  assert.equal(nanFail.error.code, 'TIMESERIES_INVARIANT_VIOLATION');

  const nonMonotonicFail = checkBrickOntologyCompatibility({
    bundle: tsBundle,
    targetStack: 'node-esm',
    sampleData: { points: [{ ts: 3000, val: 1.0 }, { ts: 2000, val: 2.0 }] }
  });
  assert.equal(nonMonotonicFail.ok, false);
  assert.equal(nonMonotonicFail.error.code, 'TIMESERIES_INVARIANT_VIOLATION');

  const validTsOk = checkBrickOntologyCompatibility({
    bundle: tsBundle,
    targetStack: 'node-esm',
    sampleData: { points: [{ ts: 1000, val: -4.5 }, { ts: 2000, val: 6.25 }] }
  });
  assert.equal(validTsOk.ok, true);
});

test('INV-LEGO-36 (HydraScope Graph & Permissions): cross-org 2-hop composition, :SUPERSEDES + asOf replay, and PORT_NAMESPACE_COLLISION', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kruschstack-ontology-compose-'));
  try {
    const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });
    const engine = createBrickOntologyEngine({
      getAuthorizedBricksFn: (opts) =>
        stack.brickExchange.listInbox({
          viewerId: opts.viewerId,
          viewerOrgId: opts.viewerOrgId
        }),
      tryBrickFn: (opts) => stack.brickExchange.tryBrick(opts)
    });

    // 1. Seal org-ocean `stripe-webhook-normalizer` (webhook:stripe -> ledger_event)
    const normalizerSeal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'stripe-webhook-normalizer',
        name: 'Stripe Webhook Normalizer',
        exportName: 'normalizeStripeEvent',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        ontology: {
          channels: ['webhook:stripe'],
          consumesPorts: ['webhook_envelope'],
          producesPorts: ['ledger_event'],
          moeProfile: 'channel-security-normalizer',
          validFrom: '2026-01-01'
        }
      },
      source: `export function normalizeStripeEvent(input) {
        if (!input || typeof input.amount !== 'number' || input.amount < 0) throw new Error('Invalid event');
        return { gross: input.amount, currency: 'USD' };
      }`,
      positiveChecks: [
        {
          name: 'normalizes valid charge',
          input: { amount: 5000 },
          expectedOutput: { gross: 5000, currency: 'USD' }
        }
      ],
      faultChecks: [
        {
          name: 'rejects negative amount',
          input: { amount: -1 },
          expectThrow: true,
          expectedErrorSubstring: 'Invalid'
        }
      ],
      authorId: 'fabio',
      orgId: 'org-ocean',
      publish: true
    });
    assert.equal(normalizerSeal.ok, true);

    // 2. Seal org-solar `fee-allocator` v1 (2026-01-01) and superseding v2 (2026-06-01)
    const feeV1Seal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'fee-allocator',
        name: 'Fee Allocator v1',
        version: 'v1',
        exportName: 'splitFee',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        ontology: {
          consumesPorts: ['ledger_event'],
          producesPorts: ['audit_record'],
          moeProfile: 'financial-integer-ledger',
          validFrom: '2026-01-01'
        }
      },
      source: `export function splitFee(input) {
        if (!input || typeof input.gross !== 'number' || input.gross < 0) throw new Error('Invalid gross');
        const fee = Math.round((input.gross * 300) / 10000);
        return { net: input.gross - fee, fee, version: 'v1' };
      }`,
      positiveChecks: [
        { name: 'v1 10000', input: { gross: 10000 }, expectedOutput: { net: 9700, fee: 300, version: 'v1' } }
      ],
      faultChecks: [
        { name: 'v1 negative', input: { gross: -5 }, expectThrow: true, expectedErrorSubstring: 'Invalid' }
      ],
      authorId: 'maya',
      orgId: 'org-solar',
      publish: true
    });
    assert.equal(feeV1Seal.ok, true);
    const v1Hash = feeV1Seal.data.bundle.lineage.sourceHash;

    const feeV2Seal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'fee-allocator',
        name: 'Fee Allocator v2',
        version: 'v2',
        exportName: 'splitFee',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        ontology: {
          consumesPorts: ['ledger_event'],
          producesPorts: ['audit_record'],
          moeProfile: 'financial-integer-ledger',
          supersedes: [v1Hash],
          validFrom: '2026-06-01'
        }
      },
      source: `export function splitFee(input) {
        if (!input || typeof input.gross !== 'number' || input.gross < 0) throw new Error('Invalid gross');
        const fee = Math.round((input.gross * 250) / 10000);
        return { net: input.gross - fee, fee, version: 'v2' };
      }`,
      positiveChecks: [
        { name: 'v2 10000', input: { gross: 10000 }, expectedOutput: { net: 9750, fee: 250, version: 'v2' } }
      ],
      faultChecks: [
        { name: 'v2 negative', input: { gross: -5 }, expectThrow: true, expectedErrorSubstring: 'Invalid' }
      ],
      authorId: 'maya',
      orgId: 'org-solar',
      publish: true
    });
    assert.equal(feeV2Seal.ok, true);
    const v2Hash = feeV2Seal.data.bundle.lineage.sourceHash;

    // 3. Seal ungranted brick in org-vault to prove zero cross-org graph leakage
    const vaultSeal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'vault-secret-normalizer',
        name: 'Vault Secret Normalizer',
        exportName: 'normVault',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        ontology: {
          channels: ['webhook:stripe'],
          consumesPorts: ['webhook_envelope'],
          producesPorts: ['ledger_event']
        }
      },
      source: `export function normVault(input) {
        if (!input || typeof input.v !== 'number') throw new Error('Invalid');
        return { gross: input.v };
      }`,
      positiveChecks: [{ name: 'ok', input: { v: 1 }, expectedOutput: { gross: 1 } }],
      faultChecks: [{ name: 'bad', input: { v: 'x' }, expectThrow: true, expectedErrorSubstring: 'Invalid' }],
      authorId: 'alice',
      orgId: 'org-vault',
      publish: true
    });
    assert.equal(vaultSeal.ok, true);

    // Before grant from org-ocean -> maya, 2-hop composition from webhook:stripe has 0 pipelines
    const beforeGrant = engine.composeBricks({
      viewerId: 'maya',
      viewerOrgId: 'org-solar',
      targetStack: 'node-esm',
      targetChannel: 'webhook:stripe',
      requiredPorts: ['audit_record']
    });
    assert.equal(beforeGrant.ok, true);
    assert.equal(beforeGrant.data.compositions.length, 0);
    assert.equal(
      beforeGrant.data.graph.nodes.some((n) => n.properties?.brickId === 'vault-secret-normalizer'),
      false,
      'Ungranted cross-org brick must never enter compiled ontology graph'
    );

    // Issue scoped grant on stripe-webhook-normalizer to maya
    const grantRes = stack.brickExchange.issueGrant({
      brickId: normalizerSeal.data.bundle.brickId,
      sourceHash: normalizerSeal.data.bundle.lineage.sourceHash,
      issuerId: 'fabio',
      issuerOrgId: 'org-ocean',
      recipients: ['maya'],
      expiresAtMs: Date.now() + 60_000
    });
    assert.equal(grantRes.ok, true);

    // Current composition resolves 2-hop pipeline using v2 and retires v1
    const afterGrant = engine.composeBricks({
      viewerId: 'maya',
      viewerOrgId: 'org-solar',
      targetStack: 'node-esm',
      targetChannel: 'webhook:stripe',
      requiredPorts: ['audit_record']
    });
    assert.equal(afterGrant.ok, true);
    assert.equal(afterGrant.data.compositions.length, 1);

    const pipeline = afterGrant.data.compositions[0];
    assert.equal(pipeline.upstreamBrickId, 'stripe-webhook-normalizer');
    assert.equal(pipeline.bridgePort, 'ledger_event');
    assert.equal(pipeline.downstreamBrickId, 'fee-allocator');
    assert.equal(pipeline.steps[1].sourceHash, v2Hash);
    assert.equal(pipeline.steps[1].version, 'v2');

    // Verify 48-bit HydraScope safe integer surrogate vertex IDs & Cypher-clean SUPERSEDES edge
    assert.equal(afterGrant.data.graph.namespace, 'brick-ontology');
    for (const node of afterGrant.data.graph.nodes) {
      assert.equal(Number.isSafeInteger(node.surrogateId), true);
      assert.ok(node.surrogateId >= 1000 && node.surrogateId <= 281474976711655);
      assert.equal(
        node.surrogateId,
        surrogateOntologyVertexId('brick-ontology', node.logicalId),
        'Surrogate vertex ID must match @krusch/toolkit and HydraScope sha256(ns + "\\0" + id) bit-for-bit'
      );
    }
    assert.equal(
      afterGrant.data.graph.nodes.some((n) => n.logicalId === 'moe_profile:financial-integer-ledger'),
      true,
      'MoE vertices must use moe_profile: prefix'
    );
    assert.equal(afterGrant.data.retiredSupersededBricks.length, 1);
    assert.equal(afterGrant.data.retiredSupersededBricks[0].sourceHash, v1Hash);
    assert.equal(
      afterGrant.data.graph.edges.some((e) => e.type === 'SUPERSEDES'),
      true
    );
    for (const edge of afterGrant.data.graph.edges) {
      assert.equal(edge.type.startsWith(':'), false, 'Edge types must be Cypher-clean without leading colons');
    }

    // Temporal `asOf` replay prior to v2's 2026-06-01 cutover restores v1
    const replayAsOf = engine.composeBricks({
      viewerId: 'maya',
      viewerOrgId: 'org-solar',
      targetStack: 'node-esm',
      targetChannel: 'webhook:stripe',
      requiredPorts: ['audit_record'],
      asOf: '2026-03-15'
    });
    assert.equal(replayAsOf.ok, true);
    assert.equal(replayAsOf.data.retiredSupersededBricks.length, 0);
    assert.equal(replayAsOf.data.compositions.length, 1);
    assert.equal(replayAsOf.data.compositions[0].steps[1].sourceHash, v1Hash);
    assert.equal(replayAsOf.data.compositions[0].steps[1].version, 'v1');

    // Port namespace isolation (`slack:channel_id` !== `discord:channel_id`, unscoped `channel_id` rejected)
    assert.equal(CANONICAL_SHARED_TYPES.includes('repo_path'), true);
    assert.equal(areOntologyPortsCompatible('ledger_event', 'ledger_event'), true);
    assert.equal(areOntologyPortsCompatible('canonical:ledger_event', 'ledger_event'), true);
    assert.equal(areOntologyPortsCompatible('slack:channel_id', 'slack:channel_id'), true);
    assert.equal(areOntologyPortsCompatible('slack.channel_id', 'slack:channel_id'), true);
    assert.equal(areOntologyPortsCompatible('slack:channel_id', 'discord:channel_id'), false);
    assert.equal(areOntologyPortsCompatible('slack:channel_id', 'channel_id'), false);
    assert.equal(areOntologyPortsCompatible('channel_id', 'channel_id'), false);

    const slackEmitter = {
      brickId: 'slack-emitter',
      source: 'export function emitSlack() { return { channelId: "C123" }; }',
      blueprint: {
        id: 'slack-emitter',
        ontology: { producesPorts: ['slack:channel_id'] }
      }
    };
    const discordPoster = {
      brickId: 'discord-poster',
      source: 'export function postDiscord(x) { return { sent: Boolean(x.channelId) }; }',
      blueprint: {
        id: 'discord-poster',
        ontology: { consumesPorts: ['discord:channel_id'], producesPorts: ['audit_record'] }
      }
    };

    const collisionCheck = checkBrickOntologyCompatibility({
      bundle: discordPoster,
      targetStack: 'node-esm',
      upstreamProducedPorts: ['slack:channel_id']
    });
    assert.equal(collisionCheck.ok, false);
    assert.equal(collisionCheck.error.code, 'PORT_NAMESPACE_COLLISION');

    const collisionCompose = composeCrossStackBricks({
      authorizedBricks: [slackEmitter, discordPoster],
      targetStack: 'node-esm',
      requiredPorts: ['audit_record']
    });
    assert.equal(collisionCompose.ok, true);
    assert.equal(collisionCompose.data.compositions.length, 0);
    assert.equal(collisionCompose.data.namespaceCollisions.length, 1);
    assert.equal(collisionCompose.data.namespaceCollisions[0].producedPort, 'slack:channel_id');
    assert.equal(collisionCompose.data.namespaceCollisions[0].consumedPort, 'discord:channel_id');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('INV-LEGO-36 (Hexagonal Binding Synthesis): $0 binding.js, 2D header-row time-series & Python binding_adapter.py verified via real tryBrickFn', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kruschstack-ontology-bind-'));
  try {
    const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });

    // Seal a real fee+timestamp brick in KruschStack
    const sealed = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'ledger-fee-stamper',
        name: 'Ledger Fee Stamper',
        exportName: 'stampLedgerFee',
        inputSchema: {
          type: 'object',
          required: ['gross', 'ts'],
          properties: {
            gross: { type: 'number' },
            ts: { type: 'number' }
          }
        },
        bindingSchema: {
          type: 'object',
          properties: {
            feeBps: { type: 'number', default: 200 }
          }
        },
        outputSchema: { type: 'object' },
        ontology: {
          consumesPorts: ['ledger_event'],
          producesPorts: ['audit_record'],
          moeProfile: 'financial-integer-ledger'
        }
      },
      source: `export function stampLedgerFee(input, binding = {}) {
        if (!input || typeof input.gross !== 'number' || input.gross < 0 || typeof input.ts !== 'number') {
          throw new Error('Invalid canonical ledger_event');
        }
        const bps = typeof binding.feeBps === 'number' ? binding.feeBps : 200;
        const fee = Math.round((input.gross * bps) / 10000);
        return { net: input.gross - fee, fee, stampedTs: input.ts };
      }`,
      positiveChecks: [
        {
          name: 'canonical ledger_event',
          input: { gross: 10000, ts: 1700000000000 },
          binding: { feeBps: 250 },
          expectedOutput: { net: 9750, fee: 250, stampedTs: 1700000000000 }
        }
      ],
      faultChecks: [
        {
          name: 'rejects negative gross',
          input: { gross: -50, ts: 1700000000000 },
          expectThrow: true,
          expectedErrorSubstring: 'Invalid'
        }
      ],
      authorId: 'fabio',
      orgId: 'org-ocean',
      publish: true
    });
    assert.equal(sealed.ok, true);
    const bundle = sealed.data.bundle;

    // 1. Synthesize $0 Node ESM `binding.js` from snake_case local sample & verify in isolated sandbox
    const jsBindRes = await synthesizeHexagonalBinding({
      bundle,
      targetStack: 'node-esm',
      localSample: {
        amount_cents: 10000,
        recorded_at: 1700000000000
      },
      bindingOverrides: { feeBps: 250 },
      tryBrickFn: (opts) => stack.brickExchange.tryBrick(opts)
    });

    assert.equal(jsBindRes.ok, true);
    assert.equal(jsBindRes.data.costTier, 'TIER_0_DETERMINISTIC');
    assert.equal(jsBindRes.data.llmTokensUsed, 0);
    assert.equal(jsBindRes.data.adapterFileName, 'binding.js');
    assert.deepEqual(jsBindRes.data.fieldMap, {
      amount_cents: 'gross',
      recorded_at: 'ts'
    });
    assert.equal(jsBindRes.data.sandboxVerification.verified, true);
    assert.deepEqual(jsBindRes.data.sandboxVerification.output, {
      net: 9750,
      fee: 250,
      stampedTs: 1700000000000
    });

    // Vendor brick + synthesized binding.js into a real ESM repo and execute `invokeAdaptedBrick`
    const repoDir = path.join(tmpDir, 'consumer-esm');
    fs.mkdirSync(repoDir, { recursive: true });
    fs.writeFileSync(path.join(repoDir, 'package.json'), JSON.stringify({ type: 'module' }), 'utf8');

    const adoptRes = await stack.brickExchange.adoptBrick({
      bundle,
      targetRepoDir: repoDir,
      bindingSource: jsBindRes.data.adapterSource
    });
    assert.equal(adoptRes.ok, true);

    const vendoredBindingMod = await import(pathToFileURL(adoptRes.data.bindingPath).href);
    const liveExecOut = vendoredBindingMod.invokeAdaptedBrick({
      amount_cents: 20000,
      recorded_at: 1700000099000
    });
    assert.deepEqual(liveExecOut, {
      net: 19500,
      fee: 500,
      stampedTs: 1700000099000
    });

    // 2. Header-row detection on 2D time-series arrays verified via real tryBrickFn
    const tsSeal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'window-mean',
        name: 'Window Mean',
        exportName: 'computeWindowMean',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        ontology: {
          consumesPorts: ['timeseries_window'],
          producesPorts: ['timeseries_window'],
          moeProfile: 'timeseries-cadence-moe'
        }
      },
      source: `export function computeWindowMean(input) {
        if (!input || !Array.isArray(input.points) || input.points.length === 0) {
          throw new Error('Missing points');
        }
        let sum = 0;
        for (const p of input.points) {
          if (typeof p.ts !== 'number' || typeof p.val !== 'number') throw new Error('Bad point');
          sum += p.val;
        }
        return { count: input.points.length, mean: sum / input.points.length, lastTs: input.points[input.points.length - 1].ts };
      }`,
      positiveChecks: [
        {
          name: 'two points',
          input: { points: [{ ts: 1000, val: 10 }, { ts: 2000, val: 30 }] },
          expectedOutput: { count: 2, mean: 20, lastTs: 2000 }
        }
      ],
      faultChecks: [
        {
          name: 'empty points',
          input: { points: [] },
          expectThrow: true,
          expectedErrorSubstring: 'Missing'
        }
      ],
      publish: true
    });
    assert.equal(tsSeal.ok, true);

    const headerBindRes = await synthesizeHexagonalBinding({
      bundle: tsSeal.data.bundle,
      targetStack: 'node-esm',
      localSample: [
        ['recorded_at', 'reading'],
        [1700000000000, 15],
        [1700000060000, 25]
      ],
      tryBrickFn: (opts) => stack.brickExchange.tryBrick(opts)
    });
    assert.equal(headerBindRes.ok, true);
    assert.equal(headerBindRes.data.hasHeaderRow, true);
    assert.deepEqual(headerBindRes.data.fieldMap, {
      recorded_at: 'ts',
      reading: 'val'
    });
    assert.equal(headerBindRes.data.sandboxVerification.verified, true);
    assert.deepEqual(headerBindRes.data.sandboxVerification.output, {
      count: 2,
      mean: 20,
      lastTs: 1700000060000
    });

    // 3. Python `binding_adapter.py` contract-adapter synthesis from snake_case sample
    const pyBindRes = await synthesizeHexagonalBinding({
      bundle,
      targetStack: 'python-fastapi',
      localSample: {
        amount_cents: 10000,
        recorded_at: 1700000000000
      },
      bindingOverrides: { feeBps: 250 },
      tryBrickFn: (opts) => stack.brickExchange.tryBrick(opts)
    });
    assert.equal(pyBindRes.ok, true);
    assert.equal(pyBindRes.data.bridgeMode, 'contract-adapter');
    assert.equal(pyBindRes.data.adapterFileName, 'binding_adapter.py');
    assert.equal(pyBindRes.data.sandboxVerification.verified, false);
    assert.match(pyBindRes.data.adapterSource, /def adapt_input\(/);
    assert.match(pyBindRes.data.adapterSource, /"amount_cents": "gross"/);
    assert.match(pyBindRes.data.adapterSource, /"recorded_at": "ts"/);

    // Execute generated Python adapter with python3 if present on host
    const pyAdapterPath = path.join(tmpDir, 'binding_adapter.py');
    fs.writeFileSync(pyAdapterPath, pyBindRes.data.adapterSource, 'utf8');
    const pyProbe = spawnSync('python3', ['--version'], { encoding: 'utf8' });
    if (pyProbe.status === 0) {
      const pyRun = spawnSync(
        'python3',
        [
          '-c',
          'import json, sys; sys.path.insert(0, sys.argv[1]); import binding_adapter as b; print(json.dumps(b.adapt_input({"amount_cents": 4500, "recorded_at": 1700000123000})))',
          tmpDir
        ],
        { encoding: 'utf8' }
      );
      assert.equal(pyRun.status, 0, pyRun.stderr);
      const pyAdapted = JSON.parse(pyRun.stdout.trim());
      assert.equal(pyAdapted.gross, 4500);
      assert.equal(pyAdapted.ts, 1700000123000);
      assert.equal('amount_cents' in pyAdapted, false, 'Consumed raw alias key must be stripped');
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SEC-01/02/03 & ARCH-01: seal verification, malicious brickId breakout, unsigned ontology tamper, prototype/cycle/BigInt guards, additionalProperties:false & HTTP gateway hardening', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kruschstack-ontology-sec-'));
  let gateway = null;

  try {
    const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });

    // 1. Seal a strict `additionalProperties: false` TypeScript brick with top-level `ontology` option (`SEC-02`, `ARCH-01`)
    const strictSeal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'strict-ts-ledger',
        name: 'Strict TS Ledger',
        language: 'ts',
        exportName: 'computeStrictNet',
        inputSchema: {
          type: 'object',
          additionalProperties: false,
          required: ['gross', 'ts'],
          properties: {
            gross: { type: 'number' },
            ts: { type: 'number' }
          }
        },
        outputSchema: {
          type: 'object',
          required: ['net', 'ts'],
          properties: {
            net: { type: 'number' },
            ts: { type: 'number' }
          }
        }
      },
      ontology: {
        stacks: ['node-esm', 'typescript-node'],
        consumesPorts: ['ledger_event'],
        producesPorts: ['audit_record'],
        moeProfile: 'financial-integer-ledger',
        validFrom: '2026-02-01'
      },
      source: `export function computeStrictNet(input: { gross: number; ts: number }, binding: { feeBps?: number } = {}) {
        if (!input || typeof input.gross !== 'number' || input.gross < 0 || typeof input.ts !== 'number') {
          throw new Error('Invalid strict ledger input');
        }
        const bps = typeof binding.feeBps === 'number' ? binding.feeBps : 100;
        const fee = Math.round((input.gross * bps) / 10000);
        return { net: input.gross - fee, ts: input.ts };
      }`,
      positiveChecks: [
        {
          name: 'valid strict input',
          input: { gross: 10000, ts: 1700000000000 },
          binding: { feeBps: 100 },
          expectedOutput: { net: 9900, ts: 1700000000000 }
        }
      ],
      faultChecks: [
        {
          name: 'rejects negative gross',
          input: { gross: -1, ts: 1700000000000 },
          expectThrow: true,
          expectedErrorSubstring: 'Invalid'
        }
      ],
      authorId: 'fabio',
      orgId: 'org-ocean',
      publish: true
    });
    assert.equal(strictSeal.ok, true);
    const strictBundle = strictSeal.data.bundle;
    assert.deepEqual(strictBundle.blueprint.ontology, strictBundle.ontology);

    // Explicit stacks=['node-esm', 'typescript-node'] must fail closed on cloudflare-edge (`ARCH-01`)
    const restrictedStackCheck = checkBrickOntologyCompatibility({
      bundle: strictBundle,
      targetStack: 'cloudflare-edge'
    });
    assert.equal(restrictedStackCheck.ok, false);
    assert.equal(restrictedStackCheck.error.code, 'STACK_RUNTIME_INCOMPATIBLE');

    // Web-Standard purity scanner catches backtick dynamic import, globalThis['Buffer'], and destructured process (`ARCH-01`)
    assert.equal(isWebStandardPureBrickSource('export async function x() { return import(`node:fs`); }'), false);
    assert.equal(isWebStandardPureBrickSource("export function x() { return globalThis['Buffer'].from('a'); }"), false);
    assert.equal(isWebStandardPureBrickSource('export function x() { const { env } = process; return env; }'), false);
    assert.equal(
      isWebStandardPureBrickSource("import type { Stats } from 'node:fs';\nexport function x(a: number) { return a / 2 / 4; }"),
      true
    );

    // Unknown ontology slugs fail closed (`ARCH-01`)
    assert.equal(
      checkBrickOntologyCompatibility({
        bundle: { brickId: 'bad-stack', source: 'export const x = () => 1;', blueprint: { id: 'bad-stack', ontology: { stacks: ['rails'] } } },
        targetStack: 'node-esm'
      }).error.code,
      'UNKNOWN_ONTOLOGY_STACK'
    );
    assert.equal(
      checkBrickOntologyCompatibility({
        bundle: { brickId: 'bad-chan', source: 'export const x = () => 1;', blueprint: { id: 'bad-chan', ontology: { channels: ['webhook:bogus'] } } },
        targetStack: 'node-esm'
      }).error.code,
      'UNKNOWN_ONTOLOGY_CHANNEL'
    );
    assert.equal(
      checkBrickOntologyCompatibility({
        bundle: { brickId: 'bad-moe', source: 'export const x = () => 1;', blueprint: { id: 'bad-moe', ontology: { moeProfile: 'bogus-moe' } } },
        targetStack: 'node-esm'
      }).error.code,
      'UNKNOWN_MOE_PROFILE'
    );

    // :SUPERSEDES safety: bare "v1" rejected, cross-org supersession ignored, cycle prevented (`ARCH-01`)
    assert.equal(
      composeCrossStackBricks({
        authorizedBricks: [
          {
            brickId: 'bad-sup',
            source: 'export const x = () => 1;',
            blueprint: { id: 'bad-sup', ontology: { supersedes: ['v1'] } }
          }
        ]
      }).error.code,
      'INVALID_SUPERSEDES_REF'
    );
    const hashA = 'a'.repeat(64);
    const hashB = 'b'.repeat(64);
    const crossOrgAndCycleCompose = composeCrossStackBricks({
      authorizedBricks: [
        {
          brickId: 'solar-core',
          orgId: 'org-solar',
          sourceHash: hashA,
          source: 'export const a = () => 1;',
          blueprint: { id: 'solar-core', ontology: { supersedes: [hashB] } }
        },
        {
          brickId: 'evil-spoof',
          orgId: 'org-evil',
          sourceHash: hashB,
          source: 'export const b = () => 2;',
          blueprint: { id: 'evil-spoof', ontology: { supersedes: [hashA] } }
        }
      ]
    });
    assert.equal(crossOrgAndCycleCompose.ok, true);
    assert.equal(crossOrgAndCycleCompose.data.retiredSupersededBricks.length, 0);

    // 2. SEC-01: Malicious brickId comment/docstring breakout & unsealed bundles rejected before code-gen
    const breakoutBundle = {
      ...strictBundle,
      brickId: 'evil-brick*/\nglobalThis.__PWNED = true;/*\n"""\nimport os\n"""',
      blueprint: {
        ...strictBundle.blueprint,
        id: 'evil-brick*/\nglobalThis.__PWNED = true;/*\n"""\nimport os\n"""'
      }
    };
    const breakoutBind = await synthesizeHexagonalBinding({
      bundle: breakoutBundle,
      targetStack: 'node-esm',
      localSample: { amount_cents: 1000, recorded_at: 1700000000000 }
    });
    assert.equal(breakoutBind.ok, false);
    assert.equal(breakoutBind.error.code, 'INVALID_BRICK_BUNDLE');
    assert.equal(globalThis.__PWNED, undefined);

    const unsealedBind = await synthesizeHexagonalBinding({
      bundle: {
        brickId: 'unsealed-demo',
        source: 'export function run(x) { return x; }',
        blueprint: { id: 'unsealed-demo', exportName: 'run' }
      },
      targetStack: 'node-esm'
    });
    assert.equal(unsealedBind.ok, false);
    assert.equal(unsealedBind.error.code, 'INVALID_BRICK_BUNDLE');

    // 3. SEC-01: Recursive __proto__, depth > 24, circular object, and BigInt return clean error envelopes
    const protoPayload = JSON.parse('{"nested":{"__proto__":{"pollutedFlag":true}}}');
    const protoRes = await synthesizeHexagonalBinding({
      bundle: strictBundle,
      targetStack: 'node-esm',
      bindingOverrides: protoPayload
    });
    assert.equal(protoRes.ok, false);
    assert.equal(protoRes.error.code, 'ONTOLOGY_FORBIDDEN_KEY');
    assert.equal(({}).pollutedFlag, undefined);

    const circularSample = { amount_cents: 100 };
    circularSample.self = circularSample;
    const circularRes = await synthesizeHexagonalBinding({
      bundle: strictBundle,
      targetStack: 'node-esm',
      localSample: circularSample
    });
    assert.equal(circularRes.ok, false);
    assert.equal(circularRes.error.code, 'CIRCULAR_PAYLOAD');

    const bigIntRes = await synthesizeHexagonalBinding({
      bundle: strictBundle,
      targetStack: 'node-esm',
      bindingOverrides: { limit: 42n }
    });
    assert.equal(bigIntRes.ok, false);
    assert.equal(bigIntRes.error.code, 'UNSERIALIZABLE_PAYLOAD');

    let deepObj = { leaf: 1 };
    for (let d = 0; d < 28; d += 1) {
      deepObj = { next: deepObj };
    }
    const deepRes = await synthesizeHexagonalBinding({
      bundle: strictBundle,
      targetStack: 'node-esm',
      localSample: deepObj
    });
    assert.equal(deepRes.ok, false);
    assert.equal(deepRes.error.code, 'ONTOLOGY_MAX_DEPTH_EXCEEDED');

    // 4. SEC-02: Unsigned top-level bundle.ontology tamper rejected with TAMPERED_ONTOLOGY
    const tamperedOntologyBundle = {
      ...strictBundle,
      ontology: {
        ...strictBundle.ontology,
        channels: ['webhook:stripe']
      }
    };
    const verifyTampered = stack.brickExchange.verifyBrick(tamperedOntologyBundle);
    assert.equal(verifyTampered.ok, false);
    assert.equal(verifyTampered.error.code, 'TAMPERED_ONTOLOGY');

    const checkTampered = checkBrickOntologyCompatibility({
      bundle: tamperedOntologyBundle,
      targetStack: 'node-esm'
    });
    assert.equal(checkTampered.ok, false);
    assert.equal(checkTampered.error.code, 'TAMPERED_ONTOLOGY');

    const bindTampered = await synthesizeHexagonalBinding({
      bundle: tamperedOntologyBundle,
      targetStack: 'node-esm'
    });
    assert.equal(bindTampered.ok, false);
    assert.equal(bindTampered.error.code, 'TAMPERED_ONTOLOGY');

    // 5. ARCH-01: additionalProperties: false adapted sample passes real tryBrick & supports { canonical: local } fieldMap + ./index.ts + adoptBrick adapterFileName
    const strictAdaptedBind = await stack.brickExchange.synthesizeBinding({
      bundle: strictBundle,
      targetStack: 'node-esm',
      fieldMap: { gross: 'legacy_cents', ts: 'settled_epoch' },
      localSample: {
        legacy_cents: 10000,
        settled_epoch: 1700000000000,
        unmapped_extra_noise: 'must_be_stripped'
      },
      bindingOverrides: { feeBps: 200 }
    });
    assert.equal(strictAdaptedBind.ok, true);
    assert.equal(strictAdaptedBind.data.sandboxVerification.verified, true);
    assert.deepEqual(strictAdaptedBind.data.sandboxVerification.output, {
      net: 9800,
      ts: 1700000000000
    });
    assert.deepEqual(strictAdaptedBind.data.adaptedSample, {
      gross: 10000,
      ts: 1700000000000
    });
    assert.match(strictAdaptedBind.data.adapterSource, /from "\.\/index\.ts"/);

    // 1D object units header row adaptation
    const tsWindowSeal = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'unit-row-sum',
        name: 'Unit Row Sum',
        exportName: 'sumPoints',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' },
        ontology: {
          consumesPorts: ['timeseries_window'],
          producesPorts: ['timeseries_window'],
          moeProfile: 'timeseries-cadence-moe'
        }
      },
      source: `export function sumPoints(input) {
        if (!input || !Array.isArray(input.points) || input.points.length === 0) throw new Error('Empty');
        let total = 0;
        for (const p of input.points) {
          if (typeof p.ts !== 'number' || typeof p.val !== 'number') throw new Error('Non-numeric point');
          total += p.val;
        }
        return { rows: input.points.length, total };
      }`,
      positiveChecks: [
        {
          name: 'two points',
          input: { points: [{ ts: 60, val: 4 }, { ts: 120, val: 6 }] },
          expectedOutput: { rows: 2, total: 10 }
        }
      ],
      faultChecks: [
        { name: 'empty', input: { points: [] }, expectThrow: true, expectedErrorSubstring: 'Empty' }
      ]
    });
    assert.equal(tsWindowSeal.ok, true);

    const objHeaderBind = await stack.brickExchange.synthesizeBinding({
      bundle: tsWindowSeal.data.bundle,
      targetStack: 'node-esm',
      localSample: [
        { recorded_at: 'epoch_s', reading: 'm/s' },
        { recorded_at: 60, reading: 4.5 },
        { recorded_at: 120, reading: 5.5 }
      ]
    });
    assert.equal(objHeaderBind.ok, true);
    assert.equal(objHeaderBind.data.hasHeaderRow, true);
    assert.equal(objHeaderBind.data.sandboxVerification.verified, true);
    assert.deepEqual(objHeaderBind.data.sandboxVerification.output, { rows: 2, total: 10 });

    // adoptBrick honors adapterFileName (`binding.ts` and `binding_adapter.py`)
    const tsRepoDir = path.join(tmpDir, 'ts-consumer');
    const adoptTs = await stack.brickExchange.adoptBrick({
      bundle: strictBundle,
      targetRepoDir: tsRepoDir,
      adapterFileName: 'binding.ts'
    });
    assert.equal(adoptTs.ok, true);
    assert.equal(path.basename(adoptTs.data.bindingPath), 'binding.ts');
    assert.equal(fs.existsSync(path.join(tsRepoDir, 'bricks', 'strict-ts-ledger', 'binding.ts')), true);

    const pyRepoDir = path.join(tmpDir, 'py-consumer');
    const adoptPy = await stack.brickExchange.adoptBrick({
      bundle: strictBundle,
      targetRepoDir: pyRepoDir,
      targetStack: 'python-fastapi'
    });
    assert.equal(adoptPy.ok, true);
    assert.equal(path.basename(adoptPy.data.bindingPath), 'binding_adapter.py');
    assert.equal(fs.existsSync(path.join(pyRepoDir, 'bricks', 'strict-ts-ledger', 'binding_adapter.py')), true);

    // 6. SEC-03: HTTP Gateway blocks injected `authorizedBricks`, ignores `"tryBrickFn": false`, requires `viewerId`, and blocks `invariantScript`
    gateway = await startHttpGateway({ stack, port: 0 });
    const baseUrl = `http://${gateway.host}:${gateway.port}`;

    // Missing viewerId on POST /brick-exchange/ontology-compose -> 401
    const noViewerRes = await fetch(`${baseUrl}/brick-exchange/ontology-compose`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetStack: 'node-esm',
        authorizedBricks: [strictBundle]
      })
    });
    assert.equal(noViewerRes.status, 401);
    const noViewerBody = await noViewerRes.json();
    assert.equal(noViewerBody.ok, false);
    assert.equal(noViewerBody.error.code, 'VIEWER_AUTH_REQUIRED');

    // Unauthorized viewer with injected authorizedBricks -> 200 with 0 bricks (injected array stripped!)
    const injectedComposeRes = await fetch(`${baseUrl}/brick-exchange/ontology-compose`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        viewerId: 'eve-ungranted',
        viewerOrgId: 'org-outsider',
        targetStack: 'node-esm',
        authorizedBricks: [strictBundle]
      })
    });
    assert.equal(injectedComposeRes.status, 200);
    const injectedComposeBody = await injectedComposeRes.json();
    assert.equal(injectedComposeBody.ok, true);
    assert.equal(injectedComposeBody.data.graph.stats.authorizedBrickCount, 0);
    assert.equal(injectedComposeBody.data.directMatches.length, 0);

    // POST /brick-exchange/ontology-bind ignores `"tryBrickFn": false` and runs real sandbox verification (failing on negative gross!)
    const bypassTryRes = await fetch(`${baseUrl}/brick-exchange/ontology-bind`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bundle: strictBundle,
        targetStack: 'node-esm',
        tryBrickFn: false,
        localSample: {
          amount_cents: -500,
          recorded_at: 1700000000000
        }
      })
    });
    assert.equal(bypassTryRes.status, 400);
    const bypassTryBody = await bypassTryRes.json();
    assert.equal(bypassTryBody.ok, false);
    assert.equal(bypassTryBody.error.code, 'BINDING_VERIFICATION_FAILED');

    // Programmatic engine.synthesizeBinding also ignores non-function tryBrickFn: false
    const directBypassRes = await stack.brickExchange.synthesizeBinding({
      bundle: strictBundle,
      targetStack: 'node-esm',
      tryBrickFn: false,
      localSample: { amount_cents: -500, recorded_at: 1700000000000 }
    });
    assert.equal(directBypassRes.ok, false);
    assert.equal(directBypassRes.error.code, 'BINDING_VERIFICATION_FAILED');

    // POST /brick-exchange/verify-blast-radius blocks inline invariantScript over HTTP -> 403
    const rceAttemptRes = await fetch(`${baseUrl}/brick-exchange/verify-blast-radius`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repoDir: tsRepoDir,
        candidateEdits: { 'src/noop.js': 'export const n = 1;\n' },
        invariantScript: 'globalThis.__emitResult({ passed: true });'
      })
    });
    assert.equal(rceAttemptRes.status, 403);
    const rceAttemptBody = await rceAttemptRes.json();
    assert.equal(rceAttemptBody.ok, false);
    assert.equal(rceAttemptBody.error.code, 'HTTP_INVARIANT_SCRIPT_FORBIDDEN');
  } finally {
    if (gateway?.server) {
      await new Promise((resolve) => gateway.server.close(resolve));
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('P2 Parity: package.json ./brick-ontology subpath, openStackDatabase, runStackDoctor & stack.status() recognize brick_exchange_* and hydrascope_* tables on v1.2.0', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kruschstack-p2-parity-'));
  try {
    const pkgRaw = JSON.parse(
      fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
    );
    assert.equal(pkgRaw.exports['./brick-ontology'], './src/engines/brick-ontology-engine.js');
    assert.equal(pkgRaw.description.includes('\u2014'), false, 'package.json description must contain zero em dashes');

    const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: false });
    try {
      const doc = stack.doctor();
      assert.equal(doc.ok, true);
      assert.equal(doc.data.tables_verified.includes('brick_exchange_bricks'), true);
      assert.equal(doc.data.tables_verified.includes('brick_exchange_grants'), true);
      assert.equal(doc.data.tables_verified.includes('brick_exchange_adoptions'), true);

      const status = stack.status();
      assert.equal(status.ok, true);
      assert.equal(status.data.version, '1.2.0');
      assert.equal(status.data.brick_exchange_tables_ready, true);
      assert.equal(status.data.hydrascope_tables_ready, true);
      assert.equal(status.data.auxiliary_engines.brickExchange.ready, true);
      assert.equal(status.data.auxiliary_engines.hydrascope.ready, true);
    } finally {
      stack.db.close();
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
