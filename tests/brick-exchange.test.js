import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createKruschStack } from '../src/index.js';
import { ALL_STACK_TOOLS } from '../src/mcp/server.js';
import { startHttpGateway } from '../bin/krusch-stack.js';

test('INV-STACK-12: stack.brickExchange seals Ed25519 bricks, enforces scoped grants & .brick-lock.json drift, maps 2-hop AST fan-out waves, and preserves 39 MCP tools', async () => {
  assert.equal(ALL_STACK_TOOLS.length, 39, 'ALL_STACK_TOOLS.length must remain 39');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kruschstack-brick-exchange-'));
  let gateway = null;

  try {
    const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });

    // Missing fault challenge must fail closed
    const noFault = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'fee-allocator',
        name: 'Fee Allocator',
        exportName: 'splitFee',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' }
      },
      source: 'export function splitFee(x) { return { net: x.gross }; }',
      positiveChecks: [{ name: 'basic', input: { gross: 100 }, expectedOutput: { net: 100 } }],
      faultChecks: []
    });
    assert.equal(noFault.ok, false);

    // Full 4-gate seal + publish
    const sealed = await stack.brickExchange.sealBrick({
      blueprint: {
        id: 'fee-allocator',
        name: 'Fee Allocator',
        exportName: 'splitFee',
        inputSchema: { type: 'object' },
        outputSchema: { type: 'object' }
      },
      source: `export function splitFee(input: { gross: number }, binding: { feeBps?: number } = {}) {
        if (typeof input.gross !== 'number' || input.gross < 0) throw new Error('Invalid gross');
        const bps = typeof binding.feeBps === 'number' ? binding.feeBps : 250;
        const fee = Math.round((input.gross * bps) / 10000);
        return { net: input.gross - fee, fee };
      }`,
      positiveChecks: [{ name: 'clean 10000', input: { gross: 10000 }, binding: { feeBps: 250 }, expectedOutput: { net: 9750, fee: 250 } }],
      faultChecks: [{ name: 'rejects negative gross', input: { gross: -10 }, expectThrow: true, expectedErrorSubstring: 'Invalid' }],
      authorId: 'fabio',
      orgId: 'org-ocean',
      estimatedHoursSaved: 8,
      publish: true
    });
    assert.equal(sealed.ok, true);
    const bundle = sealed.data.bundle;
    assert.equal(bundle.format, 'krusch-sealed-brick/v1');

    // Cross-org viewer sees 0 bricks before grant, 1 brick after grant, 0 after revoke
    const beforeInbox = stack.brickExchange.listInbox({ viewerId: 'maya', viewerOrgId: 'org-solar' });
    assert.equal(beforeInbox.data.bricks.length, 0);

    const grant = stack.brickExchange.issueGrant({
      brickId: bundle.brickId,
      sourceHash: bundle.lineage.sourceHash,
      issuerId: 'fabio',
      issuerOrgId: 'org-ocean',
      recipients: ['maya'],
      expiresAtMs: Date.now() + 60_000
    });
    assert.equal(grant.ok, true);

    const afterInbox = stack.brickExchange.listInbox({ viewerId: 'maya', viewerOrgId: 'org-solar' });
    assert.equal(afterInbox.data.bricks.length, 1);

    // Local sandbox try + repo adopt + .brick-lock.json drift check
    const tryRes = await stack.brickExchange.tryBrick({
      bundle,
      sampleInput: { gross: 20000 },
      binding: { feeBps: 100 }
    });
    assert.equal(tryRes.ok, true);
    assert.deepEqual(tryRes.data.output, { net: 19800, fee: 200 });

    const repoDir = path.join(tmpDir, 'recipient-repo');
    fs.mkdirSync(path.join(repoDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(repoDir, 'package.json'), JSON.stringify({ type: 'module' }), 'utf8');

    const adoptRes = await stack.brickExchange.adoptBrick({
      bundle,
      targetRepoDir: repoDir,
      grantId: grant.data.grant.grant_id || grant.data.grant.id,
      userId: 'maya',
      orgId: 'org-solar'
    });
    assert.equal(adoptRes.ok, true);
    assert.equal(stack.brickExchange.auditBrickLocks({ targetRepoDir: repoDir }).data.clean, true);

    // Wire 2-hop chain in recipient-repo: bricks/fee-allocator/index.js -> src/settlement.js -> src/reconciler.js
    fs.writeFileSync(
      path.join(repoDir, 'src', 'settlement.js'),
      `import { splitFee } from '../bricks/fee-allocator/index.js';\nexport function runSettle(g) { return splitFee({ gross: g }); }\n`,
      'utf8'
    );
    fs.writeFileSync(
      path.join(repoDir, 'src', 'reconciler.js'),
      `import { runSettle } from './settlement.js';\nexport function checkBatch() { const r = runSettle(10000); return { passed: r.net + r.fee === 10000 }; }\n`,
      'utf8'
    );
    fs.writeFileSync(
      path.join(repoDir, 'src', 'leaf.js'),
      `export const leafOk = true;\n`,
      'utf8'
    );

    const blast = stack.brickExchange.analyzeBlastRadius({
      repoDir,
      changedFiles: ['bricks/fee-allocator/index.js'],
      protectedFiles: ['src/reconciler.js']
    });
    assert.equal(blast.ok, true);
    assert.deepEqual(blast.data.hop1Dependents, ['src/settlement.js']);
    assert.deepEqual(blast.data.hop2Dependents, ['src/reconciler.js']);

    const fanout = stack.brickExchange.planFanOut({
      repoDir,
      tasks: [
        { id: 'W1', targetFiles: ['bricks/fee-allocator/index.js'] },
        { id: 'W2', targetFiles: ['src/settlement.js'] },
        { id: 'W3', targetFiles: ['src/leaf.js'] }
      ],
      protectedFiles: ['src/reconciler.js']
    });
    assert.equal(fanout.ok, true);
    assert.equal(fanout.data.waves.length, 2);

    // HTTP Gateway smoke check on /brick-exchange/stats
    gateway = await startHttpGateway({ stack, port: 0 });
    const httpRes = await fetch(`http://${gateway.host}:${gateway.port}/brick-exchange/stats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    const statsBody = await httpRes.json();
    assert.equal(statsBody.ok, true);
    assert.equal(statsBody.data.brickCount, 1);

    // Revoke grant
    stack.brickExchange.revokeGrant({
      actorId: 'fabio',
      grantId: grant.data.grant.grant_id || grant.data.grant.id
    });
    assert.equal(
      stack.brickExchange.listInbox({ viewerId: 'maya', viewerOrgId: 'org-solar' }).data.bricks.length,
      0
    );
  } finally {
    if (gateway?.server) {
      await new Promise((resolve) => gateway.server.close(resolve));
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
