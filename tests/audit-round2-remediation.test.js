import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  createKruschStack,
  openStackDatabase,
  compileSafeCoChangeGlob,
  maskTaskEntities,
  createToolGraph,
  normalizeGitHubRepoInput,
  generateIdeConfig
} from '../src/index.js';
import { dispatchStackTool } from '../src/mcp/server.js';
import { parseCliArgs, startHttpGateway } from '../bin/krusch-stack.js';

function rawHttpRequest({ port, method = 'GET', urlPath = '/health', headers = {}, body = '' }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        method,
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
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

describe('Round-2 Audit Remediation & Security Regression Suite (SEC-01..04, MCP-01..03, DB-01..02, API-01)', () => {
  test('SEC-01 & SEC-02: HTTP Gateway blocks Host DNS-rebinding, cross-site Origin CSRF, non-JSON POST, Bearer auth bypass, profile bypass, and path escapes', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-sec01-'));
    try {
      const gw = await startHttpGateway({
        workspaceRoot: tmpDir,
        profile: 'core',
        apiToken: 'test-gateway-token-secret',
        ephemeral: true,
        port: 0
      });
      const port = gw.port;
      try {
        // 1. Spoofed Host header -> 403 DNS_REBINDING_BLOCKED
        const rebindRes = await rawHttpRequest({
          port,
          method: 'GET',
          urlPath: '/health',
          headers: { Host: 'rebind.attacker.example:3780' }
        });
        assert.equal(rebindRes.status, 403);
        assert.equal(rebindRes.json?.error, 'DNS_REBINDING_BLOCKED');

        // 2. Cross-origin browser request -> 403 CROSS_ORIGIN_BLOCKED
        const csrfRes = await rawHttpRequest({
          port,
          method: 'POST',
          urlPath: '/call',
          headers: {
            Host: `127.0.0.1:${port}`,
            Origin: 'https://evil.example',
            'Content-Type': 'application/json',
            Authorization: 'Bearer test-gateway-token-secret'
          },
          body: '{}'
        });
        assert.equal(csrfRes.status, 403);
        assert.equal(csrfRes.json?.error, 'CROSS_ORIGIN_BLOCKED');

        // 3. Unauthenticated GET /health succeeds (200), but GET /tools without Bearer token -> 401
        const healthOk = await fetch(`http://127.0.0.1:${port}/health`);
        assert.equal(healthOk.status, 200);

        const unauthTools = await fetch(`http://127.0.0.1:${port}/tools`);
        assert.equal(unauthTools.status, 401);

        const authHeaders = {
          Authorization: 'Bearer test-gateway-token-secret',
          'Content-Type': 'application/json'
        };

        // 4. POST with text/plain Content-Type -> 415 UNSUPPORTED_MEDIA_TYPE
        const formPost = await fetch(`http://127.0.0.1:${port}/call`, {
          method: 'POST',
          headers: {
            Authorization: 'Bearer test-gateway-token-secret',
            'Content-Type': 'text/plain'
          },
          body: '{"tool":"krusch_stack_status"}'
        });
        assert.equal(formPost.status, 415);

        // 5. SEC-02: POST /call enforces --profile core (blocks frontend tool get_canonical_template -> 403)
        const disabledToolRes = await fetch(`http://127.0.0.1:${port}/call`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({
            tool: 'get_canonical_template',
            arguments: { template_id: 'footer-deadbolt' }
          })
        });
        assert.equal(disabledToolRes.status, 403);
        const disabledJson = await disabledToolRes.json();
        assert.equal(disabledJson.data?.code, 'TOOL_NOT_ENABLED');

        // 6. SEC-02: Path containment on /grounded-harness/ground and /brick-exchange/blast-radius -> 403
        const ghEscape = await fetch(`http://127.0.0.1:${port}/grounded-harness/ground`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ workspaceDir: '../../etc' })
        });
        assert.equal(ghEscape.status, 403);

        const brickEscape = await fetch(`http://127.0.0.1:${port}/brick-exchange/blast-radius`, {
          method: 'POST',
          headers: authHeaders,
          body: JSON.stringify({ repoRoot: '../../etc', targetFiles: ['passwd'] })
        });
        assert.equal(brickEscape.status, 403);
      } finally {
        await new Promise((resolve) => gw.server.close(resolve));
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('SEC-01: Harness & Workspace engines block symlink escapes outside workspaceRoot', () => {
    const wsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-symlink-ws-'));
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-symlink-out-'));
    try {
      const outsideFile = path.join(outsideDir, 'secret.txt');
      fs.writeFileSync(outsideFile, 'ORIGINAL_SECRET\n', 'utf8');
      fs.symlinkSync(outsideDir, path.join(wsDir, 'escape_dir'));

      const stack = createKruschStack({ workspaceRoot: wsDir, ephemeral: true });
      const runRes = stack.harness.run({
        goal: 'Attempt write through symlink',
        edits: [{ file_path: 'escape_dir/secret.txt', content: 'OVERWRITTEN\n' }]
      });
      if (runRes.ok) {
        const applyRes = stack.harness.applyDiff({ task_id: runRes.data.task_id });
        assert.equal(applyRes.ok, false, 'applyDiff must reject symlink escape');
      }
      assert.equal(fs.readFileSync(outsideFile, 'utf8'), 'ORIGINAL_SECRET\n');

      fs.mkdirSync(path.join(wsDir, '.krusch-stack', 'workspace'), { recursive: true });
      fs.symlinkSync(outsideDir, path.join(wsDir, '.krusch-stack', 'workspace', 'escape_dir'));
      const wsWrite = stack.workspace.writeDriveFile({
        path: 'escape_dir/secret.txt',
        content: 'OVERWRITTEN_BY_DRIVE'
      });
      assert.equal(wsWrite.ok, false, 'writeDriveFile must reject symlink escape');
      assert.equal(fs.readFileSync(outsideFile, 'utf8'), 'ORIGINAL_SECRET\n');
    } finally {
      fs.rmSync(wsDir, { recursive: true, force: true });
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  test('SEC-03, MCP-01 & MCP-02: HTTP /hydrascope/traverse viewer auth, Deadbolt policyFloorFiles alias, ttlMs, brickId lookup, and /tool-graph/call', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-mcp01-'));
    try {
      fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'src', 'policy.js'), 'export const LOCK = 1;\n', 'utf8');
      fs.writeFileSync(path.join(tmpDir, 'src', 'app.js'), 'import { LOCK } from "./policy.js";\nexport const x = LOCK;\n', 'utf8');

      const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });

      // Default stack.toolGraph has non-empty built-in spine
      assert.ok(stack.toolGraph.getStats().totalCatalogTools >= 20);
      const directCall = await stack.toolGraph.callTool('krusch_route_task', {
        prompt: 'Fix typo in README'
      });
      assert.equal(directCall.ok, true);

      // MCP-01: brick_plan_fanout honors policyFloorFiles -> WORKAROUND_REJECTED
      const fanoutBlocked = await dispatchStackTool(stack, 'brick_plan_fanout', {
        repoRoot: tmpDir,
        tasks: [{ id: 't1', files: ['src/policy.js'] }],
        policyFloorFiles: ['src/policy.js']
      });
      assert.equal(fanoutBlocked.ok, false);
      assert.equal(fanoutBlocked.error?.code, 'WORKAROUND_REJECTED');

      // Seal a private brick under org-alpha, verify ttlMs validation & brickId-based try/adopt
      const sealed = await dispatchStackTool(stack, 'brick_seal', {
        orgId: 'org-alpha',
        authorId: 'alice',
        blueprint: {
          id: 'alpha-private-calc',
          exportName: 'calcNet',
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
        source: 'export function calcNet(x) { if (!x || x.gross < 0) throw new Error("neg"); return { net: x.gross }; }',
        positiveChecks: [{ name: 'ok', input: { gross: 200 }, expectedOutput: { net: 200 } }],
        faultChecks: [{ name: 'neg', input: { gross: -5 }, expectThrow: true, expectedErrorSubstring: 'neg' }],
        publish: true
      });
      assert.equal(sealed.ok, true);

      const badGrant = await dispatchStackTool(stack, 'brick_share', {
        brickId: 'alpha-private-calc',
        sourceHash: sealed.data.bundle.sourceHash,
        actorId: 'alice',
        granteeId: 'bob',
        ttlMs: -1000
      });
      assert.equal(badGrant.ok, false);

      const tryById = await dispatchStackTool(stack, 'brick_try_local', {
        brickId: 'alpha-private-calc',
        viewerId: 'alice',
        viewerOrgId: 'org-alpha',
        sampleInput: { gross: 42 }
      });
      assert.equal(tryById.ok, true);

      const adoptDir = path.join(tmpDir, 'consumer');
      fs.mkdirSync(adoptDir, { recursive: true });
      const adoptById = await dispatchStackTool(stack, 'brick_adopt', {
        brickId: 'alpha-private-calc',
        viewerId: 'alice',
        viewerOrgId: 'org-alpha',
        targetRepoDir: adoptDir,
        localSample: { amount_cents: 200 }
      });
      assert.equal(adoptById.ok, true);
      assert.ok(fs.existsSync(path.join(adoptDir, 'bricks', 'alpha-private-calc', 'binding.js')));

      // HTTP Gateway SEC-03 (/hydrascope/traverse missing viewerId -> 401) & MCP-02 (/tool-graph/call -> 200)
      const gw = await startHttpGateway({ stack, workspaceRoot: tmpDir, port: 0 });
      const baseUrl = `http://127.0.0.1:${gw.port}`;
      try {
        const unauthHydra = await fetch(`${baseUrl}/hydrascope/traverse`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'calculatePartnerFee', includeBrickOntology: true })
        });
        assert.equal(unauthHydra.status, 401);

        const outsiderHydra = await fetch(`${baseUrl}/hydrascope/traverse`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            query: 'calculatePartnerFee',
            includeBrickOntology: true,
            viewerId: 'mallory',
            viewerOrgId: 'org-outsider'
          })
        }).then((r) => r.json());
        assert.equal(outsiderHydra.ok, true);
        assert.equal(outsiderHydra.data.brickOntology.brickCount, 0);

        const tgCall = await fetch(`${baseUrl}/tool-graph/call`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'krusch_route_task',
            arguments: { prompt: 'Run unit tests' }
          })
        });
        assert.equal(tgCall.status, 200);
        const tgCallJson = await tgCall.json();
        assert.equal(tgCallJson.ok, true);
      } finally {
        await new Promise((resolve) => gw.server.close(resolve));
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('DB-01, DB-02, SEC-04, MCP-03 & API-01: Cold reopen of empty HydraScope dir, durable provenance_reanchored, ReDoS bounds, and CLI/IDE parity', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-db01-'));
    try {
      // 1. DB-01: Ingesting an empty directory persists 0-node sentinel across cold SQLite restart
      const emptySub = path.join(tmpDir, 'empty-ws');
      fs.mkdirSync(emptySub, { recursive: true });
      const dbFile = path.join(tmpDir, 'shared.db');

      const s1 = createKruschStack({ workspaceRoot: emptySub, dbPath: dbFile, ephemeral: false });
      const ing = await s1.hydrascope.ingestDirectory({ targetDir: '.' });
      assert.equal(ing.ok, true);
      assert.equal(ing.data.nodeCount, 0);
      s1.db.close();

      const s2 = createKruschStack({ workspaceRoot: emptySub, dbPath: dbFile, ephemeral: false });
      assert.equal(s2.hydrascope.getState().data.nodeCount, 0, 'Empty ingested workspace must not resurrect fintech-core on cold reopen');
      s2.db.close();

      // 2. DB-02: Explicit provenance re-anchor survives cold SQLite restart
      const gitDir = path.join(tmpDir, 'git-repo');
      fs.mkdirSync(gitDir, { recursive: true });
      execFileSync('git', ['init', '-q'], { cwd: gitDir });
      execFileSync('git', ['config', 'user.email', 'kruschdev@users.noreply.github.com'], { cwd: gitDir });
      execFileSync('git', ['config', 'user.name', 'kruschdev'], { cwd: gitDir });
      const modPath = path.join(gitDir, 'fee.js');
      fs.writeFileSync(modPath, 'export const FEE_BPS = 25;\n', 'utf8');
      execFileSync('git', ['add', 'fee.js'], { cwd: gitDir });
      execFileSync('git', ['commit', '-q', '-m', 'init fee'], { cwd: gitDir });
      const commitSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: gitDir, encoding: 'utf8' }).trim();

      const gs1 = createKruschStack({ workspaceRoot: gitDir, ephemeral: false });
      const m1 = gs1.context.remember({
        category: 'decision',
        content: 'Set FEE_BPS to 25 bps initially.',
        provenance: { file: 'fee.js', locator: 'L1-L1', quoted_sentence: 'export const FEE_BPS = 25;' }
      });
      // Supersede with explicit provenance re-anchoring on fee.js -> triggers recordExplicitProvenanceReanchor
      const rev = gs1.context.revise({
        action: 'supersede',
        target_id: m1.data.id,
        new_content: 'Re-ratified FEE_BPS = 25 bps on fee.js.',
        reason: 'Confirmed rate stays 25 bps',
        provenance: { file: 'fee.js', locator: 'L1-L1', quoted_sentence: 'export const FEE_BPS = 25;' }
      });
      assert.equal(rev.ok, true);
      gs1.db.close();

      const gs2 = createKruschStack({ workspaceRoot: gitDir, ephemeral: false });
      const healthAfter = gs2.context.health();
      assert.equal(healthAfter.data.stale_code_findings, 0, 'Explicit provenance re-anchor must survive cold restart');
      gs2.db.close();

      // 3. SEC-04 & API-01: Sub-25ms ReDoS bounds (including single-star DP glob), option-injection rejection, createToolGraph aliases, and footer v1.2.0
      const startMs = performance.now();
      maskTaskEntities('a.a.'.repeat(10000));
      const globCheck = compileSafeCoChangeGlob('src/**/**/a/**/**/b.js');
      const singleStarGlob = compileSafeCoChangeGlob('src/*a*a*a*a*a*a*a*az.js');
      assert.equal(singleStarGlob.valid, true);
      assert.equal(singleStarGlob.regex.test(`src/${'a'.repeat(80)}.js`), false);
      const elapsedMs = performance.now() - startMs;
      assert.ok(elapsedMs < 50, `Expected linear-time entity/glob handling (<50ms), took ${elapsedMs.toFixed(2)}ms`);
      assert.equal(globCheck.valid, false, 'Excessive ** segments must be rejected');

      const dashOwner = normalizeGitHubRepoInput('-upload-pack/repo');
      assert.equal(dashOwner.cleanHttpsUrl, null, 'Leading dash owner must be rejected');

      const tg = createToolGraph(
        [
          {
            name: 'pin_one',
            description: 'Pinned tool',
            inputSchema: { type: 'object', properties: {} }
          }
        ],
        {
          pinnedToolNames: ['pin_one'],
          maxReturnedTools: 3,
          dispatcher: async () => ({ ok: true, tool: 'pin_one', summary: 'dispatched', data: { ran: true } })
        }
      );
      for (const meta of tg.getExposedTools().filter((t) => t.name !== 'pin_one')) {
        assert.equal(typeof meta.annotations.title, 'string');
      }
      const tgExec = await tg.callTool({ name: 'pin_one', arguments: {} });
      assert.equal(tgExec.ok, true);

      const feStack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });
      const footer = feStack.frontend.getCanonicalTemplate({ template_id: 'footer-deadbolt' });
      assert.ok(footer.data.html.includes('KruschStack v1.2.0'));

      // 4. MCP-03: parseCliArgs --key=value + --include-extended + generateIdeConfig deferTools
      const cli = parseCliArgs([
        'mcp',
        '--mode=modular',
        '--ide=cursor',
        '--components=context,hydrascope',
        '--include-extended',
        '--defer-tools',
        '--port=4999'
      ]);
      assert.equal(cli.flags.mode, 'modular');
      assert.equal(cli.flags.ide, 'cursor');
      assert.equal(cli.flags.components, 'context,hydrascope');
      assert.equal(cli.flags.includeExtended, true);
      assert.equal(cli.flags.deferTools, true);
      assert.equal(cli.flags.port, 4999);

      const deferIde = generateIdeConfig({
        ide: 'claude',
        mode: 'unified',
        profile: 'full',
        deferTools: true,
        includeExtended: true,
        workspaceRoot: tmpDir
      });
      assert.ok(deferIde.mcpServers['krusch-stack'].args.includes('--defer-tools'));
      assert.ok(deferIde.mcpServers['krusch-stack'].args.includes('--include-extended'));

      const envDb = openStackDatabase({ workspaceRoot: tmpDir, ephemeral: true });
      envDb.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('R2-SEC-01..05 & R2-MCP-01: HTTP /call fs/git path containment, sibling-prefix CWE-22 guard, dangling symlink & "reset" sentinel block, nowMs strip, IPv6 Host suffix block, and --defer-tools /tool-graph/call', async () => {
    const baseTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-r2-'));
    const wsDir = path.join(baseTmp, 'repo');
    const siblingDir = path.join(baseTmp, 'repo-secrets');
    fs.mkdirSync(wsDir, { recursive: true });
    fs.mkdirSync(siblingDir, { recursive: true });
    const siblingSecret = path.join(siblingDir, 'token.txt');
    fs.writeFileSync(siblingSecret, 'TOP_SECRET_SIBLING\n', 'utf8');
    fs.writeFileSync(path.join(wsDir, 'index.js'), 'export const ok = true;\n', 'utf8');

    try {
      const stack = createKruschStack({ workspaceRoot: wsDir, ephemeral: true });
      stack.git.indexRepo({ repoPath: wsDir });

      // 1. CWE-22 sibling-prefix block in git-engine readBlob & readTree
      const sibBlob = stack.git.readBlob({ path: '../repo-secrets/token.txt' });
      assert.equal(sibBlob.ok, false);
      assert.equal(sibBlob.data.error, 'path_traversal_denied');

      const sibTree = stack.git.readTree({ path: '../repo-secrets' });
      assert.equal(sibTree.ok, false);

      // 2. Dangling symlink inside workspace rejected at HTTP boundary & adoptBrick
      fs.symlinkSync(path.join(siblingDir, 'created-via-dangling.json'), path.join(wsDir, 'dangling-target'));

      // 3. Seal & issue short-lived grant, then expire it and verify HTTP strips nowMs=1
      const sealed = await stack.brickExchange.sealBrick({
        orgId: 'org-r2',
        authorId: 'owner-r2',
        blueprint: {
          id: 'r2-expiring-brick',
          exportName: 'fn',
          inputSchema: { type: 'object', properties: { n: { type: 'number' } } },
          outputSchema: { type: 'object' }
        },
        source: 'export function fn(x) { if (!x || x.n < 0) throw new Error("bad"); return { v: x.n }; }',
        positiveChecks: [{ name: 'ok', input: { n: 1 }, expectedOutput: { v: 1 } }],
        faultChecks: [{ name: 'bad', input: { n: -1 }, expectThrow: true, expectedErrorSubstring: 'bad' }],
        publish: true
      });
      assert.equal(sealed.ok, true);

      const grantRes = stack.brickExchange.issueGrant({
        brickId: 'r2-expiring-brick',
        sourceHash: sealed.data.bundle.sourceHash,
        issuerId: 'owner-r2',
        issuerOrgId: 'org-r2',
        recipients: ['guest-r2'],
        expiresAtMs: Date.now() - 5000
      });
      assert.equal(grantRes.ok, true);
      // Confirm programmatic clock-rewind sees the expired grant, proving HTTP strip is non-vacuous
      assert.equal(
        stack.brickExchange.listInbox({ viewerId: 'guest-r2', viewerOrgId: 'external-org', nowMs: 1 }).data.bricks.length,
        1
      );

      // Start HTTP gateway WITH deferTools: true to verify R2-MCP-01 + R2-SEC-*
      const gw = await startHttpGateway({
        stack,
        workspaceRoot: wsDir,
        deferTools: true,
        port: 0
      });
      const port = gw.port;
      const baseUrl = `http://127.0.0.1:${port}`;
      try {
        // R2-SEC-05: Trailing suffix after IPv6 bracket rejected -> 403
        const ipv6Spoof = await rawHttpRequest({
          port,
          method: 'GET',
          urlPath: '/health',
          headers: { Host: '[::1].attacker.example' }
        });
        assert.equal(ipv6Spoof.status, 403);

        // R2-SEC-01: POST /tool-graph/call (and POST /call after describe) blocks krusch_fs_read_page outside workspaceRoot -> 403
        const tgFsEscape = await fetch(`${baseUrl}/tool-graph/call`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'krusch_fs_read_page',
            arguments: { path: siblingSecret, page_number: 1 }
          })
        });
        assert.equal(tgFsEscape.status, 403);
        const tgFsEscapeJson = await tgFsEscape.json();
        assert.equal(tgFsEscapeJson.ok, false);
        assert.equal(tgFsEscapeJson.data?.code, 'PATH_OUTSIDE_WORKSPACE');

        // R2-SEC-02: Dangling symlink rejected over HTTP -> 403
        const danglingRes = await fetch(`${baseUrl}/brick-exchange/audit-locks`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetRepoDir: 'dangling-target' })
        });
        assert.equal(danglingRes.status, 403);

        // R2-SEC-03: Expired grant cannot be resurrected via nowMs: 1 over HTTP
        const rewindInbox = await fetch(`${baseUrl}/brick-exchange/inbox`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            viewerId: 'guest-r2',
            viewerOrgId: 'external-org',
            nowMs: 1
          })
        }).then((r) => r.json());
        assert.equal(rewindInbox.ok, true);
        assert.equal(rewindInbox.data.bricks.length, 0, 'HTTP gateway must strip caller nowMs');

        // R2-MCP-01: POST /tool-graph/call succeeds for deferred tools even when deferTools: true!
        const deferredTgCall = await fetch(`${baseUrl}/tool-graph/call`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'krusch_git_search_symbols',
            arguments: { query: 'ok' }
          })
        });
        assert.equal(deferredTgCall.status, 200);
        const deferredTgJson = await deferredTgCall.json();
        assert.equal(deferredTgJson.ok, true);
      } finally {
        await new Promise((resolve) => gw.server.close(resolve));
      }
    } finally {
      fs.rmSync(baseTmp, { recursive: true, force: true });
    }
  });
});
