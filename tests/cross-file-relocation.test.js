import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import { createKruschStack } from '../src/index.js';
import {
  findCrossFileRelocationCandidate,
  evaluateSpanDrift
} from '../src/engines/context-engine.js';

function makeTempDir(prefix = 'krusch-reloc-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeRel(rootDir, relPath, content) {
  const fullPath = path.join(rootDir, relPath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content, 'utf8');
  return fullPath;
}

describe('Cross-File Relocation Hints on INV-12 STALE_DRIFT (INV-RELOC-01..04)', () => {
  test('1. Tier 1a (git_symbols ast_exact_quote): fail-closed STALE_DRIFT + moved_candidate + health telemetry', () => {
    const ws = makeTempDir();
    try {
      const quoted = 'export function verifyInvoiceApproval(amount, actor) {';
      writeRel(
        ws,
        'src/auth/policy.js',
        [
          '// Auth policy module',
          quoted,
          '  if (!actor || amount <= 0) return false;',
          '  return amount <= 10000;',
          '}'
        ].join('\n') + '\n'
      );

      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });
      stack.engines.git.indexRepo({ repoPath: ws });

      const rem = stack.context.remember({
        category: 'invariant',
        content: 'Invoice approvals over 10k require dual authorization.',
        provenance: {
          file: 'src/auth/policy.js',
          locator: 'L2-L5',
          quoted_sentence: quoted
        }
      });
      assert.equal(rem.ok, true);

      // Initially VALID with 0 drifted / 0 relocated
      const h0 = stack.context.health();
      assert.equal(h0.data.drifted_count, 0);
      assert.equal(h0.data.relocated_candidates_count, 0);

      // Move verifyInvoiceApproval out of src/auth/policy.js into src/billing/approvals.js
      writeRel(
        ws,
        'src/auth/policy.js',
        '// Auth policy module (billing logic extracted)\nexport function checkActorSession(actor) {\n  return Boolean(actor);\n}\n'
      );
      writeRel(
        ws,
        'src/billing/approvals.js',
        [
          '// Billing approvals',
          '// Relocated from auth policy',
          quoted,
          '  if (!actor || amount <= 0) return false;',
          '  return amount <= 10000;',
          '}'
        ].join('\n') + '\n'
      );

      // Re-index AST symbols
      stack.engines.git.indexRepo({ repoPath: ws });

      const ret = stack.context.retrieve({ query: '*' });
      assert.equal(ret.ok, true);
      assert.equal(ret.data.items.length, 1);

      const item = ret.data.items[0];
      // INV-RELOC-01: Must fail closed and NEVER overwrite provenance.file
      assert.equal(item.drift_status, 'STALE_DRIFT');
      assert.equal(item.provenance.file, 'src/auth/policy.js');
      assert.equal(ret.data.drift_summary.stale_drift, 1);

      // Deterministic moved_candidate attached on item and item.provenance
      assert.ok(item.moved_candidate, 'Expected moved_candidate on drifted item');
      assert.deepEqual(item.provenance.moved_candidate, item.moved_candidate);
      assert.equal(item.moved_candidate.file, 'src/billing/approvals.js');
      assert.equal(item.moved_candidate.locator, 'L3');
      assert.equal(item.moved_candidate.start_line, 3);
      assert.equal(item.moved_candidate.end_line, 3);
      assert.equal(item.moved_candidate.citation, 'src/billing/approvals.js#L3');
      assert.equal(item.moved_candidate.source, 'git_symbols');
      assert.equal(item.moved_candidate.match_kind, 'ast_exact_quote');
      assert.equal(item.moved_candidate.symbol_name, 'verifyInvoiceApproval');
      assert.equal(item.moved_candidate.symbol_type, 'function');
      assert.equal(item.moved_candidate.candidate_count, 1);

      // Verify SQLite row provenance_file remained untouched
      const dbRow = stack.db
        .prepare('SELECT provenance_file FROM context_memories WHERE id = ?')
        .get(rem.data.id);
      assert.equal(dbRow.provenance_file, 'src/auth/policy.js');

      // Verify health() increments both drifted_count and relocated_candidates_count
      const h1 = stack.context.health();
      assert.equal(h1.ok, true);
      assert.equal(h1.data.drifted_count, 1);
      assert.equal(h1.data.relocated_candidates_count, 1);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('2. Tier 1b (git_symbols ast_symbol_name): resolves moved function when signature adds parameter', () => {
    const ws = makeTempDir();
    try {
      const origSig = 'export function computeOrderChecksum(items) {';
      writeRel(
        ws,
        'src/cart/totals.js',
        [
          origSig,
          '  return items.reduce((acc, it) => acc + it.price, 0);',
          '}'
        ].join('\n') + '\n'
      );

      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });
      stack.engines.git.indexRepo({ repoPath: ws });

      stack.context.remember({
        category: 'invariant',
        content: 'Order checksum must remain deterministic across retries.',
        provenance: {
          file: 'src/cart/totals.js',
          locator: 'L1-L3',
          quoted_sentence: origSig
        }
      });

      // Move computeOrderChecksum to src/orders/checksum.js AND reformat signature with new default param
      writeRel(
        ws,
        'src/cart/totals.js',
        'export function countItems(items) {\n  return items.length;\n}\n'
      );
      writeRel(
        ws,
        'src/orders/checksum.js',
        [
          '// Order checksum module',
          'export function computeOrderChecksum(items, currency = \'USD\') {',
          '  const sum = items.reduce((acc, it) => acc + it.price, 0);',
          '  return `${currency}:${sum}`;',
          '}'
        ].join('\n') + '\n'
      );

      stack.engines.git.indexRepo({ repoPath: ws });

      const ret = stack.context.retrieve({ query: 'Order checksum deterministic' });
      assert.equal(ret.ok, true);
      assert.equal(ret.data.items.length, 1);

      const item = ret.data.items[0];
      assert.equal(item.drift_status, 'STALE_DRIFT');
      assert.equal(item.provenance.file, 'src/cart/totals.js');
      assert.ok(item.moved_candidate);
      assert.equal(item.moved_candidate.file, 'src/orders/checksum.js');
      assert.equal(item.moved_candidate.source, 'git_symbols');
      assert.equal(item.moved_candidate.match_kind, 'ast_symbol_name');
      assert.equal(item.moved_candidate.symbol_name, 'computeOrderChecksum');
      assert.equal(item.moved_candidate.symbol_type, 'function');
      assert.equal(item.moved_candidate.start_line, 2);
      assert.equal(item.moved_candidate.end_line, 5);
      assert.equal(item.moved_candidate.locator, 'L2-L5');
      assert.equal(item.moved_candidate.citation, 'src/orders/checksum.js#L2-L5');
      assert.equal(item.moved_candidate.candidate_count, 1);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('3. Tier 2 (fs_pages fs_exact_quote): resolves moved markdown documentation paragraph via fs_pages', () => {
    const ws = makeTempDir();
    try {
      const docParagraph =
        'All inbound webhook deliveries must verify the X-Signature-Ed25519 header before enqueueing.';
      writeRel(
        ws,
        'docs/old-guide.md',
        [
          '# Webhook Security Guide',
          '',
          docParagraph,
          '',
          'Reject unsigned requests with HTTP 401.'
        ].join('\n') + '\n'
      );

      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });
      stack.engines.fs.sync({ paths: ['docs'] });

      stack.context.remember({
        category: 'invariant',
        content: 'Verify Ed25519 signature before webhook queue admission.',
        provenance: {
          file: 'docs/old-guide.md',
          locator: 'L3',
          quoted_sentence: docParagraph
        }
      });

      // Move paragraph from docs/old-guide.md to docs/new-guide.md and sync fs_pages (without git_symbols)
      writeRel(
        ws,
        'docs/old-guide.md',
        '# Legacy Guide\n\nDeprecated — see new-guide.md for current webhook rules.\n'
      );
      writeRel(
        ws,
        'docs/new-guide.md',
        [
          '# Updated Webhook Handbook',
          '',
          '## Ingress Verification',
          docParagraph
        ].join('\n') + '\n'
      );

      stack.engines.fs.sync({ paths: ['docs'] });

      const ret = stack.context.retrieve({ query: '*' });
      assert.equal(ret.ok, true);
      const item = ret.data.items[0];
      assert.equal(item.drift_status, 'STALE_DRIFT');
      assert.equal(item.provenance.file, 'docs/old-guide.md');
      assert.ok(item.moved_candidate);
      assert.equal(item.moved_candidate.file, 'docs/new-guide.md');
      assert.equal(item.moved_candidate.locator, 'L4');
      assert.equal(item.moved_candidate.start_line, 4);
      assert.equal(item.moved_candidate.end_line, 4);
      assert.equal(item.moved_candidate.citation, 'docs/new-guide.md#L4');
      assert.equal(item.moved_candidate.source, 'fs_pages');
      assert.equal(item.moved_candidate.match_kind, 'fs_exact_quote');
      assert.equal(item.moved_candidate.candidate_count, 1);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('4. Tier 3 (workspace_scan): unindexed fallback with unlinked source file resolves in < 20ms', () => {
    const ws = makeTempDir();
    try {
      const quotedBlock = [
        'export function normalizeTenantSlug(rawSlug) {',
        '  return String(rawSlug || "").trim().toLowerCase();',
        '}'
      ].join('\n');

      const legacyAbs = writeRel(ws, 'src/legacy.js', `${quotedBlock}\n`);
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      stack.context.remember({
        category: 'decision',
        content: 'Tenant slugs are normalized to lowercase trimmed strings.',
        provenance: {
          file: 'src/legacy.js',
          locator: 'L1-L3',
          quoted_sentence: quotedBlock
        }
      });

      // Completely unlink src/legacy.js and write src/modern/handler.js WITHOUT indexing git_symbols or fs_pages
      fs.unlinkSync(legacyAbs);
      writeRel(
        ws,
        'src/modern/handler.js',
        [
          '// Modernized request handler',
          'const DEFAULT_REGION = "us-east";',
          '',
          quotedBlock,
          ''
        ].join('\n')
      );

      const t0 = performance.now();
      const ret = stack.context.retrieve({ query: '*' });
      const elapsedMs = performance.now() - t0;

      assert.ok(elapsedMs < 20, `Expected workspace_scan retrieve in <20ms, took ${elapsedMs.toFixed(2)}ms`);
      assert.equal(ret.ok, true);
      const item = ret.data.items[0];
      assert.equal(item.drift_status, 'STALE_DRIFT');
      assert.equal(item.provenance.file, 'src/legacy.js');
      assert.ok(item.moved_candidate);
      assert.equal(item.moved_candidate.file, 'src/modern/handler.js');
      assert.equal(item.moved_candidate.start_line, 4);
      assert.equal(item.moved_candidate.end_line, 6);
      assert.equal(item.moved_candidate.locator, 'L4-L6');
      assert.equal(item.moved_candidate.citation, 'src/modern/handler.js#L4-L6');
      assert.equal(item.moved_candidate.source, 'workspace_scan');
      assert.equal(item.moved_candidate.match_kind, 'workspace_exact_quote');
      assert.equal(item.moved_candidate.candidate_count, 1);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('5. Security & Specificity Guards (INV-RELOC-02 & INV-RELOC-03) and Explicit Supersede Re-Anchoring', () => {
    const ws = makeTempDir();
    const outsideDir = makeTempDir('krusch-reloc-outside-');
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // 5a. Short generic quotes ("return true;" and "x = 1") -> moved_candidate is omitted / null
      writeRel(ws, 'src/orig-short.js', '// emptied\n');
      writeRel(ws, 'src/other-short.js', 'function f() {\n  let x = 1;\n  return true;\n}\n');
      const shortMem1 = stack.context.remember({
        category: 'invariant',
        content: 'Short generic return quote check',
        provenance: {
          file: 'src/orig-short.js',
          locator: 'L1',
          quoted_sentence: 'return true;'
        }
      });
      const shortMem2 = stack.context.remember({
        category: 'invariant',
        content: 'Short generic assignment quote check',
        provenance: {
          file: 'src/orig-short.js',
          locator: 'L1',
          quoted_sentence: 'x = 1'
        }
      });

      assert.equal(
        findCrossFileRelocationCandidate({
          db: stack.db,
          relFile: 'src/orig-short.js',
          quoted: 'return true;',
          workspaceRoot: ws
        }),
        null
      );
      assert.equal(
        findCrossFileRelocationCandidate({
          db: stack.db,
          relFile: 'src/orig-short.js',
          quoted: 'x = 1',
          workspaceRoot: ws
        }),
        null
      );

      // 5b. Boilerplate quote duplicated across 6 files -> moved_candidate omitted (> 5 ambiguity guard across ALL tiers)
      const boilerplateQuote = 'export function standardHealthProbeResponse() { return { healthy: true }; }';
      writeRel(ws, 'src/probe-origin.js', '// moved out\n');
      for (let i = 1; i <= 6; i += 1) {
        writeRel(ws, `src/probes/service-${i}.js`, `${boilerplateQuote}\n`);
      }
      stack.engines.git.indexRepo({ repoPath: ws });
      stack.engines.fs.sync({ paths: ['src'] });

      const ambigMem = stack.context.remember({
        category: 'decision',
        content: 'Boilerplate health probe check across 6 services',
        provenance: {
          file: 'src/probe-origin.js',
          locator: 'L1',
          quoted_sentence: boilerplateQuote
        }
      });

      // Verify Tier 1 (git_symbols), Tier 2 (fs_pages), and Tier 3 (db=null workspace_scan) all enforce <= 5 non-ambiguity
      assert.equal(
        findCrossFileRelocationCandidate({
          db: stack.db,
          relFile: 'src/probe-origin.js',
          quoted: boilerplateQuote,
          workspaceRoot: ws
        }),
        null
      );
      assert.equal(
        findCrossFileRelocationCandidate({
          db: null,
          relFile: 'src/probe-origin.js',
          quoted: boilerplateQuote,
          workspaceRoot: ws
        }),
        null
      );

      // 5c. Secret files (.env.production, credentials.json, *.pem) and symlink escaping workspaceRoot are NEVER read or suggested
      const secretQuote = 'export const UNIQUE_VAULT_SENTINEL_CONFIG = "strict-enforced-mode";';
      writeRel(ws, 'src/vault-origin.js', '// removed\n');
      const envProdAbs = writeRel(ws, '.env.production', `${secretQuote}\n`);
      const credsAbs = writeRel(ws, 'credentials.json', `${secretQuote}\n`);
      const pemAbs = writeRel(ws, 'certs/private.pem', `${secretQuote}\n`);
      const outsideSecretAbs = writeRel(outsideDir, 'escaped-target.js', `${secretQuote}\n`);
      const symlinkInsideWs = path.join(ws, 'src', 'escaped-link.js');
      fs.symlinkSync(outsideSecretAbs, symlinkInsideWs);
      const symlinkDirInsideWs = path.join(ws, 'src', 'escaped-dir-link');
      fs.symlinkSync(outsideDir, symlinkDirInsideWs);

      const secretMem = stack.context.remember({
        category: 'invariant',
        content: 'Secret & symlink containment rule',
        provenance: {
          file: 'src/vault-origin.js',
          locator: 'L1',
          quoted_sentence: secretQuote
        }
      });

      // Spy on fs.readFileSync to prove secret files and escaped symlinks are NEVER read
      const readTargets = [];
      const origReadFileSync = fs.readFileSync;
      fs.readFileSync = function spiedReadFileSync(target, ...rest) {
        readTargets.push(String(target));
        return origReadFileSync.call(fs, target, ...rest);
      };
      let retGuard;
      try {
        retGuard = stack.context.retrieve({ query: '*' });
      } finally {
        fs.readFileSync = origReadFileSync;
      }

      const forbiddenRealPaths = [
        fs.realpathSync(envProdAbs),
        fs.realpathSync(credsAbs),
        fs.realpathSync(pemAbs),
        fs.realpathSync(outsideSecretAbs),
        envProdAbs,
        credsAbs,
        pemAbs,
        outsideSecretAbs,
        symlinkInsideWs
      ];
      for (const readTarget of readTargets) {
        for (const forbidden of forbiddenRealPaths) {
          assert.notEqual(
            path.resolve(readTarget),
            path.resolve(forbidden),
            `Forbidden secret or escaped-symlink file was read: ${readTarget}`
          );
        }
      }

      const byId = new Map(retGuard.data.items.map((it) => [it.id, it]));
      for (const guardedId of [
        shortMem1.data.id,
        shortMem2.data.id,
        ambigMem.data.id,
        secretMem.data.id
      ]) {
        const it = byId.get(guardedId);
        assert.ok(it);
        assert.equal(it.drift_status, 'STALE_DRIFT');
        assert.equal('moved_candidate' in it, false);
        assert.equal('moved_candidate' in it.provenance, false);
      }

      // 5d. Explicit revise({ action: 'supersede' }) re-anchors provenance, clears STALE_DRIFT -> VALID, and omits moved_candidate
      const reanchorQuote = 'export function enforceLedgerIdempotency(txId) {';
      writeRel(ws, 'src/ledger/old.js', '// moved\n');
      writeRel(
        ws,
        'src/billing/approvals.js',
        [
          reanchorQuote,
          '  if (!txId) throw new Error("txId required");',
          '  return true;',
          '}'
        ].join('\n') + '\n'
      );
      const driftedLedger = stack.context.remember({
        category: 'invariant',
        content: 'Ledger writes must enforce idempotency keys.',
        provenance: {
          file: 'src/ledger/old.js',
          locator: 'L1',
          quoted_sentence: reanchorQuote
        }
      });

      const beforeSupersede = stack.context.retrieve({ query: 'Ledger writes idempotency' });
      const driftedItem = beforeSupersede.data.items.find((it) => it.id === driftedLedger.data.id);
      assert.ok(driftedItem);
      assert.equal(driftedItem.drift_status, 'STALE_DRIFT');
      assert.equal(driftedItem.moved_candidate?.file, 'src/billing/approvals.js');

      // Re-anchor via explicit supersede (omitting new_content preserves existing invariant text cleanly)
      const rev = stack.context.revise({
        action: 'supersede',
        target_id: driftedLedger.data.id,
        reason: 'Re-anchored after billing module consolidation',
        provenance: {
          file: 'src/billing/approvals.js',
          locator: 'L1-L4',
          quoted_sentence: reanchorQuote
        }
      });
      assert.equal(rev.ok, true);

      const afterSupersede = stack.context.retrieve({ query: 'Ledger writes idempotency' });
      const healedItem = afterSupersede.data.items.find((it) => it.id === rev.data.new_id);
      assert.ok(healedItem);
      assert.equal(healedItem.drift_status, 'VALID');
      assert.equal(healedItem.provenance.file, 'src/billing/approvals.js');
      assert.equal('moved_candidate' in healedItem, false);
      assert.equal('moved_candidate' in healedItem.provenance, false);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  test('6. Proximity tie-breaking, binary NUL-byte skip, >512KB cap, stale index skip, and INV-RELOC-04 anchor preservation', () => {
    const ws = makeTempDir();
    try {
      const sharedQuote = 'export function validateRegionalTaxCode(region, code) {';
      writeRel(ws, 'src/tax/rules.js', '// extracted\n');
      // Closer sibling in src/tax/ vs distant file in packages/legacy/
      writeRel(ws, 'packages/legacy/tax-copy.js', `${sharedQuote}\n  return Boolean(code);\n}\n`);
      writeRel(ws, 'src/tax/regional-validator.js', `${sharedQuote}\n  return Boolean(region && code);\n}\n`);

      // Binary file containing NUL byte + verbatim quote must be skipped
      const binaryPath = path.join(ws, 'src/tax/corrupt-binary.dat');
      fs.writeFileSync(
        binaryPath,
        Buffer.concat([Buffer.from([0x00, 0x01, 0x02]), Buffer.from(`\n${sharedQuote}\n`, 'utf8')])
      );

      // Oversized > 512 KB file containing verbatim quote must be skipped
      writeRel(
        ws,
        'src/tax/oversized-bundle.js',
        `${'// padding '.repeat(55000)}\n${sharedQuote}\n  return true;\n}\n`
      );

      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // Insert a stale ghost row in git_symbols pointing to a deleted file on disk
      stack.db
        .prepare(`
          INSERT INTO git_symbols (
            repo_name, file_path, symbol_name, symbol_type, signature, start_line, end_line, symbol_hash, snippet
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          'ws',
          'src/tax/deleted-ghost.js',
          'validateRegionalTaxCode',
          'function',
          sharedQuote,
          1,
          2,
          'deadbeef',
          sharedQuote
        );

      const cand = findCrossFileRelocationCandidate({
        db: stack.db,
        relFile: 'src/tax/rules.js',
        quoted: sharedQuote,
        workspaceRoot: ws
      });
      assert.ok(cand);
      assert.equal(cand.file, 'src/tax/regional-validator.js', 'Must pick closest sibling directory match');
      assert.equal(cand.candidate_count, 2, 'Binary, >512KB, and deleted ghost files must not inflate candidate_count');

      // Verify evaluateSpanDrift direct export contract & INV-RELOC-04 anchor preservation in context-engine.js
      const directDrift = evaluateSpanDrift(
        {
          provenance_file: 'src/tax/rules.js',
          provenance_locator: 'L1',
          quoted_sentence: sharedQuote,
          anchor_hash: null
        },
        ws,
        stack.db
      );
      assert.equal(directDrift.status, 'STALE_DRIFT');
      assert.equal(directDrift.moved_candidate?.file, 'src/tax/regional-validator.js');

      const engineSrc = fs.readFileSync(
        new URL('../src/engines/context-engine.js', import.meta.url),
        'utf8'
      );
      assert.ok(
        engineSrc.includes(
          "const VALID_CATEGORIES = new Set(['decision', 'invariant', 'bug', 'lesson', 'blocker']);"
        ),
        'INV-RELOC-04: VALID_CATEGORIES anchor must be preserved verbatim'
      );
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('7. Multi-line CRLF (\\r\\n) and standalone CR (\\r) normalization in Tier 1a (git_symbols) and Tier 2 (fs_pages)', () => {
    const ws = makeTempDir();
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // 7a. Tier 1a: LF multi-line quoted_sentence matching CRLF snippet & file in git_symbols
      const lfAstQuote = [
        'export function verifyCrlfMultiLineAnchor(alpha, beta) {',
        '  return alpha === beta;',
        '}'
      ].join('\n');
      writeRel(ws, 'src/crlf/orig.js', '// moved\r\n');
      const crlfAstBody = [
        '// CRLF module header',
        'export function verifyCrlfMultiLineAnchor(alpha, beta) {',
        '  return alpha === beta;',
        '}'
      ].join('\r\n') + '\r\n';
      writeRel(ws, 'src/crlf/ast-target.js', crlfAstBody);

      stack.db
        .prepare(`
          INSERT INTO git_symbols (
            repo_name, file_path, symbol_name, symbol_type, signature, start_line, end_line, symbol_hash, snippet
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          'ws',
          'src/crlf/ast-target.js',
          'verifyCrlfMultiLineAnchor',
          'function',
          'export function verifyCrlfMultiLineAnchor(alpha, beta) {',
          2,
          4,
          'crlfhash1',
          crlfAstBody
        );

      const astCand = findCrossFileRelocationCandidate({
        db: stack.db,
        relFile: 'src/crlf/orig.js',
        quoted: lfAstQuote,
        workspaceRoot: ws
      });
      assert.ok(astCand, 'Expected Tier 1a git_symbols match across CRLF snippet');
      assert.equal(astCand.file, 'src/crlf/ast-target.js');
      assert.equal(astCand.source, 'git_symbols');
      assert.equal(astCand.match_kind, 'ast_exact_quote');
      assert.equal(astCand.locator, 'L2-L4');

      // 7b. Tier 2: LF multi-line quote with short first line (<10 non-ws chars) forcing full multi-line SQLite INSTR probe against CRLF/CR fs_pages.page_text
      const lfDocQuote = [
        '### Rule:',
        'Enforce deterministic multi-line line-ending normalization across moved guides.'
      ].join('\n');
      writeRel(ws, 'docs/old-crlf.md', '# Old\r\n');
      const crDocBody = [
        '# Guide Header',
        '',
        '### Rule:',
        'Enforce deterministic multi-line line-ending normalization across moved guides.',
        'Trailing note.'
      ].join('\r\n');
      const crOnlyDiskBody = crDocBody.replace(/\r\n/g, '\r');
      writeRel(ws, 'docs/new-crlf.md', crOnlyDiskBody);

      stack.db
        .prepare(`
          INSERT INTO fs_pages (
            file_path, page_number, section_title, start_line, end_line, page_hash, page_text
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .run('docs/new-crlf.md', 1, 'Guide Header', 1, 5, 'crlfpage1', crDocBody);

      const fsCand = findCrossFileRelocationCandidate({
        db: stack.db,
        relFile: 'docs/old-crlf.md',
        quoted: lfDocQuote,
        workspaceRoot: ws
      });
      assert.ok(fsCand, 'Expected Tier 2 fs_pages match across CRLF page_text and CR disk file');
      assert.equal(fsCand.file, 'docs/new-crlf.md');
      assert.equal(fsCand.source, 'fs_pages');
      assert.equal(fsCand.match_kind, 'fs_exact_quote');
      assert.equal(fsCand.locator, 'L3-L4');
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });
});
