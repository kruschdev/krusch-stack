import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  createKruschStack,
  STACK_SCHEMA_SQL,
  isSensitiveEnvFile,
  redactEnvSecrets,
  scanForSecretLeak,
  splitIdentifierSubtokens,
  extractCodeShapeIdentifiers,
  buildFts5MatchQuery
} from '../src/index.js';
import { ALL_STACK_TOOLS, dispatchStackTool } from '../src/mcp/server.js';

function createTier2Workspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-tier2-'));
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'docs'), { recursive: true });

  // Multi-file call-graph fixture for 2-hop git_edges bridging + Porter stemming
  fs.writeFileSync(
    path.join(dir, 'src', 'billing-service.js'),
    [
      'export function orchestrateInvoiceCheckout(cartItems) {',
      '  const subtotal = computeRollupSubtotal(cartItems);',
      '  return applyLedgerTaxRate(subtotal);',
      '}',
      '',
      'export function computeRollupSubtotal(cartItems) {',
      '  return cartItems.reduce((acc, item) => acc + item.priceCents, 0);',
      '}'
    ].join('\n') + '\n',
    'utf-8'
  );

  fs.writeFileSync(
    path.join(dir, 'src', 'tax-ledger.js'),
    [
      'export function applyLedgerTaxRate(subtotalCents) {',
      '  const jurisdictionBps = 825;',
      '  return Math.round(subtotalCents * (1 + jurisdictionBps / 10000));',
      '}'
    ].join('\n') + '\n',
    'utf-8'
  );

  // Sensitive .env files vs safe .env.example template
  // Assemble synthetic secret-shaped strings dynamically so static repo secret scanners stay clean
  const fakeSk = 'sk-' + 'proj_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz123456';
  const fakeGhp = 'ghp_' + '1234567890abcdefghijklmnopqrstuvwxyz';
  fs.writeFileSync(
    path.join(dir, '.env'),
    [
      '# Production API credentials',
      `OPENAI_API_KEY=${fakeSk}`,
      `GITHUB_TOKEN=${fakeGhp}`,
      'EMPTY_FLAG=',
      'ALREADY_MASKED=[REDACTED]'
    ].join('\n') + '\n',
    'utf-8'
  );
  fs.writeFileSync(
    path.join(dir, '.env.production'),
    'DATABASE_URL=postgres://admin:SuperSecretPass99!@localhost:5432/appdb\n',
    'utf-8'
  );
  fs.writeFileSync(
    path.join(dir, '.env.example'),
    'OPENAI_API_KEY=your_key_here\nPORT=3780\n',
    'utf-8'
  );

  // Multi-page documentation for Porter FTS5 + token budgeting
  const filler = Array.from(
    { length: 18 },
    (_, idx) => `Operational runbook paragraph ${idx + 1}: verify replica checkpoints, WAL retention, and snapshot integrity before maintenance windows.`
  ).join('\n');
  fs.writeFileSync(
    path.join(dir, 'docs', 'OPERATIONS.md'),
    [
      '# Replica Maintenance Guide',
      'Always verify asynchronous replications and connection pools prior to schema rollouts.',
      filler,
      '',
      '## Snapshot Recovery Procedure',
      'Restore compressed snapshots from cold object storage and validate checksums.',
      filler
    ].join('\n') + '\n',
    'utf-8'
  );

  return { dir, fakeSk, fakeGhp };
}

describe('Tier 2A/2B Context v2.0 Parity Suite (INV-STACK-07..09)', () => {
  test('INV-STACK-07: Legacy SQLite DB auto-migrates external-content Porter FTS5 tables, backfills existing rows, and syncs UPDATE/DELETE triggers', () => {
    const { dir } = createTier2Workspace();
    const dbPath = path.join(dir, '.krusch-stack', 'legacy-tier2.db');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });

    try {
      // Seed a pre-FTS5 database directly with STACK_SCHEMA_SQL only
      const rawDb = new DatabaseSync(dbPath);
      rawDb.exec(STACK_SCHEMA_SQL);
      rawDb.prepare(`
        INSERT INTO git_repositories (name, root_path, head_commit)
        VALUES ('legacy-repo', ?, 'deadbeef')
      `).run(dir);
      rawDb.prepare(`
        INSERT INTO git_symbols (repo_name, file_path, symbol_name, symbol_type, signature, start_line, end_line, symbol_hash, snippet)
        VALUES ('legacy-repo', 'src/legacy.js', 'buildEpisodeRollups', 'function', 'function buildEpisodeRollups()', 1, 5, 'h1', ' Consolidates episodic rollups ')
      `).run();
      rawDb.prepare(`
        INSERT INTO fs_pages (file_path, page_number, section_title, start_line, end_line, page_hash, page_text)
        VALUES ('docs/LEGACY.md', 1, 'Migration Checkpoints', 1, 10, 'ph1', 'Handles incremental migrations cleanly.')
      `).run();
      rawDb.prepare(`
        INSERT INTO fs_page_memories (file_path, page_number, category, note, anchored_page_hash)
        VALUES ('docs/LEGACY.md', 1, 'warning', 'Verify foreign keys before running migrations', 'ph1')
      `).run();
      rawDb.close();

      // Open via createKruschStack -> triggers ensureStackSchemaMigrations + one-time 'rebuild'
      const stack = createKruschStack({ workspaceRoot: dir, dbPath });
      try {
        const ftsTables = stack.db
          .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%_fts' ORDER BY name ASC")
          .all()
          .map((r) => r.name);
        assert.deepEqual(ftsTables, ['fs_page_memories_fts', 'fs_pages_fts', 'git_symbols_fts']);

        // Porter FTS5 matches singular "rollup" against plural "rollups" in legacy pre-populated row
        const symSearch = stack.git.semanticSearch({ repo: 'legacy-repo', query: 'episodic rollup' });
        assert.equal(symSearch.ok, true);
        assert.equal(symSearch.data.results.length, 1);
        assert.equal(symSearch.data.results[0].symbol_name, 'buildEpisodeRollups');

        // Porter FTS5 matches singular "migration" against plural "migrations" in legacy fs_pages & fs_page_memories
        const pageSearch = stack.fs.search({ query: 'incremental migration' });
        assert.equal(pageSearch.ok, true);
        assert.ok(pageSearch.data.results.some((r) => r.file_path === 'docs/LEGACY.md'));

        // Verify AFTER UPDATE and AFTER DELETE external-content FTS5 triggers stay consistent (no FTS5 corruption)
        stack.db.prepare("UPDATE fs_pages SET page_text = 'Updated quorum heartbeats doc' WHERE file_path = 'docs/LEGACY.md'").run();
        const updatedHit = stack.fs.search({ query: 'quorum heartbeat' });
        assert.ok(updatedHit.data.results.some((r) => r.file_path === 'docs/LEGACY.md'));

        stack.db.prepare("DELETE FROM fs_pages WHERE file_path = 'docs/LEGACY.md'").run();
        stack.db.prepare("DELETE FROM fs_page_memories WHERE file_path = 'docs/LEGACY.md'").run();
        const afterDelete = stack.fs.search({ query: 'quorum heartbeat' });
        assert.equal(
          afterDelete.data.results.some((r) => r.file_path === 'docs/LEGACY.md'),
          false,
          'Deleted page must be evicted from external-content FTS5 index'
        );
      } finally {
        stack.db.close();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('INV-STACK-08: .env KEYS_ONLY redaction strips secret values while keeping keys searchable, and scanForSecretLeak blocks raw secrets', () => {
    const { dir, fakeSk, fakeGhp } = createTier2Workspace();
    try {
      assert.equal(isSensitiveEnvFile('.env'), true);
      assert.equal(isSensitiveEnvFile('/tmp/app/.env.production'), true);
      assert.equal(isSensitiveEnvFile('.env.example'), false);
      assert.equal(isSensitiveEnvFile('.env.template'), false);

      const redactedSample = redactEnvSecrets(`OPENAI_API_KEY=${fakeSk}\nEMPTY_VAR=\n`);
      assert.equal(redactedSample.includes(fakeSk), false);
      assert.match(redactedSample, /OPENAI_API_KEY=\[REDACTED\]/);
      assert.match(redactedSample, /EMPTY_VAR=/);

      const stack = createKruschStack({ workspaceRoot: dir, ephemeral: true });
      try {
        const syncRes = stack.fs.sync({});
        assert.equal(syncRes.ok, true);

        // Read .env and .env.production pages: keys are preserved, raw secrets NEVER exist in SQLite or output
        const envPage = stack.fs.readPage({ path: '.env', page_number: 1 });
        assert.equal(envPage.ok, true);
        assert.match(envPage.data.page_text, /OPENAI_API_KEY=\[REDACTED\]/);
        assert.match(envPage.data.page_text, /GITHUB_TOKEN=\[REDACTED\]/);
        assert.equal(envPage.data.page_text.includes(fakeSk), false);
        assert.equal(envPage.data.page_text.includes(fakeGhp), false);

        const prodEnvPage = stack.fs.readPage({ path: '.env.production', page_number: 1 });
        assert.equal(prodEnvPage.ok, true);
        assert.match(prodEnvPage.data.page_text, /DATABASE_URL=\[REDACTED\]/);
        assert.equal(prodEnvPage.data.page_text.includes('SuperSecretPass99!'), false);

        // .env.example remains unredacted
        const exampleEnvPage = stack.fs.readPage({ path: '.env.example', page_number: 1 });
        assert.equal(exampleEnvPage.ok, true);
        assert.match(exampleEnvPage.data.page_text, /PORT=3780/);

        // Searching for OPENAI_API_KEY finds .env without leaking the secret value
        const keySearch = stack.fs.search({ query: 'OPENAI_API_KEY' });
        assert.equal(keySearch.ok, true);
        assert.ok(keySearch.data.results.some((r) => r.file_path === '.env'));
        assert.equal(JSON.stringify(keySearch.data).includes(fakeSk), false);

        // Pre-write secret shield blocks raw API keys, GitHub tokens, PEM headers, and inline URL passwords
        assert.ok(scanForSecretLeak(`Token is ${fakeSk}`));
        assert.ok(scanForSecretLeak(`PAT is ${fakeGhp}`));
        assert.ok(scanForSecretLeak('-----BEGIN OPENSSH PRIVATE KEY-----\nabc'));
        assert.ok(scanForSecretLeak('postgres://svc:MyPlaintextSecret99@localhost:5432/db'));
        assert.equal(scanForSecretLeak('Set OPENAI_API_KEY=[REDACTED] before starting gateway'), null);

        const blockedMem = stack.fs.rememberOnPage({
          path: 'docs/OPERATIONS.md',
          page_number: 1,
          note: `Never hardcode ${fakeSk} in scripts`,
          category: 'warning'
        });
        assert.equal(blockedMem.ok, false);
        assert.equal(blockedMem.data.error, 'secret_leak_blocked');

        const safeMem = stack.fs.rememberOnPage({
          path: 'docs/OPERATIONS.md',
          page_number: 1,
          note: 'Ensure OPENAI_API_KEY=[REDACTED] is configured via environment file',
          category: 'annotation'
        });
        assert.equal(safeMem.ok, true);
      } finally {
        stack.db.close();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('INV-STACK-07 & INV-STACK-09: 2-hop git_edges call-graph bridging (0.84 cap), Porter stemming, limit_tokens, and unattested identifier telemetry', async () => {
    const { dir } = createTier2Workspace();
    try {
      assert.equal(ALL_STACK_TOOLS.length, 39, 'Tool count must remain strictly frozen at 39');
      const gitSearchTool = ALL_STACK_TOOLS.find((t) => t.name === 'krusch_git_semantic_search');
      const fsSearchTool = ALL_STACK_TOOLS.find((t) => t.name === 'krusch_fs_search');
      assert.equal(gitSearchTool.inputSchema.properties.limit_tokens.type, 'number');
      assert.equal(fsSearchTool.inputSchema.properties.limit_tokens.type, 'number');

      // Lexical unit checks
      assert.ok(splitIdentifierSubtokens('computeRollupSubtotal').includes('rollup'));
      const codeIds = extractCodeShapeIdentifiers('Check computeRollupSubtotal and missing_handler_fn in billing');
      assert.deepEqual(codeIds, ['computeRollupSubtotal', 'missing_handler_fn']);
      assert.ok(buildFts5MatchQuery('computeRollupSubtotal jurisdictionBps').includes('"rollup"'));

      const stack = createKruschStack({ workspaceRoot: dir, ephemeral: true });
      try {
        // 1. 2-Hop git_edges bridge expansion:
        // "orchestrateInvoiceCheckout" is in src/billing-service.js and calls "applyLedgerTaxRate" in src/tax-ledger.js,
        // which contains "jurisdictionBps" in its snippet! Or querying "orchestrateInvoiceCheckout ledger" where
        // Hop-1 matches orchestrateInvoiceCheckout and Hop-2 bridges applyLedgerTaxRate via git_edges!
        const bridgedRes = await dispatchStackTool(stack, 'krusch_git_semantic_search', {
          query: 'orchestrateInvoiceCheckout jurisdictionBps missing_ identifier_xyz'.replace('missing_ identifier_xyz', 'missing_symbol_xyz'),
          limit: 5
        });
        assert.equal(bridgedRes.ok, true);
        const results = bridgedRes.data.results;
        assert.ok(results.length >= 2, 'Expected Hop-1 and bridged/matched symbols');
        assert.ok(results.some((r) => r.symbol_name === 'orchestrateInvoiceCheckout'));
        assert.ok(
          bridgedRes.data.unattested_query_identifiers.includes('missing_symbol_xyz'),
          'Missing snake_case identifier must be surfaced in unattested_query_identifiers'
        );
        assert.equal(
          bridgedRes.data.unattested_query_identifiers.includes('orchestrateInvoiceCheckout'),
          false,
          'Attested camelCase identifier must NOT be listed as unattested'
        );

        // Deterministic 2-hop call-graph bridge test:
        // Two orchestrate* symbols occupy Hop-1 top-2 for "orchestrate", leaving "glacier" uncovered in Hop-1 top-2;
        // orchestrateInvoiceCheckout -> emitAuditSink (whose snippet contains "glacier") bridges emitAuditSink into top-2!
        stack.db.prepare(`
          INSERT INTO git_symbols (repo_name, file_path, symbol_name, symbol_type, signature, start_line, end_line, symbol_hash, snippet)
          VALUES (?, 'src/billing-service.js', 'orchestrateInvoiceRefund', 'function', 'function orchestrateInvoiceRefund(orderId)', 20, 24, 'h98', 'return orderId;')
        `).run(bridgedRes.data.repo);
        stack.db.prepare(`
          INSERT INTO git_symbols (repo_name, file_path, symbol_name, symbol_type, signature, start_line, end_line, symbol_hash, snippet)
          VALUES (?, 'src/audit-hook.js', 'emitAuditSink', 'function', 'function emitAuditSink(payload)', 1, 4, 'h99', 'const archiveTier = "glacier"; return archiveTier;')
        `).run(bridgedRes.data.repo);
        stack.db.prepare(`
          INSERT INTO git_edges (repo_name, from_file, from_symbol, to_symbol, edge_type)
          VALUES (?, 'src/billing-service.js', 'orchestrateInvoiceCheckout', 'emitAuditSink', 'calls')
        `).run(bridgedRes.data.repo);

        const hopCheck = stack.git.semanticSearch({
          query: 'orchestrate glacier',
          limit: 2
        });
        assert.equal(hopCheck.ok, true);
        assert.equal(hopCheck.data.results.length, 2);
        assert.equal(hopCheck.data.results[0].symbol_name, 'orchestrateInvoiceCheckout');
        const bridgedItem = hopCheck.data.results.find((r) => r.symbol_name === 'emitAuditSink');
        assert.ok(bridgedItem, '2-hop git_edges neighbor covering uncovered token "glacier" must be bridged into top-2');
        assert.equal(bridgedItem.bridge_hop, true);
        assert.equal(bridgedItem.bridge_via, 'orchestrateInvoiceCheckout');
        assert.ok(
          bridgedItem.score <= hopCheck.data.results[0].score * 0.84 + 1e-6,
          `Bridged score ${bridgedItem.score} must respect 0.84 cap against Hop-1 top score ${hopCheck.data.results[0].score}`
        );

        // 2. Token budget cap (`limit_tokens`) on both krusch_git_semantic_search and krusch_fs_search
        const tightGit = await dispatchStackTool(stack, 'krusch_git_semantic_search', {
          query: 'Subtotal',
          limit: 10,
          limit_tokens: 35
        });
        assert.equal(tightGit.ok, true);
        assert.ok(tightGit.data.results.length >= 1);
        assert.ok(tightGit.data.tokens_used <= 35, `Expected git tokens_used <= 35, got ${tightGit.data.tokens_used}`);

        const tightFs = await dispatchStackTool(stack, 'krusch_fs_search', {
          query: 'replication snapshot NonExistentConfigKey_v2',
          limit: 10,
          limit_tokens: 45
        });
        assert.equal(tightFs.ok, true);
        assert.ok(tightFs.data.results.length >= 1);
        assert.ok(tightFs.data.tokens_used <= 45, `Expected fs tokens_used <= 45, got ${tightFs.data.tokens_used}`);
        assert.ok(
          tightFs.data.unattested_query_terms.includes('NonExistentConfigKey_v2'),
          'Expected unattested code-shaped term in krusch_fs_search response'
        );
      } finally {
        stack.db.close();
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
