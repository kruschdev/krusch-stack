import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import {
  VERSION,
  createKruschStack,
  maskCodePreservingNewlines,
  generateIdeConfig,
  writeIdeConfigs,
  runStackDoctor,
  prunePreSynthesis
} from '../src/index.js';
import {
  ALL_STACK_TOOLS,
  getStackTools,
  dispatchStackTool,
  createMcpServer
} from '../src/mcp/server.js';
import { parseCliArgs, startHttpGateway } from '../bin/krusch-stack.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

function makeTempWorkspace() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-test-'));
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'src', 'math.js'),
    [
      '// Comment with fake brace { should be masked',
      'export function addNumbers(a, b) {',
      '  const str = "string with } brace";',
      '  return a + b;',
      '}',
      '',
      'export function computeTotal(items) {',
      '  return addNumbers(items.length, 10);',
      '}'
    ].join('\n') + '\n',
    'utf-8'
  );
  fs.writeFileSync(
    path.join(dir, 'ARCHITECTURE.md'),
    [
      '# System Architecture',
      'Core overview of the architecture.',
      '',
      '## Storage Engine',
      'Uses Node 22 SQLite by default with WAL mode.'
    ].join('\n') + '\n',
    'utf-8'
  );
  return dir;
}

describe('KruschStack Unified Ecosystem Suite (v1.0.0)', () => {
  test('INV-STACK-03: All 39 MCP tools declare explicit 4-boolean annotations and MIT LICENSE exists', () => {
    assert.equal(ALL_STACK_TOOLS.length, 39, 'Expected 39 total tools across the 7 stack pillars');
    const licensePath = path.join(REPO_ROOT, 'LICENSE');
    assert.ok(fs.existsSync(licensePath), 'Root MIT LICENSE file must exist');
    const licenseText = fs.readFileSync(licensePath, 'utf-8');
    assert.match(licenseText, /MIT License/);

    for (const tool of ALL_STACK_TOOLS) {
      assert.ok(tool.annotations, `Tool ${tool.name} is missing annotations object`);
      for (const key of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
        assert.equal(
          typeof tool.annotations[key],
          'boolean',
          `Tool ${tool.name} annotation '${key}' must be a boolean`
        );
      }
    }
  });

  test('INV-STACK-04: Zero leaked private homelab hostnames or LAN/Tailscale IPs across repository', () => {
    const forbiddenPatterns = [
      /\b192\.168\.\d+\.\d+\b/,
      /\b10\.10\.10\.\d+\b/,
      /\b100\.(65|106|105|98|124|92|94|69)\.\d+\.\d+\b/,
      /\b(kruschserv|kruschgame|kruschmedia|kruschsandbox|crush0|kr1yoga)\b/i
    ];

    function walkFiles(dir) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      const results = [];
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === '.krusch-stack') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          results.push(...walkFiles(full));
        } else if (entry.isFile() && full !== __filename) {
          results.push(full);
        }
      }
      return results;
    }

    const files = walkFiles(REPO_ROOT);
    assert.ok(files.length >= 15, 'Should scan all repository source and config files');
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8');
      for (const regex of forbiddenPatterns) {
        assert.equal(
          regex.test(content),
          false,
          `Forbidden private hostname/IP pattern ${regex} found in ${path.relative(REPO_ROOT, file)}`
        );
      }
    }
  });

  test('INV-STACK-05: Profile & server filtering returns expected tool subsets', () => {
    const fullTools = getStackTools({ profile: 'full' });
    const coreTools = getStackTools({ profile: 'core' });
    const contextOnly = getStackTools({ server: 'krusch-context-mcp' });
    const customSubset = getStackTools({ components: 'context,harness' });

    assert.equal(fullTools.length, 39);
    assert.equal(coreTools.length, 27);
    assert.equal(contextOnly.length, 5);
    assert.equal(customSubset.length, 12);
  });

  test('Tier 1 (krusch-context-mcp): remember, retrieve, INV-12 span drift, revise, nudge, and health', () => {
    const ws = makeTempWorkspace();
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // 1. Remember invariant anchored to src/math.js
      const rem = stack.context.remember({
        category: 'invariant',
        content: 'Do not use eval() in math utilities',
        provenance: {
          file: 'src/math.js',
          locator: 'L2-L5',
          quoted_sentence: 'return a + b;'
        }
      });
      assert.equal(rem.ok, true);
      assert.equal(rem.tool, 'krusch_context_remember');
      const memId = rem.data.id;

      // 2. Retrieve & verify VALID span drift
      const ret1 = stack.context.retrieve({ query: '*' });
      assert.equal(ret1.ok, true);
      assert.equal(ret1.data.items.length, 1);
      assert.equal(ret1.data.items[0].drift_status, 'VALID');

      // 3. Mutate the quoted line in src/math.js and verify STALE_DRIFT
      fs.writeFileSync(
        path.join(ws, 'src', 'math.js'),
        'export function addNumbers(a, b) {\n  return Number(a) + Number(b);\n}\n',
        'utf-8'
      );
      const ret2 = stack.context.retrieve({ query: '*' });
      assert.equal(ret2.data.items[0].drift_status, 'STALE_DRIFT');

      // 4. Pre-commit nudge detects eval() violation
      const nudgeFail = stack.context.nudge({
        trigger: 'pre_commit',
        code: '+ const x = eval("2 + 2");'
      });
      assert.equal(nudgeFail.ok, true);
      assert.equal(nudgeFail.data.passed, false);
      assert.ok(nudgeFail.data.findings.length >= 1);

      // 5. Supersede memory
      const rev = stack.context.revise({
        action: 'supersede',
        target_id: memId,
        new_content: 'Never use eval() or Function() in any module',
        reason: 'Expanded scope'
      });
      assert.equal(rev.ok, true);

      const health = stack.context.health();
      assert.equal(health.ok, true);
      assert.equal(health.data.active, 1);
      assert.equal(health.data.superseded, 1);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Tier 1 Epistemic & Honesty Suite (Lineage, Stemming, BUG-07 Conflicts, BUG-08 STORAGE_ERROR, Path Guard & Corruption Recovery)', () => {
    const ws = makeTempWorkspace();
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // 1. Lineage chain forwarding: querying an old superseded term resolves terminal active row + lineage
      const m1 = stack.context.remember({
        category: 'decision',
        content: 'Primary Redis cache pool port is 6379 with TLS disabled.'
      });
      const rev1 = stack.context.revise({
        action: 'supersede',
        target_id: m1.data.id,
        new_content: 'Migrated primary Valkey cache pool to port 6380 with mTLS enabled.',
        reason: 'Valkey mTLS cutover'
      });
      assert.equal(rev1.ok, true);

      const lineageRet = stack.context.retrieve({ query: 'Redis cache pool port' });
      assert.equal(lineageRet.ok, true);
      assert.equal(lineageRet.data.epistemic_status, 'SUPPORTED');
      assert.equal(lineageRet.data.items[0].id, rev1.data.new_id);
      assert.equal(lineageRet.data.items[0].lineage.length, 2);
      assert.deepEqual(lineageRet.data.chronological_order, [m1.data.id, rev1.data.new_id]);

      // 2. BUG-07: Single-stem coding query ("Could you show me how to implement a login feature?") emits 0 false conflicts
      const pad = 'Reviewed middleware pagination, structured logging, and cookie serialization across endpoints. '.repeat(3);
      stack.context.remember({
        category: 'decision',
        content: `[Session 1 | Turn #4] USER: Can you help wire the login button to our dashboard router? ${pad} | ASSISTANT: Wired login button.`
      });
      stack.context.remember({
        category: 'decision',
        content: `[Session 2 | Turn #9] USER: Honestly I have never built a login rate limiter with token buckets before, though dashboard routing works. ${pad} | ASSISTANT: Added token bucket guide.`
      });
      const loginRet = stack.context.retrieve({
        query: 'Could you show me how to implement a login feature?'
      });
      assert.equal(loginRet.data.conflicts.length, 0, 'Single-stem coding query must not emit false polarity conflicts');

      // 3. BUG-07: True multi-clause past-participle negation conflict sets epistemic_status = CONFLICTED
      stack.context.remember({
        category: 'decision',
        content: `[Session 1 | Turn #12] USER: I implemented the homepage Flask route and handled HTTP requests cleanly. ${pad} | ASSISTANT: Great Flask route setup.`
      });
      stack.context.remember({
        category: 'decision',
        content: `[Session 3 | Turn #28] USER: I have never written any Flask routes or handled HTTP requests in this project, so I am starting from scratch. ${pad} | ASSISTANT: Starting Flask routing from basics.`
      });
      const flaskRet = stack.context.retrieve({
        query: 'Have I worked with Flask routes and handled HTTP requests?'
      });
      assert.equal(flaskRet.data.epistemic_status, 'CONFLICTED');
      assert.equal(flaskRet.data.conflicts.length, 1);
      assert.equal(flaskRet.data.conflicts[0].conflict_type, 'polarity_contradiction');

      // 4. Abstention precision (NO_KNOWN_SUPPORT) & strict limit_tokens ceiling
      const absRet = stack.context.retrieve({
        query: 'Kubernetes Istio envoy sidecar mesh mTLS rotation'
      });
      assert.equal(absRet.ok, true);
      assert.equal(absRet.data.epistemic_status, 'NO_KNOWN_SUPPORT');
      assert.equal(absRet.data.items.length, 0);

      const tightRet = stack.context.retrieve({ query: '*', limit_tokens: 45 });
      assert.ok(tightRet.data.state.tokens_used <= 45, 'Used tokens must respect tight limit_tokens budget');

      // 5. Path-traversal containment in INV-12 provenance (../../etc/passwd -> STALE_DRIFT, never read outside workspaceRoot)
      const travMem = stack.context.remember({
        category: 'invariant',
        content: 'Path containment verification rule',
        provenance: {
          file: '../../etc/passwd',
          locator: 'L1-L2'
        }
      });
      const travRet = stack.context.retrieve({ query: 'Path containment verification' });
      const travItem = travRet.data.items.find((it) => it.id === travMem.data.id);
      assert.ok(travItem);
      assert.equal(travItem.drift_status, 'STALE_DRIFT');

      // 6. BUG-08: SQLite table failure emits STORAGE_ERROR (ok=false), never NO_KNOWN_SUPPORT
      stack.db.exec('DROP TABLE context_memories;');
      const brokenRet = stack.context.retrieve({ query: 'Valkey cache pool' });
      assert.equal(brokenRet.ok, false);
      assert.equal(brokenRet.data.epistemic_status, 'STORAGE_ERROR');
      assert.ok(brokenRet.data.storage_error);

      // 7. Corrupted file-backed SQLite database rotates to .corrupt.* and self-heals on open
      const corruptDbPath = path.join(ws, '.krusch-stack', 'stack.db');
      fs.mkdirSync(path.dirname(corruptDbPath), { recursive: true });
      fs.writeFileSync(corruptDbPath, 'NOT A VALID SQLITE3 HEADER PAYLOAD CORRUPTED BYTES', 'utf-8');
      const healedStack = createKruschStack({ workspaceRoot: ws, dbPath: corruptDbPath });
      const postHealHealth = healedStack.context.health();
      assert.equal(postHealHealth.ok, true);
      assert.equal(postHealHealth.data.total, 0);
      const rotatedFiles = fs.readdirSync(path.dirname(corruptDbPath)).filter((f) => f.includes('.corrupt.'));
      assert.ok(rotatedFiles.length >= 1, 'Corrupted SQLite file must be rotated with .corrupt.<ts> suffix');
      healedStack.db.close();
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Tier 1 Hybrid Vector, 3-Tier Progressive Condensation, Episode Smoothing & Legacy Schema Auto-Migration', async () => {
    const ws = makeTempWorkspace();
    try {
      // Helper to synthesize deterministic unit vectors along orthogonal basis axes (CI=true safe)
      const makeBasisVec = (axis, mixAxis = -1, mixWeight = 0) => {
        const v = new Array(1024).fill(0);
        v[axis] = 1.0;
        if (mixAxis >= 0) v[mixAxis] = mixWeight;
        const norm = Math.hypot(...v) || 1;
        return v.map((x) => Number((x / norm).toFixed(6)));
      };

      // 1. Legacy SQLite schema without `embedding` column auto-migrates cleanly without data loss
      const legacyDbPath = path.join(ws, '.krusch-stack', 'legacy.db');
      fs.mkdirSync(path.dirname(legacyDbPath), { recursive: true });
      const rawLegacy = new DatabaseSync(legacyDbPath);
      rawLegacy.exec(`
        CREATE TABLE context_memories (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          category TEXT NOT NULL,
          content TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          superseded_by INTEGER,
          revocation_reason TEXT,
          provenance_file TEXT,
          provenance_locator TEXT,
          quoted_sentence TEXT,
          anchor_hash TEXT,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        INSERT INTO context_memories (category, content) VALUES ('invariant', 'Legacy pre-embedding rule preserved');
      `);
      rawLegacy.close();

      const migratedStack = createKruschStack({ workspaceRoot: ws, dbPath: legacyDbPath });
      const cols = migratedStack.db.prepare('PRAGMA table_info(context_memories);').all();
      assert.ok(cols.some((c) => c.name === 'embedding'), 'Legacy DB must auto-migrate embedding TEXT column');
      const legacyCheck = migratedStack.context.retrieve({ query: 'Legacy pre-embedding rule' });
      assert.equal(legacyCheck.data.items.length, 1);

      // 2. Zero-lexical-overlap standing directive & semantic recall via _embedding
      const directiveVec = makeBasisVec(7, 8, 0.25);
      const queryVec = makeBasisVec(7, 8, 0.22); // cosine ~ 0.999, zero shared words
      migratedStack.context.remember({
        category: 'decision',
        content: '[Session 1 | Turn #2] USER: Whenever you craft scripts for me, favor lightweight stdlib modules with minimal dependencies. | ASSISTANT: Understood, stdlib first.',
        _embedding: directiveVec
      });
      for (let i = 0; i < 34; i++) {
        const uniqWords = Array.from({ length: 18 }, (_, k) => `astro_${i}_metric_${k}`).join(' ');
        migratedStack.context.remember({
          category: 'decision',
          content: `[Session ${(i % 4) + 1} | Turn #${(i + 2) * 2}/${(i + 2) * 2 + 1}] USER: Discussing astronomy telescope calibration step ${i} (${uniqWords}) ${'optical鏡 '.repeat(35)} | ASSISTANT: Detailed mirror grinding schedule for step ${i}: ${'1. Check focal ratio\n2. Measure wavefront error\n'.repeat(14)}`,
          _embedding: makeBasisVec(20 + i, 7, 0.55)
        });
      }

      // Add a continuation turn right after a high-signal turn in Session 4 to test Episode Kernel Smoothing
      const anchorTurn = migratedStack.context.remember({
        category: 'decision',
        content: '[Session 4 | Turn #90/91] USER: My PostgreSQL connection pooler pgbouncer max_client_conn is set to 450 in production. | ASSISTANT: Noted pgbouncer max_client_conn=450.',
        _embedding: makeBasisVec(90)
      });
      const contTurn = migratedStack.context.remember({
        category: 'decision',
        content: '[Session 4 | Turn #92/93] USER: Thanks, that sounds good! Also bump reserve_pool_size to 25 on the same host. | ASSISTANT: Updated reserve_pool_size=25.',
        _embedding: makeBasisVec(91)
      });

      const zeroLexRet = migratedStack.context.retrieve({
        query: 'Write a small CSV parser utility in Python',
        limit_tokens: 8000,
        _embedding: queryVec
      });
      assert.equal(zeroLexRet.ok, true);
      assert.ok(
        zeroLexRet.data.items.some((it) => it.content.includes('minimal dependencies')),
        'Zero-lexical-overlap standing directive must be recalled via dense _embedding'
      );

      // 3. 3-Tier Progressive Condensation (680 / 440 / 320 chars) + zero 92-char stubs
      assert.ok(zeroLexRet.data.items.length >= 25, '3-Tier condensation must pack >=25 multi-session turns in 8K budget');
      for (const it of zeroLexRet.data.items) {
        if (it.content.includes('USER:')) {
          assert.ok(it.content.includes('| ASSISTANT:'), 'Condensed dialogue turns must preserve both USER: and | ASSISTANT: segments');
        }
      }
      assert.ok(zeroLexRet.data.items[0].content.length <= 700, 'Tier 1 condensed turn must respect ~680 char ceiling');

      // 4. Episode Kernel Smoothing forward-anchors continuation turn (#92/93) when #90/91 matches strongly
      const smoothRet = migratedStack.context.retrieve({
        query: 'What is my PostgreSQL pgbouncer max_client_conn setting?',
        limit_tokens: 8000,
        _embedding: makeBasisVec(90, 91, 0.05)
      });
      const packedIds = new Set(smoothRet.data.items.map((it) => it.id));
      assert.ok(packedIds.has(anchorTurn.data.id));
      assert.ok(packedIds.has(contTurn.data.id), 'In-session continuation turn must be boosted by Episode Kernel Smoothing');

      // 5. Temporal multi-session query emits timeline_markdown & Session-by-Session Macro Progression
      const timelineRet = migratedStack.context.retrieve({
        query: 'Give me a chronological timeline of how our astronomy telescope sessions progressed across sessions',
        limit_tokens: 8000,
        _embedding: makeBasisVec(20, 21, 0.5)
      });
      assert.ok(timelineRet.data.timeline_markdown, 'Temporal multi-session query must populate timeline_markdown');
      assert.match(timelineRet.data.timeline_markdown, /Chronological Event Sequence/);
      assert.ok(timelineRet.data.rendered_context.length > 200);
      migratedStack.db.close();

      // 6. Live async Ollama/HTTP embedding auto-hydration via dispatchStackTool + graceful offline fallback
      const mockEmbedServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
          const parsed = JSON.parse(body || '{}');
          const input = String(parsed.input || parsed.prompt || '');
          const vec = input.includes('zephyr') || input.includes('breeze')
            ? makeBasisVec(300)
            : makeBasisVec(301);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ embeddings: [vec] }));
        });
      });
      await new Promise((resolve) => mockEmbedServer.listen(0, '127.0.0.1', resolve));
      const embedPort = mockEmbedServer.address().port;
      try {
        const liveStack = createKruschStack({
          workspaceRoot: ws,
          ephemeral: true,
          embedEndpoint: `http://127.0.0.1:${embedPort}/api/embed`,
          autoEmbed: true
        });
        const mcpRem = await dispatchStackTool(liveStack, 'krusch_context_remember', {
          category: 'invariant',
          content: 'Always route zephyr telemetry frames over QUIC streams.'
        });
        assert.equal(mcpRem.ok, true);
        assert.equal(mcpRem.data.has_embedding, true);

        const mcpRet = await dispatchStackTool(liveStack, 'krusch_context_retrieve', {
          query: 'How should breeze network packets be transported?'
        });
        assert.equal(mcpRet.ok, true);
        assert.equal(mcpRet.data.items.length, 1);
        assert.match(mcpRet.data.items[0].content, /zephyr telemetry/);
      } finally {
        mockEmbedServer.close();
      }

      // Offline unreachable port falls back cleanly without throwing
      const offlineStack = createKruschStack({
        workspaceRoot: ws,
        ephemeral: true,
        embedEndpoint: 'http://127.0.0.1:1/api/embed',
        autoEmbed: true
      });
      const offRem = await offlineStack.context.rememberAsync({
        category: 'decision',
        content: 'Offline fallback lexical decision on SQLite WAL checkpoints'
      });
      assert.equal(offRem.ok, true);
      assert.equal(offRem.data.has_embedding, false);
      const offRet = await offlineStack.context.retrieveAsync({ query: 'SQLite WAL checkpoints' });
      assert.equal(offRet.ok, true);
      assert.equal(offRet.data.items.length, 1);

      // Direct prunePreSynthesis check
      const condensedTurn = prunePreSynthesis(
        `[Session 2 | Turn #4/5] USER: Please check my schema ${'x '.repeat(400)} | ASSISTANT: # Summary\n- Oct 24 launch\n${'detail '.repeat(400)}`,
        { maxChars: 320 }
      );
      assert.ok(condensedTurn.includes('USER:') && condensedTurn.includes('| ASSISTANT:'));
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Tier 2A (krusch-git): INV-GIT-01 comment/string masking, AST symbols, and dependency graph', () => {
    const ws = makeTempWorkspace();
    try {
      const sample = 'const s = "{ not a block }";\nfunction demo() {\n  return 1;\n}\n';
      const masked = maskCodePreservingNewlines(sample);
      assert.equal(masked.split('\n').length, sample.split('\n').length);

      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });
      const syms = stack.git.searchSymbols({ query: 'addNumbers' });
      assert.equal(syms.ok, true);
      assert.ok(syms.data.symbols.some((s) => s.symbol_name === 'addNumbers'));

      const graph = stack.git.dependencyGraph({ symbol: 'addNumbers' });
      assert.equal(graph.ok, true);
      assert.ok(graph.data.inbound_callers.some((e) => e.from_symbol === 'computeTotal'));
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Tier 2B (krusch-fs): locate, pageTree, readPage, and SHA-256 PageMemory drift detection', () => {
    const ws = makeTempWorkspace();
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      const loc = stack.fs.locate({ pattern: '*.md' });
      assert.equal(loc.ok, true);
      assert.ok(loc.data.files.some((f) => f.file_path.endsWith('ARCHITECTURE.md')));

      const tree = stack.fs.pageTree({ path: 'ARCHITECTURE.md' });
      assert.equal(tree.ok, true);
      assert.ok(tree.data.pages.length >= 2);

      const note = stack.fs.rememberOnPage({
        path: 'ARCHITECTURE.md',
        page_number: 1,
        note: 'Verified overview section',
        category: 'annotation'
      });
      assert.equal(note.ok, true);

      const page1 = stack.fs.readPage({ path: 'ARCHITECTURE.md', page_number: 1 });
      assert.equal(page1.ok, true);
      assert.equal(page1.data.memories[0].drift_status, 'VALID');

      // Mutate ARCHITECTURE.md page 1 and verify STALE_DRIFT
      fs.writeFileSync(
        path.join(ws, 'ARCHITECTURE.md'),
        '# System Architecture (v2 Updated)\nChanged text on page 1.\n\n## Storage Engine\nSQLite.\n',
        'utf-8'
      );
      const page1After = stack.fs.readPage({ path: 'ARCHITECTURE.md', page_number: 1 });
      assert.equal(page1After.data.memories[0].drift_status, 'STALE_DRIFT');
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Tier 3 (krusch-harness): INV-STACK-06 2PC staged diff, invariant gate block, and atomic apply', () => {
    const ws = makeTempWorkspace();
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // Add an invariant forbidding eval()
      stack.context.remember({
        category: 'invariant',
        content: 'Never use eval() in codebase'
      });

      // 1. Attempt a task that violates the invariant -> BLOCKED_INVARIANT
      const blockedTask = stack.harness.run({
        goal: 'Add unsafe dynamic runner',
        edits: [{ file_path: 'src/unsafe.js', content: 'export const run = (s) => eval(s);\n' }]
      });
      assert.equal(blockedTask.data.status, 'BLOCKED_INVARIANT');
      assert.equal(fs.existsSync(path.join(ws, 'src', 'unsafe.js')), false, 'Blocked task must not touch disk');

      // 2. Stage a clean task -> STAGED (still not written to disk until applyDiff)
      const cleanTask = stack.harness.run({
        goal: 'Add safe multiply helper',
        edits: [{ file_path: 'src/multiply.js', content: 'export const multiply = (a, b) => a * b;\n' }]
      });
      assert.equal(cleanTask.ok, true);
      assert.equal(cleanTask.data.status, 'STAGED');
      assert.equal(fs.existsSync(path.join(ws, 'src', 'multiply.js')), false, 'Staged task must wait for 2PC applyDiff');

      // 3. Apply the staged diff -> writes to disk
      const applied = stack.harness.applyDiff({ task_id: cleanTask.data.task_id });
      assert.equal(applied.ok, true);
      assert.equal(applied.data.status, 'APPLIED');
      assert.equal(fs.existsSync(path.join(ws, 'src', 'multiply.js')), true);
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Tier 4 (krusch-frontend-mcp) & Tier 5 (g-krusch) & Router (krusch-cascade-router)', async () => {
    const ws = makeTempWorkspace();
    try {
      const stack = createKruschStack({ workspaceRoot: ws, ephemeral: true });

      // Frontend: Color palette + CSS to Tailwind + Canonical templates
      const palette = stack.frontend.generateColorPalette({ base_hex: '#00e5ff', harmony: 'complementary' });
      assert.equal(palette.ok, true);
      assert.equal(palette.data.palette.length, 5);

      const tw = stack.frontend.cssToTailwind({ css: 'display: flex; align-items: center; justify-content: space-between;' });
      assert.equal(tw.ok, true);
      assert.ok(tw.data.tailwind_classes.includes('flex'));
      assert.ok(tw.data.tailwind_classes.includes('items-center'));

      const tpl = stack.frontend.getCanonicalTemplate({ template_id: 'article-shell' });
      assert.equal(tpl.ok, true);
      assert.ok(tpl.data.html.includes('<article'));

      // Workspace: INV-14 MIME disambiguation (.md, .gdoc, .gsheet, .slides)
      stack.workspace.writeDriveFile({ path: 'roadmap.slides', content: '# Slide 1: KruschStack' });
      stack.workspace.writeDriveFile({ path: 'roadmap.gdoc', content: '<h1>KruschStack</h1>' });

      const slidesFile = stack.workspace.readDriveFile({ path: 'roadmap.slides' });
      const gdocFile = stack.workspace.readDriveFile({ path: 'roadmap.gdoc' });
      assert.equal(slidesFile.data.mime_type, 'application/vnd.google-apps.presentation');
      assert.equal(gdocFile.data.mime_type, 'application/vnd.google-apps.document');

      // Router: <25µs L1 classification + MCP dispatch
      const routed = await dispatchStackTool(stack, 'krusch_route_task', {
        prompt: 'Design a multi-node two-phase commit architecture refactor'
      });
      assert.equal(routed.ok, true);
      assert.ok(routed.data.tier);
      assert.equal(typeof routed.data.latency_us, 'number');
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });

  test('Installer, Doctor, CLI args, and HTTP Gateway work end-to-end', async () => {
    const ws = makeTempWorkspace();
    try {
      const cfg = generateIdeConfig({ ide: 'claude', mode: 'unified', profile: 'full', workspaceRoot: ws });
      assert.ok(cfg.mcpServers['krusch-stack']);

      const written = writeIdeConfigs({ targetDir: ws, ide: 'all', mode: 'modular', profile: 'core' });
      assert.equal(written.ok, true);
      assert.ok(fs.existsSync(path.join(ws, '.mcp.json')));
      assert.ok(fs.existsSync(path.join(ws, '.cursor', 'mcp.json')));
      assert.ok(fs.existsSync(path.join(ws, '.agent', 'AGENTS.md')));

      const doc = runStackDoctor({ workspaceRoot: ws });
      assert.equal(doc.ok, true);
      assert.equal(doc.data.sqlite_ready, true);

      const parsed = parseCliArgs(['init', '--profile', 'core', '--modular', '--json']);
      assert.equal(parsed.command, 'init');
      assert.equal(parsed.flags.profile, 'core');
      assert.equal(parsed.flags.mode, 'modular');
      assert.equal(parsed.flags.json, true);

      // Test MCP Server instantiation & HTTP Gateway on ephemeral port 0
      const { tools } = createMcpServer({ workspaceRoot: ws, ephemeral: true, profile: 'full' });
      assert.equal(tools.length, 39);

      const gw = await startHttpGateway({ workspaceRoot: ws, ephemeral: true, port: 0 });
      const addr = gw.server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${addr.port}/health`);
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.ok, true);
        assert.equal(body.version, VERSION);
        assert.equal(body.tools_count, 39);
      } finally {
        gw.server.close();
      }
    } finally {
      fs.rmSync(ws, { recursive: true, force: true });
    }
  });
});
