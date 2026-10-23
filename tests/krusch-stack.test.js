import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  VERSION,
  createKruschStack,
  maskCodePreservingNewlines,
  generateIdeConfig,
  writeIdeConfigs,
  runStackDoctor
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
