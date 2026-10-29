#!/usr/bin/env node

/**
 * @module bin/krusch-stack
 * Unified CLI for KruschStack (`npx krusch-stack <command>`).
 * Commands:
 *   - `init`   : Auto-configure Claude Code, Cursor, Windsurf, and Antigravity MCP configs + .agent/AGENTS.md
 *   - `mcp`    : Start the unified (or modular) KruschStack MCP server over stdio
 *   - `doctor` : Run end-to-end health checks across all 7 stack engines
 *   - `route`  : Classify a task prompt via the <25µs L1-L3 Cascade Router
 *   - `serve`  : Start the lightweight HTTP status & REST tool gateway (default port 3780, used by Docker)
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  VERSION,
  createKruschStack,
  writeIdeConfigs,
  runStackDoctor
} from '../src/index.js';
import { runMcpServer, getStackTools, dispatchStackTool } from '../src/mcp/server.js';

const __filename = fileURLToPath(import.meta.url);

// Node >= 22 check for native node:sqlite
const majorNode = parseInt(process.versions.node.split('.')[0], 10);
if (majorNode < 22) {
  console.error(`Error: krusch-stack v${VERSION} requires Node.js >= 22.0.0 (found v${process.versions.node}).`);
  process.exit(1);
}

/**
 * Parse CLI flags from argv slice.
 */
export function parseCliArgs(argv = process.argv.slice(2)) {
  const positional = [];
  const flags = {
    profile: process.env.KRUSCH_STACK_PROFILE || 'full',
    mode: 'unified',
    ide: 'all',
    components: undefined,
    server: undefined,
    deferTools:
      process.env.KRUSCH_STACK_DEFER_TOOLS === '1' ||
      process.env.KRUSCH_STACK_DEFER_TOOLS === 'true',
    json: false,
    ephemeral: false,
    port: Number(process.env.KRUSCH_STACK_PORT || 3780),
    workspaceRoot: process.env.KRUSCH_WORKSPACE_ROOT || process.cwd()
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--profile' && argv[i + 1]) {
      flags.profile = argv[++i];
    } else if (arg.startsWith('--profile=')) {
      flags.profile = arg.split('=')[1];
    } else if (arg === '--mode' && argv[i + 1]) {
      flags.mode = argv[++i];
    } else if (arg === '--modular') {
      flags.mode = 'modular';
    } else if (arg === '--unified') {
      flags.mode = 'unified';
    } else if (arg === '--ide' && argv[i + 1]) {
      flags.ide = argv[++i];
    } else if (arg === '--components' && argv[i + 1]) {
      flags.components = argv[++i];
    } else if (arg === '--server' && argv[i + 1]) {
      flags.server = argv[++i];
    } else if (arg === '--defer-tools') {
      flags.deferTools = true;
    } else if (arg === '--no-defer-tools') {
      flags.deferTools = false;
    } else if (arg === '--workspace' && argv[i + 1]) {
      flags.workspaceRoot = path.resolve(argv[++i]);
    } else if (arg === '--port' && argv[i + 1]) {
      flags.port = Number(argv[++i]);
    } else if (arg === '--json') {
      flags.json = true;
    } else if (arg === '--ephemeral') {
      flags.ephemeral = true;
    } else if (arg === '-h' || arg === '--help') {
      flags.help = true;
    } else if (arg === '-v' || arg === '--version') {
      flags.version = true;
    } else {
      positional.push(arg);
    }
  }

  return {
    command: positional[0] || 'mcp',
    positional: positional.slice(1),
    flags
  };
}

function printHelp() {
  console.log(`
KruschStack v${VERSION} — The Unified Sovereign AI & Coding Agent Stack

Usage:
  npx krusch-stack <command> [options]

Commands:
  init                Configure IDE MCP files (.mcp.json, .cursor/mcp.json, Windsurf, Antigravity) & .agent/AGENTS.md
  mcp                 Start the KruschStack MCP server over stdio (default)
  doctor              Verify Node 22 SQLite, Postgres, Ollama, and all 7 stack engines
  route "<prompt>"    Classify a coding or reasoning prompt via the <25µs L1-L3 Cascade Router
  serve               Start the HTTP status & REST tool gateway (default :3780)

Options:
  --profile <full|core>     Select 'full' (all 7 pillars, 39 tools) or 'core' (Tiers 1-3 + Router, 27 tools)
  --defer-tools             Collapse wide tool catalog into 6 pinned tools + 3 BM25 bridge tools
  --mode <unified|modular>  Register a single 'krusch-stack' MCP entry or separate per-pillar MCP entries
  --ide <all|claude|cursor|windsurf|antigravity>
  --components <csv>        Comma-separated subset (context,git,fs,harness,frontend,workspace,router)
  --server <name>           Run as a specific pillar server (e.g. krusch-context-mcp)
  --port <number>           HTTP port for 'serve' (default: 3780)
  --ephemeral               Use in-memory SQLite (:memory:)
  --json                    Emit raw JSON output
`);
}

/**
 * Start the lightweight HTTP status & REST gateway (for Docker and health checks).
 */
export function startHttpGateway(options = {}) {
  const port = Number(options.port || process.env.KRUSCH_STACK_PORT || 3780);
  const stack = options.stack || createKruschStack(options);
  const tools = getStackTools({
    profile: stack.profile,
    components: options.components,
    deferTools: Boolean(options.deferTools)
  });

  const server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      const report = stack.doctor();
      res.writeHead(report.ok ? 200 : 503);
      res.end(JSON.stringify({
        ok: report.ok,
        name: 'krusch-stack',
        version: VERSION,
        profile: stack.profile,
        defer_tools: Boolean(options.deferTools),
        tools_count: tools.length,
        doctor: report.data
      }, null, 2));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/tools') {
      res.writeHead(200);
      res.end(JSON.stringify({ ok: true, count: tools.length, tools }, null, 2));
      return;
    }

    const maxBodyBytes = Math.max(
      1024,
      Number(options.maxBodyBytes || process.env.KRUSCH_MAX_BODY_BYTES || 2 * 1024 * 1024)
    );

    const readBoundedJson = () =>
      new Promise((resolve, reject) => {
        const declaredLen = Number(req.headers['content-length'] || 0);
        if (Number.isFinite(declaredLen) && declaredLen > maxBodyBytes) {
          const err = new Error(`Payload Too Large: exceeds ${maxBodyBytes} byte limit`);
          err.statusCode = 413;
          req.resume();
          reject(err);
          return;
        }
        const chunks = [];
        let totalBytes = 0;
        let settled = false;
        req.on('data', (chunk) => {
          if (settled) return;
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
          totalBytes += buf.length;
          if (totalBytes > maxBodyBytes) {
            settled = true;
            const err = new Error(`Payload Too Large: exceeds ${maxBodyBytes} byte limit`);
            err.statusCode = 413;
            req.pause();
            reject(err);
            return;
          }
          chunks.push(buf);
        });
        req.on('end', () => {
          if (settled) return;
          settled = true;
          const rawBody = Buffer.concat(chunks).toString('utf8');
          try {
            const parsed = rawBody.trim() ? JSON.parse(rawBody) : {};
            resolve({ rawBody, parsed });
          } catch (_parseErr) {
            const err = new Error('Invalid JSON request body');
            err.statusCode = 400;
            reject(err);
          }
        });
        req.on('error', (err) => {
          if (settled) return;
          settled = true;
          reject(err);
        });
      });

    const sendGatewayError = (err) => {
      const code = Number.isInteger(err?.statusCode) ? err.statusCode : 400;
      const headers = code === 413 ? { Connection: 'close' } : {};
      res.writeHead(code, headers);
      res.end(JSON.stringify({ ok: false, error: err.message }, null, 2), () => {
        if (code === 413 && !req.complete) {
          req.destroy();
        }
      });
    };

    if (req.method === 'POST' && url.pathname === '/call') {
      readBoundedJson()
        .then(async ({ parsed }) => {
          const result = await dispatchStackTool(
            stack,
            parsed.tool || parsed.name,
            parsed.arguments || parsed.args || {},
            { profile: stack.profile, components: options.components }
          );
          res.writeHead(result.ok ? 200 : 400);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    if (req.method === 'POST' && url.pathname.startsWith('/resilience/')) {
      const action = url.pathname.slice('/resilience/'.length);
      readBoundedJson()
        .then(({ rawBody, parsed }) => {
          const actionMap = {
            budget: () => stack.resilience.assembleContextBudget(parsed),
            'cost-evaluate': () => stack.resilience.evaluateCostKillSwitch(parsed),
            'cost-record': () => stack.resilience.recordCostUsage(parsed),
            'verify-dag': () => stack.resilience.verifyTrajectoryDag(parsed),
            shadow: () => stack.resilience.recordShadowComparison(parsed),
            'hitl-draft': () => stack.resilience.draftHitlGate(parsed),
            'hitl-resolve': () =>
              stack.resilience.resolveHitlGate({
                gateId: parsed.gateId,
                decision: parsed.decision,
                reviewer: parsed.reviewer,
                reason: parsed.reason,
                nowMs: parsed.nowMs,
                requireSignature: true,
                signingSecret: options.slackSigningSecret ?? process.env.SLACK_SIGNING_SECRET ?? '',
                timestampHeader: req.headers['x-slack-request-timestamp'] || '',
                signatureHeader: req.headers['x-slack-signature'] || '',
                rawBody
              })
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown resilience action: ${action}` }));
            return;
          }
          const result = handler();
          const status = result.ok
            ? 200
            : result.data?.status === 'UNAUTHORIZED_SIGNATURE'
              ? 401
              : 400;
          res.writeHead(status);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ ok: false, error: 'Not Found' }));
  });

  const bindHost = options.host || process.env.KRUSCH_STACK_HOST || '127.0.0.1';
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, bindHost, () => {
      resolve({ server, port, host: bindHost, stack });
    });
  });
}

async function main() {
  const { command, positional, flags } = parseCliArgs();

  if (flags.help) {
    printHelp();
    return;
  }
  if (flags.version) {
    console.log(VERSION);
    return;
  }

  if (command === 'init') {
    const stack = createKruschStack({
      workspaceRoot: flags.workspaceRoot,
      profile: flags.profile,
      ephemeral: flags.ephemeral
    });
    const ideRes = writeIdeConfigs({
      targetDir: flags.workspaceRoot,
      ide: flags.ide,
      mode: flags.mode,
      profile: flags.profile
    });
    const docRes = stack.doctor();
    if (flags.json) {
      console.log(JSON.stringify({ ok: true, init: ideRes.data, doctor: docRes.data }, null, 2));
    } else {
      console.log(`\n🚀 KruschStack v${VERSION} initialized in ${flags.workspaceRoot}`);
      console.log(`   Profile : ${flags.profile} (${getStackTools({ profile: flags.profile }).length} MCP tools)`);
      console.log(`   Mode    : ${flags.mode}`);
      console.log(`   Files   : ${(ideRes.data.files_written || []).join(', ')}`);
      console.log(`   SQLite  : Ready (${docRes.data.components.length} active engines)\n`);
    }
    return;
  }

  if (command === 'doctor' || command === 'health') {
    const stack = createKruschStack({
      workspaceRoot: flags.workspaceRoot,
      profile: flags.profile,
      ephemeral: flags.ephemeral
    });
    const report = stack.doctor();
    if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`\n🩺 KruschStack Doctor (v${VERSION})`);
      console.log(`   Summary  : ${report.summary}`);
      console.log(`   Node.js  : ${report.data.node_version} (supported: ${report.data.node_supported})`);
      console.log(`   SQLite   : ${report.data.sqlite_ready ? 'READY' : 'FAILED'}`);
      console.log(`   Postgres : ${report.data.postgres_configured ? 'CONFIGURED' : 'Not set (using zero-setup SQLite)'}`);
      console.log(`   Ollama   : ${report.data.ollama_host}`);
      console.log(`\n   Active Pillars (${report.data.profile} profile):`);
      for (const comp of report.data.components) {
        console.log(`     ✓ [${comp.tier}] ${comp.name} — ${comp.description}`);
      }
      console.log('');
    }
    return;
  }

  if (command === 'route') {
    const prompt = positional.join(' ').trim() || 'Fix unit test in auth.js';
    const stack = createKruschStack({
      workspaceRoot: flags.workspaceRoot,
      profile: flags.profile,
      ephemeral: true
    });
    const routeRes = stack.router.routeTask({ prompt });
    console.log(JSON.stringify(routeRes, null, 2));
    return;
  }

  if (command === 'serve') {
    const { port } = await startHttpGateway({
      workspaceRoot: flags.workspaceRoot,
      profile: flags.profile,
      components: flags.components,
      deferTools: flags.deferTools,
      ephemeral: flags.ephemeral,
      port: flags.port
    });
    console.log(`🌐 KruschStack HTTP & Tool Gateway listening on http://127.0.0.1:${port}`);
    return;
  }

  // Default: start stdio MCP server
  await runMcpServer({
    workspaceRoot: flags.workspaceRoot,
    profile: flags.profile,
    components: flags.components,
    server: flags.server,
    deferTools: flags.deferTools,
    ephemeral: flags.ephemeral
  });
}

const isDirectExecution = process.argv[1] && (
  path.resolve(process.argv[1]) === __filename ||
  path.basename(process.argv[1]) === 'krusch-stack' ||
  path.basename(process.argv[1]) === 'kruschstack' ||
  path.basename(process.argv[1]) === 'krusch-stack.js'
);

if (isDirectExecution) {
  main().catch((err) => {
    console.error('[krusch-stack fatal]', err.message);
    process.exit(1);
  });
}
