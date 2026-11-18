#!/usr/bin/env node

/**
 * @module bin/krusch-stack
 * Unified CLI for KruschStack (`npx krusch-stack <command>`).
 * Commands:
 *   - `init`   : Auto-configure Claude Code, Cursor, Windsurf, and Antigravity MCP configs + .agent/AGENTS.md
 *   - `mcp`    : Start the unified (or modular) KruschStack MCP server over stdio
 *   - `doctor` : Run end-to-end health checks across all 10 stack pillars
 *   - `route`  : Classify a task prompt via the <25us L1-L3 Cascade Router
 *   - `serve`  : Start the lightweight HTTP status & REST tool gateway (default port 3780, used by Docker)
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  VERSION,
  createKruschStack,
  createToolGraphEngine,
  writeIdeConfigs,
  runStackDoctor,
  runStackCrashRecoveryDrill
} from '../src/index.js';
import {
  runMcpServer,
  getStackTools,
  dispatchStackTool,
  assertPathWithinWorkspace
} from '../src/mcp/server.js';

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
    includeExtended:
      process.env.KRUSCH_STACK_INCLUDE_EXTENDED === '1' ||
      process.env.KRUSCH_STACK_INCLUDE_EXTENDED === 'true',
    json: false,
    crashDrill: false,
    ephemeral: false,
    port: Number(process.env.KRUSCH_STACK_PORT || 3780),
    workspaceRoot: process.env.KRUSCH_WORKSPACE_ROOT || process.cwd()
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--profile' && argv[i + 1]) {
      flags.profile = argv[++i];
    } else if (arg.startsWith('--profile=')) {
      flags.profile = arg.slice('--profile='.length);
    } else if (arg === '--mode' && argv[i + 1]) {
      flags.mode = argv[++i];
    } else if (arg.startsWith('--mode=')) {
      flags.mode = arg.slice('--mode='.length);
    } else if (arg === '--modular') {
      flags.mode = 'modular';
    } else if (arg === '--unified') {
      flags.mode = 'unified';
    } else if (arg === '--ide' && argv[i + 1]) {
      flags.ide = argv[++i];
    } else if (arg.startsWith('--ide=')) {
      flags.ide = arg.slice('--ide='.length);
    } else if (arg === '--components' && argv[i + 1]) {
      flags.components = argv[++i];
    } else if (arg.startsWith('--components=')) {
      flags.components = arg.slice('--components='.length);
    } else if (arg === '--server' && argv[i + 1]) {
      flags.server = argv[++i];
    } else if (arg.startsWith('--server=')) {
      flags.server = arg.slice('--server='.length);
    } else if (arg === '--defer-tools') {
      flags.deferTools = true;
    } else if (arg === '--no-defer-tools') {
      flags.deferTools = false;
    } else if (arg === '--include-extended') {
      flags.includeExtended = true;
    } else if (arg === '--no-include-extended') {
      flags.includeExtended = false;
    } else if (arg === '--workspace' && argv[i + 1]) {
      flags.workspaceRoot = path.resolve(argv[++i]);
    } else if (arg.startsWith('--workspace=')) {
      flags.workspaceRoot = path.resolve(arg.slice('--workspace='.length));
    } else if (arg === '--port' && argv[i + 1]) {
      flags.port = Number(argv[++i]);
    } else if (arg.startsWith('--port=')) {
      flags.port = Number(arg.slice('--port='.length));
    } else if (arg === '--json') {
      flags.json = true;
    } else if (arg === '--crash-drill') {
      flags.crashDrill = true;
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
KruschStack v${VERSION}: The Unified Sovereign AI & Coding Agent Stack

Usage:
  npx krusch-stack <command> [options]

Commands:
  init                Configure IDE MCP files (.mcp.json, .cursor/mcp.json, Windsurf, Antigravity) & .agent/AGENTS.md
  mcp                 Start the KruschStack MCP server over stdio (default)
  doctor              Verify Node 22 SQLite (21 tables), companion Postgres config, Ollama, and all 10 stack pillars
  route "<prompt>"    Classify a coding or reasoning prompt via the <25us L1-L3 Cascade Router
  serve               Start the HTTP status & REST tool gateway (default :3780)

Options:
  --profile <full|core>     Select 'full' (39 unified tools) or 'core' (Tiers 1-3 + Router, 27 tools)
  --defer-tools             Collapse wide tool catalog into 6 pinned tools + 3 BM25 bridge tools
  --include-extended        Include the 23 modular extension tools (hydrascope, brick-exchange, grounded-harness)
  --mode <unified|modular>  Register a single 'krusch-stack' MCP entry or separate per-pillar MCP entries
  --ide <all|claude|cursor|windsurf|antigravity>
  --components <csv>        Comma-separated subset (context,git,fs,hydrascope,brick-exchange,harness,grounded-harness,frontend,workspace,router)
  --server <name>           Run as a specific pillar server (e.g. krusch-context-mcp, hydrascope, krusch-brick-exchange, krusch-grounded-harness)
  --crash-drill             Run the 2-process SIGKILL write-ahead journal rollback drill during 'doctor'
  --port <number>           HTTP port for 'serve' (default: 3780)
  --ephemeral               Use in-memory SQLite (:memory:)
  --json                    Emit raw JSON output
`);
}

function extractHostnameFromHostHeader(rawHostHeader) {
  const host = String(rawHostHeader || '').trim().toLowerCase();
  if (!host) return '';
  if (host.startsWith('[')) {
    const closeBracket = host.indexOf(']');
    if (closeBracket === -1) return '';
    const remainder = host.slice(closeBracket + 1);
    if (!/^(?::\d{1,5})?$/.test(remainder)) return '';
    return host.slice(0, closeBracket + 1);
  }
  const colonIdx = host.indexOf(':');
  if (colonIdx !== -1 && host.indexOf(':', colonIdx + 1) === -1) {
    const portSuffix = host.slice(colonIdx + 1);
    if (!/^\d{1,5}$/.test(portSuffix)) return '';
    return host.slice(0, colonIdx);
  }
  return host;
}

/**
 * Start the lightweight HTTP status & REST gateway (for Docker and health checks).
 */
export function startHttpGateway(options = {}) {
  const rawPort =
    options.port !== undefined && options.port !== null && options.port !== ''
      ? options.port
      : process.env.KRUSCH_STACK_PORT !== undefined && process.env.KRUSCH_STACK_PORT !== ''
        ? process.env.KRUSCH_STACK_PORT
        : 3780;
  const port = Number(rawPort);
  const bindHost = options.host || process.env.KRUSCH_STACK_HOST || '127.0.0.1';
  const stack = options.stack || createKruschStack(options);
  const includeExtended = Boolean(options.includeExtended);
  const deferTools = Boolean(options.deferTools);

  const allowedHosts = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
  if (bindHost && bindHost !== '0.0.0.0' && bindHost !== '::') {
    const cleanBind = bindHost.toLowerCase();
    allowedHosts.add(cleanBind);
    if (cleanBind.includes(':') && !cleanBind.startsWith('[')) {
      allowedHosts.add(`[${cleanBind}]`);
    }
  }
  const extraAllowed = String(options.allowedHosts ?? process.env.KRUSCH_ALLOWED_HOSTS ?? '')
    .split(',')
    .map((h) => extractHostnameFromHostHeader(h))
    .filter(Boolean);
  for (const h of extraAllowed) {
    allowedHosts.add(h);
  }

  const configuredToken = String(
    options.apiToken ?? process.env.KRUSCH_STACK_API_TOKEN ?? ''
  ).trim();
  const configuredTokenDigest = configuredToken
    ? crypto.createHash('sha256').update(configuredToken, 'utf8').digest()
    : null;

  const tools = getStackTools({
    profile: stack.profile,
    components: options.components,
    server: options.server,
    deferTools,
    includeExtended
  });
  const gatewayRawTools = getStackTools({
    profile: stack.profile,
    components: options.components,
    server: options.server,
    deferTools: false,
    includeExtended
  });

  const gatewayToolGraph =
    options.toolGraph ||
    createToolGraphEngine(gatewayRawTools, {
      dispatcher: (toolName, toolArgs) =>
        dispatchStackTool(stack, toolName, toolArgs, {
          profile: stack.profile,
          components: options.components,
          server: options.server,
          deferTools: false,
          includeExtended,
          enforceProfile: true,
          httpBoundary: true
        })
    });

  const server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');

    // SEC-01: Enforce Host header allowlist against browser DNS-rebinding attacks.
    const parsedHost = extractHostnameFromHostHeader(req.headers.host);
    const bareParsedHost =
      parsedHost.startsWith('[') && parsedHost.endsWith(']')
        ? parsedHost.slice(1, -1)
        : parsedHost;
    if (!parsedHost || (!allowedHosts.has(parsedHost) && !allowedHosts.has(bareParsedHost))) {
      res.writeHead(403);
      res.end(
        JSON.stringify(
          {
            ok: false,
            tool: 'krusch_http_gateway',
            summary: 'Blocked unrecognized Host header',
            error: 'DNS_REBINDING_BLOCKED'
          },
          null,
          2
        )
      );
      return;
    }

    // SEC-01: Block cross-site / cross-origin browser CSRF requests.
    if (String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') {
      res.writeHead(403);
      res.end(
        JSON.stringify(
          {
            ok: false,
            tool: 'krusch_http_gateway',
            summary: 'Cross-site browser requests are forbidden',
            error: 'CROSS_ORIGIN_BLOCKED'
          },
          null,
          2
        )
      );
      return;
    }
    if (req.headers.origin) {
      let originAllowed = false;
      try {
        const originUrl = new URL(String(req.headers.origin));
        const originHost = originUrl.hostname.toLowerCase();
        originAllowed = allowedHosts.has(originHost);
      } catch {
        originAllowed = false;
      }
      if (!originAllowed) {
        res.writeHead(403);
        res.end(
          JSON.stringify(
            {
              ok: false,
              tool: 'krusch_http_gateway',
              summary: 'Cross-origin browser requests are forbidden',
              error: 'CROSS_ORIGIN_BLOCKED'
            },
            null,
            2
          )
        );
        return;
      }
    }

    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      const report = stack.doctor();
      res.writeHead(report.ok ? 200 : 503);
      res.end(JSON.stringify({
        ok: report.ok,
        name: 'krusch-stack',
        version: VERSION,
        profile: stack.profile,
        defer_tools: deferTools,
        tools_count: tools.length,
        doctor: report.data
      }, null, 2));
      return;
    }

    // SEC-01: Enforce optional constant-time Bearer authentication when KRUSCH_STACK_API_TOKEN is set.
    if (configuredTokenDigest) {
      const authHeader = String(req.headers.authorization || '');
      const provided = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
      const providedDigest = crypto.createHash('sha256').update(provided, 'utf8').digest();
      if (!provided || !crypto.timingSafeEqual(providedDigest, configuredTokenDigest)) {
        res.writeHead(401, { 'WWW-Authenticate': 'Bearer realm="krusch-stack"' });
        res.end(
          JSON.stringify(
            {
              ok: false,
              tool: 'krusch_http_gateway',
              summary: 'Valid Bearer token required',
              error: 'UNAUTHORIZED'
            },
            null,
            2
          )
        );
        return;
      }
    }

    if (req.method === 'GET' && url.pathname === '/tools') {
      res.writeHead(200);
      res.end(JSON.stringify({ ok: true, count: tools.length, tools }, null, 2));
      return;
    }

    // SEC-01: Require Content-Type: application/json on POST routes to block HTML form CSRF.
    if (req.method === 'POST') {
      const contentType = String(req.headers['content-type'] || '').trim().toLowerCase();
      if (!contentType.startsWith('application/json')) {
        req.resume();
        res.writeHead(415);
        res.end(
          JSON.stringify(
            {
              ok: false,
              tool: 'krusch_http_gateway',
              summary: 'POST requests require Content-Type: application/json',
              error: 'UNSUPPORTED_MEDIA_TYPE'
            },
            null,
            2
          )
        );
        return;
      }
    }

    const maxBodyBytes = Math.max(
      1024,
      Number(options.maxBodyBytes || process.env.KRUSCH_MAX_BODY_BYTES || 2 * 1024 * 1024)
    );

    const readBoundedJson = () =>
      new Promise((resolve, reject) => {
        const hardDestroyCap = maxBodyBytes + 65536;
        const declaredLen = Number(req.headers['content-length'] || 0);
        if (Number.isFinite(declaredLen) && declaredLen > maxBodyBytes) {
          const err = new Error(`Payload Too Large: exceeds ${maxBodyBytes} byte limit`);
          err.statusCode = 413;
          err.hardDestroy = declaredLen > hardDestroyCap;
          let drained = 0;
          req.on('data', (chunk) => {
            drained += Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
            if (drained > hardDestroyCap && !req.destroyed) {
              req.destroy();
            }
          });
          req.resume();
          reject(err);
          return;
        }
        const chunks = [];
        let totalBytes = 0;
        let settled = false;
        req.on('data', (chunk) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
          totalBytes += buf.length;
          if (settled) {
            if (totalBytes > hardDestroyCap && !req.destroyed) {
              req.destroy();
            }
            return;
          }
          if (totalBytes > maxBodyBytes) {
            settled = true;
            const err = new Error(`Payload Too Large: exceeds ${maxBodyBytes} byte limit`);
            err.statusCode = 413;
            err.hardDestroy = totalBytes > hardDestroyCap;
            req.resume();
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
          if (err?.hardDestroy) {
            req.destroy();
          } else {
            const cleanupTimer = setTimeout(() => {
              if (!req.complete && !req.destroyed) req.destroy();
            }, 250);
            cleanupTimer.unref?.();
          }
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
            {
              profile: stack.profile,
              components: options.components,
              server: options.server,
              deferTools,
              includeExtended,
              enforceProfile: true,
              httpBoundary: true
            }
          );
          const code =
            result?.data?.code ||
            result?.data?.result?.data?.code ||
            result?.error?.code ||
            '';
          const status = result.ok
            ? 200
            : code === 'PATH_OUTSIDE_WORKSPACE' || code === 'TOOL_NOT_ENABLED'
              ? 403
              : 400;
          res.writeHead(status);
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
            'hitl-draft': () => stack.resilience.draftHitlGate({ ...parsed, nowMs: Date.now() }),
            'hitl-resolve': () =>
              stack.resilience.resolveHitlGate({
                gateId: parsed.gateId,
                decision: parsed.decision,
                reviewer: parsed.reviewer,
                reason: parsed.reason,
                nowMs: Date.now(),
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

    if (req.method === 'POST' && url.pathname.startsWith('/action-harness/')) {
      const action = url.pathname.slice('/action-harness/'.length);
      readBoundedJson()
        .then(({ parsed }) => {
          const actionMap = {
            start: () => stack.actionHarness.startSession(parsed),
            intercept: () => stack.actionHarness.interceptToolCall(parsed),
            outcome: () => stack.actionHarness.recordToolOutcome(parsed),
            'verify-stop': () => stack.actionHarness.verifyStop(parsed),
            summary: () => stack.actionHarness.sessionSummary(parsed)
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown action-harness action: ${action}` }));
            return;
          }
          const result = handler();
          res.writeHead(result.ok ? 200 : 400);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    if (req.method === 'POST' && url.pathname.startsWith('/grounded-harness/')) {
      const action = url.pathname.slice('/grounded-harness/'.length);
      readBoundedJson()
        .then(async ({ parsed }) => {
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            res.writeHead(400);
            res.end(JSON.stringify({ ok: false, error: 'Request JSON body must be a plain object' }));
            return;
          }
          // SEC-02: Enforce workspaceRoot containment on workspaceDir / workspace_dir over HTTP and assign canonical path.
          for (const dirKey of ['workspaceDir', 'workspace_dir']) {
            if (typeof parsed[dirKey] === 'string' && parsed[dirKey].trim()) {
              try {
                parsed[dirKey] = assertPathWithinWorkspace(parsed[dirKey], stack.workspaceRoot);
              } catch (pathErr) {
                res.writeHead(403);
                res.end(
                  JSON.stringify(
                    {
                      ok: false,
                      tool: `krusch_grounded_${action}`,
                      summary: pathErr.message,
                      error: { code: 'PATH_OUTSIDE_WORKSPACE', message: pathErr.message }
                    },
                    null,
                    2
                  )
                );
                return;
              }
            }
          }
          const actionMap = {
            'scale-profile': () => stack.groundedHarness.resolveScale(parsed),
            ground: () => stack.groundedHarness.groundWorkspace(parsed),
            'ground-and-start': () => stack.groundedHarness.groundAndStartSession(parsed),
            'evaluate-turn': () => stack.groundedHarness.evaluateTurn(parsed),
            start: () => stack.groundedHarness.startSession(parsed),
            intercept: () => stack.groundedHarness.interceptToolCall(parsed),
            outcome: () => stack.groundedHarness.recordToolOutcome(parsed),
            'verify-stop': () => stack.groundedHarness.verifyStop(parsed),
            summary: () => stack.groundedHarness.sessionSummary(parsed)
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown grounded-harness action: ${action}` }));
            return;
          }
          const result = await handler();
          res.writeHead(result.ok ? 200 : 400);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    if (req.method === 'POST' && url.pathname.startsWith('/brick-exchange/')) {
      const action = url.pathname.slice('/brick-exchange/'.length);
      readBoundedJson()
        .then(async ({ parsed }) => {
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            res.writeHead(400);
            res.end(JSON.stringify({ ok: false, error: 'Request JSON body must be a plain object' }));
            return;
          }

          // SEC-03: Block arbitrary inline invariantScript execution over HTTP gateway!
          if (
            action === 'verify-blast-radius' &&
            parsed.invariantScript !== undefined &&
            parsed.invariantScript !== null &&
            parsed.invariantScript !== ''
          ) {
            res.writeHead(403);
            res.end(
              JSON.stringify(
                {
                  ok: false,
                  tool: 'krusch_brick_verify_blast_radius',
                  summary: 'Inline invariantScript execution is forbidden over HTTP',
                  error: {
                    code: 'HTTP_INVARIANT_SCRIPT_FORBIDDEN',
                    message:
                      'Inline invariantScript execution is forbidden over HTTP; use programmatic verifyBlastRadius or CLI'
                  }
                },
                null,
                2
              )
            );
            return;
          }

          // SEC-03: Strip internal/callback/clock keys & prototype-pollution keys from untrusted HTTP JSON bodies!
          const strippedKeys = new Set([
            'authorizedBricks',
            'tryBrickFn',
            'getAuthorizedBricksFn',
            'invariantScript',
            'repairFn',
            'assertFn',
            'nowMs',
            '__proto__',
            'constructor',
            'prototype'
          ]);
          const httpPayload = {};
          for (const key of Object.keys(parsed)) {
            if (strippedKeys.has(key)) continue;
            Object.defineProperty(httpPayload, key, {
              value: parsed[key],
              enumerable: true,
              writable: true,
              configurable: true
            });
          }

          // SEC-02: Enforce workspaceRoot containment on repoDir / repoRoot / targetRepoDir over HTTP and assign canonical path.
          for (const repoKey of ['targetRepoDir', 'repoDir', 'repoRoot']) {
            if (typeof httpPayload[repoKey] === 'string' && httpPayload[repoKey].trim()) {
              try {
                httpPayload[repoKey] = assertPathWithinWorkspace(
                  httpPayload[repoKey],
                  stack.workspaceRoot
                );
              } catch (pathErr) {
                res.writeHead(403);
                res.end(
                  JSON.stringify(
                    {
                      ok: false,
                      tool: `krusch_brick_${action}`,
                      summary: pathErr.message,
                      error: { code: 'PATH_OUTSIDE_WORKSPACE', message: pathErr.message }
                    },
                    null,
                    2
                  )
                );
                return;
              }
            }
          }

          // SEC-03: Require viewerId on ontology-compose so HTTP callers must authenticate against listInbox grants!
          if (action === 'ontology-compose') {
            const rawViewerId =
              typeof httpPayload.viewerId === 'string' ? httpPayload.viewerId.trim() : '';
            if (!rawViewerId) {
              res.writeHead(401);
              res.end(
                JSON.stringify(
                  {
                    ok: false,
                    tool: 'krusch_brick_ontology_compose',
                    summary: 'viewerId is required on POST /brick-exchange/ontology-compose',
                    error: {
                      code: 'VIEWER_AUTH_REQUIRED',
                      message:
                        'Authenticated viewerId is required on POST /brick-exchange/ontology-compose'
                    }
                  },
                  null,
                  2
                )
              );
              return;
            }
            if (
              strippedKeys.has(rawViewerId) ||
              rawViewerId.includes('..') ||
              !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(rawViewerId)
            ) {
              res.writeHead(403);
              res.end(
                JSON.stringify(
                  {
                    ok: false,
                    tool: 'krusch_brick_ontology_compose',
                    summary: 'Invalid or forbidden viewerId on POST /brick-exchange/ontology-compose',
                    error: {
                      code: 'VIEWER_FORBIDDEN',
                      message: 'viewerId must be a valid safe identifier'
                    }
                  },
                  null,
                  2
                )
              );
              return;
            }
          }

          const actionMap = {
            keygen: () => (stack.brickExchange.keygen ? stack.brickExchange.keygen() : stack.brickExchange.stats()),
            seal: () => stack.brickExchange.sealBrick(httpPayload),
            verify: () => stack.brickExchange.verifyBrick(httpPayload),
            publish: () => stack.brickExchange.publishBrick(httpPayload),
            grant: () => stack.brickExchange.issueGrant(httpPayload),
            revoke: () => stack.brickExchange.revokeGrant(httpPayload),
            inbox: () => stack.brickExchange.listInbox(httpPayload),
            try: () => stack.brickExchange.tryBrick(httpPayload),
            adopt: () => stack.brickExchange.adoptBrick(httpPayload),
            'audit-locks': () => stack.brickExchange.auditBrickLocks(httpPayload),
            'blast-radius': () => stack.brickExchange.analyzeBlastRadius(httpPayload),
            fanout: () => stack.brickExchange.planFanOut(httpPayload),
            'verify-blast-radius': () => stack.brickExchange.verifyBlastRadius(httpPayload),
            'ontology-inspect': () => stack.brickExchange.inspectOntology(httpPayload),
            'ontology-check': () => stack.brickExchange.checkOntologyCompatibility(httpPayload),
            'ontology-compose': () => stack.brickExchange.composeCrossStack(httpPayload),
            'ontology-bind': () => stack.brickExchange.synthesizeBinding(httpPayload),
            stats: () => stack.brickExchange.stats()
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown brick-exchange action: ${action}` }));
            return;
          }
          const result = await handler();
          const errCode = result?.error?.code || '';
          const status = result.ok
            ? 200
            : errCode === 'VIEWER_AUTH_REQUIRED' || errCode === 'INVALID_VIEWER'
              ? 401
              : errCode === 'GRANT_ISSUER_FORBIDDEN' ||
                  errCode === 'GRANT_REVOKE_FORBIDDEN' ||
                  errCode === 'VIEWER_FORBIDDEN' ||
                  errCode === 'HTTP_INVARIANT_SCRIPT_FORBIDDEN' ||
                  errCode === 'PATH_OUTSIDE_WORKSPACE'
                ? 403
                : 400;
          res.writeHead(status);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    if (req.method === 'POST' && url.pathname.startsWith('/hydrascope/')) {
      const action = url.pathname.slice('/hydrascope/'.length);
      readBoundedJson()
        .then(async ({ parsed }) => {
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            res.writeHead(400);
            res.end(JSON.stringify({ ok: false, error: 'Request JSON body must be a plain object' }));
            return;
          }
          const safeBody = {};
          for (const key of Object.keys(parsed)) {
            if (
              key === '__proto__' ||
              key === 'constructor' ||
              key === 'prototype' ||
              key === 'allowExternalPaths' ||
              key === 'authorizedBricks' ||
              key === 'nowMs'
            ) {
              continue;
            }
            Object.defineProperty(safeBody, key, {
              value: parsed[key],
              enumerable: true,
              writable: true,
              configurable: true
            });
          }

          // SEC-03: Require authenticated viewerId over HTTP whenever 4-axis Brick Ontology hydration is requested!
          const requestsOntology = Boolean(
            safeBody.includeBrickOntology ||
              safeBody.targetStack ||
              safeBody.targetChannel ||
              (Array.isArray(safeBody.requiredPorts) && safeBody.requiredPorts.length > 0)
          );
          if (action === 'traverse' && requestsOntology) {
            const rawViewerId =
              typeof safeBody.viewerId === 'string' ? safeBody.viewerId.trim() : '';
            if (!rawViewerId) {
              res.writeHead(401);
              res.end(
                JSON.stringify(
                  {
                    ok: false,
                    tool: 'hydrascope_traverse_context',
                    summary: 'viewerId is required on POST /hydrascope/traverse when brick ontology is requested',
                    error: {
                      code: 'VIEWER_AUTH_REQUIRED',
                      message:
                        'Authenticated viewerId is required on POST /hydrascope/traverse when includeBrickOntology or 4-axis filters are set'
                    }
                  },
                  null,
                  2
                )
              );
              return;
            }
            if (
              rawViewerId.includes('..') ||
              !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(rawViewerId)
            ) {
              res.writeHead(403);
              res.end(
                JSON.stringify(
                  {
                    ok: false,
                    tool: 'hydrascope_traverse_context',
                    summary: 'Invalid or forbidden viewerId on POST /hydrascope/traverse',
                    error: {
                      code: 'VIEWER_FORBIDDEN',
                      message: 'viewerId must be a valid safe identifier'
                    }
                  },
                  null,
                  2
                )
              );
              return;
            }
          }

          const actionMap = {
            state: () => stack.hydrascope.getState(),
            traverse: () => stack.hydrascope.traverseContext(safeBody),
            'check-answerable': () => stack.hydrascope.checkAnswerable(safeBody),
            compare: () => stack.hydrascope.compareVectorVsGraph(safeBody),
            benchmark: () => stack.hydrascope.runBenchmark(),
            supersede: () => stack.hydrascope.supersedeDecision(safeBody),
            ingest: () => {
              if (typeof safeBody.targetDir === 'string' && safeBody.targetDir.trim()) {
                try {
                  safeBody.targetDir = assertPathWithinWorkspace(
                    safeBody.targetDir,
                    stack.workspaceRoot,
                    { allowReset: true }
                  );
                } catch (pathErr) {
                  return {
                    ok: false,
                    tool: 'hydrascope_ingest_directory',
                    summary: pathErr.message,
                    error: { code: 'PATH_OUTSIDE_WORKSPACE', message: pathErr.message }
                  };
                }
              }
              return stack.hydrascope.ingestDirectory({ ...safeBody, allowExternalPaths: false });
            }
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown hydrascope action: ${action}` }));
            return;
          }
          const result = await handler();
          const errCode = result?.error?.code || '';
          const status = result.ok
            ? 200
            : errCode === 'VIEWER_AUTH_REQUIRED'
              ? 401
              : errCode === 'PATH_OUTSIDE_WORKSPACE' || errCode === 'VIEWER_FORBIDDEN'
                ? 403
                : 400;
          res.writeHead(status);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    if (req.method === 'POST' && url.pathname.startsWith('/tool-graph/')) {
      const action = url.pathname.slice('/tool-graph/'.length);
      readBoundedJson()
        .then(async ({ parsed }) => {
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            res.writeHead(400);
            res.end(JSON.stringify({ ok: false, error: 'Request JSON body must be a plain object' }));
            return;
          }
          const actionMap = {
            find: () => gatewayToolGraph.findTools(parsed),
            describe: () => gatewayToolGraph.describeTool(parsed),
            call: () =>
              gatewayToolGraph.callTool(
                parsed.name || parsed.tool_name || parsed.tool || '',
                parsed.arguments || parsed.args || {}
              ),
            outcome: () => gatewayToolGraph.reportOutcome(parsed),
            reset: () => gatewayToolGraph.resetState(),
            stats: () => ({
              ok: true,
              tool: 'krusch_tool_graph_stats',
              summary: 'Retrieved Sovereign ToolGraph telemetry',
              data: gatewayToolGraph.getStats()
            })
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown tool-graph action: ${action}` }));
            return;
          }
          const result = await handler();
          const code =
            result?.data?.code ||
            result?.data?.result?.data?.code ||
            result?.error?.code ||
            '';
          const status = result.ok
            ? 200
            : code === 'PATH_OUTSIDE_WORKSPACE' || code === 'TOOL_NOT_ENABLED'
              ? 403
              : 400;
          res.writeHead(status);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    if (req.method === 'POST' && url.pathname.startsWith('/polyglot-audit/')) {
      const action = url.pathname.slice('/polyglot-audit/'.length);
      readBoundedJson()
        .then(async ({ parsed }) => {
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            res.writeHead(400);
            res.end(JSON.stringify({ ok: false, error: 'Request JSON body must be a plain object' }));
            return;
          }
          if (action === 'repository') {
            const relTarget = typeof parsed.targetDir === 'string' && parsed.targetDir.trim() ? parsed.targetDir.trim() : '.';
            let realTarget;
            try {
              const contained = assertPathWithinWorkspace(relTarget, stack.workspaceRoot);
              if (!fs.existsSync(contained)) {
                res.writeHead(400);
                res.end(JSON.stringify({ ok: false, error: 'Target directory does not exist' }));
                return;
              }
              realTarget = fs.realpathSync(contained);
            } catch (pathErr) {
              res.writeHead(403);
              res.end(JSON.stringify({ ok: false, error: pathErr.message || 'Repository path outside workspaceRoot is forbidden over HTTP' }));
              return;
            }
            const repoRes = stack.polyglotAudit.auditRepository(realTarget);
            res.writeHead(repoRes.ok ? 200 : 400);
            res.end(JSON.stringify(repoRes, null, 2));
            return;
          }
          const actionMap = {
            source: () => stack.polyglotAudit.auditSource(parsed.source || '', parsed.filePath || ''),
            'normalize-repo': () => {
              const resNorm = stack.polyglotAudit.normalizeRepoInput(parsed.input || parsed.repo || '');
              if (resNorm && typeof resNorm.ok === 'boolean' && resNorm.tool) {
                return resNorm;
              }
              const valid = Boolean(!resNorm.isRemoteCandidate || resNorm.cleanHttpsUrl);
              return {
                ok: valid,
                tool: 'krusch_polyglot_normalize_repo',
                summary: valid ? 'Normalized repository input' : 'Rejected untrusted remote repository URL',
                data: resNorm
              };
            },
            'score-coverage': () =>
              stack.polyglotAudit.scoreCoverage(
                parsed.files && typeof parsed.files === 'object' ? parsed.files : []
              )
          };
          const handler = actionMap[action];
          if (!handler) {
            res.writeHead(404);
            res.end(JSON.stringify({ ok: false, error: `Unknown polyglot-audit action: ${action}` }));
            return;
          }
          const result = await handler();
          res.writeHead(result.ok ? 200 : 400);
          res.end(JSON.stringify(result, null, 2));
        })
        .catch(sendGatewayError);
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ ok: false, error: 'Not Found' }));
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, bindHost, () => {
      const addr = server.address();
      const boundPort = addr && typeof addr === 'object' ? addr.port : port;
      resolve({ server, port: boundPort, host: bindHost, stack });
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
      profile: flags.profile,
      deferTools: flags.deferTools,
      includeExtended: flags.includeExtended
    });
    const docRes = stack.doctor();
    const activeToolCount = getStackTools({
      profile: flags.profile,
      deferTools: flags.deferTools,
      includeExtended: flags.includeExtended || flags.mode === 'modular'
    }).length;
    if (flags.json) {
      console.log(JSON.stringify({ ok: true, init: ideRes.data, doctor: docRes.data }, null, 2));
    } else {
      console.log(`\n🚀 KruschStack v${VERSION} initialized in ${flags.workspaceRoot}`);
      console.log(`   Profile : ${flags.profile} (${activeToolCount} MCP tools)`);
      console.log(`   Mode    : ${flags.mode}`);
      console.log(`   Files   : ${(ideRes.data.files_written || []).join(', ')}`);
      console.log(`   SQLite  : Ready (${docRes.data.components.length} active pillars)\n`);
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
    const drillReport = flags.crashDrill ? await runStackCrashRecoveryDrill() : null;
    if (drillReport) {
      report.data.crash_drill = drillReport.data;
      if (!drillReport.ok) {
        report.ok = false;
      }
    }
    if (flags.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`\n🩺 KruschStack Doctor (v${VERSION})`);
      console.log(`   Summary  : ${report.summary}`);
      console.log(`   Node.js  : ${report.data.node_version} (supported: ${report.data.node_supported})`);
      console.log(`   SQLite   : ${report.data.sqlite_ready ? 'READY' : 'FAILED'} (${report.data.storage_engine || 'node:sqlite'})`);
      console.log(`   Postgres : ${report.data.postgres_configured ? 'Companion URL set (runtime uses node:sqlite)' : 'Not set (using zero-setup SQLite)'}`);
      console.log(`   Ollama   : ${report.data.ollama_host}`);
      if (drillReport) {
        console.log(`   SIGKILL  : ${drillReport.ok ? 'CONVERGED' : 'FAILED'} (${drillReport.summary})`);
      }
      console.log(`\n   Active Pillars (${report.data.profile} profile):`);
      for (const comp of report.data.components) {
        console.log(`     ✓ [${comp.tier}] ${comp.name}: ${comp.description}`);
      }
      console.log('');
    }
    if (!report.ok) {
      process.exitCode = 1;
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
    const { port, host } = await startHttpGateway({
      workspaceRoot: flags.workspaceRoot,
      profile: flags.profile,
      components: flags.components,
      server: flags.server,
      deferTools: flags.deferTools,
      includeExtended: flags.includeExtended,
      ephemeral: flags.ephemeral,
      port: flags.port
    });
    console.log(`🌐 KruschStack HTTP & Tool Gateway listening on http://${host}:${port}`);
    return;
  }

  // Default: start stdio MCP server
  await runMcpServer({
    workspaceRoot: flags.workspaceRoot,
    profile: flags.profile,
    components: flags.components,
    server: flags.server,
    deferTools: flags.deferTools,
    includeExtended: flags.includeExtended,
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
