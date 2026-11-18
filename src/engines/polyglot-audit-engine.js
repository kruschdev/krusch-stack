/**
 * @module engines/polyglot-audit-engine
 * Self-contained, zero-dependency polyglot brownfield security, Slop-Breaker & Lego coverage
 * scanner across 10 languages / 14 extensions (JS, TS, Python, PHP, Java, C#, Go, Ruby, Rust,
 * Kotlin) plus SSRF-safe GitHub repository input normalizer for KruschStack.
 *
 * Enforces INV-STACK-01 (zero external npm dependencies, Node 22 built-ins only),
 * INV-STACK-02 (deterministic okEnvelope return contract), and INV-STACK-04 (sanitized
 * public defaults with zero private network literals, hostnames, or OS user home paths).
 *
 * Combines all 16 JS/TS/Python Slop-Breaker detectors (`SLOP_BREAKER_RULES`) with all 12
 * PHP & polyglot enterprise hazard detectors (`POLYGLOT_HAZARD_RULES`) = 28 deterministic rules.
 */

import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

/**
 * Build a deterministic `INV-LEGO-01` / `INV-STACK-02` error envelope.
 *
 * @param {string} code
 * @param {string} message
 * @param {unknown} [details=null]
 * @param {string} [tool='polyglot.audit']
 * @returns {{ ok: false, tool: string, summary: string, error: { code: string, message: string, details?: unknown } }}
 */
function errorEnvelope(code, message, details = null, tool = 'polyglot.audit') {
  return {
    ok: false,
    tool: String(tool || 'polyglot.audit'),
    summary: String(message || code || 'Request failed'),
    error: {
      code: String(code || 'INTERNAL_ERROR'),
      message: String(message || 'Request failed'),
      ...(details !== null && details !== undefined ? { details } : {})
    }
  };
}

const TK_NS = `@${'krusch'}/toolkit`;
const PY_TK_NS = 'krusch_toolkit';

/**
 * Frozen metadata registry of the 16 JS/TS/Python Slop-Breaker rules.
 */
export const SLOP_BREAKER_RULES = Object.freeze([
  Object.freeze({
    ruleId: 'raw-mcp-stdio',
    brickId: 'mcp',
    importPath: `${TK_NS}/mcp`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Hand-rolled MCP Server + StdioServerTransport without 4-boolean annotations.'
  }),
  Object.freeze({
    ruleId: 'manual-sse-headers',
    brickId: 'streaming',
    importPath: `${TK_NS}/streaming`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript', 'python']),
    description: 'Manual text/event-stream SSE headers lacking AbortController or heartbeat cleanup.'
  }),
  Object.freeze({
    ruleId: 'raw-pg-pool',
    brickId: 'pg',
    importPath: `${TK_NS}/pg`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Raw pg.Pool instantiation without idle error listeners or dimension-checked pgvector search.'
  }),
  Object.freeze({
    ruleId: 'raw-sqlite-database',
    brickId: 'db',
    importPath: `${TK_NS}/db`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Raw better-sqlite3 Database instantiation missing WAL pragmas or corruption guards.'
  }),
  Object.freeze({
    ruleId: 'raw-fastapi-boilerplate',
    brickId: 'fastapi_app',
    importPath: `${PY_TK_NS}.fastapi_app`,
    severity: 'warn',
    languages: Object.freeze(['python']),
    description: 'Hand-rolled FastAPI CORSMiddleware + /health route boilerplate.'
  }),
  Object.freeze({
    ruleId: 'unaborted-useeffect-fetch',
    brickId: 'react',
    importPath: `${TK_NS}/react`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Un-aborted fetch() inside React useEffect without AbortController signal.'
  }),
  Object.freeze({
    ruleId: 'raw-webhook-hmac',
    brickId: 'webhooks',
    importPath: `${TK_NS}/webhooks`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Hand-rolled webhook HMAC verification risking timing side-channels or replay.'
  }),
  Object.freeze({
    ruleId: 'raw-node-sqlite',
    brickId: 'sqlite',
    importPath: `${TK_NS}/sqlite`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Raw node:sqlite DatabaseSync instantiation without WAL/busy_timeout pragmas.'
  }),
  Object.freeze({
    ruleId: 'raw-multer-upload',
    brickId: 'upload',
    importPath: `${TK_NS}/upload`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Raw multer() upload middleware lacking magic-byte MIME verification.'
  }),
  Object.freeze({
    ruleId: 'unsafe-yaml-load',
    brickId: 'yaml',
    importPath: `${TK_NS}/yaml`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript', 'python']),
    description: 'Unsafe js-yaml or PyYAML load() vulnerable to arbitrary tags or alias bombs.'
  }),
  Object.freeze({
    ruleId: 'raw-idempotency-key',
    brickId: 'idempotency',
    importPath: `${TK_NS}/idempotency`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Hand-rolled Idempotency-Key request handling lacking atomic in-flight locks.'
  }),
  Object.freeze({
    ruleId: 'mutable-audit-ledger',
    brickId: 'audit-log',
    importPath: `${TK_NS}/audit-log`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Mutable enterprise SQL audit table or custom SHA-256 chain lacking immutability triggers.'
  }),
  Object.freeze({
    ruleId: 'raw-tenant-rbac',
    brickId: 'rbac',
    importPath: `${TK_NS}/rbac`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Hand-rolled multi-tenant IDOR or role check lacking deny-by-default precedence.'
  }),
  Object.freeze({
    ruleId: 'unsafe-pagination-cursor',
    brickId: 'pagination',
    importPath: `${TK_NS}/pagination`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Unsigned base64 pagination cursor or unclamped query/ORM limit/offset.'
  }),
  Object.freeze({
    ruleId: 'unvalidated-outbound-ssrf',
    brickId: 'security',
    importPath: `${TK_NS}/security`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript', 'python']),
    description: 'User-controlled outbound HTTP URL lacking DNS-pinned SSRF protection.'
  }),
  Object.freeze({
    ruleId: 'hardcoded-auth-secret-fallback',
    brickId: 'auth',
    importPath: `${TK_NS}/auth`,
    severity: 'warn',
    languages: Object.freeze(['javascript', 'typescript']),
    description: 'Hardcoded JWT, session, or cookie secret fallback in source.'
  })
]);

/**
 * Frozen metadata registry of the 12 PHP & polyglot enterprise hazard rules.
 */
export const POLYGLOT_HAZARD_RULES = Object.freeze([
  Object.freeze({
    ruleId: 'php-float-currency-math',
    brickId: 'audit-log',
    importPath: `${TK_NS}/audit-log`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Floating-point PHP currency rounding risking sub-cent batch drift.'
  }),
  Object.freeze({
    ruleId: 'php-raw-sql-interpolation',
    brickId: 'sqlite',
    importPath: `${TK_NS}/sqlite`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Interpolated PHP variable inside SQL statement risking SQL injection.'
  }),
  Object.freeze({
    ruleId: 'php-per-request-pdo-or-sql-leak',
    brickId: 'sqlite',
    importPath: `${TK_NS}/sqlite`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Per-request PHP DB connection or raw PDOException HTML echo.'
  }),
  Object.freeze({
    ruleId: 'php-unvalidated-superglobal-input',
    brickId: 'schema',
    importPath: `${TK_NS}/schema`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Untyped PHP $_POST/$_GET/$_REQUEST superglobal intake.'
  }),
  Object.freeze({
    ruleId: 'php-legacy-session-or-weak-crypto',
    brickId: 'auth',
    importPath: `${TK_NS}/auth`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Stateful PHP session_start() or weak/deprecated crypto (mcrypt/md5/sha1).'
  }),
  Object.freeze({
    ruleId: 'php-hardcoded-db-credentials',
    brickId: 'config',
    importPath: `${TK_NS}/config`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Hardcoded PHP database credentials in source.'
  }),
  Object.freeze({
    ruleId: 'php-unbounded-table-scan',
    brickId: 'pagination',
    importPath: `${TK_NS}/pagination`,
    severity: 'error',
    languages: Object.freeze(['php']),
    description: 'Unbounded SELECT * table scan without cursor limit.'
  }),
  Object.freeze({
    ruleId: 'polyglot-float-currency-math',
    brickId: 'audit-log',
    importPath: `${TK_NS}/audit-log`,
    severity: 'error',
    languages: Object.freeze(['java', 'csharp', 'go', 'ruby', 'rust', 'kotlin']),
    description: 'IEEE-754 float/double currency arithmetic risking sub-cent batch drift.'
  }),
  Object.freeze({
    ruleId: 'polyglot-raw-sql-concat',
    brickId: 'pg',
    importPath: `${TK_NS}/pg`,
    severity: 'error',
    languages: Object.freeze(['java', 'csharp', 'go', 'ruby', 'rust', 'kotlin']),
    description: 'Interpolated or concatenated SQL query string.'
  }),
  Object.freeze({
    ruleId: 'polyglot-unguarded-outbound-http',
    brickId: 'security',
    importPath: `${TK_NS}/security`,
    severity: 'error',
    languages: Object.freeze(['java', 'csharp', 'go', 'ruby', 'rust', 'kotlin']),
    description: 'Direct outbound HTTP client call without DNS-pinned SSRF protection.'
  }),
  Object.freeze({
    ruleId: 'polyglot-weak-crypto-digest',
    brickId: 'auth',
    importPath: `${TK_NS}/auth`,
    severity: 'error',
    languages: Object.freeze(['java', 'csharp', 'go', 'ruby', 'rust', 'kotlin']),
    description: 'Legacy MD5/SHA-1 cryptographic digest usage.'
  }),
  Object.freeze({
    ruleId: 'polyglot-unbounded-select-all',
    brickId: 'pagination',
    importPath: `${TK_NS}/pagination`,
    severity: 'error',
    languages: Object.freeze(['java', 'csharp', 'go', 'ruby', 'rust', 'kotlin']),
    description: 'Unbounded SELECT * query without cursor/limit pagination.'
  })
]);

const SEALED_BRICK_REGISTRY = Object.freeze([
  { id: 'http', importPath: `${TK_NS}/http` },
  { id: 'streaming', importPath: `${TK_NS}/streaming` },
  { id: 'mcp', importPath: `${TK_NS}/mcp` },
  { id: 'pg', importPath: `${TK_NS}/pg` },
  { id: 'db', importPath: `${TK_NS}/db` },
  { id: 'llm', importPath: `${TK_NS}/llm` },
  { id: 'embeddings', importPath: `${TK_NS}/embeddings` },
  { id: 'raw-rag', importPath: `${TK_NS}/raw-rag` },
  { id: 'vision', importPath: `${TK_NS}/vision` },
  { id: 'decide', importPath: `${TK_NS}/decide` },
  { id: 'auth', importPath: `${TK_NS}/auth` },
  { id: 'config', importPath: `${TK_NS}/config` },
  { id: 'log', importPath: `${TK_NS}/log` },
  { id: 'react', importPath: `${TK_NS}/react` },
  { id: 'edge', importPath: `${TK_NS}/edge` },
  { id: 'webhooks', importPath: `${TK_NS}/webhooks` },
  { id: 'cli', importPath: `${TK_NS}/cli` },
  { id: 'sqlite', importPath: `${TK_NS}/sqlite` },
  { id: 'security', importPath: `${TK_NS}/security` },
  { id: 'lego-scout', importPath: `${TK_NS}/lego-scout` },
  { id: 'schema', importPath: `${TK_NS}/schema` },
  { id: 'upload', importPath: `${TK_NS}/upload` },
  { id: 'cascade', importPath: `${TK_NS}/cascade` },
  { id: 'audio', importPath: `${TK_NS}/audio` },
  { id: 'yaml', importPath: `${TK_NS}/yaml` },
  { id: 'idempotency', importPath: `${TK_NS}/idempotency` },
  { id: 'audit-log', importPath: `${TK_NS}/audit-log` },
  { id: 'rbac', importPath: `${TK_NS}/rbac` },
  { id: 'pagination', importPath: `${TK_NS}/pagination` },
  { id: 'brick-exchange', importPath: `${TK_NS}/brick-exchange` },
  { id: 'tool-graph', importPath: `${TK_NS}/tool-graph` },
  { id: 'polyglot-audit', importPath: `${TK_NS}/polyglot-audit` },
  { id: 'harness-engineering', importPath: `${TK_NS}/harness-engineering` },
  { id: 'grounded-harness', importPath: `${TK_NS}/grounded-harness` },
  { id: 'fastapi_app', importPath: `${PY_TK_NS}.fastapi_app` },
  { id: 'python_mcp', importPath: `${PY_TK_NS}.mcp` },
  { id: 'python_pg', importPath: `${PY_TK_NS}.pg` },
  { id: 'python_security', importPath: `${PY_TK_NS}.security` },
  { id: 'python_schema', importPath: `${PY_TK_NS}.schema` },
  { id: 'python_upload', importPath: `${PY_TK_NS}.upload` },
  { id: 'python_http_client', importPath: `${PY_TK_NS}.http_client` },
  { id: 'python_streamlit_ui', importPath: `${PY_TK_NS}.streamlit_ui` },
  { id: 'python_yaml', importPath: `${PY_TK_NS}.yaml_loader` },
  { id: 'python_db_async', importPath: `${PY_TK_NS}.db_async` }
]);

const POLYGLOT_ONLY_EXTS = new Set(['.java', '.cs', '.go', '.rb', '.rs', '.kt']);
const JS_PY_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.py']);
const ALL_SCANNABLE_EXTS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.jsx',
  '.tsx',
  '.py',
  '.php',
  '.java',
  '.cs',
  '.go',
  '.rb',
  '.rs',
  '.kt'
]);

const SKIPPED_DIRS = new Set([
  '.git',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'target',
  'bin',
  'obj',
  'coverage',
  '.next',
  '.cache',
  '.gradle',
  '.mvn',
  '.venv',
  'venv',
  '__pycache__',
  '.krusch-stack'
]);

const SENSITIVE_LOCAL_PREFIXES = [
  '/etc',
  '/private/etc',
  '/root',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/var/run',
  '/private/var/run',
  '/run'
];

const EXACT_SENSITIVE_ROOTS = new Set(['/', '/home', '/Users']);
const SENSITIVE_SEGMENT_NAMES = new Set(['.ssh', '.gnupg', '.aws', '.kube', '.docker']);

const GITHUB_OWNER_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/;
const GITHUB_SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const RESERVED_GITHUB_ROOTS = new Set([
  'about',
  'codespaces',
  'collections',
  'customer-stories',
  'enterprise',
  'events',
  'explore',
  'features',
  'issues',
  'login',
  'marketplace',
  'new',
  'notifications',
  'organizations',
  'orgs',
  'pricing',
  'pulls',
  'search',
  'security',
  'session',
  'settings',
  'signup',
  'sponsors',
  'team',
  'topics',
  'trending'
]);

const CATALOG_AUDIT_EXEMPT_PATH_RE =
  /(?:^(?:lib|lib-py)(?:[\\/]|$)|(?:^|[\\/])(?:krusch_toolkit|krusch-stack|tests?|__tests__|benchmarks?|node_modules|site-packages|__pycache__|vendor|third_party|_?archive|archive_scratch|scratch)(?:[\\/]|$)|\.(?:test|spec)\.(?:[cm]?[jt]sx?|php|py|rb|go|rs|java|cs|kt)$|_test\.go$|(?:^|[\\/])test[_-]|\.(?:md|mdx|txt|rst|json|ya?ml|toml|lock|html|css|svg|sql|sh)$)/i;

const MAX_AUDIT_CHARS = 512_000;

const JS_REGEX_PREFIX_KEYWORDS = new Set([
  'return', 'throw', 'case', 'typeof', 'void', 'delete',
  'in', 'of', 'instanceof', 'yield', 'await', 'else', 'do'
]);

const TAINTED_URL_PROP_RE =
  /^(?:url|targetUrl|target_url|webhookUrl|webhook_url|callbackUrl|callback_url|endpoint|endpointUrl|endpoint_url|proxyUrl|proxy_url|fetchUrl|fetch_url|feedUrl|feed_url|imageUrl|image_url|sourceUrl|source_url|remoteUrl|remote_url|destUrl|dest_url|uri|href)$/i;

function inferIsPythonSource(code = '', filePath = '') {
  const fp = String(filePath || '').trim();
  if (/\.pyw?$/i.test(fp)) return true;
  if (/\.[cm]?[jt]sx?$/i.test(fp)) return false;
  return /^\s*(?:from\s+[a-zA-Z_][\w.]*\s+import\s+|import\s+(?:fastapi|yaml)\b|(?:async\s+)?def\s+[a-zA-Z_]\w*\s*\(|@[a-zA-Z_]\w*\.(?:get|post|put|delete|patch)\s*\()/m.test(
    String(code || '')
  );
}

function tryScanJsRegex(text, startIdx) {
  const len = text.length;
  let j = startIdx + 1;
  let inCharClass = false;
  while (j < len) {
    const c = text[j];
    if (c === '\n' || c === '\r') return -1;
    if (c === '\\') {
      if (j + 1 >= len || text[j + 1] === '\n' || text[j + 1] === '\r') return -1;
      j += 2;
      continue;
    }
    if (c === '[') {
      inCharClass = true;
      j += 1;
      continue;
    }
    if (c === ']' && inCharClass) {
      inCharClass = false;
      j += 1;
      continue;
    }
    if (c === '/' && !inCharClass) {
      j += 1;
      while (j < len && /[dgimsuvy]/.test(text[j])) j += 1;
      return j;
    }
    j += 1;
  }
  return -1;
}

function stripCommentLines(source = '', { isPython = false } = {}) {
  const text = String(source || '');
  if (!text) return '';
  let out = '';
  const len = text.length;
  let i = 0;
  let lastSigChar = '';
  let lastWord = '';
  let wordBuf = '';
  const templateBraceStack = [];

  const flushWord = () => {
    if (wordBuf) {
      lastWord = wordBuf;
      wordBuf = '';
    }
  };

  const scanTemplateBody = () => {
    while (i < len) {
      if (text[i] === '\\' && i + 1 < len) {
        out += text[i] + text[i + 1];
        i += 2;
        continue;
      }
      if (text[i] === '$' && text[i + 1] === '{') {
        out += '${';
        i += 2;
        templateBraceStack.push(0);
        lastSigChar = '{';
        lastWord = '';
        return;
      }
      if (text[i] === '`') {
        out += '`';
        i += 1;
        lastSigChar = '`';
        lastWord = '';
        return;
      }
      out += text[i];
      i += 1;
    }
    lastSigChar = '`';
    lastWord = '';
  };

  while (i < len) {
    const ch = text[i];
    const next = text[i + 1] || '';
    const next2 = text[i + 2] || '';

    if (!isPython && ch === '/' && next === '*') {
      flushWord();
      i += 2;
      while (i < len && !(text[i] === '*' && text[i + 1] === '/')) {
        if (text[i] === '\n') out += '\n';
        i += 1;
      }
      if (i < len) i += 2;
      continue;
    }

    if (!isPython && ch === '/' && next === '/') {
      flushWord();
      i += 2;
      while (i < len && text[i] !== '\n') i += 1;
      continue;
    }

    if (isPython && ch === '#') {
      flushWord();
      i += 1;
      while (i < len && text[i] !== '\n') i += 1;
      continue;
    }

    if (!isPython && i === 0 && ch === '#' && next === '!') {
      i += 2;
      while (i < len && text[i] !== '\n') i += 1;
      continue;
    }

    if (isPython && ((ch === "'" && next === "'" && next2 === "'") || (ch === '"' && next === '"' && next2 === '"'))) {
      flushWord();
      const delim = ch;
      out += delim + delim + delim;
      i += 3;
      while (i < len) {
        if (text[i] === '\\' && i + 1 < len) {
          out += text[i] + text[i + 1];
          i += 2;
          continue;
        }
        if (text[i] === delim && text[i + 1] === delim && text[i + 2] === delim) {
          out += delim + delim + delim;
          i += 3;
          break;
        }
        out += text[i];
        i += 1;
      }
      lastSigChar = delim;
      lastWord = '';
      continue;
    }

    if (!isPython && ch === '/' && next !== '/' && next !== '*' && (i === 0 || text[i - 1] !== '<')) {
      flushWord();
      const canStartRegex =
        lastSigChar === '' ||
        '(,[=:{;!&|?+-*~^%>'.includes(lastSigChar) ||
        (/[a-zA-Z_$]/.test(lastSigChar) && JS_REGEX_PREFIX_KEYWORDS.has(lastWord));
      if (canStartRegex) {
        const regexEnd = tryScanJsRegex(text, i);
        if (regexEnd > i) {
          out += text.slice(i, regexEnd);
          lastSigChar = '/';
          lastWord = '';
          i = regexEnd;
          continue;
        }
      }
    }

    if (!isPython && ch === '`') {
      flushWord();
      out += '`';
      i += 1;
      scanTemplateBody();
      continue;
    }

    if (ch === "'" || ch === '"') {
      flushWord();
      const quote = ch;
      out += quote;
      i += 1;
      while (i < len) {
        if (text[i] === '\\' && i + 1 < len) {
          out += text[i] + text[i + 1];
          i += 2;
          continue;
        }
        if (text[i] === '\n') {
          break;
        }
        out += text[i];
        i += 1;
        if (text[i - 1] === quote) {
          break;
        }
      }
      lastSigChar = quote;
      lastWord = '';
      continue;
    }

    if (!isPython && templateBraceStack.length > 0) {
      if (ch === '{') {
        flushWord();
        templateBraceStack[templateBraceStack.length - 1] += 1;
        lastSigChar = '{';
        out += '{';
        i += 1;
        continue;
      }
      if (ch === '}') {
        flushWord();
        if (templateBraceStack[templateBraceStack.length - 1] > 0) {
          templateBraceStack[templateBraceStack.length - 1] -= 1;
          lastSigChar = '}';
          out += '}';
          i += 1;
          continue;
        }
        templateBraceStack.pop();
        out += '}';
        i += 1;
        scanTemplateBody();
        continue;
      }
    }

    if (/[a-zA-Z0-9_$.]/.test(ch)) {
      wordBuf += ch;
      lastSigChar = ch;
    } else {
      flushWord();
      if (!/\s/.test(ch)) {
        lastSigChar = ch;
      }
    }

    out += ch;
    i += 1;
  }

  return out;
}

function isWordOrDotCode(c) {
  return (
    (c >= 97 && c <= 122) ||
    (c >= 65 && c <= 90) ||
    (c >= 48 && c <= 57) ||
    c === 95 || c === 36 || c === 46
  );
}

function isSpaceCode(c) {
  return c === 32 || c === 10 || c === 13 || c === 9 || c === 12 || c === 11;
}

function hasFetchInsideUseEffect(cleaned) {
  if (!/\buseEffect\s*\(/.test(cleaned) || !/\bfetch\s*\(/.test(cleaned)) {
    return false;
  }

  const useEffectRe = /\buseEffect\s*\(/g;
  const len = cleaned.length;
  let cursor = 0;
  let match;

  while ((match = useEffectRe.exec(cleaned)) !== null) {
    if (match.index < cursor) continue;
    const openParenIdx = match.index + match[0].length - 1;
    let i = openParenIdx + 1;
    let depth = 1;
    const tplBraceStack = [];
    let lastSigChar = '(';
    let lastWord = '';
    let wordBuf = '';
    let codeSpan = '(';

    const flushWord = () => {
      if (wordBuf) {
        lastWord = wordBuf;
        wordBuf = '';
      }
    };

    const skipTemplateLiteral = () => {
      while (i < len) {
        const tc = cleaned.charCodeAt(i);
        if (tc === 92 && i + 1 < len) {
          i += 2;
          continue;
        }
        if (tc === 36 && cleaned.charCodeAt(i + 1) === 123) {
          tplBraceStack.push(0);
          lastSigChar = '{';
          lastWord = '';
          codeSpan += ' {';
          i += 2;
          return;
        }
        if (tc === 96) {
          lastSigChar = '`';
          lastWord = '';
          codeSpan += ' ';
          i += 1;
          return;
        }
        i += 1;
      }
    };

    while (i < len && depth > 0) {
      const code = cleaned.charCodeAt(i);
      const ch = cleaned[i];

      if (code === 47 && (i === 0 || cleaned.charCodeAt(i - 1) !== 60)) {
        flushWord();
        const lastSigCode = lastSigChar ? lastSigChar.charCodeAt(0) : 0;
        const canStartRegex =
          lastSigChar === '' ||
          '(,[=:{;!&|?+-*~^%>'.includes(lastSigChar) ||
          (((lastSigCode >= 97 && lastSigCode <= 122) ||
            (lastSigCode >= 65 && lastSigCode <= 90) ||
            lastSigCode === 95 ||
            lastSigCode === 36) &&
            JS_REGEX_PREFIX_KEYWORDS.has(lastWord));
        if (canStartRegex) {
          const regexEnd = tryScanJsRegex(cleaned, i);
          if (regexEnd > i) {
            i = regexEnd;
            lastSigChar = '/';
            lastWord = '';
            codeSpan += ' ';
            continue;
          }
        }
        lastSigChar = '/';
        codeSpan += '/';
        i += 1;
        continue;
      }

      if (code === 96) {
        flushWord();
        codeSpan += ' ';
        i += 1;
        skipTemplateLiteral();
        continue;
      }

      if (code === 39 || code === 34) {
        flushWord();
        const quoteCode = code;
        i += 1;
        while (i < len) {
          const qc = cleaned.charCodeAt(i);
          if (qc === 92 && i + 1 < len) {
            i += 2;
            continue;
          }
          if (qc === 10) break;
          i += 1;
          if (qc === quoteCode) break;
        }
        lastSigChar = ch;
        lastWord = '';
        codeSpan += ' ';
        continue;
      }

      if (tplBraceStack.length > 0) {
        if (code === 123) {
          flushWord();
          tplBraceStack[tplBraceStack.length - 1] += 1;
          lastSigChar = '{';
          codeSpan += '{';
          i += 1;
          continue;
        }
        if (code === 125) {
          flushWord();
          if (tplBraceStack[tplBraceStack.length - 1] > 0) {
            tplBraceStack[tplBraceStack.length - 1] -= 1;
            lastSigChar = '}';
            codeSpan += '}';
            i += 1;
            continue;
          }
          tplBraceStack.pop();
          codeSpan += '} ';
          i += 1;
          skipTemplateLiteral();
          continue;
        }
      }

      if (code === 40) {
        flushWord();
        depth += 1;
        lastSigChar = '(';
        codeSpan += '(';
        i += 1;
        continue;
      }
      if (code === 41) {
        flushWord();
        depth -= 1;
        lastSigChar = ')';
        codeSpan += ')';
        i += 1;
        continue;
      }

      if (isWordOrDotCode(code)) {
        wordBuf += ch;
        lastSigChar = ch;
      } else {
        flushWord();
        if (!isSpaceCode(code)) {
          lastSigChar = ch;
        }
      }
      codeSpan += ch;
      i += 1;
    }

    cursor = i;
    if (/(?:^|[^.\w$])fetch\s*\(/.test(codeSpan) || /\b(?:window|globalThis|self)\.fetch\s*\(/.test(codeSpan)) {
      return true;
    }
  }

  return false;
}

function stripStringBodiesForYamlAudit(cleaned, isPython) {
  let out = '';
  const len = cleaned.length;
  let i = 0;
  const tplStack = [];

  const scanTpl = () => {
    while (i < len) {
      if (cleaned[i] === '\\' && i + 1 < len) {
        out += '  ';
        i += 2;
        continue;
      }
      if (cleaned[i] === '$' && cleaned[i + 1] === '{') {
        out += '${';
        i += 2;
        tplStack.push(0);
        return;
      }
      if (cleaned[i] === '`') {
        out += '`';
        i += 1;
        return;
      }
      out += cleaned[i] === '\n' ? '\n' : ' ';
      i += 1;
    }
  };

  while (i < len) {
    const ch = cleaned[i];
    if (
      isPython &&
      ((ch === "'" && cleaned[i + 1] === "'" && cleaned[i + 2] === "'") ||
        (ch === '"' && cleaned[i + 1] === '"' && cleaned[i + 2] === '"'))
    ) {
      const d = ch;
      out += d + d + d;
      i += 3;
      while (i < len) {
        if (cleaned[i] === '\\' && i + 1 < len) {
          out += '  ';
          i += 2;
          continue;
        }
        if (cleaned[i] === d && cleaned[i + 1] === d && cleaned[i + 2] === d) {
          out += d + d + d;
          i += 3;
          break;
        }
        out += cleaned[i] === '\n' ? '\n' : ' ';
        i += 1;
      }
      continue;
    }
    if (!isPython && ch === '`') {
      out += '`';
      i += 1;
      scanTpl();
      continue;
    }
    if (!isPython && tplStack.length > 0) {
      if (ch === '{') {
        tplStack[tplStack.length - 1] += 1;
        out += '{';
        i += 1;
        continue;
      }
      if (ch === '}') {
        if (tplStack[tplStack.length - 1] > 0) {
          tplStack[tplStack.length - 1] -= 1;
          out += '}';
          i += 1;
          continue;
        }
        tplStack.pop();
        out += '}';
        i += 1;
        scanTpl();
        continue;
      }
    }
    if (ch === "'" || ch === '"') {
      const q = ch;
      const start = i + 1;
      let j = start;
      while (j < len && cleaned[j] !== '\n') {
        if (cleaned[j] === '\\' && j + 1 < len) {
          j += 2;
          continue;
        }
        if (cleaned[j] === q) break;
        j += 1;
      }
      const inner = cleaned.slice(start, j);
      const hasClosing = j < len && cleaned[j] === q;
      const keepSpecifier =
        !isPython &&
        inner === 'js-yaml' &&
        /(?:\bfrom\s*|\brequire\s*\(\s*)$/.test(out);
      out += q + (keepSpecifier ? inner : ' '.repeat(inner.length)) + (hasClosing ? q : '');
      i = hasClosing ? j + 1 : j;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function hasUnclampedOrmOrQueryPagination(cleaned) {
  if (!/\b(?:findMany|skip|limit|offset|query)\b/.test(cleaned)) return false;
  const codeOnly = stripStringBodiesForYamlAudit(cleaned, false);
  if (/\bMath\.min\s*\(/.test(codeOnly)) return false;

  if (/\bfindMany\s*\(/.test(codeOnly) && /\bskip\s*:/.test(codeOnly) && /\btake\s*:/.test(codeOnly)) {
    const findManyRe = /\bfindMany\s*\(/g;
    let match;
    while ((match = findManyRe.exec(codeOnly)) !== null) {
      let j = match.index + match[0].length;
      const maxEnd = Math.min(codeOnly.length, j + 800);
      let depth = 1;
      let argsSlice = '';
      while (j < maxEnd && depth > 0) {
        const c = codeOnly[j];
        if (c === '(') depth += 1;
        else if (c === ')') depth -= 1;
        if (depth > 0) argsSlice += c;
        j += 1;
      }
      const hasDynamicSkip = /\bskip\s*:\s*(?!\d+\s*[,}\r\n])/.test(argsSlice);
      const hasDynamicTake =
        /\btake\s*:\s*(?!\d+\s*[,}\r\n])(?:(?:Number|parseInt)\s*\(\s*|\+\s*)?(?:(?:req|request|query|params)\??\.\s*)?(?:limit|take|pageSize|perPage|per_page)\b/.test(
          argsSlice
        );
      if (hasDynamicSkip && hasDynamicTake) {
        return true;
      }
    }
  }

  if (/(?:req|request)\??\.\s*query\b/.test(codeOnly)) {
    if (
      /\.(?:skip\s*\([^()\n]{1,120}\)\s*\.\s*limit\s*\(\s*(?!\d+\s*\))[^()\n]{1,120}\)|limit\s*\(\s*(?!\d+\s*\))[^()\n]{1,120}\)\s*\.\s*skip\s*\([^()\n]{1,120}\))/.test(
        codeOnly
      )
    ) {
      return true;
    }
    const hasCoercedLimit =
      /(?:Number|parseInt)\s*\(\s*(?:req|request)\??\.\s*query(?:\??\.\s*(?:limit|take|pageSize|per_page)\b|\[\s*['"`](?:limit|take|pageSize|per_page)['"`]\s*\])/.test(
        cleaned
      );
    const hasPairedOffset =
      /(?:req|request)\??\.\s*query(?:\??\.\s*(?:offset|skip|page)\b|\[\s*['"`](?:offset|skip|page)['"`]\s*\])/.test(
        cleaned
      );
    if (hasCoercedLimit && hasPairedOffset) {
      return true;
    }
  }

  return false;
}

function hasUnvalidatedOutboundSsrf(cleaned, isPython) {
  if (isPython) {
    if (!/\b(?:httpx|requests|aiohttp|urlopen)\b/.test(cleaned)) return false;
    const usesToolkitPySec =
      /\bkrusch_toolkit\.security\b/.test(cleaned) ||
      /\bfrom\s+krusch_toolkit\s+import\b[^\n]*\b(?:security|validate_outbound_url|is_private_or_reserved_ip)\b/.test(
        cleaned
      ) ||
      /\b(?:validate_outbound_url|is_private_or_reserved_ip)\b/.test(cleaned);
    if (usesToolkitPySec) return false;

    const codeOnly = stripStringBodiesForYamlAudit(cleaned, true);
    if (
      /\b(?:httpx|requests)\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\(\s*(?:str\s*\(\s*)?(?:request\s*\.\s*(?:query_params|args|form|values)|req\s*\.\s*(?:query_params|args))\b/.test(
        codeOnly
      ) ||
      /\burlopen\s*\(\s*(?:str\s*\(\s*)?request\s*\.\s*(?:query_params|args|form|values)\b/.test(codeOnly)
    ) {
      return true;
    }

    const pyTainted = new Set();
    for (const line of cleaned.split('\n')) {
      if (pyTainted.size >= 32) break;
      const m =
        /^\s*([A-Za-z_]\w*)\s*(?::\s*[A-Za-z_][\w[\],\s|]{0,40})?=\s*(?:str\s*\(\s*)?request\s*\.\s*(?:query_params|args|form|values)\b(.*)$/.exec(
          line
        );
      if (!m) continue;
      const lhs = m[1];
      const rhsTail = m[2] || '';
      const keyMatch = /(?:\.\s*get\s*\(\s*['"]|\[\s*['"])([A-Za-z0-9_-]+)['"]/.exec(rhsTail);
      if (TAINTED_URL_PROP_RE.test(lhs) || (keyMatch && TAINTED_URL_PROP_RE.test(keyMatch[1]))) {
        pyTainted.add(lhs);
      }
    }

    if (/@(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|api_route)\b/.test(codeOnly)) {
      const defRe = /\bdef\s+\w+\s*\(([^)]{1,240})\)/g;
      let dm;
      while ((dm = defRe.exec(codeOnly)) !== null && pyTainted.size < 32) {
        const paramRe =
          /\b(url|target_url|webhook_url|callback_url|endpoint_url|proxy_url|feed_url|source_url)\s*:\s*(?:Optional\s*\[\s*)?str\b/g;
        let pm;
        while ((pm = paramRe.exec(dm[1])) !== null && pyTainted.size < 32) {
          pyTainted.add(pm[1]);
        }
      }
    }

    for (const v of pyTainted) {
      const callRe = new RegExp(
        `\\b(?:httpx|requests|client|session)\\s*\\.\\s*(?:get|post|put|delete|patch|head|request)\\s*\\(\\s*(?:str\\s*\\(\\s*)?${v}\\s*(?:\\)\\s*)?[,)]|\\burlopen\\s*\\(\\s*${v}\\s*[,)]`
      );
      if (callRe.test(codeOnly)) {
        return true;
      }
    }
    return false;
  }

  if (!/\b(?:fetch|axios|needle|got|https?)\b/.test(cleaned)) return false;
  if (!/(?:req|request)\??\.\s*(?:query|body|params)\b|\bc\.req\.query\s*\(/.test(cleaned)) return false;
  if (new RegExp(`${TK_NS.replace('/', '\\/')}\\/security\\b|\\b(?:safeFetch|validateOutboundUrl|isPrivateOrReservedIp)\\b`).test(cleaned)) {
    return false;
  }

  const codeOnly = stripStringBodiesForYamlAudit(cleaned, false);
  const httpCallPrefix =
    '(?:(?:^|[^.\\w$])fetch|(?:globalThis|window|self)\\s*\\.\\s*fetch|\\baxios(?:\\s*\\.\\s*(?:get|post|put|delete|patch|head|request))?|\\bneedle(?:\\s*\\.\\s*(?:get|post|put|delete|head|request))?|\\bgot(?:\\s*\\.\\s*(?:get|post|put|delete|stream))?|\\bhttps?\\s*\\.\\s*(?:get|request))';

  const directCallRe = new RegExp(
    `${httpCallPrefix}\\s*\\(\\s*(?:new\\s+URL\\s*\\(\\s*)?(?:String\\s*\\(\\s*)?(?:(?:req|request)\\??\\.\\s*(?:query|body|params)\\b|c\\.req\\.query\\s*\\(|\`\\$\\{\\s*(?:req|request)\\??\\.\\s*(?:query|body|params)\\b)`
  );
  if (directCallRe.test(codeOnly)) return true;

  if (
    /\baxios(?:\s*\.\s*request)?\s*\(\s*\{[^{}]{0,240}?\burl\s*:\s*(?:String\s*\(\s*)?(?:(?:req|request)\??\.\s*(?:query|body|params)\b|c\.req\.query\s*\()/.test(
      codeOnly
    )
  ) {
    return true;
  }

  const taintedVars = new Set();
  const assignLineRe =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[^=;\n]{1,60})?\s*=\s*(?:new\s+URL\s*\(\s*)?(?:String\s*\(\s*)?(?:(?:req|request)\??\.\s*(?:query|body|params)(?:\??\.\s*([A-Za-z_$][\w$]*)|\[\s*['"`]([A-Za-z0-9_$-]+)['"`]\s*\])|`\$\{\s*(?:req|request)\??\.\s*(?:query|body|params)\??\.\s*([A-Za-z_$][\w$]*)|c\.req\.query\s*\(\s*['"`]([A-Za-z0-9_$-]+)['"`]\s*\))/;
  for (const line of cleaned.split('\n')) {
    if (taintedVars.size >= 32) break;
    const m = assignLineRe.exec(line);
    if (!m) continue;
    const lhs = m[1];
    const rhsProp = m[2] || m[3] || m[4] || m[5] || '';
    if (TAINTED_URL_PROP_RE.test(lhs) || TAINTED_URL_PROP_RE.test(rhsProp)) {
      taintedVars.add(lhs);
    }
  }

  const destructRe =
    /\b(?:const|let|var)\s*\{([^{}]{1,240})\}(?:\s*:\s*[^=;\n]{1,120})?\s*=\s*(?:req|request)\??\.\s*(?:query|body|params)\b/g;
  let dm;
  while ((dm = destructRe.exec(codeOnly)) !== null && taintedVars.size < 32) {
    for (const rawPart of dm[1].split(',')) {
      const noDefault = rawPart.split('=')[0].trim();
      const aliasMatch = /^([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?$/.exec(noDefault);
      if (!aliasMatch) continue;
      const propName = aliasMatch[1];
      const boundName = aliasMatch[2] || aliasMatch[1];
      if (TAINTED_URL_PROP_RE.test(propName)) {
        taintedVars.add(boundName);
      }
    }
  }

  for (const ident of taintedVars) {
    const esc = ident.replace(/\$/g, '\\$');
    const callRe = new RegExp(
      `${httpCallPrefix}\\s*\\(\\s*(?:new\\s+URL\\s*\\(\\s*)?(?:String\\s*\\(\\s*)?${esc}(?:\\s*\\.\\s*trim\\s*\\(\\s*\\))?(?:\\s*\\))?\\s*(?:[,)]|as\\b|\\+)`
    );
    if (callRe.test(codeOnly)) return true;

    const axiosObjRe = new RegExp(
      `\\baxios(?:\\s*\\.\\s*request)?\\s*\\(\\s*\\{[^{}]{0,240}?\\burl\\s*(?::\\s*${esc}\\b|${
        ident === 'url' ? '[,}]' : '(?!)'
      })`
    );
    if (axiosObjRe.test(codeOnly)) return true;
  }

  return false;
}

function hasHardcodedAuthSecretFallback(cleaned, isPython) {
  if (isPython) return false;
  if (new RegExp(`${TK_NS.replace('/', '\\/')}\\/auth\\b|\\bcreateAuth\\b`).test(cleaned)) return false;
  if (
    !/\b(?:JWT_SECRET|AUTH_SECRET|SESSION_SECRET|COOKIE_SECRET|TOKEN_SECRET|APP_SECRET|SIGNING_SECRET|jwt|session|cookieSession|expressjwt|jwtSecret|cookieSecret|sessionSecret)\b/.test(
      cleaned
    )
  ) {
    return false;
  }

  const codeOnly = stripStringBodiesForYamlAudit(cleaned, false);

  if (
    /\bprocess\s*\.\s*env\s*\.\s*(?:JWT_SECRET|AUTH_SECRET|SESSION_SECRET|COOKIE_SECRET|TOKEN_SECRET|APP_SECRET|SIGNING_SECRET)\s*(?:\|\||\?\?)\s*(?:(['"]) {1,}\1|` {1,}`)/.test(
      codeOnly
    )
  ) {
    return true;
  }

  const jwtCallRe = /\bjwt\s*\.\s*(?:sign|verify)\s*\(/g;
  let jm;
  while ((jm = jwtCallRe.exec(codeOnly)) !== null) {
    let j = jm.index + jm[0].length;
    const maxEnd = Math.min(codeOnly.length, j + 512);
    let parenDepth = 1;
    let braceDepth = 0;
    let bracketDepth = 0;
    let commaIdx = -1;
    while (j < maxEnd && parenDepth > 0) {
      const c = codeOnly[j];
      if (c === '(') parenDepth += 1;
      else if (c === ')') parenDepth -= 1;
      else if (c === '{') braceDepth += 1;
      else if (c === '}') braceDepth = Math.max(0, braceDepth - 1);
      else if (c === '[') bracketDepth += 1;
      else if (c === ']') bracketDepth = Math.max(0, bracketDepth - 1);
      else if (c === ',' && parenDepth === 1 && braceDepth === 0 && bracketDepth === 0) {
        commaIdx = j;
        break;
      }
      j += 1;
    }
    if (commaIdx !== -1) {
      const secondArg = codeOnly.slice(commaIdx + 1, Math.min(codeOnly.length, commaIdx + 200)).trimStart();
      if (/^(?:(['"]) {1,}\1|` {1,}`)\s*(?:[,)]|as\b)/.test(secondArg)) {
        return true;
      }
    }
  }

  const sessionCallRe = /\b(?:session|cookieSession|expressjwt|jwt)\s*\(\s*\{/g;
  let sm;
  while ((sm = sessionCallRe.exec(codeOnly)) !== null) {
    let j = sm.index + sm[0].length;
    const maxEnd = Math.min(codeOnly.length, j + 600);
    let braceDepth = 1;
    let topLevelObj = '';
    while (j < maxEnd && braceDepth > 0) {
      const c = codeOnly[j];
      if (c === '{') {
        if (braceDepth === 1) topLevelObj += '{}';
        braceDepth += 1;
      } else if (c === '}') {
        braceDepth -= 1;
      } else if (braceDepth === 1) {
        topLevelObj += c;
      }
      j += 1;
    }
    if (/\bsecret\s*:\s*(?:(['"]) {1,}\1|` {1,}`)/.test(topLevelObj)) {
      return true;
    }
  }

  if (/\b(?:jwtSecret|cookieSecret|sessionSecret)\s*:\s*(?:(['"]) {1,}\1|` {1,}`)/.test(codeOnly)) {
    return true;
  }

  return false;
}

function hasUnsafeYamlLoad(cleaned, isPython) {
  if (isPython) {
    if (!cleaned.includes('yaml.')) return false;
    const usesToolkitPyYaml =
      /\bkrusch_toolkit\.yaml_loader\b/.test(cleaned) ||
      /\bfrom\s+krusch_toolkit\s+import\b[\s\S]{0,240}?\b(?:yaml_loader|parse_safe_yaml|load_safe_yaml_pack|validate_yaml_config|dump_safe_yaml)\b/.test(
        cleaned
      );
    if (usesToolkitPyYaml) return false;

    const codeOnly = stripStringBodiesForYamlAudit(cleaned, true);
    if (/\byaml\.(?:unsafe_load|full_load|unsafe_load_all|full_load_all)\s*\(/.test(codeOnly)) {
      return true;
    }
    const loadRe = /\byaml\.load(?:_all)?\s*\(/g;
    let match;
    while ((match = loadRe.exec(codeOnly)) !== null) {
      let j = match.index + match[0].length;
      const maxEnd = Math.min(codeOnly.length, j + 1024);
      let depth = 1;
      let argsSlice = '';
      while (j < maxEnd && depth > 0) {
        const c = codeOnly[j];
        if (c === '(') depth += 1;
        else if (c === ')') depth -= 1;
        if (depth > 0) argsSlice += c;
        j += 1;
      }
      if (!/\b(?:C?SafeLoader|_SovereignSafeLoader)\b/.test(argsSlice)) {
        return true;
      }
    }
    return false;
  }

  if (!cleaned.includes('js-yaml')) return false;
  const usesToolkitJsYaml =
    new RegExp(`${TK_NS.replace('/', '\\/')}\\/yaml\\b|\\b(?:parseSafeYaml|loadSafeYamlPack|validateYamlConfig|stringifySafeYaml)\\b`).test(
      cleaned
    );
  if (usesToolkitJsYaml) return false;

  const codeOnly = stripStringBodiesForYamlAudit(cleaned, false);
  if (!codeOnly.includes('js-yaml')) return false;
  if (/\brequire\s*\(\s*['"]js-yaml['"]\s*\)\s*\.load(?:All)?\s*\(/.test(codeOnly)) {
    return true;
  }

  const nsBindings = new Set();
  const fnBindings = new Set();

  const nsImportRe =
    /\bimport\s+(?:\*\s+as\s+([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)(?:\s*,\s*\{[^}]*\})?)\s+from\s*['"]js-yaml['"]/g;
  let m;
  while ((m = nsImportRe.exec(codeOnly)) !== null) {
    const ident = m[1] || m[2];
    if (ident) nsBindings.add(ident);
  }

  const nsRequireRe =
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]js-yaml['"]\s*\)/g;
  while ((m = nsRequireRe.exec(codeOnly)) !== null) {
    if (m[1]) nsBindings.add(m[1]);
  }

  const namedRe =
    /(?:\bimport\s+(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*['"]js-yaml['"]|\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"]js-yaml['"]\s*\))/g;
  while ((m = namedRe.exec(codeOnly)) !== null) {
    const clause = m[1] || m[2] || '';
    for (const part of clause.split(',')) {
      const spec = part.trim();
      const sm =
        /^(load(?:All)?)(?:(?:\s+as\s+|\s*:\s*)([A-Za-z_$][\w$]*))?(?:\s*=[\s\S]*)?$/.exec(
          spec
        );
      if (sm) {
        fnBindings.add(sm[2] || sm[1]);
      }
    }
  }

  for (const ns of nsBindings) {
    const esc = ns.replace(/\$/g, '\\$');
    if (new RegExp(`(?:^|[^.\\w$])${esc}\\s*\\.\\s*load(?:All)?\\s*\\(`).test(codeOnly)) {
      return true;
    }
  }
  for (const fn of fnBindings) {
    const esc = fn.replace(/\$/g, '\\$');
    if (new RegExp(`(?:^|[^.\\w$])${esc}\\s*\\(`).test(codeOnly)) {
      return true;
    }
  }
  return false;
}

function detectSealedBrickIdsForSource(cleaned, isPython) {
  const matchedIds = new Set();
  for (const brick of SEALED_BRICK_REGISTRY) {
    const imp = brick.importPath;
    if (imp.startsWith(`${TK_NS}/`)) {
      if (isPython) continue;
      const escaped = imp.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp(`['"]${escaped}['"]`).test(cleaned)) {
        matchedIds.add(brick.id);
        continue;
      }
      if (brick.id === 'mcp' && new RegExp(`['"]${TK_NS.replace('/', '\\/')}\\/mcp-server['"]`).test(cleaned)) {
        matchedIds.add(brick.id);
      }
    } else if (imp.startsWith(`${PY_TK_NS}.`)) {
      if (!isPython) continue;
      const submod = imp.slice(`${PY_TK_NS}.`.length).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const directRe = new RegExp(`\\b${PY_TK_NS}\\.${submod}\\b`);
      const fromRe = new RegExp(`\\bfrom\\s+${PY_TK_NS}\\s+import\\b[^\\n]*\\b${submod}\\b`);
      if (directRe.test(cleaned) || fromRe.test(cleaned)) {
        matchedIds.add(brick.id);
      }
    }
  }
  return [...matchedIds].sort();
}

/**
 * Deterministically inspect JS/TS/Python source text across all 16 Slop-Breaker rules.
 *
 * @param {string} [code='']
 * @param {string} [filePath='']
 * @param {{ ignoreExempt?: boolean }} [options={}]
 */
export function auditBoilerplateText(code = '', filePath = '', options = {}) {
  const fullRaw = String(code || '');
  const raw = fullRaw.length > MAX_AUDIT_CHARS ? fullRaw.slice(0, MAX_AUDIT_CHARS) : fullRaw;
  const normalizedPath = String(filePath || '');
  if (!options?.ignoreExempt && normalizedPath && CATALOG_AUDIT_EXEMPT_PATH_RE.test(normalizedPath)) {
    return okEnvelope(
      'lego.catalog',
      'Zero hand-rolled boilerplate detected (exempt path)',
      {
        filePath: normalizedPath,
        clean: true,
        findings: []
      }
    );
  }

  const isPython = inferIsPythonSource(raw, normalizedPath);
  const cleaned = stripCommentLines(raw, { isPython });
  const findings = [];
  const tkEsc = TK_NS.replace('/', '\\/');

  // 1. Raw MCP Server + StdioServerTransport
  const hasRawMcp = /\bnew\s+Server\s*\(/.test(cleaned) && /\bStdioServerTransport\b/.test(cleaned);
  const usesToolkitMcp = new RegExp(`${tkEsc}\\/mcp(?:-server)?\\b`).test(cleaned);
  if (hasRawMcp && !usesToolkitMcp) {
    findings.push({
      ruleId: 'raw-mcp-stdio',
      brickId: 'mcp',
      importPath: `${TK_NS}/mcp`,
      severity: 'warn',
      message: `Hand-rolled MCP Server + StdioServerTransport detected; replace with defineMcpTool and createMcpServer from ${TK_NS}/mcp.`
    });
  }

  // 2. Manual text/event-stream SSE headers
  const hasManualSse = /text\/event-stream/i.test(cleaned);
  const usesToolkitStreaming =
    new RegExp(`${tkEsc}\\/(?:streaming|edge)\\b`).test(cleaned) ||
    /\bkrusch_toolkit\.fastapi_app\b/.test(cleaned) ||
    /\bfrom\s+krusch_toolkit\s+import\b[^\n]*\bfastapi_app\b/.test(cleaned);
  if (hasManualSse && !usesToolkitStreaming) {
    findings.push({
      ruleId: 'manual-sse-headers',
      brickId: isPython ? 'fastapi_app' : 'streaming',
      importPath: isPython ? `${PY_TK_NS}.fastapi_app` : `${TK_NS}/streaming`,
      severity: 'warn',
      message: isPython
        ? `Manual text/event-stream response detected; use sse_event_response from ${PY_TK_NS}.fastapi_app.`
        : `Manual text/event-stream plumbing detected; use sseResponse/streamChat (${TK_NS}/streaming) or edgeSseResponse (${TK_NS}/edge).`
    });
  }

  // 3. Raw PostgreSQL Pool
  const hasRawPgPool =
    /\bnew\s+pg\.Pool\s*\(/.test(cleaned) ||
    (/\bnew\s+Pool\s*\(/.test(cleaned) && /(?:from\s+['"]pg['"]|require\(\s*['"]pg['"]\s*\))/.test(cleaned));
  const usesToolkitPg = new RegExp(`${tkEsc}\\/(?:pg|polygres)\\b`).test(cleaned);
  if (hasRawPgPool && !usesToolkitPg) {
    findings.push({
      ruleId: 'raw-pg-pool',
      brickId: 'pg',
      importPath: `${TK_NS}/pg`,
      severity: 'warn',
      message: `Raw pg.Pool instantiation detected; use createPgPool, runSqlMigrations, and pgVectorSearch from ${TK_NS}/pg.`
    });
  }

  // 4. Raw better-sqlite3 Database
  const hasRawSqlite =
    /\bnew\s+Database\s*\(/.test(cleaned) &&
    (/better-sqlite3/.test(cleaned) || /\.pragma\s*\(\s*['"]journal_mode/i.test(cleaned));
  const usesToolkitDb = new RegExp(`${tkEsc}\\/db\\b`).test(cleaned);
  if (hasRawSqlite && !usesToolkitDb) {
    findings.push({
      ruleId: 'raw-sqlite-database',
      brickId: 'db',
      importPath: `${TK_NS}/db`,
      severity: 'warn',
      message: `Raw better-sqlite3 Database instantiation detected; use initDb, query, and run from ${TK_NS}/db.`
    });
  }

  // 5. Raw FastAPI CORSMiddleware + @app.get("/health")
  const hasRawFastapi =
    /\bCORSMiddleware\b/.test(cleaned) &&
    /@\w+\.get\(\s*['"]\/health['"]/.test(cleaned);
  const usesToolkitFastapi =
    /\bkrusch_toolkit\.fastapi_app\b/.test(cleaned) ||
    /\bfrom\s+krusch_toolkit\s+import\b[^\n]*\bfastapi_app\b/.test(cleaned);
  if (hasRawFastapi && !usesToolkitFastapi) {
    findings.push({
      ruleId: 'raw-fastapi-boilerplate',
      brickId: 'fastapi_app',
      importPath: `${PY_TK_NS}.fastapi_app`,
      severity: 'warn',
      message: `Hand-rolled FastAPI CORSMiddleware + /health route detected; use create_fastapi_app from ${PY_TK_NS}.fastapi_app.`
    });
  }

  // 6. Un-aborted React useEffect fetch(
  const hasUseEffectFetch = !isPython && hasFetchInsideUseEffect(cleaned);
  const hasFetchAbortGuard = /\bAbortController\b|\bsignal\b|\buseApiQuery\b|\buseSSEStream\b|\bfetchApiJson\b/.test(cleaned);
  if (hasUseEffectFetch && !hasFetchAbortGuard) {
    findings.push({
      ruleId: 'unaborted-useeffect-fetch',
      brickId: 'react',
      importPath: `${TK_NS}/react`,
      severity: 'warn',
      message: `Un-aborted fetch() inside React useEffect detected; pass AbortController signal or use useApiQuery from ${TK_NS}/react.`
    });
  }

  // 7. Hand-rolled webhook HMAC verification
  const hasRawWebhookHmac =
    !isPython &&
    /\bcreateHmac\s*\(/.test(cleaned) &&
    /\b(?:x-slack-signature|x-hub-signature-256|stripe-signature)\b/i.test(cleaned);
  const usesToolkitWebhooks = new RegExp(`${tkEsc}\\/webhooks\\b|\\b(?:verifySlackSignature|verifyGithubSignature|verifyStripeSignature)\\b`).test(cleaned);
  if (hasRawWebhookHmac && !usesToolkitWebhooks) {
    findings.push({
      ruleId: 'raw-webhook-hmac',
      brickId: 'webhooks',
      importPath: `${TK_NS}/webhooks`,
      severity: 'warn',
      message: `Hand-rolled webhook HMAC check detected; use verifySlackSignature, verifyGithubSignature, or verifyStripeSignature from ${TK_NS}/webhooks.`
    });
  }

  // 8. Raw Node 22 node:sqlite DatabaseSync
  const hasRawNodeSqlite = !isPython && /\bnew\s+DatabaseSync\s*\(/.test(cleaned);
  const usesToolkitSqlite = new RegExp(`${tkEsc}\\/sqlite\\b|\\bopenSqliteDb\\b`).test(cleaned);
  if (hasRawNodeSqlite && !usesToolkitSqlite) {
    findings.push({
      ruleId: 'raw-node-sqlite',
      brickId: 'sqlite',
      importPath: `${TK_NS}/sqlite`,
      severity: 'warn',
      message: `Raw node:sqlite DatabaseSync instantiation detected; use openSqliteDb, escapeFts5Query, and fuseRrfResults from ${TK_NS}/sqlite.`
    });
  }

  // 9. Raw multer() multipart upload middleware
  const hasRawMulter = !isPython && /\bmulter\s*\(/.test(cleaned);
  const usesToolkitUpload = new RegExp(`${tkEsc}\\/upload\\b|\\bparseBoundedMultipart\\b`).test(cleaned);
  if (hasRawMulter && !usesToolkitUpload) {
    findings.push({
      ruleId: 'raw-multer-upload',
      brickId: 'upload',
      importPath: `${TK_NS}/upload`,
      severity: 'warn',
      message: `Raw multer() upload middleware detected; use parseBoundedMultipart, verifyUploadMime, and sanitizeUploadFilename from ${TK_NS}/upload.`
    });
  }

  // 10. Unsafe YAML load
  if (hasUnsafeYamlLoad(cleaned, isPython)) {
    findings.push({
      ruleId: 'unsafe-yaml-load',
      brickId: isPython ? 'python_yaml' : 'yaml',
      importPath: isPython ? `${PY_TK_NS}.yaml_loader` : `${TK_NS}/yaml`,
      severity: 'warn',
      message: isPython
        ? `Unsafe PyYAML yaml.load()/unsafe_load()/full_load() detected; use parse_safe_yaml, validate_yaml_config, or load_safe_yaml_pack from ${PY_TK_NS}.yaml_loader.`
        : `Unsafe js-yaml load() detected; use parseSafeYaml, validateYamlConfig, or loadSafeYamlPack from ${TK_NS}/yaml.`
    });
  }

  // 11. Hand-rolled inbound Idempotency-Key handling
  if (!isPython && /idempotency-key/i.test(cleaned)) {
    const hasRawIdempotency =
      /\b(?:req|request)\s*(?:\??\.\s*headers\s*(?:(?:\?\.\s*)?\[\s*['"`](?:x-)?idempotency-key['"`]\s*\]|\??\.\s*get\s*\(\s*['"`](?:x-)?idempotency-key['"`]\s*\))|\??\.\s*(?:get|header)\s*\(\s*['"`](?:x-)?idempotency-key['"`]\s*\))/i.test(
        cleaned
      ) ||
      /\{[^{}\n]{0,120}['"`](?:x-)?idempotency-key['"`]\s*:\s*[A-Za-z_$][\w$]*[^{}\n]{0,120}\}\s*=\s*(?:req|request)\??\.headers\b/i.test(
        cleaned
      );
    const usesToolkitIdempotency =
      new RegExp(`${tkEsc}\\/idempotency\\b|\\b(?:createIdempotencyStore|withIdempotency|createIdempotencyMiddleware|normalizeIdempotencyKey|computePayloadFingerprint)\\b`).test(
        cleaned
      );
    if (hasRawIdempotency && !usesToolkitIdempotency) {
      findings.push({
        ruleId: 'raw-idempotency-key',
        brickId: 'idempotency',
        importPath: `${TK_NS}/idempotency`,
        severity: 'warn',
        message: `Hand-rolled Idempotency-Key request handling detected; use createIdempotencyStore, withIdempotency, or createIdempotencyMiddleware from ${TK_NS}/idempotency.`
      });
    }
  }

  // 12. Mutable enterprise SQL audit tables or custom SHA-256 audit hash chains
  if (!isPython && /(?:audit|ledger)/i.test(cleaned)) {
    const hasMutableAuditSql =
      (/\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+(?:[`"\[]?[a-z_][\w]*[`"\]]?\.)?[`"\[]?(?:audit_ledger|audit_trail|compliance_audit\w*)\b/i.test(
        cleaned
      ) ||
        /\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+(?:[`"\[]?[a-z_][\w]*[`"\]]?\.)?[`"\[]?audit_logs?\b[^;]{0,600}\b(?:tenant_id|org_id|organization_id|actor_id|actor)\b/i.test(
          cleaned
        )) &&
      !/\bAUDIT_LEDGER_IMMUTABLE\b/.test(cleaned);
    const hasHandRolledAuditChain =
      /\bcreateHash\s*\(\s*['"`]sha256['"`]\s*\)/.test(cleaned) &&
      /\b(?:prevHash|prev_hash)\b/.test(cleaned);
    const usesToolkitAuditLog =
      new RegExp(`${tkEsc}\\/audit-log\\b|\\b(?:createAuditLog|computeAuditEntryHash|verifyAuditChain|canonicalizeAuditPayload|GENESIS_AUDIT_HASH)\\b`).test(
        cleaned
      );
    if ((hasMutableAuditSql || hasHandRolledAuditChain) && !usesToolkitAuditLog) {
      findings.push({
        ruleId: 'mutable-audit-ledger',
        brickId: 'audit-log',
        importPath: `${TK_NS}/audit-log`,
        severity: 'warn',
        message: `Mutable or hand-rolled audit ledger detected; use createAuditLog and verifyAuditChain from ${TK_NS}/audit-log for canonical SHA-256/HMAC chaining and SQLite immutability triggers.`
      });
    }
  }

  // 13. Hand-rolled multi-tenant IDOR / scoped RBAC checks
  if (!isPython && /\b(?:tenantId|tenant_id|permissions)\b/.test(cleaned)) {
    const hasTenantContext = /\b(?:tenantId|tenant_id)\b/.test(cleaned);
    const hasRawTenantIdor =
      /\b(?:(?:req|request)\??\.(?:user|auth)|user|auth|session|caller)\??\.(?:tenantId|tenant_id)\s*(?:!==|===|!=|==)/.test(
        cleaned
      ) ||
      /(?:!==|===|!=|==)\s*(?:(?:req|request)\??\.(?:user|auth)|user|auth|session|caller)\??\.(?:tenantId|tenant_id)\b/.test(
        cleaned
      );
    const hasRawTenantRoleCheck =
      hasTenantContext &&
      (/\b(?:req|request)\??\.(?:user|auth)\??\.(?:role\b\s*(?:===|!==|==|!=)|roles\??\.includes\s*\()/.test(
        cleaned
      ) ||
        /\.includes\s*\(\s*(?:req|request)\??\.(?:user|auth)\??\.role\s*\)/.test(cleaned));
    const hasRawScopedPermissionCheck =
      /\b(?:user|auth|subject|caller|session)\??\.permissions\??\.includes\s*\(\s*['"`][a-z0-9_-]+:[a-z0-9_*-]+['"`]\s*\)/i.test(
        cleaned
      );
    const usesToolkitRbac =
      new RegExp(`${tkEsc}\\/rbac\\b|\\b(?:createRbacPolicy|evaluateAccess|assertTenantOwnership|createRbacGuard|matchPermissionPattern)\\b`).test(
        cleaned
      );
    if ((hasRawTenantIdor || hasRawTenantRoleCheck || hasRawScopedPermissionCheck) && !usesToolkitRbac) {
      findings.push({
        ruleId: 'raw-tenant-rbac',
        brickId: 'rbac',
        importPath: `${TK_NS}/rbac`,
        severity: 'warn',
        message: `Hand-rolled RBAC or multi-tenant IDOR check detected; use createRbacPolicy, evaluateAccess, assertTenantOwnership, or createRbacGuard from ${TK_NS}/rbac.`
      });
    }
  }

  // 14. Unsigned base64 pagination cursors or unclamped query/ORM pagination
  if (!isPython) {
    const usesToolkitPagination =
      new RegExp(`${tkEsc}\\/pagination\\b|\\b(?:clampPageLimit|encodeCursor|decodeCursor|buildKeysetPage|paginateItems)\\b`).test(
        cleaned
      );
    if (!usesToolkitPagination) {
      const hasUnsignedBase64Cursor =
        /\b(?:cursor|nextCursor|next_cursor)\b/i.test(cleaned) &&
        (/\bBuffer\.from\s*\([^()\n]{0,120}\bcursor\b[^()\n]{0,40},\s*['"`]base64(?:url)?['"`]\s*\)/i.test(
          cleaned
        ) ||
          /\b(?:nextCursor|next_cursor)\s*=\s*(?:Buffer\.from\s*\([^;\n]{0,160}\.toString\s*\(\s*['"`]base64(?:url)?['"`]\s*\)|btoa\s*\()/i.test(
            cleaned
          ) ||
          /\b(?:atob|btoa)\s*\([^()\n]{0,80}\bcursor\b/i.test(cleaned)) &&
        !/\b(?:createHmac|timingSafeEqual)\b/.test(cleaned);
      const hasUnclampedQuerySqlOffset =
        /(?:req|request)\??\.query\b|\bsearchParams\b/.test(cleaned) &&
        /\bLIMIT\b/i.test(cleaned) &&
        /\bOFFSET\b/i.test(cleaned) &&
        /(?:\b(?:(?:req|request)\??\.query|searchParams\.get)\s*(?:\??\.\s*(?:limit|offset|page)\b|\(\s*['"`](?:limit|offset|page)['"`]\s*\))|\{[^{}\n]{0,120}\b(?:limit|offset|page)\b[^{}\n]{0,120}\}\s*=\s*(?:req|request)\??\.query\b)/.test(
          cleaned
        ) &&
        /\b(?:LIMIT\s+(?:\$\d+|\?|:[\w]+|\d+|\$\{[^{}\n]{1,80}\})\s+OFFSET\s+(?:\$\d+|\?|:[\w]+|\d+|\$\{[^{}\n]{1,80}\})|OFFSET\s+(?:\$\d+|\?|:[\w]+|\d+|\$\{[^{}\n]{1,80}\})\s+LIMIT\s+(?:\$\d+|\?|:[\w]+|\d+|\$\{[^{}\n]{1,80}\}))/i.test(
          cleaned
        ) &&
        !/\bMath\.min\s*\(/.test(cleaned);
      const hasUnclampedOrmPagination = hasUnclampedOrmOrQueryPagination(cleaned);
      if (hasUnsignedBase64Cursor || hasUnclampedQuerySqlOffset || hasUnclampedOrmPagination) {
        findings.push({
          ruleId: 'unsafe-pagination-cursor',
          brickId: 'pagination',
          importPath: `${TK_NS}/pagination`,
          severity: 'warn',
          message: `Unsigned base64 cursor or unclamped query/ORM pagination detected; use clampPageLimit, encodeCursor, decodeCursor, or buildKeysetPage from ${TK_NS}/pagination.`
        });
      }
    }
  }

  // 15. Unvalidated user-controlled outbound HTTP URL (SSRF)
  if (hasUnvalidatedOutboundSsrf(cleaned, isPython)) {
    findings.push({
      ruleId: 'unvalidated-outbound-ssrf',
      brickId: isPython ? 'python_security' : 'security',
      importPath: isPython ? `${PY_TK_NS}.security` : `${TK_NS}/security`,
      severity: 'warn',
      message: isPython
        ? `User-controlled outbound HTTP URL detected without SSRF IP validation; validate with validate_outbound_url from ${PY_TK_NS}.security.`
        : `User-controlled outbound HTTP URL detected without SSRF protection; use safeFetch or validateOutboundUrl from ${TK_NS}/security.`
    });
  }

  // 16. Hardcoded JWT/session/cookie secret fallback
  if (hasHardcodedAuthSecretFallback(cleaned, isPython)) {
    findings.push({
      ruleId: 'hardcoded-auth-secret-fallback',
      brickId: 'auth',
      importPath: `${TK_NS}/auth`,
      severity: 'warn',
      message: `Hardcoded JWT, session, or cookie secret fallback detected; require environment-injected secrets via createAuth from ${TK_NS}/auth.`
    });
  }

  const clean = findings.length === 0;
  const summary = clean
    ? `No hand-rolled boilerplate detected${normalizedPath ? ` in ${normalizedPath}` : ''}`
    : `Found ${findings.length} boilerplate anti-pattern(s)${normalizedPath ? ` in ${normalizedPath}` : ''}`;

  return okEnvelope('lego.catalog', summary, {
    filePath: normalizedPath,
    clean,
    findings
  });
}

/**
 * Compute deterministic Sealed Lego Brick coverage vs. unsealed boilerplate slop
 * across a file list or `{ [filePath]: code }` map.
 *
 * @param {Array<{ filePath?: string, path?: string, code?: string, content?: string }> | Record<string, string>} [files=[]]
 * @param {{ tokensPerSealedBrick?: number }} [options={}]
 */
export function scoreLegoBrickCoverage(files = [], options = {}) {
  const rawTokensPerBrick = Number(options?.tokensPerSealedBrick);
  const tokensPerBrick =
    Number.isFinite(rawTokensPerBrick) && rawTokensPerBrick >= 0 ? Math.round(rawTokensPerBrick) : 850;

  let normalizedEntries = [];
  if (Array.isArray(files)) {
    normalizedEntries = files.map((item) => ({
      filePath: String(item?.filePath ?? item?.path ?? ''),
      code: String(item?.code ?? item?.content ?? '')
    }));
  } else if (files && typeof files === 'object') {
    normalizedEntries = Object.entries(files).map(([filePath, code]) => ({
      filePath: String(filePath),
      code: String(code ?? '')
    }));
  }

  let cleanFiles = 0;
  let flaggedFiles = 0;
  let sealedFiles = 0;
  let sealedTouchpoints = 0;
  const allSealedIds = new Set();
  const recommendedIds = new Set();
  const findings = [];

  for (const entry of normalizedEntries) {
    const fullRaw = entry.code;
    const raw = fullRaw.length > MAX_AUDIT_CHARS ? fullRaw.slice(0, MAX_AUDIT_CHARS) : fullRaw;
    const normalizedPath = entry.filePath;
    const isExempt = Boolean(normalizedPath && CATALOG_AUDIT_EXEMPT_PATH_RE.test(normalizedPath));

    if (!isExempt) {
      const isPython = inferIsPythonSource(raw, normalizedPath);
      const cleaned = stripCommentLines(raw, { isPython });
      const brickIds = detectSealedBrickIdsForSource(cleaned, isPython);
      if (brickIds.length > 0) {
        sealedFiles += 1;
        sealedTouchpoints += brickIds.length;
        for (const id of brickIds) {
          allSealedIds.add(id);
        }
      }
    }

    const report = auditBoilerplateText(raw, normalizedPath);
    if (report.data.clean) {
      cleanFiles += 1;
    } else {
      flaggedFiles += 1;
      for (const item of report.data.findings) {
        if (item.brickId) {
          recommendedIds.add(item.brickId);
        }
        findings.push({
          filePath: normalizedPath,
          ...item
        });
      }
    }
  }

  const slopFindingCount = findings.length;
  const totalTouchpoints = sealedTouchpoints + slopFindingCount;
  const sealedCoverageRatio =
    totalTouchpoints === 0 ? 1 : Number((sealedTouchpoints / totalTouchpoints).toFixed(4));
  const breakerTripped = slopFindingCount > 0;
  const estimatedAuditTokensSaved = sealedTouchpoints * tokensPerBrick;
  const pct = Math.round(sealedCoverageRatio * 100);
  const summary = breakerTripped
    ? `Breaker tripped: ${slopFindingCount} slop finding(s) across ${flaggedFiles}/${normalizedEntries.length} file(s) (${pct}% sealed brick coverage)`
    : `Clean pass: ${pct}% sealed brick coverage across ${normalizedEntries.length} file(s) (${sealedTouchpoints} sealed brick import(s), ~${estimatedAuditTokensSaved} audit tokens saved)`;

  return okEnvelope('lego.catalog', summary, {
    scannedFiles: normalizedEntries.length,
    cleanFiles,
    flaggedFiles,
    sealedFiles,
    sealedBrickIds: [...allSealedIds].sort(),
    sealedTouchpoints,
    slopFindingCount,
    recommendedBrickIds: [...recommendedIds].sort(),
    sealedCoverageRatio,
    breakerTripped,
    estimatedAuditTokensSaved,
    findings
  });
}

/**
 * Strip `//`, `#`, and `/* ... * /` comments while preserving line numbers.
 *
 * @param {string} source
 * @returns {string}
 */
function stripCommentsPreservingLines(source = '') {
  const text = String(source || '');
  let withoutBlock = '';
  let idx = 0;
  const len = text.length;
  while (idx < len) {
    const openIdx = text.indexOf('/*', idx);
    if (openIdx === -1) {
      withoutBlock += text.slice(idx);
      break;
    }
    withoutBlock += text.slice(idx, openIdx);
    const closeIdx = text.indexOf('*/', openIdx + 2);
    if (closeIdx === -1) {
      withoutBlock += text.slice(openIdx).replace(/[^\r\n]/g, ' ');
      break;
    }
    withoutBlock += text.slice(openIdx, closeIdx + 2).replace(/[^\r\n]/g, ' ');
    idx = closeIdx + 2;
  }
  return withoutBlock.replace(/(?:\/\/|#).*$/gm, '');
}

/**
 * Check whether `rawPath` exists strictly inside `options.workspaceRoot` without probing
 * arbitrary host filesystem paths when `options.workspaceRoot` is omitted or escaped.
 *
 * @param {string} rawPath
 * @param {{ workspaceRoot?: string }} [options={}]
 * @returns {boolean}
 */
function existsInsideWorkspace(rawPath, options = {}) {
  const wsRaw = options && typeof options === 'object' ? options.workspaceRoot : undefined;
  if (typeof wsRaw !== 'string' || !wsRaw.trim()) {
    return false;
  }
  const resolvedRoot = path.resolve(wsRaw);
  const resolvedCandidate = path.resolve(resolvedRoot, rawPath);
  if (
    resolvedCandidate === resolvedRoot ||
    !resolvedCandidate.startsWith(resolvedRoot + path.sep)
  ) {
    return false;
  }
  try {
    if (!fs.existsSync(resolvedRoot) || !fs.existsSync(resolvedCandidate)) {
      return false;
    }
    const realRoot = fs.realpathSync(resolvedRoot);
    const realCandidate = fs.realpathSync(resolvedCandidate);
    if (realCandidate === realRoot || !realCandidate.startsWith(realRoot + path.sep)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Normalize browser-copied GitHub URLs (`/tree/<ref>/...`, `/blob/<ref>/<file>`,
 * `github.com/owner/repo`, `owner/repo`, `git@github.com:owner/repo.git`) while rejecting
 * traversal segments (`..`, `%2e%2e`), leading-hyphen option injection, reserved GitHub routes,
 * and malformed encodings.
 *
 * @param {unknown} rawInput
 * @param {{ workspaceRoot?: string }} [options={}]
 */
export function normalizeGitHubRepoInput(rawInput, options = {}) {
  const raw = String(rawInput ?? '').slice(0, 4096).trim();
  if (!raw) {
    return {
      isRemoteCandidate: false,
      candidateUrl: '',
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: '',
      hintedFile: '',
      invalidGitHubPath: false
    };
  }

  let candidateUrl = raw;
  let isRemoteCandidate = false;
  const strippedRaw = raw.length > 1 ? raw.replace(/\/+$/, '') : raw;

  if (strippedRaw.startsWith('-')) {
    return {
      isRemoteCandidate: true,
      candidateUrl: '',
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  const httpGitHubMatch = /^http:\/\/((?:www\.)?github\.com)(?=[/?#]|$)(.*)$/i.exec(strippedRaw);
  const scpMatch = /^git@([A-Za-z0-9.-]+):(.+)$/i.exec(strippedRaw);

  if (scpMatch) {
    isRemoteCandidate = true;
    candidateUrl = `https://${scpMatch[1].toLowerCase()}/${scpMatch[2].replace(/^\/+|\/+$/g, '')}`;
  } else if (/^ssh:\/\/(?:[^@/]+@)?([A-Za-z0-9.-]+)\/(.+)$/i.test(strippedRaw)) {
    const m = /^ssh:\/\/(?:[^@/]+@)?([A-Za-z0-9.-]+)\/(.+)$/i.exec(strippedRaw);
    isRemoteCandidate = true;
    candidateUrl = `https://${m[1].toLowerCase()}/${m[2].replace(/\/+$/g, '')}`;
  } else if (httpGitHubMatch) {
    isRemoteCandidate = true;
    candidateUrl = `https://${httpGitHubMatch[1].toLowerCase()}${httpGitHubMatch[2]}`;
  } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) {
    isRemoteCandidate = true;
    candidateUrl = strippedRaw;
  } else if (
    /^(?:www\.)?github\.com(?:\/.*)?$/i.test(strippedRaw) &&
    !existsInsideWorkspace(raw, options)
  ) {
    isRemoteCandidate = true;
    candidateUrl = `https://${strippedRaw}`;
  } else if (
    !strippedRaw.startsWith('.') &&
    !strippedRaw.startsWith('/') &&
    !strippedRaw.includes('\\') &&
    GITHUB_OWNER_REPO_RE.test(strippedRaw) &&
    !existsInsideWorkspace(raw, options)
  ) {
    const [segA, segB] = strippedRaw.split('/');
    const cleanSegB = segB.replace(/\.git$/i, '');
    if (segA !== '.' && segA !== '..' && segA !== '.git' && cleanSegB && cleanSegB !== '.' && cleanSegB !== '..') {
      isRemoteCandidate = true;
      candidateUrl = `https://github.com/${segA}/${cleanSegB}`;
    }
  }

  if (!isRemoteCandidate) {
    return {
      isRemoteCandidate: false,
      candidateUrl: raw,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: false
    };
  }

  let parsed;
  try {
    parsed = new URL(candidateUrl);
  } catch {
    return {
      isRemoteCandidate: true,
      candidateUrl,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  const hostLower = parsed.hostname.toLowerCase();
  if (parsed.protocol !== 'https:' || (hostLower !== 'github.com' && hostLower !== 'www.github.com')) {
    return {
      isRemoteCandidate: true,
      candidateUrl,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: false
    };
  }

  const rawPathPortion = raw.split(/[?#]/)[0];
  const hasDotTraversal = /(?:^|[/:\\])\.\.(?:[/\\]|$)|%2e%2e/i.test(rawPathPortion);
  const cleanPathname = parsed.pathname.replace(/\/+$/, '');
  let hasMalformedEncoding = false;
  const rawSegments = cleanPathname
    .replace(/^\/+/, '')
    .split('/')
    .filter(Boolean)
    .map((seg) => {
      try {
        return decodeURIComponent(seg);
      } catch {
        hasMalformedEncoding = true;
        return seg;
      }
    });

  const hasDecodedTraversal = rawSegments.some((seg) => {
    const subs = seg.split(/[/\\]/).filter(Boolean);
    return subs.length === 0 || subs.some((s) => s === '.' || s === '..' || s.includes('\0'));
  });

  if (
    hasDotTraversal ||
    hasMalformedEncoding ||
    hasDecodedTraversal ||
    rawSegments.length < 2 ||
    rawSegments.some((seg) => seg === '.' || seg === '..' || seg.includes('\\') || seg.includes('\0'))
  ) {
    return {
      isRemoteCandidate: true,
      candidateUrl: `https://${hostLower}${cleanPathname}`,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  const owner = rawSegments[0];
  const repo = rawSegments[1].replace(/\.git$/i, '');
  if (
    !owner ||
    !repo ||
    !GITHUB_SEGMENT_RE.test(owner) ||
    !GITHUB_SEGMENT_RE.test(repo) ||
    owner === '.git' ||
    repo === '.git' ||
    repo === '.' ||
    repo === '..' ||
    RESERVED_GITHUB_ROOTS.has(owner.toLowerCase())
  ) {
    return {
      isRemoteCandidate: true,
      candidateUrl: `https://${hostLower}${cleanPathname}`,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  if ((rawSegments[2] === 'blob' || rawSegments[2] === 'tree') && rawSegments[3]?.startsWith('-')) {
    return {
      isRemoteCandidate: true,
      candidateUrl: `https://${hostLower}${cleanPathname}`,
      repoSlug: null,
      cleanHttpsUrl: null,
      displayTarget: raw,
      hintedFile: '',
      invalidGitHubPath: true
    };
  }

  let hintedFile = '';
  if (rawSegments[2] === 'blob' && rawSegments.length >= 5) {
    const candidateHint = rawSegments
      .slice(4)
      .join('/')
      .replace(/\/+/g, '/')
      .replace(/^\/+|\/+$/g, '');
    if (
      candidateHint.startsWith('-') ||
      candidateHint.split('/').some((seg) => seg.startsWith('-'))
    ) {
      return {
        isRemoteCandidate: true,
        candidateUrl: `https://${hostLower}${cleanPathname}`,
        repoSlug: null,
        cleanHttpsUrl: null,
        displayTarget: raw,
        hintedFile: '',
        invalidGitHubPath: true
      };
    }
    hintedFile = candidateHint;
  }

  const repoSlug = `${owner}/${repo}`;
  return {
    isRemoteCandidate: true,
    candidateUrl: `https://github.com/${repoSlug}`,
    repoSlug,
    cleanHttpsUrl: `https://github.com/${repoSlug}.git`,
    displayTarget: `https://github.com/${repoSlug}`,
    hintedFile,
    invalidGitHubPath: false
  };
}

/**
 * Audit a single source file across PHP, Java, C#, Go, Ruby, Rust, Kotlin, JS/TS, or Python
 * for legacy security, SQLi, float-currency, SSRF, weak-crypto, unbounded-query, and Slop-Breaker
 * hazards, mapping each finding to its canonical replacement brick.
 *
 * @param {string} source
 * @param {string} filePath
 */
export function auditPolyglotSource(source = '', filePath = '') {
  const fullSource = String(source || '');
  const boundedSource = fullSource.length > MAX_AUDIT_CHARS ? fullSource.slice(0, MAX_AUDIT_CHARS) : fullSource;
  const normalizedPath = String(filePath || '');
  const ext = path.extname(normalizedPath).toLowerCase();
  const isPhp = ext === '.php' || (!ext && /^\s*<\?php\b/i.test(boundedSource));

  if (!isPhp && (JS_PY_EXTS.has(ext) || !ext)) {
    const slop = auditBoilerplateText(boundedSource, normalizedPath, { ignoreExempt: true });
    return (slop.data.findings || []).map((item) => ({
      filePath: normalizedPath,
      ...item
    }));
  }

  const cleaned = stripCommentsPreservingLines(boundedSource);
  const findings = [];

  const pushFinding = (ruleId, brickId, importPath, message) => {
    findings.push({
      filePath: normalizedPath,
      ruleId,
      brickId,
      importPath,
      severity: 'error',
      message
    });
  };

  if (isPhp) {
    if (
      /\b(?:round|number_format)\s*\([^;\n]{0,400}\$(?:this->)?[A-Za-z0-9_]*(?:price|amount|vat|tax|discount|fee|total|subtotal|cash|pos|tendered|balance)[A-Za-z0-9_]*/i.test(
        cleaned
      ) ||
      /\$(?:this->)?[A-Za-z0-9_]*(?:price|amount|vat|tax|discount|fee|total|subtotal)[A-Za-z0-9_]*\s*=\s*round\s*\(/i.test(
        cleaned
      )
    ) {
      pushFinding(
        'php-float-currency-math',
        'audit-log',
        `${TK_NS}/audit-log`,
        `Floating-point PHP currency rounding risks sub-cent batch drift; port to integer-cent largest-remainder allocation with ${TK_NS}/audit-log.`
      );
    }
    if (
      /["']\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"'\n]{0,400}\$[A-Za-z_]/i.test(cleaned) ||
      /\bmysqli_query\s*\([^;\n]{0,400}\$_(?:GET|POST|REQUEST)/i.test(cleaned)
    ) {
      pushFinding(
        'php-raw-sql-interpolation',
        'sqlite',
        `${TK_NS}/sqlite`,
        `Interpolated PHP variable inside SQL statement risks SQL injection; port to parameterized ${TK_NS}/sqlite or ${TK_NS}/pg queries.`
      );
    }
    if (
      /\bnew\s+PDO\s*\(/.test(cleaned) ||
      /\bmysqli_connect\s*\(/.test(cleaned) ||
      /\becho\b[^;\n]{0,400}->getMessage\s*\(\s*\)/.test(cleaned)
    ) {
      pushFinding(
        'php-per-request-pdo-or-sql-leak',
        'sqlite',
        `${TK_NS}/sqlite`,
        `Per-request PHP DB connection or raw PDOException HTML echo detected; centralize pooled DB access with ${TK_NS}/sqlite or ${TK_NS}/pg and ${TK_NS}/http.`
      );
    }
    if (/\$_(?:POST|GET|REQUEST)\s*\[/.test(cleaned)) {
      pushFinding(
        'php-unvalidated-superglobal-input',
        'schema',
        `${TK_NS}/schema`,
        `Untyped PHP $_POST/$_GET superglobal intake; validate payloads with ${TK_NS}/schema (s, validateSchema).`
      );
    }
    if (
      /\bsession_start\s*\(/.test(cleaned) ||
      /\bmcrypt_create_iv\s*\(/.test(cleaned) ||
      /\b(?:md5|sha1)\s*\(/.test(cleaned)
    ) {
      pushFinding(
        'php-legacy-session-or-weak-crypto',
        'auth',
        `${TK_NS}/auth`,
        `Stateful PHP session_start() or weak/deprecated crypto (mcrypt/md5/sha1) detected; port to stateless httpOnly JWT sessions via ${TK_NS}/auth.`
      );
    }
    if (
      /\$(?:password|passwd|db_pass|dbpass)\s*=\s*['"][^'"]+['"]/i.test(cleaned) ||
      /\bdefine\s*\(\s*['"]DB_PASS(?:WORD)?['"]\s*,\s*['"][^'"]+['"]\s*\)/i.test(cleaned)
    ) {
      pushFinding(
        'php-hardcoded-db-credentials',
        'config',
        `${TK_NS}/config`,
        `Hardcoded PHP database credentials in source; externalize configuration via ${TK_NS}/config (loadProjectConfig, envOr).`
      );
    }
    if (
      /\bSELECT\s+\*\s+FROM\s+[A-Za-z0-9_`]+(?:\s*;|\s*["'])/i.test(cleaned) &&
      !/\bLIMIT\b/i.test(cleaned)
    ) {
      pushFinding(
        'php-unbounded-table-scan',
        'pagination',
        `${TK_NS}/pagination`,
        `Unbounded SELECT * table scan without cursor limit; port list routes to ${TK_NS}/pagination (encodeCursor, paginateItems).`
      );
    }
    return findings;
  }

  if (POLYGLOT_ONLY_EXTS.has(ext)) {
    if (
      /\b(?:double|float)\s+[A-Za-z0-9_]*(?:price|amount|fee|tax|vat|total|subtotal|balance|discount|rate)[A-Za-z0-9_]*\b/i.test(
        cleaned
      ) ||
      /\b[A-Za-z0-9_]*(?:price|amount|fee|tax|vat|total|subtotal|balance)[A-Za-z0-9_]*\s*\.\s*round\s*\(\s*2\s*\)/i.test(
        cleaned
      )
    ) {
      pushFinding(
        'polyglot-float-currency-math',
        'audit-log',
        `${TK_NS}/audit-log`,
        `IEEE-754 float/double currency arithmetic risks sub-cent batch drift; port to integer-cent largest-remainder allocation with ${TK_NS}/audit-log.`
      );
    }
    if (
      /"\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\n]{0,400}"\s*\+/i.test(cleaned) ||
      /'\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^'\n]{0,400}'\s*\+/i.test(cleaned) ||
      /\b(?:fmt\.Sprintf|String\.format)\s*\(\s*["'`]\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i.test(
        cleaned
      ) ||
      /\$"\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\n]{0,400}\{/i.test(cleaned) ||
      /"\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"\n]{0,400}#\{/i.test(cleaned)
    ) {
      pushFinding(
        'polyglot-raw-sql-concat',
        'pg',
        `${TK_NS}/pg`,
        `Interpolated or concatenated SQL query string detected; port to parameterized ${TK_NS}/pg or ${TK_NS}/sqlite queries.`
      );
    }
    if (
      /\b(?:http\.(?:Get|Post|NewRequest)|new\s+HttpClient\s*\(|RestTemplate\b|WebClient\.create|Net::HTTP\.|URI\.open\s*\(|reqwest::get\s*\()/.test(
        cleaned
      )
    ) {
      pushFinding(
        'polyglot-unguarded-outbound-http',
        'security',
        `${TK_NS}/security`,
        `Direct outbound HTTP client call without DNS-pinned SSRF protection; port outbound calls to ${TK_NS}/security (safeFetch, validateOutboundUrl).`
      );
    }
    if (
      /\bMessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']\s*\)/i.test(cleaned) ||
      /\b(?:MD5|SHA1)\.Create\s*\(/i.test(cleaned) ||
      /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/.test(cleaned) ||
      /\bDigest::(?:MD5|SHA1)\b/.test(cleaned)
    ) {
      pushFinding(
        'polyglot-weak-crypto-digest',
        'auth',
        `${TK_NS}/auth`,
        `Legacy MD5/SHA-1 cryptographic digest detected; port authentication and token signing to ${TK_NS}/auth or SHA-256 HMAC.`
      );
    }
    if (
      /\bSELECT\s+\*\s+FROM\s+[A-Za-z0-9_.`"]+/i.test(cleaned) &&
      !/\b(?:LIMIT|TOP|FETCH\s+FIRST|Pageable)\b/i.test(cleaned)
    ) {
      pushFinding(
        'polyglot-unbounded-select-all',
        'pagination',
        `${TK_NS}/pagination`,
        `Unbounded SELECT * query without cursor/limit pagination; port list endpoints to ${TK_NS}/pagination.`
      );
    }
  }

  return findings;
}

function isSensitiveLocalDir(candidatePath) {
  const normalized = path.resolve(candidatePath).replace(/\\/g, '/');
  if (EXACT_SENSITIVE_ROOTS.has(normalized)) {
    return true;
  }
  for (const prefix of SENSITIVE_LOCAL_PREFIXES) {
    if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
      return true;
    }
  }
  for (const seg of normalized.split('/').filter(Boolean)) {
    if (SENSITIVE_SEGMENT_NAMES.has(seg.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * Scan a local directory across all 10 languages / 14 extensions, combining the 16 JS/TS/Python
 * Slop-Breaker rules with the 12 PHP & polyglot enterprise hazard rules.
 *
 * @param {string} targetDir
 * @param {{ maxFiles?: number, tool?: string }} [options={}]
 */
export function auditPolyglotRepository(targetDir, options = {}) {
  const safeTool =
    typeof options?.tool === 'string' && options.tool.trim()
      ? options.tool.trim()
      : 'polyglot.audit';
  if (!targetDir || typeof targetDir !== 'string' || !targetDir.trim()) {
    return errorEnvelope('INVALID_TARGET_DIR', 'targetDir must be a non-empty directory path.', null, safeTool);
  }

  const candidateRoot = path.resolve(targetDir.trim());
  if (isSensitiveLocalDir(candidateRoot)) {
    return errorEnvelope('PATH_BLOCKED', 'Scanning sensitive system or credential directories is forbidden.', null, safeTool);
  }

  let realRoot;
  try {
    const lstat = fs.lstatSync(candidateRoot);
    if (lstat.isSymbolicLink()) {
      return errorEnvelope('SYMLINK_ROOT_BLOCKED', 'Symbolic link root directories are rejected.', null, safeTool);
    }
    realRoot = fs.realpathSync(candidateRoot);
    if (!fs.statSync(realRoot).isDirectory()) {
      return errorEnvelope('NOT_A_DIRECTORY', 'targetDir must resolve to a directory.', null, safeTool);
    }
  } catch {
    return errorEnvelope('DIRECTORY_NOT_FOUND', 'Target directory does not exist.', null, safeTool);
  }

  if (isSensitiveLocalDir(realRoot)) {
    return errorEnvelope('PATH_BLOCKED', 'Resolved path targets a sensitive directory.', null, safeTool);
  }

  const maxFiles = Math.max(1, Math.min(Number(options?.maxFiles) || 200, 2000));
  const discovered = [];

  const walk = (curDir) => {
    if (discovered.length >= maxFiles) return;
    let entries;
    try {
      entries = fs.readdirSync(curDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (discovered.length >= maxFiles) break;
      if (entry.name.startsWith('.') || SKIPPED_DIRS.has(entry.name) || entry.isSymbolicLink()) continue;
      const full = path.join(curDir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!ALL_SCANNABLE_EXTS.has(ext)) continue;
        try {
          const st = fs.statSync(full);
          if (st.size <= 0 || st.size > 262_144) continue;
          const buf = fs.readFileSync(full);
          if (buf.subarray(0, 4096).includes(0)) continue;
          discovered.push({
            filePath: path.relative(realRoot, full).replace(/\\/g, '/'),
            ext,
            content: buf.toString('utf8')
          });
        } catch {
          /* Ignore unreadable file */
        }
      }
    }
  };

  walk(realRoot);

  const jsPyFiles = [];
  const polyFindings = [];

  for (const item of discovered) {
    if (item.ext === '.php' || POLYGLOT_ONLY_EXTS.has(item.ext)) {
      if (!CATALOG_AUDIT_EXEMPT_PATH_RE.test(item.filePath)) {
        polyFindings.push(...auditPolyglotSource(item.content, item.filePath));
      }
    } else {
      jsPyFiles.push({ filePath: item.filePath, content: item.content });
    }
  }

  const baseCoverage = scoreLegoBrickCoverage(jsPyFiles);
  const baseData = baseCoverage.data;
  const allFindings = [...(baseData.findings || []), ...polyFindings];
  const flaggedFiles = new Set(allFindings.map((f) => f.filePath));
  const recommendedBricks = new Set(baseData.recommendedBrickIds || []);
  for (const f of polyFindings) {
    if (f.brickId) recommendedBricks.add(f.brickId);
  }

  const totalTouchpoints = baseData.sealedTouchpoints + allFindings.length;
  const sealedCoverageRatio =
    totalTouchpoints === 0
      ? 1
      : Number((baseData.sealedTouchpoints / totalTouchpoints).toFixed(4));

  return okEnvelope(
    safeTool,
    `Scanned ${discovered.length} file(s) across polyglot workspace: ${allFindings.length} hazard/slop finding(s).`,
    {
      scannedFiles: discovered.length,
      cleanFiles: Math.max(0, discovered.length - flaggedFiles.size),
      flaggedFiles: flaggedFiles.size,
      sealedTouchpoints: baseData.sealedTouchpoints,
      slopFindingCount: allFindings.length,
      sealedCoverageRatio,
      breakerTripped: allFindings.length > 0,
      recommendedBrickIds: [...recommendedBricks].sort(),
      findings: allFindings
    }
  );
}

/**
 * Create the KruschStack Polyglot Audit & Lego Coverage Engine.
 *
 * @param {{ workspaceRoot?: string }} [options={}]
 */
export function createPolyglotAuditEngine({ workspaceRoot = process.cwd() } = {}) {
  const defaultRoot = path.resolve(workspaceRoot || process.cwd());

  return {
    auditSource: (source, filePath = '') => {
      const isObj = source && typeof source === 'object' && !Array.isArray(source);
      const rawSource = isObj ? String(source.source ?? source.code ?? '') : String(source ?? '');
      const rawPath = isObj
        ? String(source.filePath ?? source.file_path ?? filePath ?? '')
        : String(filePath ?? '');
      const findings = auditPolyglotSource(rawSource, rawPath);
      const recommendedBrickIds = [...new Set(findings.map((f) => f.brickId).filter(Boolean))].sort();
      return okEnvelope(
        'krusch_polyglot_audit_source',
        findings.length === 0
          ? `Clean pass: 0 polyglot/slop hazards in ${rawPath || '<inline>'}`
          : `Found ${findings.length} hazard/slop finding(s) in ${rawPath || '<inline>'}`,
        {
          filePath: rawPath,
          clean: findings.length === 0,
          findingCount: findings.length,
          recommendedBrickIds,
          findings
        }
      );
    },
    auditRepository: (targetDir = defaultRoot, opts = {}) => {
      if (targetDir && typeof targetDir === 'object' && !Array.isArray(targetDir)) {
        const dir = targetDir.targetDir || targetDir.target_dir || targetDir.path || defaultRoot;
        return auditPolyglotRepository(dir, {
          ...targetDir,
          maxFiles: targetDir.maxFiles ?? targetDir.max_files,
          ...opts
        });
      }
      return auditPolyglotRepository(targetDir || defaultRoot, opts);
    },
    normalizeRepoInput: (rawInput, opts = {}) => {
      const isObj = Boolean(rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput));
      const actualInput = isObj ? (rawInput.input ?? rawInput.repo ?? rawInput.url ?? '') : rawInput;
      const mergedOpts = isObj
        ? { workspaceRoot: defaultRoot, ...rawInput, ...(opts && typeof opts === 'object' ? opts : {}) }
        : { workspaceRoot: defaultRoot, ...(opts && typeof opts === 'object' ? opts : {}) };
      const norm = normalizeGitHubRepoInput(actualInput, mergedOpts);
      const valid = !norm.isRemoteCandidate || Boolean(norm.cleanHttpsUrl);
      if (valid) {
        return okEnvelope(
          'krusch_polyglot_normalize_repo',
          norm.cleanHttpsUrl
            ? `Normalized GitHub repository input to ${norm.cleanHttpsUrl}`
            : 'Normalized local repository input',
          norm
        );
      }
      return {
        ...errorEnvelope(
          'UNTRUSTED_REPO_INPUT',
          'Rejected untrusted or malformed remote repository input',
          norm,
          'krusch_polyglot_normalize_repo'
        ),
        data: norm
      };
    },
    scoreCoverage: scoreLegoBrickCoverage
  };
}
