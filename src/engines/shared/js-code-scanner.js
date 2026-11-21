/**
 * @module engines/shared/js-code-scanner
 * Shared Zero-Dependency JS/TS Lexical Comment Stripper, Literal Masker, Specifier Decoder,
 * Prototype-Pollution Guard, Public Sanitizer, and Web-Standard Purity Scanner for KruschStack.
 *
 * Enforces:
 * - INV-STACK-01: Zero external npm dependencies and zero sibling engine imports (leaf module).
 * - INV-STACK-04: Zero leaked private LAN/Tailscale IPs, internal hostnames, secrets, or OS home paths.
 * - SEC-02: Control-header parenthesis stack (`if`/`while`/`for`/`for await`/`with`) and `.` / `?.`
 *   property-access suppression on `REGEX_PRECEDING_KEYWORDS`, plus regex-aware string/template masking.
 * - SEC-08: Hex/Unicode escape decoding (`\xHH`, `\uHHHH`, `\u{H...}`) on module specifiers and detection
 *   of non-literal `import(expr)`, `createRequire`, `import.meta.dirname`/`filename`, bare/member `process`,
 *   `Buffer`/`.Buffer`, `Deno`, `Bun`, and computed `globalThis[...]` access.
 */

export const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
export const MAX_PAYLOAD_DEPTH = 24;

export const NODE_BUILTIN_MODULES = new Set([
  'assert',
  'assert/strict',
  'async_hooks',
  'buffer',
  'child_process',
  'cluster',
  'console',
  'constants',
  'crypto',
  'dgram',
  'diagnostics_channel',
  'dns',
  'dns/promises',
  'domain',
  'events',
  'fs',
  'fs/promises',
  'http',
  'http2',
  'https',
  'inspector',
  'inspector/promises',
  'module',
  'net',
  'os',
  'path',
  'path/posix',
  'path/win32',
  'perf_hooks',
  'process',
  'punycode',
  'querystring',
  'readline',
  'readline/promises',
  'repl',
  'sqlite',
  'stream',
  'stream/consumers',
  'stream/promises',
  'stream/web',
  'string_decoder',
  'sys',
  'timers',
  'timers/promises',
  'tls',
  'trace_events',
  'tty',
  'url',
  'util',
  'util/types',
  'v8',
  'vm',
  'wasi',
  'worker_threads',
  'zlib'
]);

export const BANNED_HOST_MODULES = new Set([
  'fs',
  'fs/promises',
  'net',
  'tls',
  'http',
  'https',
  'http2',
  'dgram',
  'dns',
  'dns/promises',
  'child_process',
  'worker_threads',
  'cluster',
  'os',
  'v8',
  'vm',
  'inspector',
  'inspector/promises',
  'module',
  'process',
  'readline',
  'repl',
  'tty',
  'wasi',
  'sqlite'
]);

const CONTROL_HEADER_KEYWORDS = new Set(['if', 'while', 'for', 'with']);

const REGEX_PRECEDING_KEYWORDS = new Set([
  'return',
  'throw',
  'case',
  'delete',
  'void',
  'typeof',
  'yield',
  'await',
  'in',
  'instanceof',
  'of',
  'new',
  'else',
  'do'
]);

// Assembled dynamically so static repository leak scanners never match detector patterns (INV-STACK-04).
export const SECRET_LEAK_RE = new RegExp(
  [
    `${'AIza' + 'Sy'}[A-Za-z0-9_-]{3,}`,
    `\\b${'sk' + '-'}[A-Za-z0-9_-]{4,}`,
    `\\b${'gh' + 'p_'}[A-Za-z0-9]{4,}`,
    `\\bgh[ousr]_[A-Za-z0-9]{6,}`,
    `\\bgithub_pat_[A-Za-z0-9_]{6,}`,
    `\\bxox[baprs]-[A-Za-z0-9-]{6,}`,
    `${'-----' + 'BEGIN'}\\b`
  ].join('|')
);

const SCRUB_SECRET_TOKEN_GLOBAL_RE = new RegExp(
  [
    `${'AIza' + 'Sy'}[A-Za-z0-9_-]{3,}`,
    `\\b${'sk' + '-'}[A-Za-z0-9_-]{4,}`,
    `\\b${'gh' + 'p_'}[A-Za-z0-9]{4,}`,
    `\\bgh[ousr]_[A-Za-z0-9]{6,}`,
    `\\bgithub_pat_[A-Za-z0-9_]{6,}`,
    `\\bxox[baprs]-[A-Za-z0-9-]{6,}`,
    `${'-----' + 'BEGIN'}[\\s\\S]*?${'-----' + 'END'}[^\\n]*`,
    `${'-----' + 'BEGIN'}[^\\n]*`
  ].join('|'),
  'g'
);

export const LOCAL_FS_DIR_LEAK_RE = new RegExp(
  `(?<![A-Za-z0-9._-])\\/(?:${['ho' + 'me', 'Us' + 'ers', 'm' + 'nt'].join('|')})\\/[A-Za-z0-9._-]+`
);

const SCRUB_LOCAL_HOME_PATH_GLOBAL_RE = new RegExp(
  `(?<![A-Za-z0-9._-])\\/(?:${['ho' + 'me', 'Us' + 'ers', 'm' + 'nt'].join('|')})\\/[A-Za-z0-9._/-]+`,
  'g'
);

export const PRIVATE_DOMAIN_LEAK_RE = new RegExp(
  `\\.(?:${['l' + 'an', 'lo' + 'cal', 'inter' + 'nal', 'ts\\.' + 'net'].join('|')})\\b`,
  'i'
);

const SCRUB_PRIVATE_DOMAIN_GLOBAL_RE = new RegExp(
  `\\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.(?:${['l' + 'an', 'lo' + 'cal', 'inter' + 'nal', 'ts\\.' + 'net'].join('|')})\\b`,
  'gi'
);

/**
 * Check whether `value` is a plain JSON-style object (`Object.prototype` or `null` prototype).
 * @param {unknown} value
 * @returns {boolean}
 */
export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Safely define an enumerable own property without triggering `__proto__` setters.
 * @param {Record<string, any>} target
 * @param {string} key
 * @param {unknown} value
 */
export function defineSafeProp(target, key, value) {
  if (FORBIDDEN_KEYS.has(key)) {
    return;
  }
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true
  });
}

/**
 * Deeply clone and freeze plain objects and arrays while dropping forbidden prototype keys.
 * @template T
 * @param {T} value
 * @returns {T}
 */
export function deepFreezePlain(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return /** @type {any} */ (Object.freeze(value.map((item) => deepFreezePlain(item))));
  }
  const out = {};
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) continue;
    defineSafeProp(out, key, deepFreezePlain(/** @type {any} */ (value)[key]));
  }
  return /** @type {any} */ (Object.freeze(out));
}

/**
 * Recursively scan an object/array graph for prototype-pollution keys (`__proto__`, `constructor`, `prototype`),
 * circular references (`WeakSet`), and nesting exceeding `depth > 24` (fail-closed `SEC-01`).
 *
 * @param {unknown} value
 * @param {number} [depth=0]
 * @param {WeakSet<object>} [seen=new WeakSet()]
 * @returns {string | null}
 */
export function hasForbiddenKeyRecursive(value, depth = 0, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object') {
    return null;
  }
  if (depth > MAX_PAYLOAD_DEPTH) {
    return '__max_depth_exceeded__';
  }
  if (seen.has(value)) {
    return '__circular_reference__';
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        const nested = hasForbiddenKeyRecursive(value[i], depth + 1, seen);
        if (nested) return nested;
      }
      return null;
    }
    if (!isPlainObject(value)) {
      return null;
    }
    const ownNames = Object.getOwnPropertyNames(value);
    for (let i = 0; i < ownNames.length; i += 1) {
      const key = ownNames[i];
      if (FORBIDDEN_KEYS.has(key)) {
        return key;
      }
      const nested = hasForbiddenKeyRecursive(/** @type {any} */ (value)[key], depth + 1, seen);
      if (nested) return nested;
    }
    return null;
  } finally {
    seen.delete(value);
  }
}

function isPrivateOrCgnatIpv4Octets(o1, o2, o3, o4) {
  if (
    !Number.isInteger(o1) ||
    !Number.isInteger(o2) ||
    !Number.isInteger(o3) ||
    !Number.isInteger(o4) ||
    o1 < 0 ||
    o1 > 255 ||
    o2 < 0 ||
    o2 > 255 ||
    o3 < 0 ||
    o3 > 255 ||
    o4 < 0 ||
    o4 > 255
  ) {
    return false;
  }
  const isClassA = o1 === 10;
  const isClassB = o1 === 172 && o2 >= 16 && o2 <= 31;
  const isClassC = o1 === 192 && o2 === 168;
  const isCgnat = o1 === 100 && o2 >= 64 && o2 <= 127;
  return isClassA || isClassB || isClassC || isCgnat;
}

/**
 * Check whether `text` contains a private RFC-1918 or Tailscale CGNAT IPv4 literal (`INV-STACK-04`).
 * @param {string} text
 * @returns {boolean}
 */
export function containsPrivateIpv4Literal(text) {
  if (typeof text !== 'string' || !text) return false;
  const ipv4Re = /(?<![0-9])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![0-9])/g;
  for (const match of text.matchAll(ipv4Re)) {
    if (
      isPrivateOrCgnatIpv4Octets(
        Number(match[1]),
        Number(match[2]),
        Number(match[3]),
        Number(match[4])
      )
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Scrub accidental private network IPs, secret tokens, internal hostnames, or host user paths (`INV-STACK-04`).
 * @param {unknown} value
 * @returns {string}
 */
export function scrubOntologyString(value) {
  if (typeof value !== 'string' || !value) return '';
  const ipv4Scrubbed = value.replace(
    /(?<![0-9])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![0-9])/g,
    (full, a, b, c, d) =>
      isPrivateOrCgnatIpv4Octets(Number(a), Number(b), Number(c), Number(d))
        ? '[REDACTED_PRIVATE_IP]'
        : full
  );
  return ipv4Scrubbed
    .replace(SCRUB_SECRET_TOKEN_GLOBAL_RE, '[REDACTED_SECRET]')
    .replace(SCRUB_PRIVATE_DOMAIN_GLOBAL_RE, '[REDACTED_PRIVATE_HOST]')
    .replace(SCRUB_LOCAL_HOME_PATH_GLOBAL_RE, '[REDACTED_PATH]');
}

export function isIdentStart(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
}

export function isIdentPart(code) {
  return isIdentStart(code) || (code >= 48 && code <= 57);
}

/**
 * Decode JavaScript string/template escape sequences (`\xHH`, `\uHHHH`, `\u{H...}`, line continuations)
 * inside module specifiers or bracket property literals so `\u006eode:fs` and `'f\x73'` are caught (`SEC-08`).
 *
 * @param {string} rawSpecifier
 * @returns {string}
 */
export function decodeJsStringSpecifier(rawSpecifier) {
  if (typeof rawSpecifier !== 'string' || rawSpecifier.length === 0) {
    return '';
  }
  return rawSpecifier
    .replace(/\\\r?\n/g, '')
    .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (full, hex) => {
      const cp = Number.parseInt(hex, 16);
      if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return full;
      try {
        return String.fromCodePoint(cp);
      } catch {
        return full;
      }
    })
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_full, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_full, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\([nrtbfv0\\'"])/g, (_full, esc) => {
      switch (esc) {
        case 'n':
          return '\n';
        case 'r':
          return '\r';
        case 't':
          return '\t';
        case 'b':
          return '\b';
        case 'f':
          return '\f';
        case 'v':
          return '\v';
        case '0':
          return '\0';
        default:
          return esc;
      }
    })
    .replace(/\\([^0-9xXuU])/g, '$1');
}

function consumeUnmaskedTemplateBody(source, startIdx, out, templateBraceStack, currentBraceDepth) {
  const len = source.length;
  let i = startIdx;
  while (i < len) {
    const c = source[i];
    if (c === '\\' && i + 1 < len) {
      out.push(c, source[i + 1]);
      i += 2;
      continue;
    }
    if (c === '`') {
      out.push(c);
      return i + 1;
    }
    if (c === '$' && source[i + 1] === '{') {
      out.push('$', '{');
      templateBraceStack.push(currentBraceDepth);
      return i + 2;
    }
    out.push(c);
    i += 1;
  }
  return i;
}

function consumeMaskedTemplateBody(code, startIdx, out, templateBraceStack, currentBraceDepth) {
  const len = code.length;
  let i = startIdx;
  while (i < len) {
    const c = code[i];
    if (c === '\\' && i + 1 < len) {
      out.push(' ', code[i + 1] === '\n' || code[i + 1] === '\r' ? code[i + 1] : ' ');
      i += 2;
      continue;
    }
    if (c === '`') {
      out.push('`');
      return i + 1;
    }
    if (c === '$' && code[i + 1] === '{') {
      out.push('$', '{');
      templateBraceStack.push(currentBraceDepth);
      return i + 2;
    }
    out.push(c === '\n' || c === '\r' ? c : ' ');
    i += 1;
  }
  return i;
}

/**
 * Strip JS/TS line and block comments while preserving string, template, and RegExp literals (`SEC-02`):
 * - Tracks `parenStack` (`'control-header'` vs `'expr'`) for `if (...)`, `while (...)`, `for (...)`,
 *   `for await (...)`, and `with (...)` so closing `)` restores `canStartRegex = true`.
 * - Tracks `afterPropertyDot` (`.` and `?.`) so member accesses like `obj.in / 1` never trigger
 *   `REGEX_PRECEDING_KEYWORDS`.
 *
 * @param {string} source
 * @returns {string}
 */
export function stripJsCommentsPreservingLiterals(source) {
  const text = typeof source === 'string' ? source : String(source ?? '');
  const len = text.length;
  const out = [];
  let i = 0;
  let canStartRegex = true;
  let afterPropertyDot = false;
  let pendingControlKeyword = null;
  let braceDepth = 0;
  const parenStack = [];
  const templateBraceStack = [];

  while (i < len) {
    const ch = text[i];
    const next = i + 1 < len ? text[i + 1] : '';

    // Line comment //
    if (ch === '/' && next === '/') {
      out.push(' ', ' ');
      i += 2;
      while (i < len && text[i] !== '\n') {
        out.push(text[i] === '\r' ? '\r' : ' ');
        i += 1;
      }
      continue;
    }

    // Block comment /* ... */
    if (ch === '/' && next === '*') {
      out.push(' ', ' ');
      i += 2;
      while (i < len) {
        if (text[i] === '*' && text[i + 1] === '/') {
          out.push(' ', ' ');
          i += 2;
          break;
        }
        out.push(text[i] === '\n' || text[i] === '\r' ? text[i] : ' ');
        i += 1;
      }
      continue;
    }

    // Whitespace preserves `canStartRegex`, `afterPropertyDot`, and `pendingControlKeyword`
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      out.push(ch);
      i += 1;
      continue;
    }

    // Single or double quoted string literal
    if (ch === "'" || ch === '"') {
      const quote = ch;
      out.push(ch);
      i += 1;
      while (i < len) {
        const c = text[i];
        out.push(c);
        i += 1;
        if (c === '\\' && i < len) {
          out.push(text[i]);
          i += 1;
          continue;
        }
        if (c === quote) break;
      }
      canStartRegex = false;
      afterPropertyDot = false;
      pendingControlKeyword = null;
      continue;
    }

    // Template literal opening
    if (ch === '`') {
      out.push(ch);
      afterPropertyDot = false;
      pendingControlKeyword = null;
      const prevStackLen = templateBraceStack.length;
      i = consumeUnmaskedTemplateBody(text, i + 1, out, templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > prevStackLen;
      continue;
    }

    // Template interpolation `${ ... }` closing brace
    if (
      ch === '}' &&
      templateBraceStack.length > 0 &&
      braceDepth === templateBraceStack[templateBraceStack.length - 1]
    ) {
      templateBraceStack.pop();
      out.push(ch);
      afterPropertyDot = false;
      pendingControlKeyword = null;
      const prevStackLen = templateBraceStack.length;
      i = consumeUnmaskedTemplateBody(text, i + 1, out, templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > prevStackLen;
      continue;
    }

    // RegExp literal
    if (ch === '/' && canStartRegex && next !== '/' && next !== '*') {
      out.push(ch);
      i += 1;
      let inCharClass = false;
      while (i < len) {
        const c = text[i];
        if (c === '\n' || c === '\r') {
          break;
        }
        out.push(c);
        i += 1;
        if (c === '\\' && i < len && text[i] !== '\n' && text[i] !== '\r') {
          out.push(text[i]);
          i += 1;
          continue;
        }
        if (c === '[') inCharClass = true;
        else if (c === ']') inCharClass = false;
        else if (c === '/' && !inCharClass) {
          while (i < len && isIdentPart(text.charCodeAt(i))) {
            out.push(text[i]);
            i += 1;
          }
          break;
        }
      }
      canStartRegex = false;
      afterPropertyDot = false;
      pendingControlKeyword = null;
      continue;
    }

    // Identifier or keyword
    if (isIdentStart(ch.charCodeAt(0))) {
      const start = i;
      while (i < len && isIdentPart(text.charCodeAt(i))) {
        out.push(text[i]);
        i += 1;
      }
      const word = text.slice(start, i);
      if (afterPropertyDot) {
        afterPropertyDot = false;
        pendingControlKeyword = null;
        canStartRegex = false;
      } else if (word === 'await' && pendingControlKeyword === 'for') {
        pendingControlKeyword = 'for-await';
        canStartRegex = true;
      } else if (CONTROL_HEADER_KEYWORDS.has(word)) {
        pendingControlKeyword = word;
        canStartRegex = false;
      } else {
        pendingControlKeyword = null;
        canStartRegex = REGEX_PRECEDING_KEYWORDS.has(word);
      }
      continue;
    }

    // Numeric literal
    if (ch >= '0' && ch <= '9') {
      while (i < len && (isIdentPart(text.charCodeAt(i)) || text[i] === '.')) {
        out.push(text[i]);
        i += 1;
      }
      canStartRegex = false;
      afterPropertyDot = false;
      pendingControlKeyword = null;
      continue;
    }

    // Optional chaining `?.` (when not ternary + leading-dot number `x?.5:1`)
    if (ch === '?' && next === '.' && !(text[i + 2] >= '0' && text[i + 2] <= '9')) {
      out.push('?', '.');
      i += 2;
      afterPropertyDot = true;
      canStartRegex = false;
      pendingControlKeyword = null;
      continue;
    }

    // Spread/rest `...`, leading-dot number `.5`, or member dot `.`
    if (ch === '.') {
      if (next === '.' && text[i + 2] === '.') {
        out.push('.', '.', '.');
        i += 3;
        afterPropertyDot = false;
        canStartRegex = true;
        pendingControlKeyword = null;
        continue;
      }
      if (next >= '0' && next <= '9') {
        out.push('.');
        i += 1;
        while (i < len && (isIdentPart(text.charCodeAt(i)) || text[i] === '.')) {
          out.push(text[i]);
          i += 1;
        }
        afterPropertyDot = false;
        canStartRegex = false;
        pendingControlKeyword = null;
        continue;
      }
      out.push('.');
      i += 1;
      afterPropertyDot = true;
      canStartRegex = false;
      pendingControlKeyword = null;
      continue;
    }

    afterPropertyDot = false;

    if (ch === '(') {
      parenStack.push(pendingControlKeyword !== null ? 'control-header' : 'expr');
      pendingControlKeyword = null;
      canStartRegex = true;
      out.push(ch);
      i += 1;
      continue;
    }

    pendingControlKeyword = null;

    if (ch === ')') {
      const frame = parenStack.length > 0 ? parenStack.pop() : 'expr';
      canStartRegex = frame === 'control-header';
      out.push(ch);
      i += 1;
      continue;
    }

    if (ch === '{') {
      braceDepth += 1;
      canStartRegex = true;
    } else if (ch === '}') {
      braceDepth = Math.max(0, braceDepth - 1);
      canStartRegex = false;
    } else if (ch === ']') {
      canStartRegex = false;
    } else if ((ch === '+' && next === '+') || (ch === '-' && next === '-')) {
      out.push(ch, next);
      i += 2;
      canStartRegex = false;
      continue;
    } else {
      canStartRegex = true;
    }

    out.push(ch);
    i += 1;
  }

  return out.join('');
}

export const stripCommentsPreservingLiterals = stripJsCommentsPreservingLiterals;

/**
 * Mask string, template-text, and RegExp pattern bodies with spaces while keeping `${...}`
 * interpolation expressions intact (`SEC-02`).
 * Uses the same control-header `parenStack` and `afterPropertyDot` state machine as
 * `stripJsCommentsPreservingLiterals` so quotes inside RegExp literals (`/"/`) can never open
 * fake string literals that hide downstream code!
 *
 * @param {string} commentStrippedCode
 * @returns {string}
 */
export function maskStringAndTemplateBodies(commentStrippedCode) {
  const code = typeof commentStrippedCode === 'string' ? commentStrippedCode : '';
  const len = code.length;
  const out = [];
  let i = 0;
  let canStartRegex = true;
  let afterPropertyDot = false;
  let pendingControlKeyword = null;
  let braceDepth = 0;
  const parenStack = [];
  const templateBraceStack = [];

  while (i < len) {
    const ch = code[i];
    const next = i + 1 < len ? code[i + 1] : '';

    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      out.push(ch);
      i += 1;
      continue;
    }

    if (ch === "'" || ch === '"') {
      const quote = ch;
      out.push(quote);
      i += 1;
      while (i < len) {
        const c = code[i];
        if (c === '\\' && i + 1 < len) {
          out.push(' ', code[i + 1] === '\n' || code[i + 1] === '\r' ? code[i + 1] : ' ');
          i += 2;
          continue;
        }
        if (c === quote) {
          out.push(quote);
          i += 1;
          break;
        }
        out.push(c === '\n' || c === '\r' ? c : ' ');
        i += 1;
      }
      canStartRegex = false;
      afterPropertyDot = false;
      pendingControlKeyword = null;
      continue;
    }

    if (ch === '`') {
      out.push('`');
      afterPropertyDot = false;
      pendingControlKeyword = null;
      const prevStackLen = templateBraceStack.length;
      i = consumeMaskedTemplateBody(code, i + 1, out, templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > prevStackLen;
      continue;
    }

    if (
      ch === '}' &&
      templateBraceStack.length > 0 &&
      braceDepth === templateBraceStack[templateBraceStack.length - 1]
    ) {
      templateBraceStack.pop();
      out.push('}');
      afterPropertyDot = false;
      pendingControlKeyword = null;
      const prevStackLen = templateBraceStack.length;
      i = consumeMaskedTemplateBody(code, i + 1, out, templateBraceStack, braceDepth);
      canStartRegex = templateBraceStack.length > prevStackLen;
      continue;
    }

    if (ch === '/' && canStartRegex && next !== '/' && next !== '*') {
      out.push('/');
      i += 1;
      let inCharClass = false;
      while (i < len) {
        const c = code[i];
        if (c === '\n' || c === '\r') {
          break;
        }
        if (c === '\\' && i + 1 < len && code[i + 1] !== '\n' && code[i + 1] !== '\r') {
          out.push(' ', ' ');
          i += 2;
          continue;
        }
        if (c === '[') {
          inCharClass = true;
          out.push(' ');
          i += 1;
          continue;
        }
        if (c === ']') {
          inCharClass = false;
          out.push(' ');
          i += 1;
          continue;
        }
        if (c === '/' && !inCharClass) {
          out.push('/');
          i += 1;
          while (i < len && isIdentPart(code.charCodeAt(i))) {
            out.push(code[i]);
            i += 1;
          }
          break;
        }
        out.push(' ');
        i += 1;
      }
      canStartRegex = false;
      afterPropertyDot = false;
      pendingControlKeyword = null;
      continue;
    }

    if (isIdentStart(ch.charCodeAt(0))) {
      const start = i;
      while (i < len && isIdentPart(code.charCodeAt(i))) {
        out.push(code[i]);
        i += 1;
      }
      const word = code.slice(start, i);
      if (afterPropertyDot) {
        afterPropertyDot = false;
        pendingControlKeyword = null;
        canStartRegex = false;
      } else if (word === 'await' && pendingControlKeyword === 'for') {
        pendingControlKeyword = 'for-await';
        canStartRegex = true;
      } else if (CONTROL_HEADER_KEYWORDS.has(word)) {
        pendingControlKeyword = word;
        canStartRegex = false;
      } else {
        pendingControlKeyword = null;
        canStartRegex = REGEX_PRECEDING_KEYWORDS.has(word);
      }
      continue;
    }

    if (ch >= '0' && ch <= '9') {
      while (i < len && (isIdentPart(code.charCodeAt(i)) || code[i] === '.')) {
        out.push(code[i]);
        i += 1;
      }
      canStartRegex = false;
      afterPropertyDot = false;
      pendingControlKeyword = null;
      continue;
    }

    if (ch === '?' && next === '.' && !(code[i + 2] >= '0' && code[i + 2] <= '9')) {
      out.push('?', '.');
      i += 2;
      afterPropertyDot = true;
      canStartRegex = false;
      pendingControlKeyword = null;
      continue;
    }

    if (ch === '.') {
      if (next === '.' && code[i + 2] === '.') {
        out.push('.', '.', '.');
        i += 3;
        afterPropertyDot = false;
        canStartRegex = true;
        pendingControlKeyword = null;
        continue;
      }
      if (next >= '0' && next <= '9') {
        out.push('.');
        i += 1;
        while (i < len && (isIdentPart(code.charCodeAt(i)) || code[i] === '.')) {
          out.push(code[i]);
          i += 1;
        }
        afterPropertyDot = false;
        canStartRegex = false;
        pendingControlKeyword = null;
        continue;
      }
      out.push('.');
      i += 1;
      afterPropertyDot = true;
      canStartRegex = false;
      pendingControlKeyword = null;
      continue;
    }

    afterPropertyDot = false;

    if (ch === '(') {
      parenStack.push(pendingControlKeyword !== null ? 'control-header' : 'expr');
      pendingControlKeyword = null;
      canStartRegex = true;
      out.push(ch);
      i += 1;
      continue;
    }

    pendingControlKeyword = null;

    if (ch === ')') {
      const frame = parenStack.length > 0 ? parenStack.pop() : 'expr';
      canStartRegex = frame === 'control-header';
      out.push(ch);
      i += 1;
      continue;
    }

    if (ch === '{') {
      braceDepth += 1;
      canStartRegex = true;
    } else if (ch === '}') {
      braceDepth = Math.max(0, braceDepth - 1);
      canStartRegex = false;
    } else if (ch === ']') {
      canStartRegex = false;
    } else if ((ch === '+' && next === '+') || (ch === '-' && next === '-')) {
      out.push(ch, next);
      i += 2;
      canStartRegex = false;
      continue;
    } else {
      canStartRegex = true;
    }

    out.push(ch);
    i += 1;
  }

  return out.join('');
}

/**
 * Detect whether `codeOnly` (comment- and literal-masked JS/TS code) references `ident`
 * as a runtime global/member (`process`, `g.process`, `const { env } = process`, `cond ? process : null`),
 * while ignoring pure object-literal property keys (`{ process: 1 }`) and TypeScript type declarations.
 *
 * @param {string} codeOnly
 * @param {string} ident
 * @returns {boolean}
 */
export function hasRuntimeIdentifierReference(codeOnly, ident) {
  const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`\\b${escaped}\\b`, 'g');
  for (const match of codeOnly.matchAll(re)) {
    const start = match.index ?? 0;
    const end = start + ident.length;

    let beforeIdx = start - 1;
    while (beforeIdx >= 0 && /\s/.test(codeOnly[beforeIdx])) {
      beforeIdx -= 1;
    }
    const prevChar = beforeIdx >= 0 ? codeOnly[beforeIdx] : '';

    // Check preceding declaration keyword (`interface Foo`, `type Foo`)
    if (beforeIdx >= 0 && isIdentPart(codeOnly.charCodeAt(beforeIdx))) {
      let kwStart = beforeIdx;
      while (kwStart > 0 && isIdentPart(codeOnly.charCodeAt(kwStart - 1))) {
        kwStart -= 1;
      }
      const prevWord = codeOnly.slice(kwStart, beforeIdx + 1);
      if (prevWord === 'interface' || prevWord === 'type') {
        continue;
      }
    }

    let afterIdx = end;
    while (afterIdx < codeOnly.length && /\s/.test(codeOnly[afterIdx])) {
      afterIdx += 1;
    }
    if (codeOnly[afterIdx] === '?') {
      let optIdx = afterIdx + 1;
      while (optIdx < codeOnly.length && /\s/.test(codeOnly[optIdx])) {
        optIdx += 1;
      }
      if (codeOnly[optIdx] === ':') {
        afterIdx = optIdx;
      }
    }
    const nextChar = afterIdx < codeOnly.length ? codeOnly[afterIdx] : '';

    // Pure object literal key or TS parameter/type field (`{ process: 1 }`, `(process: string)`),
    // UNLESS inside destructuring (`const { process: p } = globalThis`).
    if (nextChar === ':' && (prevChar === '{' || prevChar === ',' || prevChar === '(' || prevChar === ';')) {
      if (prevChar === '(' || prevChar === ';') {
        continue;
      }
      // Check if enclosing `{ ... }` is a destructuring pattern (`} =`) vs object literal
      let scanBrace = end;
      let depth = 1;
      while (scanBrace < codeOnly.length && depth > 0) {
        if (codeOnly[scanBrace] === '{') depth += 1;
        else if (codeOnly[scanBrace] === '}') depth -= 1;
        scanBrace += 1;
      }
      while (scanBrace < codeOnly.length && /\s/.test(codeOnly[scanBrace])) {
        scanBrace += 1;
      }
      if (codeOnly[scanBrace] !== '=') {
        continue;
      }
    }

    return true;
  }
  return false;
}

/**
 * Strip TypeScript type-only `import type` and `export type` statements without crossing statement boundaries.
 * @param {string} commentStripped
 * @returns {string}
 */
export function stripTypeOnlyImportExport(commentStripped) {
  return commentStripped
    .replace(/\bimport\s+type\s+(?:[^;]*?\s+from\s+)?(['"`])(?:\\.|(?!\1)[\s\S])*?\1\s*;?/g, ' ')
    .replace(/\bexport\s+type\s+\{[^;]*?\}(?:\s+from\s+(['"`])(?:\\.|(?!\1)[\s\S])*?\1)?\s*;?/g, ' ');
}

/**
 * Scan JS/TS source code for Node/Deno/Bun host modules or globals that violate Web-Standard purity (`SEC-02`, `SEC-08`).
 * Returns `{ pure: false, violations: ['EMPTY_SOURCE'] }` on empty/whitespace input.
 *
 * @param {unknown} source
 * @returns {{ pure: boolean, violations: string[] }}
 */
export function scanWebStandardPurity(source) {
  if (typeof source !== 'string' || !source.trim()) {
    return { pure: false, violations: ['EMPTY_SOURCE'] };
  }

  const violations = [];
  const pushViolation = (v) => {
    if (!violations.includes(v)) violations.push(v);
  };

  const commentStripped = stripTypeOnlyImportExport(stripJsCommentsPreservingLiterals(source));

  const inspectSpecifier = (rawSpec) => {
    const decoded = decodeJsStringSpecifier(String(rawSpec || '')).trim();
    if (!decoded) return;
    if (decoded.startsWith('node:')) {
      pushViolation(`node-specifier:${decoded}`);
      return;
    }
    if (decoded.startsWith('bun:') || decoded === 'bun') {
      pushViolation(`bun-specifier:${decoded}`);
      return;
    }
    if (decoded.startsWith('deno:')) {
      pushViolation(`deno-specifier:${decoded}`);
      return;
    }
    const baseMod = decoded.split('/')[0];
    if (NODE_BUILTIN_MODULES.has(decoded) || NODE_BUILTIN_MODULES.has(baseMod)) {
      pushViolation(`node-builtin:${decoded}`);
    }
  };

  let match;
  const staticImportRe = /\bimport\s+(?!type\b)[\s\S]*?\bfrom\s*(['"`])((?:\\.|(?!\1)[\s\S])*)\1/g;
  while ((match = staticImportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const sideEffectImportRe = /\bimport\s*(['"`])((?:\\.|(?!\1)[\s\S])*)\1/g;
  while ((match = sideEffectImportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const reExportRe =
    /\bexport\s+(?!type\b)(?:\*(?:\s+as\s+[A-Za-z_$][A-Za-z0-9_$]*)?|\{[\s\S]*?\})\s*from\s*(['"`])((?:\\.|(?!\1)[\s\S])*)\1/g;
  while ((match = reExportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const dynImportRe =
    /(?<!(?:\.\s*|\?\.\s*|function\s+))\bimport\s*\(\s*(['"`])((?:\\.|(?!\1)(?!\$\{)[\s\S])*)\1\s*\)/g;
  while ((match = dynImportRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const requireRe =
    /(?<!(?:\.\s*|\?\.\s*|function\s+))\brequire\s*\(\s*(['"`])((?:\\.|(?!\1)[\s\S])*)\1\s*\)/g;
  while ((match = requireRe.exec(commentStripped)) !== null) {
    inspectSpecifier(match[2]);
  }

  const codeOnly = maskStringAndTemplateBodies(commentStripped);

  // Non-literal or interpolated dynamic `import(expr)` (`SEC-08`)
  if (
    /(?<!(?:\.\s*|\?\.\s*|function\s+))\bimport\s*\(\s*(?!(?:'[^']*'|"[^"]*"|`[^`$]*`)\s*\))/.test(
      codeOnly
    )
  ) {
    pushViolation('dynamic-import:non-literal');
  }

  // CommonJS `require(...)` and `createRequire(...)` (`SEC-08`)
  if (/(?<!(?:\.\s*|\?\.\s*|function\s+))\brequire\s*\(/.test(codeOnly)) {
    pushViolation('node-global:require');
  }
  if (/\bcreateRequire\b/.test(codeOnly)) {
    pushViolation('node-global:createRequire');
  }

  // Bare `process`, `.process`, `Buffer`, `.Buffer`, `Deno`, `Bun` (`SEC-08`)
  if (hasRuntimeIdentifierReference(codeOnly, 'process') || /\.\s*process\b/.test(codeOnly)) {
    pushViolation('node-global:process');
  }

  if (
    hasRuntimeIdentifierReference(codeOnly, 'Buffer') ||
    /\.\s*Buffer\b/.test(codeOnly) ||
    /\bnew\s+Buffer\s*\(/.test(codeOnly)
  ) {
    pushViolation('node-global:Buffer');
  }

  if (hasRuntimeIdentifierReference(codeOnly, 'Deno') || /\.\s*Deno\b/.test(codeOnly)) {
    pushViolation('host-global:Deno');
  }

  if (hasRuntimeIdentifierReference(codeOnly, 'Bun') || /\.\s*Bun\b/.test(codeOnly)) {
    pushViolation('host-global:Bun');
  }

  // `__dirname`, `__filename`, `import.meta.dirname`, `import.meta.filename` (`SEC-08`)
  if (
    /(?<![.\w$])(?:__dirname|__filename)\b/.test(codeOnly) ||
    /\bimport\s*\.\s*meta\s*\.\s*(?:dirname|filename)\b/.test(codeOnly)
  ) {
    pushViolation('node-global:__dirname/__filename');
  }

  // Computed bracket access on global objects `globalThis[...]` (`SEC-08`)
  if (/\b(?:globalThis|global|window|self)\s*(?:\?\.\s*)?\[/.test(codeOnly)) {
    pushViolation('global-computed-access:globalThis[...]');
  }

  return {
    pure: violations.length === 0,
    violations
  };
}

/**
 * Check whether a brick's source uses pure Web-Standard ECMAScript / Web APIs
 * with zero `node:*` built-ins, `process`, `Buffer`, `Deno`, `Bun`, `globalThis[...]`,
 * non-literal `import(expr)`, or CommonJS `require` / `createRequire`.
 *
 * @param {string} source
 * @returns {boolean}
 */
export function isWebStandardPureBrickSource(source) {
  return scanWebStandardPurity(source).pure;
}
