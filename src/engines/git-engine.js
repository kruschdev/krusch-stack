/**
 * @module engines/git-engine
 * Tier 2A: Codebase Structure, AST Symbols & Call Graph (krusch-git).
 * Enforces INV-GIT-01 (comment/string-masked AST brace matching),
 * INV-GIT-02 (atomic per-file symbol/edge replacement on re-index),
 * INV-STACK-07 (external-content Porter FTS5 + lazy Top-K snippet hydration), and
 * INV-STACK-09 (gated 2-hop git_edges call-graph bridging, limit_tokens & unattested_query_identifiers).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';
import {
  stemToken,
  estimateTokens,
  splitIdentifierSubtokens,
  extractCodeShapeIdentifiers,
  buildFts5MatchQuery,
  STOP_WORDS
} from './context-lexical.js';

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  '.krusch-stack',
  'dist',
  'build',
  'coverage',
  '.next',
  '.cache',
  '__pycache__'
]);

const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.java', '.md']);

const CALL_STOPWORDS = new Set([
  'if',
  'for',
  'while',
  'switch',
  'catch',
  'function',
  'return',
  'typeof',
  'instanceof',
  'await',
  'new',
  'super',
  'import',
  'export',
  'from',
  'delete',
  'void',
  'throw',
  'case',
  'Number',
  'String',
  'Boolean',
  'Object',
  'Array',
  'Set',
  'Map',
  'Promise',
  'Error',
  'RegExp',
  'Math',
  'JSON',
  'Date',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite'
]);

const SHORT_QUERY_FILLERS = new Set([
  'a', 'an', 'as', 'at', 'be', 'by', 'do', 'if', 'in',
  'is', 'it', 'no', 'of', 'on', 'or', 'so', 'to', 'up'
]);

function isQueryStopword(tok) {
  return STOP_WORDS.has(tok) || SHORT_QUERY_FILLERS.has(tok);
}

/**
 * Expand a lowercase token into its primary morphological stem plus safe derivational roots (>= 5 chars)
 * so inflections like `validators` <-> `validate`/`validation` and `rollups` <-> `rollup` align cleanly.
 * @param {string} token
 * @returns {string[]}
 */
function expandTokenStems(token) {
  const w = String(token ?? '').toLowerCase();
  if (!w) return [];
  const primary = stemToken(w);
  const out = new Set([w, primary]);

  if (w.includes('_')) {
    const collapsed = w.replace(/_/g, '');
    if (collapsed.length >= 2) {
      out.add(collapsed);
      out.add(stemToken(collapsed));
    }
  }

  if (primary.endsWith('ation') && primary.length - 5 >= 5) {
    out.add(primary.slice(0, -5));
  }
  if (primary.endsWith('ion') && primary.length - 3 >= 5) {
    out.add(primary.slice(0, -3));
  }
  if (primary.endsWith('ator') && primary.length - 4 >= 5) {
    out.add(primary.slice(0, -4));
    out.add(primary.slice(0, -2));
  } else if ((primary.endsWith('or') || primary.endsWith('er')) && primary.length - 2 >= 5) {
    out.add(primary.slice(0, -2));
  }

  return [...out];
}

/**
 * Collect deduplicated lowercase identifier sub-tokens across any text or identifier string.
 * @param {string} text
 * @returns {string[]}
 */
function collectSubtokens(text) {
  const raw = String(text ?? '');
  if (!raw) return [];
  const seen = new Set();
  const out = [];

  for (const chunk of raw.split(/[^A-Za-z0-9_$]+/)) {
    if (!chunk) continue;
    const subtokens = splitIdentifierSubtokens(chunk);
    if (Array.isArray(subtokens)) {
      for (const sub of subtokens) {
        const lower = String(sub ?? '').toLowerCase();
        if (lower && !seen.has(lower)) {
          seen.add(lower);
          out.push(lower);
        }
      }
    }
  }

  return out;
}

/**
 * Build a Set of sub-tokens and morphological stems for fast O(1) lexical matching.
 * @param {string} text
 * @returns {Set<string>}
 */
function buildStemSet(text) {
  const stems = new Set();
  for (const sub of collectSubtokens(text)) {
    for (const s of expandTokenStems(sub)) {
      stems.add(s);
    }
  }
  return stems;
}

/**
 * Estimate token usage for a hydrated symbol search result row.
 * @param {object} row
 * @returns {number}
 */
function estimateSymbolRowTokens(row) {
  const header = `${row.file_path || ''}:${row.symbol_name || ''} ${row.signature || ''}`;
  const full = row.snippet ? `${header}\n${row.snippet}` : header;
  return Math.max(1, estimateTokens(full));
}

/**
 * Format a winning symbol candidate into the canonical semanticSearch row shape.
 * @param {object} row
 * @param {string} snippet
 * @returns {object}
 */
function formatSymbolResultRow(row, snippet) {
  const formatted = {
    repo_name: row.repo_name,
    file_path: row.file_path,
    symbol_name: row.symbol_name,
    symbol_type: row.symbol_type,
    signature: row.signature,
    start_line: row.start_line,
    end_line: row.end_line,
    symbol_hash: row.symbol_hash,
    snippet: String(snippet ?? ''),
    score: row.score
  };
  if (row.bridge_hop) {
    formatted.bridge_hop = true;
    formatted.bridge_via = row.bridge_via;
  }
  return formatted;
}

/**
 * Compute SHA-256 hex digest.
 * @param {string} text
 * @returns {string}
 */
function sha256(text) {
  return crypto.createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex');
}

/**
 * INV-GIT-01: Mask comments, regex literals, and string/template literals with spaces
 * while preserving every newline and exact character offset.
 * @param {string} source
 * @param {{ maskStrings?: boolean, allowHashComment?: boolean }} [options]
 * @returns {string}
 */
export function maskCodePreservingNewlines(source, options = {}) {
  const { maskStrings = true, allowHashComment = false } = options || {};
  const input = String(source ?? '');
  const out = new Array(input.length);
  let i = 0;
  const len = input.length;
  let prevNonSpace = '';

  while (i < len) {
    const ch = input[i];
    const next = i + 1 < len ? input[i + 1] : '';

    // Single-line hash comment # (Python / Shell)
    if (allowHashComment && ch === '#') {
      out[i] = ' ';
      i += 1;
      while (i < len && input[i] !== '\n') {
        out[i] = input[i] === '\r' ? '\r' : ' ';
        i += 1;
      }
      continue;
    }

    // Single-line comment //
    if (ch === '/' && next === '/') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      while (i < len && input[i] !== '\n') {
        out[i] = input[i] === '\r' ? '\r' : ' ';
        i += 1;
      }
      continue;
    }

    // Block comment /* ... */
    if (ch === '/' && next === '*') {
      out[i] = ' ';
      out[i + 1] = ' ';
      i += 2;
      while (i < len) {
        if (input[i] === '*' && i + 1 < len && input[i + 1] === '/') {
          out[i] = ' ';
          out[i + 1] = ' ';
          i += 2;
          break;
        }
        out[i] = input[i] === '\n' || input[i] === '\r' ? input[i] : ' ';
        i += 1;
      }
      continue;
    }

    // Single-line regex literal /.../
    if (
      ch === '/' &&
      next !== '/' &&
      next !== '*' &&
      next !== ' ' &&
      next !== '\n' &&
      (!prevNonSpace || '=(,:;!&|?{}[~+-*%<>^'.includes(prevNonSpace))
    ) {
      let j = i + 1;
      let inCharClass = false;
      let foundClose = false;
      while (j < len && input[j] !== '\n' && input[j] !== '\r') {
        if (input[j] === '\\') {
          j += 2;
          continue;
        }
        if (input[j] === '[') inCharClass = true;
        else if (input[j] === ']') inCharClass = false;
        else if (input[j] === '/' && !inCharClass) {
          foundClose = true;
          break;
        }
        j += 1;
      }
      if (foundClose) {
        while (i <= j) {
          out[i] = maskStrings ? ' ' : input[i];
          i += 1;
        }
        prevNonSpace = '/';
        continue;
      }
    }

    // String or template literal: ', ", `
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      out[i] = maskStrings ? ' ' : ch;
      i += 1;
      while (i < len) {
        const c = input[i];
        if (c === '\\') {
          out[i] = maskStrings ? ' ' : c;
          if (i + 1 < len) {
            out[i + 1] = maskStrings
              ? (input[i + 1] === '\n' || input[i + 1] === '\r' ? input[i + 1] : ' ')
              : input[i + 1];
            i += 2;
          } else {
            i += 1;
          }
          continue;
        }
        if (c === quote) {
          out[i] = maskStrings ? ' ' : c;
          i += 1;
          break;
        }
        out[i] = maskStrings ? (c === '\n' || c === '\r' ? c : ' ') : c;
        i += 1;
      }
      prevNonSpace = quote;
      continue;
    }

    out[i] = ch;
    if (ch !== ' ' && ch !== '\t' && ch !== '\n' && ch !== '\r') {
      prevNonSpace = ch;
    }
    i += 1;
  }

  return out.join('');
}

/**
 * Find the matching closing brace index in a masked source string starting at openBraceIndex.
 * @param {string} maskedSource
 * @param {number} openBraceIndex
 * @returns {number}
 */
function findMatchingBrace(maskedSource, openBraceIndex) {
  let depth = 0;
  for (let i = openBraceIndex; i < maskedSource.length; i += 1) {
    const ch = maskedSource[i];
    if (ch === '{') {
      depth += 1;
    } else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        return i;
      }
    }
  }
  return Math.max(openBraceIndex, maskedSource.length - 1);
}

/**
 * Find the matching closing parenthesis index in a masked source string starting at openParenIndex.
 * @param {string} maskedSource
 * @param {number} openParenIndex
 * @returns {number}
 */
function findMatchingParen(maskedSource, openParenIndex) {
  let depth = 0;
  for (let i = openParenIndex; i < maskedSource.length; i += 1) {
    const ch = maskedSource[i];
    if (ch === '(') {
      depth += 1;
    } else if (ch === ')') {
      depth -= 1;
      if (depth === 0) {
        return i;
      }
    }
  }
  return -1;
}

/**
 * Build an array of 0-based character offsets for each line start.
 * @param {string} source
 * @returns {number[]}
 */
function buildLineOffsets(source) {
  const offsets = [0];
  for (let i = 0; i < source.length; i += 1) {
    if (source[i] === '\n') {
      offsets.push(i + 1);
    }
  }
  return offsets;
}

/**
 * Convert a 0-based character offset to a 1-based line number using binary search.
 * @param {number[]} lineOffsets
 * @param {number} offset
 * @returns {number}
 */
function offsetToLine(lineOffsets, offset) {
  let low = 0;
  let high = lineOffsets.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    if (lineOffsets[mid] <= offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return Math.max(1, high + 1);
}

/**
 * Extract outbound function call identifiers from a masked symbol body.
 * @param {string} maskedBody
 * @param {string} selfSymbolName
 * @returns {string[]}
 */
function extractCalledSymbols(maskedBody, selfSymbolName) {
  const called = new Set();
  const callRegex = /\b([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of maskedBody.matchAll(callRegex)) {
    const name = match[1];
    if (!name || name === selfSymbolName || CALL_STOPWORDS.has(name)) {
      continue;
    }
    called.add(name);
  }
  return [...called];
}

/**
 * Extract symbols and outbound call edges from JS/TS source code using INV-GIT-01.
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
function parseJsTsSymbols(source) {
  const masked = maskCodePreservingNewlines(source);
  const lineOffsets = buildLineOffsets(source);
  const lines = source.split(/\r?\n/);
  const symbols = [];
  const edges = [];
  const seenKeys = new Set();

  function recordSymbol(symbolName, type, declStartIndex, openBraceIndex) {
    const closeBraceIndex = findMatchingBrace(masked, openBraceIndex);
    const startLine = offsetToLine(lineOffsets, declStartIndex);
    const endLine = offsetToLine(lineOffsets, closeBraceIndex);
    const key = `${symbolName}:${startLine}`;
    if (seenKeys.has(key)) return;
    seenKeys.add(key);

    const rawSignature = source
      .slice(declStartIndex, openBraceIndex)
      .replace(/\s+/g, ' ')
      .trim();
    const snippet = lines.slice(startLine - 1, Math.min(endLine, startLine + 24)).join('\n');
    const fullBody = source.slice(declStartIndex, closeBraceIndex + 1);
    const maskedBody = masked.slice(openBraceIndex + 1, closeBraceIndex);

    symbols.push({
      symbol_name: symbolName,
      symbol_type: type,
      signature: rawSignature,
      start_line: startLine,
      end_line: endLine,
      symbol_hash: sha256(fullBody),
      snippet
    });

    const callees = extractCalledSymbols(maskedBody, symbolName);
    for (const callee of callees) {
      edges.push({
        from_symbol: symbolName,
        to_symbol: callee,
        edge_type: 'calls'
      });
    }
  }

  // 1. Function declarations (supports nested parens/destructuring in default args)
  const fnHeadRegex = /(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/g;
  for (const match of masked.matchAll(fnHeadRegex)) {
    const symbolName = match[1];
    const openParenIndex = match.index + match[0].length - 1;
    const closeParenIndex = findMatchingParen(masked, openParenIndex);
    if (closeParenIndex < 0) continue;
    const afterParen = masked.slice(closeParenIndex + 1, closeParenIndex + 120);
    const braceRel = afterParen.match(/^\s*(?::[^{;]+)?\{/);
    if (!braceRel) continue;
    const openBraceIndex = closeParenIndex + 1 + braceRel[0].length - 1;
    recordSymbol(symbolName, 'function', match.index, openBraceIndex);
  }

  // 2. Class declarations
  const classRegex = /(?:export\s+(?:default\s+)?)?class\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+[A-Za-z0-9_$.]+)?\s*\{/g;
  for (const match of masked.matchAll(classRegex)) {
    const symbolName = match[1];
    const openBraceIndex = match.index + match[0].length - 1;
    recordSymbol(symbolName, 'class', match.index, openBraceIndex);
  }

  // 3. Const/let/var assigned arrow or function expressions
  const varFnHeadRegex = /(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\*?\s*\(|\()/g;
  for (const match of masked.matchAll(varFnHeadRegex)) {
    const symbolName = match[1];
    const openParenIndex = match.index + match[0].length - 1;
    const closeParenIndex = findMatchingParen(masked, openParenIndex);
    if (closeParenIndex < 0) continue;
    const afterParen = masked.slice(closeParenIndex + 1, closeParenIndex + 120);
    const braceRel = afterParen.match(/^\s*(?::[^={;]+)?(?:\s*=>)?\s*\{/);
    if (!braceRel) continue;
    const openBraceIndex = closeParenIndex + 1 + braceRel[0].length - 1;
    recordSymbol(symbolName, 'function', match.index, openBraceIndex);
  }

  symbols.sort((a, b) => a.start_line - b.start_line);
  return { symbols, edges };
}

/**
 * Extract symbols and call edges from Python source code.
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
function parsePythonSymbols(source) {
  const lines = source.split(/\r?\n/);
  const symbols = [];
  const edges = [];
  const declRegex = /^(\s*)(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)\s*(?:\(([^)]*)\))?\s*:/;

  for (let idx = 0; idx < lines.length; idx += 1) {
    const match = lines[idx].match(declRegex);
    if (!match) continue;

    const indent = match[1].length;
    const kind = match[2] === 'class' ? 'class' : 'function';
    const symbolName = match[3];
    const startLine = idx + 1;
    let endLine = startLine;

    for (let j = idx + 1; j < lines.length; j += 1) {
      const line = lines[j];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }
      const currentIndent = line.match(/^(\s*)/)[1].length;
      if (currentIndent <= indent) {
        break;
      }
      endLine = j + 1;
    }

    const bodyLines = lines.slice(startLine - 1, endLine);
    const bodyText = bodyLines.join('\n');
    const snippet = bodyLines.slice(0, 25).join('\n');

    symbols.push({
      symbol_name: symbolName,
      symbol_type: kind,
      signature: lines[idx].trim().replace(/:$/, ''),
      start_line: startLine,
      end_line: endLine,
      symbol_hash: sha256(bodyText),
      snippet
    });

    const callees = extractCalledSymbols(bodyLines.slice(1).join('\n'), symbolName);
    for (const callee of callees) {
      edges.push({
        from_symbol: symbolName,
        to_symbol: callee,
        edge_type: 'calls'
      });
    }
  }

  return { symbols, edges };
}

/**
 * Extract Markdown heading sections as structural symbols.
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
function parseMarkdownSymbols(source) {
  const lines = source.split(/\r?\n/);
  const headings = [];

  for (let idx = 0; idx < lines.length; idx += 1) {
    const match = lines[idx].match(/^(#{1,6})\s+(.+?)\s*$/);
    if (match) {
      headings.push({
        level: match[1].length,
        title: match[2].trim(),
        line: idx + 1,
        raw: lines[idx].trim()
      });
    }
  }

  const symbols = headings.map((h, i) => {
    let endLine = lines.length;
    for (let j = i + 1; j < headings.length; j += 1) {
      if (headings[j].level <= h.level) {
        endLine = headings[j].line - 1;
        break;
      }
    }
    const sectionLines = lines.slice(h.line - 1, endLine);
    return {
      symbol_name: h.title,
      symbol_type: 'section',
      signature: h.raw,
      start_line: h.line,
      end_line: Math.max(h.line, endLine),
      symbol_hash: sha256(sectionLines.join('\n')),
      snippet: sectionLines.slice(0, 20).join('\n')
    };
  });

  return { symbols, edges: [] };
}

const JAVA_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'try', 'catch', 'finally',
  'synchronized', 'return', 'new', 'throw', 'throws', 'super', 'this', 'assert'
]);

/**
 * Extract Java classes, interfaces, annotations (@interface), enums, records, methods,
 * constructors, static/standard import edges, and outbound call edges (krusch-git v1.2.3 parity).
 * @param {string} source
 * @returns {{ symbols: Array<object>, edges: Array<object> }}
 */
export function parseJavaSymbols(source) {
  const noComments = maskCodePreservingNewlines(source, { maskStrings: false });
  const masked = maskCodePreservingNewlines(source, { maskStrings: true });
  const lineOffsets = buildLineOffsets(source);
  const lines = source.split(/\r?\n/);
  const symbols = [];
  const edges = [];
  const seenSymbolKeys = new Set();
  const seenEdgeKeys = new Set();

  function addEdge(fromSymbol, toSymbol, edgeType) {
    if (!fromSymbol || !toSymbol || fromSymbol === toSymbol) return;
    const key = `${fromSymbol}->${toSymbol}:${edgeType}`;
    if (seenEdgeKeys.has(key)) return;
    seenEdgeKeys.add(key);
    edges.push({
      from_symbol: fromSymbol,
      to_symbol: toSymbol,
      edge_type: edgeType
    });
  }

  // 1. Java imports: import a.b.Foo; or import static a.b.Owner.member;
  const importedSymbols = [];
  const importRegex = /(?:^|\n)[ \t]*import\s+(static\s+)?([a-zA-Z0-9_.*$]+)\s*;/g;
  for (const match of noComments.matchAll(importRegex)) {
    const isStatic = Boolean(match[1]);
    const targetPath = match[2].trim();
    const segments = targetPath.split('.').filter((s) => s && s !== '*');
    if (segments.length > 0) {
      const leaf = segments[segments.length - 1];
      importedSymbols.push(leaf);
      if (isStatic && segments.length >= 2) {
        const ownerType = segments[segments.length - 2];
        if (/^[A-Z]/.test(ownerType)) {
          importedSymbols.push(ownerType);
          importedSymbols.push(`${ownerType}.${leaf}`);
        }
      }
    }
  }

  // 2. Java Classes, Interfaces, Annotations (@interface), Enums, and Records
  const typeScopes = [];
  const typeRegex = /(?:^|\n)[ \t]*(?:@[a-zA-Z0-9_.]+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed|strictfp)\s+)*(@\s*interface|class|interface|enum|record)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)[^{;]*\{/g;
  for (const match of masked.matchAll(typeRegex)) {
    const kind = match[1].replace(/\s+/g, '');
    const typeName = match[2];
    const declStartIdx = match.index + (match[0].startsWith('\n') ? 1 : 0);
    const openBraceIdx = match.index + match[0].length - 1;
    const closeBraceIdx = findMatchingBrace(masked, openBraceIdx);
    const startLine = offsetToLine(lineOffsets, declStartIdx);
    const endLine = offsetToLine(lineOffsets, closeBraceIdx);
    const symKey = `${typeName}:${startLine}`;
    if (seenSymbolKeys.has(symKey)) continue;
    seenSymbolKeys.add(symKey);

    const symType = kind === 'class' ? 'class' : 'type';
    const signature = source.slice(declStartIdx, openBraceIdx).replace(/\s+/g, ' ').trim();
    const fullBody = source.slice(declStartIdx, closeBraceIdx + 1);
    const snippet = lines.slice(startLine - 1, Math.min(endLine, startLine + 24)).join('\n');

    typeScopes.push({ name: typeName, kind, startIdx: openBraceIdx, endIdx: closeBraceIdx });
    symbols.push({
      symbol_name: typeName,
      symbol_type: symType,
      signature,
      start_line: startLine,
      end_line: endLine,
      symbol_hash: sha256(fullBody),
      snippet
    });
  }

  // Record cross-file import edges from declared top-level types
  const topLevelTypes = typeScopes.filter(
    (outer) => !typeScopes.some((other) => other !== outer && outer.startIdx > other.startIdx && outer.endIdx < other.endIdx)
  );
  for (const t of topLevelTypes) {
    for (const impSym of importedSymbols) {
      addEdge(t.name, impSym, 'imports');
    }
  }

  function resolveEnclosingJavaType(idx) {
    let best = null;
    for (const scope of typeScopes) {
      if (idx > scope.startIdx && idx < scope.endIdx) {
        if (!best || (scope.endIdx - scope.startIdx) < (best.endIdx - best.startIdx)) {
          best = scope;
        }
      }
    }
    return best;
  }

  // 3. Java Concrete Methods & Constructors ({-bodied)
  const methodScopes = [];
  const methodRegex = /(?:^|\n)[ \t]*(?:@[a-zA-Z0-9_.]+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|default|native|strictfp)\s+)+(?:<[^>]+>\s+)?(?:[a-zA-Z0-9_$<>[\],.? ]+\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^;{}]*?\)\s*(?:throws\s+[a-zA-Z0-9_.,\s$]+)?\{/g;
  for (const match of masked.matchAll(methodRegex)) {
    const methodName = match[1];
    if (JAVA_KEYWORDS.has(methodName)) continue;

    const declStartIdx = match.index + (match[0].startsWith('\n') ? 1 : 0);
    const openBraceIdx = match.index + match[0].length - 1;
    const closeBraceIdx = findMatchingBrace(masked, openBraceIdx);
    const startLine = offsetToLine(lineOffsets, declStartIdx);
    const endLine = offsetToLine(lineOffsets, closeBraceIdx);
    const owner = resolveEnclosingJavaType(declStartIdx);
    const qualifiedName = owner ? `${owner.name}.${methodName}` : methodName;
    const symKey = `${qualifiedName}:${startLine}`;
    if (seenSymbolKeys.has(symKey)) continue;
    seenSymbolKeys.add(symKey);

    methodScopes.push({ startIdx: openBraceIdx, endIdx: closeBraceIdx });

    const signature = source.slice(declStartIdx, openBraceIdx).replace(/\s+/g, ' ').trim();
    const fullBody = source.slice(declStartIdx, closeBraceIdx + 1);
    const maskedBody = masked.slice(openBraceIdx + 1, closeBraceIdx);
    const snippet = lines.slice(startLine - 1, Math.min(endLine, startLine + 24)).join('\n');

    symbols.push({
      symbol_name: qualifiedName,
      symbol_type: 'method',
      signature,
      start_line: startLine,
      end_line: endLine,
      symbol_hash: sha256(fullBody),
      snippet
    });

    const callees = extractCalledSymbols(maskedBody, methodName);
    for (const callee of callees) {
      addEdge(qualifiedName, callee, 'calls');
      if (owner) {
        addEdge(owner.name, callee, 'calls');
      }
    }
  }

  // 4. Java Interface / Abstract Method Signatures (;-terminated outside concrete method bodies)
  const ifaceMethodRegex = /(?:^|\n)[ \t]*(?:@[a-zA-Z0-9_.]+(?:\([^)]*\))?\s+)*(?:(?:public|protected|abstract)\s+)*(?:<[^>]+>\s+)?[a-zA-Z_$][a-zA-Z0-9_$<>[\],.?]*(?:\s*<[^>]+>)?(?:\[\])*\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^;{}]*?\)\s*(?:throws\s+[a-zA-Z0-9_.,\s$]+)?;/g;
  for (const match of masked.matchAll(ifaceMethodRegex)) {
    const methodName = match[1];
    if (JAVA_KEYWORDS.has(methodName)) continue;
    const declStartIdx = match.index + (match[0].startsWith('\n') ? 1 : 0);
    if (methodScopes.some((ms) => declStartIdx > ms.startIdx && declStartIdx < ms.endIdx)) continue;
    const owner = resolveEnclosingJavaType(declStartIdx);
    if (!owner) continue;

    const sigText = source.slice(declStartIdx, match.index + match[0].length).replace(/\s+/g, ' ').trim();
    if (/^(?:return|throw|new)\b/.test(sigText)) continue;
    if (owner.kind !== 'interface' && owner.kind !== '@interface' && !/\babstract\b/.test(sigText)) continue;

    const startLine = offsetToLine(lineOffsets, declStartIdx);
    const qualifiedName = `${owner.name}.${methodName}`;
    const symKey = `${qualifiedName}:${startLine}`;
    if (seenSymbolKeys.has(symKey)) continue;
    seenSymbolKeys.add(symKey);

    const cleanSig = sigText.replace(/;$/, '').trim();
    symbols.push({
      symbol_name: qualifiedName,
      symbol_type: 'method',
      signature: cleanSig,
      start_line: startLine,
      end_line: startLine,
      symbol_hash: sha256(sigText),
      snippet: cleanSig
    });
  }

  symbols.sort((a, b) => a.start_line - b.start_line);
  return { symbols, edges };
}

function escapeIdentifierForWordBoundary(ident) {
  return String(ident || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasWholeIdentifierInText(text, ident) {
  if (!text || !ident) return false;
  const escaped = escapeIdentifierForWordBoundary(ident);
  const re = new RegExp(`(?<![A-Za-z0-9_$])${escaped}(?![A-Za-z0-9_$])`);
  return re.test(text);
}

const RECEIVER_STOPWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'try', 'catch', 'finally',
  'return', 'new', 'throw', 'throws', 'super', 'this', 'self', 'cls', 'true', 'false',
  'null', 'none', 'var', 'val', 'let', 'const', 'def', 'class', 'import', 'from'
]);

/**
 * Extract 1-hop local/field/parameter variable names typed as or constructed from `localSymbolName`
 * so `analyzeImportSymbolActivity` recognizes active cursor usage via `receiver.method(...)`.
 */
function extractBoundReceiverNames(maskedPrefix, localSymbolName, isPyLike, isJava) {
  if (!maskedPrefix || !localSymbolName || localSymbolName.length < 2) return [];
  const esc = escapeIdentifierForWordBoundary(localSymbolName);
  const receivers = new Set();
  let m;

  if (isPyLike) {
    const assignRe = new RegExp(`(?:\\bself\\.)?([A-Za-z_][A-Za-z0-9_]*)\\s*(?::[^=\\n]{1,64})?=\\s*(?:await\\s+)?${esc}\\s*\\(`, 'g');
    while ((m = assignRe.exec(maskedPrefix)) !== null) {
      const name = m[1];
      if (name && name.length >= 2 && !RECEIVER_STOPWORDS.has(name.toLowerCase())) {
        receivers.add(name);
      }
    }
    const annotRe = new RegExp(`\\b([A-Za-z_][A-Za-z0-9_]*)\\s*:\\s*(?:Optional\\[|List\\[|Sequence\\[)?${esc}\\b`, 'g');
    while ((m = annotRe.exec(maskedPrefix)) !== null) {
      const name = m[1];
      if (name && name.length >= 2 && !RECEIVER_STOPWORDS.has(name.toLowerCase())) {
        receivers.add(name);
      }
    }
  } else if (isJava) {
    const typedDeclRe = new RegExp(`\\b${esc}(?:\\s*<[^>\\n]{1,80}>)?(?:\\[\\])*\\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\\b`, 'g');
    while ((m = typedDeclRe.exec(maskedPrefix)) !== null) {
      const name = m[1];
      if (name && name.length >= 2 && !RECEIVER_STOPWORDS.has(name.toLowerCase())) {
        receivers.add(name);
      }
    }
    const newAssignRe = new RegExp(`(?:\\bthis\\.)?([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*new\\s+${esc}\\b`, 'g');
    while ((m = newAssignRe.exec(maskedPrefix)) !== null) {
      const name = m[1];
      if (name && name.length >= 2 && !RECEIVER_STOPWORDS.has(name.toLowerCase())) {
        receivers.add(name);
      }
    }
  } else {
    const jsNewRe = new RegExp(`(?:\\bthis\\.|\\b(?:const|let|var)\\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*(?:await\\s+)?(?:new\\s+)?${esc}\\s*\\(`, 'g');
    while ((m = jsNewRe.exec(maskedPrefix)) !== null) {
      const name = m[1];
      if (name && name.length >= 2 && !RECEIVER_STOPWORDS.has(name.toLowerCase())) {
        receivers.add(name);
      }
    }
  }

  return [...receivers];
}

/**
 * Parse structured import bindings (`{ localName, exportedName, moduleStem, targetPath, isStatic }`)
 * across Python, Java, JS/TS, Go, and Rust, and classify each imported binding against `codePrefix`
 * into `immediate_cursor`, `unused_staged`, or `earlier_only` (krusch-git v1.2.3 parity).
 *
 * @param {string} codePrefix
 * @param {string} [importStatement='']
 * @param {string} [filePath='']
 * @param {{ immediateLineWindow?: number }} [options={}]
 */
export function analyzeImportSymbolActivity(codePrefix, importStatement = '', filePath = '', options = {}) {
  const ext = path.extname(filePath || '').toLowerCase();
  const immediateLineWindow = Math.max(1, Number(options.immediateLineWindow ?? 5));
  const combinedImportsSource = String(importStatement || '').trim()
    ? String(importStatement)
    : String(codePrefix || '');

  const bindings = [];
  const seenBindingKey = new Set();
  const pushBinding = (localName, exportedName, moduleStem, targetPath, isStatic = false) => {
    const loc = String(localName || '').trim();
    const exp = String(exportedName || loc).trim();
    if (!loc || loc === '*' || !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(loc)) return;
    const key = `${loc}::${exp}::${moduleStem || ''}`;
    if (seenBindingKey.has(key)) return;
    seenBindingKey.add(key);
    bindings.push({
      localName: loc,
      exportedName: exp,
      moduleStem: String(moduleStem || '').trim(),
      targetPath: String(targetPath || '').trim(),
      isStatic: Boolean(isStatic),
      receiverNames: [],
      matchedViaReceiver: false,
      status: 'unused_staged'
    });
  };

  if (ext === '.java') {
    const cleanImp = maskCodePreservingNewlines(combinedImportsSource, { maskStrings: false });
    const javaImpRe = /(?:^|\n)[ \t]*import\s+(static\s+)?([A-Za-z0-9_.*$]+)\s*;/g;
    for (const m of cleanImp.matchAll(javaImpRe)) {
      const isStatic = Boolean(m[1]);
      const fullPath = m[2].trim();
      if (fullPath.endsWith('.*')) continue;
      const segs = fullPath.split('.').filter(Boolean);
      if (segs.length === 0) continue;
      const leaf = segs[segs.length - 1];
      const ownerStem = isStatic && segs.length >= 2 ? segs[segs.length - 2] : leaf;
      pushBinding(leaf, leaf, ownerStem, fullPath, isStatic);
    }
  } else if (ext === '.py' || (!ext && /\b(?:from\s+\S+\s+import|def\s+\w+)/.test(`${combinedImportsSource}\n${codePrefix}`))) {
    const commentStripped = String(combinedImportsSource)
      .split(/\r?\n/)
      .map((l) => l.replace(/#.*$/, ''))
      .join('\n');
    const joined = commentStripped
      .replace(/\\\r?\n/g, ' ')
      .replace(/(from\s+[A-Za-z0-9_.]+\s+import\s*)\(\s*([\s\S]*?)\s*\)/g, (_all, prefix, inner) => `${prefix}(${inner.replace(/\r?\n/g, ' ')})`);
    for (const rawLine of joined.split(/\r?\n/)) {
      const cleaned = rawLine.trim();
      if (!cleaned) continue;

      const fromMatch = cleaned.match(/^from\s+([A-Za-z0-9_.]+)\s+import\s+\(?([^)]+)\)?$/);
      if (fromMatch) {
        const modPath = fromMatch[1];
        const modParts = modPath.replace(/^\.+/, '').split('.').filter(Boolean);
        const moduleStem = modParts.length > 0 ? modParts[modParts.length - 1] : '';
        for (const item of fromMatch[2].split(',')) {
          const trimmed = item.trim();
          if (!trimmed || trimmed === '*') continue;
          const asParts = trimmed.split(/\s+as\s+/i).map((s) => s.trim()).filter(Boolean);
          if (asParts.length >= 2) {
            pushBinding(asParts[1], asParts[0], moduleStem, modPath, false);
          } else if (asParts.length === 1) {
            pushBinding(asParts[0], asParts[0], moduleStem, modPath, false);
          }
        }
        continue;
      }

      const impMatch = cleaned.match(/^import\s+(.+)$/);
      if (impMatch) {
        for (const item of impMatch[1].split(',')) {
          const trimmed = item.trim();
          if (!trimmed) continue;
          const asParts = trimmed.split(/\s+as\s+/i).map((s) => s.trim()).filter(Boolean);
          const modPath = asParts[0] || '';
          const modSegments = modPath.split('.').filter(Boolean);
          const moduleStem = modSegments.length > 0 ? modSegments[modSegments.length - 1] : '';
          if (!moduleStem) continue;
          const localAlias = asParts.length >= 2 ? asParts[1] : modSegments[0];
          pushBinding(localAlias, moduleStem, moduleStem, modPath, false);
        }
      }
    }
  } else if (ext === '.rs') {
    const cleanRs = maskCodePreservingNewlines(combinedImportsSource, { maskStrings: false });
    const rsUseRe = /(?:^|\n)[ \t]*(?:pub\s+)?use\s+([A-Za-z0-9_:{}*,\s]+)\s*;/g;
    for (const m of cleanRs.matchAll(rsUseRe)) {
      const spec = m[1].trim();
      const braceMatch = spec.match(/^([A-Za-z0-9_:]+)::\{([^}]+)\}$/);
      if (braceMatch) {
        const basePath = braceMatch[1];
        const baseSegs = basePath.split('::').filter(Boolean);
        const modStem = baseSegs[baseSegs.length - 1] || '';
        for (const item of braceMatch[2].split(',')) {
          const t = item.trim();
          if (!t || t === 'self' || t === '*') continue;
          const asParts = t.split(/\s+as\s+/).map((s) => s.trim());
          pushBinding(asParts[1] || asParts[0], asParts[0], modStem, `${basePath}::${asParts[0]}`, false);
        }
      } else {
        const asParts = spec.split(/\s+as\s+/).map((s) => s.trim());
        const segs = (asParts[0] || '').split('::').filter(Boolean);
        const leaf = segs[segs.length - 1] || '';
        const modStem = segs.length >= 2 ? segs[segs.length - 2] : leaf;
        if (leaf && leaf !== '*') {
          pushBinding(asParts[1] || leaf, leaf, modStem, asParts[0], false);
        }
      }
    }
  } else if (ext === '.go') {
    const cleanGo = maskCodePreservingNewlines(combinedImportsSource, { maskStrings: false });
    const goImpRe = /(?:([A-Za-z_][A-Za-z0-9_]*)\s+)?"([^"\n]+)"/g;
    for (const m of cleanGo.matchAll(goImpRe)) {
      const alias = m[1] || '';
      const pkgPath = m[2].trim();
      const segs = pkgPath.split('/').filter(Boolean);
      const pkgStem = segs[segs.length - 1] || '';
      if (pkgStem && alias !== '_') {
        pushBinding(alias || pkgStem, pkgStem, pkgStem, pkgPath, false);
      }
    }
  } else {
    const cleanJs = maskCodePreservingNewlines(combinedImportsSource, { maskStrings: false });
    const esmRe = /(?:^|\n)[ \t]*import\s+(?:type\s+)?([\s\S]*?)\s+from\s+['"]([^'"]+)['"]/g;
    for (const m of cleanJs.matchAll(esmRe)) {
      const clause = m[1].trim();
      const modSpec = m[2].trim();
      const modStem = path.basename(modSpec, path.extname(modSpec));
      const namedMatch = clause.match(/\{([\s\S]*?)\}/);
      if (namedMatch) {
        for (const item of namedMatch[1].split(',')) {
          const cleaned = item.replace(/^type\s+/, '').trim();
          if (!cleaned) continue;
          const asParts = cleaned.split(/\s+as\s+/).map((s) => s.trim()).filter(Boolean);
          pushBinding(asParts[1] || asParts[0], asParts[0], modStem, modSpec, false);
        }
      }
      const beforeBrace = clause.replace(/\{[\s\S]*?\}/, '').replace(/,/g, '').trim();
      if (beforeBrace) {
        const nsMatch = beforeBrace.match(/^\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)$/);
        if (nsMatch) {
          pushBinding(nsMatch[1], modStem, modStem, modSpec, false);
        } else if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(beforeBrace)) {
          pushBinding(beforeBrace, beforeBrace, modStem, modSpec, false);
        }
      }
    }
  }

  let sanitizedPrefix = String(codePrefix || '');
  const isPyLike = ext === '.py' || (!ext && /\bdef\s+\w+/.test(sanitizedPrefix));
  const isJava = ext === '.java';
  if (isPyLike) {
    sanitizedPrefix = sanitizedPrefix
      .replace(/"""[\s\S]*?"""/g, (m) => m.replace(/[^\n]/g, ' '))
      .replace(/'''[\s\S]*?'''/g, (m) => m.replace(/[^\n]/g, ' '));
  }
  const maskedPrefix = maskCodePreservingNewlines(sanitizedPrefix, {
    maskStrings: true,
    allowHashComment: isPyLike || ext === '.sh'
  });

  const bodyLines = maskedPrefix
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !/^(?:import\s+|from\s+[A-Za-z0-9_.]+\s+import\s+|package\s+|use\s+)/.test(l));

  const fullBodyText = bodyLines.join('\n');
  const splitIdx = Math.max(0, bodyLines.length - immediateLineWindow);
  const earlierText = bodyLines.slice(0, splitIdx).join('\n');
  const immediateText = bodyLines.slice(splitIdx).join('\n');

  const immediateCursorBindings = [];
  const unusedStagedBindings = [];
  const earlierOnlyBindings = [];

  for (const b of bindings) {
    const directImmediate = hasWholeIdentifierInText(immediateText, b.localName);
    const directEarlier = hasWholeIdentifierInText(earlierText, b.localName);
    let viaReceiverImmediate = false;

    if (!directImmediate && directEarlier) {
      const receivers = extractBoundReceiverNames(fullBodyText, b.localName, isPyLike, isJava);
      b.receiverNames = receivers;
      for (const recv of receivers) {
        if (hasWholeIdentifierInText(immediateText, recv)) {
          viaReceiverImmediate = true;
          break;
        }
      }
    }

    if (directImmediate || viaReceiverImmediate) {
      b.status = 'immediate_cursor';
      b.matchedViaReceiver = viaReceiverImmediate && !directImmediate;
      immediateCursorBindings.push(b);
    } else if (!directEarlier) {
      b.status = 'unused_staged';
      unusedStagedBindings.push(b);
    } else {
      b.status = 'earlier_only';
      earlierOnlyBindings.push(b);
    }
  }

  const uniqueNames = (arr) => [...new Set(arr.flatMap((b) => [b.exportedName, b.localName]).filter(Boolean))];

  return {
    bindings,
    immediateCursorBindings,
    unusedStagedBindings,
    earlierOnlyBindings,
    immediateCursorSymbols: uniqueNames(immediateCursorBindings),
    unusedStagedSymbols: uniqueNames(unusedStagedBindings),
    earlierOnlySymbols: uniqueNames(earlierOnlyBindings),
    hasActiveCursorImport: immediateCursorBindings.length > 0,
    unusedImportRatio: bindings.length > 0 ? unusedStagedBindings.length / bindings.length : 0
  };
}

/**
 * Walk a repository directory and return relative file paths for supported code/doc files.
 * @param {string} rootDir
 * @returns {string[]}
 */
function walkIndexableFiles(rootDir) {
  const results = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      if (entry.name.startsWith('.') && entry.name !== '.agent') continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (CODE_EXTENSIONS.has(ext)) {
          const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/');
          results.push(relPath);
        }
      }
    }
  }

  walk(rootDir);
  return results.sort();
}

/**
 * Attempt to read HEAD commit hash from .git directory without spawning a subprocess.
 * @param {string} repoRoot
 * @returns {string}
 */
function readGitHeadCommit(repoRoot) {
  try {
    const headFile = path.join(repoRoot, '.git', 'HEAD');
    if (!fs.existsSync(headFile)) return 'working-tree';
    const headContent = fs.readFileSync(headFile, 'utf8').trim();
    if (headContent.startsWith('ref:')) {
      const refRel = headContent.slice(4).trim();
      const refFile = path.join(repoRoot, '.git', refRel);
      if (fs.existsSync(refFile)) {
        return fs.readFileSync(refFile, 'utf8').trim().slice(0, 40);
      }
    }
    return headContent.slice(0, 40) || 'working-tree';
  } catch {
    return 'working-tree';
  }
}

/**
 * Create a Tier 2A Git & AST Engine instance.
 * @param {object} options
 * @param {import('node:sqlite').DatabaseSync} options.db
 * @param {string} [options.workspaceRoot]
 */
export function createGitEngine({ db, workspaceRoot = process.cwd() }) {
  const root = path.resolve(workspaceRoot);
  const defaultRepoName = path.basename(root) || 'workspace';

  const upsertRepoStmt = db.prepare(`
    INSERT INTO git_repositories (name, root_path, head_commit, indexed_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(name) DO UPDATE SET
      root_path = excluded.root_path,
      head_commit = excluded.head_commit,
      indexed_at = datetime('now')
  `);

  const deleteFileSymbolsStmt = db.prepare(`
    DELETE FROM git_symbols WHERE repo_name = ? AND file_path = ?
  `);

  const deleteFileEdgesStmt = db.prepare(`
    DELETE FROM git_edges WHERE repo_name = ? AND from_file = ?
  `);

  const insertSymbolStmt = db.prepare(`
    INSERT OR REPLACE INTO git_symbols (
      repo_name,
      file_path,
      symbol_name,
      symbol_type,
      signature,
      start_line,
      end_line,
      symbol_hash,
      snippet
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertEdgeStmt = db.prepare(`
    INSERT INTO git_edges (
      repo_name,
      from_file,
      from_symbol,
      to_symbol,
      edge_type
    ) VALUES (?, ?, ?, ?, ?)
  `);

  /**
   * Index a repository into git_repositories, git_symbols, and git_edges.
   * Enforces INV-GIT-01 and INV-GIT-02.
   * @param {object|string} [options]
   */
  function indexRepo(options = {}) {
    const rawPath = typeof options === 'string'
      ? options
      : (options?.repoPath || options?.path || root);
    const repoRoot = path.resolve(rawPath);
    const repoName = (typeof options === 'object' && options?.repoName)
      ? String(options.repoName)
      : (path.basename(repoRoot) || defaultRepoName);

    if (!fs.existsSync(repoRoot) || !fs.statSync(repoRoot).isDirectory()) {
      return okEnvelope(
        'krusch_git_index_repo',
        `Repository directory not found: ${repoRoot}`,
        { error: 'directory_not_found', repo_path: repoRoot },
        false
      );
    }

    const headCommit = readGitHeadCommit(repoRoot);
    upsertRepoStmt.run(repoName, repoRoot, headCommit);

    const relFiles = walkIndexableFiles(repoRoot);
    let symbolsIndexed = 0;
    let edgesIndexed = 0;

    for (const relFile of relFiles) {
      const absFile = path.join(repoRoot, relFile);
      let content = '';
      try {
        content = fs.readFileSync(absFile, 'utf8');
      } catch {
        continue;
      }

      // INV-GIT-02: Delete stale rows for (repo_name, file_path) before inserting
      deleteFileSymbolsStmt.run(repoName, relFile);
      deleteFileEdgesStmt.run(repoName, relFile);

      const ext = path.extname(relFile).toLowerCase();
      let parsed = { symbols: [], edges: [] };
      if (ext === '.py') {
        parsed = parsePythonSymbols(content);
      } else if (ext === '.java') {
        parsed = parseJavaSymbols(content);
      } else if (ext === '.md') {
        parsed = parseMarkdownSymbols(content);
      } else {
        parsed = parseJsTsSymbols(content);
      }

      for (const sym of parsed.symbols) {
        insertSymbolStmt.run(
          repoName,
          relFile,
          sym.symbol_name,
          sym.symbol_type,
          sym.signature,
          sym.start_line,
          sym.end_line,
          sym.symbol_hash,
          sym.snippet
        );
        symbolsIndexed += 1;
      }

      for (const edge of parsed.edges) {
        insertEdgeStmt.run(
          repoName,
          relFile,
          edge.from_symbol,
          edge.to_symbol,
          edge.edge_type
        );
        edgesIndexed += 1;
      }
    }

    return okEnvelope(
      'krusch_git_index_repo',
      `Indexed ${relFiles.length} file(s), ${symbolsIndexed} symbol(s), and ${edgesIndexed} call edge(s) in ${repoName}.`,
      {
        repo: repoName,
        root_path: repoRoot,
        head_commit: headCommit,
        files_indexed: relFiles.length,
        symbols_indexed: symbolsIndexed,
        edges_indexed: edgesIndexed
      },
      true
    );
  }

  /**
   * Automatically index workspaceRoot if git_repositories is empty.
   */
  function ensureIndexed() {
    const row = db.prepare('SELECT COUNT(*) AS cnt FROM git_repositories').get();
    if (!row || Number(row.cnt) === 0) {
      indexRepo({ repoPath: root, repoName: defaultRepoName });
    }
  }

  /**
   * Resolve a repository record by name or fallback to the default workspace repository.
   * @param {string} [repo]
   * @returns {{ name: string, root_path: string, head_commit: string }}
   */
  function resolveRepoRecord(repo) {
    ensureIndexed();
    if (repo && repo !== '*') {
      const exact = db.prepare('SELECT * FROM git_repositories WHERE name = ?').get(String(repo));
      if (exact) return exact;
    }
    const first = db.prepare('SELECT * FROM git_repositories ORDER BY id ASC LIMIT 1').get();
    return first || { name: defaultRepoName, root_path: root, head_commit: 'working-tree' };
  }

  /**
   * List all indexed Git repositories and symbol statistics.
   */
  function listRepos() {
    ensureIndexed();
    const repos = db.prepare(`
      SELECT
        r.name,
        r.root_path,
        r.head_commit,
        r.indexed_at,
        COUNT(s.id) AS symbol_count
      FROM git_repositories r
      LEFT JOIN git_symbols s ON s.repo_name = r.name
      GROUP BY r.name, r.root_path, r.head_commit, r.indexed_at
      ORDER BY r.name ASC
    `).all().map((r) => ({
      name: r.name,
      root_path: r.root_path,
      head_commit: r.head_commit,
      indexed_at: r.indexed_at,
      symbol_count: Number(r.symbol_count)
    }));

    return okEnvelope(
      'krusch_git_list_repos',
      `Found ${repos.length} indexed repository(ies).`,
      { repos },
      true
    );
  }

  /**
   * Read directory tree entries within an indexed repository.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} [params.path='']
   */
  function readTree({ repo, path: relPath = '' } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const cleanRel = String(relPath ?? '').replace(/^\/+/, '');
    const targetDir = path.resolve(repoRecord.root_path, cleanRel);

    if (!targetDir.startsWith(path.resolve(repoRecord.root_path))) {
      return okEnvelope(
        'krusch_git_read_tree',
        'Path traversal outside repository root is not permitted.',
        { error: 'path_traversal_denied' },
        false
      );
    }

    if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
      return okEnvelope(
        'krusch_git_read_tree',
        `Directory not found: ${cleanRel || '.'}`,
        { repo: repoRecord.name, path: cleanRel, error: 'not_found' },
        false
      );
    }

    const dirEntries = fs.readdirSync(targetDir, { withFileTypes: true })
      .filter((entry) => !IGNORED_DIRS.has(entry.name))
      .map((entry) => {
        const entryAbs = path.join(targetDir, entry.name);
        const entryRel = path.relative(repoRecord.root_path, entryAbs).replace(/\\/g, '/');
        const isDir = entry.isDirectory();
        const size = isDir ? 0 : fs.statSync(entryAbs).size;
        return {
          name: entry.name,
          path: entryRel,
          type: isDir ? 'directory' : 'file',
          size
        };
      })
      .sort((a, b) => {
        if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

    return okEnvelope(
      'krusch_git_read_tree',
      `Listed ${dirEntries.length} entry(ies) in ${repoRecord.name}:${cleanRel || '.'}.`,
      {
        repo: repoRecord.name,
        path: cleanRel,
        entries: dirEntries
      },
      true
    );
  }

  /**
   * Read file blob contents with optional 1-indexed line slicing.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} params.path
   * @param {number} [params.start_line]
   * @param {number} [params.end_line]
   */
  function readBlob({ repo, path: relPath, start_line, end_line } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const rawRel = String(relPath ?? '').trim();
    if (!rawRel) {
      return okEnvelope(
        'krusch_git_read_blob',
        'File path is required.',
        { error: 'path_required' },
        false
      );
    }

    const targetFile = path.isAbsolute(rawRel)
      ? path.resolve(rawRel)
      : path.resolve(repoRecord.root_path, rawRel);

    if (!targetFile.startsWith(path.resolve(repoRecord.root_path))) {
      return okEnvelope(
        'krusch_git_read_blob',
        'Path traversal outside repository root is not permitted.',
        { error: 'path_traversal_denied' },
        false
      );
    }

    if (!fs.existsSync(targetFile) || !fs.statSync(targetFile).isFile()) {
      return okEnvelope(
        'krusch_git_read_blob',
        `File not found: ${rawRel}`,
        { repo: repoRecord.name, path: rawRel, error: 'not_found' },
        false
      );
    }

    const fullContent = fs.readFileSync(targetFile, 'utf8');
    const lines = fullContent.split(/\r?\n/);
    const startLine = Number.isInteger(Number(start_line)) && Number(start_line) >= 1
      ? Number(start_line)
      : 1;
    const endLine = Number.isInteger(Number(end_line)) && Number(end_line) >= startLine
      ? Math.min(lines.length, Number(end_line))
      : lines.length;

    const content = lines.slice(startLine - 1, endLine).join('\n');
    const normalizedRel = path.relative(repoRecord.root_path, targetFile).replace(/\\/g, '/');

    return okEnvelope(
      'krusch_git_read_blob',
      `Read ${normalizedRel} (L${startLine}-L${endLine} of ${lines.length}).`,
      {
        repo: repoRecord.name,
        path: normalizedRel,
        start_line: startLine,
        end_line: endLine,
        total_lines: lines.length,
        content
      },
      true
    );
  }

  /**
   * Search AST symbols across a repository by name, signature, or symbol type.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} [params.query='']
   * @param {string} [params.symbol_type]
   */
  function searchSymbols({ repo, query = '', symbol_type } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const trimmedQuery = String(query ?? '').trim();
    const likePattern = !trimmedQuery || trimmedQuery === '*' ? '%' : `%${trimmedQuery}%`;

    let rows;
    if (symbol_type) {
      rows = db.prepare(`
        SELECT
          repo_name,
          file_path,
          symbol_name,
          symbol_type,
          signature,
          start_line,
          end_line,
          symbol_hash,
          snippet
        FROM git_symbols
        WHERE repo_name = ?
          AND symbol_type = ?
          AND (symbol_name LIKE ? OR signature LIKE ?)
        ORDER BY file_path ASC, start_line ASC
        LIMIT 100
      `).all(repoRecord.name, String(symbol_type), likePattern, likePattern);
    } else {
      rows = db.prepare(`
        SELECT
          repo_name,
          file_path,
          symbol_name,
          symbol_type,
          signature,
          start_line,
          end_line,
          symbol_hash,
          snippet
        FROM git_symbols
        WHERE repo_name = ?
          AND (symbol_name LIKE ? OR signature LIKE ?)
        ORDER BY file_path ASC, start_line ASC
        LIMIT 100
      `).all(repoRecord.name, likePattern, likePattern);
    }

    return okEnvelope(
      'krusch_git_search_symbols',
      `Found ${rows.length} symbol(s) matching "${trimmedQuery || '*'}" in ${repoRecord.name}.`,
      {
        repo: repoRecord.name,
        query: trimmedQuery,
        symbols: rows
      },
      true
    );
  }

  /**
   * List all symbols declared in a specific file.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} params.file_path
   */
  function fileSymbols({ repo, file_path, path: altPath } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const rawFile = String(file_path || altPath || '').trim();
    if (!rawFile) {
      return okEnvelope(
        'krusch_git_file_symbols',
        'file_path is required.',
        { error: 'file_path_required', symbols: [] },
        false
      );
    }

    const normalizedFile = path.isAbsolute(rawFile)
      ? path.relative(repoRecord.root_path, rawFile).replace(/\\/g, '/')
      : rawFile.replace(/^\.\/+/, '').replace(/\\/g, '/');

    // If file exists on disk and has not been indexed yet (or was recently created), index it now
    const absCandidate = path.resolve(repoRecord.root_path, normalizedFile);
    if (fs.existsSync(absCandidate) && fs.statSync(absCandidate).isFile()) {
      const existingCount = db.prepare(`
        SELECT COUNT(*) AS cnt FROM git_symbols WHERE repo_name = ? AND file_path = ?
      `).get(repoRecord.name, normalizedFile);
      if (!existingCount || Number(existingCount.cnt) === 0) {
        indexRepo({ repoPath: repoRecord.root_path, repoName: repoRecord.name });
      }
    }

    const rows = db.prepare(`
      SELECT
        repo_name,
        file_path,
        symbol_name,
        symbol_type,
        signature,
        start_line,
        end_line,
        symbol_hash,
        snippet
      FROM git_symbols
      WHERE repo_name = ? AND file_path = ?
      ORDER BY start_line ASC
    `).all(repoRecord.name, normalizedFile);

    return okEnvelope(
      'krusch_git_file_symbols',
      `Found ${rows.length} symbol(s) in ${normalizedFile}.`,
      {
        repo: repoRecord.name,
        file_path: normalizedFile,
        symbols: rows
      },
      true
    );
  }

  /**
   * Trace inbound callers and outbound callees for a target symbol before changing signatures.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} params.symbol
   */
  function dependencyGraph({ repo, symbol } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const symbolName = String(symbol ?? '').trim();
    if (!symbolName) {
      return okEnvelope(
        'krusch_git_dependency_graph',
        'symbol is required.',
        { error: 'symbol_required' },
        false
      );
    }

    const definitions = db.prepare(`
      SELECT
        repo_name,
        file_path,
        symbol_name,
        symbol_type,
        signature,
        start_line,
        end_line,
        symbol_hash
      FROM git_symbols
      WHERE repo_name = ? AND symbol_name = ?
      ORDER BY file_path ASC, start_line ASC
    `).all(repoRecord.name, symbolName);

    const inbound = db.prepare(`
      SELECT
        repo_name,
        from_file,
        from_symbol,
        to_symbol,
        edge_type
      FROM git_edges
      WHERE repo_name = ? AND to_symbol = ?
      ORDER BY from_file ASC, from_symbol ASC
    `).all(repoRecord.name, symbolName);

    const outbound = db.prepare(`
      SELECT
        repo_name,
        from_file,
        from_symbol,
        to_symbol,
        edge_type
      FROM git_edges
      WHERE repo_name = ? AND from_symbol = ?
      ORDER BY to_symbol ASC
    `).all(repoRecord.name, symbolName);

    return okEnvelope(
      'krusch_git_dependency_graph',
      `Symbol "${symbolName}" has ${definitions.length} definition(s), ${inbound.length} inbound caller(s), and ${outbound.length} outbound callee(s).`,
      {
        repo: repoRecord.name,
        symbol: symbolName,
        definitions,
        inbound,
        outbound,
        inbound_callers: inbound,
        outbound_callees: outbound
      },
      true
    );
  }

  /**
   * Hybrid lexical/BM25-weighted code search across indexed symbols and snippets,
   * with Porter FTS5, sub-token/stemmed matching, gated 2-hop call-graph bridging,
   * lazy Top-K snippet hydration, token budgeting, and unattested identifier telemetry.
   * @param {object} [params]
   * @param {string} [params.repo]
   * @param {string} [params.query='']
   * @param {number} [params.limit=10]
   * @param {number} [params.limit_tokens]
   */
  function semanticSearch({ repo, query = '', limit = 10, limit_tokens } = {}) {
    const repoRecord = resolveRepoRecord(repo);
    const trimmedQuery = String(query ?? '').trim();
    const maxResults = Number.isFinite(Number(limit)) && Number(limit) > 0
      ? Math.max(1, Math.min(50, Math.floor(Number(limit))))
      : 10;
    const hasTokenLimit = Number.isFinite(Number(limit_tokens)) && Number(limit_tokens) > 0;
    const tokenBudget = hasTokenLimit ? Math.max(1, Math.floor(Number(limit_tokens))) : null;

    // INV-STACK-07: Metadata-only candidate scan (do NOT select snippet for full table)
    const allSymbols = db.prepare(`
      SELECT
        id,
        repo_name,
        file_path,
        symbol_name,
        symbol_type,
        signature,
        start_line,
        end_line,
        symbol_hash
      FROM git_symbols
      WHERE repo_name = ?
    `).all(repoRecord.name);

    const symbolById = new Map(allSymbols.map((s) => [Number(s.id), s]));

    /**
     * Lazily hydrate `snippet` ONLY for winning rows and enforce optional `limit_tokens`.
     * @param {Array<object>} winningRows
     * @returns {{ results: Array<object>, tokens_used: number }}
     */
    function hydrateAndBudgetWinners(winningRows) {
      const selectSnippetStmt = db.prepare('SELECT snippet FROM git_symbols WHERE id = ?');
      const results = [];
      let tokensUsed = 0;

      for (const row of winningRows) {
        const rawSnippet = selectSnippetStmt.get(row.id)?.snippet || '';
        const candidate = formatSymbolResultRow(row, rawSnippet);
        const candidateTokens = estimateSymbolRowTokens(candidate);

        if (!hasTokenLimit) {
          results.push(candidate);
          tokensUsed += candidateTokens;
          continue;
        }

        if (tokensUsed + candidateTokens <= tokenBudget) {
          results.push(candidate);
          tokensUsed += candidateTokens;
          continue;
        }

        const remainingTokens = tokenBudget - tokensUsed;
        const header = `${candidate.file_path || ''}:${candidate.symbol_name || ''} ${candidate.signature || ''}`;
        const prefixLen = header.length + 1;
        const maxSnippetChars = Math.max(0, remainingTokens * 4 - prefixLen);

        if (results.length === 0) {
          const truncatedSnippet = maxSnippetChars === 0
            ? ''
            : rawSnippet.length <= maxSnippetChars
              ? rawSnippet
              : maxSnippetChars > 3
                ? `${rawSnippet.slice(0, maxSnippetChars - 3).trimEnd()}...`
                : rawSnippet.slice(0, maxSnippetChars);
          const firstBounded = formatSymbolResultRow(row, truncatedSnippet);
          const usedForFirst = Math.min(tokenBudget, estimateSymbolRowTokens(firstBounded));
          results.push(firstBounded);
          tokensUsed += usedForFirst;
          break;
        }

        if (maxSnippetChars >= 32 && rawSnippet.length > 0) {
          const truncatedSnippet = rawSnippet.length <= maxSnippetChars
            ? rawSnippet
            : `${rawSnippet.slice(0, maxSnippetChars - 3).trimEnd()}...`;
          const bounded = formatSymbolResultRow(row, truncatedSnippet);
          const boundedTokens = estimateSymbolRowTokens(bounded);
          if (tokensUsed + boundedTokens <= tokenBudget) {
            results.push(bounded);
            tokensUsed += boundedTokens;
          }
        }
        break;
      }

      return { results, tokens_used: tokensUsed };
    }

    if (!trimmedQuery || trimmedQuery === '*') {
      const wildcardRows = allSymbols
        .map((row) => ({ ...row, score: 1.0 }))
        .sort((a, b) => a.file_path.localeCompare(b.file_path) || a.start_line - b.start_line)
        .slice(0, maxResults);

      const { results, tokens_used } = hydrateAndBudgetWinners(wildcardRows);
      return okEnvelope(
        'krusch_git_semantic_search',
        `Semantic search for "${trimmedQuery}" returned ${results.length} result(s).`,
        {
          repo: repoRecord.name,
          query: trimmedQuery,
          results,
          unattested_query_identifiers: [],
          tokens_used
        },
        true
      );
    }

    // INV-STACK-07: Query external-content Porter FTS5 virtual table
    const ftsMap = new Map();
    let ftsAvailable = true;
    const ftsQuery = buildFts5MatchQuery(trimmedQuery);
    if (ftsQuery && typeof ftsQuery === 'string' && ftsQuery.trim().length > 0) {
      try {
        const ftsRows = db.prepare(`
          SELECT rowid, bm25(git_symbols_fts, 10.0, 5.0, 4.0, 2.0) AS rank
          FROM git_symbols_fts
          WHERE git_symbols_fts MATCH ?
          ORDER BY rank ASC
        `).all(ftsQuery);
        for (let idx = 0; idx < ftsRows.length; idx += 1) {
          const ftsRow = ftsRows[idx];
          const id = Number(ftsRow.rowid);
          if (symbolById.has(id) && !ftsMap.has(id)) {
            const absRank = Math.abs(Number(ftsRow.rank) || 0);
            const normRank = absRank > 0
              ? 0.7 * (absRank / (1 + absRank)) + 0.3 * (1 / (1 + idx))
              : 1 / (1 + idx);
            const boost = 4 + 6 * normRank;
            ftsMap.set(id, boost);
          }
        }
      } catch {
        ftsAvailable = false;
      }
    }

    const allRawTerms = [...new Set(trimmedQuery.toLowerCase().split(/[^a-z0-9_$]+/).filter(Boolean))];
    const nonStopRawTerms = allRawTerms.filter((t) => !isQueryStopword(t));
    const rawTerms = nonStopRawTerms.length > 0 ? nonStopRawTerms : allRawTerms;

    const subTerms = collectSubtokens(trimmedQuery);
    const effectiveSubTerms = subTerms.length > 0
      ? subTerms
      : rawTerms.filter((t) => t.length >= 2);
    const filteredDistinctive = effectiveSubTerms.filter((t) => !isQueryStopword(t));
    const distinctiveTokens = filteredDistinctive.length > 0 ? filteredDistinctive : effectiveSubTerms;
    const distinctiveTokenStems = distinctiveTokens.map((tok) => ({
      tok,
      stems: expandTokenStems(tok)
    }));

    const symbolMetaCache = new Map();
    function getSymbolMeta(row) {
      const id = Number(row.id);
      let cached = symbolMetaCache.get(id);
      if (cached) return cached;
      const nameLower = row.symbol_name.toLowerCase();
      const sigLower = (row.signature || '').toLowerCase();
      const pathLower = row.file_path.toLowerCase();
      const nameStems = buildStemSet(row.symbol_name);
      const sigStems = buildStemSet(row.signature || '');
      const pathStems = buildStemSet(row.file_path);
      const allStems = new Set([...nameStems, ...sigStems, ...pathStems]);
      const collapsedJoined = `${nameLower.replace(/[^a-z0-9]/g, '')} ${pathLower.replace(/[^a-z0-9]/g, '')}`;
      cached = {
        nameLower,
        sigLower,
        pathLower,
        nameStems,
        sigStems,
        pathStems,
        allStems,
        collapsedJoined
      };
      symbolMetaCache.set(id, cached);
      return cached;
    }

    const scored = [];
    for (const row of allSymbols) {
      const meta = getSymbolMeta(row);
      let score = 0;

      for (const term of rawTerms) {
        if (meta.nameLower === term) {
          score += 10;
        } else if (term.length >= 3 && meta.nameLower.includes(term)) {
          score += 6;
        }
        if (term.length >= 3 && meta.sigLower.includes(term)) {
          score += 4;
        }
        if (term.length >= 3 && meta.pathLower.includes(term)) {
          score += 3;
        }
      }

      for (const { stems } of distinctiveTokenStems) {
        if (stems.some((s) => meta.nameStems.has(s))) score += 5;
        if (stems.some((s) => meta.sigStems.has(s))) score += 3;
        if (stems.some((s) => meta.pathStems.has(s))) score += 2;
      }

      const ftsBoost = ftsMap.get(Number(row.id)) || 0;
      score += ftsBoost;

      if (score > 0) {
        scored.push({ ...row, score: Number(score.toFixed(4)) });
      }
    }

    // Fallback when FTS5 is absent on a custom DB or query only matches punctuation/substrings inside snippet
    if (scored.length === 0 && rawTerms.length > 0) {
      const fallbackScores = new Map();
      const likeSnippetStmt = db.prepare(`
        SELECT id FROM git_symbols WHERE repo_name = ? AND lower(snippet) LIKE ?
      `);
      for (const term of rawTerms) {
        const rows = likeSnippetStmt.all(repoRecord.name, `%${term}%`);
        for (const r of rows) {
          const id = Number(r.id);
          if (symbolById.has(id)) {
            fallbackScores.set(id, (fallbackScores.get(id) || 0) + 2);
          }
        }
      }
      for (const [id, score] of fallbackScores.entries()) {
        const sym = symbolById.get(id);
        if (sym) {
          scored.push({ ...sym, score });
        }
      }
    }

    const compareScoredSymbols = (a, b) =>
      b.score - a.score ||
      a.file_path.localeCompare(b.file_path) ||
      a.start_line - b.start_line;

    scored.sort(compareScoredSymbols);
    let topWinners = scored.slice(0, maxResults);

    function coversToken(sym, tok, stems) {
      const meta = getSymbolMeta(sym);
      if (meta.nameLower === tok) return true;
      if (tok.length >= 3 && (meta.nameLower.includes(tok) || meta.sigLower.includes(tok) || meta.pathLower.includes(tok))) {
        return true;
      }
      const collapsedTok = tok.replace(/[^a-z0-9]/g, '');
      if (collapsedTok.length >= 4 && meta.collapsedJoined.includes(collapsedTok)) {
        return true;
      }
      return stems.some((s) => meta.allStems.has(s));
    }

    // INV-STACK-09: Gated 2-hop git_edges call-graph bridge expansion
    if (distinctiveTokenStems.length >= 2 && topWinners.length > 0) {
      const uncoveredEntries = distinctiveTokenStems.filter(
        ({ tok, stems }) => !topWinners.some((sym) => coversToken(sym, tok, stems))
      );

      if (uncoveredEntries.length > 0) {
        const uncoveredFtsByToken = new Map();
        if (ftsAvailable) {
          for (const { tok } of uncoveredEntries) {
            const tokFts = buildFts5MatchQuery(tok);
            if (!tokFts) continue;
            try {
              const rows = db.prepare('SELECT rowid FROM git_symbols_fts WHERE git_symbols_fts MATCH ?').all(tokFts);
              uncoveredFtsByToken.set(tok, new Set(rows.map((r) => Number(r.rowid))));
            } catch {
              // Ignore per-token FTS errors
            }
          }
        }

        const symbolsByName = new Map();
        for (const sym of allSymbols) {
          let list = symbolsByName.get(sym.symbol_name);
          if (!list) {
            list = [];
            symbolsByName.set(sym.symbol_name, list);
          }
          list.push(sym);
        }

        const hop1TopIds = new Set(topWinners.map((s) => Number(s.id)));
        const seeds = topWinners.slice(0, 3);
        const topHop1Score = Number(topWinners[0].score) || 1;
        const rawBridgeCap = Math.min(topHop1Score * 0.84, Math.max(0.01, topHop1Score - 0.01));
        const bridgeCap = rawBridgeCap >= 0.0001
          ? Math.floor(rawBridgeCap * 10000) / 10000
          : rawBridgeCap;

        const selectEdgesStmt = db.prepare(`
          SELECT from_symbol, to_symbol
          FROM git_edges
          WHERE repo_name = ? AND (from_symbol = ? OR to_symbol = ?)
        `);
        const checkSnippetLikeStmt = !ftsAvailable
          ? db.prepare('SELECT 1 AS hit FROM git_symbols WHERE id = ? AND lower(snippet) LIKE ?')
          : null;

        const bridgedById = new Map();
        for (const seed of seeds) {
          const edges = selectEdgesStmt.all(repoRecord.name, seed.symbol_name, seed.symbol_name);
          for (const edge of edges) {
            const neighborName = edge.from_symbol === seed.symbol_name
              ? edge.to_symbol
              : edge.from_symbol;
            if (!neighborName || neighborName === seed.symbol_name) continue;

            const candidates = symbolsByName.get(neighborName);
            if (!candidates) continue;

            for (const cand of candidates) {
              const candId = Number(cand.id);
              if (hop1TopIds.has(candId)) continue;

              let matchedUncovered = 0;
              for (const { tok, stems } of uncoveredEntries) {
                if (
                  coversToken(cand, tok, stems) ||
                  uncoveredFtsByToken.get(tok)?.has(candId) ||
                  (checkSnippetLikeStmt && Boolean(checkSnippetLikeStmt.get(candId, `%${tok}%`)))
                ) {
                  matchedUncovered += 1;
                }
              }

              if (matchedUncovered === 0 && ftsMap.has(candId) && uncoveredFtsByToken.size === 0) {
                matchedUncovered = 1;
              }

              if (matchedUncovered >= 1) {
                const coverageRatio = matchedUncovered / uncoveredEntries.length;
                const scaled = bridgeCap * (0.9 + 0.1 * coverageRatio);
                const candScore = Math.min(
                  bridgeCap,
                  scaled >= 0.0001 ? Math.floor(scaled * 10000) / 10000 : scaled
                );
                const prev = bridgedById.get(candId);
                if (!prev || candScore > prev.score) {
                  bridgedById.set(candId, {
                    ...cand,
                    score: candScore,
                    bridge_hop: true,
                    bridge_via: seed.symbol_name
                  });
                }
              }
            }
          }
        }

        if (bridgedById.size > 0) {
          const bridgedList = [...bridgedById.values()].sort(compareScoredSymbols);
          if (topWinners.length < maxResults) {
            const needed = maxResults - topWinners.length;
            topWinners = [...topWinners, ...bridgedList.slice(0, needed)];
            topWinners.sort(compareScoredSymbols);
          } else {
            const reserveForBridge = Math.min(2, bridgedList.length, Math.max(0, maxResults - 1));
            const keepHop1Count = Math.max(1, maxResults - reserveForBridge);
            topWinners = [
              ...topWinners.slice(0, keepHop1Count),
              ...bridgedList.slice(0, reserveForBridge)
            ];
            topWinners.sort(compareScoredSymbols);
            topWinners = topWinners.slice(0, maxResults);
          }
        }
      }
    }

    const { results, tokens_used } = hydrateAndBudgetWinners(topWinners);

    const rawCodeIdentifiers = extractCodeShapeIdentifiers(trimmedQuery);
    let unattested_query_identifiers = [];
    if (Array.isArray(rawCodeIdentifiers) && rawCodeIdentifiers.length > 0) {
      const haystack = results
        .map((r) => `${r.symbol_name || ''}\n${r.signature || ''}\n${r.file_path || ''}\n${r.snippet || ''}`)
        .join('\n')
        .toLowerCase();
      unattested_query_identifiers = rawCodeIdentifiers.filter((ident) => {
        const normalized = String(ident ?? '').replace(/^`+|`+$/g, '').toLowerCase();
        return normalized.length > 0 && !haystack.includes(normalized);
      });
    }

    return okEnvelope(
      'krusch_git_semantic_search',
      `Semantic search for "${trimmedQuery}" returned ${results.length} result(s).`,
      {
        repo: repoRecord.name,
        query: trimmedQuery,
        results,
        unattested_query_identifiers,
        tokens_used
      },
      true
    );
  }

  return {
    listRepos,
    readTree,
    readBlob,
    searchSymbols,
    fileSymbols,
    dependencyGraph,
    semanticSearch,
    indexRepo
  };
}
