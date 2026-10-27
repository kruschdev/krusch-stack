/**
 * @module mcp/deferred-bridge
 * In-memory Okapi BM25 Deferred Tool Bridge for KruschStack (INV-HE-05).
 * Collapses the 39-tool catalog into 6 pinned high-frequency tools + 3 BM25 meta-tools
 * (`krusch_tool_search`, `krusch_tool_describe`, `krusch_tool_call`) while preserving
 * INV-STACK-02 envelopes, INV-STACK-03 4-boolean annotations, and INV-STACK-05 profile boundaries.
 */

import { okEnvelope } from '../db/sqlite.js';

const BM25_K1 = 1.2;
const BM25_B = 0.75;

const FIELD_WEIGHTS = Object.freeze({
  name: 3.0,
  title: 2.0,
  component: 1.5,
  params: 1.5,
  description: 1.0
});

const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
  'in', 'into', 'is', 'it', 'of', 'on', 'or', 'that', 'the', 'this',
  'to', 'with'
]);

const KNOWN_TOOL_COMPONENTS = Object.freeze({
  krusch_context_retrieve: 'context',
  krusch_context_remember: 'context',
  krusch_context_revise: 'context',
  krusch_context_nudge: 'context',
  krusch_context_health: 'context',
  krusch_git_list_repos: 'git',
  krusch_git_read_tree: 'git',
  krusch_git_read_blob: 'git',
  krusch_git_search_symbols: 'git',
  krusch_git_file_symbols: 'git',
  krusch_git_dependency_graph: 'git',
  krusch_git_semantic_search: 'git',
  krusch_fs_locate: 'fs',
  krusch_fs_search: 'fs',
  krusch_fs_page_tree: 'fs',
  krusch_fs_read_page: 'fs',
  krusch_fs_remember_on_page: 'fs',
  krusch_fs_sync: 'fs',
  krusch_run: 'harness',
  krusch_task_status: 'harness',
  krusch_diff: 'harness',
  krusch_apply_diff: 'harness',
  krusch_explain: 'harness',
  krusch_reject: 'harness',
  krusch_abort: 'harness',
  generate_color_palette: 'frontend',
  css_to_tailwind: 'frontend',
  query_design_rules: 'frontend',
  get_canonical_template: 'frontend',
  list_canonical_templates: 'frontend',
  generate_responsive_breakpoints: 'frontend',
  get_agent_steering: 'workspace',
  search_drive_rag: 'workspace',
  read_drive_file: 'workspace',
  write_drive_file: 'workspace',
  list_drive_workspace: 'workspace',
  get_workspace_status: 'workspace',
  krusch_route_task: 'router',
  krusch_stack_status: 'router'
});

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) {
      deepFreeze(value[key]);
    }
  }
  return value;
}

export const PINNED_CORE_TOOL_NAMES = Object.freeze([
  'krusch_context_retrieve',
  'krusch_context_remember',
  'krusch_context_nudge',
  'krusch_git_search_symbols',
  'krusch_fs_locate',
  'krusch_run'
]);

export const DEFERRED_BRIDGE_TOOL_NAMES = Object.freeze([
  'krusch_tool_search',
  'krusch_tool_describe',
  'krusch_tool_call'
]);

const BRIDGE_TOOL_NAME_SET = new Set(DEFERRED_BRIDGE_TOOL_NAMES);

export const DEFERRED_BRIDGE_TOOLS = deepFreeze([
  {
    name: 'krusch_tool_search',
    description: 'Search deferred KruschStack tools using Okapi BM25 ranking across names, titles, pillars, parameters, and descriptions.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search keywords for locating relevant KruschStack tools'
        },
        component: {
          type: 'string',
          description: 'Optional pillar filter (context, git, fs, harness, frontend, workspace, router)'
        },
        limit: {
          type: 'number',
          default: 8,
          description: 'Maximum ranked tool summaries to return'
        }
      },
      required: ['query']
    },
    annotations: {
      title: 'Search Deferred KruschStack Tools (BM25)',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  {
    name: 'krusch_tool_describe',
    description: 'Inspect the full JSON inputSchema and MCP annotations for a KruschStack tool prior to invocation.',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'Exact KruschStack tool name to inspect'
        }
      },
      required: ['tool_name']
    },
    annotations: {
      title: 'Inspect Full Schema for a KruschStack Tool',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false
    }
  },
  {
    name: 'krusch_tool_call',
    description: 'Invoke an enabled KruschStack tool by name with structured JSON arguments.',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'Exact KruschStack tool name to invoke'
        },
        arguments: {
          type: 'object',
          description: 'Arguments object forwarded to the target KruschStack tool'
        }
      },
      required: ['tool_name']
    },
    annotations: {
      title: 'Invoke a Deferred KruschStack Tool',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false
    }
  }
]);

/**
 * Split snake_case, camelCase, PascalCase, kebab-case, and punctuation into lowercase alphanumeric tokens.
 * @param {string} text
 * @returns {string[]}
 */
function tokenizeIdentifierOrProse(text) {
  if (typeof text !== 'string' || !text) return [];
  const expanded = text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
  if (!expanded) return [];
  return expanded.split(/\s+/).filter(Boolean);
}

/**
 * Light plural stemmer for identifier/prose tokens without distorting short acronyms (e.g. css, fs, wcag).
 * @param {string} token
 * @returns {string}
 */
function lightStem(token) {
  if (token.length < 4) return token;
  if (token.length >= 5 && token.endsWith('ies')) {
    return `${token.slice(0, -3)}y`;
  }
  if (
    token.endsWith('s') &&
    !token.endsWith('ss') &&
    !token.endsWith('us') &&
    !token.endsWith('is')
  ) {
    return token.slice(0, -1);
  }
  return token;
}

/**
 * Infer a tool's component pillar even when `getStackTools()` has stripped the internal `component` key.
 * @param {object} tool
 * @returns {string}
 */
function resolveToolComponent(tool) {
  if (typeof tool?.component === 'string' && tool.component.trim()) {
    return tool.component.trim().toLowerCase();
  }
  const name = typeof tool?.name === 'string' ? tool.name : '';
  if (KNOWN_TOOL_COMPONENTS[name]) {
    return KNOWN_TOOL_COMPONENTS[name];
  }
  if (name.startsWith('krusch_context_')) return 'context';
  if (name.startsWith('krusch_git_')) return 'git';
  if (name.startsWith('krusch_fs_')) return 'fs';
  return '';
}

/**
 * Strip internal-only `component` property before exposing an MCP tool definition on `tools/list` or `describeTool`.
 * @param {object} tool
 * @returns {object}
 */
function toPublicToolDefinition(tool) {
  const { component: _component, ...publicDef } = tool;
  return publicDef;
}

/**
 * Create an in-memory Okapi BM25 deferred tool bridge over a profile-filtered KruschStack tool list.
 *
 * @param {Array<object>} allowedTools
 * @param {object} [options]
 * @param {string[]} [options.pinnedToolNames]
 * @param {(toolName: string, args: object) => Promise<any> | any} [options.dispatcher]
 */
export function createStackDeferredBridge(allowedTools = [], options = {}) {
  const inputList = Array.isArray(allowedTools) ? allowedTools : [];
  const pinnedNames = Array.isArray(options.pinnedToolNames)
    ? options.pinnedToolNames
    : PINNED_CORE_TOOL_NAMES;
  const pinnedSet = new Set(pinnedNames);
  const dispatcher = typeof options.dispatcher === 'function' ? options.dispatcher : null;

  // Filter out bridge meta-tools if ever passed in allowedTools to prevent self-indexing/recursion
  const underlyingRawTools = inputList.filter(
    (tool) => tool && typeof tool.name === 'string' && !BRIDGE_TOOL_NAME_SET.has(tool.name)
  );

  const docs = [];
  const toolByName = new Map();
  const docFreq = new Map();
  let totalDocLength = 0;

  for (const rawTool of underlyingRawTools) {
    const publicTool = toPublicToolDefinition(rawTool);
    const component = resolveToolComponent(rawTool);
    const propKeys = Object.keys(rawTool.inputSchema?.properties || {});
    const requiredParams = Array.isArray(rawTool.inputSchema?.required)
      ? [...rawTool.inputSchema.required]
      : [];

    const weightedTf = new Map();
    let docLength = 0;

    const addFieldTokens = (tokens, weight) => {
      for (const tok of tokens) {
        weightedTf.set(tok, (weightedTf.get(tok) || 0) + weight);
        docLength += weight;
        const stem = lightStem(tok);
        if (stem !== tok) {
          weightedTf.set(stem, (weightedTf.get(stem) || 0) + weight * 0.4);
        }
      }
    };

    addFieldTokens(tokenizeIdentifierOrProse(rawTool.name), FIELD_WEIGHTS.name);
    addFieldTokens(tokenizeIdentifierOrProse(rawTool.annotations?.title || ''), FIELD_WEIGHTS.title);
    addFieldTokens(tokenizeIdentifierOrProse(component), FIELD_WEIGHTS.component);
    addFieldTokens(propKeys.flatMap((key) => tokenizeIdentifierOrProse(key)), FIELD_WEIGHTS.params);
    addFieldTokens(
      tokenizeIdentifierOrProse(rawTool.description || '').filter((tok) => !STOP_WORDS.has(tok)),
      FIELD_WEIGHTS.description
    );

    const effectiveDocLength = docLength > 0 ? docLength : 1;
    totalDocLength += effectiveDocLength;

    for (const term of weightedTf.keys()) {
      docFreq.set(term, (docFreq.get(term) || 0) + 1);
    }

    const entry = {
      name: rawTool.name,
      title: rawTool.annotations?.title || rawTool.name,
      description: rawTool.description || '',
      component,
      requiredParams,
      publicTool,
      weightedTf,
      docLength: effectiveDocLength
    };

    docs.push(entry);
    toolByName.set(rawTool.name, entry);
  }

  const totalDocs = docs.length;
  const avgDocLength = totalDocs > 0 ? totalDocLength / totalDocs : 1;

  const pinnedExposedTools = docs
    .filter((entry) => pinnedSet.has(entry.name))
    .map((entry) => entry.publicTool);

  const exposedTools = Object.freeze([...pinnedExposedTools, ...DEFERRED_BRIDGE_TOOLS]);
  const publicUnderlyingTools = docs.map((entry) => entry.publicTool);
  const fullSchemaBytes = Buffer.byteLength(JSON.stringify(publicUnderlyingTools), 'utf8');
  const exposedSchemaBytes = Buffer.byteLength(JSON.stringify(exposedTools), 'utf8');
  const reductionPct = fullSchemaBytes > 0
    ? Number((((fullSchemaBytes - exposedSchemaBytes) / fullSchemaBytes) * 100).toFixed(2))
    : 0;

  function computeIdf(term) {
    const df = docFreq.get(term) || 0;
    if (df === 0 || totalDocs === 0) return 0;
    return Math.log(1 + (totalDocs - df + 0.5) / (df + 0.5));
  }

  function isBridgeTool(name) {
    return typeof name === 'string' && BRIDGE_TOOL_NAME_SET.has(name);
  }

  function isAllowedUnderlyingTool(name) {
    return typeof name === 'string' && !BRIDGE_TOOL_NAME_SET.has(name) && toolByName.has(name);
  }

  function searchTools(args = {}) {
    const safeArgs = args && typeof args === 'object' ? args : {};
    const rawQuery = typeof safeArgs.query === 'string' ? safeArgs.query : '';
    const trimmedQuery = rawQuery.trim();
    const componentFilter = typeof safeArgs.component === 'string' && safeArgs.component.trim()
      ? safeArgs.component.trim().toLowerCase()
      : null;
    const parsedLimit = Number(safeArgs.limit);
    const limit = Number.isFinite(parsedLimit) && parsedLimit > 0
      ? Math.min(50, Math.max(1, Math.floor(parsedLimit)))
      : 8;

    const candidates = componentFilter
      ? docs.filter((doc) => doc.component === componentFilter)
      : docs;

    if (trimmedQuery === '*' || (trimmedQuery === '' && componentFilter)) {
      const wildcardResults = candidates.slice(0, limit).map((doc) => ({
        name: doc.name,
        title: doc.title,
        description: doc.description,
        required_params: [...doc.requiredParams],
        score: 0
      }));
      return okEnvelope(
        'krusch_tool_search',
        `Listed ${wildcardResults.length} of ${totalDocs} KruschStack tools`,
        {
          query: rawQuery,
          total_catalog: totalDocs,
          results: wildcardResults
        }
      );
    }

    const rawTokens = tokenizeIdentifierOrProse(trimmedQuery);
    const filteredTokens = rawTokens.filter((tok) => !STOP_WORDS.has(tok));
    const queryTokens = filteredTokens.length > 0 ? filteredTokens : rawTokens;

    if (queryTokens.length === 0) {
      return okEnvelope(
        'krusch_tool_search',
        `Matched 0 of ${totalDocs} KruschStack tools for empty query`,
        {
          query: rawQuery,
          total_catalog: totalDocs,
          results: []
        }
      );
    }

    // Deduplicate query terms while preserving expanded stem fallback weights
    const queryTermWeights = new Map();
    for (const tok of queryTokens) {
      queryTermWeights.set(tok, (queryTermWeights.get(tok) || 0) + 1.0);
      const stem = lightStem(tok);
      if (stem !== tok && !queryTermWeights.has(stem)) {
        queryTermWeights.set(stem, 0.35);
      }
    }

    const scored = [];
    for (const doc of candidates) {
      let score = 0;
      const lengthNorm = 1 - BM25_B + BM25_B * (doc.docLength / avgDocLength);
      for (const [term, qWeight] of queryTermWeights.entries()) {
        const tf = doc.weightedTf.get(term) || 0;
        if (tf <= 0) continue;
        const idf = computeIdf(term);
        const bm25Term = idf * ((tf * (BM25_K1 + 1)) / (tf + BM25_K1 * lengthNorm));
        score += bm25Term * qWeight;
      }
      if (score > 0) {
        scored.push({
          doc,
          score: Number(score.toFixed(4))
        });
      }
    }

    scored.sort((a, b) => b.score - a.score || a.doc.name.localeCompare(b.doc.name));

    const results = scored.slice(0, limit).map(({ doc, score }) => ({
      name: doc.name,
      title: doc.title,
      description: doc.description,
      required_params: [...doc.requiredParams],
      score
    }));

    return okEnvelope(
      'krusch_tool_search',
      `Found ${results.length} matching KruschStack tools (catalog: ${totalDocs})`,
      {
        query: rawQuery,
        total_catalog: totalDocs,
        results
      }
    );
  }

  function describeTool(args = {}) {
    const safeArgs = args && typeof args === 'object' ? args : {};
    const toolName = typeof safeArgs.tool_name === 'string' ? safeArgs.tool_name.trim() : '';

    if (!toolName) {
      return okEnvelope(
        'krusch_tool_describe',
        'Missing required parameter: tool_name',
        { error: 'Parameter "tool_name" must be a non-empty string' },
        false
      );
    }

    if (!isAllowedUnderlyingTool(toolName)) {
      return okEnvelope(
        'krusch_tool_describe',
        `Tool '${toolName}' is not available in the active profile`,
        {
          error: `Tool '${toolName}' is unknown, recursive, or disabled in the active KruschStack profile`
        },
        false
      );
    }

    const entry = toolByName.get(toolName);
    return okEnvelope(
      'krusch_tool_describe',
      `Retrieved full schema for ${toolName}`,
      { tool: entry.publicTool }
    );
  }

  async function callTool(args = {}) {
    const safeArgs = args && typeof args === 'object' ? args : {};
    const toolName = typeof safeArgs.tool_name === 'string' ? safeArgs.tool_name.trim() : '';

    if (!toolName) {
      return okEnvelope(
        'krusch_tool_call',
        'Missing required parameter: tool_name',
        { error: 'Parameter "tool_name" must be a non-empty string' },
        false
      );
    }

    if (isBridgeTool(toolName)) {
      return okEnvelope(
        'krusch_tool_call',
        `Recursive bridge call rejected for '${toolName}'`,
        {
          error: `Recursive invocation of deferred bridge meta-tool '${toolName}' is not permitted`
        },
        false
      );
    }

    if (!isAllowedUnderlyingTool(toolName)) {
      return okEnvelope(
        'krusch_tool_call',
        `Tool '${toolName}' is not enabled in the active profile`,
        {
          error: `MethodNotFound: Tool '${toolName}' is unknown or excluded by the active KruschStack profile`
        },
        false
      );
    }

    const rawToolArgs = safeArgs.arguments;
    if (
      rawToolArgs !== undefined &&
      rawToolArgs !== null &&
      (typeof rawToolArgs !== 'object' || Array.isArray(rawToolArgs))
    ) {
      return okEnvelope(
        'krusch_tool_call',
        `Invalid arguments payload for '${toolName}'`,
        { error: 'Parameter "arguments" must be a plain JSON object' },
        false
      );
    }

    if (!dispatcher) {
      return okEnvelope(
        'krusch_tool_call',
        `No dispatcher configured for '${toolName}'`,
        { error: 'Deferred bridge was initialized without an underlying tool dispatcher' },
        false
      );
    }

    const resolvedArgs = rawToolArgs && typeof rawToolArgs === 'object' ? rawToolArgs : {};
    try {
      const result = await dispatcher(toolName, resolvedArgs);
      if (
        result &&
        typeof result === 'object' &&
        typeof result.ok === 'boolean' &&
        typeof result.tool === 'string'
      ) {
        return result;
      }
      return okEnvelope(toolName, `Executed ${toolName}`, result ?? {});
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return okEnvelope(
        'krusch_tool_call',
        `Execution failed for '${toolName}': ${message}`,
        { error: message },
        false
      );
    }
  }

  function getStats() {
    return {
      fullToolCount: totalDocs,
      exposedToolCount: exposedTools.length,
      fullSchemaBytes,
      exposedSchemaBytes,
      reductionPct
    };
  }

  return {
    exposedTools,
    isBridgeTool,
    isAllowedUnderlyingTool,
    searchTools,
    describeTool,
    callTool,
    getStats
  };
}
