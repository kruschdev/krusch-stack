import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { createKruschStack } from '../src/index.js';
import {
  ALL_STACK_TOOLS,
  getStackTools,
  dispatchStackTool,
  createMcpServer
} from '../src/mcp/server.js';
import { parseCliArgs } from '../bin/krusch-stack.js';
import {
  PINNED_CORE_TOOL_NAMES,
  DEFERRED_BRIDGE_TOOL_NAMES,
  DEFERRED_BRIDGE_TOOLS,
  createStackDeferredBridge
} from '../src/mcp/deferred-bridge.js';

describe('KruschStack Deferred Tool Bridge (INV-HE-05)', () => {
  test('Exports frozen constants and INV-STACK-03 4-boolean annotations on all bridge tools', () => {
    assert.deepEqual(PINNED_CORE_TOOL_NAMES, [
      'krusch_context_retrieve',
      'krusch_context_remember',
      'krusch_context_nudge',
      'krusch_git_search_symbols',
      'krusch_fs_locate',
      'krusch_run'
    ]);
    assert.equal(Object.isFrozen(PINNED_CORE_TOOL_NAMES), true);

    assert.deepEqual(DEFERRED_BRIDGE_TOOL_NAMES, [
      'krusch_tool_search',
      'krusch_tool_describe',
      'krusch_tool_call'
    ]);
    assert.equal(Object.isFrozen(DEFERRED_BRIDGE_TOOL_NAMES), true);

    assert.equal(DEFERRED_BRIDGE_TOOLS.length, 3);
    assert.equal(Object.isFrozen(DEFERRED_BRIDGE_TOOLS), true);

    for (const tool of DEFERRED_BRIDGE_TOOLS) {
      assert.equal(Object.isFrozen(tool), true);
      assert.equal(Object.isFrozen(tool.annotations), true);
      assert.equal(Object.isFrozen(tool.inputSchema), true);
      assert.equal(typeof tool.annotations.title, 'string');
      assert.ok(tool.annotations.title.length > 0);
      for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
        assert.equal(
          typeof tool.annotations[hint],
          'boolean',
          `Bridge tool ${tool.name} must define boolean ${hint}`
        );
      }
    }

    const searchDef = DEFERRED_BRIDGE_TOOLS.find((t) => t.name === 'krusch_tool_search');
    assert.deepEqual(searchDef.inputSchema.required, ['query']);
    assert.equal(searchDef.inputSchema.properties.limit.default, 8);
    assert.equal(searchDef.annotations.readOnlyHint, true);
    assert.equal(searchDef.annotations.idempotentHint, true);

    const describeDef = DEFERRED_BRIDGE_TOOLS.find((t) => t.name === 'krusch_tool_describe');
    assert.deepEqual(describeDef.inputSchema.required, ['tool_name']);
    assert.equal(describeDef.annotations.readOnlyHint, true);
    assert.equal(describeDef.annotations.idempotentHint, true);

    const callDef = DEFERRED_BRIDGE_TOOLS.find((t) => t.name === 'krusch_tool_call');
    assert.deepEqual(callDef.inputSchema.required, ['tool_name']);
    assert.equal(callDef.annotations.readOnlyHint, false);
    assert.equal(callDef.annotations.destructiveHint, false);
    assert.equal(callDef.annotations.idempotentHint, false);
    assert.equal(callDef.annotations.openWorldHint, false);
  });

  test('Compresses full 39-tool catalog to 9 exposed tools with >60% schema byte reduction', () => {
    assert.equal(ALL_STACK_TOOLS.length, 39);
    const bridge = createStackDeferredBridge(ALL_STACK_TOOLS);

    assert.equal(bridge.exposedTools.length, 9);
    assert.equal(Object.isFrozen(bridge.exposedTools), true);
    assert.deepEqual(
      bridge.exposedTools.map((t) => t.name),
      [...PINNED_CORE_TOOL_NAMES, ...DEFERRED_BRIDGE_TOOL_NAMES]
    );

    // Internal `component` field must be stripped from exposed MCP tool schemas
    for (const tool of bridge.exposedTools) {
      assert.equal('component' in tool, false, `Exposed tool ${tool.name} must not leak internal component key`);
      for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
        assert.equal(typeof tool.annotations[hint], 'boolean');
      }
    }

    const stats = bridge.getStats();
    assert.equal(stats.fullToolCount, 39);
    assert.equal(stats.exposedToolCount, 9);
    assert.ok(stats.fullSchemaBytes > stats.exposedSchemaBytes);
    assert.ok(
      stats.reductionPct > 60,
      `Expected >60% schema byte reduction, got ${stats.reductionPct}% (${stats.exposedSchemaBytes}/${stats.fullSchemaBytes} bytes)`
    );
  });

  test('Okapi BM25 ranks target tools #1 across all 7 KruschStack pillars and camelCase/snake_case queries', () => {
    // Pass getStackTools({ profile: 'full' }) where .component was stripped to verify component inference as well
    const fullTools = getStackTools({ profile: 'full' });
    assert.equal(fullTools.length, 39);
    const bridge = createStackDeferredBridge(fullTools);

    const expectedTopHits = [
      // Required benchmark queries
      { query: 'color palette', expected: 'generate_color_palette' },
      { query: 'wcag', expected: 'generate_color_palette' },
      { query: 'drive', expected: 'search_drive_rag' },
      { query: 'dependency graph', expected: 'krusch_git_dependency_graph' },
      { query: 'page tree', expected: 'krusch_fs_page_tree' },
      { query: 'abort', expected: 'krusch_abort' },

      // Additional coverage across all 7 pillars
      { query: 'supersede invalidate memory', expected: 'krusch_context_revise' },
      { query: 'memory store health', expected: 'krusch_context_health' },
      { query: 'read file blob', expected: 'krusch_git_read_blob' },
      { query: 'anchor note on page', expected: 'krusch_fs_remember_on_page' },
      { query: 'apply verified diff', expected: 'krusch_apply_diff' },
      { query: 'css to tailwind', expected: 'css_to_tailwind' },
      { query: 'responsive breakpoints', expected: 'generate_responsive_breakpoints' },
      { query: 'gdoc gsheet slides', expected: 'write_drive_file' },
      { query: 'route task cascade', expected: 'krusch_route_task' },
      { query: 'stack status readiness', expected: 'krusch_stack_status' },

      // camelCase & parameter name queries
      { query: 'generateColorPalette', expected: 'generate_color_palette' },
      { query: 'templateId canonical', expected: 'get_canonical_template' },
      { query: 'quoted_sentence provenance', expected: 'krusch_context_remember' }
    ];

    for (const { query, expected } of expectedTopHits) {
      const res = bridge.searchTools({ query, limit: 5 });
      assert.equal(res.ok, true);
      assert.equal(res.tool, 'krusch_tool_search');
      assert.equal(res.data.total_catalog, 39);
      assert.ok(res.data.results.length >= 1, `Expected >=1 result for query "${query}"`);
      assert.equal(
        res.data.results[0].name,
        expected,
        `Expected "${expected}" to rank #1 for query "${query}", got "${res.data.results[0].name}"`
      );
      assert.equal(typeof res.data.results[0].title, 'string');
      assert.equal(typeof res.data.results[0].description, 'string');
      assert.equal(Array.isArray(res.data.results[0].required_params), true);
      assert.ok(res.data.results[0].score > 0);
    }

    // Component filter narrows results strictly to the requested pillar
    const frontendOnly = bridge.searchTools({ query: '*', component: 'frontend', limit: 10 });
    assert.equal(frontendOnly.ok, true);
    assert.equal(frontendOnly.data.results.length, 6);
    assert.ok(frontendOnly.data.results.some((r) => r.name === 'css_to_tailwind'));
    assert.ok(frontendOnly.data.results.every((r) => !r.name.startsWith('krusch_git_')));

    // Empty query without component filter returns clean empty array
    const emptySearch = bridge.searchTools({ query: '   ' });
    assert.equal(emptySearch.ok, true);
    assert.deepEqual(emptySearch.data.results, []);
  });

  test('describeTool returns full schema for allowed tools and ok=false for missing or bridge tools', () => {
    const bridge = createStackDeferredBridge(ALL_STACK_TOOLS);

    const desc = bridge.describeTool({ tool_name: 'krusch_git_dependency_graph' });
    assert.equal(desc.ok, true);
    assert.equal(desc.tool, 'krusch_tool_describe');
    assert.equal(desc.data.tool.name, 'krusch_git_dependency_graph');
    assert.deepEqual(desc.data.tool.inputSchema.required, ['symbol']);
    assert.equal(desc.data.tool.annotations.readOnlyHint, true);
    assert.equal('component' in desc.data.tool, false);

    const missingParam = bridge.describeTool({});
    assert.equal(missingParam.ok, false);
    assert.equal(missingParam.tool, 'krusch_tool_describe');
    assert.match(missingParam.data.error, /tool_name/);

    const unknown = bridge.describeTool({ tool_name: 'non_existent_tool' });
    assert.equal(unknown.ok, false);
    assert.equal(unknown.tool, 'krusch_tool_describe');

    const bridgeSelf = bridge.describeTool({ tool_name: 'krusch_tool_call' });
    assert.equal(bridgeSelf.ok, false);
    assert.equal(bridgeSelf.tool, 'krusch_tool_describe');
  });

  test('Enforces profile isolation (core excludes frontend/workspace) and blocks recursive krusch_tool_* calls', async () => {
    const dispatchedCalls = [];
    const coreTools = getStackTools({ profile: 'core' });
    assert.equal(coreTools.length, 27);

    const bridge = createStackDeferredBridge(coreTools, {
      dispatcher: async (toolName, toolArgs) => {
        dispatchedCalls.push({ toolName, toolArgs });
        return {
          ok: true,
          tool: toolName,
          summary: `Mock dispatched ${toolName}`,
          data: { echoed: toolArgs }
        };
      }
    });

    assert.equal(bridge.exposedTools.length, 9);
    assert.equal(bridge.isAllowedUnderlyingTool('krusch_abort'), true);
    assert.equal(bridge.isAllowedUnderlyingTool('generate_color_palette'), false);
    assert.equal(bridge.isAllowedUnderlyingTool('search_drive_rag'), false);

    // Out-of-profile tools do not appear in search, describe, or call
    const frontendSearch = bridge.searchTools({ query: 'color palette wcag' });
    assert.equal(
      frontendSearch.data.results.some((r) => r.name === 'generate_color_palette'),
      false
    );

    const forbiddenDescribe = bridge.describeTool({ tool_name: 'generate_color_palette' });
    assert.equal(forbiddenDescribe.ok, false);

    const forbiddenCall = await bridge.callTool({
      tool_name: 'generate_color_palette',
      arguments: { base_hex: '#00e5ff' }
    });
    assert.equal(forbiddenCall.ok, false);
    assert.equal(forbiddenCall.tool, 'krusch_tool_call');
    assert.match(forbiddenCall.data.error, /MethodNotFound/);
    assert.equal(dispatchedCalls.length, 0);

    // Recursive bridge meta-tool calls are strictly rejected
    for (const metaTool of DEFERRED_BRIDGE_TOOL_NAMES) {
      assert.equal(bridge.isBridgeTool(metaTool), true);
      assert.equal(bridge.isAllowedUnderlyingTool(metaTool), false);
      const recRes = await bridge.callTool({
        tool_name: metaTool,
        arguments: { query: 'abort' }
      });
      assert.equal(recRes.ok, false);
      assert.equal(recRes.tool, 'krusch_tool_call');
      assert.match(recRes.data.error, /Recursive/i);
    }
    assert.equal(dispatchedCalls.length, 0);

    // Malformed non-object arguments payload is rejected cleanly
    const badArgsRes = await bridge.callTool({
      tool_name: 'krusch_abort',
      arguments: ['not-an-object']
    });
    assert.equal(badArgsRes.ok, false);
    assert.equal(dispatchedCalls.length, 0);

    // Allowed deferred tool dispatches cleanly and preserves underlying envelope
    const validCall = await bridge.callTool({
      tool_name: 'krusch_abort',
      arguments: { task_id: 'task-123' }
    });
    assert.equal(validCall.ok, true);
    assert.equal(validCall.tool, 'krusch_abort');
    assert.deepEqual(validCall.data.echoed, { task_id: 'task-123' });
    assert.equal(dispatchedCalls.length, 1);

    // Single modular server with zero pinned core tools exposes only the 3 bridge tools
    const frontendServerTools = getStackTools({ server: 'krusch-frontend-mcp' });
    const frontendBridge = createStackDeferredBridge(frontendServerTools);
    assert.equal(frontendBridge.exposedTools.length, 3);
  });

  test('End-to-end search -> describe -> call workflow against ephemeral KruschStack instance', async () => {
    const stack = createKruschStack({ ephemeral: true });
    try {
      const bridge = createStackDeferredBridge(getStackTools({ profile: 'full' }), {
        dispatcher: (name, args) => dispatchStackTool(stack, name, args)
      });

      // Step 1: Search for Tailwind conversion tool
      const searchRes = bridge.searchTools({ query: 'compile css tailwind utilities', limit: 3 });
      assert.equal(searchRes.ok, true);
      assert.equal(searchRes.data.results[0].name, 'css_to_tailwind');
      assert.deepEqual(searchRes.data.results[0].required_params, ['css']);

      // Step 2: Describe full schema
      const descRes = bridge.describeTool({ tool_name: 'css_to_tailwind' });
      assert.equal(descRes.ok, true);
      assert.equal(descRes.data.tool.inputSchema.properties.css.type, 'string');

      // Step 3: Call deferred tool through bridge and verify INV-STACK-02 envelope
      const callRes = await bridge.callTool({
        tool_name: 'css_to_tailwind',
        arguments: { css: 'display: flex; align-items: center;' }
      });
      assert.equal(callRes.ok, true);
      assert.equal(callRes.tool, 'css_to_tailwind');
      assert.equal(typeof callRes.summary, 'string');
      assert.ok(callRes.data);

      // Step 4: Verify graceful error envelope when dispatcher is omitted or throws
      const noDispBridge = createStackDeferredBridge(getStackTools({ profile: 'full' }));
      const noDispRes = await noDispBridge.callTool({ tool_name: 'css_to_tailwind', arguments: { css: 'color: red;' } });
      assert.equal(noDispRes.ok, false);
      assert.equal(noDispRes.tool, 'krusch_tool_call');

      const throwBridge = createStackDeferredBridge(getStackTools({ profile: 'full' }), {
        dispatcher: async () => {
          throw new Error('simulated engine fault');
        }
      });
      const throwRes = await throwBridge.callTool({ tool_name: 'css_to_tailwind', arguments: { css: 'color: red;' } });
      assert.equal(throwRes.ok, false);
      assert.equal(throwRes.tool, 'krusch_tool_call');
      assert.match(throwRes.data.error, /simulated engine fault/);
    } finally {
      stack.db.close();
    }
  });

  test('Choke-point integration: getStackTools, createMcpServer, dispatchStackTool, and CLI --defer-tools', async () => {
    assert.equal(ALL_STACK_TOOLS.length, 39);
    assert.equal(getStackTools({ profile: 'full' }).length, 39);
    assert.equal(getStackTools({ profile: 'full', deferTools: true }).length, 9);

    const parsed = parseCliArgs(['mcp', '--profile', 'core', '--defer-tools']);
    assert.equal(parsed.flags.profile, 'core');
    assert.equal(parsed.flags.deferTools, true);

    const { stack, tools, deferredBridge } = createMcpServer({
      ephemeral: true,
      profile: 'core',
      deferTools: true
    });
    try {
      assert.equal(tools.length, 9);
      assert.ok(deferredBridge);

      const searchViaDispatch = await dispatchStackTool(
        stack,
        'krusch_tool_search',
        { query: 'page tree' },
        { deferredBridge, profile: 'core' }
      );
      assert.equal(searchViaDispatch.ok, true);
      assert.equal(searchViaDispatch.data.results[0].name, 'krusch_fs_page_tree');

      const blockedFrontendViaDispatch = await dispatchStackTool(
        stack,
        'krusch_tool_call',
        { tool_name: 'generate_color_palette', arguments: {} },
        { deferredBridge, profile: 'core' }
      );
      assert.equal(blockedFrontendViaDispatch.ok, false);

      const allowedRouteViaDispatch = await dispatchStackTool(
        stack,
        'krusch_tool_call',
        { tool_name: 'krusch_route_task', arguments: { prompt: 'Run unit tests' } },
        { deferredBridge, profile: 'core' }
      );
      assert.equal(allowedRouteViaDispatch.ok, true);
      assert.equal(allowedRouteViaDispatch.tool, 'krusch_route_task');
    } finally {
      stack.db.close();
    }
  });
});
