import test from 'node:test';
import assert from 'node:assert/strict';
import { createFrontendEngine } from '../src/engines/frontend-engine.js';
import { ALL_STACK_TOOLS, getStackTools } from '../src/mcp/server.js';

const PRIVATE_IP_RE = /\b(?:192\.168\.\d+\.\d+|10\.10\.10\.\d+|100\.\d+\.\d+\.\d+)\b/;

test('krusch-stack canonical Lego starter templates obey INV-STACK-02, INV-STACK-04, and INV-STACK-09', () => {
  assert.equal(ALL_STACK_TOOLS.length, 39, 'ALL_STACK_TOOLS must stay strictly 39');
  const engine = createFrontendEngine({});
  const listed = engine.listCanonicalTemplates();
  assert.equal(listed.ok, true);
  assert.ok(listed.data.count >= 10);

  const tplTool = ALL_STACK_TOOLS.find((t) => t.name === 'get_canonical_template');
  assert.ok(tplTool, 'Missing get_canonical_template in ALL_STACK_TOOLS');
  const schemaEnum = tplTool.inputSchema.properties.template_id.enum;

  const ids = listed.data.templates.map((t) => t.template_id);
  assert.deepEqual([...schemaEnum].sort(), [...ids].sort(), 'MCP schema enum must match frontend-engine template IDs');

  for (const id of [
    'lego-node-api',
    'lego-mcp-server',
    'lego-sse-route',
    'lego-react-shell',
    'lego-fastapi-app'
  ]) {
    assert.ok(ids.includes(id), `Expected canonical Lego template ${id}`);
    assert.ok(schemaEnum.includes(id), `Expected ${id} in ALL_STACK_TOOLS enum`);
    const fetched = engine.getCanonicalTemplate({ template_id: id });
    assert.equal(fetched.ok, true);
    assert.equal(fetched.data.template_id, id);
    assert.ok(fetched.data.html.length > 40);
    assert.equal(PRIVATE_IP_RE.test(fetched.data.html), false, `Template ${id} leaked private IP`);
  }

  for (const protoKey of ['toString', 'constructor', 'valueOf', '__proto__']) {
    const res = engine.getCanonicalTemplate({ template_id: protoKey });
    assert.equal(res.ok, false, `Prototype key ${protoKey} must return ok: false`);

    const palette = engine.generateColorPalette({ base_hex: '#00e5ff', harmony: protoKey });
    assert.equal(palette.ok, true);
    assert.equal(palette.data.harmony_swatches.length, 2);

    const bp = engine.generateResponsiveBreakpoints({ component_type: protoKey });
    assert.equal(bp.ok, true);
    assert.ok(bp.data.tailwind_classes.includes('grid-cols-1'));
    assert.equal(bp.data.breakpoints[1].columns, 2);
    assert.equal(bp.data.breakpoints[2].columns, 3);

    const stackTools = getStackTools({ profile: 'full', server: protoKey });
    assert.equal(stackTools.length, 39);
  }

  const tw = engine.cssToTailwind({
    css: 'display: constructor; flex-direction: toString; padding: constructor; border-radius: toString; font-weight: valueOf; text-align: __proto__; width: ;'
  });
  assert.equal(tw.ok, true);
  assert.equal(tw.data.className.includes('function'), false);
  assert.equal(tw.data.className.includes('Object'), false);
  assert.deepEqual(tw.data.classes, ['p-[constructor]', 'rounded-[tostring]']);

  // REF13-03: Linear O(N) unclosed CSS comment stripping + safe arbitrary value sanitization
  const t0 = performance.now();
  const commentFlood = engine.cssToTailwind({ css: '/* '.repeat(25000) });
  const elapsedMs = performance.now() - t0;
  assert.equal(commentFlood.ok, true);
  assert.deepEqual(commentFlood.data.classes, []);
  assert.ok(elapsedMs < 50, `Expected O(N) comment strip <50ms, took ${elapsedMs.toFixed(1)}ms`);

  const validCalc = engine.cssToTailwind({
    css: '.card { width: calc(100% - 2rem); padding: 4px 8px; } /* trailing */'
  });
  assert.deepEqual(validCalc.data.classes, ['w-[calc(100%_-_2rem)]', 'p-[4px_8px]']);

  const unsafeVals = engine.cssToTailwind({
    css: 'width: 10px" data-bad="1; height: 5px] bad [; margin: url(https://invalid.example);'
  });
  assert.deepEqual(unsafeVals.data.classes, []);
  assert.ok(unsafeVals.data.unmapped.length >= 2);

  // REF14-01: monochromatic harmony, split-complementary enum parity, and #000000 zero-lightness preservation
  const paletteTool = ALL_STACK_TOOLS.find((t) => t.name === 'generate_color_palette');
  assert.deepEqual(
    paletteTool.inputSchema.properties.harmony.enum,
    ['complementary', 'analogous', 'triadic', 'split-complementary', 'monochromatic']
  );

  const mono = engine.generateColorPalette({ base_hex: '#00e5ff', harmony: 'monochromatic' });
  assert.equal(mono.ok, true);
  assert.equal(mono.data.harmony, 'monochromatic');
  assert.equal(mono.data.harmony_swatches.length, 1);
  assert.equal(mono.data.harmony_swatches[0].hue_offset, 0);
  assert.equal(mono.data.harmony_swatches[0].hex, '#00e5ff');

  const black = engine.generateColorPalette({ base_hex: '#000000', harmony: 'complementary' });
  assert.equal(black.ok, true);
  assert.equal(black.data.palette.find((s) => s.stop === 500).hsl.l, 0);
  assert.equal(black.data.harmony_swatches[0].hex, '#000000');
  assert.equal(black.data.harmony_swatches[1].hex, '#000000');
});

