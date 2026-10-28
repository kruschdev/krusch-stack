import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  createKruschStack,
  parseJavaSymbols,
  analyzeImportSymbolActivity
} from '../src/index.js';

describe('Tier 2A Java AST & Live Import Activity Parity (krusch-git v1.2.3)', () => {
  it('parseJavaSymbols extracts classes, interfaces, @interface, enums, records, methods, and cross-file edges', () => {
    const javaSource = [
      'package com.acme.resilience;',
      '',
      'import java.util.List;',
      'import static com.acme.metrics.Telemetry.recordLatency;',
      '',
      '// Comment with fake brace: class FakeInComment { void nope() {} }',
      'public interface OrderPolicy {',
      '  boolean canAccept(String tenantId, int amountCents) throws IllegalArgumentException;',
      '}',
      '',
      'public enum CircuitState {',
      '  CLOSED, OPEN, HALF_OPEN',
      '}',
      '',
      'public record RetryBudget(int maxAttempts, long backoffMs) {',
      '}',
      '',
      '@interface Audited {',
      '}',
      '',
      'public final class OrderGateway implements OrderPolicy {',
      '  private final String label = "string { not a class }";',
      '',
      '  public OrderGateway() {',
      '  }',
      '',
      '  @Override',
      '  public boolean canAccept(String tenantId, int amountCents) {',
      '    recordLatency(tenantId, amountCents);',
      '    return amountCents > 0;',
      '  }',
      '}'
    ].join('\n');

    const { symbols, edges } = parseJavaSymbols(javaSource);
    const names = symbols.map((s) => s.symbol_name);

    assert.ok(names.includes('OrderPolicy'));
    assert.ok(names.includes('OrderPolicy.canAccept'));
    assert.ok(names.includes('CircuitState'));
    assert.ok(names.includes('RetryBudget'));
    assert.ok(names.includes('Audited'));
    assert.ok(names.includes('OrderGateway'));
    assert.ok(names.includes('OrderGateway.OrderGateway'));
    assert.ok(names.includes('OrderGateway.canAccept'));
    assert.ok(!names.includes('FakeInComment'));

    const importTargets = edges.filter((e) => e.edge_type === 'imports').map((e) => e.to_symbol);
    assert.ok(importTargets.includes('List'));
    assert.ok(importTargets.includes('Telemetry'));
    assert.ok(importTargets.includes('recordLatency'));

    const callTargets = edges.filter((e) => e.edge_type === 'calls').map((e) => e.to_symbol);
    assert.ok(callTargets.includes('recordLatency'));
  });

  it('indexRepo indexes .java files end-to-end and bridges cross-file Java symbols via INV-STACK-09', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'krusch-stack-java-'));
    try {
      const srcDir = path.join(tmpDir, 'src', 'main', 'java', 'acme');
      fs.mkdirSync(srcDir, { recursive: true });

      fs.writeFileSync(
        path.join(srcDir, 'CircuitBreakerRegistry.java'),
        [
          'package acme;',
          '',
          'public class CircuitBreakerRegistry {',
          '  public boolean allowExecution(String routeKey, int quorumThreshold) {',
          '    return quorumThreshold > 0 && routeKey != null;',
          '  }',
          '}'
        ].join('\n'),
        'utf8'
      );

      fs.writeFileSync(
        path.join(srcDir, 'PaymentDispatcher.java'),
        [
          'package acme;',
          '',
          'import acme.CircuitBreakerRegistry;',
          '',
          'public class PaymentDispatcher {',
          '  private final CircuitBreakerRegistry registry = new CircuitBreakerRegistry();',
          '',
          '  public boolean dispatchSettlement(String merchantAccount, int cents) {',
          '    return registry.allowExecution(merchantAccount, cents);',
          '  }',
          '}'
        ].join('\n'),
        'utf8'
      );

      const stack = createKruschStack({ workspaceRoot: tmpDir, ephemeral: true });
      const idxRes = stack.git.indexRepo({ repoPath: tmpDir, repoName: 'acme-java' });
      assert.equal(idxRes.ok, true);
      assert.equal(idxRes.data.files_indexed, 2);

      const fileSyms = stack.git.fileSymbols({
        repo: 'acme-java',
        file_path: 'src/main/java/acme/PaymentDispatcher.java'
      });
      assert.equal(fileSyms.ok, true);
      assert.ok(fileSyms.data.symbols.some((s) => s.symbol_name === 'PaymentDispatcher.dispatchSettlement'));

      const depGraph = stack.git.dependencyGraph({
        repo: 'acme-java',
        symbol: 'CircuitBreakerRegistry'
      });
      assert.equal(depGraph.ok, true);
      assert.ok(depGraph.data.inbound.some((e) => e.from_symbol === 'PaymentDispatcher'));

      const searchRes = stack.git.semanticSearch({
        repo: 'acme-java',
        query: 'dispatchSettlement quorumThreshold',
        limit: 5
      });
      assert.equal(searchRes.ok, true);
      const hitNames = searchRes.data.results.map((r) => r.symbol_name);
      assert.ok(hitNames.includes('PaymentDispatcher.dispatchSettlement'));
      assert.ok(
        hitNames.some((n) => n.startsWith('CircuitBreakerRegistry')),
        `Expected 2-hop/hybrid Java search to surface CircuitBreakerRegistry alongside PaymentDispatcher, got ${JSON.stringify(hitNames)}`
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('analyzeImportSymbolActivity classifies multiline commented Python & 1-hop bound receivers accurately', () => {
    const pyImports = [
      'from cache.tiered import (',
      '  HotSegmentCache as SC,  # inline comment before closing paren',
      '  ColdArchiveWriter,',
      ')',
      'from metrics.logger import AuditTrail'
    ].join('\n');

    const pyPrefix = [
      'class StorageCoordinator:',
      '    def __init__(self, cfg):',
      '        self.audit = AuditTrail(cfg)',
      '        self.audit.record_boot()',
      '        self.hot_cache = SC(max_items=512)',
      '',
      '    def fetch_entry(self, key: str):',
      '        normalized = key.strip().lower()',
      '        cached = self.hot_cache.lookup(normalized)'
    ].join('\n');

    const pyAct = analyzeImportSymbolActivity(pyPrefix, pyImports, 'coordinator.py', {
      immediateLineWindow: 3
    });

    assert.ok(pyAct.immediateCursorSymbols.includes('HotSegmentCache'));
    assert.ok(pyAct.immediateCursorSymbols.includes('SC'));
    assert.ok(pyAct.unusedStagedSymbols.includes('ColdArchiveWriter'));
    assert.ok(pyAct.earlierOnlySymbols.includes('AuditTrail'));
    assert.equal(pyAct.hasActiveCursorImport, true);
  });

  it('analyzeImportSymbolActivity handles Java static imports, typed fields, and ESM named/aliased imports', () => {
    const javaImports = [
      'import static com.acme.codec.VarintCodec.encodeUnsigned;',
      'import com.acme.resilience.CircuitBreakerRegistry;',
      'import com.acme.resilience.FallbackSnapshot;',
      'import com.acme.audit.LegacyTracer;'
    ].join('\n');

    const javaPrefix = [
      'public class FrameWriter {',
      '  private final CircuitBreakerRegistry breakerRegistry;',
      '  public FrameWriter(CircuitBreakerRegistry reg) {',
      '    LegacyTracer.init();',
      '    this.breakerRegistry = reg;',
      '  }',
      '  public byte[] writeHeader(int frameId) {',
      '    if (!breakerRegistry.isOpen(frameId)) {',
      '      return encodeUnsigned(frameId);'
    ].join('\n');

    const javaAct = analyzeImportSymbolActivity(javaPrefix, javaImports, 'FrameWriter.java', {
      immediateLineWindow: 3
    });

    assert.ok(javaAct.immediateCursorSymbols.includes('CircuitBreakerRegistry'));
    assert.ok(javaAct.immediateCursorSymbols.includes('encodeUnsigned'));
    assert.ok(javaAct.unusedStagedSymbols.includes('FallbackSnapshot'));
    assert.ok(javaAct.earlierOnlySymbols.includes('LegacyTracer'));

    const jsAct = analyzeImportSymbolActivity(
      [
        "import { createSigner as makeSigner, verifyDigest, unusedHelper } from './crypto-core.js';",
        'function boot() {',
        '  verifyDigest("init");',
        '}',
        'function signPayload(buf) {',
        '  const signer = makeSigner();',
        '  return signer.sign(buf);'
      ].join('\n'),
      '',
      'src/auth.js',
      { immediateLineWindow: 3 }
    );

    assert.ok(jsAct.immediateCursorSymbols.includes('createSigner'));
    assert.ok(jsAct.unusedStagedSymbols.includes('unusedHelper'));
    assert.ok(jsAct.earlierOnlySymbols.includes('verifyDigest'));
  });
});
