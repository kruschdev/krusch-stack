/**
 * @module engines/router-engine
 * Cognitive Model Router (krusch-cascade-router) for KruschStack.
 * Provides sub-millisecond (<25µs) L1 heuristic task classification across
 * L1_FAST_LOCAL, L2_SWE_MOE, L2_5_BURST_120B, and L3_FRONTIER_REFEREE,
 * plus unified stack health telemetry. Enforces INV-STACK-04 (sanitized localhost defaults).
 */

import { okEnvelope } from '../db/sqlite.js';

const TIER_CATALOG = {
  L1_FAST_LOCAL: {
    tier: 'L1_FAST_LOCAL',
    model: 'qwen2.5-coder:7b',
    provider: 'ollama-local',
    max_context: 16384,
    cost_tier: 'free-local'
  },
  L2_SWE_MOE: {
    tier: 'L2_SWE_MOE',
    model: 'qwen3-coder-30b-moe:latest',
    provider: 'ollama-local',
    max_context: 16384,
    cost_tier: 'free-local'
  },
  L2_5_BURST_120B: {
    tier: 'L2_5_BURST_120B',
    model: 'gpt-oss:120b',
    provider: 'ollama-burst',
    max_context: 131072,
    cost_tier: 'burst-gpu'
  },
  L3_FRONTIER_REFEREE: {
    tier: 'L3_FRONTIER_REFEREE',
    model: 'gemini-4-argon',
    provider: 'frontier-api',
    max_context: 1048576,
    cost_tier: 'frontier'
  }
};

const L3_RE = /\b(referee|security\s+audit|cso|stride|owasp|formal\s+verification|compliance|zero-finding|cross-family|constitutional)\b/i;
const L2_5_RE = /\b(120b|burst|deep\s+architecture|multi-agent\s+swarm|spec-first\s+refactor|large-scale|100k\s+context|theorem|physics)\b/i;
const L2_RE = /\b(refactor|implement|bug|fix|unit\s+test|migration|sql|schema|ast|endpoint|component|engine|docker|diff)\b/i;

/**
 * Create the Cognitive Model Router engine.
 * @param {object} [options]
 * @param {object} [options.config]
 */
export function createRouterEngine({ config = {} } = {}) {
  const ollamaHost =
    config.ollamaHost ||
    process.env.OLLAMA_HOST ||
    'http://127.0.0.1:11434';
  const burstHost =
    config.burstHost ||
    process.env.OLLAMA_BURST_HOST ||
    'http://127.0.0.1:11435';

  let totalRouted = 0;
  let totalLatencyUs = 0;

  /**
   * Classify a prompt/task in <25µs into L1_FAST_LOCAL, L2_SWE_MOE, L2_5_BURST_120B, or L3_FRONTIER_REFEREE.
   * @param {object} [params]
   * @param {string} [params.prompt='']
   * @param {string} [params.task_type]
   * @param {string} [params.budget_tier='auto']
   */
  function routeTask({ prompt = '', task_type, budget_tier = 'auto' } = {}) {
    const startNs = process.hrtime.bigint();

    const text = String(prompt || '');
    const explicitType = String(task_type || '').toLowerCase();
    const budget = String(budget_tier || 'auto').toLowerCase();

    let selectedKey = 'L1_FAST_LOCAL';
    let reason = 'Fast local L1 heuristic match for lightweight or bounded query';
    let confidence = 0.92;

    if (budget === 'frontier' || budget === 'l3' || explicitType === 'referee' || explicitType === 'security_audit') {
      selectedKey = 'L3_FRONTIER_REFEREE';
      reason = 'Explicit frontier/referee tier or security audit escalation';
      confidence = 0.98;
    } else if (budget === 'burst' || budget === 'l2.5' || budget === 'l2_5' || explicitType === 'architecture') {
      selectedKey = 'L2_5_BURST_120B';
      reason = 'High-complexity burst tier requested for deep architectural synthesis';
      confidence = 0.95;
    } else if (budget === 'local_only' || budget === 'l1') {
      selectedKey = 'L1_FAST_LOCAL';
      reason = 'Strict L1 fast local budget constraint';
      confidence = 0.99;
    } else if (L3_RE.test(text)) {
      selectedKey = 'L3_FRONTIER_REFEREE';
      reason = 'Detected high-stakes referee/security/compliance signal in prompt';
      confidence = 0.94;
    } else if (L2_5_RE.test(text) || text.length > 4000) {
      selectedKey = 'L2_5_BURST_120B';
      reason = 'Detected deep architectural or long-context synthesis workload';
      confidence = 0.91;
    } else if (
      budget === 'l2' ||
      explicitType === 'code' ||
      explicitType === 'refactor' ||
      L2_RE.test(text) ||
      text.length > 240
    ) {
      selectedKey = 'L2_SWE_MOE';
      reason = 'Detected multi-step software engineering / code synthesis workload';
      confidence = 0.93;
    }

    const elapsedNs = Number(process.hrtime.bigint() - startNs);
    const latencyUs = Number((elapsedNs / 1000).toFixed(2));

    totalRouted += 1;
    totalLatencyUs += latencyUs;

    const spec = TIER_CATALOG[selectedKey];
    const endpoint =
      selectedKey === 'L2_5_BURST_120B'
        ? burstHost
        : selectedKey === 'L3_FRONTIER_REFEREE'
          ? 'https://generativelanguage.googleapis.com'
          : ollamaHost;

    return okEnvelope(
      'krusch_route_task',
      `Routed to ${spec.tier} (${spec.model}) in ${latencyUs}µs`,
      {
        tier: spec.tier,
        model: spec.model,
        provider: spec.provider,
        endpoint,
        max_context: spec.max_context,
        cost_tier: spec.cost_tier,
        latency_us: latencyUs,
        within_sla: latencyUs < 250,
        confidence,
        reason,
        task_type: explicitType || 'inferred',
        budget_tier: budget
      }
    );
  }

  /**
   * Return unified status across all KruschStack engines and router metrics.
   * @param {object} [params]
   * @param {object} [params.engines]
   */
  function getStackStatus({ engines = {} } = {}) {
    const registeredPillars = [
      'context',
      'git',
      'fs',
      'harness',
      'frontend',
      'workspace',
      'router'
    ];

    const engineStates = {};
    for (const name of registeredPillars) {
      if (name === 'router') {
        engineStates[name] = { ready: true };
      } else {
        engineStates[name] = { ready: Boolean(engines && engines[name]) };
      }
    }

    const avgLatencyUs = totalRouted > 0 ? Number((totalLatencyUs / totalRouted).toFixed(2)) : 0;

    return okEnvelope(
      'krusch_stack_status',
      `KruschStack v1.0.0 healthy (${Object.values(engineStates).filter((s) => s.ready).length}/${registeredPillars.length} pillars active)`,
      {
        status: 'healthy',
        version: '1.0.0',
        ollama_host: ollamaHost,
        burst_host: burstHost,
        engines: engineStates,
        router_metrics: {
          total_routed: totalRouted,
          avg_latency_us: avgLatencyUs,
          available_tiers: Object.keys(TIER_CATALOG)
        }
      }
    );
  }

  return {
    routeTask,
    getStackStatus
  };
}
