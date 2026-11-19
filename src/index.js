/**
 * @module krusch-stack
 * Unified Sovereign AI & Coding Agent Stack.
 * Bundles Tier 1 Working Memory (krusch-context-mcp), Tier 2A Git DAG & AST Graph (krusch-git),
 * Tier 2B Page-Anchored OS Filesystem (krusch-fs), Tier 3 2PC Staged Execution Harness (krusch-harness),
 * Frontend Design Engine (krusch-frontend-mcp), Google Workspace Hub (g-krusch), and L1-L3 Cascade Router.
 */

import path from 'node:path';
import {
  openStackDatabase,
  ensureStackSchemaMigrations,
  isSqliteCorruptionError,
  okEnvelope,
  STACK_SCHEMA_SQL
} from './db/sqlite.js';
import { createContextEngine, packStackTokenBudget } from './engines/context-engine.js';
import {
  prunePreRetrieval,
  prunePostRetrieval,
  prunePreSynthesis,
  selectMinimalCoveringSet
} from './engines/context-prune.js';
import {
  cosineSimilarity,
  parseEmbeddingVector,
  serializeEmbeddingVector,
  fetchOptionalEmbedding,
  splitIdentifierSubtokens,
  extractCodeShapeIdentifiers,
  buildFts5MatchQuery
} from './engines/context-lexical.js';
import {
  createGitEngine,
  maskCodePreservingNewlines,
  parseJavaSymbols,
  analyzeImportSymbolActivity
} from './engines/git-engine.js';
import {
  createFsEngine,
  isSensitiveEnvFile,
  redactEnvSecrets,
  scanForSecretLeak
} from './engines/fs-engine.js';
import { createHarnessEngine, fsyncDirectory } from './engines/harness-engine.js';
import { createFrontendEngine } from './engines/frontend-engine.js';
import { createWorkspaceEngine } from './engines/workspace-engine.js';
import { createRouterEngine } from './engines/router-engine.js';
import {
  createResilienceEngine,
  estimateTokenCount,
  RESILIENCE_SCHEMA_SQL
} from './engines/resilience-engine.js';
import {
  createActionHarnessEngine,
  classifyToolMutability,
  canonicalizeToolCallKey,
  ACTION_HARNESS_SCHEMA_SQL
} from './engines/action-harness-engine.js';
import {
  GROUNDED_HARNESS_SCHEMA_SQL,
  SCALE_TIERS,
  inferModelScaleMetadata,
  resolveScaleProfile,
  buildScaleAwareDirective,
  buildSafeGeminiToolConfig,
  normalizeCodeSnippetForHash,
  canonicalizeGroundedToolCallKey,
  inspectOutputDefects,
  formatTimeoutWithPartialStdout,
  execCommandWithPartialStdout,
  introspectWorkspaceSchemas,
  compileTurnZeroGrounding,
  createGroundedHarnessEngine
} from './engines/grounded-harness-engine.js';
import {
  BRICK_EXCHANGE_SCHEMA_SQL,
  generateEd25519BrickKeys,
  verifySealedBrickBundle,
  createBrickExchangeEngine,
  CANONICAL_SHARED_TYPES,
  STACK_ONTOLOGY_STACKS,
  STACK_ONTOLOGY_PORTS,
  STACK_ONTOLOGY_CHANNELS,
  STACK_ONTOLOGY_MOE_PROFILES,
  hasForbiddenKeyRecursive,
  parsePortReference,
  isWebStandardPureBrickSource,
  areOntologyPortsCompatible,
  surrogateOntologyVertexId,
  normalizeBrickOntology,
  inspectBrickOntology,
  checkBrickOntologyCompatibility,
  composeCrossStackBricks,
  synthesizeHexagonalBinding,
  createBrickOntologyEngine
} from './engines/brick-exchange-engine.js';
import {
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift
} from './engines/grounded-auth-drift.js';
import {
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  compileExecutableRules,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  synthesizeRulesWithTeacher,
  evolveRulesFromTraces
} from './engines/grounded-trace-synthesizer.js';
import {
  HYDRASCOPE_SCHEMA_SQL,
  FINTECH_BENCHMARK_CORPUS,
  HYDRASCOPE_BENCHMARK_SCENARIOS,
  compileArtifactsToHydraGraph,
  compileDirectoryToHydraGraph,
  createHydraScopeEngine
} from './engines/hydrascope-engine.js';
import {
  DEFAULT_COCHANGE_RULES,
  isUnifiedDiffText,
  parseUnifiedDiffFiles,
  compileSafeCoChangeGlob,
  parseCoChangeRuleDirective,
  extractMemoryCoChangeRules,
  evaluateCoChangeRules,
  findBlamedDiffMemories,
  scanSupersededStaleCode,
  detectLegoBoilerplateViolations,
  recordExplicitProvenanceReanchor,
  createGitAlignmentEngine
} from './engines/git-alignment-engine.js';
import {
  TOOL_GRAPH_SHARED_TYPES,
  DEFAULT_TOOL_GRAPH_OPTIONS,
  maskTaskEntities,
  extractGivenTypesFromTask,
  inferToolGraphSchema,
  compileToolGraph,
  buildToolPrerequisiteGraph,
  createToolGraph,
  createToolGraphRouter,
  createToolGraphEngine
} from './engines/tool-graph-engine.js';
import {
  POLYGLOT_HAZARD_RULES,
  SLOP_BREAKER_RULES,
  auditBoilerplateText,
  scoreLegoBrickCoverage,
  normalizeGitHubRepoInput,
  auditPolyglotSource,
  auditPolyglotRepository,
  createPolyglotAuditEngine
} from './engines/polyglot-audit-engine.js';
import {
  createObservabilityEngine,
  isBlockedDecision,
  formatExplainReportText
} from './engines/observability-engine.js';
import {
  generateIdeConfig,
  writeIdeConfigs,
  IDE_CONFIG_PATHS,
  VALID_STACK_PROFILES,
  normalizeStackProfile,
  buildDefaultAgentsMd
} from './installer/ide-config.js';
import { runStackDoctor, runStackCrashRecoveryDrill } from './installer/doctor.js';
import { runStackDemo, formatStackDemoText } from './installer/demo.js';

export const VERSION = '1.3.1';

const DEFAULT_STACK_TOOL_GRAPH_SPINE = Object.freeze([
  {
    name: 'krusch_context_retrieve',
    description: 'Retrieve working memory invariants, recent decisions, and state briefings.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit_tokens: { type: 'number' } }, required: ['query'] },
    outputSchema: { type: 'object', properties: { memory_id: { type: 'number' } } }
  },
  {
    name: 'krusch_context_remember',
    description: 'Persist durable project decisions, invariants, bugs, and lessons.',
    inputSchema: { type: 'object', properties: { category: { type: 'string' }, content: { type: 'string' } }, required: ['category', 'content'] },
    outputSchema: { type: 'object', properties: { memory_id: { type: 'number' } } }
  },
  {
    name: 'krusch_context_revise',
    description: 'Supersede or invalidate an existing working memory entry by target_id.',
    inputSchema: { type: 'object', properties: { action: { type: 'string' }, target_id: { type: 'number' }, reason: { type: 'string' } }, required: ['action', 'target_id', 'reason'] }
  },
  {
    name: 'krusch_context_nudge',
    description: 'Audit staged code diffs against project invariants and co-change rules.',
    inputSchema: { type: 'object', properties: { trigger: { type: 'string' }, code: { type: 'string' } }, required: ['code'] }
  },
  {
    name: 'krusch_context_health',
    description: 'Inspect working memory store health, span drift, and superseded stale code.',
    inputSchema: { type: 'object', properties: {} }
  },
  {
    name: 'krusch_git_list_repos',
    description: 'List indexed Git repositories in the stack.',
    inputSchema: { type: 'object', properties: {} },
    outputSchema: { type: 'object', properties: { repo_path: { type: 'string' } } }
  },
  {
    name: 'krusch_git_search_symbols',
    description: 'Search AST symbols across indexed Git repositories.',
    inputSchema: { type: 'object', properties: { repo: { type: 'string' }, query: { type: 'string' } }, required: ['query'] },
    outputSchema: { type: 'object', properties: { symbol: { type: 'string' }, file_path: { type: 'string' } } }
  },
  {
    name: 'krusch_git_file_symbols',
    description: 'List AST symbols declared in a file path.',
    inputSchema: { type: 'object', properties: { repo: { type: 'string' }, file_path: { type: 'string' } }, required: ['file_path'] },
    outputSchema: { type: 'object', properties: { symbol: { type: 'string' } } }
  },
  {
    name: 'krusch_git_dependency_graph',
    description: 'Trace inbound callers and outbound callees of an AST symbol.',
    inputSchema: { type: 'object', properties: { repo: { type: 'string' }, symbol: { type: 'string' } }, required: ['symbol'] }
  },
  {
    name: 'krusch_git_semantic_search',
    description: 'Hybrid BM25 and dense vector semantic search across codebase symbols.',
    inputSchema: { type: 'object', properties: { repo: { type: 'string' }, query: { type: 'string' } }, required: ['query'] },
    outputSchema: { type: 'object', properties: { file_path: { type: 'string' }, symbol: { type: 'string' } } }
  },
  {
    name: 'krusch_fs_locate',
    description: 'Locate workspace files by glob pattern and metadata.',
    inputSchema: { type: 'object', properties: { pattern: { type: 'string' } } },
    outputSchema: { type: 'object', properties: { file_path: { type: 'string' } } }
  },
  {
    name: 'krusch_fs_search',
    description: 'Hybrid BM25 search across OS file pages and PageMemory annotations.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] },
    outputSchema: { type: 'object', properties: { file_path: { type: 'string' } } }
  },
  {
    name: 'krusch_fs_page_tree',
    description: 'Inspect structural page table-of-contents and SHA-256 hashes for a file.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] }
  },
  {
    name: 'krusch_fs_read_page',
    description: 'Read a bounded file page with anchored memories and drift status.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, page_number: { type: 'number' } }, required: ['path'] }
  },
  {
    name: 'hydrascope_traverse_context',
    description: 'Traverse structural graph context, temporal SUPERSEDES lineage, and 4-axis ontology.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, asOf: { type: 'string' } }, required: ['query'] }
  },
  {
    name: 'hydrascope_check_answerable',
    description: 'Verify zero-LLM structural answerability before invoking a generator.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] }
  },
  {
    name: 'krusch_run',
    description: 'Stage file edits as unified diffs through the 2PC invariant harness.',
    inputSchema: { type: 'object', properties: { goal: { type: 'string' }, edits: { type: 'array' } }, required: ['goal'] },
    outputSchema: { type: 'object', properties: { task_id: { type: 'string' } } }
  },
  {
    name: 'krusch_task_status',
    description: 'Check the status of a staged 2PC harness task.',
    inputSchema: { type: 'object', properties: { task_id: { type: 'string' } }, required: ['task_id'] }
  },
  {
    name: 'krusch_diff',
    description: 'Inspect the staged unified diff for a 2PC harness task.',
    inputSchema: { type: 'object', properties: { task_id: { type: 'string' } }, required: ['task_id'] }
  },
  {
    name: 'krusch_apply_diff',
    description: 'Atomically apply a STAGED 2PC harness diff to disk.',
    inputSchema: { type: 'object', properties: { task_id: { type: 'string' } }, required: ['task_id'] }
  },
  {
    name: 'krusch_route_task',
    description: 'Classify a coding or reasoning prompt via the <25us L1-L3 Cascade Router.',
    inputSchema: { type: 'object', properties: { prompt: { type: 'string' } }, required: ['prompt'] }
  },
  {
    name: 'krusch_stack_status',
    description: 'Inspect unified health and row telemetry across all 10 KruschStack pillars.',
    inputSchema: { type: 'object', properties: {} }
  }
]);

/**
 * Create a unified KruschStack instance with all 10 stack pillars + production resilience, 2PC action-harness, Turn-0 grounded-harness, Sovereign ToolGraph, and Polyglot Audit engines wired to a shared SQLite substrate (with 21-table PostgreSQL DDL parity in db/init.sql).
 * @param {object} [options]
 * @param {string} [options.workspaceRoot]
 * @param {string} [options.dbPath]
 * @param {boolean} [options.ephemeral]
 * @param {'core'|'full'} [options.profile='full']
 * @param {object} [options.routerConfig]
 * @param {string} [options.embedEndpoint]
 * @param {string} [options.embedModel]
 * @param {boolean} [options.autoEmbed]
 * @param {boolean} [options.recoverOnStartup]
 */
export function createKruschStack(options = {}) {
  const workspaceRoot = path.resolve(
    options.workspaceRoot || process.env.KRUSCH_WORKSPACE_ROOT || process.cwd()
  );
  const profile = normalizeStackProfile(
    options.profile || process.env.KRUSCH_STACK_PROFILE || 'full',
    'full'
  );
  const envDbPath = typeof process.env.DB_PATH === 'string' ? process.env.DB_PATH.trim() : '';
  const effectiveDbPath = options.dbPath || envDbPath || undefined;
  const hasExplicitFileDb = Boolean(effectiveDbPath && effectiveDbPath !== ':memory:');
  const ephemeral =
    options.ephemeral === true ||
    effectiveDbPath === ':memory:' ||
    (options.ephemeral !== false && !hasExplicitFileDb && process.env.KRUSCH_EPHEMERAL === '1');
  const recoverOnStartup = Boolean(options.recoverOnStartup ?? !ephemeral);
  const db = options.db || openStackDatabase({
    workspaceRoot,
    dbPath: effectiveDbPath,
    ephemeral
  });
  if (options.db) {
    ensureStackSchemaMigrations(db);
  }

  const context = createContextEngine({
    db,
    workspaceRoot,
    ephemeral,
    embedEndpoint: options.embedEndpoint,
    embedModel: options.embedModel,
    autoEmbed: options.autoEmbed
  });
  const git = createGitEngine({ db, workspaceRoot });
  const fs = createFsEngine({ db, workspaceRoot });
  const harness = createHarnessEngine({ db, workspaceRoot, contextEngine: context });
  const startupRecovery = recoverOnStartup ? harness.recoverInFlight() : null;
  const frontend = createFrontendEngine({ db });
  const workspace = createWorkspaceEngine({ db, workspaceRoot });
  const router = createRouterEngine({ config: options.routerConfig });
  const resilience = createResilienceEngine({ db });
  const actionHarness = createActionHarnessEngine({ db, contextEngine: context });
  const groundedHarness = createGroundedHarnessEngine({ db, workspaceRoot });
  const brickExchange = createBrickExchangeEngine({ db, workspaceRoot });
  const hydrascope = createHydraScopeEngine({
    db,
    workspaceRoot,
    brickExchange,
    hydraUrl: options.hydraUrl,
    hydraToken: options.hydraToken,
    hydraGraphId: options.hydraGraphId,
    namespace: options.hydraNamespace
  });
  const gitAlignment = createGitAlignmentEngine({ db, workspaceRoot });
  const polyglotAudit = createPolyglotAuditEngine({ workspaceRoot });
  const observability = createObservabilityEngine({ db, workspaceRoot, contextEngine: context });

  const defaultToolGraphDispatcher = async (toolName, toolArgs = {}) => {
    switch (toolName) {
      case 'krusch_context_retrieve':
        return context.retrieveAsync(toolArgs);
      case 'krusch_context_remember':
        return context.rememberAsync(toolArgs);
      case 'krusch_context_revise':
        return context.reviseAsync(toolArgs);
      case 'krusch_context_nudge':
        return context.nudge(toolArgs);
      case 'krusch_context_health':
        return context.health(toolArgs);
      case 'krusch_git_list_repos':
        return git.listRepos(toolArgs);
      case 'krusch_git_search_symbols':
        return git.searchSymbols(toolArgs);
      case 'krusch_git_file_symbols':
        return git.fileSymbols(toolArgs);
      case 'krusch_git_dependency_graph':
        return git.dependencyGraph(toolArgs);
      case 'krusch_git_semantic_search':
        return git.semanticSearch(toolArgs);
      case 'krusch_fs_locate':
        return fs.locate(toolArgs);
      case 'krusch_fs_search':
        return fs.search(toolArgs);
      case 'krusch_fs_page_tree':
        return fs.pageTree(toolArgs);
      case 'krusch_fs_read_page':
        return fs.readPage(toolArgs);
      case 'hydrascope_traverse_context':
        return hydrascope.traverseContext(toolArgs);
      case 'hydrascope_check_answerable':
        return hydrascope.checkAnswerable(toolArgs);
      case 'krusch_run':
        return harness.run(toolArgs);
      case 'krusch_task_status':
        return harness.taskStatus(toolArgs);
      case 'krusch_diff':
        return harness.diff(toolArgs);
      case 'krusch_apply_diff':
        return harness.applyDiff(toolArgs);
      case 'krusch_route_task':
        return router.routeTask(toolArgs);
      case 'krusch_stack_status':
        return router.getStackStatus({ engines, db });
      default:
        return okEnvelope(
          toolName || 'krusch_tool_graph_call',
          `Unknown default spine tool: ${toolName}`,
          { error: `Unknown default spine tool: ${toolName}` },
          false
        );
    }
  };

  const toolGraph = createToolGraphEngine(
    Array.isArray(options.toolGraphTools) ? options.toolGraphTools : DEFAULT_STACK_TOOL_GRAPH_SPINE,
    {
      dispatcher: defaultToolGraphDispatcher,
      ...(options.toolGraphOptions || {})
    }
  );

  const engines = {
    context,
    git,
    fs,
    hydrascope,
    harness,
    frontend,
    workspace,
    router,
    resilience,
    actionHarness,
    groundedHarness,
    brickExchange,
    gitAlignment,
    toolGraph,
    polyglotAudit,
    observability
  };

  return {
    version: VERSION,
    workspaceRoot,
    profile,
    db,
    startupRecovery,
    engines,
    context,
    git,
    fs,
    hydrascope,
    harness,
    frontend,
    workspace,
    router,
    resilience,
    actionHarness,
    groundedHarness,
    brickExchange,
    gitAlignment,
    toolGraph,
    polyglotAudit,
    observability,
    doctor: () => runStackDoctor({ workspaceRoot, db, profile }),
    status: () => router.getStackStatus({ engines, db })
  };
}

export {
  openStackDatabase,
  ensureStackSchemaMigrations,
  isSqliteCorruptionError,
  okEnvelope,
  STACK_SCHEMA_SQL,
  RESILIENCE_SCHEMA_SQL,
  ACTION_HARNESS_SCHEMA_SQL,
  GROUNDED_HARNESS_SCHEMA_SQL,
  BRICK_EXCHANGE_SCHEMA_SQL,
  SCALE_TIERS,
  createContextEngine,
  packStackTokenBudget,
  prunePreRetrieval,
  prunePostRetrieval,
  prunePreSynthesis,
  selectMinimalCoveringSet,
  cosineSimilarity,
  parseEmbeddingVector,
  serializeEmbeddingVector,
  fetchOptionalEmbedding,
  splitIdentifierSubtokens,
  extractCodeShapeIdentifiers,
  buildFts5MatchQuery,
  createGitEngine,
  maskCodePreservingNewlines,
  parseJavaSymbols,
  analyzeImportSymbolActivity,
  createFsEngine,
  isSensitiveEnvFile,
  redactEnvSecrets,
  scanForSecretLeak,
  createHarnessEngine,
  fsyncDirectory,
  createFrontendEngine,
  createWorkspaceEngine,
  createRouterEngine,
  createResilienceEngine,
  estimateTokenCount,
  createActionHarnessEngine,
  classifyToolMutability,
  canonicalizeToolCallKey,
  inferModelScaleMetadata,
  resolveScaleProfile,
  buildScaleAwareDirective,
  buildSafeGeminiToolConfig,
  normalizeCodeSnippetForHash,
  canonicalizeGroundedToolCallKey,
  inspectOutputDefects,
  formatTimeoutWithPartialStdout,
  execCommandWithPartialStdout,
  introspectWorkspaceSchemas,
  compileTurnZeroGrounding,
  createGroundedHarnessEngine,
  generateEd25519BrickKeys,
  verifySealedBrickBundle,
  createBrickExchangeEngine,
  CANONICAL_SHARED_TYPES,
  STACK_ONTOLOGY_STACKS,
  STACK_ONTOLOGY_PORTS,
  STACK_ONTOLOGY_CHANNELS,
  STACK_ONTOLOGY_MOE_PROFILES,
  hasForbiddenKeyRecursive,
  parsePortReference,
  isWebStandardPureBrickSource,
  areOntologyPortsCompatible,
  surrogateOntologyVertexId,
  normalizeBrickOntology,
  inspectBrickOntology,
  checkBrickOntologyCompatibility,
  composeCrossStackBricks,
  synthesizeHexagonalBinding,
  createBrickOntologyEngine,
  SENSITIVE_SCOPE_DOMAINS,
  AUTH_DRIFT_REASON_CODES,
  inferGoalAttestedScopes,
  inspectAndRepairDartBoundaries,
  evaluateAuthorizationDrift,
  auditTrajectoryAuthorizationDrift,
  SYNTHESIZED_RULE_ACTIONS,
  DEFAULT_EVOLVED_HARNESS_RULES,
  compileSafeRuleRegex,
  compileExecutableRules,
  extractShellCommandsFromTrajectory,
  mineFailureTrajectories,
  verifyCandidateRulesOnTraces,
  synthesizeRulesWithTeacher,
  evolveRulesFromTraces,
  HYDRASCOPE_SCHEMA_SQL,
  FINTECH_BENCHMARK_CORPUS,
  HYDRASCOPE_BENCHMARK_SCENARIOS,
  compileArtifactsToHydraGraph,
  compileDirectoryToHydraGraph,
  createHydraScopeEngine,
  DEFAULT_COCHANGE_RULES,
  isUnifiedDiffText,
  parseUnifiedDiffFiles,
  compileSafeCoChangeGlob,
  parseCoChangeRuleDirective,
  extractMemoryCoChangeRules,
  evaluateCoChangeRules,
  findBlamedDiffMemories,
  scanSupersededStaleCode,
  detectLegoBoilerplateViolations,
  recordExplicitProvenanceReanchor,
  createGitAlignmentEngine,
  TOOL_GRAPH_SHARED_TYPES,
  DEFAULT_TOOL_GRAPH_OPTIONS,
  maskTaskEntities,
  extractGivenTypesFromTask,
  inferToolGraphSchema,
  compileToolGraph,
  buildToolPrerequisiteGraph,
  createToolGraph,
  createToolGraphRouter,
  createToolGraphEngine,
  POLYGLOT_HAZARD_RULES,
  SLOP_BREAKER_RULES,
  auditBoilerplateText,
  scoreLegoBrickCoverage,
  normalizeGitHubRepoInput,
  auditPolyglotSource,
  auditPolyglotRepository,
  createPolyglotAuditEngine,
  generateIdeConfig,
  writeIdeConfigs,
  IDE_CONFIG_PATHS,
  VALID_STACK_PROFILES,
  normalizeStackProfile,
  buildDefaultAgentsMd,
  runStackDoctor,
  runStackCrashRecoveryDrill,
  runStackDemo,
  formatStackDemoText,
  createObservabilityEngine,
  isBlockedDecision,
  formatExplainReportText
};
