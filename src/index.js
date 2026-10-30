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
import { generateIdeConfig, writeIdeConfigs, IDE_CONFIG_PATHS } from './installer/ide-config.js';
import { runStackDoctor } from './installer/doctor.js';

export const VERSION = '1.0.0';

/**
 * Create a unified KruschStack instance with all 7 component engines + production resilience engine wired to a shared SQLite/Postgres substrate.
 * @param {object} [options]
 * @param {string} [options.workspaceRoot]
 * @param {string} [options.dbPath]
 * @param {boolean} [options.ephemeral]
 * @param {'core'|'full'} [options.profile='full']
 * @param {object} [options.routerConfig]
 * @param {string} [options.embedEndpoint]
 * @param {string} [options.embedModel]
 * @param {boolean} [options.autoEmbed]
 */
export function createKruschStack(options = {}) {
  const workspaceRoot = path.resolve(
    options.workspaceRoot || process.env.KRUSCH_WORKSPACE_ROOT || process.cwd()
  );
  const profile = (options.profile || process.env.KRUSCH_STACK_PROFILE || 'full') === 'core' ? 'core' : 'full';
  const hasExplicitFileDb = Boolean(options.dbPath && options.dbPath !== ':memory:');
  const ephemeral =
    options.ephemeral === true ||
    options.dbPath === ':memory:' ||
    (options.ephemeral !== false && !hasExplicitFileDb && process.env.KRUSCH_EPHEMERAL === '1');
  const db = options.db || openStackDatabase({
    workspaceRoot,
    dbPath: options.dbPath,
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
  const frontend = createFrontendEngine({ db });
  const workspace = createWorkspaceEngine({ db, workspaceRoot });
  const router = createRouterEngine({ config: options.routerConfig });
  const resilience = createResilienceEngine({ db });

  const engines = {
    context,
    git,
    fs,
    harness,
    frontend,
    workspace,
    router,
    resilience
  };

  return {
    version: VERSION,
    workspaceRoot,
    profile,
    db,
    engines,
    context,
    git,
    fs,
    harness,
    frontend,
    workspace,
    router,
    resilience,
    doctor: () => runStackDoctor({ workspaceRoot, db, profile }),
    status: () => router.getStackStatus({ engines })
  };
}

export {
  openStackDatabase,
  ensureStackSchemaMigrations,
  isSqliteCorruptionError,
  okEnvelope,
  STACK_SCHEMA_SQL,
  RESILIENCE_SCHEMA_SQL,
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
  generateIdeConfig,
  writeIdeConfigs,
  IDE_CONFIG_PATHS,
  runStackDoctor
};
