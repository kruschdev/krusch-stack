/**
 * @module krusch-stack
 * Unified Sovereign AI & Coding Agent Stack.
 * Bundles Tier 1 Working Memory (krusch-context-mcp), Tier 2A Git DAG & AST Graph (krusch-git),
 * Tier 2B Page-Anchored OS Filesystem (krusch-fs), Tier 3 2PC Staged Execution Harness (krusch-harness),
 * Frontend Design Engine (krusch-frontend-mcp), Google Workspace Hub (g-krusch), and L1-L3 Cascade Router.
 */

import path from 'node:path';
import { openStackDatabase, okEnvelope, STACK_SCHEMA_SQL } from './db/sqlite.js';
import { createContextEngine } from './engines/context-engine.js';
import { createGitEngine, maskCodePreservingNewlines } from './engines/git-engine.js';
import { createFsEngine } from './engines/fs-engine.js';
import { createHarnessEngine } from './engines/harness-engine.js';
import { createFrontendEngine } from './engines/frontend-engine.js';
import { createWorkspaceEngine } from './engines/workspace-engine.js';
import { createRouterEngine } from './engines/router-engine.js';
import { generateIdeConfig, writeIdeConfigs, IDE_CONFIG_PATHS } from './installer/ide-config.js';
import { runStackDoctor } from './installer/doctor.js';

export const VERSION = '1.0.0';

/**
 * Create a unified KruschStack instance with all 7 component engines wired to a shared SQLite/Postgres substrate.
 * @param {object} [options]
 * @param {string} [options.workspaceRoot]
 * @param {string} [options.dbPath]
 * @param {boolean} [options.ephemeral]
 * @param {'core'|'full'} [options.profile='full']
 * @param {object} [options.routerConfig]
 */
export function createKruschStack(options = {}) {
  const workspaceRoot = path.resolve(
    options.workspaceRoot || process.env.KRUSCH_WORKSPACE_ROOT || process.cwd()
  );
  const profile = (options.profile || process.env.KRUSCH_STACK_PROFILE || 'full') === 'core' ? 'core' : 'full';
  const db = options.db || openStackDatabase({
    workspaceRoot,
    dbPath: options.dbPath,
    ephemeral: options.ephemeral
  });

  const context = createContextEngine({ db, workspaceRoot });
  const git = createGitEngine({ db, workspaceRoot });
  const fs = createFsEngine({ db, workspaceRoot });
  const harness = createHarnessEngine({ db, workspaceRoot, contextEngine: context });
  const frontend = createFrontendEngine({ db });
  const workspace = createWorkspaceEngine({ db, workspaceRoot });
  const router = createRouterEngine({ config: options.routerConfig });

  const engines = {
    context,
    git,
    fs,
    harness,
    frontend,
    workspace,
    router
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
    doctor: () => runStackDoctor({ workspaceRoot, db, profile }),
    status: () => router.getStackStatus({ engines })
  };
}

export {
  openStackDatabase,
  okEnvelope,
  STACK_SCHEMA_SQL,
  createContextEngine,
  createGitEngine,
  maskCodePreservingNewlines,
  createFsEngine,
  createHarnessEngine,
  createFrontendEngine,
  createWorkspaceEngine,
  createRouterEngine,
  generateIdeConfig,
  writeIdeConfigs,
  IDE_CONFIG_PATHS,
  runStackDoctor
};
