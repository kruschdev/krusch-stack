/**
 * @module installer/ide-config
 * Multi-IDE MCP configuration generator and writer for KruschStack.
 * Supports Claude Code (.mcp.json), Cursor (.cursor/mcp.json),
 * Windsurf (.windsurf/mcp_config.json), and Antigravity (.antigravity/mcp_config.json).
 * Enforces INV-STACK-04 (zero private IPs/hostnames) and INV-STACK-05 (profile filtering).
 */

import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope } from '../db/sqlite.js';

export const IDE_CONFIG_PATHS = {
  claude: '.mcp.json',
  cursor: path.join('.cursor', 'mcp.json'),
  windsurf: path.join('.windsurf', 'mcp_config.json'),
  antigravity: path.join('.antigravity', 'mcp_config.json')
};

export const VALID_STACK_PROFILES = Object.freeze([
  'memory-only',
  'coding-agent',
  'core',
  'full'
]);

const PROFILE_ALIAS_MAP = new Map([
  ['memory-only', 'memory-only'],
  ['memory_only', 'memory-only'],
  ['memory', 'memory-only'],
  ['coding-agent', 'coding-agent'],
  ['coding_agent', 'coding-agent'],
  ['coding', 'coding-agent'],
  ['core', 'core'],
  ['full', 'full']
]);

const MEMORY_ONLY_MODULAR_SERVERS = ['krusch-context-mcp'];

const CODING_AGENT_MODULAR_SERVERS = [
  'krusch-context-mcp',
  'krusch-git',
  'krusch-harness',
  'krusch-grounded-harness'
];

const CORE_MODULAR_SERVERS = [
  'krusch-context-mcp',
  'krusch-git',
  'krusch-fs',
  'hydrascope',
  'krusch-brick-exchange',
  'krusch-harness',
  'krusch-grounded-harness',
  'krusch-cascade-router'
];

const FULL_EXTRA_SERVERS = [
  'krusch-frontend-mcp',
  'g-krusch'
];

/**
 * Normalize a progressive KruschStack profile string (`INV-STACK-05`).
 * Accepts `'memory-only'` (`'memory'`), `'coding-agent'` (`'coding'`), `'core'`, and `'full'`.
 * Falls back to `fallback` (`'full'` by default) when omitted or unrecognized.
 * @param {unknown} profile
 * @param {'memory-only'|'coding-agent'|'core'|'full'} [fallback='full']
 * @returns {'memory-only'|'coding-agent'|'core'|'full'}
 */
export function normalizeStackProfile(profile, fallback = 'full') {
  const resolvedFallback =
    typeof fallback === 'string' && PROFILE_ALIAS_MAP.has(fallback.trim().toLowerCase())
      ? PROFILE_ALIAS_MAP.get(fallback.trim().toLowerCase())
      : 'full';
  if (typeof profile !== 'string') {
    return resolvedFallback;
  }
  const key = profile.trim().toLowerCase();
  return PROFILE_ALIAS_MAP.get(key) || resolvedFallback;
}

function getModularServersForProfile(normalizedProfile) {
  if (normalizedProfile === 'memory-only') {
    return [...MEMORY_ONLY_MODULAR_SERVERS];
  }
  if (normalizedProfile === 'coding-agent') {
    return [...CODING_AGENT_MODULAR_SERVERS];
  }
  if (normalizedProfile === 'core') {
    return [...CORE_MODULAR_SERVERS];
  }
  return [...CORE_MODULAR_SERVERS, ...FULL_EXTRA_SERVERS];
}

/**
 * Generate MCP server configuration for a target IDE, mode, and profile.
 * @param {object} [options]
 * @param {'claude'|'cursor'|'windsurf'|'antigravity'|'all'} [options.ide='claude']
 * @param {'unified'|'modular'} [options.mode='unified']
 * @param {'memory-only'|'coding-agent'|'core'|'full'} [options.profile='full']
 * @param {string} [options.workspaceRoot=process.cwd()]
 * @param {boolean} [options.deferTools=false]
 * @param {boolean} [options.includeExtended=false]
 */
export function generateIdeConfig({
  ide = 'claude',
  mode = 'unified',
  profile = 'full',
  workspaceRoot = process.cwd(),
  deferTools = false,
  includeExtended = false
} = {}) {
  const normalizedProfile = normalizeStackProfile(profile, 'full');
  const normalizedMode = mode === 'modular' ? 'modular' : 'unified';
  const resolvedRoot = path.resolve(workspaceRoot);

  const mcpServers = {};

  if (normalizedMode === 'unified') {
    const unifiedArgs = ['-y', 'krusch-stack', 'mcp', '--profile', normalizedProfile];
    if (includeExtended) unifiedArgs.push('--include-extended');
    if (deferTools) unifiedArgs.push('--defer-tools');
    mcpServers['krusch-stack'] = {
      command: 'npx',
      args: unifiedArgs,
      env: {
        KRUSCH_WORKSPACE_ROOT: resolvedRoot
      }
    };
  } else {
    const serverNames = getModularServersForProfile(normalizedProfile);

    for (const serverName of serverNames) {
      const serverArgs = ['-y', 'krusch-stack', 'mcp', '--server', serverName];
      if (deferTools) serverArgs.push('--defer-tools');
      mcpServers[serverName] = {
        command: 'npx',
        args: serverArgs,
        env: {
          KRUSCH_WORKSPACE_ROOT: resolvedRoot
        }
      };
    }
  }

  const configObject = { mcpServers };
  const summary = `Generated ${normalizedMode} MCP config (${normalizedProfile} profile) for ${ide} with ${Object.keys(mcpServers).length} server entry(s).`;

  Object.defineProperties(configObject, {
    ok: { value: true, enumerable: false },
    tool: { value: 'krusch_ide_config', enumerable: false },
    summary: { value: summary, enumerable: false },
    ide: { value: ide, enumerable: false },
    mode: { value: normalizedMode, enumerable: false },
    profile: { value: normalizedProfile, enumerable: false },
    data: {
      value: {
        ide,
        mode: normalizedMode,
        profile: normalizedProfile,
        workspaceRoot: resolvedRoot,
        mcpServers
      },
      enumerable: false
    }
  });

  return configObject;
}

export function buildDefaultAgentsMd({
  mode = 'unified',
  profile = 'full',
  includeExtended = false
} = {}) {
  const normalizedProfile = normalizeStackProfile(profile, 'full');
  const hasExtendedMcp = mode === 'modular' || Boolean(includeExtended);

  if (normalizedProfile === 'memory-only') {
    return `# Agent Operating Manual (\`AGENTS.md\`)

> Powered by **KruschStack** (\`krusch-stack\`, \`memory-only\` profile): Tier 1 Working Memory & Invariants.

## 1. Session Start, Working Memory & Pre-Commit Invariants (Tier 1: \`krusch-context-mcp\`)
- Call \`krusch_context_retrieve({ query: "*", include_state: true, limit_tokens: 4000 })\` on Turn 1 to hydrate active project invariants, decisions, and lessons.
- Record durable architecture decisions, bug root-causes, and invariants with \`krusch_context_remember\`.
- Supersede or invalidate outdated decisions with full lineage via \`krusch_context_revise\`.
- Audit staged code changes and co-change/blame rules before committing via \`krusch_context_nudge({ trigger: "pre_commit", code: "<diff>" })\`, and inspect store hygiene with \`krusch_context_health\`.

> Tip: Upgrade anytime to AST symbol navigation and 2PC staged execution with \`npx krusch-stack init --profile coding-agent\`.
`;
  }

  if (normalizedProfile === 'coding-agent') {
    const tier3GroundedLine = hasExtendedMcp
      ? '\n- Use `krusch_ground_workspace` and `krusch_grounded_verify_stop` for zero-LLM Turn-0 schema grounding and defect-only stop gating.'
      : '';
    return `# Agent Operating Manual (\`AGENTS.md\`)

> Powered by **KruschStack** (\`krusch-stack\`, \`coding-agent\` profile): Tier 1 Working Memory, Tier 2A AST Graph & Tier 3 2PC Staged Execution.

## 1. Session Start, Working Memory & Git Alignment (Tier 1: \`krusch-context-mcp\`)
- Call \`krusch_context_retrieve({ query: "*", include_state: true, limit_tokens: 4000 })\` on Turn 1 to hydrate active project invariants, decisions, and lessons.
- Record durable architecture decisions and invariants with \`krusch_context_remember\`, evolve them with \`krusch_context_revise\`, and inspect store hygiene with \`krusch_context_health\`.
- Audit staged code changes and co-change/blame rules before committing via \`krusch_context_nudge({ trigger: "pre_commit", code: "<diff>" })\`.

## 2. Codebase AST & Dependency Graph Exploration (Tier 2A: \`krusch-git\`)
- Locate symbols with \`krusch_git_search_symbols\` and inspect callers/callees via \`krusch_git_dependency_graph\` before modifying public interfaces.
- Read bounded source ranges with \`krusch_git_read_blob\` and run hybrid symbol search with \`krusch_git_semantic_search\`.

## 3. Staged 2PC Verification Harness (Tier 3: \`krusch-harness\`)
- Stage multi-file edits with \`krusch_run\`, inspect unified diffs with \`krusch_diff\`, and apply verified changes with \`krusch_apply_diff\`.${tier3GroundedLine}
`;
  }

  const tier2Extra = hasExtendedMcp
    ? '\n- Traverse multi-hop structural context and temporal `asOf` ADR lineage via `hydrascope_traverse_context`, and verify/compose sealed runtime bricks via `brick_inbox` / `brick_blast_radius`.'
    : '\n- Enable `--modular` (or `--include-extended`) to also expose `hydrascope_*`, `brick_*`, and `krusch_grounded_*` MCP tools alongside the 39 core unified tools.';
  const tier3Extra = hasExtendedMcp
    ? '\n- Use `krusch_ground_workspace` and `krusch_grounded_verify_stop` for zero-LLM Turn-0 schema grounding and defect-only stop gating.'
    : '';
  return `# Agent Operating Manual (\`AGENTS.md\`)

> Powered by **KruschStack** (\`krusch-stack\`): Unified 3-Tier+Ontology Coding Agent MCP Ecosystem.

## 1. Session Start, Working Memory & Git Alignment (Tier 1: \`krusch-context-mcp\`)
- Call \`krusch_context_retrieve({ query: "*", include_state: true, limit_tokens: 4000 })\` on Turn 1 to hydrate active project invariants, decisions, and lessons.
- Record durable architecture decisions and invariants with \`krusch_context_remember\`.
- Audit staged code changes and co-change/blame rules before committing via \`krusch_context_nudge({ trigger: "pre_commit", code: "<diff>" })\`.

## 2. Codebase AST & Filesystem Exploration (Tier 2)
- Locate symbols with \`krusch_git_search_symbols\` and inspect callers/callees via \`krusch_git_dependency_graph\` before modifying public interfaces.
- Use \`krusch_fs_locate\`, \`krusch_fs_page_tree\`, and \`krusch_fs_read_page\` for bounded structural file reads and page-anchored notes (\`krusch_fs_remember_on_page\`).${tier2Extra}

## 3. Staged 2PC Verification Harness (Tier 3)
- Stage multi-file edits with \`krusch_run\`, inspect unified diffs with \`krusch_diff\`, and apply verified changes with \`krusch_apply_diff\`.${tier3Extra}
`;
}

/**
 * Safely write/merge IDE MCP configurations and scaffold `.agent/AGENTS.md` if missing.
 * @param {object} [options]
 * @param {string} [options.targetDir=process.cwd()]
 * @param {'claude'|'cursor'|'windsurf'|'antigravity'|'all'} [options.ide='all']
 * @param {'unified'|'modular'} [options.mode='unified']
 * @param {'memory-only'|'coding-agent'|'core'|'full'} [options.profile='full']
 * @param {boolean} [options.deferTools=false]
 * @param {boolean} [options.includeExtended=false]
 */
export function writeIdeConfigs({
  targetDir = process.cwd(),
  ide = 'all',
  mode = 'unified',
  profile = 'full',
  deferTools = false,
  includeExtended = false
} = {}) {
  const resolvedDir = path.resolve(targetDir);
  const normalizedProfile = normalizeStackProfile(profile, 'full');
  const normalizedMode = mode === 'modular' ? 'modular' : 'unified';
  const selectedIdes =
    ide === 'all'
      ? Object.keys(IDE_CONFIG_PATHS)
      : IDE_CONFIG_PATHS[ide]
        ? [ide]
        : ['claude'];

  const generated = generateIdeConfig({
    ide,
    mode: normalizedMode,
    profile: normalizedProfile,
    workspaceRoot: resolvedDir,
    deferTools,
    includeExtended
  });

  const filesWritten = [];

  for (const ideKey of selectedIdes) {
    const relPath = IDE_CONFIG_PATHS[ideKey];
    const absPath = path.join(resolvedDir, relPath);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });

    let existing = {};
    if (fs.existsSync(absPath)) {
      try {
        const raw = fs.readFileSync(absPath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          existing = parsed;
        }
      } catch {
        existing = {};
      }
    }

    const merged = {
      ...existing,
      mcpServers: {
        ...(existing.mcpServers && typeof existing.mcpServers === 'object'
          ? existing.mcpServers
          : {}),
        ...generated.mcpServers
      }
    };

    fs.writeFileSync(absPath, `${JSON.stringify(merged, null, 2)}\n`, 'utf8');
    filesWritten.push(absPath);
  }

  const agentsMdPath = path.join(resolvedDir, '.agent', 'AGENTS.md');
  let agentsMdCreated = false;
  if (!fs.existsSync(agentsMdPath)) {
    fs.mkdirSync(path.dirname(agentsMdPath), { recursive: true });
    fs.writeFileSync(
      agentsMdPath,
      buildDefaultAgentsMd({
        mode: normalizedMode,
        profile: normalizedProfile,
        includeExtended
      }),
      'utf8'
    );
    agentsMdCreated = true;
    filesWritten.push(agentsMdPath);
  }

  const envelope = okEnvelope(
    'krusch_ide_install',
    `Configured ${selectedIdes.length} IDE config file(s) (${normalizedMode} mode, ${normalizedProfile} profile) in ${resolvedDir}.`,
    {
      target_dir: resolvedDir,
      ide,
      mode: normalizedMode,
      profile: normalizedProfile,
      files_written: filesWritten,
      filesWritten,
      agents_md_path: agentsMdPath,
      agentsMdPath,
      agents_md_created: agentsMdCreated,
      mcpServers: generated.mcpServers
    }
  );

  return {
    ...envelope,
    filesWritten,
    agentsMdPath,
    mcpServers: generated.mcpServers
  };
}
