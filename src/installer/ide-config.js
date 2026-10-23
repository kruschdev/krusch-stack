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

const CORE_MODULAR_SERVERS = [
  'krusch-context-mcp',
  'krusch-git',
  'krusch-fs',
  'krusch-harness'
];

const FULL_EXTRA_SERVERS = [
  'krusch-frontend-mcp',
  'g-krusch'
];

/**
 * Generate MCP server configuration for a target IDE, mode, and profile.
 * @param {object} [options]
 * @param {'claude'|'cursor'|'windsurf'|'antigravity'|'all'} [options.ide='claude']
 * @param {'unified'|'modular'} [options.mode='unified']
 * @param {'core'|'full'} [options.profile='full']
 * @param {string} [options.workspaceRoot=process.cwd()]
 */
export function generateIdeConfig({
  ide = 'claude',
  mode = 'unified',
  profile = 'full',
  workspaceRoot = process.cwd()
} = {}) {
  const normalizedProfile = profile === 'core' ? 'core' : 'full';
  const normalizedMode = mode === 'modular' ? 'modular' : 'unified';
  const resolvedRoot = path.resolve(workspaceRoot);

  const mcpServers = {};

  if (normalizedMode === 'unified') {
    mcpServers['krusch-stack'] = {
      command: 'npx',
      args: ['-y', 'krusch-stack', 'mcp', '--profile', normalizedProfile],
      env: {
        KRUSCH_WORKSPACE_ROOT: resolvedRoot
      }
    };
  } else {
    const serverNames =
      normalizedProfile === 'full'
        ? [...CORE_MODULAR_SERVERS, ...FULL_EXTRA_SERVERS]
        : [...CORE_MODULAR_SERVERS];

    for (const serverName of serverNames) {
      mcpServers[serverName] = {
        command: 'npx',
        args: ['-y', 'krusch-stack', 'mcp', '--server', serverName],
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

const DEFAULT_AGENTS_MD = `# Agent Operating Manual (\`AGENTS.md\`)

> Powered by **KruschStack** (\`krusch-stack\`) — Unified 3-Tier Coding Agent MCP Ecosystem.

## 1. Session Start & Working Memory (Tier 1: \`krusch-context-mcp\`)
- Call \`krusch_context_retrieve({ query: "*", include_state: true, limit_tokens: 4000 })\` on Turn 1 to hydrate active project invariants, decisions, and lessons.
- Record durable architecture decisions and invariants with \`krusch_context_remember\`.
- Audit staged code changes before committing via \`krusch_context_nudge({ trigger: "pre_commit", code: "<diff>" })\`.

## 2. Codebase AST & Filesystem Exploration (Tier 2A & 2B: \`krusch-git\` & \`krusch-fs\`)
- Locate symbols with \`krusch_git_search_symbols\` and inspect callers/callees via \`krusch_git_dependency_graph\` before modifying public interfaces.
- Use \`krusch_fs_locate\`, \`krusch_fs_page_tree\`, and \`krusch_fs_read_page\` for bounded structural file reads and page-anchored notes (\`krusch_fs_remember_on_page\`).

## 3. Staged 2PC Verification Harness (Tier 3: \`krusch-harness\`)
- Stage multi-file edits with \`krusch_run\`, inspect unified diffs with \`krusch_diff\`, and apply verified changes with \`krusch_apply_diff\`.
`;

/**
 * Safely write/merge IDE MCP configurations and scaffold `.agent/AGENTS.md` if missing.
 * @param {object} [options]
 * @param {string} [options.targetDir=process.cwd()]
 * @param {'claude'|'cursor'|'windsurf'|'antigravity'|'all'} [options.ide='all']
 * @param {'unified'|'modular'} [options.mode='unified']
 * @param {'core'|'full'} [options.profile='full']
 */
export function writeIdeConfigs({
  targetDir = process.cwd(),
  ide = 'all',
  mode = 'unified',
  profile = 'full'
} = {}) {
  const resolvedDir = path.resolve(targetDir);
  const selectedIdes =
    ide === 'all'
      ? Object.keys(IDE_CONFIG_PATHS)
      : IDE_CONFIG_PATHS[ide]
        ? [ide]
        : ['claude'];

  const generated = generateIdeConfig({
    ide,
    mode,
    profile,
    workspaceRoot: resolvedDir
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
    fs.writeFileSync(agentsMdPath, DEFAULT_AGENTS_MD, 'utf8');
    agentsMdCreated = true;
    filesWritten.push(agentsMdPath);
  }

  const envelope = okEnvelope(
    'krusch_ide_install',
    `Configured ${selectedIdes.length} IDE config file(s) (${mode} mode, ${profile} profile) in ${resolvedDir}.`,
    {
      target_dir: resolvedDir,
      ide,
      mode,
      profile,
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
