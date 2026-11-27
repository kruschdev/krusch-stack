/**
 * @module mcp/server
 * Unified Model Context Protocol (MCP) Gateway for KruschStack.
 * Enforces INV-STACK-02 (universal envelope), INV-STACK-03 (4-boolean MCP tool annotations on every tool),
 * and INV-STACK-05 (profile & component filtering: --profile core|full, --components <csv>, --server <name>).
 */

import fs from 'node:fs';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError
} from '@modelcontextprotocol/sdk/types.js';
import { createKruschStack, VERSION } from '../index.js';
import { okEnvelope } from '../db/sqlite.js';
import {
  createStackDeferredBridge,
  DEFERRED_BRIDGE_TOOLS,
  DEFERRED_BRIDGE_TOOL_NAMES,
  PINNED_CORE_TOOL_NAMES
} from './deferred-bridge.js';

export {
  createStackDeferredBridge,
  DEFERRED_BRIDGE_TOOLS,
  DEFERRED_BRIDGE_TOOL_NAMES,
  PINNED_CORE_TOOL_NAMES
};

const SERVER_TO_COMPONENT = {
  'krusch-context-mcp': 'context',
  'krusch-git': 'git',
  'krusch-fs': 'fs',
  hydrascope: 'hydrascope',
  'hydrascope-mcp': 'hydrascope',
  'krusch-brick-exchange': 'brick-exchange',
  'krusch-harness': 'harness',
  'krusch-grounded-harness': 'grounded-harness',
  'krusch-frontend-mcp': 'frontend',
  'krusch-workspace': 'workspace',
  'krusch-cascade-router': 'router'
};

const MODULAR_EXTENSION_COMPONENTS = new Set([
  'hydrascope',
  'brick-exchange',
  'grounded-harness'
]);

const MODULAR_SERVER_PINNED_DEFAULTS = Object.freeze({
  hydrascope: ['hydrascope_traverse_context', 'hydrascope_check_answerable'],
  'hydrascope-mcp': ['hydrascope_traverse_context', 'hydrascope_check_answerable'],
  'krusch-brick-exchange': ['brick_inbox', 'brick_blast_radius'],
  'krusch-grounded-harness': ['krusch_ground_workspace', 'krusch_grounded_verify_stop']
});

export function assertPathWithinWorkspace(candidatePath, workspaceRoot, { allowReset = false } = {}) {
  const raw = typeof candidatePath === 'string' ? candidatePath.trim() : '';
  if (!raw) return raw;
  if (allowReset && raw === 'reset') return 'reset';

  const makeEscapeErr = (msg) => {
    const err = new Error(msg);
    err.code = 'PATH_OUTSIDE_WORKSPACE';
    err.statusCode = 403;
    return err;
  };

  const resolvedRoot = path.resolve(workspaceRoot || process.cwd());
  let realRoot = resolvedRoot;
  if (fs.existsSync(resolvedRoot)) {
    realRoot = fs.realpathSync(resolvedRoot);
  }
  const absCandidate = path.resolve(resolvedRoot, raw);
  const relLexical = path.relative(resolvedRoot, absCandidate);
  if (relLexical.startsWith('..') || path.isAbsolute(relLexical)) {
    throw makeEscapeErr(`Path escapes workspaceRoot: ${raw}`);
  }

  // Walk every path segment with lstatSync (without existsSync) so dangling symlinks are caught too.
  const segments = relLexical.split(path.sep).filter(Boolean);
  let walkCur = resolvedRoot;
  for (const seg of segments) {
    walkCur = path.join(walkCur, seg);
    let st;
    try {
      st = fs.lstatSync(walkCur);
    } catch (err) {
      if (err?.code === 'ENOENT' || err?.code === 'ENOTDIR') {
        break;
      }
      throw err;
    }
    if (st.isSymbolicLink()) {
      let realTarget;
      try {
        realTarget = fs.realpathSync(walkCur);
      } catch {
        throw makeEscapeErr(`Dangling symbolic link is forbidden at workspace boundary: ${raw}`);
      }
      if (realTarget !== realRoot && !realTarget.startsWith(realRoot + path.sep)) {
        throw makeEscapeErr(`Symlink escapes workspaceRoot: ${raw}`);
      }
    }
  }

  let cur = absCandidate;
  while (cur && cur !== path.dirname(cur) && !fs.existsSync(cur)) {
    cur = path.dirname(cur);
  }
  if (fs.existsSync(cur)) {
    const realAncestor = fs.realpathSync(cur);
    if (realAncestor !== realRoot && !realAncestor.startsWith(realRoot + path.sep)) {
      throw makeEscapeErr(`Path resolves outside workspaceRoot via symlink: ${raw}`);
    }
  }
  return absCandidate;
}

const MEMORY_ONLY_COMPONENTS = new Set(['context']);
const CODING_AGENT_COMPONENTS = new Set(['context', 'git', 'harness']);
const CORE_COMPONENTS = new Set(['context', 'git', 'fs', 'harness', 'router']);
const FULL_COMPONENTS = new Set(['context', 'git', 'fs', 'harness', 'frontend', 'workspace', 'router']);

/**
 * Helper to build an MCP tool definition with mandatory 4-boolean annotations (INV-STACK-03 / Memory #567).
 */
function defineTool({
  name,
  component,
  title,
  description,
  inputSchema,
  readOnlyHint = true,
  destructiveHint = false,
  idempotentHint = true,
  openWorldHint = false
}) {
  return {
    name,
    component,
    description,
    inputSchema,
    annotations: {
      title: title || name,
      readOnlyHint: Boolean(readOnlyHint),
      destructiveHint: Boolean(destructiveHint),
      idempotentHint: Boolean(idempotentHint),
      openWorldHint: Boolean(openWorldHint)
    }
  };
}

export const ALL_STACK_TOOLS = [
  // ============================================================================
  // Tier 1: krusch-context-mcp (5 tools)
  // ============================================================================
  defineTool({
    name: 'krusch_context_retrieve',
    component: 'context',
    title: 'Retrieve Working Memory & Invariants',
    description: 'Hydrate active project invariants, decisions, bugs, lessons, and span-grounded drift status.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query or "*" for full state hydration' },
        category: { type: 'string', enum: ['decision', 'invariant', 'bug', 'lesson', 'blocker'] },
        include_state: { type: 'boolean', default: true },
        include_lineage: { type: 'boolean', description: 'Include superseded lineage history (auto-enabled on temporal queries)' },
        condense: { type: 'boolean', description: 'Enable 3-tier progressive condensation (auto-enabled on episodic stores >=30 turns)' },
        include_markdown: { type: 'boolean', default: false },
        limit_tokens: { type: 'number', default: 4000 }
      }
    }
  }),
  defineTool({
    name: 'krusch_context_remember',
    component: 'context',
    title: 'Remember Project Decision or Invariant',
    description: 'Persist a durable rule, architectural decision, bug root-cause, lesson, or blocker with optional file/span provenance.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        category: { type: 'string', enum: ['decision', 'invariant', 'bug', 'lesson', 'blocker'] },
        content: { type: 'string', description: 'Durable rule or decision statement' },
        provenance: {
          type: 'object',
          properties: {
            file: { type: 'string' },
            locator: { type: 'string' },
            quoted_sentence: { type: 'string' }
          }
        }
      },
      required: ['category', 'content']
    }
  }),
  defineTool({
    name: 'krusch_context_revise',
    component: 'context',
    title: 'Supersede or Invalidate Memory',
    description: 'Supersede an evolving decision with lineage or invalidate an obsolete rule.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['supersede', 'invalidate'] },
        target_id: { type: 'number', description: 'ID of memory record to revise' },
        new_content: { type: 'string', description: 'Replacement content when action is supersede' },
        reason: { type: 'string', description: 'Reason for revision or revocation' },
        provenance: {
          type: 'object',
          properties: {
            file: { type: 'string' },
            locator: { type: 'string' },
            quoted_sentence: { type: 'string' }
          }
        }
      },
      required: ['action', 'target_id']
    }
  }),
  defineTool({
    name: 'krusch_context_nudge',
    component: 'context',
    title: 'Audit Diff Against Invariants',
    description: 'Audit staged code or unified diffs against active project invariants (max 3 findings).',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        trigger: { type: 'string', default: 'pre_commit' },
        code: { type: 'string', description: 'Code or unified diff to audit' },
        file_path: { type: 'string', description: 'Optional target file path for git blame attribution' },
        enable_lego_guard: { type: 'boolean', description: 'Optional flag to force INV-LEGO-01 boilerplate check' }
      }
    }
  }),
  defineTool({
    name: 'krusch_context_health',
    component: 'context',
    title: 'Inspect Memory Store Health',
    description: 'Inspect memory store statistics and INV-12 span-grounded drift counts.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }),

  // ============================================================================
  // Tier 2A: krusch-git (7 tools)
  // ============================================================================
  defineTool({
    name: 'krusch_git_list_repos',
    component: 'git',
    title: 'List Indexed Git Repositories',
    description: 'List indexed repositories and symbol statistics in the workspace.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }),
  defineTool({
    name: 'krusch_git_read_tree',
    component: 'git',
    title: 'Read Repository Directory Tree',
    description: 'List files and directories at a given path inside the repository.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string' },
        path: { type: 'string', default: '' }
      }
    }
  }),
  defineTool({
    name: 'krusch_git_read_blob',
    component: 'git',
    title: 'Read Repository File Blob',
    description: 'Read bounded lines from a file in the repository.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string' },
        path: { type: 'string' },
        start_line: { type: 'number' },
        end_line: { type: 'number' }
      },
      required: ['path']
    }
  }),
  defineTool({
    name: 'krusch_git_search_symbols',
    component: 'git',
    title: 'Search AST Symbols',
    description: 'Locate functions, classes, methods, exports, and markdown sections across the codebase.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string' },
        query: { type: 'string' },
        symbol_type: { type: 'string' }
      },
      required: ['query']
    }
  }),
  defineTool({
    name: 'krusch_git_file_symbols',
    component: 'git',
    title: 'List Symbols in File',
    description: 'List all extracted AST symbols and line spans within a specific file.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string' },
        file_path: { type: 'string' }
      },
      required: ['file_path']
    }
  }),
  defineTool({
    name: 'krusch_git_dependency_graph',
    component: 'git',
    title: 'Trace AST Symbol Blast Radius',
    description: 'Trace inbound callers and outbound callees for a symbol before modifying signatures.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string' },
        symbol: { type: 'string' }
      },
      required: ['symbol']
    }
  }),
  defineTool({
    name: 'krusch_git_semantic_search',
    component: 'git',
    title: 'Hybrid Codebase Search',
    description: 'Search symbols and code snippets using keyword + structural token ranking.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repo: { type: 'string' },
        query: { type: 'string' },
        limit: { type: 'number', default: 10 },
        limit_tokens: { type: 'number' }
      },
      required: ['query']
    }
  }),

  // ============================================================================
  // Tier 2B: krusch-fs (6 tools)
  // ============================================================================
  defineTool({
    name: 'krusch_fs_locate',
    component: 'fs',
    title: 'Locate Files by Glob Pattern',
    description: 'Fast file metadata and glob lookup without reading full file contents.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', default: '*' },
        category: { type: 'string', default: 'all' },
        min_size_bytes: { type: 'number', default: 0 }
      }
    }
  }),
  defineTool({
    name: 'krusch_fs_search',
    component: 'fs',
    title: 'Search Indexed OS Pages & PageMemory',
    description: 'Search structural file pages and anchored PageMemory notes.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        category: { type: 'string', default: 'all' },
        limit: { type: 'number', default: 10 },
        limit_tokens: { type: 'number' }
      },
      required: ['query']
    }
  }),
  defineTool({
    name: 'krusch_fs_page_tree',
    component: 'fs',
    title: 'Inspect File Structural Page Tree',
    description: 'Inspect the structural table of contents (page numbers, section titles, line ranges, SHA-256 hashes) before reading a file.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' }
      },
      required: ['path']
    }
  }),
  defineTool({
    name: 'krusch_fs_read_page',
    component: 'fs',
    title: 'Read Bounded File Page with Drift Status',
    description: 'Read a specific page of a file along with anchored notes and SHA-256 drift verification (VALID vs STALE_DRIFT).',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        page_number: { type: 'number', default: 1 }
      },
      required: ['path']
    }
  }),
  defineTool({
    name: 'krusch_fs_remember_on_page',
    component: 'fs',
    title: 'Anchor Note to File Page',
    description: 'Pin a durable operational note or warning to an exact file page anchored by SHA-256 hash.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        page_number: { type: 'number', default: 1 },
        note: { type: 'string' },
        category: { type: 'string', enum: ['annotation', 'warning', 'summary', 'todo'], default: 'annotation' }
      },
      required: ['path', 'note']
    }
  }),
  defineTool({
    name: 'krusch_fs_sync',
    component: 'fs',
    title: 'Sync Files into Page Memory',
    description: 'Index or refresh workspace files into the structural page store.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        paths: { type: 'array', items: { type: 'string' } }
      }
    }
  }),

  // ============================================================================
  // Tier 3: krusch-harness (7 tools)
  // ============================================================================
  defineTool({
    name: 'krusch_run',
    component: 'harness',
    title: 'Stage 2PC Coding Task & Invariant Gate',
    description: 'Stage proposed file edits as a unified diff and run the pre-commit invariant gate without mutating the working tree.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        goal: { type: 'string' },
        edits: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              file_path: { type: 'string' },
              content: { type: 'string' }
            },
            required: ['file_path', 'content']
          }
        }
      },
      required: ['goal']
    }
  }),
  defineTool({
    name: 'krusch_task_status',
    component: 'harness',
    title: 'Check Staged Task Status',
    description: 'Inspect the state of a staged 2PC task (STAGED, BLOCKED_INVARIANT, APPLIED, REJECTED, ABORTED).',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        task_id: { type: 'string' }
      },
      required: ['task_id']
    }
  }),
  defineTool({
    name: 'krusch_diff',
    component: 'harness',
    title: 'Inspect Staged Unified Diff',
    description: 'Retrieve the staged unified diff for a task before applying to disk.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        task_id: { type: 'string' }
      },
      required: ['task_id']
    }
  }),
  defineTool({
    name: 'krusch_apply_diff',
    component: 'harness',
    title: 'Atomically Apply Verified Diff to Working Tree',
    description: 'Apply a STAGED task diff to disk after passing the invariant gate.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        task_id: { type: 'string' }
      },
      required: ['task_id']
    }
  }),
  defineTool({
    name: 'krusch_explain',
    component: 'harness',
    title: 'Explain Task Transitions & Invariant Findings',
    description: 'Explain why a task was staged or blocked by project invariants.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        task_id: { type: 'string' }
      },
      required: ['task_id']
    }
  }),
  defineTool({
    name: 'krusch_reject',
    component: 'harness',
    title: 'Reject Staged Task',
    description: 'Reject a staged diff with a recorded reason without writing to disk.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        task_id: { type: 'string' },
        reason: { type: 'string' }
      },
      required: ['task_id']
    }
  }),
  defineTool({
    name: 'krusch_abort',
    component: 'harness',
    title: 'Abort Staged Task',
    description: 'Cancel and abort an in-progress or staged task.',
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        task_id: { type: 'string' }
      },
      required: ['task_id']
    }
  }),

  // ============================================================================
  // Tier 4: krusch-frontend-mcp (6 tools)
  // ============================================================================
  defineTool({
    name: 'generate_color_palette',
    component: 'frontend',
    title: 'Generate WCAG Color Palette',
    description: 'Generate a 5-stop HSL color palette with WCAG 2.1 contrast ratios against dark and light surfaces.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        base_hex: { type: 'string', default: '#00e5ff' },
        harmony: {
          type: 'string',
          enum: ['complementary', 'analogous', 'triadic', 'split-complementary', 'monochromatic'],
          default: 'complementary'
        }
      }
    }
  }),
  defineTool({
    name: 'css_to_tailwind',
    component: 'frontend',
    title: 'Compile CSS to Tailwind Utilities',
    description: 'Convert raw CSS declarations into deterministic Tailwind utility classes.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        css: { type: 'string' }
      },
      required: ['css']
    }
  }),
  defineTool({
    name: 'query_design_rules',
    component: 'frontend',
    title: 'Query Frontend Design & Accessibility Rules',
    description: 'Retrieve typography, contrast, spacing, and layout rules from the design system store.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        category: { type: 'string' }
      }
    }
  }),
  defineTool({
    name: 'get_canonical_template',
    component: 'frontend',
    title: 'Get Canonical HTML/SVG or Lego Starter Template',
    description: 'Retrieve a canonical HTML/SVG, Vercel, or @krusch/toolkit & krusch_toolkit Lego starter template (article-shell, site-header, footer-deadbolt, cyber-grid, deadbolt-svg, nav-back, lego-node-api, lego-mcp-server, lego-sse-route, lego-react-shell, lego-fastapi-app, lego-cloudflare-worker, lego-webhook-route, lego-vercel-nextjs-shell, lego-vercel-edge-sse, lego-vercel-json).',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        template_id: {
          type: 'string',
          enum: [
            'article-shell',
            'site-header',
            'footer-deadbolt',
            'cyber-grid',
            'deadbolt-svg',
            'nav-back',
            'lego-node-api',
            'lego-mcp-server',
            'lego-sse-route',
            'lego-react-shell',
            'lego-fastapi-app',
            'lego-cloudflare-worker',
            'lego-webhook-route',
            'lego-vercel-nextjs-shell',
            'lego-vercel-edge-sse',
            'lego-vercel-json'
          ]
        }
      },
      required: ['template_id']
    }
  }),
  defineTool({
    name: 'list_canonical_templates',
    component: 'frontend',
    title: 'List Canonical Frontend & Lego Templates',
    description: 'List all available canonical HTML/SVG component templates and @krusch/toolkit & krusch_toolkit Lego starter bricks.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }),
  defineTool({
    name: 'generate_responsive_breakpoints',
    component: 'frontend',
    title: 'Generate Responsive Breakpoint Specs',
    description: 'Generate 375px (mobile), 768px (tablet), and 1440px (desktop) responsive layout specs.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        component_type: { type: 'string', default: 'grid' }
      }
    }
  }),

  // ============================================================================
  // Tier 5: Local Workspace Hub (krusch-workspace, 6 tools)
  // ============================================================================
  defineTool({
    name: 'get_agent_steering',
    component: 'workspace',
    title: 'Get Workspace Agent Steering',
    description: 'Read the workspace agent.md steering directives.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }),
  defineTool({
    name: 'search_drive_rag',
    component: 'workspace',
    title: 'Search Workspace Drive RAG',
    description: 'Search workspace documents, Docs, Sheets, and Slides.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        limit: { type: 'number', default: 10 }
      },
      required: ['query']
    }
  }),
  defineTool({
    name: 'read_drive_file',
    component: 'workspace',
    title: 'Read Workspace Document',
    description: 'Read a document from the workspace store by path with MIME disambiguation.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' }
      },
      required: ['path']
    }
  }),
  defineTool({
    name: 'write_drive_file',
    component: 'workspace',
    title: 'Write Workspace Document (.md, .gdoc, .gsheet, .slides)',
    description: 'Write a Markdown, Google Doc (.gdoc), Sheet (.gsheet), or Slide deck (.slides) to the workspace with INV-14 MIME disambiguation.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string' },
        content: { type: 'string' },
        mime_type: { type: 'string' }
      },
      required: ['path', 'content']
    }
  }),
  defineTool({
    name: 'list_drive_workspace',
    component: 'workspace',
    title: 'List Workspace Files',
    description: 'List all files stored in the workspace hub.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        folder: { type: 'string', default: '' }
      }
    }
  }),
  defineTool({
    name: 'get_workspace_status',
    component: 'workspace',
    title: 'Get Workspace Hub Status',
    description: 'Inspect document counts and MIME breakdown in the workspace hub.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }),

  // ============================================================================
  // Router & Stack Diagnostics (2 tools)
  // ============================================================================
  defineTool({
    name: 'krusch_route_task',
    component: 'router',
    title: 'Route Task Across L1-L3 Model Cascade',
    description: 'Classify a coding or reasoning prompt in <25µs into L1_FAST_LOCAL, L2_SWE_MOE, L2_5_BURST_120B, or L3_FRONTIER_REFEREE.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        prompt: { type: 'string' },
        task_type: { type: 'string' },
        budget_tier: { type: 'string', default: 'auto' }
      },
      required: ['prompt']
    }
  }),
  defineTool({
    name: 'krusch_stack_status',
    component: 'router',
    title: 'Inspect Full KruschStack Status',
    description: 'Return aggregate readiness and telemetry across all KruschStack engines.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  })
];

/**
 * Modular extension MCP tools exposed when running per-server (`--server hydrascope`,
 * `--server krusch-brick-exchange`, `--server krusch-grounded-harness`) or explicit `--components`
 * while keeping default unified `ALL_STACK_TOOLS.length === 39` strictly intact.
 */
export const MODULAR_EXTENSION_TOOLS = [
  // ============================================================================
  // Tier 2C: hydrascope (6 tools)
  // ============================================================================
  defineTool({
    name: 'hydrascope_traverse_context',
    component: 'hydrascope',
    title: 'Traverse Structural Agent Context & Temporal Ontology',
    description:
      'Walk multi-hop AST call/import/env edges and temporal SUPERSEDES lineage (plus optional 4-Axis Brick Ontology) to assemble a bounded context slice.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Engineering task or question to ground structurally.' },
        asOf: { type: 'string', description: 'Optional ISO date (YYYY-MM-DD) for point-in-time historical graph replay.' },
        tokenBudget: { type: 'integer', default: 900, description: 'Maximum context token budget.' },
        maxHops: { type: 'integer', default: 3, description: 'Maximum structural hops (1 to 6).' },
        includeBrickOntology: { type: 'boolean', description: 'Also query the authorized 4-Axis Brick Ontology when true.' },
        viewerId: { type: 'string', description: 'Authorized viewer member ID for scoped 4-Axis Brick Ontology hydration.' },
        viewerOrgId: { type: 'string', description: 'Authorized viewer organization slug for 4-Axis Brick Ontology hydration.' },
        targetStack: { type: 'string', description: 'Optional 4-Axis runtime stack filter (node-esm, typescript-node, python-fastapi, react-vite, cloudflare-edge).' },
        targetChannel: { type: 'string', description: 'Optional 4-Axis channel filter (e.g. webhook:stripe, workspace:gmail).' },
        requiredPorts: { type: 'array', items: { type: 'string' }, description: 'Optional canonical or namespaced data ports.' }
      },
      required: ['query']
    }
  }),
  defineTool({
    name: 'hydrascope_check_answerable',
    component: 'hydrascope',
    title: 'Check Pre-Flight Ontology Answerability',
    description:
      'Verify at zero LLM token cost whether every queried technical subsystem or identifier is grounded in the HydraScope ontology before calling a model.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Candidate user or agent question.' }
      },
      required: ['query']
    }
  }),
  defineTool({
    name: 'hydrascope_compare_vector_vs_graph',
    component: 'hydrascope',
    title: 'Compare Dense Vector Top-K vs Structural Traversal',
    description:
      'Run a head-to-head comparison between dense cosine top-K retrieval and HydraScope structural traversal, reporting missed multi-hop dependencies, superseded ADR poisoning, and token savings.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Engineering task or question to compare.' },
        asOf: { type: 'string', description: 'Optional ISO date (YYYY-MM-DD) for temporal evaluation.' },
        tokenBudget: { type: 'integer', default: 900 },
        topK: { type: 'integer', default: 4 }
      },
      required: ['query']
    }
  }),
  defineTool({
    name: 'hydrascope_run_benchmark',
    component: 'hydrascope',
    title: 'Run 8-Task Proof-Over-Vectors Benchmark Suite',
    description:
      'Execute the 8-scenario evaluation suite comparing Full-Repo Stuffing, Dense Vector Store Top-K, and HydraScope Structural Traversal.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {}
    }
  }),
  defineTool({
    name: 'hydrascope_supersede_decision',
    component: 'hydrascope',
    title: 'Supersede Architecture Decision in HydraScope',
    description:
      'Write a new Architecture Decision Record with a directed SUPERSEDES edge, retiring the superseded rule from active context while preserving asOf history.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        oldId: { type: 'string' },
        newId: { type: 'string' },
        title: { type: 'string' },
        content: { type: 'string' },
        governsIds: { type: 'array', items: { type: 'string' } },
        effectiveAt: { type: 'string' }
      },
      required: ['oldId', 'newId', 'title', 'content']
    }
  }),
  defineTool({
    name: 'hydrascope_ingest_directory',
    component: 'hydrascope',
    title: 'Compile Local Repository Directory into HydraScope',
    description:
      'Parse 10-language AST symbols, relative imports, environment variable reads, and ADR markdown files from a workspace directory (or "reset" to restore the FinTech benchmark graph).',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        targetDir: { type: 'string' }
      },
      required: ['targetDir']
    }
  }),

  // ============================================================================
  // Tier 2D: krusch-brick-exchange (10 tools)
  // ============================================================================
  defineTool({
    name: 'brick_seal',
    component: 'brick-exchange',
    title: 'Verify & Seal Brick',
    description:
      'Run 4-gate sandbox verification (zero-ambient-I/O safety, schema contract, positive + adversarial fault checks, and Ed25519 signature) to produce a sealed brick bundle.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        blueprint: { type: 'object' },
        source: { type: 'string' },
        positiveChecks: { type: 'array', items: { type: 'object' } },
        faultChecks: { type: 'array', items: { type: 'object' } },
        authorId: { type: 'string' },
        orgId: { type: 'string' },
        ontology: { type: 'object' },
        publish: { type: 'boolean' }
      },
      required: ['blueprint', 'source', 'positiveChecks', 'faultChecks']
    }
  }),
  defineTool({
    name: 'brick_verify',
    component: 'brick-exchange',
    title: 'Verify Sealed Brick Bundle',
    description: 'Verify canonical SHA-256 digests, fault-challenge coverage, and Ed25519 signature of a sealed brick bundle.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        bundle: { type: 'object' },
        trustedPublicKeyPem: { type: 'string' }
      },
      required: ['bundle']
    }
  }),
  defineTool({
    name: 'brick_suggest',
    component: 'brick-exchange',
    title: 'Suggest Eligible Bricks & Recipients',
    description: 'Recommend authorized sealed bricks and polyglot/boilerplate candidates for an actor or workspace.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        actorId: { type: 'string' },
        viewerId: { type: 'string' },
        viewerOrgId: { type: 'string' },
        brickId: { type: 'string' },
        repoRoot: { type: 'string' }
      }
    }
  }),
  defineTool({
    name: 'brick_share',
    component: 'brick-exchange',
    title: 'Issue Scoped Brick Grant',
    description: 'Issue a scoped federated or recipient-bound Common Ground grant for a verified brick.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        brickId: { type: 'string' },
        sourceHash: { type: 'string' },
        issuerId: { type: 'string' },
        actorId: { type: 'string' },
        issuerOrgId: { type: 'string' },
        scope: { type: 'string' },
        recipients: { type: 'array', items: { type: 'string' } },
        ttlMs: { type: 'number' },
        expiresAtMs: { type: 'number' }
      },
      required: ['brickId', 'issuerOrgId']
    }
  }),
  defineTool({
    name: 'brick_inbox',
    component: 'brick-exchange',
    title: 'List Authorized Brick Inbox & 4-Axis Compositions',
    description: 'List sealed bricks authorized for a viewer via org membership or active grants, with optional 4-axis cross-stack composition.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        viewerId: { type: 'string' },
        viewerOrgId: { type: 'string' },
        targetStack: { type: 'string' },
        targetChannel: { type: 'string' },
        requiredPorts: { type: 'array', items: { type: 'string' } }
      }
    }
  }),
  defineTool({
    name: 'brick_try_local',
    component: 'brick-exchange',
    title: 'Try Sealed Brick Locally in Sandbox',
    description: 'Execute a sealed brick in the isolated local sandbox against recipient sampleInput with zero remote upload.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        bundle: { type: 'object' },
        viewerId: { type: 'string' },
        brickId: { type: 'string' },
        sourceHash: { type: 'string' },
        sampleInput: {},
        binding: { type: 'object' }
      },
      required: ['sampleInput']
    }
  }),
  defineTool({
    name: 'brick_adopt',
    component: 'brick-exchange',
    title: 'Adopt & Vendor Sealed Brick into Repo',
    description: 'Vendor a verified sealed brick into bricks/<brickId>/, synthesize hexagonal binding adapter if requested, and update .brick-lock.json.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        bundle: { type: 'object' },
        userId: { type: 'string' },
        viewerId: { type: 'string' },
        brickId: { type: 'string' },
        targetRepoDir: { type: 'string' },
        targetStack: { type: 'string' },
        localSample: {},
        fieldMap: { type: 'object' }
      },
      required: ['targetRepoDir']
    }
  }),
  defineTool({
    name: 'brick_revoke',
    component: 'brick-exchange',
    title: 'Revoke Scoped Brick Grant',
    description: 'Immediately revoke a previously issued brick grant so future cross-org discovery and adoptions fail closed.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        actorId: { type: 'string' },
        grantId: { type: 'string' }
      },
      required: ['actorId', 'grantId']
    }
  }),
  defineTool({
    name: 'brick_blast_radius',
    component: 'brick-exchange',
    title: 'Analyze 2-Hop AST Blast Radius',
    description: 'Compute Deadbolt 2-hop AST dependency cones (hop0 -> hop1 -> hop2) and Policy Floor status for target files.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repoRoot: { type: 'string' },
        repoDir: { type: 'string' },
        targetFiles: { type: 'array', items: { type: 'string' } },
        changedFiles: { type: 'array', items: { type: 'string' } },
        policyFloorFiles: { type: 'array', items: { type: 'string' } },
        protectedFiles: { type: 'array', items: { type: 'string' } }
      },
      required: ['targetFiles']
    }
  }),
  defineTool({
    name: 'brick_plan_fanout',
    component: 'brick-exchange',
    title: 'Plan Disjoint 2-Hop Subagent Waves',
    description: 'Sequence multi-agent tasks into conflict-free 2-hop AST waves and serialize choke points.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        repoRoot: { type: 'string' },
        repoDir: { type: 'string' },
        tasks: { type: 'array', items: { type: 'object' } },
        policyFloorFiles: { type: 'array', items: { type: 'string' } },
        protectedFiles: { type: 'array', items: { type: 'string' } }
      },
      required: ['tasks']
    }
  }),

  // ============================================================================
  // Tier 3B: krusch-grounded-harness (7 tools)
  // ============================================================================
  defineTool({
    name: 'krusch_ground_workspace',
    component: 'grounded-harness',
    title: 'Compile Turn-0 Workspace Grounding',
    description:
      'Introspect workspace schemas (CSV/TSV, JSON/JSONL, read-only SQLite DDL, source symbols, and 256/32 Raw-RAG docs) with 0 LLM calls and emit a KV-cache-stable prompt bundle.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        goal: { type: 'string' },
        workspaceDir: { type: 'string' },
        model: { type: 'string' },
        tools: { type: 'array', items: { type: 'object' } },
        pinnedToolNames: { type: 'array', items: { type: 'string' } },
        maxGroundingTokens: { type: 'integer' }
      }
    }
  }),
  defineTool({
    name: 'krusch_resolve_scale_profile',
    component: 'grounded-harness',
    title: 'Resolve Scale-Aware Harness Profile',
    description:
      'Deterministically map a model identifier and thinking hints into SMALL_MODEL, MID_MODEL, or FRONTIER_REASONING harness policy.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        model: { type: 'string' },
        activeParamsB: { type: 'number' },
        totalParamsB: { type: 'number' },
        thinkingEnabled: { type: 'boolean' }
      }
    }
  }),
  defineTool({
    name: 'krusch_grounded_session_start',
    component: 'grounded-harness',
    title: 'Start Grounded Harness Session',
    description: 'Create or reset a SQLite-tracked grounded session seeded with Turn-0 chunk IDs, file digests, and scale profile.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        goal: { type: 'string' },
        model: { type: 'string' },
        anchor_date: { type: 'string' },
        prefix_hash: { type: 'string' },
        seen_chunk_ids: { type: 'array', items: { type: 'string' } },
        file_digests: { type: 'object' },
        allowed_scopes: { type: 'array', items: { type: 'string' } },
        turn0_tokens: { type: 'integer' },
        max_duplicate_writes: { type: 'integer' }
      },
      required: ['goal']
    }
  }),
  defineTool({
    name: 'krusch_grounded_intercept',
    component: 'grounded-harness',
    title: 'Intercept Tool Call With Passive Safety & Read Memoization',
    description: 'Check a proposed tool call against the frozen policy floor, secret-leak guard, duplicate-write guard, and read memoization cache.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        step: { type: 'integer' },
        tool_name: { type: 'string' },
        args: { type: 'object' },
        mutating: { type: 'boolean' },
        suppress_turn0_reads: { type: 'boolean' },
        block_spin_loop: { type: 'boolean' }
      },
      required: ['session_id', 'tool_name']
    }
  }),
  defineTool({
    name: 'krusch_grounded_outcome',
    component: 'grounded-harness',
    title: 'Record Tool Call Execution Outcome',
    description: 'Commit or fail a pending intercepted tool call, memoizing read previews and preserving partial stdout on timeouts.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        event_id: { type: 'string' },
        ok: { type: 'boolean' },
        result_preview: { type: 'string' },
        timed_out: { type: 'boolean' },
        partial_stdout: { type: 'string' },
        pending_diffs_delta: { type: 'integer' },
        verification_passed: { type: 'boolean' }
      },
      required: ['session_id', 'event_id']
    }
  }),
  defineTool({
    name: 'krusch_grounded_verify_stop',
    component: 'grounded-harness',
    title: 'Verify Outer Loop Stop With Zero-Turn Defect-Only Gate',
    description: 'Approve zero-overhead completion when pendingDiffsCount=0 and output has 0 objective defects.',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        assistant_text: { type: 'string' },
        candidate_answer: {},
        finish_reason: { type: 'string' },
        expect_non_empty_answer: { type: 'boolean' },
        pending_diffs_count: { type: 'integer' },
        latest_verification_passed: { type: 'boolean' }
      },
      required: ['session_id']
    }
  }),
  defineTool({
    name: 'krusch_grounded_summary',
    component: 'grounded-harness',
    title: 'Get Grounded Session Telemetry Summary',
    description: 'Retrieve session metrics including exploratory foraging ratio, memoized reads, spin loops blocked, and output defects caught.',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' }
      },
      required: ['session_id']
    }
  })
];

function resolveRawToolCatalog(allowedSet, includeExtended = false) {
  let needsExtended = Boolean(includeExtended);
  if (!needsExtended) {
    for (const extComp of MODULAR_EXTENSION_COMPONENTS) {
      if (allowedSet.has(extComp)) {
        needsExtended = true;
        break;
      }
    }
  }
  const sourceCatalog = needsExtended
    ? [...ALL_STACK_TOOLS, ...MODULAR_EXTENSION_TOOLS]
    : ALL_STACK_TOOLS;
  return sourceCatalog.filter((t) => allowedSet.has(t.component));
}

function resolveAllowedComponentSet({ profile = 'full', components, server } = {}) {
  if (server && Object.hasOwn(SERVER_TO_COMPONENT, server)) {
    return new Set([SERVER_TO_COMPONENT[server]]);
  }
  if (Array.isArray(components) && components.length > 0) {
    return new Set(components.map((c) => String(c).trim().toLowerCase()));
  }
  if (typeof components === 'string' && components.trim()) {
    return new Set(
      components
        .split(',')
        .map((c) => c.trim().toLowerCase())
        .filter(Boolean)
    );
  }
  const normalized = typeof profile === 'string' ? profile.trim().toLowerCase() : 'full';
  if (normalized === 'memory-only' || normalized === 'memory_only' || normalized === 'memory') {
    return MEMORY_ONLY_COMPONENTS;
  }
  if (normalized === 'coding-agent' || normalized === 'coding_agent' || normalized === 'coding') {
    return CODING_AGENT_COMPONENTS;
  }
  return normalized === 'core' ? CORE_COMPONENTS : FULL_COMPONENTS;
}

/**
 * Filter tools by profile ('core' | 'full'), explicit component list, or single modular server name.
 * When `deferTools: true` is set, collapses the filtered catalog into pinned core tools + 3 BM25 bridge meta-tools.
 */
function resolveEffectivePinnedTools(server, pinnedToolNames) {
  if (Array.isArray(pinnedToolNames)) return pinnedToolNames;
  if (server && Object.hasOwn(MODULAR_SERVER_PINNED_DEFAULTS, server)) {
    return MODULAR_SERVER_PINNED_DEFAULTS[server];
  }
  return undefined;
}

export function getStackTools({
  profile = 'full',
  components,
  server,
  deferTools = false,
  pinnedToolNames,
  includeExtended = false
} = {}) {
  const allowed = resolveAllowedComponentSet({ profile, components, server });
  const rawAllowed = resolveRawToolCatalog(allowed, includeExtended);
  if (deferTools) {
    const bridge = createStackDeferredBridge(rawAllowed, {
      pinnedToolNames: resolveEffectivePinnedTools(server, pinnedToolNames)
    });
    return [...bridge.exposedTools];
  }
  return rawAllowed.map(({ component: _c, ...toolDef }) => toolDef);
}

const INTERNAL_STRIPPED_ARG_KEYS = new Set([
  'allowExternalPaths',
  'authorizedBricks',
  'tryBrickFn',
  'getAuthorizedBricksFn',
  'invariantScript',
  'repairFn',
  'assertFn',
  'nowMs',
  '__proto__',
  'constructor',
  'prototype'
]);

const UNTRUSTED_BOUNDARY_STRIPPED_ARG_KEYS = new Set([
  ...INTERNAL_STRIPPED_ARG_KEYS,
  'viewerOrgId'
]);

/**
 * Dispatch a tool call by name against a KruschStack instance.
 */
export async function dispatchStackTool(stack, toolName, rawArgs = {}, options = {}) {
  const inputArgs = rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs) ? rawArgs : {};
  const strippedSet =
    options.httpBoundary || options.mcpBoundary
      ? UNTRUSTED_BOUNDARY_STRIPPED_ARG_KEYS
      : INTERNAL_STRIPPED_ARG_KEYS;
  const cleanArgs = {};
  for (const key of Object.keys(inputArgs)) {
    if (strippedSet.has(key)) continue;
    Object.defineProperty(cleanArgs, key, {
      value: inputArgs[key],
      enumerable: true,
      writable: true,
      configurable: true
    });
  }
  let args = cleanArgs;

  if ((options.httpBoundary || options.mcpBoundary || options.allowExternalPaths !== true) && stack?.workspaceRoot) {
    try {
      const isGitTool = String(toolName || '').startsWith('krusch_git_');
      for (const pathKey of [
        'targetDir',
        'repoRoot',
        'repoDir',
        'targetRepoDir',
        'workspaceDir',
        'workspace_dir',
        'file_path'
      ]) {
        if (typeof cleanArgs[pathKey] === 'string' && cleanArgs[pathKey].trim()) {
          const checkedAbs = assertPathWithinWorkspace(
            cleanArgs[pathKey],
            stack.workspaceRoot,
            {
              allowReset:
                pathKey === 'targetDir' && toolName === 'hydrascope_ingest_directory'
            }
          );
          if (pathKey === 'file_path' && isGitTool && checkedAbs !== 'reset') {
            cleanArgs[pathKey] = path.relative(path.resolve(stack.workspaceRoot), checkedAbs) || '.';
          } else {
            cleanArgs[pathKey] = checkedAbs;
          }
        }
      }
      if (
        typeof cleanArgs.path === 'string' &&
        cleanArgs.path.trim() &&
        (String(toolName || '').startsWith('krusch_fs_') || isGitTool)
      ) {
        const checkedAbs = assertPathWithinWorkspace(cleanArgs.path, stack.workspaceRoot);
        cleanArgs.path = isGitTool
          ? path.relative(path.resolve(stack.workspaceRoot), checkedAbs) || '.'
          : checkedAbs;
      }
      if (Array.isArray(cleanArgs.paths)) {
        cleanArgs.paths = cleanArgs.paths.map((item) =>
          typeof item === 'string' && item.trim()
            ? assertPathWithinWorkspace(item, stack.workspaceRoot)
            : item
        );
      }
      if (
        cleanArgs.provenance &&
        typeof cleanArgs.provenance === 'object' &&
        !Array.isArray(cleanArgs.provenance) &&
        typeof cleanArgs.provenance.file === 'string' &&
        cleanArgs.provenance.file.trim()
      ) {
        assertPathWithinWorkspace(cleanArgs.provenance.file, stack.workspaceRoot);
      }
    } catch (pathErr) {
      return okEnvelope(
        toolName || 'krusch_call',
        pathErr.message,
        { error: pathErr.message, code: 'PATH_OUTSIDE_WORKSPACE' },
        false
      );
    }
    args = cleanArgs;
  }

  if (
    toolName === 'krusch_tool_search' ||
    toolName === 'krusch_tool_describe' ||
    toolName === 'krusch_tool_call'
  ) {
    const allowedSet = resolveAllowedComponentSet({
      profile: options.profile || stack.profile,
      components: options.components,
      server: options.server
    });
    const bridge =
      options.deferredBridge ||
      createStackDeferredBridge(
        resolveRawToolCatalog(allowedSet, options.includeExtended),
        {
          pinnedToolNames: resolveEffectivePinnedTools(options.server, options.pinnedToolNames),
          dispatcher: (innerToolName, innerArgs) =>
            dispatchStackTool(stack, innerToolName, innerArgs, {
              ...options,
              deferTools: false
            })
        }
      );

    if (toolName === 'krusch_tool_search') {
      return bridge.searchTools(args);
    }
    if (toolName === 'krusch_tool_describe') {
      return bridge.describeTool(args);
    }
    return bridge.callTool(args);
  }

  if (options.enforceProfile) {
    const allowedSet = resolveAllowedComponentSet({
      profile: options.profile || stack.profile,
      components: options.components,
      server: options.server
    });
    const allowedRaw = resolveRawToolCatalog(allowedSet, options.includeExtended);
    const allowedNames = options.deferTools
      ? new Set(
          createStackDeferredBridge(allowedRaw, {
            pinnedToolNames: resolveEffectivePinnedTools(options.server, options.pinnedToolNames)
          }).exposedTools.map((t) => t.name)
        )
      : new Set(allowedRaw.map((t) => t.name));

    if (!allowedNames.has(toolName)) {
      return okEnvelope(
        toolName || 'krusch_call',
        `Tool '${toolName}' is not enabled in the active profile`,
        {
          error: `MethodNotFound: Tool '${toolName}' is unknown or disabled in the active KruschStack profile`,
          code: 'TOOL_NOT_ENABLED'
        },
        false
      );
    }
  }

  const {
    context,
    git,
    fs,
    hydrascope,
    brickExchange,
    harness,
    groundedHarness,
    frontend,
    workspace,
    router,
    polyglotAudit
  } = stack.engines;
  switch (toolName) {
    // Tier 1: Context
    case 'krusch_context_retrieve':
      return context.retrieveAsync(args);
    case 'krusch_context_remember':
      return context.rememberAsync(args);
    case 'krusch_context_revise':
      return context.reviseAsync(args);
    case 'krusch_context_nudge':
      return context.nudge(args);
    case 'krusch_context_health':
      return context.health(args);

    // Tier 2A: Git
    case 'krusch_git_list_repos':
      return git.listRepos(args);
    case 'krusch_git_read_tree':
      return git.readTree(args);
    case 'krusch_git_read_blob':
      return git.readBlob(args);
    case 'krusch_git_search_symbols':
      return git.searchSymbols(args);
    case 'krusch_git_file_symbols':
      return git.fileSymbols(args);
    case 'krusch_git_dependency_graph':
      return git.dependencyGraph(args);
    case 'krusch_git_semantic_search':
      return git.semanticSearch(args);

    // Tier 2B: FS
    case 'krusch_fs_locate':
      return fs.locate(args);
    case 'krusch_fs_search':
      return fs.search(args);
    case 'krusch_fs_page_tree':
      return fs.pageTree(args);
    case 'krusch_fs_read_page':
      return fs.readPage(args);
    case 'krusch_fs_remember_on_page':
      return fs.rememberOnPage(args);
    case 'krusch_fs_sync':
      return fs.sync(args);

    // Tier 3: Harness
    case 'krusch_run':
      return harness.run(args);
    case 'krusch_task_status':
      return harness.taskStatus(args);
    case 'krusch_diff':
      return harness.diff(args);
    case 'krusch_apply_diff':
      return harness.applyDiff(args);
    case 'krusch_explain':
      return harness.explain(args);
    case 'krusch_reject':
      return harness.reject(args);
    case 'krusch_abort':
      return harness.abort(args);

    // Tier 4: Frontend
    case 'generate_color_palette':
      return frontend.generateColorPalette(args);
    case 'css_to_tailwind':
      return frontend.cssToTailwind(args);
    case 'query_design_rules':
      return frontend.queryDesignRules(args);
    case 'get_canonical_template':
      return frontend.getCanonicalTemplate(args);
    case 'list_canonical_templates':
      return frontend.listCanonicalTemplates(args);
    case 'generate_responsive_breakpoints':
      return frontend.generateResponsiveBreakpoints(args);

    // Tier 5: Workspace
    case 'get_agent_steering':
      return workspace.getAgentSteering(args);
    case 'search_drive_rag':
      return workspace.searchDriveRag(args);
    case 'read_drive_file':
      return workspace.readDriveFile(args);
    case 'write_drive_file':
      return workspace.writeDriveFile(args);
    case 'list_drive_workspace':
      return workspace.listDriveWorkspace(args);
    case 'get_workspace_status':
      return workspace.getWorkspaceStatus(args);

    // Tier 2C: HydraScope
    case 'hydrascope_traverse_context':
      return hydrascope.traverseContext(args);
    case 'hydrascope_check_answerable':
      return hydrascope.checkAnswerable(args);
    case 'hydrascope_compare_vector_vs_graph':
      return hydrascope.compareVectorVsGraph(args);
    case 'hydrascope_run_benchmark':
      return hydrascope.runBenchmark(args);
    case 'hydrascope_supersede_decision':
      return hydrascope.supersedeDecision(args);
    case 'hydrascope_ingest_directory':
      return hydrascope.ingestDirectory({ ...args, allowExternalPaths: false });

    // Tier 2D: Brick Exchange
    case 'brick_seal':
      return brickExchange.sealBrick(args);
    case 'brick_verify':
      return brickExchange.verifyBrick(args);
    case 'brick_suggest': {
      const inboxRes = brickExchange.listInbox({
        viewerId: args.viewerId || args.actorId || 'anonymous',
        viewerOrgId: args.viewerOrgId
      });
      const allBricks = inboxRes.data?.bricks || [];
      const filteredBricks = args.brickId
        ? allBricks.filter((b) => (b.brickId || b.blueprint?.id) === args.brickId)
        : allBricks;
      const repoScan =
        args.repoRoot && polyglotAudit
          ? polyglotAudit.auditRepository(args.repoRoot)
          : null;
      return okEnvelope(
        'brick_suggest',
        `Evaluated brick suggestions (${filteredBricks.length} authorized brick(s))`,
        {
          brickId: args.brickId || null,
          authorizedBricks: filteredBricks,
          repoCoverage: repoScan?.ok ? repoScan.data : null,
          repoCoverageError: repoScan && !repoScan.ok ? repoScan.error || repoScan.summary : null
        }
      );
    }
    case 'brick_share':
      return brickExchange.issueGrant({
        ...args,
        issuerId: args.issuerId || args.actorId
      });
    case 'brick_inbox': {
      const { authorizedBricks: _ignoredAuthorized, ...safeInboxArgs } = args;
      const inbox = brickExchange.listInbox(safeInboxArgs);
      if (
        inbox.ok &&
        (safeInboxArgs.targetStack ||
          safeInboxArgs.targetChannel ||
          (Array.isArray(safeInboxArgs.requiredPorts) && safeInboxArgs.requiredPorts.length > 0))
      ) {
        const composed = brickExchange.composeCrossStack({
          ...safeInboxArgs,
          authorizedBricks: inbox.data?.bricks || []
        });
        if (!composed.ok) {
          return composed;
        }
        return okEnvelope('brick_inbox', `${inbox.summary} | ${composed.summary}`, {
          ...inbox.data,
          composition: composed.data
        });
      }
      return inbox;
    }
    case 'brick_try_local':
      return brickExchange.tryBrick(args);
    case 'brick_adopt':
      return brickExchange.adoptBrick(args);
    case 'brick_revoke':
      return brickExchange.revokeGrant(args);
    case 'brick_blast_radius':
      return brickExchange.analyzeBlastRadius({
        ...args,
        repoDir: args.repoDir ?? args.repoRoot,
        changedFiles: args.changedFiles ?? args.targetFiles,
        protectedFiles: args.protectedFiles ?? args.policyFloorFiles
      });
    case 'brick_plan_fanout':
      return brickExchange.planFanOut({
        ...args,
        repoDir: args.repoDir ?? args.repoRoot,
        protectedFiles: args.protectedFiles ?? args.policyFloorFiles
      });

    // Tier 3B: Grounded Harness
    case 'krusch_ground_workspace':
      return groundedHarness.groundWorkspace(args);
    case 'krusch_resolve_scale_profile':
      return groundedHarness.resolveScale(args);
    case 'krusch_grounded_session_start':
      return groundedHarness.startSession(args);
    case 'krusch_grounded_intercept':
      return groundedHarness.interceptToolCall(args);
    case 'krusch_grounded_outcome':
      return groundedHarness.recordToolOutcome(args);
    case 'krusch_grounded_verify_stop':
      return groundedHarness.verifyStop(args);
    case 'krusch_grounded_summary':
      return groundedHarness.sessionSummary(args);

    // Router & Stack Status
    case 'krusch_route_task':
      return router.routeTask(args);
    case 'krusch_stack_status':
      return router.getStackStatus({ engines: stack.engines, db: stack.db });

    default:
      throw new McpError(ErrorCode.MethodNotFound, `Unknown KruschStack tool: ${toolName}`);
  }
}

/**
 * Create a configured MCP Server instance for KruschStack.
 */
export function createMcpServer(options = {}) {
  const stack = options.stack || createKruschStack(options);
  const effectiveProfile = options.profile || stack.profile;
  const deferTools = Boolean(
    options.deferTools ??
      (process.env.KRUSCH_STACK_DEFER_TOOLS === '1' ||
        process.env.KRUSCH_STACK_DEFER_TOOLS === 'true')
  );
  const allowedSet = resolveAllowedComponentSet({
    profile: effectiveProfile,
    components: options.components,
    server: options.server
  });
  const rawAllowed = resolveRawToolCatalog(allowedSet, options.includeExtended);
  const deferredBridge = deferTools
    ? createStackDeferredBridge(rawAllowed, {
        pinnedToolNames: resolveEffectivePinnedTools(options.server, options.pinnedToolNames),
        dispatcher: (innerToolName, innerArgs) =>
          dispatchStackTool(stack, innerToolName, innerArgs, {
            mcpBoundary: true,
            profile: effectiveProfile,
            components: options.components,
            server: options.server,
            includeExtended: options.includeExtended
          })
      })
    : null;
  const tools = deferTools
    ? [...deferredBridge.exposedTools]
    : rawAllowed.map(({ component: _c, ...toolDef }) => toolDef);
  const allowedNames = new Set(tools.map((t) => t.name));

  const mcpServer = new Server(
    {
      name: options.server || 'krusch-stack',
      version: VERSION
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  mcpServer.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const args = request.params.arguments || {};

    if (!allowedNames.has(toolName)) {
      throw new McpError(
        ErrorCode.MethodNotFound,
        `Tool '${toolName}' is not enabled in the active profile`
      );
    }

    try {
      const result = await dispatchStackTool(stack, toolName, args, {
        mcpBoundary: true,
        deferredBridge,
        profile: effectiveProfile,
        components: options.components,
        server: options.server,
        includeExtended: options.includeExtended
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ],
        isError: !result.ok
      };
    } catch (err) {
      if (err instanceof McpError) throw err;
      const errEnvelope = okEnvelope(toolName, `Error: ${err.message}`, { error: err.message }, false);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(errEnvelope, null, 2)
          }
        ],
        isError: true
      };
    }
  });

  return { mcpServer, stack, tools, deferredBridge };
}

/**
 * Start the KruschStack MCP server over stdio.
 */
export async function runMcpServer(options = {}) {
  const { mcpServer } = createMcpServer(options);
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
  return mcpServer;
}
