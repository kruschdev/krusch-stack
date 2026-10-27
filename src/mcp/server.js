/**
 * @module mcp/server
 * Unified Model Context Protocol (MCP) Gateway for KruschStack.
 * Enforces INV-STACK-02 (universal envelope), INV-STACK-03 (4-boolean MCP tool annotations on every tool),
 * and INV-STACK-05 (profile & component filtering: --profile core|full, --components <csv>, --server <name>).
 */

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
  'krusch-harness': 'harness',
  'krusch-frontend-mcp': 'frontend',
  'g-krusch': 'workspace',
  'krusch-cascade-router': 'router'
};

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
        reason: { type: 'string', description: 'Reason for revision or revocation' }
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
        code: { type: 'string', description: 'Code or unified diff to audit' }
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
        harmony: { type: 'string', enum: ['complementary', 'analogous', 'triadic', 'monochromatic'], default: 'complementary' }
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
    title: 'Get Canonical HTML/SVG Component Template',
    description: 'Retrieve a canonical HTML/SVG template (article-shell, footer-deadbolt, cyber-grid, deadbolt-svg, nav-back).',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    inputSchema: {
      type: 'object',
      properties: {
        template_id: { type: 'string', enum: ['article-shell', 'footer-deadbolt', 'cyber-grid', 'deadbolt-svg', 'nav-back'] }
      },
      required: ['template_id']
    }
  }),
  defineTool({
    name: 'list_canonical_templates',
    component: 'frontend',
    title: 'List Canonical Frontend Templates',
    description: 'List all available canonical HTML/SVG component templates.',
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
  // Tier 5: g-krusch Workspace Hub (6 tools)
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
    description: 'Return aggregate readiness and telemetry across all 7 KruschStack engines.',
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

function resolveAllowedComponentSet({ profile = 'full', components, server } = {}) {
  if (server && SERVER_TO_COMPONENT[server]) {
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
  return profile === 'core' ? CORE_COMPONENTS : FULL_COMPONENTS;
}

/**
 * Filter tools by profile ('core' | 'full'), explicit component list, or single modular server name.
 * When `deferTools: true` is set, collapses the filtered catalog into pinned core tools + 3 BM25 bridge meta-tools.
 */
export function getStackTools({
  profile = 'full',
  components,
  server,
  deferTools = false,
  pinnedToolNames
} = {}) {
  const allowed = resolveAllowedComponentSet({ profile, components, server });
  const rawAllowed = ALL_STACK_TOOLS.filter((t) => allowed.has(t.component));
  if (deferTools) {
    const bridge = createStackDeferredBridge(rawAllowed, { pinnedToolNames });
    return [...bridge.exposedTools];
  }
  return rawAllowed.map(({ component: _c, ...toolDef }) => toolDef);
}

/**
 * Dispatch a tool call by name against a KruschStack instance.
 */
export async function dispatchStackTool(stack, toolName, args = {}, options = {}) {
  if (
    toolName === 'krusch_tool_search' ||
    toolName === 'krusch_tool_describe' ||
    toolName === 'krusch_tool_call'
  ) {
    const bridge =
      options.deferredBridge ||
      createStackDeferredBridge(
        ALL_STACK_TOOLS.filter((t) =>
          resolveAllowedComponentSet({
            profile: options.profile || stack.profile,
            components: options.components,
            server: options.server
          }).has(t.component)
        ),
        {
          pinnedToolNames: options.pinnedToolNames,
          dispatcher: (innerToolName, innerArgs) => dispatchStackTool(stack, innerToolName, innerArgs)
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

  const { context, git, fs, harness, frontend, workspace, router } = stack.engines;
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

    // Router & Stack Status
    case 'krusch_route_task':
      return router.routeTask(args);
    case 'krusch_stack_status':
      return router.getStackStatus({ engines: stack.engines });

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
  const rawAllowed = ALL_STACK_TOOLS.filter((t) =>
    resolveAllowedComponentSet({
      profile: effectiveProfile,
      components: options.components,
      server: options.server
    }).has(t.component)
  );
  const deferredBridge = deferTools
    ? createStackDeferredBridge(rawAllowed, {
        pinnedToolNames: options.pinnedToolNames,
        dispatcher: (innerToolName, innerArgs) => dispatchStackTool(stack, innerToolName, innerArgs)
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
        deferredBridge,
        profile: effectiveProfile,
        components: options.components,
        server: options.server
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
