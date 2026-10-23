# KruschStack (`krusch-stack`)

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Node.js >= 22](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen.svg)](https://nodejs.org)
[![MCP Compatible](https://img.shields.io/badge/MCP-39%20Tools-blueviolet.svg)](https://modelcontextprotocol.io)

**The Unified Sovereign AI & Coding Agent Stack.**

`krusch-stack` combines all 7 pillars of the Krusch developer ecosystem into a **single zero-setup `npx` command** (backed by Node 22 native `node:sqlite`) and a **one-command `docker compose up -d` stack** (backed by `pgvector/pgvector:pg16`).

Instead of installing, configuring, and wiring 7 separate repositories across Claude Code, Cursor, Windsurf, or Antigravity, one command installs the entire stack.

---

## ⚡ Quick Start (Under 30 Seconds)

### Option A: Zero-Docker Local Install (`npx`)

```bash
# 1. Auto-configure Claude Code (.mcp.json), Cursor, Windsurf & Antigravity + initialize SQLite
npx krusch-stack init

# 2. Verify all 7 stack pillars
npx krusch-stack doctor
```

### Option B: Full Docker Stack (PostgreSQL 16 + `pgvector` + Gateway)

```bash
git clone https://github.com/kruschdev/krusch-stack.git
cd krusch-stack
docker compose up -d
curl http://127.0.0.1:3780/health
```

---

## 🏗️ What's Inside `krusch-stack` (The 7 Unified Pillars)

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        KRUSCH-STACK UNIFIED GATEWAY                        │
│               `npx krusch-stack mcp`  (39 Annotated MCP Tools)             │
├──────────────────────┬───────────────────────────┬─────────────────────────┤
│ 1. WORKING MEMORY    │ 2A. CODEBASE AST & GIT    │ 2B. OS PAGE MEMORY      │
│ krusch-context-mcp   │ krusch-git                │ krusch-fs               │
│ • retrieve / remember│ • search_symbols          │ • locate / search       │
│ • revise / nudge     │ • dependency_graph        │ • page_tree / read_page │
│ • INV-12 span drift  │ • read_tree / read_blob   │ • remember_on_page      │
├──────────────────────┼───────────────────────────┼─────────────────────────┤
│ 3. 2PC HARNESS       │ 4. FRONTEND DESIGN MCP    │ 5. WORKSPACE HUB        │
│ krusch-harness       │ krusch-frontend-mcp       │ g-krusch                │
│ • run (stages diff)  │ • generate_color_palette  │ • get_agent_steering    │
│ • apply_diff (2PC)   │ • css_to_tailwind         │ • search_drive_rag      │
│ • explain / reject   │ • canonical_templates     │ • write (.gdoc/.slides) │
├──────────────────────┴───────────────────────────┴─────────────────────────┤
│ 6. COGNITIVE CASCADE ROUTER (`krusch-cascade-router`)                      │
│ • <25µs L1 heuristic fast-path -> L2 Local MoE -> L2.5 120B -> L3 Referee  │
└────────────────────────────────────────────────────────────────────────────┘
```

| Pillar | Standalone Repo | Tools Included | Storage Default |
|--------|-----------------|----------------|-----------------|
| **Tier 1: Working Memory** | [`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp) | `krusch_context_retrieve`, `krusch_context_remember`, `krusch_context_revise`, `krusch_context_nudge`, `krusch_context_health` | `node:sqlite` + PG |
| **Tier 2A: Git & AST Graph** | [`krusch-git`](https://github.com/kruschdev/krusch-git) | `krusch_git_list_repos`, `krusch_git_read_tree`, `krusch_git_read_blob`, `krusch_git_search_symbols`, `krusch_git_file_symbols`, `krusch_git_dependency_graph`, `krusch_git_semantic_search` | `node:sqlite` + PG |
| **Tier 2B: OS Page Memory** | [`krusch-fs-mcp`](https://github.com/kruschdev/krusch-fs-mcp) | `krusch_fs_locate`, `krusch_fs_search`, `krusch_fs_page_tree`, `krusch_fs_read_page`, `krusch_fs_remember_on_page`, `krusch_fs_sync` | `node:sqlite` + PG |
| **Tier 3: 2PC Staged Harness** | [`krusch`](https://github.com/kruschdev/krusch) | `krusch_run`, `krusch_task_status`, `krusch_diff`, `krusch_apply_diff`, `krusch_explain`, `krusch_reject`, `krusch_abort` | `node:sqlite` + PG |
| **Tier 4: Frontend Design** | [`krusch-frontend-mcp`](https://github.com/kruschdev/krusch-frontend-mcp) | `generate_color_palette`, `css_to_tailwind`, `query_design_rules`, `get_canonical_template`, `list_canonical_templates`, `generate_responsive_breakpoints` | `node:sqlite` |
| **Tier 5: Workspace Hub** | [`G-krusch`](https://github.com/kruschdev/G-krusch) | `get_agent_steering`, `search_drive_rag`, `read_drive_file`, `write_drive_file`, `list_drive_workspace`, `get_workspace_status` | `node:sqlite` |
| **Router & Diagnostics** | [`krusch-cascade-router`](https://github.com/kruschdev/krusch-cascade-router) | `krusch_route_task`, `krusch_stack_status` | In-Memory `<25µs` |

---

## 🛠️ IDE Configuration Modes (`unified` vs `modular`)

### 1. Unified Single-Server Mode (Default)
Registers **one** MCP server (`krusch-stack`) that exposes all 39 tools (or 27 core coding tools with `--profile core`):

```json
{
  "mcpServers": {
    "krusch-stack": {
      "command": "npx",
      "args": ["-y", "krusch-stack", "mcp", "--profile", "full"]
    }
  }
}
```

### 2. Modular Multi-Server Mode (`npx krusch-stack init --modular`)
Registers each pillar as its own dedicated MCP entry (`krusch-context-mcp`, `krusch-git`, `krusch-fs`, `krusch-harness`, `krusch-frontend-mcp`, `g-krusch`), all powered by the single `krusch-stack` installation:

```bash
npx krusch-stack init --modular --profile full
```

### 3. Custom Component Subset
Pick only the pillars you want:

```bash
npx krusch-stack mcp --components context,git,harness
```

---

## 🧪 Programmatic Node.js API

```javascript
import { createKruschStack } from 'krusch-stack';

const stack = createKruschStack({ ephemeral: true });

// 1. Record an architectural invariant (Tier 1)
stack.context.remember({
  category: 'invariant',
  content: 'Never use eval() in production modules.'
});

// 2. Stage a code change through the 2PC Harness (Tier 3)
const staged = stack.harness.run({
  goal: 'Add greeting helper',
  edits: [{ file_path: 'src/greet.js', content: 'export const greet = (n) => `Hello ${n}`;\n' }]
});

// 3. Route a task in <25µs (Cascade Router)
const route = stack.router.routeTask({
  prompt: 'Architect a distributed two-phase commit state machine'
});
```

---

## 🤗 Open-Weights Models & SFT Dataset (Trained Through `krusch-stack`)

We use `krusch-stack` to generate AST-grounded 11-phase code audit trajectories and unit-test-verified (`npm test` / `pytest`, exit `0`) bug remediations, then distill them back into open-weights QLoRA adapters for the `L2` and `L2.5` Cascade Router tiers:

| Resource | Hugging Face Hub | Cascade Role / Base Model |
|----------|------------------|---------------------------|
| **SFT Dataset (`17,899` rows)** | [`krush420/sovereign-code-audit-sft`](https://huggingface.co/datasets/krush420/sovereign-code-audit-sft) | 3 Splits: `argon_golden_remediations` (`401`), `elitist_120b_teacher` (`2,208`), `code_audit_11phase_sft` (`15,290`) |
| **30B Student QLoRA (`L2`)** | [`krush420/qwen3-coder-30b-sre-lora`](https://huggingface.co/krush420/qwen3-coder-30b-sre-lora) | [`Qwen/Qwen3-Coder-30B-A3B-Instruct`](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct) (`30.5B` total / `3.3B` active MoE) |
| **120B Teacher QLoRA (`L2.5`)** | [`krush420/gpt-oss-120b-sre-lora`](https://huggingface.co/krush420/gpt-oss-120b-sre-lora) | [`openai/gpt-oss-120b`](https://huggingface.co/openai/gpt-oss-120b) (`116.8B` total / `5.1B` active MXFP4 MoE) |

---

## 📜 License

MIT © Kevin Ruschman (`kruschdev`)

