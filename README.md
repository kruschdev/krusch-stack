# KruschStack (`krusch-stack`)

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Node.js >= 22](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen.svg)](https://nodejs.org)
[![MCP Compatible](https://img.shields.io/badge/MCP-39%20Tools-blueviolet.svg)](https://modelcontextprotocol.io)
[![DolphinBench #1 Overall](https://img.shields.io/badge/DolphinBench-%231%20Overall%2091.17%25%20(%2424.54)-00e5ff.svg)](https://krusch.dev/articles/return-on-memory-dolphinbench)
[![#1 Open-Weights ($0.00)](https://img.shields.io/badge/DolphinBench%20Open--Weights-%231%20Gemma%204%2031B%2057.33%25%20(%240.00)-brightgreen.svg)](https://huggingface.co/krush420/gemma4-31b-sre-lora)

**The Unified Sovereign AI & Coding Agent Stack.**

`krusch-stack` combines all 7 pillars of the Krusch developer ecosystem into a **single zero-setup `npx` command** (backed by Node 22 native `node:sqlite`) and a **one-command `docker compose up -d` stack** (backed by `pgvector/pgvector:pg16`).

Instead of installing, configuring, and wiring 7 separate repositories across Claude Code, Cursor, Windsurf, or Antigravity, one command installs the entire stack.

> 🏆 **Official `DolphinBench` (`27` Runs / `16,200` Official `gpt-5.6-sol` Traces Across `6` Model Families, `13,539` Sessions)**: Pairing `Gemini 4 Argon (Low Thinking)` with my byte-identical `0o444` frozen `$0.00` `SovereignMemoryStore` (`node:sqlite` Zero-LLM Raw-RAG + 4-Way RRF) achieves **`#1 Overall` at `91.17%` (`547/600` @ `$24.54`, `35.38s` median; `89.17%` [`535/600`] @ `$23.92` + Grounded Harness, `Argon Low Oracle@2 = 94.00%` [`564/600`])**—**`+20.50 pp` (`+123` tasks)** above Official `#1` `Hermes + GPT 5.6 Luna + Mem0` (`70.67%` @ `$96.21`) at **`~3.9x` (`~4x`) lower cost** (alongside model-matched **`GPT 5.6 Luna (High) + Grounded` `81.50%` [`489/600` @ `$1.35`, `30.03s` = `1.57x` faster than `Luna High Base` `81.33%`, `+10.83 pp` & `71.1x` cheaper than `#1` `Mem0`]** & **`Luna (Low)` `76.67%` [`460/600` @ `$1.10`]**, `Argon Medium` `89.17%` [`535/600` @ `$24.57`], and Turn-0 Briefing-Only `78.00%`/`79.17%` @ `$15.76`/`$16.91`, $\Delta\Delta = +3.17\text{ pp}, p = 0.0320$; **`97.83%` [`587/600`] `Oracle@27`**, **`4.19x` `LBF=4+` multiplier**; Queued UUIDs `c047b063-822c-49fb-8b36-27c3763d6ca7` & `29389157-b01b-42b5-8193-17d9a496f580`). At **`$0.00` total cost**, [**`krush420/gemma4-31b-sre-lora`**](https://huggingface.co/krush420/gemma4-31b-sre-lora) (`Google Gemma 4 31B` Wave-6 QLoRA + BF16 Ref-Anchored DPO) + `krusch-grounded-harness` (`INV-STACK-11`) achieves **`#1 Open-Weights` at `57.33%` (`344/600`: `Morgan 149`, `Alex 103`, `Riley 92`; `+3.17 pp` / `+19` tasks over `54.17%` Stock & `+0.67 pp` over `56.67%` [`340/600`] Stock + Grounded)** alongside **`54.83%` (`329/600` Wave-5 Std.)**, **`54.17%` (`325/600` Thinking ON Stock, Queued UUID `288671ad-afe0-40a3-93af-b834c9bbd306`)**, **`53.67%` (`322/600` Wave-4 Std.)**, & **`52.00%` (`312/600` Thinking OFF, `Gemma 4 Oracle@6 = 71.83%` [`431/600`])**, **beating ALL `8` non-`GPT-5.6-Luna` commercial cloud stacks** (`MiniMax M3 + Mem0` `47.83%` @ `$148.02` through `Claude Sonnet 5 + Mem0` `32.33%` @ `$1,830.57`), while `30B Wave-4 + Grounded` reaches **`43.00%` (`258/600`, `#1 Qwen/MoE`, `Wave-4 Oracle@3 = 58.50%`, `30B Oracle@5 = 61.17%`)**, full-600 `30B Wave-4 + 2PC` cuts duplicate MCP calls **`-95.2%` (`42 -> 2`, `Oracle@2 = 50.33%`)**, and `$0.00` open-weights **`Oracle@17` reaches `83.17%` (`499/600`, `+12.50 pp` above `#1` `Mem0`)** (`8` queued archives on `dolphinbench.ai`, `27/27` `submission.validate` passed). Read [**Paper #27 — Return on Memory**](https://krusch.dev/articles/return-on-memory-dolphinbench) ([**PDF**](https://krusch.dev/papers/return-on-memory-dolphinbench.pdf)) and [**Paper #26 — What DolphinBench Taught Me About Local AI**](https://krusch.dev/articles/what-dolphinbench-taught-me-about-local-ai).

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
| **Tier 3A: 2PC Staged Harness** | [`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness) | `krusch_run`, `krusch_task_status`, `krusch_diff`, `krusch_apply_diff`, `krusch_explain`, `krusch_reject`, `krusch_abort` *(+ `stack.actionHarness` & `POST /action-harness/*` `INV-STACK-10`)* | `node:sqlite` + PG |
| **Tier 3B: Grounded Harness** | [`grounded-harness`](https://github.com/kruschdev/grounded-harness) | `stack.groundedHarness` (`krusch-stack/grounded-harness`) & `POST /grounded-harness/*` (`INV-STACK-11`: zero-LLM Turn-0 schema/hazard grounding, scale-aware tiers, memoization & defect-only stop gate; `39` MCP tools preserved) | `node:sqlite` + PG |
| **Tier 4: Frontend Design** | [`krusch-frontend-mcp`](https://github.com/kruschdev/krusch-frontend-mcp) | `generate_color_palette`, `css_to_tailwind`, `query_design_rules`, `get_canonical_template`, `list_canonical_templates`, `generate_responsive_breakpoints` | `node:sqlite` |
| **Tier 5: Workspace Hub** | [`G-krusch`](https://github.com/kruschdev/G-krusch) | `get_agent_steering`, `search_drive_rag`, `read_drive_file`, `write_drive_file`, `list_drive_workspace`, `get_workspace_status` | `node:sqlite` |
| **Router & Diagnostics** | [`krusch-cascade-router`](https://github.com/kruschdev/krusch-cascade-router) | `krusch_route_task`, `krusch_stack_status` | In-Memory `<25µs` |
| **Companion Runtime Bricks** | [`toolkit` (`@krusch/toolkit` & `krusch_toolkit`)](https://github.com/kruschdev/toolkit) | 39 Node/TS/Workers & Python Lego bricks + `krusch-lego` CLI (`16` `<1ms` Slop-Breaker detectors) backing `get_canonical_template` (`lego-*`) & `INV-LEGO-01..35` | App Runtime (ESM / Py 3.11+) |

### 📊 Verified Third-Party Benchmarks Across Pillars

> 📄 **Full Cross-Stack Comparison, Honest Gaps & Reproduction Gates**: Read **[`BENCHMARKS.md`](./BENCHMARKS.md)** for the complete comparison against open-source wrapper stacks and commercial cloud stacks (`past.dev`, `Mem0`, `Honcho`, `NotDiamond`, `Martian`, OpenAI + Cohere) across **`333,000+` queries and multi-turn episodes**, my **`90/90` SHA-256 clean-room verification gates** across `13` external suites (`49` Hugging Face audit logs = `48` raw JSON + `1` live PR #169 receipt bundle), open/queued upstream submissions (`DolphinBench` `8` queued across `27` validated runs / `16,200` traces, `RouterArena` PR #169, `withmartian/routerbench`), and where frontier cloud models still lead.

| Stack Pillar | Official External Benchmark | Verified Result (Sovereign Hybrid & Hermetic Open-Weights) |
| :--- | :--- | :--- |
| **Security & Policy Floor** | **ETH SpyLab AgentDojo v1.2.2 (`1,046` Eps, `949` Attacks)** | **`0.00%` Targeted ASR (`0/949`, `100%` Defense)** vs. `19.28%` raw ASR (`57.14%` `slack`, `52.78%` `banking`) · **`69.07%` Benign** (Spotlighting) & **`83` hardline floor blocks** |
| **Tier 1 (`krusch-context-mcp`)** | **ICLR 2026 BEAM (`100K`–`10M` tok, `2,000/2,000` Qs)** | **`92.58%` (`100K`) & `93.00%` (`10M` IE) Recall** (`78.67%` 4-split weighted); zero E2E drop `100K`→`1M` (`72.86%`); beats cloud `past.dev` on Contradiction Resolution (`4/4` splits) & `10M` Multi-Session Reasoning |
| **Agentic Memory & Execution** | **Official DolphinBench (`600/600`, `27` Runs / `16,200` Traces, `13,539` Sessions)** | **`#1 Overall` `91.17%` (`547/600` @ `$24.54`, `35.38s`)** `Gemini 4 Argon (Low)` (`89.17%` [`535/600` @ `$23.92`] `+ Grounded`, `Argon Low Oracle@2 = 94.00%` [`564/600`]) + `89.17%` (`535/600` @ `$24.57`) `Medium` + model-matched **`GPT 5.6 Luna (High) + Grounded Harness` `81.50%` (`489/600` @ `$1.35`, `30.03s` median = `1.57x` faster than `Luna High Base` `81.33%` / `47.02s`, `+10.83 pp` & `71.1x` cheaper than `#1` `Mem0`, `+4.50 pp` `Riley` over `2PC`)** & **`Luna (Low)` `76.67%` (`460/600` @ `$1.10`)** over byte-identical `0o444` frozen `$0.00` `SovereignMemoryStore` (**`+20.50 pp` / `+123` tasks** > `#1` `Hermes + GPT 5.6 Luna + Mem0` `70.67%` @ `$96.21`, **`~3.9x` lower cost**; `78.00%`/`79.17%` Briefing-Only @ `$15.76`/`$16.91`, $\Delta\Delta = +3.17\text{ pp}, p = 0.0320$; **`97.83%` [`587/600`] `Oracle@27`**, **`4.19x` `LBF=4+`**; UUID `c047b063-822c-49fb-8b36-27c3763d6ca7`) · **`#1 Open-Weights` `57.33%` (`344/600` @ `$0.00`: `Morgan 149`, `Alex 103`, `Riley 92`; `+3.17 pp` / `+19` tasks over Stock) [`krush420/gemma4-31b-sre-lora`](https://huggingface.co/krush420/gemma4-31b-sre-lora) + Grounded, `56.67%` (`340/600` Stock + Grounded, `+2.50 pp` / `+5.50 pp` `Riley`, `15` spin loops blocked), `54.83%` (`329/600` Wave-5 Std.) & `54.17%` (`325/600` Stock, UUID `288671ad-afe0-40a3-93af-b834c9bbd306`) `Google Gemma 4 31B`** (`53.67%` Wave-4 Std., `52.00%` Thinking OFF, `Gemma 4 Oracle@6 = 71.83%` [`431/600`], **`Oracle@17 = 83.17%` [`499/600`]**), **beating ALL `8` non-`GPT-5.6-Luna` cloud stacks** (`MiniMax M3 + Mem0` `47.83%` @ `$148.02` to `Sonnet 5 + Mem0` `32.33%` @ `$1,830.57`), plus **`43.00%` (`258/600`) `30B Wave-4 + Grounded` (`#1 Qwen/MoE`, `Wave-4 Oracle@3 = 58.50%`, `30B Oracle@5 = 61.17%`)**, `42.67%` `30B Wave-4` (`42.00%` `30B Wave-4 + 2PC` cutting dup MCP calls `-95.2%` [`42 -> 2`], `Oracle@2 = 50.33%`), `39.50%` `120B Wave-4`, `38.50%` `80B` & `30B Wave-6`, `35.33%` `Qwen2.5-Coder-32B` (`+22.00 pp` vs. `Gemma 4 Wave-6 + Grounded`), `34.50%` `Hermes-4-14B`, `18.33%` `8B Wave-4` (`15.7x` lift) (`8` queued on `dolphinbench.ai` across `6` families; [Paper #27](https://krusch.dev/articles/return-on-memory-dolphinbench) · [PDF](https://krusch.dev/papers/return-on-memory-dolphinbench.pdf) · [Paper #26](https://krusch.dev/articles/what-dolphinbench-taught-me-about-local-ai)) |
| **Tier 2A (`krusch-git`)** | **ACL 2025 CoIR (`2.39M` Docs, `162,216` Qs) & RepoBench-R (`47,998` Qs)** | **`56.40%` `#1` CoIR 10-Task `NDCG@10` (`73.88%` `R@10` > `Voyage-Code-002` `56.26%`)** · **RepoBench-R `19.12%` Macro `Acc@1` / `68.58%` `Acc@5`** (beats `CodeBERT` & `UniXcoder`) |
| **Tier 2B / Evidentiary (`krusch-nexus`)** | **LegalBench-RAG (`714` Docs, `6,889` Full / `776` Mini Qs)** | **`26.74%` Full Macro F1 (`k=1`) & `25.81%` F1 / `44.72%` Recall (`k=2`)** (`47.71%` R@6; `+128.5%` / `2.29x` F1 vs. fixed dense; `33.95%` `MAUD` R@2 > OpenAI `3-large` + Cohere R@64 `28.28%`) |
| **Tier 3A (`krusch-coding-harness` & `INV-STACK-10`)** | **Aider Polyglot (`225/225`), BIRD-SQL (`500/500`) & 2PC Action Harness** | **Polyglot `19.56%` → `51.56%` `Pass@2` (`2.64x`, ties `Claude 3.5 Sonnet`)** · **BIRD-SQL `26.00%` → `40.20%` EX (`1.55x`, `100%` valid SQL)** · **2PC Action Harness (`-95.2%` dup MCP calls `42→2` & `50.33%` `Oracle@2` across `600` tasks; `-100%` `10→0` & `+20.0 pp` mech on slice @ `$0.00`)** |
| **Tier 3B (`grounded-harness` & `INV-STACK-11`)** | **Adyen `DABstep` (`120` Eps) & `DolphinBench` (`3,600` Grounded Traces)** | **`90.0%` (`9/10`: `100%` easy, `85.7%` hard) on `gemini-4-argon` @ `$0.81`** (**`-74.5%` cost** vs. `$3.19` ungrounded & **`2.54x` speedup**, `5.1` turns) · **`40.0%` on `gemma4:31b` @ `$0.00`** (`+20.0 pp` vs. ungrounded) · **`DolphinBench` `#1 Open-Weights` `57.33%` (`344/600` @ `$0.00` `gemma4-31b-sre-lora`) & `56.67%` (`340/600` Stock + Grounded), `43.00%` (`258/600` `30B Wave-4 + Grounded`), `81.50%` (`489/600` @ `$1.35`, `1.57x` faster `Luna High`), & `89.17%` (`535/600` @ `$23.92`, `Argon Low Oracle@2 = 94.00%`)** |
| **Deferred MCP (`--defer-tools`)** | **UC Berkeley BFCL v3 Live (`2,251/2,251` Qs, `6/6` Splits in `64`-Tool Hub)** | **`59.88%` → `66.28%` Micro (`+144` Qs) & `84.69%` Irrelevance (`+17.46 pp`)** with **`-80.67%` fewer schema tokens** (`29` schema repairs healed) |
| **Router (`krusch-cascade-router`)** | **Martian RouterBench (`73K`), ACL 2026 LLMRouterBench (`12.5K`) & RouterArena (`8.4K`)** | **`#1` RouterBench ID/OOD `AIQ` (`0.7488` `0-shot` & `0.7695` `5-shot`, `-72.63%` cost @ `98%` `GPT-4`, `#1` OOD `0.7268` / `0.7455` > `ZeroRouter`)** · **`#1` LLMRouterBench Pareto (`0.4269`, `-83.95%` cost, `25.25%` `ARC-AGI`)** · **`0.7263` (`72.63`, `#13 / 34`) RouterArena Official CI (`74.44%` Acc @ `$0.3802/1K`, `91.43%` rob., `0` abnormal, `8,400/8,400` OpenRouter receipts; beats `Azure-Model-Router` `0.7037` [`2.0x` cheaper], `GPT-5` `0.6432` [`26.4x` cheaper], `OrcaRouter-Adaptive` `0.7248`, `Martian` `0.5756` [`12.7x` cheaper], `NotDiamond` `0.5729` [`10.8x` cheaper] & `RouteLLM` `0.4807`, [PR #169](https://github.com/RouteWorks/RouterArena/pull/169#issuecomment-6585010769) open)** ([audit logs](https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks)) |

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

// 4. Production Resilience Engine (krusch-stack/resilience & 127.0.0.1:3780/resilience/*)
// Strict pre-flight context budgeting, $0.50 cost kill-switch, 100-trajectory Golden DAG gate,
// 5% non-blocking shadow trajectory diffing, and 72h Slack HMAC-SHA256 HITL leases:
const budget = stack.resilience.assembleContextBudget({
  systemPrompt: 'Enforce 2PC invariants.',
  query: 'Update auth middleware',
  maxContextTokens: 16384,
  outputReserveTokens: 2048
});
const dagCheck = stack.resilience.verifyTrajectoryDag({
  steps: [{ tool: 'read_file', ok: true }, { tool: 'run_tests', ok: true }, { tool: 'apply_staged_diff', ok: true }],
  goldenDag: { requirePassingPrerequisite: [['run_tests', 'apply_staged_diff']] }
});

// 5. Generalized 2PC Tool-Action Harness (INV-STACK-10: stack.actionHarness & POST /action-harness/*)
// Extends Tier 3 2PC governance to external RPC/MCP tool trajectories (ALL_STACK_TOOLS.length === 39 unchanged!):
// blocks duplicate read spin-loops (BLOCK_SPIN_LOOP), blocks duplicate writes (BLOCK_DUPLICATE_WRITE),
// stages mutations after placeholder/ISO-date/secret/nudge checks, and gates premature zero-action stops.
stack.actionHarness.startSession({
  session_id: 'sess-001',
  persona: 'morgan',
  goal: 'Send the Q4 launch update email to the engineering channel',
  anchor_date: '2026-11-01',
  enforce_context_nudge: true
});
const intercepted = stack.actionHarness.interceptToolCall({
  session_id: 'sess-001',
  step: 1,
  tool_name: 'mcp__email__send_message',
  args: { to: 'eng@example.com', subject: 'Q4 Launch Update', body: 'All gates green.' },
  is_mutating: true
});
if (intercepted.data.allowed) {
  stack.actionHarness.recordToolOutcome({
    session_id: 'sess-001',
    event_id: intercepted.data.event_id,
    status: 'COMMITTED',
    result_preview: 'Message sent (id=msg_42)'
  });
}
const stopGate = stack.actionHarness.verifyStop({
  session_id: 'sess-001',
  step: 2,
  final_text: 'Sent the Q4 launch update email to eng@example.com.'
});
const summary = stack.actionHarness.sessionSummary({ session_id: 'sess-001' });

// 6. Turn-0 Grounded, Scale-Aware, Defect-Only Harness (INV-STACK-11: stack.groundedHarness & POST /grounded-harness/*)
// Zero-LLM Turn-0 schema/hazard introspection (CSV "NA" keep_default_na=False, JSON null/[], SQLite DDL),
// monotonic scale-aware profiles (SMALL_MODEL / MID_MODEL / FRONTIER_REASONING), memoization, and defect-only stop gate:
const grounded = stack.groundedHarness.groundAndStartSession({
  session_id: 'gh-001',
  goal: 'Compute North America merchant settlement fee rate',
  model: 'gemini-4-argon'
});
const ghStop = stack.groundedHarness.verifyStop({
  session_id: 'gh-001',
  candidate_answer: '0.015',
  expect_non_empty_answer: true
});
```

### 🌐 HTTP Gateway Action-Harness & Grounded-Harness Routes (`npx krusch-stack serve`, default `:3780`)

When running `npx krusch-stack serve` (or via Docker Compose on `http://127.0.0.1:3780`), both the Generalized `2PC` Tool-Action Harness (`INV-STACK-10`) and the Turn-0 Grounded Harness (`INV-STACK-11`) are exposed over HTTP alongside `/health`, `/tools`, `/call`, and `/resilience/*`—operating at the outer orchestration boundary so **`ALL_STACK_TOOLS.length === 39` remains strictly unchanged**:

- `POST /action-harness/{start,intercept,outcome,verify-stop,summary}` → `stack.actionHarness.*` (`ALLOW_READ`, `ALLOW_MUTATION`, `BLOCK_SPIN_LOOP`, `BLOCK_READ_STREAK`, `BLOCK_DUPLICATE_WRITE`, `HOLD_FOR_REVISION`)
- `POST /grounded-harness/{scale-profile,ground,ground-and-start,evaluate-turn,start,intercept,outcome,verify-stop,summary}` → `stack.groundedHarness.*` (`ALLOW`, `MEMOIZED`, `BLOCK_SPIN_LOOP`, `FORCE_VERIFY`, `REJECT_OUTPUT_DEFECT`, `ALLOW_STOP`)

> 📖 **Architecture & Benchmark Whitepapers**: Read [**Paper #27 — Return on Memory (`#1` Official DolphinBench `91.17%`)**](https://krusch.dev/articles/return-on-memory-dolphinbench) ([**PDF**](https://krusch.dev/papers/return-on-memory-dolphinbench.pdf)), [**Paper #26 — What DolphinBench Taught Me About Local AI (`#1` Open-Weights `57.33%` `gemma4-31b-sre-lora` / `54.17%` Stock @ `$0.00`)**](https://krusch.dev/articles/what-dolphinbench-taught-me-about-local-ai), and [**Paper #23 — The 15 Production Agentic Systems**](https://krusch.dev/articles/fifteen-production-agent-systems).

---

## 🤗 Open-Weights Models, SFT+DPO Dataset & Benchmarks (Trained Through `krusch-stack`)

I use `krusch-stack` to generate AST-grounded 11-phase code audit trajectories, unit-test-verified (`npm test` / `pytest`, exit `0`) bug remediations, `@krusch/toolkit` Lego-First idioms, and multi-turn MCP/workspace tool-calling + DPO calibration pairs, then distill them back into open-weights Wave-4 / Wave-6 adapters across `L1.5`, `L2`, and `L2.5`:

| Resource | Hugging Face / GitHub | Cascade Role / Base Model |
|----------|-----------------------|---------------------------|
| **Jean SRE Daemon (`jean-sre`)** | [`kruschdev/Jean-SRE-by-kruschdev`](https://github.com/kruschdev/Jean-SRE-by-kruschdev) | Autonomous 24/7 11-Phase Code Auditor, Test-Gated Remediator & Distillation Harness (`49/49` tests) |
| **SFT + DPO Dataset (`18,131` rows)** | [`krush420/sovereign-code-audit-sft`](https://huggingface.co/datasets/krush420/sovereign-code-audit-sft) | 7 Zero-Leak Splits: `code_audit_11phase_sft` (`15,290`), `elitist_120b_teacher` (`2,308`), `argon_golden_remediations` (`401`), `agentic_tool_calling_sft` (`64`), `lego_and_referee_calibration_sft` (`38`), `agentic_tool_calling_dpo` (`18`), `referee_calibration_dpo` (`12`) |
| **8B Edge Agent & Referee LoRA (`L1.5`)** | [`krush420/llama3-hermes3-8b-sre-lora`](https://huggingface.co/krush420/llama3-hermes3-8b-sre-lora) | [`NousResearch/Hermes-3-Llama-3.1-8B`](https://huggingface.co/NousResearch/Hermes-3-Llama-3.1-8B) (Built with Meta Llama 3 · BF16 LoRA + DPO, `18.33%` [`110/600`] = `15.7x` DolphinBench lift) |
| **30B Student QLoRA (`L2`)** | [`krush420/qwen3-coder-30b-sre-lora`](https://huggingface.co/krush420/qwen3-coder-30b-sre-lora) | [`Qwen/Qwen3-Coder-30B-A3B-Instruct`](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct) (`30.5B` total / `3.3B` active MoE · **`#1 Qwen/MoE` `43.00%` [`258/600`] + Grounded**, `42.67%` [`256/600`] Base & `42.00%` + `2PC` [`30B Oracle@5 = 61.17%`] @ `$0.00`) |
| **31B Dense `#1` Open-Weights QLoRA (`L2`)** | [`krush420/gemma4-31b-sre-lora`](https://huggingface.co/krush420/gemma4-31b-sre-lora) | [`google/gemma-4-31b-it`](https://huggingface.co/google/gemma-4-31b-it) (`30.7B` `100%` active dense, Apache-2.0 · Wave-6 QLoRA + BF16 Ref-Anchored DPO · **`#1 Open-Weights` `57.33%` [`344/600`] + Grounded** / `56.67%` Stock + Grounded / `54.83%` Wave-5 / `54.17%` Stock ON / `52.00%` OFF, `Gemma 4 Oracle@6 = 71.83%` @ `$0.00`) |
| **120B Teacher QLoRA (`L2.5`)** | [`krush420/gpt-oss-120b-sre-lora`](https://huggingface.co/krush420/gpt-oss-120b-sre-lora) | [`openai/gpt-oss-120b`](https://huggingface.co/openai/gpt-oss-120b) (`116.8B` total / `5.1B` active MXFP4 MoE · `39.50%` [`237/600`] DolphinBench @ `$0.00`) |
| **Hermetic Benchmarks (`90/90` Gates)** | [`krush420/sovereign-g4-benchmarks`](https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks) · [`Arena`](https://huggingface.co/spaces/krush420/sovereign-router-arena) | `333,000+` queries/episodes across `13` suites (`#1` Official DolphinBench `91.17%` Argon Low @ `$24.54` & `89.17%` Argon Low + Grounded @ `$23.92` [`Argon Low Oracle@2 = 94.00%`], model-matched `GPT 5.6 Luna + Grounded` `81.50%` @ `$1.35` [`1.57x` faster, `71.1x` cheaper than `Mem0`], `adyen/DABstep` `90.0%` @ `$0.81` [`-74.5%` cost, `2.54x` speedup], + `#1` Open-Weights `57.33%` `gemma4-31b-sre-lora` / `56.67%` Stock + Grounded @ `$0.00`), `49` Hugging Face audit logs (`48` raw JSON + `1` live PR #169 receipt bundle), and `14` viewer splits |

---

## 📜 License

MIT © kruschdev (<kruschdev@users.noreply.github.com>)

