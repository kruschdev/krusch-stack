/**
 * @module docs/video/storyboard
 * @description Authoritative 6-scene storyboard, TTS phonetic script, synchronized captions,
 * and verified empirical telemetry for the KruschStack narrated product tour video.
 *
 * Invariants enforced:
 *   - INV-SOLO-VOICE-01: Strictly first-person singular ("I") or direct product statements (zero plural "we"/"our"/"us").
 *   - INV-LEGO-26: Zero host paths, private IPs, or internal hostnames.
 *   - Evidence precision: Explicit verification tiers (CI-verified PR, queued DolphinBench UUID, clean-room SHA-256).
 */

export const VIDEO_META = Object.freeze({
  title: 'KruschStack — The Unified Sovereign AI & Coding Agent Stack',
  version: 'v1.1.0',
  width: 1920,
  height: 1080,
  fps: 30,
  repoUrl: 'github.com/kruschdev/krusch-stack',
  siteUrl: 'krusch.dev'
});

export const DEADBOLT_POLYGON_POINTS =
  '121,2 79,25 93,28 48,50 78,53 19,89 58,85 5,128 44,124 5,158 34,155 4,212 47,191 35,186 70,171 52,168 105,139 66,140 123,103 74,105 128,69 86,69 126,35 102,36';

export const SCENES = Object.freeze([
  {
    id: 'hook',
    chapter: '01',
    navLabel: 'PROBLEM',
    kicker: 'THE AGENT INFRASTRUCTURE GAP',
    headline: 'Stop Juggling 7 Disconnected MCP Servers.',
    subhead: 'One command unifies persistent memory, AST graphs, OS pages, and 2PC + Grounded harnesses.',
    prePadSec: 0.35,
    postPadSec: 0.45,
    ttsText:
      'Coding agents lose context across sessions, grep codebases blindly, and edit files without guardrails. Wiring memory, A.S.T. graphs, and safety harnesses usually takes seven separate servers. So I built Crush-Stack: one unified, sovereign A.I., and coding-agent stack.',
    captions: [
      'Coding agents lose context across sessions, grep codebases blindly, and edit files without guardrails.',
      'Wiring memory, AST graphs, and safety harnesses usually takes 7 separate servers.',
      'So I built KruschStack — one unified sovereign AI & coding agent stack.'
    ]
  },
  {
    id: 'cli',
    chapter: '02',
    navLabel: 'ZERO-SETUP CLI',
    kicker: 'UNDER 30 SECONDS · ZERO DOCKER REQUIRED',
    headline: 'npx krusch-stack init && npx krusch-stack doctor',
    subhead: 'Auto-wires Claude Code, Cursor, Windsurf & Antigravity on Node 22 native node:sqlite.',
    prePadSec: 0.30,
    postPadSec: 0.45,
    ttsText:
      'In under thirty seconds, N-P-X crush-stack init wires Claude Code, Cursor, Windsurf, and Antigravity on Node 22 sequel-lite, with zero Docker required. One doctor check verifies all thirty-nine M.C.P. tools, or cuts schema tokens eighty percent via BM-25 deferral.',
    captions: [
      'In under 30 seconds, `npx krusch-stack init` wires Claude Code, Cursor, Windsurf & Antigravity.',
      'Backed by Node 22 native `node:sqlite` — zero Docker required.',
      '`npx krusch-stack doctor` verifies 39 MCP tools — or cuts schema tokens 80.7% via `--defer-tools`.'
    ]
  },
  {
    id: 'pillars',
    chapter: '03',
    navLabel: '7 PILLARS',
    kicker: 'UNIFIED 39-TOOL ARCHITECTURE',
    headline: 'Seven Sovereign Pillars Sharing One Substrate.',
    subhead: 'Span-grounded working memory, AST call graphs, page memory, design bricks, and <25µs routing.',
    prePadSec: 0.30,
    postPadSec: 0.45,
    ttsText:
      'Inside, seven pillars share one engine: Tier One working memory with SHA-256 span-drift checks; Tier Two A.S.T. call graphs and page-anchored file memory; frontend Lego bricks and Workspace R.A.G.; plus a sub-25-microsecond pure-CPU cascade router.',
    captions: [
      'Seven unified pillars: Tier 1 Working Memory with `INV-12` `SHA-256` span-drift checks,',
      'Tier 2A Git & AST call graphs, Tier 2B page-anchored OS memory, Frontend Lego & Workspace RAG,',
      'Plus a `<25µs` pure-CPU Stage-0 Cognitive Cascade Router across L1 through L3.'
    ]
  },
  {
    id: 'harnesses',
    chapter: '04',
    navLabel: 'HARNESSES',
    kicker: 'OUTER ORCHESTRATION BOUNDARY · ALL_STACK_TOOLS === 39',
    headline: 'Turn-0 Grounding + Staged 2PC Execution.',
    subhead: 'Deterministic pre-flight introspection, spin-loop memoization, policy floors, and journaled file ops.',
    prePadSec: 0.30,
    postPadSec: 0.45,
    ttsText:
      'Before any edit touches disk, Turn-Zero Grounding scans schemas, blocks spin-loops, and gates output defects. Every mutation stages in isolation behind a frozen policy floor, committing through a write-ahead journal and POSIX atomic rename.',
    captions: [
      'Before any edit touches disk, Turn-0 Grounding scans schemas, blocks spin-loops & gates output defects.',
      'Every mutation stages in isolation behind an import-frozen policy floor,',
      'Committing through a `<32ms` write-ahead journal and POSIX atomic rename.'
    ]
  },
  {
    id: 'benchmarks',
    chapter: '05',
    navLabel: 'BENCHMARKS',
    kicker: '335,000+ TRACES · 14 EXTERNAL SUITES · 95/95 SHA-256 GATES',
    headline: 'Audited Against Published Commercial Cloud Stacks.',
    subhead: 'Reproducible clean-room artifacts, queued leaderboard archives, and CI-verified upstream receipts.',
    prePadSec: 0.30,
    postPadSec: 0.50,
    ttsText:
      'Across 335,000 traces and fourteen external suites, Crush-Stack hits 91.2 percent on DolphinBench at nearly four-times lower cost, and 57.3 percent on open weights at zero dollars, plus 90.3 percent on Snap Lo-Co-Mo, C.I.-verified RouterArena scores, and zero percent AgentDojo attack success.',
    captions: [
      'Across `335,000+` traces & `14` external suites with `95/95` `SHA-256` clean-room gates:',
      '`DolphinBench`: `91.17%` Argon Low (`~3.9x` cheaper vs. `Mem0`) & `57.33%` Open-Weights @ `$0.00`.',
      '`Snap LoCoMo`: `90.26%` Acc @ `$0.00` ingest · `RouterArena` PR #169: `0.7263` CI-verified · `AgentDojo`: `0.00%` ASR.'
    ]
  },
  {
    id: 'outro',
    chapter: '06',
    navLabel: 'QUICK START',
    kicker: 'MIT OPEN SOURCE · NODE >= 22 · DOCKER OPTIONAL',
    headline: 'Install KruschStack in One Command.',
    subhead: 'Sovereign memory, AST precision, and verified execution for every coding agent.',
    prePadSec: 0.30,
    postPadSec: 0.75,
    ttsText:
      'One command. Thirty-nine tools. Sovereign memory and verified execution. Run N-P-X crush-stack init today, and explore the M.I.T. source and SHA-256 audit logs on GitHub and crush dot dev.',
    captions: [
      'One command. `39` tools. Sovereign memory & verified execution.',
      'Run `npx krusch-stack init` — explore MIT source & audit logs at `github.com/kruschdev/krusch-stack` & `krusch.dev`.'
    ]
  }
]);

export const PILLAR_CARDS = Object.freeze([
  {
    tier: 'TIER 1',
    name: 'krusch-context-mcp',
    title: 'Working Memory & Invariants',
    bullets: ['Zero-LLM Raw-RAG + 4-Way Porter FTS5 RRF', 'INV-12 SHA-256 span-drift & cross-file relocation', '5 tools: retrieve, remember, revise, nudge, health'],
    accent: '#00E5FF'
  },
  {
    tier: 'TIER 2A',
    name: 'krusch-git',
    title: 'Git DAG & AST Call Graph',
    bullets: ['Authoritative symbol spine & 2-hop call graph', 'Hybrid BM25 + pgvector / SQLite code search', '7 tools: search_symbols, dependency_graph, read_blob'],
    accent: '#38BDF8'
  },
  {
    tier: 'TIER 2B',
    name: 'krusch-fs',
    title: 'OS Structural Page Memory',
    bullets: ['Bounded structural TOC & SHA-256 page hashes', '.env secret redaction + anchored PageMemory', '6 tools: locate, search, page_tree, read_page, sync'],
    accent: '#00F5D4'
  },
  {
    tier: 'TIER 3A + 3B',
    name: 'krusch-harness + grounded',
    title: '2PC & Turn-0 Grounded Harnesses',
    bullets: ['<150ms Turn-0 CSV/JSON/SQLite hazard scan', 'Isolated staging + <32ms journal + atomic rename', '7 MCP tools + /action-harness & /grounded-harness'],
    accent: '#A78BFA'
  },
  {
    tier: 'TIER 4',
    name: 'krusch-frontend-mcp',
    title: 'Design System & Lego Bricks',
    bullets: ['16 canonical templates & @krusch/toolkit bricks', 'WCAG AA contrast palettes & responsive tokens', '6 tools: get_canonical_template, query_design_rules'],
    accent: '#F472B6'
  },
  {
    tier: 'TIER 5',
    name: 'g-krusch',
    title: 'Workspace Hub & Drive RAG',
    bullets: ['Agent steering docs & hybrid document RAG', 'SQLite zero-setup local indexing & status checks', '6 tools: get_agent_steering, search_drive_rag, write'],
    accent: '#FBBF24'
  }
]);

export const BENCHMARK_CARDS = Object.freeze([
  {
    suite: 'Official DolphinBench (600/600 Tasks · 28 Runs)',
    badge: 'QUEUED UUID c047b063 + CLEAN-ROOM',
    badgeColor: '#00E5FF',
    heroMetric: '91.17%',
    heroLabel: 'Gemini 4 Argon (Low) + $0.00 SovereignMemoryStore @ $24.54',
    subMetric: '57.33% Open-Weights (Gemma 4 31B LoRA + Grounded) @ $0.00 (#1 in 28-run suite)',
    bars: [
      { label: 'KruschStack + Argon Low ($24.54)', pct: 91.17, color: 'linear-gradient(90deg, #00E5FF, #00F5D4)' },
      { label: 'Published Mem0 + Luna ($96.21)', pct: 70.67, color: 'rgba(148, 163, 184, 0.42)' },
      { label: 'KruschStack + Gemma 4 31B ($0.00)', pct: 57.33, color: 'linear-gradient(90deg, #8B6EFF, #38BDF8)' }
    ]
  },
  {
    suite: 'Official Snap LoCoMo (ACL 2024 · 1,540/1,540 Qs)',
    badge: '5/5 CLEAN-ROOM GATES · $0.00 INGEST',
    badgeColor: '#00F5D4',
    heroMetric: '90.26%',
    heroLabel: 'End-to-End QA Accuracy · 95.77% Evidence Recall (181.8ms median)',
    subMetric: '89.68% @ 4,465 mean tokens (6.7x compression) · 92.66% Oracle@2',
    bars: [
      { label: 'SovereignMemoryStore Zero-LLM ($0.00)', pct: 90.26, color: 'linear-gradient(90deg, #00F5D4, #00E5FF)' },
      { label: 'Evidence Turn Recall (dia_id)', pct: 95.77, color: 'linear-gradient(90deg, #38BDF8, #8B6EFF)' },
      { label: 'LivingBrain Zero-LLM Baseline', pct: 70.40, color: 'rgba(148, 163, 184, 0.42)' }
    ]
  },
  {
    suite: 'RouteWorks / RouterArena (PR #169 · 8,400 Live Receipts)',
    badge: 'github-actions[bot] CI-VERIFIED',
    badgeColor: '#A78BFA',
    heroMetric: '0.7263',
    heroLabel: '74.44% Accuracy @ $0.38/1K · 91.43% Robustness · <25µs Dispatch',
    subMetric: '26.4x cheaper than GPT-5 (0.6432) · 12.7x cheaper than Martian (0.5756)',
    bars: [
      { label: 'Krusch Cascade Router ($0.38/1K)', pct: 72.63, color: 'linear-gradient(90deg, #A78BFA, #00E5FF)' },
      { label: 'Azure Model Router ($0.76/1K)', pct: 70.37, color: 'rgba(148, 163, 184, 0.42)' },
      { label: 'Martian / NotDiamond (~$4.1–$4.8/1K)', pct: 57.56, color: 'rgba(148, 163, 184, 0.30)' }
    ]
  },
  {
    suite: 'ETH SpyLab AgentDojo v1.2.2 + Adyen DABstep',
    badge: '95/95 SHA-256 AUDIT GATES',
    badgeColor: '#34D399',
    heroMetric: '0.00% ASR',
    heroLabel: '0 / 949 Prompt-Injection Attacks Succeeded (vs. 19.28% Unguarded)',
    subMetric: 'Adyen DABstep: 90.0% Acc w/ Turn-0 Grounding (-74.5% Cost · 2.54x Faster)',
    bars: [
      { label: 'AgentDojo Injection Defense (949/949)', pct: 100.0, color: 'linear-gradient(90deg, #34D399, #00E5FF)' },
      { label: 'DABstep Turn-0 Grounded (Argon)', pct: 90.0, color: 'linear-gradient(90deg, #00E5FF, #8B6EFF)' },
      { label: 'BFCL v3 --defer-tools Token Savings', pct: 80.67, color: 'linear-gradient(90deg, #38BDF8, #00F5D4)' }
    ]
  }
]);
