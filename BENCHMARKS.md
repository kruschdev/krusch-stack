# KruschStack Empirical Benchmarks: Cross-Stack Comparison, Reproduction Gates & Honest Gaps

[![Powered By KruschStack](https://img.shields.io/badge/Stack-krusch--stack%20v1.0-cyan.svg)](https://github.com/kruschdev/krusch-stack)
[![Hermetic Integrity Gates](https://img.shields.io/badge/SHA--256%20%26%20Proxy%20Gates-43%2F43%20Passed-brightgreen.svg)](https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks)
[![Open-Weights Loopback](https://img.shields.io/badge/Open--Weights%20Cloud%20Calls-0%20(127.0.0.1)-blueviolet.svg)](https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks)
[![Interactive Arena](https://img.shields.io/badge/%F0%9F%A4%97%20Pareto%20Explorer-sovereign--router--arena-00e5ff.svg)](https://huggingface.co/spaces/krush420/sovereign-router-arena)

## TL;DR

Across `80,000+` queries, multi-million-token conversations, and sandboxed compile/test trajectories on five public peer-reviewed benchmarks, **`krusch-stack`** delivers **state-of-the-art cost-accuracy routing** (`#1` on `RouteWorks/RouterArena` GitHub CI PR #169 at `0.7883` / `80.72%` accuracy @ `$0.2117/1K` and `#1` lowest Pareto distance `0.4269` at `-83.95%` cost across `12,566` prompts on ACL 2026 `LLMRouterBench`), **strong open-weights retrieval** on ICLR 2026 `BEAM` (`100K`–`10M` tokens, `2,000/2,000` probes), `RepoBench-R` (`47,998` Python & Java cross-file queries), and `LegalBench-RAG` (`6,889` character-exact legal span queries), and a **`2.64x` `$0`-API coding lift** (`19.56%` → `51.56%` `Pass@2` across all `225/225` 6-language `Aider Polyglot` suites) by pairing open-weights `openai/gpt-oss-120b` with our 2PC `Verify-on-Stop` harness. Scope qualifiers are essential: open-weights `51.56%` `Pass@2` ties cloud `Claude 3.5 Sonnet` (`51.6%`) and beats `GPT-4o` (`23.1%`), while multi-turn frontier reasoning models (`o3`, `gpt-5`, `Claude 4`, `Gemini 4 Argon`) still hold the `75%–88%+` coding ceiling and self-judged cloud memory stacks still lead aggregate `BEAM` E2E QA (`86%–92%` vs. `70.6%–73.5%` under strict cross-family referees)—empirically validating our hybrid design: sovereign local/open-weights execution for ~85% of traffic, reserving frontier escalation strictly for the ~15% tail.

---

## 1. Condensed External Benchmark Scorecard (`43 / 43` Hermetic Gates Passed)

Every open-weights benchmark below ran hermetically inside a single isolated **96 GB NVIDIA RTX PRO 6000 Blackwell (`sm_120`)** clean-room VM over `127.0.0.1:11434` loopback with **zero outbound cloud API calls**, runtime JS `Proxy` oracle-leakage traps, and SHA-256-pinned raw per-query audit logs published on Hugging Face ([`krush420/sovereign-g4-benchmarks`](https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks)).

| Stack Pillar & Repo | Public External Benchmark | Scale & Grading Discipline | Verified Result & External Comparison |
| :--- | :--- | :--- | :--- |
| **Router (Cloud Pool)**<br>[`krusch-cascade-router`](https://github.com/kruschdev/krusch-cascade-router) | **[RouteWorks RouterArena](https://github.com/RouteWorks/RouterArena/pull/169)**<br>*(Official GitHub CI, PR #169 — open)* | `8,400` queries + `420` robustness noise perturbations (`github-actions[bot]`) | **`0.7883` Workflow Score (`#1` in CI)** · **`80.72%` Acc @ `$0.2117/1K`** (`90.48%` robustness, `0` abnormal); surpasses `Paix2` (`0.7763` @ `$0.27`), `KT-ModelRouter` (`0.7628` @ `$0.27`), `vLLM-SR` (`0.7486`), `Azure-Model-Router` (`0.7042`), `Martian` (`0.5756` @ `$4.83`), `NotDiamond` (`0.5729` @ `$4.10`), and `RouteLLM` (`0.4807`). |
| **Router (ID + Unseen OOD)**<br>[`krusch-cascade-router`](https://github.com/kruschdev/krusch-cascade-router) | **ACL 2026 `LLMRouterBench`**<br>(`NPULH/LLMRouterBench`) | `12,566` prompts × `13` frontier LLMs (`id_test=3,005` + unseen OOD `HLE` & `ARC-AGI` `ood_test=2,558`; `0` LLM judges) | **`#1` Lowest Pareto Distance (`0.4269`) across all 10 policies** (`42.78%` Micro / `57.78%` Macro Acc @ `$14.39/1K`, **`-83.95%` cost** vs. `best_single` `gpt-5` `$89.62/1K`, `1.27ms` dispatch); beats `RouteLLM`, `KNN`, `MLP` & `RouterDC` on unseen OOD (**`25.25%` `ARC-AGI`** vs. `8.75%` `RouteLLM` & `9.25%` `MLP`). |
| **Router (Live SSE Stream)**<br>[`krusch-cascade-router`](https://github.com/kruschdev/krusch-cascade-router) | **Live `RouterArena` SSE Cascade**<br>(`gemma4:e4b` + `7B` + `120B` in `75.2 GB` VRAM) | `809` `sub_10` live generations + `420` `robustness` queries; all `325` SSE aborts (`58,743` wasted tokens) billed | **Lifts `7B` `+11.93 pp` (`48.36%` → `60.29%`, `0.6111` Arena, `78.99%` OptAcc)** while cutting **`120B` TTFT `-48.0%`** (`1,694.5ms` → `880.7ms`) and **cost `-37.4%`** (`-60.2%` on Path A `$0.0646/1K`, `73.33%` robustness). |
| **Router (Agentic Loop)**<br>[`krusch-cascade-router`](https://github.com/kruschdev/krusch-cascade-router) | **Agentic `Aider Polyglot` Routing**<br>*(6 Languages × 4 Policies)* | `60` Exercism suites × `4` multi-step policies = `240` sandboxed compile/test trajectories | **`51.67%` `Pass@2` (`31/60`, `+20` healed)** — **`100%` parity across all `6/6` languages** with `static_heavy_120b` (`51.67%`) and **`+30.00 pp` (`2.38x`) over `llm_router_preflight` (`21.67%`)** at **`0.395ms` overhead (`1,442x` faster than `569.51ms`)** and `+7.32%` higher `Pass@2/$`. |
| **Tier 1 Working Memory**<br>[`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp) (`v2.0.0`) | **Official ICLR 2026 `BEAM`**<br>(`100K`, `500K`, `1M`, `10M`) | `100` chats (`163,559` turns, `~178.34M` tok), `2,000/2,000` probes in fixed `~8K` prompt budget; dual cross-family judges | **`92.58%` (`100K`) & `93.00%` (`10M` IE) recall** (`78.67%` weighted 4-split recall; beats pure dense `8K` on `4/4` splits); **zero E2E drop `100K` → `1M`** (`70.60%` → `71.82%` → `72.86%` on `hermes3`); **beats cloud `past.dev`** on **Contradiction Resolution (`4/4` splits)**, **`10M` IE** (`70.00%` vs. `68.75%`), and **`10M` MSR** (`29.54%` Qwen / `38.33%` Hermes vs. `28.17%`). |
| **Tier 2A Codebase AST**<br>[`krusch-git`](https://github.com/kruschdev/krusch-git) (`v1.2.3`) | **`RepoBench-R` (ICLR 2024)**<br>*(Cross-File Code Retrieval)* | `47,998` valid Python & Java queries across all 8 `cff`/`cfr` × `easy`/`hard` splits (`0` LLM judges) | **`19.12%` 8-Split Macro `Acc@1`** (`+21.8%` vs. pure dense `15.69%`, `+61.5%` vs. import-order `11.84%`), **`68.58%` `Acc@5`** (sweeps `8/8` splits), `0.3957` MRR, and **`31.33%` Py / `27.45%` Java `cfr` Easy `Acc@1`**—surpassing published **`CodeBERT` (`~20.6%`/`~19.3%`)** & **`UniXcoder` (`~28.8%`/`~26.9%`)**. |
| **Tier 2B / Evidentiary Spine**<br>[`krusch-nexus`](https://github.com/kruschdev/krusch-nexus) (`v0.2.6`) | **`LegalBench-RAG`**<br>*(Character-Exact Span IR)* | `714` docs (`CUAD`, `MAUD`, `ContractNLI`, `PrivacyQA`), `6,889` full / `776` mini queries (`sort_by_document: false`, `0` LLM judges) | **`26.74%` Full Macro F1 (`k=1`)** (`2.29x` / `+128.5%` over fixed `160`-tok dense `11.70%`; `37.09%` `ContractNLI` F1), **`25.81%` F1 / `44.72%` Recall (`k=2`)**, `47.71%` Recall (`k=6`), and **`33.95%` `MAUD` `Recall@2`** > published OpenAI `text-embedding-3-large` + Cohere Rerank `MAUD` `Recall@64` (`28.28%`). |
| **Tier 3 2PC Harness**<br>[`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness) | **`Aider Polyglot` (`225/225`)**<br>*(C++, Go, Java, JS, Python, Rust)* | All `225/225` Exercism suites with mandatory test un-skipping; native unit-test execution (`0` LLM judges) | **`Pass@1 = 19.56%` (`44/225`) → `Pass@2 = 51.56%` (`116/225`)** (**`2.64x` / `+32.00 pp` lift**, `72` tasks self-healed in 1 `Verify-on-Stop` turn, `0` truncated diffs)—**ties cloud `Claude 3.5 Sonnet` (`51.6%`)** & **beats `GPT-4o` (`23.1%`)** at `$0` API cost. |
| **Unified MCP Gateway**<br>[`krusch-stack`](https://github.com/kruschdev/krusch-stack) (`--defer-tools`) | **MCP Upfront Schema Overhead**<br>*(39 Annotated Tools)* | `npx krusch-stack mcp --defer-tools` Okapi BM25 dynamic schema discovery | Cuts upfront tool-schema payload by **`-68.5%`** (`27,480` → `8,650` bytes), keeping `9` pinned core tools hot and hydrating specialist schemas on demand. |

---

## 2. How `krusch-stack` Stacks Up Against Three Architecture Archetypes

### A. vs. Standard Open-Source "Wrapper" Stacks *(LangChain / LlamaIndex + Flat 500-Tok Chunks + Supervised Routers + Unguarded Shells)*

1. **Zero-Shot Structural + Centroid Routing vs. Supervised Routers & LLM Preflight**:
   - Supervised routers (`RouteLLM` matrix factorization, `MLP`, `KNN`, `RouterDC`) fit benchmark training distributions well (`61%–66%` ID accuracy on `LLMRouterBench`), then collapse on unseen out-of-distribution reasoning suites (`8.75%` `RouteLLM` and `9.25%` `MLP` on `ARC-AGI`). `krusch-cascade-router`'s zero-shot structural complexity gate + isotropic `8K` `snowflake-arctic-embed2` centroids achieve **`#1` overall `all_test` Pareto distance (`0.4269`)** and **`25.25%` on unseen `ARC-AGI`** (`~2.8x` `RouteLLM`) with zero supervised training split required.
   - In multi-step coding loops (`Aider Polyglot` `n=60`), invoking a `7B` LLM preflight classifier before every turn burns `569.51ms` per step and misroutes `98.3%` of fresh tasks onto weak models (`21.67%` `Pass@2`). Deterministic failure-taxonomy escalation (`KruschFailureClassifier` + `CascadeRouter`) runs in **`0.395ms` (`1,442x` faster)** and reaches **`51.67%` `Pass@2`** (`+30.00 pp`).
2. **Structure-Preserving Substrates vs. Flat Token Slicing**:
   - Holding the exact same `snowflake-arctic-embed2` (`1024d`) model constant on `LegalBench-RAG` (`6,889` queries), replacing fixed `160`-token sliding windows (`11.70%` Macro F1) with `KruschNexus`'s hierarchical `Section → Clause` parser, document/section-path contextual headers, and local `mxbai-rerank-large-v2` cross-encoder reranking more than doubles span-exact F1 to **`26.74%` (`2.29x`)**.
   - On `RepoBench-R` (`47,998` cross-file code queries), combining AST symbol signatures + live in-file symbol reference activity + hybrid BM25/dense RRF beats pure dense vector search across all `8/8` Python and Java splits (`19.12%` vs. `15.69%` Macro `Acc@1`; `68.58%` `Acc@5`).
3. **Transactional 2PC Staging vs. Unguarded Disk Mutation**:
   - Standard agent loops let models overwrite working-tree files directly, often leaving truncated files or broken builds. Staging edits in SQLite/PostgreSQL behind `TruncationGuard` (`0` corrupted files across `225` tasks) and running 1 `Verify-on-Stop` compiler/test feedback turn heals **`72` initially failing tasks (`+32.00 pp`)** without human intervention.

### B. vs. Commercial Cloud Agent, Router & Memory Stacks *(`NotDiamond`, `Martian`, `Azure-Model-Router`, `past.dev`, `Hindsight`, OpenAI + Cohere)*

1. **Routing Cost & Latency Frontier**:
   - On official `RouteWorks/RouterArena` CI (`8,400` queries), `krusch-cascade-router` (`0.7883` @ `$0.2117/1K`) outperforms commercial cloud routers including `Azure-Model-Router` (`0.7042`), `Martian` (`0.5756` @ `$4.83/1K` — **`22.8x` more expensive**), and `NotDiamond` (`0.5729` @ `$4.10/1K` — **`19.4x` more expensive**), while charging `$0.00` and `<15–42.5 µs` on Stage-0 CPU decisions.
   - During live multi-model generation (`RouterArena` `sub_10`), speculative SSE logprob/loop monitoring (`Path B`) aborts low-confidence `7B` streams mid-flight and replays on `120B`, cutting `120B` mean TTFT by **`-48.0%`** (`1,694.5ms` → `880.7ms`) and total compute cost by **`-37.4%`** even after billing every single aborted token (`58,743` wasted tokens across `325` aborts).
2. **10-Million-Token Conversational Memory (`ICLR 2026 BEAM`)**:
   - Packing a fixed `~8K`-token (`~69`-turn) slice out of conversations up to `11.6M` tokens (`0.66%` of context) on zero-Docker `node:sqlite`, `krusch-context-mcp v2.0.0` exhibits **zero E2E QA degradation from `100K` → `500K` → `1M`** (`70.60%` → `71.82%` → `72.86%` on `hermes3`; `64.26%` → `62.31%` → `64.64%` on `qwen2.5:32b`).
   - Despite using a `100%` open-weights reader (`gpt-oss:120b`) instead of frontier cloud APIs, `krusch-context-mcp` **outperforms cloud `past.dev` (`openai/gpt-5.6-luna`)** on **Contradiction Resolution across all `4/4` splits** (`92.50%` Stock / `98.13%` SRE-QLoRA vs. `78.13%` at `100K`; `89.64%` vs. `78.57%` at `500K`; `77.68%` vs. `75.36%` at `1M`; `78.75%` vs. `73.13%` at `10M`), **`10M` Information Extraction** (`70.00%` vs. `68.75%`), and **`10M` Multi-Session Reasoning** (`29.54%` Qwen / `38.33%` Hermes vs. `28.17%`).
3. **Air-Gapped Legal Span Grounding**:
   - On `LegalBench-RAG`'s `MAUD` merger-agreement suite (`1,676` queries), `KruschNexus` achieves **`33.95%` character-exact `Recall@2`** (`k=2` spans) with `100%` local weights—surpassing the published `LegalBench-RAG` benchmark paper's best cloud pipeline (`OpenAI text-embedding-3-large` + `Cohere Rerank` `MAUD` `Recall@64` = `28.28%`) while retrieving `32x` fewer spans.

### C. Clean-Room Auditability & Anti-Cheating Controls

Most self-reported AI benchmarks fail basic systems scrutiny due to silent cloud fallbacks, answer-rubric leakage, skipped unit tests, or single-model self-judging. Every benchmark in our suite enforces five deterministic invariants:

- **Loopback Air-Gap (`0` Cloud APIs)**: Open-weights runs execute against `127.0.0.1:11434` inside an isolated `96 GB` Blackwell VM with `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `GEMINI_API_KEY` unset/empty and asserted in the audit log.
- **Runtime JS `Proxy` Oracle Traps**: Evaluation harnesses wrap benchmark ground-truth fields (`rubric`, `answer`, `snippets`, `records[model].performance`, `records[model].cost`) in `Proxy` traps that throw `BENCHMARK_INTEGRITY_VIOLATION` if touched during indexing, routing, or generation.
- **Mandatory Test Un-Skipping**: `Aider Polyglot` runners strip skip annotations (`#[ignore]`, `t.Skip`, `@Disabled`, `xtest`, `it.skip`, `@unittest.skip`) and SHA-256-pin pristine test files so an agent cannot "pass" by deleting or mutating unit tests.
- **Honest Wasted-Token Billing**: Speculative SSE cascade logs record and bill `100%` of tokens emitted by aborted `7B` streams (`58,743` wasted tokens across `325` aborts) before computing cost savings.
- **Zero LLM Self-Judging**: `RepoBench-R`, `LegalBench-RAG`, `Aider Polyglot`, and `LLMRouterBench` use `100%` deterministic mathematical/compiler scorers (`0` LLM judges); `BEAM` uses two independent cross-family referees (`qwen2.5:32b` + `hermes3:latest`).

---

## 3. Honest Gaps, Methodology Caveats & Open Upstream Submissions

Publishing only wins hides where open-weights systems still hit real ceilings. Below are the exact gaps and caveats in our current numbers:

1. **Aggregate `BEAM` E2E Reader Ceiling (`70.6%–73.5%` Open-Weights vs. `86.2%` `Hindsight` / `92.1%` `past.dev`)**:
   - **Cross-Family Referees vs. Cloud Self-Judging**: Our `BEAM` E2E scores grade open-weights `gpt-oss:120b` (`5.1B` active parameters) using two independent cross-family open-weights referees (`qwen2.5:32b` and `hermes3:latest`, `81%–88%` binary agreement). By contrast, `past.dev`'s `92.1%` leaderboard entry uses `openai/gpt-5.6-luna` as **both** the reader and its own judge.
   - **Strict Ordering Rubrics (`Event Ordering`: `9.68%` Qwen / `43.17%` Hermes vs. `100%` `past.dev`)**: `krusch-context-mcp v2.0.0` retrieves **`81.19%`** of gold `Event Ordering` turns at `100K`, yet `qwen2.5:32b` awards `0.0` whenever an ordered list of 6–10 milestones shifts by a single position—creating a `33.49 pp` inter-referee grading spread on identical model outputs.
   - **Passive `supersedes_id = NULL` Benchmark Ingestion (`Knowledge Update`: `37.5%–52.5%` at `100K` vs. `86%–92.5%` `past.dev`, despite `97.50%` Recall)**: To avoid tuning benchmark-specific write heuristics, our `BEAM` runner ingests raw chat turns passively with `supersedes_id = NULL`, leaving superseded historical turns active inside the `8K` context window where they distract the reader. In live IDE sessions, agents explicitly call `krusch_context_revise({ action: "supersede" })` to archive obsolete decisions (`status = 'superseded'`), eliminating stale-turn competition at the storage layer.
2. **Frontier Multi-Turn Reasoning Ceiling on Hard Coding (`51.56%` `Pass@2` vs. `75%–88%+`)**:
   - One `Verify-on-Stop` retry (`Pass@2`) lifts open-weights `gpt-oss:120b` from `19.56%` to **`51.56%` (`116/225`)** at `$0` API cost—tying `Claude 3.5 Sonnet` (`51.6%`) and beating `GPT-4o` (`23.1%`)—but `109/225` deeply algorithmic C++/Rust/Go/Java suites still fail after a single compiler/test feedback turn. Multi-turn frontier reasoning stacks (`o3`, `gpt-5`, `Claude 4`, `Gemini 4 Argon`) reach `75%–88%+`, which is why `krusch-cascade-router` escalates repeated local verification failures to L3 frontier models rather than forcing local-only execution on the hardest ~15% of tasks.
3. **Open Status of Upstream Leaderboard PRs (No Unmerged Claims)**:
   - **`RouteWorks/RouterArena` ([PR #169](https://github.com/RouteWorks/RouterArena/pull/169))**: Evaluated (`0.7883` workflow score) by the official `RouteWorks` `github-actions[bot]` CI evaluator on all `8,400` queries + `420` robustness perturbations; **PR #169 is currently open and awaiting maintainer merge** onto the upstream leaderboard branch.
   - **`Aider Polyglot` & `AgentDojo` Upstream Submissions**: Our `225/225` `Aider Polyglot` run evaluates the exact upstream `Aider-AI/polyglot-benchmark` problem sets inside `krusch-coding-harness`'s `Verify-on-Stop` state machine (an official Aider standalone Docker `benchmark.py` PR and an ETH Zurich `AgentDojo` Defense PR for our import-frozen policy floors are unsubmitted next steps).
4. **Upstream Benchmark Dataset Hygiene Disclosures**:
   - **`RepoBench-R` (`47,998 / 48,000`)**: Two upstream rows (`[5522, 7591]` in `python_cff/test_easy` of `tianyang/repobench_python_v1.1`) contain out-of-bounds `gold_snippet_index` pointers beyond `context.length` and are deterministically quarantined and logged rather than silently coerced.
   - **`ICLR 2026 BEAM` Canary (`Conv 14 KU Q1`)**: Upstream `100K` Conversation `14` Knowledge Update `Q1` queries a nonexistent `"running shoe"` topic; our zero-leakage verifier enforces `score == 0.00` (`canary_conv14_ku_q1_zero: true`).

---

## 4. Raw Audit Logs & One-Command Verification

All `16` SHA-256-pinned raw per-query JSON audit logs (`43/43` gates) and `8` structured `jsonl` splits are publicly archived on Hugging Face:

- **Benchmark Dataset & Raw Audit Logs (`CC-BY-4.0`)**: [`huggingface.co/datasets/krush420/sovereign-g4-benchmarks`](https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks)
- **Interactive Pareto & Trajectory Explorer**: [`huggingface.co/spaces/krush420/sovereign-router-arena`](https://huggingface.co/spaces/krush420/sovereign-router-arena)
- **Test-Verified Code Audit SFT Dataset (`17,899` rows)**: [`huggingface.co/datasets/krush420/sovereign-code-audit-sft`](https://huggingface.co/datasets/krush420/sovereign-code-audit-sft)
- **Open-Weights QLoRA Adapters**: [`krush420/gpt-oss-120b-sre-lora`](https://huggingface.co/krush420/gpt-oss-120b-sre-lora) (`L2.5` Teacher) & [`krush420/qwen3-coder-30b-sre-lora`](https://huggingface.co/krush420/qwen3-coder-30b-sre-lora) (`L2` Student)

### Inspect All Splits in Python (`<30` Seconds)

```python
from datasets import load_dataset

# Top-level 10-row scorecard with SHA-256 audit log digests
scorecard = load_dataset("krush420/sovereign-g4-benchmarks", "scorecard", split="test")
for row in scorecard:
    print(f"{row['benchmark']}: {row['primary_metric']} ({row['audit_log_sha256'][:12]}...)")

# Per-benchmark splits:
# "llmrouterbench_splits" | "cascade_live_routerarena" | "cascade_agentic_polyglot"
# "polyglot_225" | "repobench_splits" | "legalbench_domains" | "beam_multisplit"
polyglot = load_dataset("krush420/sovereign-g4-benchmarks", "polyglot_225", split="test")
print("Healed by Verify-on-Stop:", sum(1 for r in polyglot if r["healed_by_verify_on_stop"]))
```

### Verify Cryptographic SHA-256 Digests Locally

```bash
# Clone the HF benchmark archive and verify raw per-query JSON digests
git clone https://huggingface.co/datasets/krush420/sovereign-g4-benchmarks
cd sovereign-g4-benchmarks

python3 -c '
import hashlib, json, pathlib
rows = [json.loads(line) for line in pathlib.Path("data/scorecard_summary.jsonl").read_text().splitlines()]
for r in rows:
    if r["audit_log_file"].startswith("raw_audit_logs/"):
        actual = hashlib.sha256(pathlib.Path(r["audit_log_file"]).read_bytes()).hexdigest()
        assert actual == r["audit_log_sha256"], f"Mismatch on {r[\"audit_log_file\"]}"
        print("PASS:", r["audit_log_file"], actual[:16])
'
```
