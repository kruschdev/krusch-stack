# Why Two-Phase Commit (2PC) for Agent File Writes

Most coding agent harnesses hand an LLM a direct `write_file` or `edit_file` tool that mutates your working tree the moment the model emits JSON arguments. That shortcut feels fast in a single-file demo, and becomes a reliability hazard as soon as an agent runs multi-step autonomous loops.

---

## The Hazard of Direct `write_file` in Autonomous Loops

Letting an LLM write straight to disk conflates **candidate generation** (a probabilistic guess) with **state commitment** (mutating your repository or external systems):

1. **Violated Invariants Already on Disk**: An agent edits 4 files directly, introduces a banned `eval()` call or hardcoded credential in file 3, and only notices after the dirty working tree already broke your local dev server or watcher.
2. **Torn Multi-File Edits on Crash or Timeout**: If a 4-file refactor hits a subprocess timeout, OOM kill, or `SIGKILL` after writing file 2 of 4, half your modules expect the new function signature while the other half export the old one.
3. **Broken Cross-File Imports Before Tests Run**: Direct overwrites destroy the last known-good state in place before a syntax check or test suite can validate the batch as a unit.
4. **Duplicate Mutating Tool Calls**: Under retry pressure or context degradation, models frequently re-issue the exact same mutating RPC (`create_issue`, `send_invoice`, `write_file`) twice with identical arguments.

---

## Separating Candidate Generation From Disk Commitment

`krusch-stack` splits every mutation into two deterministic phases backed by Node 22 `node:sqlite` (`WAL` mode):

```text
  Agent Proposes Multi-File Patch (or Mutating MCP Tool Call)
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ PHASE 1: STAGE & VERIFY (0 Bytes Written to Working Tree)           │
  │  • Build unified diff in SQLite (`harness_tasks`)                   │
  │  • Run pre-disk invariant audit (`krusch_context_nudge`)            │
  │  • Run optional sandbox check / test gate                           │
  │  -> Violation? Return `BLOCKED_INVARIANT` / `HOLD_FOR_REVISION`     │
  └────────────────────────────┬────────────────────────────────────────┘
                               │ `status === "STAGED"`
                               ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ PHASE 2: JOURNALED ATOMIC COMMIT (`<32ms`)                          │
  │  1. Verify working-tree SHA-256 matches `base_sha256` (no drift)    │
  │  2. Write & `fsync` sibling `.krusch-tmp-<uuid>` files              │
  │  3. Record preimages in `harness_apply_journal` (`state: APPLYING`) │
  │  4. Swap via POSIX atomic `renameSync` + directory `fsync`          │
  └──────────────┬───────────────────────────────────────┬──────────────┘
                 │ All files swapped                     │ `SIGKILL` / Power Loss mid-batch
                 ▼                                       ▼
        `status: "APPLIED"`                    Startup `recoverInFlight()` restores
        Clean working tree                     exact preimages & unlinks `.krusch-tmp-*`
```

---

## Walkthrough in Code & CLI

### 1. Stage, Audit, and Atomically Apply File Edits (`stack.harness`)

```javascript
import { createKruschStack } from 'krusch-stack';

const stack = createKruschStack({ workspaceRoot: process.cwd() });
stack.context.remember({ category: 'invariant', content: 'Never use eval() in payment modules.' });

// Phase 1: Stage unified diff & audit invariants (0 bytes written to src/pay.js if blocked)
const staged = stack.harness.run({
  goal: 'Calculate integer-cent settlement fee',
  edits: [{ file_path: 'src/pay.js', content: 'export const feeCents = (cents) => Math.round(cents * 0.015);\n' }]
});

// Phase 2: Only commit to disk when status === 'STAGED' (vs. 'BLOCKED_INVARIANT')
if (staged.data.status === 'STAGED') {
  const applied = stack.harness.applyDiff({ task_id: staged.data.task_id });
  console.log(applied.data.status); // 'APPLIED'
}
```

If the proposed patch had included `eval(payload)`, `stack.harness.run` would return `status: "BLOCKED_INVARIANT"` with the matched invariant ID, and `src/pay.js` on disk would remain untouched.

Similarly, if you or another editor modified `src/pay.js` between Phase 1 (`run`) and Phase 2 (`applyDiff`), `applyDiff` detects the `base_sha256` mismatch and fails closed with `error: "WORKING_TREE_DRIFT_DETECTED"` rather than silently clobbering your manual edits.

Over MCP (`npx -y krusch-stack mcp --profile coding-agent`), your IDE agent follows the exact same 3-verb contract: call `krusch_run` to stage, optionally inspect with `krusch_diff`, and call `krusch_apply_diff` only when `status === "STAGED"`.

### 2. Extending 2PC to External MCP Tool Mutations (`stack.actionHarness`)

File writes are not the only side effects an agent can botch. `stack.actionHarness` (`krusch-stack/action-harness`) applies the same pre-commit gate to external RPC and MCP tool calls before execution:

- **`BLOCK_DUPLICATE_WRITE`**: Computes a canonical argument signature and blocks identical mutating calls already staged or committed in the active session (`DUPLICATE_SIDE_EFFECT`).
- **`HOLD_FOR_REVISION`**: Holds mutating calls containing unresolved placeholders (`"TBD"`, `"<insert_id>"`, `"YYYY-MM-DD"`), malformed ISO dates, inline API secrets (`SECRET_LEAK_BLOCKED`), or active context invariant violations before any external endpoint sees the request.

```javascript
const session = stack.actionHarness.startSession({
  session_id: 'act-01',
  goal: 'Schedule customer migration window',
  anchor_date: '2026-11-18'
});

const gate = stack.actionHarness.interceptToolCall({
  session_id: session.data.session_id,
  tool_name: 'create_calendar_event',
  args: { title: 'Migration Window', start_date: 'TBD' }
});
// gate.data.allowed === false, gate.data.decision === 'HOLD_FOR_REVISION'
```

### 3. Inspect Refusals & Run a Real `SIGKILL` Crash Drill

When your agent gets blocked or held, inspect the exact deterministic rule and diff preview from your terminal:

```bash
npx krusch-stack explain --blocked
```

```text
[harness]        task-8f3c12a9  BLOCKED_INVARIANT      src/pay.js (invariant #1: Never use eval() in payment modules)
[action_harness] evt_419a2c0e   HOLD_FOR_REVISION      create_calendar_event ([start_date] UNRESOLVED_PLACEHOLDER: "TBD")
[action_harness] evt_903b77d1   BLOCK_DUPLICATE_WRITE  send_customer_invoice (repeat #2 blocked)
```

For CI pipelines or background services running `npx krusch-stack serve`, `npx krusch-stack explain --json` and `GET /telemetry` expose the same structured counters (`blocked_invariant`, `staged_2pc_commits`, `journals_rolled_back`).

You do not have to take crash atomicity on faith. Run the built-in 2-process crash drill in `<1 second`:

```bash
npx krusch-stack doctor --crash-drill
```

This command spawns a worker process, triggers a multi-file `applyDiff`, sends a real OS `SIGKILL` immediately after the first `renameSync`, boots a fresh recovery process, and verifies byte-for-byte preimage restoration with zero orphaned `.krusch-tmp-*` files. If you need multi-worker network queues with `PostgreSQL 16` ACID locks and isolated Linux network sandboxes (`Bubblewrap` `bwrap --unshare-net`), deploy the standalone [`kruschdev/krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness) daemon.

---

## Honest Tradeoffs: When You Need 2PC vs. Plain `git checkout`

- **When plain `git checkout` or `git worktree` is enough**: If you run a single interactive prompt, read every line in your IDE diff viewer before saving, and never run unattended multi-file loops or external mutating MCP tools, native Git rollback is already fast and simple.
- **When journaled 2PC + invariant gates pay off**: Once agents iterate autonomously across multi-file refactors, local open-weights retries, or background CI tasks, catching invariant errors *before* disk mutation and gating retries on clean diffs changes outcomes dramatically. On **Aider Polyglot (`225/225` tasks)**, adding 2PC test-gated retry lifted accuracy from **`19.56%` `Pass@1` to `51.56%` `Pass@2` (`2.64x`)**, and on **DolphinBench (`600` tasks, `30B` local model)**, `2PC` action gating cut duplicate mutating MCP calls from `42` down to **`2` (`-95.2%`)**.
