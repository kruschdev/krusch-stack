# Adding Reliable Memory to Cursor and Claude Code in One Command

If you use Cursor, Claude Code, Windsurf, or Antigravity every day, you do not need a 10-pillar infrastructure platform just to stop your coding agent from forgetting architectural rules between chats. You want your agent to remember hard constraints, notice when code underneath a rule changed, and keep its tool budget lean.

---

## The Problem With Static Rules Files (`CLAUDE.md` & `.cursorrules`)

Static markdown files work for the first week of a project, then fail in three predictable ways:

1. **Silent Rule Rot**: You write *"Always validate Stripe webhooks in `src/api/stripe.ts`"* in `CLAUDE.md`. Two months later, someone refactors that handler or changes its signature. The markdown line never throws an error, so your agent keeps obeying stale instructions against code that moved or changed.
2. **Unbounded Prompt Bloat**: Every rule, bug postmortem, and edge case in `.cursorrules` or `CLAUDE.md` gets injected into every turn, even when you are editing an unrelated CSS file.
3. **Decision Amnesia**: When you replace an old architectural choice by deleting or overwriting a bullet in `CLAUDE.md`, you erase *why* the previous approach failed. Three weeks later, a new chat session proposes the exact pattern you already abandoned.

---

## One Command (`--profile memory-only`, 5 Verbs, ~350 Tokens)

Run a single command inside your repository (requires **Node.js >= 22.0.0**):

```bash
npx -y krusch-stack init --profile memory-only
```

*(Prefer installing only the standalone memory package without the rest of `krusch-stack`? Run `npx -y krusch-context-mcp init` from [`kruschdev/krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp).)*

Both options run on Node 22 built-in `node:sqlite` in Write-Ahead Logging (`WAL`) mode at `.krusch-stack/stack.db`: **`$0.00` API cost, zero cloud keys, and zero Docker containers**. Instead of dumping 40 tools into your context window, `--profile memory-only` exposes strictly **5 MCP verbs** (`~350` schema tokens total): `krusch_context_retrieve`, `krusch_context_remember`, `krusch_context_revise`, `krusch_context_nudge`, and `krusch_context_health`.

### Manual Cursor Setup (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "krusch-stack": {
      "command": "npx",
      "args": ["-y", "krusch-stack", "mcp", "--profile", "memory-only"],
      "env": {
        "KRUSCH_WORKSPACE_ROOT": "/path/to/your/project"
      }
    }
  }
}
```

### Manual Claude Code Setup

```bash
claude mcp add krusch-stack -- npx -y krusch-stack mcp --profile memory-only
```

---

## Concrete Walkthrough: 3 Real Moments in Daily Coding

### 1. Anchor an Invariant to Exact Code (`krusch_context_remember`)

Instead of pasting a vague note into a markdown file, tell your agent to record the invariant anchored to the exact file and line signature it governs:

```json
{
  "category": "invariant",
  "content": "Billing charges must pass integer cents, never floating-point dollars.",
  "provenance": {
    "file": "src/billing/charge.ts",
    "locator": "L42",
    "quoted_sentence": "export async function chargeCustomer(amountCents: number)"
  }
}
```

At write time, `krusch-stack` hashes the anchored code span with SHA-256 and stores `anchor_hash` alongside the rule in SQLite.

### 2. Catch Silent Rule Rot Automatically (`VALID` vs. `STALE_DRIFT`)

When you open a fresh Cursor or Claude Code session next week, `krusch_context_retrieve` hydrates active invariants within a strict token budget and re-verifies every anchored file span on disk:

- **`VALID`**: The anchored line at `src/billing/charge.ts#L42` still matches its SHA-256 digest.
- **`HEALED_LINE_SHIFT`**: Someone added imports at the top of `src/billing/charge.ts`, shifting the function to `L58`. The engine locates the exact span, heals the line number automatically, and keeps the rule active.
- **`STALE_DRIFT`**: A teammate rewrote `chargeCustomer` to accept a `Money` value object, or moved it into another module. Instead of blindly enforcing a stale rule, `krusch_context_retrieve` flags `drift_status: "STALE_DRIFT"` (and surfaces a cross-file `moved_candidate` hint when relocated) so you and your agent know the underlying code changed.

```json
{
  "id": 1,
  "category": "invariant",
  "drift_status": "STALE_DRIFT",
  "provenance": {
    "file": "src/billing/charge.ts",
    "locator": "L42",
    "moved_candidate": {
      "file": "src/billing/money-charge.ts",
      "locator": "L19"
    }
  }
}
```

### 3. Evolve Decisions Without Amnesia (`krusch_context_revise` & `nudge`)

When your architecture intentionally changes, you supersede the old rule by ID rather than deleting history:

```json
{
  "action": "supersede",
  "target_id": 1,
  "new_content": "Billing charges must accept a validated Money({ amountCents, currency }) struct.",
  "reason": "Multi-currency checkout shipped in PR #184; bare integer cents lacked ISO currency guards."
}
```

Memory `#1` transitions to `status: "superseded"` with a pointer to `#2`. Future sessions enforce `#2` while retaining the exact lineage explaining why bare numbers and floats were retired.

Before committing a multi-file edit, your agent calls `krusch_context_nudge` to audit staged changes against active invariants and `git blame` co-change history:

```json
{
  "trigger": "pre_commit",
  "code": "+ export async function chargeRefund(amountDollars: number) {"
}
```

Instead of discovering a broken invariant in code review, your agent catches the mismatch locally before `git commit`.

---

## Stay on `memory-only` or Upgrade Later?

- **Stay on `--profile memory-only`** (`5` tools, `~350` tokens) or standalone [`kruschdev/krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp) if you already like your IDE's native search and file editing and only want persistent, drift-checked memory.
- **Switch to `--profile coding-agent`** (`19` tools, `npx -y krusch-stack init`) when you also want local AST symbol/call-graph search (`krusch-git`) and two-phase commit (`2PC`) staged file writes (`krusch-harness`).
- **Verify anytime** in `<1 second` with `npx krusch-stack doctor` or inspect recent memory and nudge decisions via `npx krusch-stack explain`.
