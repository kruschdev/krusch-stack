# Install `krusch-stack`

These are instructions for a coding agent (Claude Code, Codex, Cursor, Windsurf, or Antigravity) that a person asked to install and configure `krusch-stack` on their machine or inside their repository.

`krusch-stack` (`v1.3.0`) packages a local, zero-cloud AI coding agent control plane (Persistent Working Memory, Codebase AST & Call-Graph Search, Bounded OS PageMemory, Temporal Graph Context, Signed Brick Exchange, 2PC Staged File & Action Harness, Turn-0 Grounded Harness, Frontend Design Templates, Workspace Docs RAG, and `<25µs` Cascade Routing) into a single `npx` command backed by Node 22 native `node:sqlite`.

## 1. Check Prerequisites First (All at Once)

Run one read-only check before making any changes:

```bash
id -u
node -v 2>/dev/null || echo "MISSING: node"
npm -v 2>/dev/null || echo "MISSING: npm"
npx --version 2>/dev/null || echo "MISSING: npx"
docker compose version 2>/dev/null || echo "OPTIONAL_MISSING: docker-compose"
ollama --version 2>/dev/null || echo "OPTIONAL_MISSING: ollama"
```

Evaluate the results:
1. **User check**: If `id -u` prints `0` (root), stop and ask the person to run you as a standard non-root user.
2. **Node.js `>= 22.0.0` (Required)**: `krusch-stack` relies on Node 22's built-in `node:sqlite` (`DatabaseSync`) so zero native C++ compilation or Docker containers are required. If `node -v` is missing or below `v22.0.0`, ask the person before installing or switching to Node 22 (`nvm install 22` or `fnm use 22`).
3. **Docker & Ollama (Strictly Optional)**: Neither is needed for the default local setup. Only use Docker if the person explicitly requests the containerized HTTP Gateway (`127.0.0.1:3780`) and companion PostgreSQL 16 + `pgvector` schema (`db/init.sql`).

## 2. Pick the Smallest Profile Matching the Person's Request

Do not expose tools the person does not need. Choose the smallest profile that matches what they asked for:

| Profile | Unified Tools | Approx. Schema Tokens | When to Choose This Profile |
| :--- | :--- | :--- | :--- |
| `memory-only` | **5 tools** | `~350` tokens | Person only wants persistent cross-session memory, architectural invariants, and SHA-256 span drift checks (`krusch-context-mcp`). |
| `coding-agent` *(Default for `init`)* | **19 tools** | `~1,450` tokens | **Recommended default for software repos**: Memory + AST symbol/call-graph search (`krusch-git`) + 2PC staged file safety (`krusch-harness`, plus `krusch-grounded-harness` when `--modular` is passed). |
| `core` | **27 tools** | `~2,100` tokens | Person also wants bounded OS file PageMemory (`krusch-fs`) and `<25µs` L1-L3 task routing. |
| `full` | **39 tools** | `~3,100` tokens (`~600` w/ `--defer-tools`) | Person explicitly wants the complete 10-pillar stack including Frontend Design templates and Workspace Docs RAG. |

*(Tip: Add `--defer-tools` on smaller context budgets or local `16K` Ollama models to compress tool schema tokens by `-80.67%` via BM25 deferral.)*

## 3. Choose the Setup Mode & Verify

### Optional Pre-Install Walkthrough (`<1s`, Zero Side Effects)

If the person wants to see `krusch-stack` work before writing configs into their repo, run the isolated temporary walkthrough:

```bash
npx -y krusch-stack demo
```

### Mode A: Zero-Docker Local SQLite + IDE MCP Setup (Recommended Default)

Inside the project directory where the person wants persistent memory, AST search, and 2PC staged execution (`init` defaults to `--profile coding-agent` when `--profile` is omitted):

```bash
# 1. Initialize .krusch-stack/stack.db (WAL mode) and write non-destructive IDE MCP configs
#    (Pass --profile memory-only, --profile core, or --profile full if requested)
npx -y krusch-stack init --ide all

# 2. Verify Node >= 22, all 21 SQLite tables, and active profile health
npx -y krusch-stack doctor

# 3. Optional: Run the 2-process SIGKILL mid-apply journal rollback self-test
npx -y krusch-stack doctor --crash-drill

# 4. Inspect decision history & verify observability ("Why did the agent allow or block that?")
npx -y krusch-stack explain --limit 5
```

### Mode B: From Source Checkout (If `npx` Registry Package Is Unavailable or Person Asked to Clone)

```bash
git clone https://github.com/kruschdev/krusch-stack.git
cd krusch-stack
npm ci
[ -f .env ] || cp .env.example .env
npm test
node ./bin/krusch-stack.js demo
node ./bin/krusch-stack.js doctor --crash-drill
```

### Mode C: Optional Docker Compose Stack (HTTP Gateway on `127.0.0.1:3780` + Companion PostgreSQL 16 `db/init.sql`)

Only run this if Docker is active and the person asked for shared PostgreSQL DDL provisioning or HTTP gateway mode. Check whether port `3780` or `5432` is already bound first (`ss -ltnp | grep -E ':(3780|5432)\b' || true`):

```bash
git clone https://github.com/kruschdev/krusch-stack.git
cd krusch-stack
[ -f .env ] || cp .env.example .env
docker compose up -d
curl -fsS http://127.0.0.1:3780/health
```

## 4. Connect to the Person's Coding Agent / IDE

`npx -y krusch-stack init --ide all` writes workspace-scoped MCP files (`.mcp.json`, `.cursor/mcp.json`, `.windsurf/mcp_config.json`, `.antigravity/mcp_config.json`) using the `coding-agent` profile by default, plus a profile-matched `.agent/AGENTS.md`. If the person wants global user-level registration across all projects, merge the `krusch-stack` entry into their active client config without removing their existing MCP servers (replace `coding-agent` below with `memory-only`, `core`, or `full` to match Section 2):

- **Claude Code CLI**:
  ```bash
  claude mcp add krusch-stack -- npx -y krusch-stack mcp --profile coding-agent
  ```
  *(If installed from a local git clone, replace `npx -y krusch-stack` with `node /path/to/krusch-stack/bin/krusch-stack.js` using the real checkout path.)*
- **Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), or Antigravity (`~/.gemini/antigravity/mcp_config.json`)**:
  ```json
  {
    "mcpServers": {
      "krusch-stack": {
        "command": "npx",
        "args": ["-y", "krusch-stack", "mcp", "--profile", "coding-agent"]
      }
    }
  }
  ```
- **Codex (`~/.codex/config.toml`)**:
  ```toml
  [mcp_servers.krusch-stack]
  command = "npx"
  args = ["-y", "krusch-stack", "mcp", "--profile", "coding-agent"]
  ```

## Never

- **Never run `npm`, `npx`, or `krusch-stack` with `sudo` or as `root`**.
- **Never overwrite an existing global MCP config file** (`~/.cursor/mcp.json`, `~/.gemini/antigravity/mcp_config.json`, `~/.codex/config.toml`); read the file first, parse it, add or update only the `krusch-stack` key, and write it back cleanly.
- **Never invent API keys or database credentials** in `.env`; the SQLite WAL backend works offline at `$0.00` with zero keys.
- **Never start Docker containers** unless the person asked for PostgreSQL/Docker mode and ports `3780`/`5432` are free.

## Tell the Person After

Share a concise status report:
1. **Selected profile, setup mode & storage path** (for example, `coding-agent` profile [19 tools] with Zero-Docker `node:sqlite` at `.krusch-stack/stack.db`, or Docker Compose HTTP gateway on `http://127.0.0.1:3780` with companion PostgreSQL 16 schema on `127.0.0.1:5432`).
2. **Verification status**: Confirm `krusch-stack doctor` (plus `demo`, `--crash-drill`, or `npm test` if run) passed cleanly.
3. **Post-install debugging command**: Mention `npx -y krusch-stack explain` whenever they want to inspect why an edit, tool call, or stop attempt was allowed, memoized, or blocked.
4. **Configured IDEs & first-turn test prompt**: List the exact MCP config files updated, remind the person to reload MCP servers or open a new agent session, and suggest asking: `"Run krusch_context_retrieve to verify KruschStack memory is connected."`
