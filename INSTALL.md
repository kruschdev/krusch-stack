# Install `krusch-stack`

These are instructions for a coding agent (Claude Code, Codex, Cursor, Windsurf, or Antigravity) that a person asked to install and configure `krusch-stack` on their machine or inside their repository.

`krusch-stack` packages the entire Krusch agent infrastructure ecosystem (Working Memory & Git Alignment, Git & AST Symbol Graph, OS Page Memory, HydraScope Structural Context & Temporal Ontology, Validated Brick Exchange & 4-Axis Ontology, 2PC Staged Execution Harness, Turn-0 Grounded Harness, Frontend Design MCP with 16 Lego/Vercel templates, Google Workspace Hub, Sovereign ToolGraph, Polyglot Audit, and the `<25µs` Cascade Router) into a single `npx` command and unified MCP server.

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
2. **Node.js `>= 22.0.0` (Required)**: `krusch-stack` relies on Node 22's built-in `node:sqlite` (`DatabaseSync`) so zero native C++ compilation or Docker containers are required. If `node -v` is missing or below `v22.0.0`, ask the person before installing/switching to Node 22 (`nvm install 22` or `fnm use 22`).
3. **Docker & Ollama (Strictly Optional)**: Neither is needed for the default local setup. Only use Docker if the person explicitly requests the containerized HTTP Gateway (`127.0.0.1:3780`) and companion PostgreSQL 16 + `pgvector` schema (`db/init.sql`).

## 2. Choose the Right Setup Mode

- **Mode A: Zero-Docker Local SQLite + IDE MCP Setup (Recommended Default)**: Runs `npx krusch-stack init` in the person's target workspace, initializes `.krusch-stack/stack.db` in WAL mode (`21` SQLite tables across all `10` stack pillars), writes non-destructive IDE MCP configurations, and runs `npx krusch-stack doctor`.
- **Mode B: Source Checkout + Full Test & Crash-Recovery Verification**: Clones `https://github.com/kruschdev/krusch-stack.git`, runs the automated unit/integration test suite and the 2-process `SIGKILL` crash-recovery drill, and links the local binary into MCP clients.
- **Mode C: Docker Compose Stack (Only if requested)**: Starts companion `pgvector/pgvector:pg16` (`db/init.sql` 21-table DDL parity) and the `krusch-stack` HTTP gateway (`node:sqlite` runtime) bound on `127.0.0.1:3780`.

## 3. Install & Verify

### Mode A: Zero-Docker One-Command Setup (Default)

Inside the project directory where the person wants persistent memory, AST search, and staged execution:

```bash
# Initialize .krusch-stack/stack.db and generate IDE MCP configs (enable --defer-tools if the client has tight prompt budgets)
npx -y krusch-stack init --ide all --defer-tools

# Verify Node 22, all 21 SQLite tables, and all 10 active stack pillars
npx -y krusch-stack doctor

# Optional: Run the 2-process SIGKILL mid-apply journal rollback self-test
npx -y krusch-stack doctor --crash-drill
```

### Mode B: From Source Checkout (If `npx` Registry Package Is Unavailable or Person Asked to Clone)

```bash
git clone https://github.com/kruschdev/krusch-stack.git
cd krusch-stack
npm ci
[ -f .env ] || cp .env.example .env
npm test
node ./bin/krusch-stack.js doctor --crash-drill
```

### Mode C: Optional Docker Compose Stack (HTTP Gateway on `127.0.0.1:3780` + Companion PostgreSQL 16 `db/init.sql`)

Only run this if Docker is active and the person asked for shared PostgreSQL or HTTP gateway mode. Check whether port `3780` or `5432` is already bound first (`ss -ltnp | grep -E ':(3780|5432)\b' || true`):

```bash
git clone https://github.com/kruschdev/krusch-stack.git
cd krusch-stack
[ -f .env ] || cp .env.example .env
docker compose up -d
curl -fsS http://127.0.0.1:3780/health
```

## 4. Connect to the Person's Coding Agent / IDE

`npx -y krusch-stack init --ide all` writes workspace-scoped MCP files (`.mcp.json`, `.cursor/mcp.json`, `.windsurf/mcp_config.json`, `.antigravity/mcp_config.json`). If the person wants global user-level registration across all projects, merge the `krusch-stack` entry into their active client config without removing their existing MCP servers:

- **Claude Code CLI**:
  ```bash
  claude mcp add krusch-stack -- npx -y krusch-stack mcp --profile full --defer-tools
  ```
  *(If installed from a local git clone, replace `npx -y krusch-stack` with `node /absolute/path/to/krusch-stack/bin/krusch-stack.js` using the real `pwd`.)*
- **Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), or Antigravity (`~/.gemini/antigravity/mcp_config.json`)**:
  ```json
  {
    "mcpServers": {
      "krusch-stack": {
        "command": "npx",
        "args": ["-y", "krusch-stack", "mcp", "--profile", "full", "--defer-tools"]
      }
    }
  }
  ```
- **Codex (`~/.codex/config.toml`)**:
  ```toml
  [mcp_servers.krusch-stack]
  command = "npx"
  args = ["-y", "krusch-stack", "mcp", "--profile", "full", "--defer-tools"]
  ```

*(Use `--profile core` instead of `--profile full` if the person only wants the 27 backend/memory/AST/harness tools without Frontend Design and Workspace Hub.)*

## Never

- **Never run `npm`, `npx`, or `krusch-stack` with `sudo` or as `root`**.
- **Never overwrite an existing global MCP config file** (`~/.cursor/mcp.json`, `~/.gemini/antigravity/mcp_config.json`, `~/.codex/config.toml`); read the file first, parse it, add or update only the `krusch-stack` key, and write it back cleanly.
- **Never invent API keys or database credentials** in `.env`; the SQLite WAL backend works offline at `$0.00` with zero keys.
- **Never start Docker containers** unless the person asked for PostgreSQL/Docker mode and ports `3780`/`5432` are free.

## Tell the Person After

Share a concise status report:
1. **Setup mode & storage path** (for example, Zero-Docker `node:sqlite` at `.krusch-stack/stack.db`, or Docker Compose HTTP gateway on `http://127.0.0.1:3780` with `node:sqlite` volume `/app/.krusch-stack/stack.db` and companion PostgreSQL 16 schema on `127.0.0.1:5432`).
2. **Verification status**: Confirm `krusch-stack doctor` (and `--crash-drill` / `npm test` if run) passed cleanly.
3. **Configured IDEs**: List the exact MCP config files updated and remind the person to reload MCP servers or open a new agent session so the 39 tools appear.
4. **First-turn test prompt**: Suggest asking in their next session: `"Run krusch_stack_status and krusch_context_retrieve to verify KruschStack is connected."`
