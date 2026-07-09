# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

`claude-tunnel` is a **Claude Code + ruflo (claude-flow v3) orchestration workspace**, not an application. There is no `src/` or `package.json` and no commits yet on `master` — the substance of the repo is its tooling wiring: a 3-layer memory system, Claude Code lifecycle hooks, and a session-management script. When adding real code, follow the File Organization layout below.

## Architecture

### 3-layer memory system

Memory is the central design of this workspace. Three independent layers persist context across sessions; `scripts/claude-resume.sh` is the single entry point that prepares/restores all three, and `.claude/settings.json` hooks keep them in sync during a session.

| Layer | Location | Managed by |
|-------|----------|------------|
| 1. Claude Code Memory | `~/.claude/projects/<project-id>/memory/*.md` (+ `MEMORY.md` index) | Auto-loaded by Claude Code; written via the memory workflow |
| 2. Ruflo AgentDB | `.claude/memory.db` + `ruvector.db` (vector embeddings, HNSW patterns) | `ruflo memory *` commands |
| 3. Ruflo Session State | `.claude-flow/sessions/` | `ruflo hooks session-restore` / `session-end` |

The `<project-id>` in layer 1 is the absolute workspace path with `/` → `-` and the leading slash collapsed to a single `-` (see `claude-resume.sh:38`). `MEMORY.md` is the human-readable index; individual `*.md` files hold one fact each.

### Hooks lifecycle (`.claude/settings.json`)

Every Claude Code lifecycle event is routed to `.claude/helpers/hook-handler.cjs` (with `.claude/helpers/auto-memory-hook.mjs` for memory import/sync). The handler path falls back to `$HOME` if the project-local copy is missing. Key wirings:

- **PreToolUse / PostToolUse** (`Bash`, `Write|Edit|MultiEdit`) → `pre-bash`/`post-bash`, `pre-edit`/`post-edit` (learning + risk assessment)
- **UserPromptSubmit** → `route` (the `[INTELLIGENCE]` / agent-routing suggestions you see prepended to prompts)
- **SessionStart** → `session-restore` + auto-memory `import`
- **Stop** → auto-memory `sync`; **SessionEnd** → `session-end`
- **PreCompact** (auto & manual) → persists state before context compaction

Because these hooks run on every action, `ruflo` (or `npx ruflo@latest`) must be resolvable on PATH for the memory/learning features to work; hooks are written to fail silently (`|| true`) so their absence never blocks the session.

### Session management (`scripts/claude-resume.sh`)

The canonical way to start/resume work — always launches `claude` with `--dangerously-skip-permissions` and restores memory first. All commands run against the workspace root regardless of cwd.

```bash
./scripts/claude-resume.sh              # Interactive resume picker (default)
./scripts/claude-resume.sh <session-id> # Resume specific session
./scripts/claude-resume.sh --new [name] # New (optionally named) session
./scripts/claude-resume.sh --continue   # Continue most recent session
./scripts/claude-resume.sh --fork <id>  # Fork a session (new ID, same context)
./scripts/claude-resume.sh --pr [num]   # Resume session linked to a PR
./scripts/claude-resume.sh --memory     # Show status across all 3 memory layers
./scripts/claude-resume.sh --cleanup    # Cleanup stale entries + compress AgentDB
./scripts/claude-resume.sh --export     # Export ruflo memory to JSON backup
```

An `EXIT` trap runs `session-end` (summary + persist + metrics) when the wrapped `claude` process ends.

## Toolchain

- **Ruflo** (claude-flow v3) — AI agent orchestration, global install; provides `memory`, `hooks`, `swarm`, `agent` CLI commands
- **SuperClaude** — AI-powered git workflows (`superclaude commit`, changelog, review, readme)
- **Claude Code** — CLI, always run with `--dangerously-skip-permissions`
- **Agent Skills** (addyosmani/agent-skills) — engineering-workflow skills in `~/.claude/skills/`; start with the `using-agent-skills` meta-skill to find the right one
- **Headroom** (`headroom`) — context compression, claude-wrap set up **without** Serena (`--no-serena`)

## MCP servers

| Server | Command | Purpose |
|--------|---------|---------|
| claude-flow@alpha | `npx claude-flow@alpha mcp start` | Ruflo orchestration (314+ tools) |
| ruv-swarm | `npx ruv-swarm@latest mcp start` | Swarm coordination |
| flow-nexus | `npx flow-nexus@latest mcp start` | Cloud features |
| github | `npx -y @modelcontextprotocol/server-github` | GitHub integration |
| playwright | `npx -y @playwright/mcp` | Browser automation |
| sequential-thinking | `npx -y @modelcontextprotocol/server-sequential-thinking` | Reasoning chains |
| context7 | `npx -y @upstash/context7-mcp` | Documentation lookup |

## Startup defaults

- Always run with `--dangerously-skip-permissions`
- Use `--effort max` for complex tasks
- Give sessions descriptive names for easy resume

## File Organization

When application code is added, place it under:

- `/src` — source code
- `/tests` — tests
- `/docs` — documentation (`/docs/adr` for ADRs, `/docs/ddd` for domain docs — see `claudeFlow` config in `.claude/settings.json`)
- `/config` — configuration
- `/scripts` — utility scripts (currently `claude-resume.sh`)

## Behavioral rules

- Do what has been asked; nothing more, nothing less
- **NEVER save working files, tests, or markdown to the root folder** — use the directories above
- ALWAYS read before editing; prefer editing existing files over creating new ones
- NEVER create documentation files unless explicitly requested
- Use `superclaude commit` for commit messages when committing
- For any non-trivial task, first check whether a skill in `~/.claude/skills/` fits (via the `using-agent-skills` meta-skill) before solving it by hand
