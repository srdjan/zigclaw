# P4: Prompt and Agent Loop

## Status

## Implemented
- Deterministic prompt bundle assembly (`src/agent/bundle.zig`):
  - system prompt
  - user message
  - recalled memory items
  - `prompt_hash` (SHA-256 hex)
  - `policy_hash`
- System prompt composition (`src/agent/prompt.zig`) includes:
  - workspace root
  - active capability preset
  - policy hash
  - sorted allowed tools
  - workspace snapshot (files, sizes, sha256)
  - optional inline content of `AGENTS.md`, `SOUL.md`, `TOOLS.md` (truncated)
- Workspace scan (`src/agent/workspace.zig`) with stable sort and ignore list.
- CLI prompt tools:
  - `zigclaw prompt dump --format json|text`
  - `zigclaw prompt diff --a <file> --b <file>`
- Multi-turn agent loop with provider tool-calling support (`src/agent/loop.zig`).
- Static multi-agent orchestration support:
  - `[orchestration]` + `[agents.<id>]`
  - per-agent capability preset
  - built-in `delegate_agent` tool when `delegate_to` is configured

## Partial/Scaffolded
- Max turns and delegation depth are fixed constants in code (`max_agent_turns = 10`, default max delegate depth `3`), not config-driven.
- Agent stop condition is provider/tool-call driven; no additional planner/scheduler layer.
