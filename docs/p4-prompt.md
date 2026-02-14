# P4: Deterministic prompt assembly + dump/diff tooling

Implemented:
- Workspace scanner:
  - stable lexicographic ordering of relative paths
  - ignore common build/system dirs: `.git`, `.zigclaw`, `zig-out`, `node_modules`, `target`
  - skip large files (configurable constants in code for now)
  - per-file sha256 (hex)
- System prompt now includes:
  - workspace root + active preset + policy hash
  - sorted allowed tool list
  - workspace snapshot (paths + sizes + sha256)
  - optional full content sections for `AGENTS.md`, `SOUL.md`, `TOOLS.md` if present (truncated)
- CLI:
  - `zigclaw prompt dump --message "..."`
    - `--format json|text` (default json)
    - `--out <path>` to write to file
  - `zigclaw prompt diff --a <path> --b <path>` line-based diff
- Prompt hash:
  - sha256 over: system + user + recalled memory items (title+snippet)
  - included in dump output

Notes:
- Diff is intentionally simple and deterministic (line-by-line). It's meant for catching prompt drift quickly.
