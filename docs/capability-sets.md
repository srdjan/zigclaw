# Capability Presets

ZigClaw uses **capability presets** in config to define allowed autonomy.

## Schema

Configured in `zigclaw.toml` as:
- `[capabilities]`
- `[capabilities.presets.<name>]`

Each preset has:
- `tools`: allowed tool names
- `allow_network`: provider/tool network gate
- `allow_write_paths`: writable mount roots

Example:
```toml
[capabilities]
active_preset = "readonly"

[capabilities.presets.readonly]
tools = ["echo", "fs_read"]
allow_network = false
allow_write_paths = []
```

## Policy Compilation

## Implemented
- Presets are parsed/validated in `src/config.zig`.
- `src/policy.zig` compiles the active preset into:
  - allowed tool set
  - mount mapping behavior
  - stable `policy hash`
- Delegated child runs are attenuated by capability tokens (`src/policy/token.zig`, `src/agent/loop.zig`) to enforce least-privilege subsets.
- If `active_preset` is missing or unknown, policy falls back to first configured preset.

## Enforcement Points

## Implemented
- Tool allow/deny: `tools_runner.run` checks `cfg.policy.isToolAllowed(...)`.
- Network-sensitive tool manifest gate: `requires_network = true` requires `allow_network = true`.
- Provider network gate: `openai_compat` is denied when `allow_network = false`.
- Mount decisions are explainable (`policy explain --mount ...`).

## Policy Hash

## Implemented
- `policy hash` is SHA-256 over canonicalized policy inputs (workspace root, preset name, `allow_network`, sorted tools, sorted write paths).
- Available via CLI:
```sh
zig-out/bin/zigclaw policy hash --config zigclaw.toml
```
