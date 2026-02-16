# P2: Policy and Auditability

## Status

## Implemented
- Policy compilation from config capability presets (`src/policy.zig`).
- Stable `policy hash` generation (SHA-256 over canonicalized policy inputs).
- Delegation capability tokens for least-privilege child runs (`src/policy/token.zig`).
- CLI policy inspection:
  - `zigclaw policy hash`
  - `zigclaw policy explain --tool <name>`
  - `zigclaw policy explain --mount <path>`
  - `zigclaw policy explain --command "..."`
- Mount explanation reports:
  - `allowed`
  - `read_only` (when allowed)
  - mapped `guest_path` (when allowed)
- Command explanation uses command-byte allowlist from `src/security/commands.zig`.
- Decision audit log sink (`[logging]`) with size-based rotation in `src/decision_log.zig`.

## Decision Categories Observed in Code

## Implemented
- Tool policy: `tool.allow`, `tool.network`
- Provider policy: `provider.network`, `provider.select`, `provider.fixtures`, `provider.reliable`
- Memory policy: `memory.backend`, `memory.recall`
- Gateway policy: `gateway.request_bytes`, `gateway.auth`, `gateway.throttle`
- Delegation token policy: `delegation.token.mint`, `delegation.token.expired`, `delegation.token.turns_exhausted`

Each decision event includes:
- `ts_unix_ms`
- `request_id`
- `prompt_hash` (nullable)
- `decision`
- `subject`
- `allowed`
- `reason`
- `policy_hash`

## Partial/Scaffolded
- Policy engine is config-compiled and local-process only (no remote policy backend).
- No signed policy artifacts or external policy distribution mechanism yet.
