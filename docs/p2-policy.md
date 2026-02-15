# P2: Compiled policy + audit trail

Implemented:
- `PolicyPlan` compiled from validated config (active preset => hash + allow-sets).
- Stable `policy_hash` (sha256 over canonicalized policy inputs).
- Decision log sink is configurable via `[logging]` (dir/file + rotation).
- `zigclaw policy hash` prints the current policy hash.
- `zigclaw policy explain --tool <name>` prints a stable JSON explanation:
  `{ "tool":"...", "allowed":true/false, "reason":"...", "policy_hash":"..." }`
- `zigclaw policy explain --mount <path>` explains path accessibility and boundary mode:
  `{ "mount":"...", "allowed":true/false, "guest_path":"...", "read_only":true/false, ... }`
- `zigclaw policy explain --command "<cmd>"` explains command allowlist safety:
  `{ "command":"...", "allowed":true/false, "reason":"...", "policy_hash":"..." }`
- Policy decision events now include both `request_id` and `prompt_hash` (nullable when unavailable).
- Decision categories now include provider and memory pathways:
  `provider.network`, `provider.select`, `provider.fixtures`, `provider.reliable`,
  `memory.backend`, and `memory.recall`.
- Gateway boundaries are now covered as decision categories:
  `gateway.auth` and `gateway.request_bytes`.
- Per-client gateway throttling is enforced when enabled and logged as:
  `gateway.throttle` (allow/deny).

Next:
- Add distributed/shared limiter storage for multi-process gateway deployments.
