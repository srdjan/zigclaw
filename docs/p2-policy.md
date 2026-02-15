# P2: Compiled policy + audit trail

Implemented:
- `PolicyPlan` compiled from validated config (active preset => hash + allow-sets).
- Stable `policy_hash` (sha256 over canonicalized policy inputs).
- Decision log (JSONL) written to `./.zigclaw/decisions.jsonl` (created if missing).
- `zigclaw policy hash` prints the current policy hash.
- `zigclaw policy explain --tool <name>` prints a stable JSON explanation:
  `{ "tool":"...", "allowed":true/false, "reason":"...", "policy_hash":"..." }`
- `zigclaw policy explain --mount <path>` explains path accessibility and boundary mode:
  `{ "mount":"...", "allowed":true/false, "guest_path":"...", "read_only":true/false, ... }`
- `zigclaw policy explain --command "<cmd>"` explains command allowlist safety:
  `{ "command":"...", "allowed":true/false, "reason":"...", "policy_hash":"..." }`

Next:
- Add log sink config (`[logging]`) and rotation.
- Include prompt_hash + request_id in all decision events.
