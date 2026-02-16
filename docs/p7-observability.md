# P7: Observability

## Status

## Implemented
- Request IDs are generated as 32-hex values (`src/obs/trace.zig`) and used across CLI/gateway paths.
- Operational JSONL log sink (`src/obs/logger.zig`) with rotation:
  - file: `zigclaw.jsonl`
  - configured by `[observability]`
- Decision/audit JSONL log sink (`src/decision_log.zig`) with rotation:
  - default file: `decisions.jsonl`
  - configured by `[logging]`
- Optional attestation receipt artifacts (`src/attestation/receipt.zig`):
  - `<workspace_root>/.zigclaw/receipts/<request_id>.json`
- Optional replay capsule artifacts (`src/replay/recorder.zig`):
  - `<workspace_root>/.zigclaw/capsules/<request_id>.json`

## Observability Events

`src/obs/logger.zig` event kinds:
- `gateway_request`
- `queue_job`
- `tool_run`
- `agent_run`
- `provider_call`
- `err`

Each event line includes:
- `ts_ms`
- `kind`
- `request_id`
- `payload`

## Decision Audit Events

`src/decision_log.zig` writes policy/audit decisions including:
- `tool.allow`, `tool.network`
- `provider.network`, `provider.select`, `provider.fixtures`, `provider.reliable`
- `memory.backend`, `memory.recall`
- `gateway.request_bytes`, `gateway.auth`, `gateway.throttle`
- `delegation.token.mint`, `delegation.token.expired`, `delegation.token.turns_exhausted`

Each line includes:
- `ts_unix_ms`, `request_id`, `prompt_hash`, `decision`, `subject`, `allowed`, `reason`, `policy_hash`

## Config

```toml
[observability]
enabled = true
dir = "./.zigclaw/logs"
max_file_bytes = 1048576
max_files = 5

[logging]
enabled = true
dir = "./.zigclaw"
file = "decisions.jsonl"
max_file_bytes = 1048576
max_files = 5
```

## Partial/Scaffolded
- Logging is best-effort by design; log-write failures do not fail request execution.
