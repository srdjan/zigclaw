# P7: Auditing + Observability

Implemented:
- Request IDs:
  - Every CLI `agent`, `tools run`, and every gateway request gets a `request_id` (32-hex).
  - Gateway response includes `request_id`; also sets `x-request-id` header.
- JSONL audit log (append-only):
  - Default dir: `<workspace_root>/.zigclaw/logs`
  - File: `zigclaw.jsonl`
  - Rotation by size, keep N files.
- Logged events (minimum viable set):
  - `gateway.request` (method, target, bytes_in)
  - `tool.run` (tool, args_sha256, allowed)
  - `agent.run` (prompt_hash, provider_kind, model)
  - `provider.call` (kind, model, status)
  - `error` (error_name, context)

Config keys:
```toml
[observability]
enabled = true
dir = "./.zigclaw/logs"
max_file_bytes = 1048576
max_files = 5
```

Notes:
- Logging is best-effort; failures to write logs do not break the request (but errors are printed to stderr).
- JSONL format keeps the pipeline simple: `jq`, `ripgrep`, etc.
