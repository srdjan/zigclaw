# P6: HTTP Gateway (local) with token auth + JSON API

Implemented:
- `zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]`
- Token auth:
  - token file: `<workspace_root>/.zigclaw/gateway.token` (auto-created)
  - header: `Authorization: Bearer <token>`
  - `/health` is unauthenticated
- Routes:
  - `GET /health` -> `{ ok, policy_hash }`
  - `GET /v1/tools` -> `{ tools: [...] }`
  - `GET /v1/tools/<tool>` -> manifest JSON
  - `POST /v1/tools/run` body: `{ "tool": "...", "args": {...} }`
  - `POST /v1/agent/enqueue` body: `{ "message": "...", "request_id"?: "...", "agent_id"?: "..." }` -> queue async run (`202`)
  - `GET /v1/queue/metrics` -> queue depth/latency-oriented counters (`incoming_*`, `processing`, `outgoing`, `canceled`, `cancel_markers`)
  - `GET /v1/requests/<request_id>[?include_payload=1]` -> queue state JSON (`queued|processing|completed|canceled|not_found`)
  - `POST /v1/requests/<request_id>/cancel` -> attempts cancellation; returns queue cancellation result JSON
  - `POST /v1/agent` body: `{ "message": "..." }`

Notes:
- Minimal HTTP/1.1 parser (request-line + headers + content-length).
- One-request-per-connection (simple, predictable).
- The gateway is intended for **localhost** usage; if you bind to 0.0.0.0 you should additionally firewall it.
- Cancel behavior:
  - queued requests are moved to `canceled` immediately
  - processing requests return `state=processing` + `cancel_pending=true` and transition to `canceled` at cooperative worker checks
