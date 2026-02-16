# P6: Gateway

## Status

## Implemented
- Start command:
```sh
zig-out/bin/zigclaw gateway start --bind 127.0.0.1 --port 8787 --config zigclaw.toml
```
- Local HTTP server (`src/gateway/server.zig`) with token auth.
- Token lifecycle (`src/gateway/token.zig`): token stored at `<workspace_root>/.zigclaw/gateway.token`.
- Request size boundary (`security.max_request_bytes`).
- Optional rate limiting (`gateway.rate_limit_*`) with `memory` or `file` store.
- Route handling in `src/gateway/routes.zig`.

## Auth Model
- `/health` is unauthenticated.
- Other routes require `Authorization: Bearer <token>`.
- Auth check uses constant-time equality.

## Routes (Current)

- `GET /health`
  - `200` -> `{ "request_id": "...", "ok": true, "policy_hash": "..." }`
- `GET /v1/tools`
  - `200` -> `{ "request_id": "...", "tools_json": "{...}" }`
- `GET /v1/tools/<tool>`
  - `200` -> `{ "request_id": "...", "manifest_json": "{...}" }`
- `POST /v1/tools/run`
  - body: `{ "tool": "...", "args": { ... } }`
  - `200` -> `{ "request_id": "...", "result_json": "{...}" }`
- `POST /v1/agent`
  - body: `{ "message": "..." }`
  - `200` -> `{ "request_id": "...", "content": "...", "turns": N }`
- `POST /v1/agent/enqueue`
  - body: `{ "message": "...", "request_id"?: "...", "agent_id"?: "..." }`
  - `202` -> `{ "request_id": "...", "queued": true }`
- `POST /v1/events`
  - body: `{ "title"|"message": "...", "priority"?: "...", "owner"?: "...", "project"?: "...", "tags"?: "...", "context"?: "...", "idempotency_key"?: "...", "id"?: "..." }`
  - `202` -> `{ "request_id": "...", "created": true|false, "task_slug": "...", "task_path": "..." }`
- `GET /v1/requests/<request_id>[?include_payload=1|true|yes]`
  - `200` -> queue status JSON (`queued|processing|completed|canceled|not_found`)
- `POST /v1/requests/<request_id>/cancel`
  - `200` -> cancel result JSON
- `GET /v1/queue/metrics`
  - `200` -> queue metric counters

All responses include `x-request-id` header.

## Partial/Scaffolded
- HTTP stack is intentionally minimal: request parser + single-request-per-connection model.
- Some route payloads intentionally embed JSON as string fields (`tools_json`, `manifest_json`, `result_json`) rather than nested objects.
