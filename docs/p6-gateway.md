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
- Ops dashboard endpoints (`/ops`, `/v1/ops`) also accept `?token=<gateway-token>` for browser-friendly local access.
- Auth check uses constant-time equality.

## Routes (Current)

- `GET /health`
  - `200` -> `{ "request_id": "...", "ok": true, "policy_hash": "..." }`
- `GET /v1/tools`
  - `200` -> `{ "request_id": "...", "tools": [ ... ] }`
- `GET /v1/tools/<tool>`
  - `200` -> `{ "request_id": "...", "manifest": { ... } }`
- `POST /v1/tools/run`
  - body: `{ "tool": "...", "args": { ... } }`
  - `200` -> `{ "request_id": "...", "result": { ... } }`
- `POST /v1/agent`
  - body: `{ "message": "..." }`
  - `200` -> `{ "request_id": "...", "content": "...", "turns": N, "merkle_root"?: "...", "event_count"?: N }`
- `POST /v1/agent/enqueue`
  - body: `{ "message": "...", "request_id"?: "...", "agent_id"?: "..." }`
  - `202` -> `{ "request_id": "...", "queued": true }`
- `POST /v1/events`
  - body: `{ "title"|"message": "...", "priority"?: "...", "owner"?: "...", "project"?: "...", "tags"?: "...", "context"?: "...", "idempotency_key"?: "...", "id"?: "..." }`
  - `202` -> `{ "request_id": "...", "created": true|false, "task_slug": "...", "task_path": "..." }`
- `GET /v1/requests/<request_id>[?include_payload=1|true|yes]`
  - `200` -> queue status JSON (`queued|processing|completed|canceled|not_found`)
  - completed payloads use nested `result` object (with fallback `result_raw` only if payload cannot be parsed)
- `POST /v1/requests/<request_id>/cancel`
  - `200` -> cancel result JSON
- `GET /v1/queue/metrics`
  - `200` -> queue metric counters
- `GET /v1/queue/requests?state=all|queued|processing|completed|canceled&limit=N`
  - `200` -> `{ "now_ms": N, "filter": "...", "limit": N, "total": N, "items": [ { "request_id": "...", "state": "...", "file": "...", "ts_ms": N, ... } ] }`
- `GET /v1/ops`
  - query: `limit=N` (1-50), `view=full|state`
  - `200` -> full: `{ "request_id": "...", "generated_at_ms": N, "view": "full", "queue": {...}, "audit_summary": {...}, "recent_receipts": [...], "recent_capsules": [...] }`
  - `200` -> state: `{ "request_id": "...", "generated_at_ms": N, "view": "state", "state": "idle|queued|busy", "queue": {...} }`
- `GET /ops[?token=<gateway-token>&limit=N&interval_ms=2000&view=full|state]`
  - `200` -> lightweight HTML dashboard that polls `/v1/ops` and supports client-side filter controls
- `GET /v1/runs/<request_id>/summary`
  - `200` -> `{ "request_id": "...", "state": "...", "status": {...}, "status_path": "...", "receipt_path": "...", "receipt_exists": bool, "receipt_url": "...", "capsule_path": "...", "capsule_exists": bool, "capsule_url": "..." }`
- `GET /v1/receipts/<request_id>`
  - `200` -> attestation receipt JSON
  - `404` -> `{ "request_id": "...", "error": "FileNotFound" }`
- `GET /v1/capsules/<request_id>`
  - `200` -> replay capsule JSON
  - `404` -> `{ "request_id": "...", "error": "FileNotFound" }`

All responses include `x-request-id` header.

## Partial/Scaffolded
- HTTP stack is intentionally minimal: request parser + single-request-per-connection model.
