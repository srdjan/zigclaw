# Architecture

This document reflects the current implementation in `src/`.

## Runtime Components

## Implemented
- CLI entrypoint and command router: `src/main.zig`
- Runtime diagnostics command (`zigclaw doctor`): `src/doctor.zig`
- Interactive setup wizard and prompts: `src/setup/*.zig`
- Binary self-update flow (`check` + atomic replace): `src/update/*.zig`
- Shell completion generation and grouped help in CLI router: `src/main.zig`
- Encrypted vault storage for secrets: `src/vault/*.zig`
- Config parse/normalize/validate pipeline: `src/config.zig`
- Compiled policy + policy hash + explain APIs: `src/policy.zig`
- Agent loop (multi-turn, tool calls, delegation): `src/agent/loop.zig`
- Prompt bundle + deterministic hash: `src/agent/bundle.zig`
- Provider layer and wrappers: `src/providers/*.zig`
- Tool subsystem (manifest loading, schema validation, protocol runner): `src/tools/*.zig`
- Queue worker and file-backed durable queue: `src/queue/worker.zig`
- HTTP gateway with token auth and queue/tool/agent routes: `src/gateway/*.zig`
- Run/ops UX surfaces (`run summary`, `ops summary|watch`, `queue watch`): `src/main.zig`
- Audit reporting and receipt verification commands: `src/audit/*.zig`
- Attestation receipt generation and verification: `src/attestation/*.zig`
- Replay capsule capture/replay/diff: `src/replay/*.zig`
- Primitive task/template system with markdown+YAML schema contracts: `src/primitives/tasks.zig`
- Git-backed persistence lifecycle (`init`, `status`, `sync`): `src/persistence/git_sync.zig`
- Observability and decision logging: `src/obs/logger.zig`, `src/decision_log.zig`

## Partial/Scaffolded
- `memory.backend = "sqlite"` is accepted but currently falls back to markdown backend (`src/memory/memory.zig`).
- Gateway HTTP server is intentionally minimal HTTP/1.1 (single request per connection, no advanced routing/middleware stack).

## Execution Boundaries

## Tool boundary
- Tool plugins communicate via JSON over stdin/stdout (`src/tools/protocol.zig`, protocol version `0`).
- Manifest `native = false` (default): execute with `wasmtime` and mapped dirs.
- Manifest `native = true`: execute host binary directly.
- Capability policy controls allowed tool names and writable path mounts.

## Provider boundary
- Provider selection and wrappers are built from config in `src/providers/factory.zig`.
- `openai_compat` provider is implemented via `curl` subprocess (`src/providers/openai_compat.zig`).
- API key resolution supports inline secret, vault-backed key lookup, and env var fallback.

## Queue boundary
- Queue persistence is filesystem-based (`incoming`, `processing`, `outgoing`, `canceled`, `cancel_requests`).
- Worker can run once or continuously and supports delayed retry scheduling.
- Optional automation pickup can move primitive tasks from `open` to `in-progress` and enqueue execution.

## Gateway boundary
- Token auth using bearer token from `<workspace_root>/.zigclaw/gateway.token`.
- Request-size and optional rate-limit checks happen before auth-protected route handling.
- `POST /v1/events` can convert event payloads into primitive tasks with idempotency support.
- `GET /v1/receipts/<request_id>` and `GET /v1/capsules/<request_id>` expose attestation/replay artifacts.
- `GET /v1/queue/requests` provides queue listings for operator UIs/scripts.
- `GET /v1/runs/<request_id>/summary` provides receipt/capsule-aware run summaries.
- Tool routes now return nested JSON values (arrays/objects) rather than JSON-encoded strings.
- Lightweight ops dashboard routes are available at `/ops` (HTML) and `/v1/ops` (JSON snapshot).

## Attestation and Replay boundary
- Attestation receipts are stored at `<workspace_root>/.zigclaw/receipts/<request_id>.json`.
- Replay capsules are stored at `<workspace_root>/.zigclaw/capsules/<request_id>.json`.
- Replay run executes through `capsule_replay` provider mode to avoid re-running tools.

## Build and Deploy Model

## Implemented
- Single Zig build definition in `build.zig`:
  - `zig build`: core binary
  - `zig build test`: unit/integration tests
  - `zig build plugins`: build/install plugin binaries and manifests
- Default install output path: `zig-out/bin`

## Partial/Scaffolded
- No container orchestration/deployment manifests are included in-repo.
