# Architecture

This document reflects the current implementation in `src/`.

## Runtime Components

## Implemented
- CLI entrypoint and command router: `src/main.zig`
- Config parse/normalize/validate pipeline: `src/config.zig`
- Compiled policy + policy hash + explain APIs: `src/policy.zig`
- Agent loop (multi-turn, tool calls, delegation): `src/agent/loop.zig`
- Prompt bundle + deterministic hash: `src/agent/bundle.zig`
- Provider layer and wrappers: `src/providers/*.zig`
- Tool subsystem (manifest loading, schema validation, protocol runner): `src/tools/*.zig`
- Queue worker and file-backed durable queue: `src/queue/worker.zig`
- HTTP gateway with token auth and queue/tool/agent routes: `src/gateway/*.zig`
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

## Queue boundary
- Queue persistence is filesystem-based (`incoming`, `processing`, `outgoing`, `canceled`, `cancel_requests`).
- Worker can run once or continuously and supports delayed retry scheduling.

## Gateway boundary
- Token auth using bearer token from `<workspace_root>/.zigclaw/gateway.token`.
- Request-size and optional rate-limit checks happen before auth-protected route handling.

## Build and Deploy Model

## Implemented
- Single Zig build definition in `build.zig`:
  - `zig build`: core binary
  - `zig build test`: unit/integration tests
  - `zig build plugins`: build/install plugin binaries and manifests
- Default install output path: `zig-out/bin`

## Partial/Scaffolded
- No container orchestration/deployment manifests are included in-repo.
