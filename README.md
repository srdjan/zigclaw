# zigclaw

A Zig port scaffold of `zeroclaw` focusing on:
- idiomatic Zig architecture (`union(enum)` dispatch, explicit allocators, error sets)
- capability sets (config-driven policy)
- WASI tool plugins (JSON protocol over stdin/stdout) executed via `wasmtime`

This repo is intentionally **scaffold-first**: it builds and runs locally, with clear TODOs for parity features.

## Requirements
- Zig (tested with recent Zig 0.12+)
- Optional (for tools): `wasmtime` in PATH

## Quickstart

Build:
```sh
zig build
```

Run agent (stub provider response for now):
```sh
zig build run -- agent --message "hello"
```

Run as a specific configured agent profile:
```sh
zig build run -- agent --message "review this change" --agent planner
```

Build WASI plugins (WASM + manifest):
```sh
zig build plugins
```

Run a plugin (requires wasmtime):
```sh
# plugin artifacts are installed into zig-out/bin/
zig-out/bin/zigclaw tools list
zig-out/bin/zigclaw tools describe echo
zig-out/bin/zigclaw tools run echo --args '{"text":"hi"}'
```

## Config

Default config path: `./zigclaw.toml`

Validate/print normalized config (stable TOML):
```sh
zig-out/bin/zigclaw config validate --config zigclaw.toml --format toml
```

Example config is included at `zigclaw.toml`.

### Static Multi-Agent Profiles (minimal)

```toml
[orchestration]
leader_agent = "planner"

[agents.planner]
capability_preset = "readonly"
delegate_to = ["writer"]
system_prompt = "Break work down, then delegate."

[agents.writer]
capability_preset = "dev"
delegate_to = []
system_prompt = "Implement delegated tasks precisely."
```

Notes:
- `zigclaw agent` defaults to `orchestration.leader_agent` when profiles are configured.
- Use `--agent <id>` to run a specific profile.
- Delegation is explicit through the built-in `delegate_agent` tool.
- Each profile enforces its own `capability_preset`.

## Queue (durable worker mode)

Enqueue an agent job:
```sh
zig-out/bin/zigclaw queue enqueue-agent --message "summarize status" --agent planner
```

Run worker once (process a single queued job if present):
```sh
zig-out/bin/zigclaw queue worker --once
```

Run worker continuously:
```sh
zig-out/bin/zigclaw queue worker
```

View queue metrics:
```sh
zig-out/bin/zigclaw queue metrics
```

Cancel a queued request:
```sh
zig-out/bin/zigclaw queue cancel --request-id req_123
```

Inspect a request:
```sh
zig-out/bin/zigclaw queue status --request-id req_123
zig-out/bin/zigclaw queue status --request-id req_123 --include-payload
```

Config:
```toml
[queue]
dir = "./.zigclaw/queue"
poll_ms = 1000
max_retries = 2
retry_backoff_ms = 500
retry_jitter_pct = 20
```

Notes:
- `queue enqueue-agent` is idempotent by `request_id`; duplicate IDs are rejected with `DuplicateRequestId`.
- `queue status` states are: `queued`, `processing`, `completed`, `canceled`, `not_found`.
- Canceling a `processing` request returns `state=processing` with `cancel_pending=true`; it transitions to `canceled` when the worker observes the cancel marker.
- Retry scheduling uses exponential backoff (`retry_backoff_ms`) and optional jitter (`retry_jitter_pct`).

## Layout
- `src/` native zigclaw core
- `plugins/` WASI plugins compiled to `wasm32-wasi`
- `docs/` architecture + protocol notes


## Policy

Print policy hash:
```sh
zig-out/bin/zigclaw policy hash --config zigclaw.toml
```

Explain whether a tool is allowed:
```sh
zig-out/bin/zigclaw policy explain --tool fs_read --config zigclaw.toml
```

Explain mount accessibility and mode (read-only vs writable):
```sh
zig-out/bin/zigclaw policy explain --mount ./tmp/work --config zigclaw.toml
```

Explain whether a command string passes the safety allowlist:
```sh
zig-out/bin/zigclaw policy explain --command "wasmtime run --mapdir /workspace::/workspace plugin.wasm" --config zigclaw.toml
```

Decision logs are written as JSONL to `./.zigclaw/decisions.jsonl`.


## Prompt (deterministic)

Dump the full prompt bundle (system + user + memory) with hash:
```sh
zig-out/bin/zigclaw prompt dump --message "hello" --format json --config zigclaw.toml
```

Write a text dump to a file:
```sh
zig-out/bin/zigclaw prompt dump --message "hello" --format text --out /tmp/prompt.txt
```

Diff two dumps:
```sh
zig-out/bin/zigclaw prompt diff --a /tmp/prompt1.txt --b /tmp/prompt2.txt
```


## Providers

OpenAI-compatible:
```toml
[providers.primary]
kind = "openai_compat"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
model = "gpt-4.1-mini"
temperature = 0.2
```

Record fixtures (offline / deterministic dev):
```toml
[providers.fixtures]
mode = "record"
dir = "./.zigclaw/fixtures"
```

Replay fixtures (fully deterministic runs):
```toml
[providers.fixtures]
mode = "replay"
dir = "./.zigclaw/fixtures"
```


## Gateway (local HTTP)

Start:
```sh
zig-out/bin/zigclaw gateway start --bind 127.0.0.1 --port 8787
```

Health:
```sh
curl http://127.0.0.1:8787/health
```

The gateway prints a token on startup. Use it like:
```sh
TOKEN="... printed ..."
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/tools
```

Async queue flow via gateway:
```sh
TOKEN="... printed ..."
curl -sS -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message":"summarize this","request_id":"req_demo_1"}' \
  http://127.0.0.1:8787/v1/agent/enqueue

curl -sS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/v1/requests/req_demo_1

curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/v1/requests/req_demo_1/cancel

curl -sS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8787/v1/queue/metrics
```


## Observability (audit log)

ZigClaw writes JSONL logs by default to:
- `<workspace_root>/.zigclaw/logs/zigclaw.jsonl` (rotated)

Config:
```toml
[observability]
enabled = true
dir = "./.zigclaw/logs"
max_file_bytes = 1048576
max_files = 5
```
