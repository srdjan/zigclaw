# zigclaw

ZigClaw is a local-first Zig agent runtime with:
- config-driven capability presets and compiled policy hash
- tool execution via plugin manifests (WASI plugins and native plugins)
- provider abstraction (`stub`, `openai_compat`) with fixture and retry wrappers
- queue worker mode and local HTTP gateway
- JSONL observability + decision/audit logs

This README reflects the current implementation in `src/`.

## Requirements
- Zig (project currently builds/tests with Zig 0.14-era std APIs)
- `wasmtime` in `PATH` for WASI tools (`native = false` manifests)
- `curl` in `PATH` for:
  - `openai_compat` provider
  - `http_fetch` native plugin

## Quickstart

Build core binary:
```sh
zig build
```

Build/install plugins and manifests to `zig-out/bin`:
```sh
zig build plugins
```

Generate starter config (skips if `zigclaw.toml` already exists):
```sh
zig-out/bin/zigclaw init
```

Run with local deterministic provider (no network):
```sh
zig-out/bin/zigclaw agent --message "hello" --config zigclaw.toml
```

Run in interactive mode:
```sh
zig-out/bin/zigclaw agent --interactive --config zigclaw.toml
```

## CLI Commands

Command list is taken from `src/main.zig:usage()`.

```text
zigclaw init
zigclaw agent --message "..." [--verbose] [--interactive] [--agent id] [--config zigclaw.toml]
zigclaw prompt dump --message "..." [--format json|text] [--out path] [--config zigclaw.toml]
zigclaw prompt diff --a file --b file
zigclaw tools list [--config zigclaw.toml]
zigclaw tools describe <tool> [--config zigclaw.toml]
zigclaw tools run <tool> --args '{}' [--config zigclaw.toml]
zigclaw queue enqueue-agent --message "..." [--agent id] [--request-id id] [--config zigclaw.toml]
zigclaw queue worker [--once] [--max-jobs N] [--poll-ms N] [--config zigclaw.toml]
zigclaw queue status --request-id <id> [--include-payload] [--config zigclaw.toml]
zigclaw queue cancel --request-id <id> [--config zigclaw.toml]
zigclaw queue metrics [--config zigclaw.toml]
zigclaw config validate [--config zigclaw.toml] [--format toml|text]
zigclaw policy hash [--config zigclaw.toml]
zigclaw policy explain (--tool <name> | --mount <path> | --command "cmd") [--config zigclaw.toml]
zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
```

## Config

Validate and print normalized config:
```sh
zig-out/bin/zigclaw config validate --config zigclaw.toml --format toml
```

Normalized output is stable and omits `providers.primary.api_key`.

Canonical normalized example (matches `tests/golden/config_normalized.toml`):
```toml
config_version = 1

[capabilities]
active_preset = "dev"

[capabilities.presets.dev]
tools = ["echo", "fs_read"]
allow_network = true
allow_write_paths = ["./.zigclaw", "./tmp"]

[capabilities.presets.readonly]
tools = ["echo"]
allow_network = false
allow_write_paths = []

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

[gateway]
rate_limit_enabled = false
rate_limit_store = "memory"
rate_limit_window_ms = 1000
rate_limit_max_requests = 60
rate_limit_dir = "./.zigclaw/gateway_rate_limit"

[security]
workspace_root = "."
max_request_bytes = 262144

[providers.primary]
kind = "stub"
model = "gpt-4.1-mini"
temperature = 0.2
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[providers.fixtures]
mode = "off"
dir = "./.zigclaw/fixtures"

[providers.reliable]
retries = 0
backoff_ms = 250

[memory]
backend = "markdown"
root = "./.zigclaw/memory"

[tools]
wasmtime_path = "wasmtime"
plugin_dir = "./zig-out/bin"

[queue]
dir = "./.zigclaw/queue"
poll_ms = 1000
max_retries = 2
retry_backoff_ms = 500
retry_jitter_pct = 20
```

## Capability Presets and Policy

Policy hash:
```sh
zig-out/bin/zigclaw policy hash --config zigclaw.toml
```

Policy explanations:
```sh
zig-out/bin/zigclaw policy explain --tool fs_read --config zigclaw.toml
zig-out/bin/zigclaw policy explain --mount ./tmp/work --config zigclaw.toml
zig-out/bin/zigclaw policy explain --command "wasmtime run --mapdir /workspace::/workspace plugin.wasm" --config zigclaw.toml
```

`policy explain --command` uses an allowlist over command bytes (`a-zA-Z0-9`, `.`, `_`, `/`, `-`, space, `:`, `=`, `,`).

## Tools

List and describe installed tool manifests:
```sh
zig-out/bin/zigclaw tools list --config zigclaw.toml
zig-out/bin/zigclaw tools describe echo --config zigclaw.toml
```

Run a tool with JSON args:
```sh
zig-out/bin/zigclaw tools run echo --args '{"text":"hi"}' --config zigclaw.toml
```

Execution model:
- `native = false` (default): run `wasmtime --mapdir ... <tool>.wasm`
- `native = true`: run host binary `<plugin_dir>/<tool>`

## Prompt and Agent Loop

Prompt bundle dump/diff:
```sh
zig-out/bin/zigclaw prompt dump --message "hello" --format json --config zigclaw.toml
zig-out/bin/zigclaw prompt dump --message "hello" --format text --out /tmp/prompt.txt --config zigclaw.toml
zig-out/bin/zigclaw prompt diff --a /tmp/prompt_a.txt --b /tmp/prompt_b.txt
```

Agent orchestration supports optional static profiles (`[orchestration]`, `[agents.<id>]`) and a built-in `delegate_agent` tool when `delegate_to` is configured.

## Providers

Primary provider config:
```toml
[providers.primary]
kind = "openai_compat" # "stub" | "openai_compat"
model = "gpt-4.1-mini"
temperature = 0.2
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
```

Fixture/retry wrappers:
```toml
[providers.fixtures]
mode = "off" # "off" | "record" | "replay"
dir = "./.zigclaw/fixtures"

[providers.reliable]
retries = 2
backoff_ms = 250
```

## Queue

Enqueue/run/status/cancel/metrics:
```sh
zig-out/bin/zigclaw queue enqueue-agent --message "summarize status" --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw queue worker --once --config zigclaw.toml
zig-out/bin/zigclaw queue status --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw queue cancel --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw queue metrics --config zigclaw.toml
```

Queue states: `queued`, `processing`, `completed`, `canceled`, `not_found`.

## Gateway

Start local gateway:
```sh
zig-out/bin/zigclaw gateway start --bind 127.0.0.1 --port 8787 --config zigclaw.toml
```

On startup, gateway prints bearer token and token file path (`<workspace_root>/.zigclaw/gateway.token`).

Health endpoint (no auth):
```sh
curl -sS http://127.0.0.1:8787/health
```

Authenticated examples:
```sh
TOKEN="$(cat ./.zigclaw/gateway.token)"

curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/tools
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/tools/echo
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"tool":"echo","args":{"text":"hi"}}' \
  http://127.0.0.1:8787/v1/tools/run
```

Note: some gateway responses intentionally return embedded JSON as strings (`tools_json`, `manifest_json`, `result_json`).

## Observability and Audit Logs

Operational events (`[observability]`) are written to:
- `<workspace_root>/<observability.dir>/zigclaw.jsonl`

Policy/decision audit events (`[logging]`) are written to:
- `<workspace_root>/<logging.dir>/<logging.file>`

Both sinks support size-based rotation.

## Project Layout
- `src/`: core runtime (`config`, `policy`, `agent`, `providers`, `tools`, `queue`, `gateway`)
- `plugins/`: example tools + SDK
- `docs/`: implementation-phase and architecture docs
- `tests/`: golden files and fixtures
