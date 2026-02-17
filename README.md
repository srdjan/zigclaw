# zigclaw

ZigClaw is a local-first Zig agent runtime with:
- config-driven capability presets and compiled policy hash
- tool execution via plugin manifests (WASI plugins and native plugins)
- provider abstraction (`stub`, `openai_compat`) with fixture and retry wrappers
- setup wizard, encrypted vault secrets, and in-place self-update command
- queue worker mode and local HTTP gateway
- JSONL observability + decision/audit logs
- tamper-evident execution receipts and replay capsules

>Reference projects: 
>TinyClaw by `jlia0` [tyniclaw](https://github.com/jlia0/tinyclaw) and original inspiration: [zeroclaw](https://github.com/zeroclaw-labs/zeroclaw) from `zeroclaw-labs`.

## Requirements
- Zig nightly (0.16-dev; tracks latest std APIs)
- `wasmtime` in `PATH` for WASI tools (`native = false` manifests)
- `git` in `PATH` for `zigclaw git init|status|sync`
- `curl` in `PATH` for:
  - `openai_compat` provider
  - `zigclaw update` manifest/binary fetch
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
zigclaw version [--json]
zigclaw doctor [--config zigclaw.toml] [--json]
zigclaw setup
zigclaw update [--check] [--url <manifest-url>] [--json]
zigclaw run summary --request-id <id> [--config zigclaw.toml] [--json]
zigclaw ops summary [--format text|json] [--limit N] [--config zigclaw.toml]
zigclaw ops watch [--format text|json] [--limit N] [--poll-ms N] [--iterations N] [--config zigclaw.toml]
zigclaw vault set <name> [--vault <path>] [--json]
zigclaw vault get <name> [--vault <path>] [--json]
zigclaw vault list [--vault <path>] [--json]
zigclaw vault delete <name> [--vault <path>] [--json]
zigclaw init [--json]
zigclaw init --quick [--json]
zigclaw init --guided
zigclaw agent --message "..." [--verbose] [--interactive] [--agent id] [--config zigclaw.toml] [--json]
zigclaw prompt dump --message "..." [--format json|text] [--out path] [--config zigclaw.toml]
zigclaw prompt diff --a file --b file [--json]
zigclaw tools list [--config zigclaw.toml]
zigclaw tools describe <tool> [--config zigclaw.toml]
zigclaw tools run <tool> --args '{}' [--config zigclaw.toml]
zigclaw task add "..." [--priority p] [--owner o] [--project p] [--tags "a,b"] [--status s] [--config zigclaw.toml]
zigclaw task list [--status s] [--owner o] [--project p] [--format text|json] [--config zigclaw.toml]
zigclaw task done <slug> [--reason "..."] [--config zigclaw.toml]
zigclaw primitive validate <slug|path> [--config zigclaw.toml]
zigclaw templates list [--config zigclaw.toml]
zigclaw templates show [task] [--config zigclaw.toml]
zigclaw templates validate [task] [--config zigclaw.toml]
zigclaw git init [--remote <url>] [--branch <name>] [--json] [--config zigclaw.toml]
zigclaw git status [--json] [--config zigclaw.toml]
zigclaw git sync [--message "..."] [--push] [--json] [--config zigclaw.toml]
zigclaw queue enqueue-agent --message "..." [--agent id] [--request-id id] [--config zigclaw.toml]
zigclaw queue worker [--once] [--max-jobs N] [--poll-ms N] [--config zigclaw.toml]
zigclaw queue status --request-id <id> [--include-payload] [--config zigclaw.toml]
zigclaw queue watch --request-id <id> [--include-payload] [--poll-ms N] [--timeout-ms N] [--json] [--config zigclaw.toml]
zigclaw queue cancel --request-id <id> [--config zigclaw.toml]
zigclaw queue metrics [--config zigclaw.toml]
zigclaw config validate [--config zigclaw.toml] [--format toml|text|json] [--json]
zigclaw policy hash [--config zigclaw.toml] [--json]
zigclaw policy explain (--tool <name> | --mount <path> | --command "cmd") [--config zigclaw.toml]
zigclaw audit report [--request-id <id>] [--from <ts>] [--to <ts>] [--format text|json] [--config zigclaw.toml]
zigclaw audit verify --request-id <id> [--format text|json] [--config zigclaw.toml]
zigclaw audit summary [--from <ts>] [--to <ts>] [--format text|json] [--config zigclaw.toml]
zigclaw attest <request_id> [--config zigclaw.toml]
zigclaw attest verify --request-id <id> --event-index <n> [--config zigclaw.toml]
zigclaw replay capture --request-id <id> [--config zigclaw.toml]
zigclaw replay run --capsule <path> [--config zigclaw.toml]
zigclaw replay diff --a <path1> --b <path2>
zigclaw gateway start [--bind 127.0.0.1] [--port 8787] [--config zigclaw.toml]
zigclaw completion zsh|bash|fish
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
vault_path = "./.zigclaw/vault.enc"

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

[attestation]
enabled = false

[replay]
enabled = false

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
capsule_path = ""

[providers.reliable]
retries = 0
backoff_ms = 250

[memory]
backend = "markdown"
root = "./.zigclaw/memory"

[memory.primitives]
enabled = true
templates_dir = "./.zigclaw/memory/templates"
strict_schema = true

[tools]
wasmtime_path = "wasmtime"
plugin_dir = "./zig-out/bin"

[tools.registry]
strict = false

[queue]
dir = "./.zigclaw/queue"
poll_ms = 1000
max_retries = 2
retry_backoff_ms = 500
retry_jitter_pct = 20

[automation]
task_pickup_enabled = false
default_owner = "zigclaw"
pickup_statuses = ["open"]

[persistence.git]
enabled = false
repo_dir = "."
author_name = "zigclaw"
author_email = "zigclaw@local"
default_branch = "main"
allow_paths = ["./.zigclaw/memory/tasks", "./.zigclaw/memory/projects", "./.zigclaw/memory/decisions", "./.zigclaw/memory/lessons", "./.zigclaw/memory/people", "./.zigclaw/memory/templates"]
deny_paths = ["./.zigclaw/queue", "./.zigclaw/logs", "./.zigclaw/gateway.token", "./.zig-cache", "./zig-out"]
push_default = false
remote_name = "origin"
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
Delegated child runs are attenuated with capability tokens (tool/write-path/network narrowing + optional turn/expiry constraints).

## Providers

Primary provider config:
```toml
[providers.primary]
kind = "openai_compat" # "stub" | "openai_compat"
model = "gpt-4.1-mini"
temperature = 0.2
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
# optional vault-backed secret lookup
# api_key_vault = "openai_api_key"
```

Fixture/retry wrappers:
```toml
[providers.fixtures]
mode = "off" # "off" | "record" | "replay" | "capsule_replay"
dir = "./.zigclaw/fixtures"
capsule_path = "" # required when mode = "capsule_replay"

[providers.reliable]
retries = 2
backoff_ms = 250
```

`openai_compat` API key resolution order is: `providers.primary.api_key` -> vault key `providers.primary.api_key_vault` -> env var `providers.primary.api_key_env`.

## Setup, Vault, Audit, Attestation, Replay, Update

Unified onboarding flows:
```sh
zig-out/bin/zigclaw init
zig-out/bin/zigclaw init --guided
zig-out/bin/zigclaw setup
```
`init` now runs scaffold + post-setup checks (`zigclaw doctor`). `setup` runs the guided wizard path and offers optional plugin build.

Encrypted vault secret management:
```sh
zig-out/bin/zigclaw vault set openai_api_key --vault ./.zigclaw/vault.enc
zig-out/bin/zigclaw vault get openai_api_key --vault ./.zigclaw/vault.enc
zig-out/bin/zigclaw vault list --vault ./.zigclaw/vault.enc
zig-out/bin/zigclaw vault delete openai_api_key --vault ./.zigclaw/vault.enc
```

Audit/reporting and receipt verification:
```sh
zig-out/bin/zigclaw audit report --request-id req_demo_1 --format text --config zigclaw.toml
zig-out/bin/zigclaw audit verify --request-id req_demo_1 --format json --config zigclaw.toml
zig-out/bin/zigclaw attest req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw attest verify --request-id req_demo_1 --event-index 0 --config zigclaw.toml
```

Replay capture/run/diff:
```sh
zig-out/bin/zigclaw replay capture --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw replay run --capsule ./.zigclaw/capsules/req_demo_1.json --config zigclaw.toml
zig-out/bin/zigclaw replay diff --a capsule_a.json --b capsule_b.json
```

Self-update:
```sh
zig-out/bin/zigclaw update --check
zig-out/bin/zigclaw update
```

Doctor diagnostics:
```sh
zig-out/bin/zigclaw doctor --config zigclaw.toml
zig-out/bin/zigclaw doctor --config zigclaw.toml --json
```

Shell completions:
```sh
zig-out/bin/zigclaw completion zsh > ~/.zfunc/_zigclaw
zig-out/bin/zigclaw completion bash > /etc/bash_completion.d/zigclaw
zig-out/bin/zigclaw completion fish > ~/.config/fish/completions/zigclaw.fish
```

Most commands now support `--json` for machine-readable output (for example: `version`, `doctor`, `update`, `run summary`, `vault`, `init`, non-interactive `agent`, `prompt diff`, `config validate`, `policy hash`, and `queue watch`).

## Queue

Enqueue/run/status/cancel/metrics:
```sh
zig-out/bin/zigclaw queue enqueue-agent --message "summarize status" --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw queue worker --once --config zigclaw.toml
zig-out/bin/zigclaw queue status --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw queue watch --request-id req_demo_1 --poll-ms 500 --config zigclaw.toml
zig-out/bin/zigclaw queue cancel --request-id req_demo_1 --config zigclaw.toml
zig-out/bin/zigclaw queue metrics --config zigclaw.toml
zig-out/bin/zigclaw run summary --request-id req_demo_1 --config zigclaw.toml
```

Queue states: `queued`, `processing`, `completed`, `canceled`, `not_found`.

Lightweight ops dashboard:
```sh
zig-out/bin/zigclaw ops summary --config zigclaw.toml
zig-out/bin/zigclaw ops watch --poll-ms 1000 --config zigclaw.toml
```

## Primitives and Git Persistence

Create/list/complete primitive tasks:
```sh
zig-out/bin/zigclaw task add "Reply to client about shipping delay" --priority high --owner clawdious --project ops --tags "client,email" --config zigclaw.toml
zig-out/bin/zigclaw task list --status open --format text --config zigclaw.toml
zig-out/bin/zigclaw task done reply-to-client-about-shipping-delay --reason "Sent tracking and ETA" --config zigclaw.toml
```

Validate a primitive and inspect task template schema:
```sh
zig-out/bin/zigclaw primitive validate reply-to-client-about-shipping-delay --config zigclaw.toml
zig-out/bin/zigclaw templates show task --config zigclaw.toml
```

Git-backed persistence workflow:
```sh
zig-out/bin/zigclaw git init --branch main --config zigclaw.toml
zig-out/bin/zigclaw git status --config zigclaw.toml
zig-out/bin/zigclaw git sync --message "sync primitive memory updates" --config zigclaw.toml
```

## Gateway

Start local gateway:
```sh
zig-out/bin/zigclaw gateway start --bind 127.0.0.1 --port 8787 --config zigclaw.toml
```

On startup, gateway prints bearer token, an Ops UI URL, and token file path (`<workspace_root>/.zigclaw/gateway.token`).

Additional trigger-style endpoint:
- `POST /v1/events` creates/updates primitive tasks from event payloads (`title`/`message`, `priority`, `owner`, `project`, `tags`, optional `idempotency_key`).
- `GET /v1/receipts/<request_id>` returns attestation receipt JSON (when present).
- `GET /v1/capsules/<request_id>` returns replay capsule JSON (when present).
- `GET /ops?token=<gateway-token>[&limit=N&interval_ms=2000&view=state|full]` serves a lightweight auto-refreshing ops dashboard with filters.
- `GET /v1/ops?limit=N&view=state|full` returns the dashboard snapshot as JSON (auth via bearer token; browser UI can use `?token=`).

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
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/receipts/req_demo_1
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/capsules/req_demo_1
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/ops
```

Browser dashboard:
```sh
open "http://127.0.0.1:8787/ops?token=$TOKEN"
```

Gateway responses now return nested JSON objects/arrays for tool listings/manifests/results (no embedded JSON strings).
`POST /v1/agent` responses include `merkle_root` and `event_count` when `[attestation].enabled = true`.

## Observability and Audit Logs

Operational events (`[observability]`) are written to:
- `<workspace_root>/<observability.dir>/zigclaw.jsonl`

Policy/decision audit events (`[logging]`) are written to:
- `<workspace_root>/<logging.dir>/<logging.file>`

Attestation receipts are written to:
- `<workspace_root>/.zigclaw/receipts/<request_id>.json` (when `[attestation].enabled = true`)

Replay capsules are written to:
- `<workspace_root>/.zigclaw/capsules/<request_id>.json` (when `[replay].enabled = true`)

Both sinks support size-based rotation.

## Project Layout
- `src/`: core runtime (`config`, `policy`, `agent`, `providers`, `tools`, `queue`, `gateway`, `attestation`, `replay`, `vault`, `update`)
- `plugins/`: example tools + SDK
- `docs/`: implementation-phase and architecture docs
- `tests/`: golden files and fixtures
