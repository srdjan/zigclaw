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
