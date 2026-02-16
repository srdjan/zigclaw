# P5: Providers

## Status

## Implemented
- Provider kinds (`src/config.zig`, `ProviderKind`):
  - `stub`
  - `openai_compat`
- Provider factory and wrapper composition (`src/providers/factory.zig`):
  - base provider
  - optional fixtures wrapper (`off|record|replay|capsule_replay`)
  - optional reliable retry wrapper (`retries > 0`)
- `openai_compat` API key resolution order:
  - `providers.primary.api_key`
  - vault key from `providers.primary.api_key_vault`
  - env var named by `providers.primary.api_key_env`
- OpenAI-compatible chat integration (`src/providers/openai_compat.zig`):
  - POST to `{base_url}/chat/completions`
  - request supports multi-turn messages + tool definitions
  - parses `finish_reason`, `tool_calls`, and token usage
- Deterministic `stub` provider for local/testing runs.

## Provider Config (Current)

```toml
[providers.primary]
kind = "stub" # "stub" | "openai_compat"
model = "gpt-4.1-mini"
temperature = 0.2
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
# optional inline secret (parsed but omitted in normalized output)
# api_key = "..."
# optional vault key name (prompts for passphrase)
# api_key_vault = "openai_api_key"

[providers.fixtures]
mode = "off" # "off" | "record" | "replay" | "capsule_replay"
dir = "./.zigclaw/fixtures"
capsule_path = "" # required when mode = "capsule_replay"

[providers.reliable]
retries = 0
backoff_ms = 250
```

## Partial/Scaffolded
- `openai_compat` implementation uses `curl` subprocess, not a native HTTP client.
- Fixtures hash currently derives from legacy request fields (`model`, `temperature`, `system`, `user`, `memory_context`) and does not include full multi-turn `messages`/`tools` payload.
- Retry wrapper classifies a fixed set of permanent errors; no external retry policy config beyond retries/backoff.
