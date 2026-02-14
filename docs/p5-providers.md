# P5: Providers (OpenAI-compatible HTTP) + recording/replay + reliable wrapper + per-turn arena

Implemented:
- Provider kinds:
  - `stub` (deterministic)
  - `openai_compat` (HTTP POST to `{base_url}/chat/completions`)
- Provider wrappers:
  - fixtures `record`/`replay` (hash-addressed JSON fixtures)
  - reliable retry wrapper (fixed backoff; deterministic)
- Per-turn arena allocator in agent loop:
  - all per-run allocations are reclaimed with `arena.deinit()`

Config:
```toml
[providers.primary]
kind = "openai_compat"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
model = "gpt-4.1-mini"
temperature = 0.2

[providers.fixtures]
mode = "record" # or "replay"
dir = "./.zigclaw/fixtures"

[providers.reliable]
retries = 2
backoff_ms = 250
```

Fixture file format: `fixtures/<sha256>.json`
```json
{
  "request": { ... },
  "response": { "content": "..." }
}
```

Notes:
- The OpenAI-compatible provider uses `POST /chat/completions` for broad compatibility.
- Secrets (`api_key`) are never printed in normalized config.
