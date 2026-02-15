# P1: Config Foundation

## Status

## Implemented
- TOML subset parser in `src/config.zig`:
  - tables (`[a.b]`)
  - scalar values: string / bool / int / float
  - arrays
  - comments (`# ...`)
- Flattened key map + typed config build.
- Unknown-key warnings (ignored keys are retained as warnings, not hard errors).
- Validation output:
  - `zigclaw config validate --format toml` (stable normalized TOML)
  - `zigclaw config validate --format text` (human-readable summary)
- Secret handling: `providers.primary.api_key` can be parsed, but normalized TOML omits it.
- Basic value guards/clamps:
  - `queue.retry_jitter_pct > 100` -> clamped to `100` with warning
  - `gateway.rate_limit_window_ms == 0` -> clamped to `1` with warning
  - `gateway.rate_limit_max_requests == 0` -> clamped to `1` with warning

## Partial/Scaffolded
- Parser is intentionally not full TOML spec (no datetime/inline tables/multiline strings support).
- Type/range validation is field-specific, not a generic declarative schema engine.
- Error reporting is warning/key-oriented; no rich line/column diagnostics.

## Current Config Sections

Current typed schema in `src/config.zig` includes:
- `config_version`
- `[capabilities]`, `[capabilities.presets.<name>]`
- `[orchestration]`, `[agents.<id>]`
- `[observability]`
- `[logging]`
- `[gateway]`
- `[security]`
- `[providers.primary]`
- `[providers.fixtures]`
- `[providers.reliable]`
- `[memory]`
- `[tools]`
- `[queue]`

## Normalized Example

Use `tests/golden/config_normalized.toml` as canonical normalized format.
