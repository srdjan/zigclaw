# P3: Tool System

## Status

## Implemented
- Tool manifest loading from `<plugin_dir>/<tool>.toml` (`src/tools/manifest.zig`).
- Tool args schema validation (`src/tools/schema.zig`).
- Tool runtime execution (`src/tools/runner.zig`) with:
  - capability preset allowlist gate
  - `requires_network` gate vs preset `allow_network`
  - runtime timeout watchdog (`max_runtime_ms`)
  - bounded stdout/stderr reads (`max_stdout_bytes`, `max_stderr_bytes`)
- CLI tool commands:
  - `zigclaw tools list`
  - `zigclaw tools describe <tool>`
  - `zigclaw tools run <tool> --args '{...}'`
- Tool protocol encode/decode (`src/tools/protocol.zig`, version `0`).

## Implemented Plugin Modes
- **WASI plugin** (default): manifest `native = false`, run with `wasmtime` and mapped dirs.
- **Native plugin**: manifest `native = true`, run host binary directly.

## Example Manifest (valid)

```toml
tool_name = "echo"
version = "0.1.0"
description = "Echo back a text field"
requires_network = false
max_runtime_ms = 2000
max_stdout_bytes = 65536
max_stderr_bytes = 65536

[args]
type = "object"
required = ["text"]

[args.properties.text]
type = "string"
max_length = 1024
```

## Partial/Scaffolded
- Args validator enforces declared properties and required fields, but does not reject unknown extra keys.
- Mount `read_only` is policy intent metadata; strict RO enforcement depends on runtime/tool behavior.
