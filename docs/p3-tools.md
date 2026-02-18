# P3: Tool System

## Status

## Implemented
- Tool manifest loading from `<plugin_dir>/<tool>.toml` (`src/tools/manifest.zig`).
- Tool args schema validation (`src/tools/schema.zig`).
- Tool runtime execution (`src/tools/runner.zig`) with:
  - capability preset allowlist gate
  - provider-level external tool filter (`tools.filter`)
  - `requires_network` gate vs preset `allow_network`
  - runtime timeout watchdog (`max_runtime_ms`)
  - bounded stdout/stderr reads (`max_stdout_bytes`, `max_stderr_bytes`)
- CLI tool commands:
  - `zigclaw tools list` (scans both `plugin_dir` and `external_dir`)
  - `zigclaw tools describe <tool>` (resolves from correct directory based on built-in/external status)
  - `zigclaw tools run <tool> --args '{...}'`
- Tool protocol encode/decode (`src/tools/protocol.zig`, version `0`).
- Built-in tool registry with `isBuiltin()` lookup (`src/tools/registry.zig`).

## Implemented Plugin Modes
- **WASI plugin** (default): manifest `native = false`, run with `wasmtime` and mapped dirs.
- **Native plugin**: manifest `native = true`, run host binary directly.

## Directory Convention
- `plugins/` - source code for built-in tools (compiled to `zig-out/bin/`)
- `ext-tools/` - user-supplied external tools (pre-built binaries/WASI + `tool.toml` manifests)

Built-in tools are resolved from `tools.plugin_dir` (default `./zig-out/bin`). External tools are resolved from `tools.external_dir` (default `./ext-tools`). Both use the same manifest format (`tool.toml`).

## External Tool Filtering

A second authorization layer defaults to denying all external tools, requiring explicit opt-in. This addresses the security gap where a compromised or misconfigured provider could request execution of arbitrary external tools.

Configuration:
```toml
[tools.filter]
allow_external = false          # default: deny all external tools
external_allow_list = []        # when allow_external=true and this is non-empty, only listed tools pass
```

Decision logic for a tool name:
- **Built-in** (present in `registry_generated.zig`): always passes the filter, manifest loaded from `plugin_dir`.
- **External** (not in registry):
  - `allow_external = false`: denied with `error.ExternalToolDenied`.
  - `allow_external = true`, `external_allow_list` empty: allowed, manifest loaded from `external_dir`.
  - `allow_external = true`, `external_allow_list` non-empty: allowed only if tool name is in the list.

This layers additively with capability presets: both the preset and the filter must allow a tool for it to execute. The `delegate_agent` pseudo-tool is naturally exempt because it is handled in `agent/loop.zig` and never reaches the runner.

Filter decisions are logged under the `tool.external_filter` decision category.

Config validation produces warnings when:
- A built-in tool appears in `external_allow_list` (redundant - built-in tools bypass the filter).
- A tool in `external_allow_list` is not referenced by any capability preset (dead entry).

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
