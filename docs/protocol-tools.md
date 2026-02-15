# Tool Protocol

Current protocol version is `0` (`src/tools/protocol.zig`).

## Request (core -> plugin)

```json
{
  "protocol_version": 0,
  "request_id": "abc123",
  "tool": "echo",
  "args_json": "{\"text\":\"hi\"}",
  "cwd": "/workspace",
  "mounts": [
    {"host_path":".","guest_path":"/workspace","read_only":true}
  ]
}
```

## Response (plugin -> core)

```json
{
  "protocol_version": 0,
  "request_id": "abc123",
  "ok": true,
  "data_json": "{\"echo\":\"hi\"}",
  "stdout": "echo ok",
  "stderr": ""
}
```

## Manifest Schema

Tool manifests are TOML files loaded by `src/tools/manifest.zig`.

## Implemented fields
- `tool_name`, `version`, `description`
- `requires_network` (default `false`)
- `native` (default `false`)
- `max_runtime_ms` (default `2000`)
- `max_stdout_bytes`, `max_stderr_bytes` (default `65536`)
- `[args]` with `type = "object"`
- `[args.properties.<name>]` with:
  - `type = "string" | "integer" | "boolean"`
  - optional `max_length`, `enum`, `min`, `max`
- `required = [ ... ]`

## Args Validation

`src/tools/schema.zig` validates:
- request JSON must be an object
- required keys present
- declared property type checks
- string `max_length`
- string `enum` inclusion
- integer `min` / `max`

Unknown extra keys in args are currently ignored (not rejected).

## Execution Mode

## Implemented
- `native = false`: invoke `wasmtime` with `--mapdir` mounts and `<tool>.wasm`.
- `native = true`: invoke host binary `<plugin_dir>/<tool>`.

## Partial/Scaffolded
- `read_only` on mounts is policy metadata; strict read-only mount semantics are not enforced by CLI-level `--mapdir` alone.
