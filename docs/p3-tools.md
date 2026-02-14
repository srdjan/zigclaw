# P3: Tool boundary hardening + manifests + args schema

Implemented:
- Tool manifest per plugin (TOML), installed next to WASM:
  - `zig-out/bin/<tool>.wasm`
  - `zig-out/bin/<tool>.toml`
- `zigclaw tools list` reads manifests from `tools.plugin_dir`.
- `zigclaw tools describe <tool>` prints manifest JSON.
- Args schema validation (subset) enforced before execution:
  - object type, properties, required, enum, max_length, min/max (ints)
- ToolRunner hardening:
  - WASI preopened dirs using wasmtime `--mapdir HOST::GUEST`
  - runtime timeout (`max_runtime_ms`) (best-effort watchdog)
  - stdout/stderr caps (`max_*_bytes`)
  - deny tools requiring network unless explicitly allowed (fail-closed)
  - audit decision logged for allow/deny (P2)

Manifest format (example):
```toml
tool_name = "echo"
version = "0.1.0"
description = "Echo args"
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

Notes:
- Read-only mounts cannot be strictly enforced by wasmtime CLI alone; we enforce *mount selection* and treat RO as policy intent.
