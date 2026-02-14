# Architecture (scaffold)

**Core (native Zig)**
- CLI + config
- capability sets + policy
- agent loop + prompt builder
- providers (stub now)
- memory (markdown backend scaffolding)
- security validators
- gateway server scaffolding

**Tool execution boundary**
- tools run as WASI plugins
- core invokes `wasmtime <plugin.wasm>`
- JSON protocol over stdin/stdout
- filesystem access restricted via WASI preopened dirs (configured mounts)
