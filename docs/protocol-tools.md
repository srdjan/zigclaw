# Tool Protocol (v0)

Request (stdin):
```json
{
  "protocol_version": 0,
  "request_id": "abc",
  "tool": "echo",
  "args_json": "{\"text\":\"hi\"}",
  "cwd": "/workspace",
  "mounts": [
    {"host_path":"./","guest_path":"/workspace","read_only":true}
  ]
}
```

Response (stdout):
```json
{
  "protocol_version": 0,
  "request_id": "abc",
  "ok": true,
  "data_json": "{\"echo\":\"hi\"}",
  "stdout": "",
  "stderr": ""
}
```

Notes:
- `args_json` and `data_json` are JSON-encoded strings (so the protocol stays simple without custom raw JSON injection).
- In later versions you can move to `args` and `data` as proper JSON objects.
