# P1: Config foundation

Implemented:
- TOML parser with a broader subset than the scaffold parser:
  - tables `[a.b]`
  - `key = "string" | true/false | int | float | [ ... ]`
  - basic string escapes
  - comments `# ...`
- Validation pipeline:
  - parse -> KeyMap (flattened `a.b.c` keys)
  - typed Config fill + unknown-key warnings
  - `config_version` supported at top-level (and `meta.config_version`)
- Normalized output:
  - `zigclaw config validate` prints a stable normalized TOML

Next (P1 continuation if needed):
- Strict schema with per-field constraints (min/max, enums)
- Better error spans (line/col)
- Full TOML spec support (multi-line strings, datetime, inline tables)
