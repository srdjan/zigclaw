# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-02-18

### Added
- Provider-level external tool filtering:
  - New `[tools.filter]` config section with `allow_external` (default `false`) and `external_allow_list` fields. External tools are denied by default, requiring explicit opt-in.
  - New `tools.external_dir` config field (default `./ext-tools`) for user-supplied external tool manifests and binaries, separate from the built-in `tools.plugin_dir`.
  - `isBuiltin()` function in the tool registry to distinguish built-in tools from external ones.
  - External tool filter enforcement in the tool runner with `tool.external_filter` decision log events.
  - `error.ExternalToolDenied` with actionable error hints in CLI, agent loop, and non-retryable error classification.
  - Config validation warns when a built-in tool appears in `external_allow_list` (redundant) or when a listed tool is not referenced by any capability preset (dead entry).
  - `tools list` and `tools describe` now scan both `plugin_dir` and `external_dir`.
  - JSON schema, normalized TOML output, and debug print updated to include new fields.
- Config tooling improvements:
  - `zigclaw config schema` command: generates a JSON Schema from the `Config` struct for editor autocompletion (VS Code Even Better TOML, etc.).
  - `zigclaw config diff --a <file1> --b <file2> [--json]` command: semantic diff between two TOML config files, reporting added, removed, and changed keys with old/new values.
  - "Did you mean?" suggestions for misspelled config keys: unknown keys now show the closest valid key name when within Levenshtein distance 2.
  - Comment preservation in TOML round-trip: inline comments (e.g. `# "stub" | "openai_compat"`) survive `config validate` normalization.
  - Shared string utilities extracted to `src/util/str.zig` (Levenshtein distance, closest match).
- Multi-model orchestration: per-agent provider selection via named providers (`[providers.NAME]` sections) and inline agent overrides (`provider_model`, `provider_temperature`, `provider_base_url`, `provider_api_key_env`). Resolution priority: `[providers.primary]` < named provider < inline fields.
- `NamedProviderConfig` struct and `provider_named` field on `Config`.
- Extended `AgentProfileConfig` with `provider`, `provider_model`, `provider_temperature`, `provider_base_url`, `provider_api_key_env` fields.
- `cfgForAgent()` now patches `provider_primary` with named/inline overrides before provider factory call.
- `provider.select` decision log reason now includes `agent=`, `kind=`, `model=` for multi-model tracing.
- Setup wizard (`zigclaw init --guided`) prompts for a separate worker model and creates a named provider.
- Config validation warns on unknown named provider references in `agents.*.provider`.
- `zigclaw chat` command as the primary user-facing entry point:
  - Interactive session, one-shot positional argument (`zigclaw chat "message"`), `--message` flag, and stdin pipe (`echo "msg" | zigclaw chat`).
  - `--model`, `--preset`, `--agent`, `--json`, `--verbose` flags.
  - Prompt shows active model name: `[gpt-4.1-mini] > `.
  - Slash commands in interactive mode: `/help`, `/model`, `/turns`, `/clear`.
- Persistent multi-turn conversation history in interactive REPL (both `chat` and `agent --interactive`):
  - History retained across turns, capped at 40 messages (20 user/assistant pairs).
  - All prior turns sent to the model on each new message for full context.
  - Token usage printed to stderr after each response: `[N tokens in, N tokens out]`.
- `AgentResult.Usage` struct accumulating `prompt_tokens`, `completion_tokens`, and `total_tokens` across all turns of a single run.
- `RunOptions.prior_messages` field for injecting conversation history into `runLoop`.
- Zero-config provider auto-detection: if `providers.primary.kind` is `stub` and `OPENAI_API_KEY` is set, `chat` and `agent` automatically switch to `openai_compat` with model `gpt-4.1-mini`.
- `ZIGCLAW_MODEL` and `ZIGCLAW_BASE_URL` environment variable overrides (between config-file values and CLI flags in precedence).
- `--model` and `--preset` runtime overrides on both `chat` and `agent` commands.
- `--full` flag on `zigclaw init` for comprehensive config scaffold; default generates a minimal ~15-line config.
- `--help-all` flag for flat full command listing.
- Grouped `--help` output (Getting Started / Agent / Operations / Configuration sections).
- Per-subcommand `--help` now calls the command's own `usageX()` instead of generic usage.
- `unknownCommand()` with Levenshtein-distance typo suggestions (threshold: edit distance <= 2).
- `src/util/term.zig`: ANSI color helpers respecting `NO_COLOR` and TTY detection.
- Colorized doctor check levels (green/yellow/red) and error/hint output in CLI.
- Interactive mode error hints for common failures: `ProviderApiKeyMissing`, `ProviderNetworkNotAllowed`, `ToolNotAllowed`, `Canceled`.
- `chat` command added to shell completions (zsh, bash, fish) and onboarding next-step messaging.

### Changed
- `zigclaw init` default config now uses `kind = "openai_compat"` (previously `"stub"`).
- `zigclaw init` onboarding next step updated from `zigclaw agent --message "hello"` to `zigclaw chat`.
- `src/providers/openai_compat.zig`: raw JSON writing now uses `stream.beginWriteRaw()`/`endWriteRaw()` API instead of a separate raw writer parameter.

## [Unreleased] - 2026-02-16

### Added
- Enterprise/runtime hardening features:
  - interactive setup wizard (`zigclaw setup`)
  - encrypted vault commands (`zigclaw vault set|get|list|delete`)
  - self-update command (`zigclaw update`, `zigclaw update --check`)
  - audit commands (`zigclaw audit report|verify|summary`)
- Git-backed persistence module for primitive state in `src/persistence/git_sync.zig`.
- New CLI commands:
  - `zigclaw git init`
  - `zigclaw git status`
  - `zigclaw git sync`
- Attestation + replay toolchain:
  - Merkle-tree execution receipts with CLI and gateway retrieval (`attest`, `/v1/receipts/<id>`)
  - replay capsules with capture/run/diff commands (`replay capture|run|diff`)
  - capsule replay provider mode (`providers.fixtures.mode = "capsule_replay"`)
- Delegation capability tokens for least-privilege sub-agent execution attenuation.
- UX/usability improvements:
  - new diagnostics command: `zigclaw doctor` (dependency/config/plugin/writability/provider checks)
  - broader machine-readable output via `--json` on key commands (`version`, `update`, `vault`, `init`, non-interactive `agent`, `prompt diff`, `config validate`, `policy hash`)
  - actionable CLI error messages with command-specific remediation hints
  - grouped command help with examples and related commands (`zigclaw <group> --help`)
  - unified onboarding path (`init` + guided `setup`) with post-setup doctor checks and optional plugin build prompt
  - live queue progress stream (`zigclaw queue watch --request-id ...`)
  - run artifact summary (`zigclaw run summary --request-id ...`)
  - shell completion generation (`zigclaw completion zsh|bash|fish`)
  - lightweight terminal ops dashboard (`zigclaw ops summary|watch`)
  - lightweight gateway ops web dashboard (`GET /ops`, `GET /v1/ops`)
  - ops web dashboard filters (`limit`, `interval_ms`, `view=state|full`)
  - hidden secret/passphrase prompts for vault and provider auth flows
  - gateway schema cleanup: nested JSON fields for tools/manifests/results (no JSON-in-string wrappers)
- New configuration section `[persistence.git]` with path allow/deny filters, branch/remote controls, and push defaults.
- New configuration fields:
  - `vault_path`
  - `[attestation].enabled`
  - `[replay].enabled`
  - `providers.primary.api_key_vault`
  - `providers.fixtures.capsule_path`
  - `[tools.registry].strict`
- Test coverage for Git persistence status classification and sync allow/deny behavior in `src/tests.zig`.
- Vault crypto/file round-trip tests and replay/attestation integration tests in `src/tests.zig`.

### Fixed
- Correct repo-root detection so nested workspaces are not mistaken for parent repositories.
- Correct porcelain status parsing so paths are classified reliably.
- Include ignored entries in status classification so denied paths remain visible as ignored.
- Removed memory leaks in change classification dedup logic.
- Fixed vault decrypt double-free and added regression coverage.
