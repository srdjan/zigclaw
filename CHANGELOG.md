# Changelog

All notable changes to this project will be documented in this file.

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
