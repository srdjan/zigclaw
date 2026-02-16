# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-02-16

### Added
- Git-backed persistence module for primitive state in `src/persistence/git_sync.zig`.
- New CLI commands:
  - `zigclaw git init`
  - `zigclaw git status`
  - `zigclaw git sync`
- New configuration section `[persistence.git]` with path allow/deny filters, branch/remote controls, and push defaults.
- Test coverage for Git persistence status classification and sync allow/deny behavior in `src/tests.zig`.

### Fixed
- Correct repo-root detection so nested workspaces are not mistaken for parent repositories.
- Correct porcelain status parsing so paths are classified reliably.
- Include ignored entries in status classification so denied paths remain visible as ignored.
- Removed memory leaks in change classification dedup logic.
