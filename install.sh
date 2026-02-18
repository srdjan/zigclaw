#!/usr/bin/env bash
set -euo pipefail

INSTALL_BIN="${HOME}/.local/bin"
INSTALL_DATA="${HOME}/.local/share/zigclaw"
INSTALL_CFG="${HOME}/.config/zigclaw"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building zigclaw (ReleaseSafe)..."
cd "$SCRIPT_DIR"
zig build -Doptimize=ReleaseSafe

mkdir -p "$INSTALL_DATA/bin" "$INSTALL_DATA/plugins" "$INSTALL_BIN" "$INSTALL_CFG"

# Binary
cp zig-out/bin/zigclaw "$INSTALL_DATA/bin/zigclaw"
chmod +x "$INSTALL_DATA/bin/zigclaw"

# Plugins: WASM binaries, native binaries, and .toml manifests
cp zig-out/bin/*.wasm zig-out/bin/*.toml "$INSTALL_DATA/plugins/" 2>/dev/null || true
for plugin in zig-out/bin/shell_exec zig-out/bin/http_fetch; do
    [ -f "$plugin" ] && cp "$plugin" "$INSTALL_DATA/plugins/" && chmod +x "$INSTALL_DATA/plugins/$(basename "$plugin")"
done

# Global default config - only create if absent so existing edits are preserved
if [ ! -f "$INSTALL_CFG/zigclaw.toml" ]; then
    cat > "$INSTALL_CFG/zigclaw.toml" <<TOML
config_version = 1

[tools]
plugin_dir = "${INSTALL_DATA}/plugins"
TOML
    echo "Created: $INSTALL_CFG/zigclaw.toml"
else
    echo "Preserved existing config: $INSTALL_CFG/zigclaw.toml"
fi

# Wrapper: injects --config <global> when no project-local zigclaw.toml is present
# and the user did not pass --config themselves.
cat > "$INSTALL_BIN/zigclaw" <<'WRAPPER'
#!/bin/sh
_real="${HOME}/.local/share/zigclaw/bin/zigclaw"
_cfg="${HOME}/.config/zigclaw/zigclaw.toml"

_use_global=1
[ -f "./zigclaw.toml" ] && _use_global=0
case " $* " in *" --config "*) _use_global=0 ;; esac

if [ "$_use_global" = "1" ] && [ -f "$_cfg" ]; then
    exec "$_real" --config "$_cfg" "$@"
else
    exec "$_real" "$@"
fi
WRAPPER
chmod +x "$INSTALL_BIN/zigclaw"

echo "Installed: $INSTALL_BIN/zigclaw"

case ":${PATH}:" in
    *":${INSTALL_BIN}:"*) ;;
    *) echo "NOTE: add ${INSTALL_BIN} to your PATH  (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\")" ;;
esac
