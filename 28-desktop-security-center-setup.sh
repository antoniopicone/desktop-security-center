#!/usr/bin/env bash
# Installs Desktop Security Center for the current user.
#
# Same pattern as 23-kenburns-screensaver-setup.sh: a standalone,
# idempotent script — not (yet) wired into disk-setup/autoinstall.yaml.tpl.
# See spec §6.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ID="it.antoniopicone.DesktopSecurityCenter"
INSTALL_DIR="$HOME/.local/share/desktop-security-center"
BIN_DIR="$HOME/.local/bin"
SCHEMA_DIR="$HOME/.local/share/glib-2.0/schemas"
DESKTOP_DIR="$HOME/.local/share/applications"

log() { printf '==> %s\n' "$1"; }

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command '$1' not found" >&2
        exit 1
    fi
}

log "Checking dependencies"
require_cmd python3
require_cmd pkexec
require_cmd glib-compile-schemas

if ! command -v ufw >/dev/null 2>&1; then
    echo "warning: ufw not found — the Firewall module needs it. Install with: sudo apt install ufw" >&2
fi

python3 - <<'PYEOF'
import sys
try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk  # noqa: F401
except Exception as exc:  # noqa: BLE001
    print(f"error: GTK4/libadwaita PyGObject bindings not available: {exc}", file=sys.stderr)
    print("Install with: sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1", file=sys.stderr)
    sys.exit(1)
PYEOF

log "Installing app to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
rsync -a --delete \
    --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' --exclude 'tests' \
    "$SCRIPT_DIR/src" "$SCRIPT_DIR/helpers" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/helpers/desktop-security-center-helper"

log "Installing launcher to $BIN_DIR"
mkdir -p "$BIN_DIR"
install -m 0755 "$SCRIPT_DIR/bin/desktop-security-center" "$BIN_DIR/desktop-security-center"

log "Installing gsettings schema"
mkdir -p "$SCHEMA_DIR"
install -m 0644 "$SCRIPT_DIR/schemas/$APP_ID.gschema.xml" "$SCHEMA_DIR/"
glib-compile-schemas "$SCHEMA_DIR"

log "Installing desktop entry"
mkdir -p "$DESKTOP_DIR"
install -m 0644 "$SCRIPT_DIR/data/$APP_ID.desktop" "$DESKTOP_DIR/"
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "note: $BIN_DIR is not on PATH — add it to your shell profile, or launch from the app grid." ;;
esac

log "Done. Launch from the app grid as \"Desktop Security Center\", or run: $BIN_DIR/desktop-security-center"
