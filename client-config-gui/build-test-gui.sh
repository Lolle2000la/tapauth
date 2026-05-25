#!/bin/bash
# Build and test the TapAuth configuration GUI with a local tapauthd daemon.
# Uses ephemeral systemd units for socket activation (matching production),
# then launches the GUI as the current (unprivileged) user.
#
# Usage: ./build-test-gui.sh
#        ./build-test-gui.sh --release

set -e

ORIGINAL_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

RELEASE_FLAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            echo "Usage: $0 [--release]"
            echo ""
            echo "Build tapauthd and the config GUI, start the daemon via ephemeral"
            echo "systemd units, and launch the GUI as an unprivileged user."
            echo ""
            echo "Options:"
            echo "  --release    Build in release mode (default: debug)"
            echo ""
            echo "Prerequisites:"
            echo "  - 'tapauthd' and 'tapauthd-clients' system user/group must exist"
            echo "    (run create-dev-users.sh)"
            echo "  - /var/lib/tapauth must be writable by tapauthd"
            echo "  - The PolKit action org.tapauth.config.admin should be configured,"
            echo "    or run as root (UID=0 fallback)"
            cd "$ORIGINAL_DIR"
            exit 0
            ;;
        --release)
            RELEASE_FLAG="--release"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth Config GUI - Build and Test                   ║"
echo "║         (Rootless mode: unprivileged GUI → daemon IPC)        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

BUILD_DIR="target"
if [ -n "$RELEASE_FLAG" ]; then
    BUILD_DIR="target/release"
else
    BUILD_DIR="target/debug"
fi
TAPAUTHD_BIN="${PROJECT_ROOT}/${BUILD_DIR}/tapauthd"
GUI_BIN="${PROJECT_ROOT}/${BUILD_DIR}/tapauth-config"
TAPAUTHD_SOCK_DIR="/run/tapauthd"
TAPAUTHD_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd-gui.sock"
CONFIG_DIR="/var/lib/tapauth"

# ── Prerequisites ──────────────────────────────────────────────────

if ! id tapauthd >/dev/null 2>&1; then
    echo "❌ System user 'tapauthd' not found."
    echo "   Run: sudo ./create-dev-users.sh"
    exit 1
fi
echo "✅ tapauthd user exists"

if ! getent group tapauthd-clients >/dev/null 2>&1; then
    echo "   Creating system group 'tapauthd-clients'"
    sudo groupadd --system tapauthd-clients || true
fi
echo "✅ tapauthd-clients group exists"

if [ ! -d "$CONFIG_DIR" ]; then
    echo "   Creating $CONFIG_DIR"
    sudo mkdir -p "$CONFIG_DIR"
    sudo chown tapauthd:tapauthd "$CONFIG_DIR"
    sudo chmod 0700 "$CONFIG_DIR"
fi
echo "✅ $CONFIG_DIR is ready"

# ── Build ──────────────────────────────────────────────────────────

echo ""
echo "==> Building tapauthd..."
cargo build $RELEASE_FLAG --manifest-path tapauthd/Cargo.toml

echo ""
echo "==> Building tapauth-config GUI..."
cargo build $RELEASE_FLAG --manifest-path client-config-gui/Cargo.toml

if [ ! -x "$TAPAUTHD_BIN" ]; then
    echo "❌ tapauthd binary not found at $TAPAUTHD_BIN"
    exit 1
fi
if [ ! -x "$GUI_BIN" ]; then
    echo "❌ tapauth-config binary not found at $GUI_BIN"
    exit 1
fi
echo "✅ Build complete"

# ── Cleanup ────────────────────────────────────────────────────────

TEMP_UNIT_DIR=""
TEMP_BIN_DIR=""
cleanup() {
    echo ""
    echo "==> Cleaning up..."
    sudo systemctl stop tapauthd-gui.service 2>/dev/null || true
    sudo systemctl stop tapauthd-gui.socket 2>/dev/null || true
    sudo rm -f /run/systemd/system/tapauthd-gui.socket 2>/dev/null || true
    sudo rm -f /run/systemd/system/tapauthd-gui.service 2>/dev/null || true
    sudo systemctl daemon-reload 2>/dev/null || true
    sudo rm -f "$TAPAUTHD_SOCK_PATH" 2>/dev/null || true
    if [ -n "$TEMP_UNIT_DIR" ] && [ -d "$TEMP_UNIT_DIR" ]; then
        sudo rm -rf "$TEMP_UNIT_DIR" 2>/dev/null || true
    fi
    if [ -n "$TEMP_BIN_DIR" ] && [ -d "$TEMP_BIN_DIR" ]; then
        sudo rm -rf "$TEMP_BIN_DIR" 2>/dev/null || true
    fi
    echo "✅ Cleanup complete."
    cd "$ORIGINAL_DIR"
}
trap cleanup EXIT

# ── Start daemon via ephemeral systemd units ───────────────────────

echo ""
echo "==> Starting tapauthd via ephemeral systemd units..."

# Ensure runtime directory exists
sudo mkdir -p "$TAPAUTHD_SOCK_DIR"
if getent group tapauthd-clients >/dev/null 2>&1; then
    sudo chgrp tapauthd-clients "$TAPAUTHD_SOCK_DIR" || true
fi
sudo chmod 0750 "$TAPAUTHD_SOCK_DIR"

# Create temporary directories for units and binary
TEMP_UNIT_DIR=$(mktemp -d -t tapauthd-gui-units.XXXXXX)
echo "    Temporary units directory: $TEMP_UNIT_DIR"

# Copy daemon binary to an executable location (avoid noexec mounts)
TEMP_BIN_DIR=$(sudo mktemp -d -p /run tapauthd-gui-bin.XXXXXX 2>/dev/null)
if [ -z "$TEMP_BIN_DIR" ] || [ ! -d "$TEMP_BIN_DIR" ]; then
    echo "❌ Failed to create temporary binary directory under /run"
    exit 1
fi
sudo chmod 0755 "$TEMP_BIN_DIR"
sudo install -m 0755 "$TAPAUTHD_BIN" "$TEMP_BIN_DIR/tapauthd"

# Stop any prior instances
sudo systemctl stop tapauthd-gui.service 2>/dev/null || true
sudo systemctl stop tapauthd-gui.socket 2>/dev/null || true
sudo rm -f /run/systemd/system/tapauthd-gui.socket 2>/dev/null || true
sudo rm -f /run/systemd/system/tapauthd-gui.service 2>/dev/null || true
sudo systemctl daemon-reload 2>/dev/null || true

# Write temporary socket unit
cat > "$TEMP_UNIT_DIR/tapauthd-gui.socket" << EOF
[Unit]
Description=TapAuth daemon IPC test socket (GUI dev)
PartOf=tapauthd-gui.service

[Socket]
ListenStream=$TAPAUTHD_SOCK_PATH
SocketUser=root
SocketGroup=tapauthd-clients
SocketMode=0660
DirectoryMode=0750
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
EOF

# Write temporary service unit
cat > "$TEMP_UNIT_DIR/tapauthd-gui.service" << EOF
[Unit]
Description=TapAuth authentication daemon (GUI dev)
Requires=tapauthd-gui.socket
Wants=bluetooth.target
After=dbus.service bluetooth.target network.target

[Service]
Type=simple
User=tapauthd
Group=tapauthd
Sockets=tapauthd-gui.socket
ExecStart=$TEMP_BIN_DIR/tapauthd
Restart=on-failure
Environment="RUST_LOG=${RUST_LOG:-debug}"

NoNewPrivileges=yes
PrivateTmp=no
ProtectSystem=no
ProtectHome=no

[Install]
WantedBy=multi-user.target
EOF

# Link and start
sudo systemctl link --runtime "$TEMP_UNIT_DIR/tapauthd-gui.socket" || { echo "❌ Failed to link socket unit"; exit 1; }
sudo systemctl link --runtime "$TEMP_UNIT_DIR/tapauthd-gui.service" || { echo "❌ Failed to link service unit"; exit 1; }
sudo systemctl daemon-reload || { echo "❌ systemd daemon-reload failed"; exit 1; }
sudo systemctl start tapauthd-gui.socket || { echo "❌ Failed to start socket"; exit 1; }

# Wait for socket
echo -n "    Waiting for socket"
for i in $(seq 1 50); do
    if sudo test -S "$TAPAUTHD_SOCK_PATH"; then
        echo ""
        echo "✅ Socket ready: $TAPAUTHD_SOCK_PATH"
        break
    fi
    echo -n "."
    sleep 0.1
done
if ! sudo test -S "$TAPAUTHD_SOCK_PATH"; then
    echo ""
    echo "❌ Socket did not appear.  Check daemon logs:"
    echo "   sudo journalctl -u tapauthd-gui.service -n 200 --no-pager"
    exit 1
fi

echo "    View logs: sudo journalctl -u tapauthd-gui.service -f"

# ── Run GUI ────────────────────────────────────────────────────────

echo ""
echo "==> Launching config GUI (as unprivileged user: $(whoami))"
echo "    The GUI connects to $TAPAUTHD_SOCK_PATH for all admin operations."
echo ""

export TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH"
exec "$GUI_BIN"
