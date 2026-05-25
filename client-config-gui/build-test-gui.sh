#!/bin/bash
# Build and test the TapAuth configuration GUI with a local tapauthd daemon.
# Uses ephemeral systemd units for socket activation (matching production),
# then launches the GUI as the current (unprivileged) user.
#
# Usage: ./build-test-gui.sh
#        ./build-test-gui.sh --release
#
# Intentionally avoid `set -e` to keep logs visible on failure; check critical
# steps manually.

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
TAPAUTHD_DEFAULT_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd.sock"
TAPAUTHD_GUI_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd-gui.sock"
CONFIG_DIR="/var/lib/tapauth"
CLIENT_KEY_FILE="${CONFIG_DIR}/client_key"
CLIENT_CSK_FILE="${CONFIG_DIR}/client_symmetric_key"
POLICY_FILE="${PROJECT_ROOT}/tapauthd/org.tapauth.config.admin.policy"
POLICY_INSTALL_DIR="/usr/local/share/polkit-1/actions"
LOG_FILE="/tmp/tapauthd-gui-test.log"

# ── Prerequisites ──────────────────────────────────────────────────

if ! id tapauthd >/dev/null 2>&1; then
    echo "❌ System user 'tapauthd' not found."
    echo "   Run: sudo ./create-dev-users.sh"
    cd "$ORIGINAL_DIR"
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

# Install PolKit policy so tapauthd can check authorizations for action owners
if [ -f "$POLICY_FILE" ]; then
    sudo mkdir -p "$POLICY_INSTALL_DIR"
    sudo cp "$POLICY_FILE" "$POLICY_INSTALL_DIR/"
    echo "✅ PolKit policy installed"
fi

# ── Build ──────────────────────────────────────────────────────────

echo ""
echo "==> Building tapauthd..."
cargo build $RELEASE_FLAG --manifest-path tapauthd/Cargo.toml

echo ""
echo "==> Building tapauth-config GUI..."
cargo build $RELEASE_FLAG --manifest-path client-config-gui/Cargo.toml

if [ ! -x "$TAPAUTHD_BIN" ]; then
    echo "❌ tapauthd binary not found at $TAPAUTHD_BIN"
    cd "$ORIGINAL_DIR"
    exit 1
fi
if [ ! -x "$GUI_BIN" ]; then
    echo "❌ tapauth-config binary not found at $GUI_BIN"
    cd "$ORIGINAL_DIR"
    exit 1
fi
echo "✅ Build complete"

# ── Cleanup ────────────────────────────────────────────────────────

TEMP_UNIT_DIR=""
TEMP_BIN_DIR=""
DAEMON_PID=""
ACTIVATION_MODE="manual"

cleanup() {
    echo ""
    echo "==> Cleaning up temporary files..."
    # Grace period so daemon can finish background cleanup (BLE disconnects)
    local GRACE_SECONDS="1"
    if [ -n "$TAPAUTHD_GRACE_MS" ]; then
        GRACE_SECONDS=$(awk -v ms="$TAPAUTHD_GRACE_MS" 'BEGIN{ printf "%.3f", ms/1000 }')
    elif [ -n "$TAPAUTHD_GRACE_SECONDS" ]; then
        GRACE_SECONDS="$TAPAUTHD_GRACE_SECONDS"
    fi
    echo "    Granting daemon grace period: ${GRACE_SECONDS}s before teardown"
    sleep "$GRACE_SECONDS"

    case "$ACTIVATION_MODE" in
        systemd-temp)
            echo "    Stopping temporary systemd units..."
            sudo systemctl stop tapauthd-gui.service 2>/dev/null || true
            sudo systemctl stop tapauthd-gui.socket 2>/dev/null || true
            sudo rm -f /run/systemd/system/tapauthd-gui.socket 2>/dev/null || true
            sudo rm -f /run/systemd/system/tapauthd-gui.service 2>/dev/null || true
            sudo systemctl daemon-reload 2>/dev/null || true
            sudo rm -f "$TAPAUTHD_GUI_SOCK_PATH" 2>/dev/null || true
            if [ -n "$TEMP_UNIT_DIR" ] && [ -d "$TEMP_UNIT_DIR" ]; then
                sudo rm -rf "$TEMP_UNIT_DIR" 2>/dev/null || true
            fi
            if [ -n "$TEMP_BIN_DIR" ] && [ -d "$TEMP_BIN_DIR" ]; then
                sudo rm -rf "$TEMP_BIN_DIR" 2>/dev/null || true
            fi
            ;;
        manual)
            if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
                echo "    Stopping tapauthd (PID=$DAEMON_PID)..."
                kill "$DAEMON_PID" 2>/dev/null || true
                wait "$DAEMON_PID" 2>/dev/null || true
            fi
            sudo rm -f "$TAPAUTHD_SOCK_PATH" 2>/dev/null || true
            ;;
        systemd-existing)
            echo "    Using existing systemd socket; no socket cleanup needed."
            ;;
    esac
    echo "✅ Cleanup complete."
    cd "$ORIGINAL_DIR"
}
trap cleanup EXIT

# ── Start daemon ───────────────────────────────────────────────────

echo ""
echo "==> Preparing tapauthd IPC socket"

# Ensure runtime directory exists (world-readable for dev so unprivileged
# GUI can reach the socket; production uses tapauthd-clients group instead)
sudo mkdir -p "$TAPAUTHD_SOCK_DIR" || true
if getent group tapauthd-clients >/dev/null 2>&1; then
    sudo chgrp tapauthd-clients "$TAPAUTHD_SOCK_DIR" || true
fi
sudo chmod 0755 "$TAPAUTHD_SOCK_DIR" || true

# Detect whether TapAuth is configured (keys exist and are correct size)
UNCONFIGURED=0
if [ ! -f "$CLIENT_KEY_FILE" ] || [ "$(stat -c%s "$CLIENT_KEY_FILE" 2>/dev/null || echo 0)" -ne 32 ]; then
    UNCONFIGURED=1
fi
if [ ! -f "$CLIENT_CSK_FILE" ] || [ "$(stat -c%s "$CLIENT_CSK_FILE" 2>/dev/null || echo 0)" -ne 32 ]; then
    UNCONFIGURED=1
fi

TAPAUTHD_SOCK_PATH="$TAPAUTHD_DEFAULT_SOCK_PATH"

if command -v systemctl >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
    if sudo systemctl is-active --quiet tapauthd.socket; then
        ACTIVATION_MODE="systemd-existing"
        TAPAUTHD_SOCK_PATH="$TAPAUTHD_DEFAULT_SOCK_PATH"
        echo "    Using existing systemd socket: $TAPAUTHD_SOCK_PATH"
        echo "    View logs with: sudo journalctl -u tapauthd.service -f"
    else
        ACTIVATION_MODE="systemd-temp"
        TAPAUTHD_SOCK_PATH="$TAPAUTHD_GUI_SOCK_PATH"
        echo "    Creating temporary systemd units for testing..."

        # Create temporary directories for units and binary
        TEMP_UNIT_DIR=$(mktemp -d -t tapauthd-gui-units.XXXXXX)
        echo "    Temporary units directory: $TEMP_UNIT_DIR"

        # Install binary in executable location (avoid noexec mounts on /tmp, /home)
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

        # Write temporary socket unit (world-accessible for dev convenience;
        # production uses tapauthd-clients group with 0660 instead)
        cat > "$TEMP_UNIT_DIR/tapauthd-gui.socket" << EOF
[Unit]
Description=TapAuth daemon IPC test socket (GUI dev)
PartOf=tapauthd-gui.service

[Socket]
ListenStream=$TAPAUTHD_GUI_SOCK_PATH
SocketUser=root
SocketGroup=tapauthd-clients
SocketMode=0666
DirectoryMode=0755
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
        echo "    Started temporary socket: $TAPAUTHD_SOCK_PATH"
        echo "    View logs with: sudo journalctl -u tapauthd-gui.service -f"
    fi
else
    echo "    systemd not available; starting daemon manually"
    echo "    Ensuring runtime directory at $TAPAUTHD_SOCK_DIR"
    sudo mkdir -p "$TAPAUTHD_SOCK_DIR" || true
    if getent group tapauthd-clients >/dev/null 2>&1; then
        sudo chgrp tapauthd-clients "$TAPAUTHD_SOCK_DIR" || true
    fi
    sudo chmod 0755 "$TAPAUTHD_SOCK_DIR" || true

    TAPAUTHD_SOCK_PATH="$TAPAUTHD_DEFAULT_SOCK_PATH"
    echo "    Launching daemon with TAPAUTHD_SOCK=$TAPAUTHD_SOCK_PATH"
    echo "    Daemon logs will be written to $LOG_FILE"
    sudo env RUST_LOG="${RUST_LOG:-debug}" TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH" "$TAPAUTHD_BIN" > "$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
fi

# Wait for socket readiness
echo -n "    Waiting for socket to appear"
for i in $(seq 1 50); do
    if sudo test -S "$TAPAUTHD_SOCK_PATH"; then
        echo ""
        echo "✅ Socket ready: $TAPAUTHD_SOCK_PATH"
        # In manual mode the daemon creates the socket as tapauthd:tapauthd 0660.
        # Make it world-accessible so the unprivileged GUI can connect.
        if [ "$ACTIVATION_MODE" = "manual" ]; then
            sudo chmod 0666 "$TAPAUTHD_SOCK_PATH" 2>/dev/null || true
        fi
        break
    fi
    echo -n "."
    sleep 0.1
done
if ! sudo test -S "$TAPAUTHD_SOCK_PATH"; then
    echo ""
    echo "❌ Socket did not appear at $TAPAUTHD_SOCK_PATH"
    if [ "$ACTIVATION_MODE" = "manual" ]; then
        echo "   ➤ Check daemon logs: tail -n +1 -f $LOG_FILE"
    else
        UNIT_NAME="tapauthd.service"
        [ "$ACTIVATION_MODE" = "systemd-temp" ] && UNIT_NAME="tapauthd-gui.service"
        echo "   ➤ Check daemon logs: sudo journalctl -u $UNIT_NAME -n 200 --no-pager"
    fi
    exit 1
fi

# Health check: only if configured. Otherwise skip to avoid failing on unconfigured hosts.
if [ "$UNCONFIGURED" -eq 0 ]; then
    echo "    Performing daemon health check..."
    sudo python3 - << PY || { echo "❌ Health check failed"; exit 1; }
import socket, struct
path = "$TAPAUTHD_SOCK_PATH"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.5)
s.connect(path)
# send zero-length frame (u32 BE = 0)
s.sendall(struct.pack('>I', 0))
s.close()
print("OK")
PY
    echo "✅ Daemon health check passed"
else
    echo "    Skipping daemon health check (TapAuth not configured: missing keys)"
fi

if [ "$ACTIVATION_MODE" = "manual" ]; then
    echo "    ➤ View daemon logs with: tail -f $LOG_FILE"
else
    UNIT_NAME="tapauthd.service"
    [ "$ACTIVATION_MODE" = "systemd-temp" ] && UNIT_NAME="tapauthd-gui.service"
    echo "    ➤ View daemon logs with: sudo journalctl -u $UNIT_NAME -f"
fi

# ── Run GUI ────────────────────────────────────────────────────────

echo ""
echo "==> Launching config GUI (as unprivileged user: $(whoami))"
echo "    The GUI connects to $TAPAUTHD_SOCK_PATH for all admin operations."
echo ""

export TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH"
exec "$GUI_BIN"
