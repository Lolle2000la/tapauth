#!/bin/bash
# Build and test the TapAuth configuration GUI with a local tapauthd daemon.
# Builds tapauthd with fallback-socket for manual testing, starts it,
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
TAPAUTHD_EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            echo "Usage: $0 [--release]"
            echo ""
            echo "Build tapauthd and the config GUI, start the daemon, and launch the GUI."
            echo "Runs the GUI as an unprivileged user talking to daemon via IPC."
            echo ""
            echo "Options:"
            echo "  --release    Build in release mode (default: debug)"
            echo ""
            echo "Prerequisites:"
            echo "  - 'tapauthd' system user must exist (run create-dev-users.sh)"
            echo "  - /var/lib/tapauth must be writable by tapauthd (daemon manages it)"
            echo "  - The PolKit action org.tapauth.config.admin should be configured,"
            echo "    or the GUI must be run as root (UID=0 fallback)"
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
TAPAUTHD_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd.sock"
TAPAUTHD_LOG="/tmp/tapauthd-test-gui.log"
CONFIG_DIR="/var/lib/tapauth"

# ── Prerequisites ──────────────────────────────────────────────────

if ! id tapauthd >/dev/null 2>&1; then
    echo "❌ System user 'tapauthd' not found."
    echo "   Run: sudo ./create-dev-users.sh"
    exit 1
fi
echo "✅ tapauthd user exists"

if [ ! -d "$CONFIG_DIR" ]; then
    echo "   Creating $CONFIG_DIR"
    sudo mkdir -p "$CONFIG_DIR"
    sudo chown tapauthd:tapauthd "$CONFIG_DIR"
    sudo chmod 0700 "$CONFIG_DIR"
fi
echo "✅ $CONFIG_DIR is ready"

# ── Build ──────────────────────────────────────────────────────────

echo ""
echo "==> Building tapauthd (with fallback-socket for manual testing)..."
cargo build $RELEASE_FLAG --manifest-path tapauthd/Cargo.toml \
    --features fallback-socket --no-default-features

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

DAEMON_PID=""
cleanup() {
    echo ""
    echo "==> Cleaning up..."
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "    Stopping tapauthd (PID=$DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    sudo rm -f "$TAPAUTHD_SOCK_PATH" 2>/dev/null || true
    echo "✅ Cleanup complete."
    cd "$ORIGINAL_DIR"
}
trap cleanup EXIT

# ── Start daemon ───────────────────────────────────────────────────

echo ""
echo "==> Starting tapauthd (manual, fallback-socket)..."

sudo mkdir -p "$TAPAUTHD_SOCK_DIR"
sudo chmod 0750 "$TAPAUTHD_SOCK_DIR"

echo "    Socket:  $TAPAUTHD_SOCK_PATH"
echo "    Log:     $TAPAUTHD_LOG"

sudo env \
    RUST_LOG="${RUST_LOG:-debug}" \
    TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH" \
    "$TAPAUTHD_BIN" \
    > "$TAPAUTHD_LOG" 2>&1 &
DAEMON_PID=$!

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
    echo "❌ Socket did not appear. Check daemon log:"
    echo "   tail -n +1 $TAPAUTHD_LOG"
    exit 1
fi

# ── Run GUI ────────────────────────────────────────────────────────

echo ""
echo "==> Launching config GUI (as unprivileged user: $(whoami))"
echo "    The GUI connects to $TAPAUTHD_SOCK_PATH for all admin operations."
echo "    Daemon logs: tail -f $TAPAUTHD_LOG"
echo ""

export TAPAUTHD_SOCK="$TAPAUTHD_SOCK_PATH"
exec "$GUI_BIN"
