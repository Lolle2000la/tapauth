#!/bin/bash
# Integration test runner for TapAuth daemon
# Sets up temporary daemon via systemd or manual mode, runs tests, cleans up

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         TapAuth Integration Tests                             ║"
echo "║         (Non-interactive daemon IPC validation)               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

TAPAUTHD_BIN="${PROJECT_ROOT}/target/release/tapauthd"
TAPAUTHD_SOCK_DIR="/run/tapauthd"
TAPAUTHD_TEST_SOCK_PATH="${TAPAUTHD_SOCK_DIR}/tapauthd-test.sock"
ACTIVATION_MODE="manual"
DAEMON_PID=""
TEMP_UNIT_DIR=""

# Cleanup function
cleanup() {
    echo ""
    echo "==> Cleaning up test environment..."
    case "$ACTIVATION_MODE" in
        systemd-temp)
            sudo systemctl stop tapauthd-test.service 2>/dev/null || true
            sudo systemctl stop tapauthd-test.socket 2>/dev/null || true
            sudo systemctl disable tapauthd-test.socket 2>/dev/null || true
            sudo systemctl daemon-reload 2>/dev/null || true
            sudo rm -f "$TAPAUTHD_TEST_SOCK_PATH" 2>/dev/null || true
            if [ -n "$TEMP_UNIT_DIR" ] && [ -d "$TEMP_UNIT_DIR" ]; then
                sudo rm -rf "$TEMP_UNIT_DIR" 2>/dev/null || true
            fi
            ;;
        manual)
            if [ -n "$DAEMON_PID" ]; then
                echo "    Stopping tapauthd (PID=$DAEMON_PID)..."
                kill "$DAEMON_PID" 2>/dev/null || true
                wait "$DAEMON_PID" 2>/dev/null || true
            fi
            sudo rm -f "$TAPAUTHD_TEST_SOCK_PATH" 2>/dev/null || true
            ;;
        systemd-existing)
            echo "    Using existing systemd socket; no cleanup needed."
            ;;
    esac
    echo "✅ Cleanup complete."
}
trap cleanup EXIT

# Build the daemon and tests
echo "==> Building daemon and integration tests..."
cargo build --release -p tapauthd || { echo "❌ Daemon build failed"; exit 1; }
cargo test --test integration_test --no-run || { echo "❌ Test build failed"; exit 1; }
echo "✅ Build successful"

# Set up daemon
echo ""
echo "==> Setting up test daemon..."

if command -v systemctl >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
    if sudo systemctl is-active --quiet tapauthd.socket; then
        ACTIVATION_MODE="systemd-existing"
        export TAPAUTHD_SOCK="${TAPAUTHD_SOCK_DIR}/tapauthd.sock"
        echo "    Using existing systemd socket: $TAPAUTHD_SOCK"
    else
        ACTIVATION_MODE="systemd-temp"
        export TAPAUTHD_SOCK="$TAPAUTHD_TEST_SOCK_PATH"
        echo "    Creating temporary systemd units..."

        # Ensure tapauthd user exists
        if ! id tapauthd >/dev/null 2>&1; then
            sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd || true
        fi

        # Create temp directory for units
        TEMP_UNIT_DIR=$(mktemp -d -t tapauthd-test-units.XXXXXX)

        # Socket unit
        cat > "$TEMP_UNIT_DIR/tapauthd-test.socket" << EOF
[Unit]
Description=TapAuth daemon IPC test socket

[Socket]
ListenStream=$TAPAUTHD_TEST_SOCK_PATH
SocketUser=root
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
EOF

        # Service unit
        cat > "$TEMP_UNIT_DIR/tapauthd-test.service" << EOF
[Unit]
Description=TapAuth authentication daemon (test)
Requires=tapauthd-test.socket
After=network.target bluetooth.target

[Service]
Type=simple
User=root
Group=root
Sockets=tapauthd-test.socket
ExecStart=$TAPAUTHD_BIN
Restart=on-failure
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
EOF

        sudo systemctl link --runtime "$TEMP_UNIT_DIR/tapauthd-test.socket" || exit 1
        sudo systemctl link --runtime "$TEMP_UNIT_DIR/tapauthd-test.service" || exit 1
        sudo systemctl daemon-reload || exit 1
        sudo systemctl start tapauthd-test.socket || exit 1
        echo "    Started temporary systemd socket: $TAPAUTHD_SOCK"
    fi
else
    ACTIVATION_MODE="manual"
    export TAPAUTHD_SOCK="$TAPAUTHD_TEST_SOCK_PATH"
    echo "    Starting daemon manually..."
    
    sudo mkdir -p "$TAPAUTHD_SOCK_DIR" || true
    sudo chmod 0755 "$TAPAUTHD_SOCK_DIR" || true
    
    if ! id tapauthd >/dev/null 2>&1; then
        sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin tapauthd || true
    fi
    
    sudo env RUST_LOG=info TAPAUTHD_SOCK="$TAPAUTHD_SOCK" "$TAPAUTHD_BIN" >/dev/null 2>&1 &
    DAEMON_PID=$!
fi

# Wait for socket
echo -n "    Waiting for socket"
for i in {1..50}; do
    if [ -S "$TAPAUTHD_SOCK" ]; then echo ""; break; fi
    echo -n "."; sleep 0.1
done
if [ ! -S "$TAPAUTHD_SOCK" ]; then
    echo ""; echo "❌ Socket did not appear: $TAPAUTHD_SOCK"; exit 1
fi
echo "✅ Daemon ready at $TAPAUTHD_SOCK"

# Run the integration tests
echo ""
echo "==> Running integration tests..."
echo "---------------------------------------------------------------------"

# Set timeout for individual tests
export RUST_TEST_THREADS=1  # Run tests serially to avoid race conditions

cargo test --test integration_test -- --nocapture --test-threads=1

TEST_EXIT_CODE=$?

echo "---------------------------------------------------------------------"
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All integration tests passed!"
else
    echo "⚠️  Some tests failed (exit code: $TEST_EXIT_CODE)"
fi

exit $TEST_EXIT_CODE
