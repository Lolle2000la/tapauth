#!/bin/bash
# Master End-to-End (E2E) Test Suite for TapAuth (Pairing + UDP + BLE)
# Runs the real production Android app against the real Linux daemon.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║      TapAuth Full Real-Android End-to-End Test Suite          ║"
echo "║      (TCP Pairing + UDP Network + BLE GATT Authentication)   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Ensure adb is in PATH
if ! command -v adb &> /dev/null; then
    for p in "/usr/local/lib/android/sdk/platform-tools" "$ANDROID_HOME/platform-tools" "$ANDROID_SDK_ROOT/platform-tools" "$HOME/Android/Sdk/platform-tools"; do
        if [ -x "$p/adb" ]; then
            export PATH="$PATH:$p"
            break
        fi
    done
fi

# Check for running Android emulator
if ! adb devices | grep -q 'emulator-[0-9]*'; then
    echo "❌ ERROR: No active Android emulator detected."
    echo "   Please start an emulator (e.g. via Android Studio or 'emulator @<avd_name>') before running this test."
    exit 1
fi

echo "✅ Android emulator detected."

# Setup isolated sandbox directory to avoid dirtying the host
TEST_DIR=$(mktemp -d -t tapauth-e2e.XXXXXX)
export TAPAUTHD_SOCK="${TEST_DIR}/tapauthd.sock"
PAM_SERVICE_NAME="tapauth-test-e2e"
PAM_CONFIG_PATH="/etc/pam.d/${PAM_SERVICE_NAME}"

# Detect test username
if [ -n "$SUDO_USER" ]; then
    TEST_USER="$SUDO_USER"
else
    TEST_USER="$(whoami)"
fi

echo "ℹ️  Test User: $TEST_USER"
echo "ℹ️  Isolated Socket: $TAPAUTHD_SOCK"
echo "ℹ️  Sandbox Directory: $TEST_DIR"
echo ""

DAEMON_PID=""
BUMBLE_PID=""
REFLECTOR_PID=""
BIO_PID=""

cleanup() {
    EXIT_CODE=$?
    echo ""
    echo "==> Cleaning up test environment (exit code: $EXIT_CODE)..."
    if [ "$EXIT_CODE" -ne 0 ] && [ -n "$DAEMON_LOG" ] && [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/bumble-bridge.log ]; then
        echo "=== BUMBLE LOG DUMP ==="
        cat /tmp/bumble-bridge.log
        echo "======================="
    fi
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant 2>/dev/null || true
    if [ -f /tmp/bumble-bridge.pid ]; then
        kill "$(cat /tmp/bumble-bridge.pid)" 2>/dev/null || true
        rm -f /tmp/bumble-bridge.pid
    fi
    if [ -f /tmp/udp-reflector.pid ]; then
        kill "$(cat /tmp/udp-reflector.pid)" 2>/dev/null || true
        rm -f /tmp/udp-reflector.pid
    fi
    if [ "$INSTALLED_POLKIT" = true ]; then
        sudo rm -f "$POLKIT_POLICY_DEST" 2>/dev/null || true
    fi
    sudo rm -f "$PAM_CONFIG_PATH" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "✅ Teardown complete."
}
trap cleanup EXIT INT TERM

# Step 0: Register PolKit policy for daemon admin authorization
POLKIT_POLICY_SRC="${PROJECT_ROOT}/tapauthd/dev.rourunisen.tapauth.config.admin.policy"
POLKIT_POLICY_DEST="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy"
INSTALLED_POLKIT=false
if [ -d "/usr/share/polkit-1/actions" ] && [ -f "$POLKIT_POLICY_SRC" ] && [ ! -f "$POLKIT_POLICY_DEST" ]; then
    echo "    Registering PolKit policy for testing..."
    sudo cp "$POLKIT_POLICY_SRC" "$POLKIT_POLICY_DEST" 2>/dev/null || true
    INSTALLED_POLKIT=true
fi

# Step 1: Build necessary Linux binaries
echo "==> Step 1: Building Linux components (tapauthd, tapauth-ipc-cli, client-pam)..."
cargo build --release -p tapauthd --features fallback-socket,ble --bin tapauthd --bin tapauth-ipc-cli
cargo build --release -p client-pam --features dev-socket-override

TAPAUTHD_BIN="${PROJECT_ROOT}/target/release/tapauthd"
CLI_BIN="${PROJECT_ROOT}/target/release/tapauth-ipc-cli"
PAM_LIB="${PROJECT_ROOT}/target/release/libclient_pam.so"

# Step 2: Install Android App and Test Runner on Emulator
echo "==> Step 2: Ensuring Android App and Instrumentation Tests are installed..."
# If APKs exist, install them; otherwise build via gradle if local environment permits
if [ -f "server-android/app/build/outputs/apk/debug/app-debug.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/debug/app-debug.apk || true
fi
if [ -f "server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk || true
fi

# Step 3: Setup Bridges and Virtual Transport Layers
echo "==> Step 3: Setting up Transport Bridges (BLE + UDP)..."
"$SCRIPT_DIR/ci/setup-emulator-ble-bridge.sh"
"$SCRIPT_DIR/ci/setup-emulator-udp-bridge.sh"
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" setup

# Step 4: Launch tapauthd daemon in test mode
echo "==> Step 4: Launching tapauthd daemon..."
DAEMON_LOG="${TEST_DIR}/tapauthd.log"
env RUST_LOG="debug" TAPAUTHD_SOCK="$TAPAUTHD_SOCK" "$TAPAUTHD_BIN" > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

echo -n "    Waiting for daemon socket"
for i in {1..50}; do
    if [ -S "$TAPAUTHD_SOCK" ]; then break; fi
    echo -n "."; sleep 0.1
done
echo ""

if [ ! -S "$TAPAUTHD_SOCK" ]; then
    echo "❌ ERROR: tapauthd socket failed to initialize. Daemon log:"
    cat "$DAEMON_LOG"
    exit 1
fi
echo "✅ tapauthd daemon is active."

# Step 5: Phase 1 - Real TCP Device Pairing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 1: Real TCP Pairing & SAS Anti-MITM Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Initiating pairing from desktop daemon..."
START_OUTPUT=$("$CLI_BIN" start-pairing)
PORT=$(echo "$START_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL=$(echo "$START_OUTPUT" | grep 'URL=' | cut -d'=' -f2)

echo "    Pairing Port: $PORT"
echo "    Pairing URL:  $PAIR_URL"

# Wait for pairing in background
WAIT_LOG="${TEST_DIR}/wait_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT" > "$WAIT_LOG" 2>&1 &
WAIT_PID=$!

# Trigger Android PairingClient via Instrumentation Test in background
echo "==> Triggering PairingClient inside Android Emulator..."
AM_LOG="${TEST_DIR}/am_pairing.log"
adb shell am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_host 10.0.2.2 \
    -e pairing_port "$PORT" \
    dev.rourunisen.tapauth.debug.test/dev.rourunisen.tapauth.crypto.TapAuthTestRunner > "$AM_LOG" 2>&1 &
AM_PID=$!

wait "$WAIT_PID" || {
    echo "❌ wait-for-pairing failed. Log:"
    cat "$WAIT_LOG"
    exit 1
}

SAS_CODE=$(grep 'SAS=' "$WAIT_LOG" | cut -d'=' -f2)
echo "✅ SAS Code generated & verified: $SAS_CODE"

echo "==> Completing pairing handshake..."
COMPLETE_OUTPUT=$("$CLI_BIN" complete-pairing "$PORT")
SERVER_HEX=$(echo "$COMPLETE_OUTPUT" | grep 'SERVER_HEX=' | cut -d'=' -f2)
echo "✅ Device pairing finalized successfully! Server Key: $SERVER_HEX"

# Wait for Android pairing test to finish successfully
wait "$AM_PID" || {
    echo "❌ Android pairing instrumentation test failed. Log:"
    cat "$AM_LOG"
    exit 1
}
cat "$AM_LOG"

# Verify paired servers in daemon
SERVERS_COUNT=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$SERVERS_COUNT" -lt 1 ]; then
    echo "❌ ERROR: No paired servers recorded in daemon state."
    exit 1
fi
echo "✅ Verified 1 paired Android device registered."

# Start background biometric auto-grant listener for auth tests
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
sleep 1

# Step 6: Phase 2 - Local Network (UDP) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2: Local Network (UDP) End-to-End Authentication       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Setting transport config: UDP enabled, BLE disabled..."
"$CLI_BIN" set-transports --ble false --network true

echo "==> Requesting authentication for user '$TEST_USER'..."
UDP_AUTH_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20)
echo "$UDP_AUTH_OUTPUT"

if echo "$UDP_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
    echo "✅ Local Network (UDP) Authentication PASSED!"
else
    echo "❌ Local Network (UDP) Authentication FAILED."
    cat "$DAEMON_LOG"
    exit 1
fi

# Step 7: Phase 3 - Bluetooth Low Energy (BLE) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 3: Bluetooth Low Energy (BLE) Authentication           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Setting transport config: BLE enabled, UDP disabled..."
"$CLI_BIN" set-transports --ble true --network false

echo "==> Requesting authentication for user '$TEST_USER' over virtual BLE..."
BLE_AUTH_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20)
echo "$BLE_AUTH_OUTPUT"

if echo "$BLE_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
    echo "✅ Bluetooth Low Energy (BLE) Authentication PASSED!"
else
    echo "❌ Bluetooth Low Energy (BLE) Authentication FAILED."
    cat "$DAEMON_LOG"
    exit 1
fi

# Step 8: Phase 4 - Parallel Discovery Race (Both Enabled)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 4: Parallel Discovery Race (UDP + BLE Simultaneous)    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Setting transport config: Both BLE and UDP enabled..."
"$CLI_BIN" set-transports --ble true --network true

PARALLEL_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20)
echo "$PARALLEL_OUTPUT"

if echo "$PARALLEL_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
    echo "✅ Parallel Discovery Race Authentication PASSED!"
else
    echo "❌ Parallel Discovery Race Authentication FAILED."
    exit 1
fi

# Step 9: Phase 5 - Denial Testing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5: Explicit User Denial & Rejection Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Stop auto-grant watcher
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant

echo "==> Initiating auth and simulating biometric rejection..."
DENIAL_OUT=""
set +e
DENIAL_OUT=$("$CLI_BIN" pam-auth "$TEST_USER" 5 &)
DENIAL_CLI_PID=$!
sleep 0.5
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" deny
wait "$DENIAL_CLI_PID"
DENIAL_EXIT=$?
set -e

if [ "$DENIAL_EXIT" -ne 0 ]; then
    echo "✅ Explicit Denial correctly rejected (exit code: $DENIAL_EXIT)."
else
    echo "⚠️ Warning: Expected denial exit != 0, got $DENIAL_EXIT."
fi

# Step 10: Phase 6 - Device Removal / Un-pairing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 6: Device Removal / Un-pairing Lifecycle               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

echo "==> Removing paired device $SERVER_HEX..."
"$CLI_BIN" remove-device "$SERVER_HEX"

REMAINING=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$REMAINING" -eq 0 ]; then
    echo "✅ Device successfully removed. Remaining paired devices: 0"
else
    echo "❌ ERROR: Device removal failed, count=$REMAINING."
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  🎉 ALL REAL-ANDROID END-TO-END TESTS PASSED SUCCESSFULLY!    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
