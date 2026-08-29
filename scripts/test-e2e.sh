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
export TAPAUTH_STATE_DIR="${TEST_DIR}/state"
export TAPAUTH_DEV_MODE=1
export DAEMON_LOG="${TEST_DIR}/tapauthd.log"
mkdir -p "$TAPAUTH_STATE_DIR"
chmod 700 "$TAPAUTH_STATE_DIR"

PAM_SERVICE_NAME="tapauth-test-e2e"
PAM_CONFIG_PATH="/etc/pam.d/${PAM_SERVICE_NAME}"

# Detect test username (matches caller UID for daemon IPC authorization)
TEST_USER="$(whoami)"

echo "ℹ️  Test User: $TEST_USER"
echo "ℹ️  Isolated Socket: $TAPAUTHD_SOCK"
echo "ℹ️  State Directory: $TAPAUTH_STATE_DIR"
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
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/udp-reflector.log ]; then
        echo "=== UDP REFLECTOR LOG DUMP ==="
        cat /tmp/udp-reflector.log
        echo "=============================="
    fi
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/bumble-bridge.log ]; then
        echo "=== BUMBLE LOG DUMP ==="
        cat /tmp/bumble-bridge.log
        echo "======================="
    fi
    if [ "$EXIT_CODE" -ne 0 ]; then
        echo "=== ANDROID LOGCAT DUMP ==="
        adb logcat -d -v time -s AuthenticationService:* TapAuthApplication:* PairingClient:* BiometricPromptActivity:* TapAuthCrypto:* 2>/dev/null || true
        echo "==========================="
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
    if [ -w "$PAM_CONFIG_PATH" ]; then
        rm -f "$PAM_CONFIG_PATH" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "✅ Teardown complete."
}
trap cleanup EXIT INT TERM

# Step 0: Register PolKit policy if permissions allow
POLKIT_POLICY_SRC="${PROJECT_ROOT}/tapauthd/dev.rourunisen.tapauth.config.admin.policy"
POLKIT_POLICY_DEST="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy"
INSTALLED_POLKIT=false
if [ -d "/usr/share/polkit-1/actions" ] && [ -w "/usr/share/polkit-1/actions" ] && [ -f "$POLKIT_POLICY_SRC" ] && [ ! -f "$POLKIT_POLICY_DEST" ]; then
    echo "    Registering PolKit policy for testing..."
    cp "$POLKIT_POLICY_SRC" "$POLKIT_POLICY_DEST" 2>/dev/null || true
    INSTALLED_POLKIT=true
fi

# Step 1: Build necessary Linux binaries
echo "==> Step 1: Building Linux components (tapauthd, tapauth-ipc-cli, client-pam)..."
cargo build -p tapauthd --features fallback-socket,ble --bin tapauthd --bin tapauth-ipc-cli
cargo build -p client-pam --features dev-socket-override

TAPAUTHD_BIN="${PROJECT_ROOT}/target/debug/tapauthd"
CLI_BIN="${PROJECT_ROOT}/target/debug/tapauth-ipc-cli"
PAM_LIB="${PROJECT_ROOT}/target/debug/libclient_pam.so"

# Step 2: Install Android App and Test Runner on Emulator
echo "==> Step 2: Ensuring Android App and Instrumentation Tests are installed..."
# If APKs exist, install them; otherwise build via gradle if local environment permits
if [ -f "server-android/app/build/outputs/apk/debug/app-debug.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/debug/app-debug.apk || true
fi
if [ -f "server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk || true
fi

echo "==> Granting runtime permissions to Android app..."
adb shell pm grant dev.rourunisen.tapauth.debug android.permission.POST_NOTIFICATIONS 2>/dev/null || true
adb shell pm grant dev.rourunisen.tapauth.debug android.permission.ACCESS_FINE_LOCATION 2>/dev/null || true
adb shell pm grant dev.rourunisen.tapauth.debug android.permission.BLUETOOTH_CONNECT 2>/dev/null || true
adb shell pm grant dev.rourunisen.tapauth.debug android.permission.BLUETOOTH_ADVERTISE 2>/dev/null || true
adb shell pm grant dev.rourunisen.tapauth.debug android.permission.BLUETOOTH_SCAN 2>/dev/null || true

# Step 3: Setup Bridges and Virtual Transport Layers
echo "==> Step 3: Setting up Transport Bridges (BLE + UDP)..."
"$SCRIPT_DIR/ci/setup-emulator-ble-bridge.sh"
"$SCRIPT_DIR/ci/setup-emulator-udp-bridge.sh"
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" setup

# Step 4: Launch tapauthd daemon in test mode
echo "==> Step 4: Launching tapauthd daemon..."
env TAPAUTH_DEV_MODE="1" TAPAUTH_LOG_LEVEL="debug" RUST_LOG="debug" TAPAUTHD_SOCK="$TAPAUTHD_SOCK" "$TAPAUTHD_BIN" > "$DAEMON_LOG" 2>&1 &
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
echo "    Desktop Derived SAS: $SAS_CODE"

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

# Verify SAS matching between Desktop and Android
ANDROID_SAS=$(grep -o 'ANDROID_DERIVED_SAS=[0-9-]*' "$AM_LOG" | head -n1 | cut -d'=' -f2 || true)
if [ -z "$ANDROID_SAS" ]; then
    ANDROID_SAS=$(adb shell run-as dev.rourunisen.tapauth.debug cat files/derived_sas.txt 2>/dev/null | tr -d '\r\n' || true)
fi
if [ -z "$ANDROID_SAS" ]; then
    ANDROID_SAS=$(adb logcat -d | grep -o 'Derived SAS: [0-9-]*' | tail -n1 | cut -d':' -f2 | tr -d ' \r\n' || true)
fi
echo "    Android Derived SAS: $ANDROID_SAS"

if [ -n "$SAS_CODE" ] && [ -n "$ANDROID_SAS" ] && [ "$ANDROID_SAS" = "$SAS_CODE" ]; then
    echo "✅ SAS Anti-MITM Verification PASSED! Both sides derived identical code: $SAS_CODE"
else
    echo "❌ ERROR: SAS Anti-MITM verification mismatch! Desktop=$SAS_CODE, Android=$ANDROID_SAS"
    exit 1
fi

# Verify paired servers in daemon
SERVERS_COUNT=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$SERVERS_COUNT" -lt 1 ]; then
    echo "❌ ERROR: No paired servers recorded in daemon state."
    exit 1
fi
echo "✅ Verified 1 paired Android device registered."

# Step 5b: Ensure runtime permissions and start Android app/background services
echo "==> Starting Android foreground services for authentication..."
adb shell am force-stop dev.rourunisen.tapauth.debug 2>/dev/null || true
adb shell am start -n dev.rourunisen.tapauth.debug/dev.rourunisen.tapauth.MainActivity
sleep 2

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
UDP_AUTH_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20 || true)
echo "$UDP_AUTH_OUTPUT"

if echo "$UDP_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
    echo "✅ Local Network (UDP) Authentication PASSED!"
else
    echo "❌ Local Network (UDP) Authentication FAILED."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Step 6b: Phase 2b - Real PAM Module Authentication (pamtester)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2b: Real PAM Module Authentication (pamtester)         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2

PAM_TESTABLE="false"
if command -v pamtester >/dev/null 2>&1 && [ -w /etc/pam.d ] && [ -f "$PAM_LIB" ]; then
    PAM_TESTABLE="true"
fi

if [ "$PAM_TESTABLE" = "true" ]; then
    echo "==> Configuring temporary PAM service at /etc/pam.d/tapauth-test-e2e..."
    printf 'auth required %s\naccount required pam_permit.so\n' "$PAM_LIB" > /etc/pam.d/tapauth-test-e2e

    echo "==> Executing pamtester for user '$TEST_USER'..."
    set +e
    TAPAUTHD_SOCK="$TAPAUTHD_SOCK" pamtester tapauth-test-e2e "$TEST_USER" authenticate
    PAM_EXIT=$?
    set -e

    rm -f /etc/pam.d/tapauth-test-e2e

    if [ "$PAM_EXIT" -eq 0 ]; then
        echo "✅ Real PAM Module Authentication PASSED (exit code: $PAM_EXIT)!"
    else
        echo "❌ Real PAM Module Authentication FAILED (exit code: $PAM_EXIT)."
        exit 1
    fi
else
    echo "ℹ️  Real PAM module testing skipped (/etc/pam.d not writable or pamtester missing)."
fi

# Step 7: Phase 3 - Bluetooth Low Energy (BLE) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 3: Bluetooth Low Energy (BLE) Authentication           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2

BLE_AVAILABLE="true"
if [ -f /tmp/ble-available.txt ]; then
    BLE_AVAILABLE=$(cat /tmp/ble-available.txt)
fi

if [ "$BLE_AVAILABLE" = "true" ]; then
    echo "==> Setting transport config: BLE enabled, UDP disabled..."
    "$CLI_BIN" set-transports --ble true --network false

    echo "==> Requesting authentication for user '$TEST_USER' over virtual BLE..."
    BLE_AUTH_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20 || true)
    echo "$BLE_AUTH_OUTPUT"

    if echo "$BLE_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
        echo "✅ Bluetooth Low Energy (BLE) Authentication PASSED!"
    else
        echo "❌ Bluetooth Low Energy (BLE) Authentication FAILED."
        if [ -f "$DAEMON_LOG" ]; then
            echo "=== DAEMON LOG DUMP ==="
            cat "$DAEMON_LOG"
            echo "======================="
        fi
        exit 1
    fi
else
    echo "❌ ERROR: Virtual BLE (/dev/vhci) is required for E2E testing but is not available!"
    exit 1
fi

# Step 8: Phase 4 - Parallel Discovery Race (Both Enabled)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 4: Parallel Discovery Race (UDP + BLE Simultaneous)    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2

if [ "$BLE_AVAILABLE" = "true" ]; then
    echo "==> Setting transport config: Both BLE and UDP enabled..."
    "$CLI_BIN" set-transports --ble true --network true

    PARALLEL_OUTPUT=$("$CLI_BIN" pam-auth "$TEST_USER" 20 || true)
    echo "$PARALLEL_OUTPUT"

    if echo "$PARALLEL_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
        echo "✅ Parallel Discovery Race Authentication PASSED!"
    else
        echo "❌ Parallel Discovery Race Authentication FAILED."
        exit 1
    fi
else
    echo "❌ ERROR: Virtual BLE (/dev/vhci) is required for Parallel Race testing but is not available!"
    exit 1
fi

# Step 9: Phase 5 - Denial Testing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5: Explicit User Denial & Rejection Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Stop auto-grant watcher
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
sleep 2

echo "==> Setting transport config: UDP enabled, BLE disabled..."
"$CLI_BIN" set-transports --ble false --network true

echo "==> Initiating auth and simulating biometric rejection..."
DENIAL_OUT_LOG="${TEST_DIR}/denial-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 10 > "$DENIAL_OUT_LOG" 2>&1 &
DENIAL_CLI_PID=$!

sleep 0.5
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" deny

set +e
wait "$DENIAL_CLI_PID"
DENIAL_EXIT=$?
set -e

cat "$DENIAL_OUT_LOG"

if [ "$DENIAL_EXIT" -ne 0 ] && grep -q "OUTCOME=DENIED" "$DENIAL_OUT_LOG"; then
    echo "✅ Explicit Denial correctly rejected with OUTCOME=DENIED (exit code: $DENIAL_EXIT)."
else
    echo "❌ ERROR: Expected explicit denial with OUTCOME=DENIED, but got exit code $DENIAL_EXIT."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Step 9b: Phase 5b - Authentication Timeout Verification
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5b: Authentication Timeout Verification                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 2
echo "==> Requesting authentication with 3s timeout and no response..."
TIMEOUT_OUT_LOG="${TEST_DIR}/timeout-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 3 > "$TIMEOUT_OUT_LOG" 2>&1 || true

cat "$TIMEOUT_OUT_LOG"

if grep -q "OUTCOME=TIMEOUT" "$TIMEOUT_OUT_LOG"; then
    echo "✅ Authentication Timeout correctly detected OUTCOME=TIMEOUT!"
else
    echo "❌ ERROR: Expected OUTCOME=TIMEOUT, but got:"
    cat "$TIMEOUT_OUT_LOG"
    exit 1
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

sleep 2
echo "==> Verifying authentication returns PAM_IGNORE when no devices are configured..."
UNPAIRED_AUTH_LOG="${TEST_DIR}/unpaired-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 5 > "$UNPAIRED_AUTH_LOG" 2>&1 || true
cat "$UNPAIRED_AUTH_LOG"

if grep -q "OUTCOME=IGNORE" "$UNPAIRED_AUTH_LOG"; then
    echo "✅ Un-paired authentication correctly returns OUTCOME=IGNORE (password fallback enabled)!"
else
    echo "❌ ERROR: Expected OUTCOME=IGNORE after device removal, but got:"
    cat "$UNPAIRED_AUTH_LOG"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  E2E TEST MATRIX SUMMARY                                      ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║  Phase 1: Real TCP Pairing & SAS Anti-MITM:      PASSED       ║"
echo "║  Phase 2: Local Network (UDP) Authentication:    PASSED       ║"
if [ "$PAM_TESTABLE" = "true" ]; then
echo "║  Phase 2b: Real PAM Module (pamtester):          PASSED       ║"
else
echo "║  Phase 2b: Real PAM Module (pamtester):          SKIPPED      ║"
fi
if [ "$BLE_AVAILABLE" = "true" ]; then
echo "║  Phase 3: Bluetooth Low Energy (BLE):            PASSED       ║"
echo "║  Phase 4: Parallel Race (UDP + BLE):             PASSED       ║"
else
echo "║  Phase 3: Bluetooth Low Energy (BLE):            SKIPPED (VM) ║"
echo "║  Phase 4: Parallel Race (UDP + BLE):             SKIPPED (VM) ║"
fi
echo "║  Phase 5: Explicit Denial & Rejection:           PASSED       ║"
echo "║  Phase 5b: Authentication Timeout:               PASSED       ║"
echo "║  Phase 6: Device Removal & PAM_IGNORE:           PASSED       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "🎉 ALL MANDATORY END-TO-END TESTS PASSED SUCCESSFULLY!"
