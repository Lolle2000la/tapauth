#!/bin/bash
# Runs complete E2E test suite across real Android emulator for Ubuntu, Fedora, and Arch Linux packages
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKSPACE_DIR"

export E2E_KEEP_BLE_BRIDGE=1
trap 'if [ -f /tmp/bumble-bridge.pid ]; then kill "$(cat /tmp/bumble-bridge.pid)" 2>/dev/null || true; rm -f /tmp/bumble-bridge.pid; fi' EXIT

# Ensure host virtual BLE bridge is up
echo "==> Starting Virtual BLE Bridge on host..."
"$SCRIPT_DIR/setup-emulator-ble-bridge.sh"

# 1. Run JNI crypto instrumentation tests directly on emulator via ADB
echo "=================================================="
echo " [0/3] Running JNI Crypto Instrumentation Tests"
echo "=================================================="
E2E_APK="server-android/app/build/outputs/apk/e2e/app-e2e.apk"
TEST_APK="server-android/app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk"
for apk in "$E2E_APK" "$TEST_APK"; do
    if [ ! -f "$apk" ]; then
        echo "❌ ERROR: expected APK not found: $apk"
        exit 1
    fi
done
adb install -r -t "$E2E_APK"
adb install -r -t "$TEST_APK"
# Capture the full output first, then select the first matching line: piping
# through `head -n1` can SIGPIPE the producer, and under `set -o pipefail` that
# nonzero status would abort the script before the fallback runner is used.
INSTRUMENTATION="$(adb shell pm list instrumentation 2>/dev/null || true)"
RUNNER="$(printf '%s\n' "$INSTRUMENTATION" | grep dev.rourunisen.tapauth | cut -d: -f2 | cut -d' ' -f1 || true)"
RUNNER="${RUNNER%%$'\n'*}"
if [ -z "$RUNNER" ]; then
    RUNNER="dev.rourunisen.tapauth.e2e.test/dev.rourunisen.tapauth.crypto.TapAuthTestRunner"
fi
echo "==> Using test runner: $RUNNER"
adb shell am instrument -w -r -e class dev.rourunisen.tapauth.crypto.TapAuthCryptoTest "$RUNNER" > /tmp/jni-test.log 2>&1 || true
cat /tmp/jni-test.log
if grep -q "FAILURES!!!" /tmp/jni-test.log || ! grep -q "OK (" /tmp/jni-test.log; then
    echo "❌ JNI Crypto Tests Failed!"
    exit 1
fi
echo "✅ JNI Crypto Instrumentation Tests Passed!"

# Build tapauth-ipc-cli from the workspace: it is a testing-only admin tool
# that the distro packages deliberately do not ship. Installed-package mode
# always uses the production socket path, so the default (non-dev) build is
# sufficient. The containers below have no Rust toolchain and reuse this binary
# through the bind-mounted /workspace/target directory.
export CARGO_TARGET_DIR="$WORKSPACE_DIR/target"
cargo build -p tapauthd --bin tapauth-ipc-cli

# 2. Run E2E against installed Ubuntu (.deb) package on host
echo "=================================================="
echo " [1/3] Running E2E against installed Ubuntu (.deb) package"
echo "=================================================="
sudo -E env "PATH=$PATH" TAPAUTH_E2E_USE_INSTALLED_PACKAGE=1 ./scripts/test-e2e.sh
sudo apt-get purge -y tapauth 2>/dev/null || true

# Pass emulator auth token to containers so adb emu can authenticate to the console
AUTH_TOKEN_MOUNT=()
if [ -f "$HOME/.emulator_auth_token" ]; then
  AUTH_TOKEN_MOUNT=(-v "$HOME/.emulator_auth_token:/root/.emulator_auth_token:ro")
elif [ -f "/root/.emulator_auth_token" ]; then
  AUTH_TOKEN_MOUNT=(-v "/root/.emulator_auth_token:/root/.emulator_auth_token:ro")
fi

# 3. Run E2E against installed Fedora (.rpm) package in container
echo "=================================================="
echo " [2/3] Running E2E against installed Fedora (.rpm) package"
echo "=================================================="
"$SCRIPT_DIR/setup-emulator-ble-bridge.sh"
docker run --rm --privileged --net=host --pid=host \
  -v /dev:/dev \
  -v /tmp:/tmp \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "$WORKSPACE_DIR":/workspace \
  ${AUTH_TOKEN_MOUNT[@]+"${AUTH_TOKEN_MOUNT[@]}"} \
  fedora:latest /workspace/scripts/ci/run-container-e2e.sh fedora /workspace/pkg-fedora-test

# 4. Run E2E against installed Arch Linux (.pkg.tar.zst) package in container
echo "=================================================="
echo " [3/3] Running E2E against installed Arch Linux (.pkg.tar.zst) package"
echo "=================================================="
"$SCRIPT_DIR/setup-emulator-ble-bridge.sh"
docker run --rm --privileged --net=host --pid=host \
  -v /dev:/dev \
  -v /tmp:/tmp \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "$WORKSPACE_DIR":/workspace \
  ${AUTH_TOKEN_MOUNT[@]+"${AUTH_TOKEN_MOUNT[@]}"} \
  archlinux:base-devel /workspace/scripts/ci/run-container-e2e.sh arch /workspace/pkg-arch-test

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ACROSS ALL THREE DISTROS!"
echo "=================================================="
