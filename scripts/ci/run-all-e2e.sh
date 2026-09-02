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
adb install -r -t server-android/app/build/outputs/apk/e2e/app-e2e.apk || true
adb install -r -t server-android/app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk || true
RUNNER=$(adb shell pm list instrumentation | grep dev.rourunisen.tapauth | head -n1 | cut -d: -f2 | cut -d' ' -f1)
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

# 2. Run E2E against installed Ubuntu (.deb) package on host
echo "=================================================="
echo " [1/3] Running E2E against installed Ubuntu (.deb) package"
echo "=================================================="
sudo -E env "PATH=$PATH" TAPAUTH_E2E_USE_INSTALLED_PACKAGE=1 ./scripts/test-e2e.sh
sudo apt-get purge -y tapauth-fprintd tapauth 2>/dev/null || true

# 3. Run E2E against installed Fedora (.rpm) package in container
echo "=================================================="
echo " [2/3] Running E2E against installed Fedora (.rpm) package"
echo "=================================================="
docker run --rm --privileged --net=host --pid=host \
  -v /dev:/dev \
  -v /tmp:/tmp \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "$WORKSPACE_DIR":/workspace \
  fedora:latest /workspace/scripts/ci/run-container-e2e.sh fedora /workspace/pkg-fedora

# 4. Run E2E against installed Arch Linux (.pkg.tar.zst) package in container
echo "=================================================="
echo " [3/3] Running E2E against installed Arch Linux (.pkg.tar.zst) package"
echo "=================================================="
docker run --rm --privileged --net=host --pid=host \
  -v /dev:/dev \
  -v /tmp:/tmp \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "$WORKSPACE_DIR":/workspace \
  archlinux:base-devel /workspace/scripts/ci/run-container-e2e.sh arch /workspace/pkg-arch

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ACROSS ALL THREE DISTROS!"
echo "=================================================="
