#!/bin/bash
# Runs the complete E2E suite on a real Android emulator against the installed
# Ubuntu (.deb) package on the host and the Fedora (.rpm) / Arch (.pkg.tar.zst)
# packages inside systemd-booting containers.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKSPACE_DIR"

# Common systemd-container bootstrap, run before `exec /sbin/init`:
#  * mask systemd-resolved: it rewrites /etc/resolv.conf to 127.0.0.53, which
#    breaks the post-boot package downloads (Docker's resolv.conf must be kept);
#  * mask systemd-firstboot: without /etc/machine-id it prompts on the console
#    and hangs sysinit, so the container never finishes booting;
#  * mask systemd-networkd: unused under --net=host.
# A machine-id is generated too, so nothing else waits on firstboot.
SYSTEMD_BOOTSTRAP='
mkdir -p /etc/systemd/system
ln -sf /dev/null /etc/systemd/system/systemd-resolved.service
ln -sf /dev/null /etc/systemd/system/systemd-firstboot.service
ln -sf /dev/null /etc/systemd/system/systemd-networkd.service
ln -sf /dev/null /etc/systemd/system/systemd-networkd.socket
[ -s /etc/machine-id ] || systemd-machine-id-setup
exec /sbin/init
'

export E2E_KEEP_BLE_BRIDGE=1
trap 'if [ -f /tmp/bumble-bridge.pid ]; then kill "$(cat /tmp/bumble-bridge.pid)" 2>/dev/null || true; rm -f /tmp/bumble-bridge.pid; fi; rm -f /tmp/tapauth-vhci-dev' EXIT

# Ensure host virtual BLE bridge is up (with the host bluetoothd, which the
# Ubuntu host pass below needs).
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

# Hand the virtual Bluetooth adapter to the container instances: only one
# bluetoothd may own an adapter, and the Fedora/Arch containers run their own
# (see run-systemd-container.sh). Stop the host daemon, then re-assert the
# host-owned Bumble bridge without starting bluetoothd again.
echo "==> Yielding the host Bluetooth daemon to the systemd containers..."
sudo systemctl stop bluetooth 2>/dev/null || true
sudo pkill -x bluetoothd 2>/dev/null || true
TAPAUTH_E2E_BLE_BRIDGE_ONLY=1 "$SCRIPT_DIR/setup-emulator-ble-bridge.sh"

# 3. Run E2E against installed Fedora (.rpm) package in a systemd container
echo "=================================================="
echo " [2/3] Running E2E against installed Fedora (.rpm) package"
echo "=================================================="
# fedora:latest ships no init, so install systemd+dbus then run the common
# bootstrap (masks + machine-id) and exec systemd as PID 1.
"$SCRIPT_DIR/run-systemd-container.sh" fedora fedora:latest /workspace/pkg-fedora-test \
    sh -c "dnf -y install systemd dbus && ${SYSTEMD_BOOTSTRAP}"

# 4. Run E2E against installed Arch Linux (.pkg.tar.zst) package in a systemd container
echo "=================================================="
echo " [3/3] Running E2E against installed Arch Linux (.pkg.tar.zst) package"
echo "=================================================="
# Same common bootstrap; archlinux:base-devel already ships systemd.
"$SCRIPT_DIR/run-systemd-container.sh" arch archlinux:base-devel /workspace/pkg-arch-test \
    sh -c "${SYSTEMD_BOOTSTRAP}"

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ACROSS ALL THREE DISTROS!"
echo "=================================================="
