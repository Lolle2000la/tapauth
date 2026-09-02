#!/bin/bash
# Runs complete E2E test suite across real Android emulator for Ubuntu, Fedora, and Arch Linux packages
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$WORKSPACE_DIR"

# 1. Run JNI crypto instrumentation tests (on device/emulator)
echo "=================================================="
echo " [0/3] Running JNI Crypto Instrumentation Tests"
echo "=================================================="
(cd server-android && ./gradlew connectedE2eAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=dev.rourunisen.tapauth.crypto.TapAuthCryptoTest --stacktrace)

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
docker run --rm --privileged --net=host \
  -v /dev:/dev \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "$WORKSPACE_DIR":/workspace \
  fedora:latest /workspace/scripts/ci/run-container-e2e.sh fedora /workspace/pkg-fedora

# 4. Run E2E against installed Arch Linux (.pkg.tar.zst) package in container
echo "=================================================="
echo " [3/3] Running E2E against installed Arch Linux (.pkg.tar.zst) package"
echo "=================================================="
docker run --rm --privileged --net=host \
  -v /dev:/dev \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
  -v "$WORKSPACE_DIR":/workspace \
  archlinux:base-devel /workspace/scripts/ci/run-container-e2e.sh arch /workspace/pkg-arch

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ACROSS ALL THREE DISTROS!"
echo "=================================================="
