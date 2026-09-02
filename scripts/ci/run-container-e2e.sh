#!/bin/bash
# Runs TapAuth E2E tests inside a container (Fedora or Arch) against host Android emulator
set -euo pipefail

DISTRO="${1:-}"
PACKAGE_DIR="${2:-}"

if [[ -z "$DISTRO" || -z "$PACKAGE_DIR" ]]; then
    echo "Usage: $0 <fedora|arch> <package-dir>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=================================================="
echo " Starting TapAuth E2E Test on Distro: $DISTRO"
echo " Package directory: $PACKAGE_DIR"
echo "=================================================="

case "$DISTRO" in
    fedora)
        echo "==> Installing Fedora runtime requirements..."
        dnf install -y pamtester python3 python3-cryptography python3-protobuf qrencode dbus procps-ng iproute android-tools

        echo "==> Installing pre-built Fedora RPM packages..."
        dnf install -y "$PACKAGE_DIR"/tapauth-[0-9]*.rpm "$PACKAGE_DIR"/tapauth-fprintd-[0-9]*.rpm
        ;;

    arch)
        echo "==> Installing Arch Linux runtime requirements..."
        pacman -Sy --noconfirm python python-cryptography python-protobuf qrencode dbus procps-ng iproute2 gcc pam android-tools

        echo "==> Building standalone pamtester..."
        gcc -o /usr/bin/pamtester "$WORKSPACE_DIR/scripts/ci/pamtester.c" -lpam -lpam_misc

        echo "==> Installing pre-built Arch Linux packages..."
        pacman -U --noconfirm "$PACKAGE_DIR"/tapauth-[0-9]*.pkg.tar.zst "$PACKAGE_DIR"/tapauth-fprintd-[0-9]*.pkg.tar.zst
        ;;

    *)
        echo "Unknown distro: $DISTRO"
        exit 1
        ;;
esac

echo "==> Verifying system users, permissions, and directories..."
id tapauthd
getent group tapauthd-clients
mkdir -p /run/tapauthd /etc/tapauth
chown tapauthd:tapauthd /etc/tapauth /run/tapauthd 2>/dev/null || true
chmod 0755 /etc/tapauth /run/tapauthd 2>/dev/null || true

# Check ADB connectivity to host emulator
if command -v adb >/dev/null 2>&1; then
    echo "==> Checking ADB connectivity to host emulator..."
    adb devices
    adb shell pm clear dev.rourunisen.tapauth.e2e || true
fi

echo "==> Running TapAuth E2E suite against installed $DISTRO package..."
cd "$WORKSPACE_DIR"
export TAPAUTH_DEV_MODE=1
export TAPAUTH_E2E_USE_INSTALLED_PACKAGE=1
./scripts/test-e2e.sh

echo "==> Verifying clean package uninstallation on $DISTRO..."
case "$DISTRO" in
    fedora)
        dnf remove -y tapauth-fprintd tapauth
        ;;
    arch)
        pacman -R --noconfirm tapauth-fprintd tapauth
        ;;
esac

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ON DISTRO: $DISTRO"
echo "=================================================="
