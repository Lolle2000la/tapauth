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

# Set up a dummy kde-fingerprint to verify PAM stack repair by tapauth-fprintd
mkdir -p /etc/pam.d
cat << 'EOF' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
EOF

case "$DISTRO" in
    fedora)
        echo "==> Installing Fedora runtime requirements..."
        dnf install -y pamtester python3 python3-cryptography python3-protobuf qrencode dbus dbus-tools procps-ng iproute android-tools systemd bluez bluez-deprecated

        echo "==> Installing pre-built Fedora RPM packages..."
        dnf install -y "$PACKAGE_DIR"/tapauth-[0-9]*.rpm "$PACKAGE_DIR"/tapauth-fprintd-[0-9]*.rpm
        ;;

    arch)
        echo "==> Installing Arch Linux runtime requirements..."
        pacman -Sy --noconfirm python python-cryptography python-protobuf qrencode dbus procps-ng iproute2 gcc pam android-tools bluez bluez-utils

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

echo "==> Verifying PAM fingerprint stack was patched by tapauth-fprintd on $DISTRO..."
grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
! grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint

echo "==> Verifying system users, permissions, and directories..."
id tapauthd
getent group tapauthd-clients
mkdir -p /run/tapauthd /etc/tapauth /var/lib/tapauth
chown -R tapauthd:tapauthd /etc/tapauth /run/tapauthd /var/lib/tapauth 2>/dev/null || true
chmod 0755 /etc/tapauth /run/tapauthd 2>/dev/null || true
chmod 0700 /var/lib/tapauth 2>/dev/null || true

# Verify shipped systemd unit files syntax using distro's systemd
if command -v systemd-analyze >/dev/null 2>&1; then
    echo "==> Verifying shipped systemd unit files syntax via systemd-analyze..."
    systemd-analyze verify /usr/lib/systemd/system/tapauthd.service /usr/lib/systemd/system/tapauthd.socket || true
fi

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
export TAPAUTH_E2E_DAEMON_MODE=dev
./scripts/test-e2e.sh

echo "==> Verifying clean package uninstallation on $DISTRO..."
case "$DISTRO" in
    fedora)
        rpm -e tapauth-fprintd tapauth
        ;;
    arch)
        pacman -R --noconfirm tapauth-fprintd tapauth
        ;;
esac

echo "==> Verifying PAM fingerprint stack was cleanly restored after simultaneous removal on $DISTRO..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ON DISTRO: $DISTRO"
echo "=================================================="
