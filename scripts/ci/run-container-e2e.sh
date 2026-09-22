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

# Keep the host's Bumble bridge alive: cleanup in test-e2e.sh would otherwise
# kill it through the shared /tmp/bumble-bridge.pid with --pid=host, forcing
# run-all-e2e.sh to restart it for every container.
export E2E_KEEP_BLE_BRIDGE=1

# Plant a dummy fingerprint stack to prove the distro package never rewrites
# unrelated/vendor PAM files (TapAuth only touches the services it opts into).
mkdir -p /etc/pam.d
cat << 'EOF' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
EOF

case "$DISTRO" in
    fedora)
        echo "==> Installing Fedora runtime requirements..."
        dnf install -y pamtester python3 python3-cryptography python3-protobuf qrencode dbus dbus-tools procps-ng iproute android-tools systemd bluez bluez-deprecated util-linux binutils

        echo "==> Installing pre-built Fedora RPM packages..."
        dnf install -y "$PACKAGE_DIR"/tapauth-[0-9]*.rpm
        ;;

    arch)
        echo "==> Installing Arch Linux runtime requirements..."
        pacman -Sy --noconfirm python python-cryptography python-protobuf qrencode dbus procps-ng iproute2 gcc pam android-tools bluez bluez-utils util-linux

        echo "==> Building standalone pamtester..."
        gcc -o /usr/bin/pamtester "$WORKSPACE_DIR/scripts/ci/pamtester.c" -lpam -lpam_misc

        echo "==> Installing pre-built Arch Linux packages..."
        pacman -U --noconfirm "$PACKAGE_DIR"/tapauth-[0-9]*.pkg.tar.zst
        ;;

    *)
        echo "Unknown distro: $DISTRO"
        exit 1
        ;;
esac

echo "==> Verifying the dummy fingerprint stack stayed untouched on $DISTRO..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint

echo "==> Verifying system users, permissions, and directories..."
id tapauthd
getent group tapauthd-clients
# Do NOT chown /etc/tapauth: the package ships it root:root and tmpfiles creates
# the daemon-owned config.toml. Asserting the real posture keeps the E2E from
# masking a packaging permission bug that would break SaveConfig on first use.
mkdir -p /run/tapauthd /var/lib/tapauth
chown tapauthd:tapauthd /run/tapauthd /var/lib/tapauth 2>/dev/null || true
chmod 0755 /run/tapauthd 2>/dev/null || true
chmod 0700 /var/lib/tapauth 2>/dev/null || true
[ -d /etc/tapauth ] || { echo "❌ /etc/tapauth missing after package install"; exit 1; }
[ "$(stat -c '%U:%G' /etc/tapauth)" = "root:root" ] \
    || { echo "❌ /etc/tapauth owner is $(stat -c '%U:%G' /etc/tapauth), expected root:root"; exit 1; }
[ -f /etc/tapauth/config.toml ] \
    || { echo "❌ /etc/tapauth/config.toml missing after package install (did tmpfiles run?)"; exit 1; }
[ "$(stat -c '%U:%G' /etc/tapauth/config.toml)" = "tapauthd:tapauthd" ] \
    || { echo "❌ config.toml owner is $(stat -c '%U:%G' /etc/tapauth/config.toml), expected tapauthd:tapauthd"; exit 1; }
# Drop to the daemon uid with coreutils only (runuser is not in every image).
chroot --userspec=tapauthd:tapauthd / /usr/bin/test -w /etc/tapauth/config.toml \
    || { echo "❌ tapauthd cannot write /etc/tapauth/config.toml (SaveConfig would fail)"; exit 1; }
echo "✅ /etc/tapauth is root:root with a daemon-writable config.toml"

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
        rpm -e tapauth
        ;;
    arch)
        pacman -R --noconfirm tapauth
        ;;
esac

echo "==> Verifying the dummy fingerprint stack is still untouched after removal on $DISTRO..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ON DISTRO: $DISTRO"
echo "=================================================="
