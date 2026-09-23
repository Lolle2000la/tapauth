#!/bin/bash
# Runs the TapAuth E2E suite inside a systemd-booting container (Fedora or Arch)
# against the host Android emulator, using the installed package's units.
#
# The container's PID 1 is systemd and it runs its own D-Bus/polkitd/bluetoothd
# (see scripts/ci/run-systemd-container.sh), so this script is always driven via
# `docker exec` against that live init.
#
# Usage: run-container-e2e.sh <fedora|arch> <package-dir>
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

# Keep the host's Bumble bridge alive: the systemd containers rely on it (they
# run only their own bluetoothd, not the bridge), so cleanup must not kill it.
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
        # The container runs its own system bus, polkitd and bluetoothd (see
        # scripts/ci/run-systemd-container.sh).
        dnf install -y polkit

        echo "==> Installing pre-built Fedora RPM packages..."
        dnf install -y "$PACKAGE_DIR"/tapauth-[0-9]*.rpm
        ;;

    arch)
        echo "==> Installing Arch Linux runtime requirements..."
        pacman -Sy --noconfirm python python-cryptography python-protobuf qrencode dbus procps-ng iproute2 gcc pam android-tools bluez bluez-utils util-linux
        pacman -Sy --noconfirm polkit

        # Arch ships no `pamtester` package (AUR-only), so compile the minimal
        # stand-in from scripts/ci/pamtester.c. The Ubuntu host and Fedora
        # container install the genuine tool from their distro repos.
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
# NB: use an explicit `if`, not `! grep` — under `set -e` a negated command is
# exempt from errexit, so `! grep ...` would make this check vacuous.
if grep -q "pam_tapauth.so" /etc/pam.d/kde-fingerprint; then
    echo "❌ ERROR: $DISTRO package wired pam_tapauth.so into the unrelated kde-fingerprint PAM stack"
    exit 1
fi

echo "==> Verifying system users, permissions, and directories..."
id tapauthd
getent group tapauthd-clients
# Do NOT chown /etc/tapauth: the package ships it root:root and tmpfiles creates
# the daemon-owned config.toml. Asserting the real posture keeps the E2E from
# masking a packaging permission bug that would break SaveConfig on first use.

# Assert a directory's owner/group/mode exactly.
assert_dir_posture() {
    local dir="$1" owner="$2" group="$3" mode="$4"
    [ -d "$dir" ] || { echo "❌ $dir missing after package install (did tmpfiles run?)"; exit 1; }
    [ "$(stat -c '%U:%G' "$dir")" = "$owner:$group" ] \
        || { echo "❌ $dir owner is $(stat -c '%U:%G' "$dir"), expected $owner:$group"; exit 1; }
    [ "$(stat -c '%a' "$dir")" = "$mode" ] \
        || { echo "❌ $dir mode is $(stat -c '%a' "$dir"), expected $mode"; exit 1; }
}

# The package's tmpfiles (and the socket unit) own these paths, so assert the
# shipped posture instead of creating/loosening it here.
assert_dir_posture /run/tapauthd tapauthd tapauthd-clients 750
assert_dir_posture /var/lib/tapauth tapauthd tapauthd 700

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

# The container runs its own system bus, polkitd and bluetoothd. The daemon
# itself is socket-activated from the package's units (test-e2e.sh enables and
# starts tapauthd.socket); make sure the supporting services are up.
echo "==> Starting container systemd services (dbus, polkit, bluetooth)..."
systemctl start dbus.socket 2>/dev/null || true
systemctl enable --now polkit 2>/dev/null || true
systemctl enable --now bluetooth 2>/dev/null || true
systemctl --no-pager --failed || true

# Check ADB connectivity to host emulator
if command -v adb >/dev/null 2>&1; then
    echo "==> Checking ADB connectivity to host emulator..."
    adb devices
    adb shell pm clear dev.rourunisen.tapauth.e2e || true
fi

echo "==> Running TapAuth E2E suite against installed $DISTRO package..."
cd "$WORKSPACE_DIR"
export TAPAUTH_E2E_USE_INSTALLED_PACKAGE=1
export TAPAUTH_E2E_DAEMON_MODE=systemd
# The host owns the Bumble bridge; the container's bluetoothd owns the resulting
# vhci adapter, so the suite must verify it, not launch it.
export TAPAUTH_E2E_EXTERNAL_BLE_BRIDGE=1
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
# NB: use an explicit `if`, not `! grep` — under `set -e` a negated command is
# exempt from errexit, so `! grep ...` would make this check vacuous.
if grep -q "pam_tapauth.so" /etc/pam.d/kde-fingerprint; then
    echo "❌ ERROR: $DISTRO package wired pam_tapauth.so into the unrelated kde-fingerprint PAM stack"
    exit 1
fi

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ON DISTRO: $DISTRO"
echo "=================================================="
