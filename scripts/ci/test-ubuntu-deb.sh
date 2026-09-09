#!/bin/bash
# End-to-end container test for Debian/Ubuntu packaging (.deb)
# Tests:
# 1. Debian package build via dpkg-buildpackage using packaging/debian/
# 2. Base package (tapauth) installation via apt-get
# 3. Directory & config file permissions (0755/0644) and ownership (tapauthd:tapauthd)
# 4. Systemd service and socket unit placement
# 5. PAM scope: only sudo, su, polkit-1 are patched (with .tapauth-bak backups);
#    common-auth and fingerprint stacks stay stock (virtual fprintd bridge
#    handles lock screens/greeters via pam_fprintd.so)
# 6. D-Bus service and policy file placement (shipped in the base package)
# 7. Base package purge: PAM files restored, state cleaned up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)

echo "=================================================="
echo "Testing Ubuntu/Debian packaging for TapAuth ${PKG_VER}"
echo "=================================================="

SKIP_BUILD=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ "$SKIP_BUILD" = false ]; then
    echo "==> 1. Installing Debian build tools and dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        build-essential debhelper-compat protobuf-compiler libdbus-1-dev libsystemd-dev libpam0g-dev clang libclang-dev pkg-config git tar dpkg-dev polkitd dbus sudo curl ca-certificates

    # Ensure Rust toolchain >= 1.85 is available for lockfile v4
    if ! command -v cargo >/dev/null 2>&1 || [ "$(rustc --version 2>/dev/null | cut -d ' ' -f2 | cut -d. -f2 || echo 0)" -lt 85 ]; then
        echo "Installing modern Rust toolchain via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    echo "==> 2. Building Debian packages using build-debian-packages.sh..."
    "${WORKSPACE_DIR}/scripts/ci/build-debian-packages.sh"
fi

echo "==> 3. Testing installation of base package (tapauth)..."
apt-get install -y /tmp/deb-build/tapauth_${PKG_VER}*.deb

echo "Checking directory and config file ownership and permissions..."
test -d /etc/tapauth
DIR_OWNER=$(stat -c "%U:%G" /etc/tapauth)
DIR_MODE=$(stat -c "%a" /etc/tapauth)
echo "/etc/tapauth: $DIR_OWNER ($DIR_MODE)"
test "$DIR_OWNER" = "tapauthd:tapauthd"
test "$DIR_MODE" = "755"

test -f /etc/tapauth/config.toml
if grep -Eq '^enable_fprintd_bridge' /etc/tapauth/config.toml; then
    echo "ERROR: install must not write enable_fprintd_bridge into config.toml (daemon default is true)"
    exit 1
fi
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
echo "/etc/tapauth/config.toml: $OWNER ($MODE)"
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

test -f /lib/systemd/system/tapauthd.service || test -f /usr/lib/systemd/system/tapauthd.service
test -f /lib/systemd/system/tapauthd.socket || test -f /usr/lib/systemd/system/tapauthd.socket

echo "Verifying the tapauth-fprintd subpackage is gone..."
if ls /tmp/deb-build/tapauth-fprintd_*.deb >/dev/null 2>&1; then
    echo "ERROR: tapauth-fprintd subpackage was removed but a .deb for it was still built"
    exit 1
fi
if dpkg -l tapauth-fprintd 2>/dev/null | grep -q '^ii'; then
    echo "ERROR: tapauth-fprintd is installed"
    exit 1
fi

echo "Verifying the virtual fprintd D-Bus files ship in the base package..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
test -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "Verifying PAM scope: only sudo, su and polkit-1 are patched..."
for pam_svc in sudo su polkit-1; do
    test -f "/etc/pam.d/${pam_svc}"
    grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
    test -f "/etc/pam.d/${pam_svc}.tapauth-bak"
    ! grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}.tapauth-bak"
done

echo "Verifying common-auth is NOT patched (no pam-auth-update profile anymore)..."
if [ -f /etc/pam.d/common-auth ]; then
    ! grep "pam_tapauth.so" /etc/pam.d/common-auth
fi

echo "Creating dummy kde-fingerprint PAM stack to verify it stays STOCK..."
mkdir -p /etc/pam.d
cat << 'PAMEof' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
@include common-auth
PAMEof

echo "==> 4b. Testing package upgrade and reconfiguration..."
dpkg -i /tmp/deb-build/tapauth_${PKG_VER}*.deb

echo "Verifying configuration, PAM wiring, and permissions survived upgrade..."
test -f /etc/tapauth/config.toml
if grep -Eq '^enable_fprintd_bridge' /etc/tapauth/config.toml; then
    echo "ERROR: upgrade wrote enable_fprintd_bridge into config.toml"
    exit 1
fi
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"
for pam_svc in sudo su polkit-1; do
    grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
done

echo "Verifying that kde-fingerprint was NOT modified (stays stock)..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
test ! -e /etc/pam.d/kde-fingerprint.tapauth-bak
test ! -f /etc/dconf/db/gdm.d/10-tapauth-fingerprint

echo "==> 5. Testing purge of base package (tapauth)..."
apt-get purge -y tapauth
test ! -d /etc/tapauth || [ -z "$(ls -A /etc/tapauth 2>/dev/null)" ]

echo "Verifying the three PAM services were restored upon purge..."
for pam_svc in sudo su polkit-1; do
    if [ -f "/etc/pam.d/${pam_svc}" ]; then
        ! grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
    fi
    test ! -e "/etc/pam.d/${pam_svc}.tapauth-bak"
done

echo "Verifying that kde-fingerprint is untouched by uninstall..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint

echo "=================================================="
echo "🎉 ALL UBUNTU/DEBIAN BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
