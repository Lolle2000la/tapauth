#!/bin/bash
# End-to-end container test for Debian/Ubuntu packaging (.deb)
# Tests:
# 1. Debian package build via dpkg-buildpackage using packaging/debian/
# 2. Base package (tapauth) installation via apt-get
# 3. Directory & config file permissions (0755/0644) and ownership (tapauthd:tapauthd)
# 4. Systemd service and socket unit placement
# 5. Subpackage (tapauth-fprintd) installation and config bridge toggle
# 6. D-Bus service and policy file placement
# 7. Subpackage removal and config bridge disablement
# 8. Base package purge and cleanup of /etc/tapauth
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
        build-essential debhelper-compat protobuf-compiler libdbus-1-dev libsystemd-dev libpam0g-dev clang libclang-dev pkg-config git tar dpkg-dev polkitd dbus curl ca-certificates

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
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
echo "/etc/tapauth/config.toml: $OWNER ($MODE)"
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

test -f /lib/systemd/system/tapauthd.service || test -f /usr/lib/systemd/system/tapauthd.service
test -f /lib/systemd/system/tapauthd.socket || test -f /usr/lib/systemd/system/tapauthd.socket

echo "Verifying pam-auth-update wired pam_tapauth.so into /etc/pam.d/common-auth..."
if [ -f /etc/pam.d/common-auth ]; then
    grep "pam_tapauth.so" /etc/pam.d/common-auth
fi

echo "Creating dummy kde-fingerprint PAM stack to verify repair..."
mkdir -p /etc/pam.d
cat << 'PAMEof' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
@include common-auth
PAMEof

echo "==> 4. Testing installation of subpackage (tapauth-fprintd)..."
apt-get install -y /tmp/deb-build/tapauth-fprintd_${PKG_VER}*.deb

echo "Checking config file and bridge enablement after subpackage install..."
grep "enable_fprintd_bridge = true" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
test -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "Verifying that kde-fingerprint was updated to pam_tapauth.so..."
grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
! grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint

echo "==> 4b. Testing package upgrade and reconfiguration..."
dpkg -i /tmp/deb-build/tapauth_${PKG_VER}*.deb
dpkg -i /tmp/deb-build/tapauth-fprintd_${PKG_VER}*.deb

echo "Verifying configuration, PAM wiring, and permissions survived upgrade..."
grep "enable_fprintd_bridge = true" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"
grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
if [ -f /etc/pam.d/common-auth ]; then
    grep "pam_tapauth.so" /etc/pam.d/common-auth
fi

echo "==> 5. Testing removal and purge of subpackage (tapauth-fprintd)..."
apt-get remove -y tapauth-fprintd
test -f /etc/tapauth/config.toml
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml

echo "Verifying that kde-fingerprint reverted pam_fprintd.so..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint

echo "Re-installing tapauth-fprintd to test apt purge..."
apt-get install -y /tmp/deb-build/tapauth-fprintd_${PKG_VER}*.deb
grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
apt-get purge -y tapauth-fprintd
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
test ! -f /etc/dconf/db/gdm.d/10-tapauth-fingerprint

echo "==> 6. Testing purge of base package (tapauth)..."
apt-get purge -y tapauth
test ! -d /etc/tapauth || [ -z "$(ls -A /etc/tapauth 2>/dev/null)" ]
if [ -f /etc/pam.d/common-auth ]; then
    echo "Verifying pam_tapauth.so unwired from common-auth upon purge..."
    ! grep "pam_tapauth.so" /etc/pam.d/common-auth
fi

echo "=================================================="
echo "🎉 ALL UBUNTU/DEBIAN BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
