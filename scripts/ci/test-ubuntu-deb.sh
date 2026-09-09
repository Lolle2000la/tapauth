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
# 6. D-Bus policy file placement (shipped in the base package; deliberately
#    NO activation service file — see the coexistence test)
# 7. Coexistence with the real fprintd package: fprintd installs first,
#    tapauth installs/removes without touching fprintd's activation file
# 8. Upgrade from a published v0.10.0-style package: stale pam-auth-update
#    line in common-auth must be dropped on upgrade AND on plain remove
# 9. Base package purge: PAM files restored, state cleaned up
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
echo "Installing the REAL fprintd package first (coexistence P0 test: tapauth"
echo "must install without file conflicts over fprintd's D-Bus activation file)..."
apt-get install -y fprintd
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
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

echo "Verifying the virtual fprintd D-Bus policy ships in the base package..."
test -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf
# Deliberately NO D-Bus activation service file shipped by tapauth: fprintd's
# own package owns /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
# and a same-Name duplicate cannot win activation (dbus-daemon keeps the
# first-sorted file; dbus-broker ignores files not named after the bus name).
# Check the tapauth package file list (the path itself may legitimately exist
# because the coexistence test installs the real fprintd package).
if dpkg -L tapauth | grep -q "dbus-1/system-services"; then
    echo "ERROR: tapauth ships a D-Bus activation service file (must not — fprintd owns the only winning one)"
    exit 1
fi
if [ -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service ] && \
   grep -q "tapauthd" /usr/share/dbus-1/system-services/net.reactivated.Fprint.service 2>/dev/null; then
    echo "ERROR: net.reactivated.Fprint.service contains tapauthd (tapauth must never own that file)"
    exit 1
fi

echo "Verifying coexistence with the real fprintd package (installs first, no conflicts)..."
if ! dpkg -s fprintd >/dev/null 2>&1; then
    apt-get install -y fprintd
fi
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
echo "Real fprintd activation Exec: $FPRINT_BIN"
case "$FPRINT_BIN" in
    *tapauthd*) echo "ERROR: fprintd's activation file points at tapauthd — package overwrote it"; exit 1 ;;
esac
# Remove any stale tapauth-era activation file (should not exist)
test ! -e /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service

echo "Verifying fprintd's activation file survived the tapauth install untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
case "$FPRINT_BIN" in
    /usr/libexec/fprintd|/usr/lib/fprintd/fprintd|/usr/sbin/fprintd) : ;;
    *) echo "ERROR: fprintd activation Exec changed: $FPRINT_BIN"; exit 1 ;;
esac

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

echo "==> 4c. Testing upgrade from a published v0.10.0-style package (pam-auth-update era)..."
# v0.10.0 shipped a /usr/share/pam-configs/tapauth profile and ran
# pam-auth-update --package, generating a tapauth line in
# /etc/pam.d/common-auth. Upgrading to this package removes the profile;
# the maintainer scripts must regenerate the pam-auth-update-managed
# stacks so the stale line disappears — and a later plain "apt remove"
# must never leave a common-auth line pointing at a missing module.
cat > /usr/share/pam-configs/tapauth <<'PAMEof'
Name: TapAuth Phone Authentication Module
Default: yes
Priority: 512
Auth-Type: Primary
Auth:
	sufficient	pam_tapauth.so
PAMEof
pam-auth-update --package
grep "pam_tapauth.so" /etc/pam.d/common-auth
# dpkg removes the old profile when the new package unpacks; simulate by
# deleting it and re-installing (upgrade triggers postinst regeneration).
rm -f /usr/share/pam-configs/tapauth
dpkg -i /tmp/deb-build/tapauth_${PKG_VER}*.deb
if grep -q "pam_tapauth.so" /etc/pam.d/common-auth 2>/dev/null; then
    echo "ERROR: upgrade did not drop the stale pam-auth-update tapauth line from common-auth"
    exit 1
fi
echo "common-auth is clean after the v0.10.0-style upgrade."
# Direct PAM wiring must survive the regeneration.
for pam_svc in sudo su polkit-1; do
    grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
done

echo "==> 4d. Testing plain remove (dpkg -r, not purge) leaves no stale common-auth line..."
dpkg -r tapauth
if grep -q "pam_tapauth.so" /etc/pam.d/common-auth 2>/dev/null; then
    echo "ERROR: plain remove left a tapauth line in common-auth (missing-module auth failure)"
    exit 1
fi
echo "common-auth is clean after plain remove."

echo "==> 5. Testing purge of base package (tapauth)..."
dpkg -P tapauth
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

echo "Verifying the real fprintd package survived the full tapauth lifecycle untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
case "$FPRINT_BIN" in
    /usr/libexec/fprintd|/usr/lib/fprintd/fprintd|/usr/sbin/fprintd) : ;;
    *) echo "ERROR: fprintd activation Exec changed after tapauth removal: $FPRINT_BIN"; exit 1 ;;
esac
if [ -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf ]; then
    echo "ERROR: tapauth D-Bus policy file survived package removal"
    exit 1
fi

echo "=================================================="
echo "🎉 ALL UBUNTU/DEBIAN BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
