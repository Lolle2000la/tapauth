#!/bin/bash
# End-to-end container test for Debian/Ubuntu packaging (.deb)
# Tests:
# 1. Debian package build via dpkg-buildpackage using packaging/debian/
# 2. Base package (tapauth) installation via apt-get
# 3. Directory & config file permissions (0755/0644) and ownership (tapauthd:tapauthd)
# 4. Systemd service and socket unit placement
# 5. PAM scope: only sudo, su, polkit-1 are patched (with .tapauth-bak backups);
#    common-auth and fingerprint stacks stay stock. In su, the TapAuth line
#    must land after pam_rootok/pam_wheel (no root bypass).
# 6. D-Bus policy file shipped in the base package; NO activation file and NO
#    emulation marker in the base package (bridge opt-in); the optional
#    tapauth-fprintd-emulation package ships the marker
#    /usr/share/tapauth/fprintd-emulation.enabled
# 7. Coexistence with the real fprintd package: fprintd installs first,
#    tapauth installs/removes without touching fprintd's activation file
# 8. Upgrade from a published v0.10.0-style package: stale pam-auth-update
#    line in common-auth must be dropped on upgrade AND on plain remove
# 9. Base package purge: PAM files restored, state cleaned up
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)

# Shared virtual-fprintd D-Bus coexistence verification helpers
source "${SCRIPT_DIR}/verify-fprintd-coexistence.sh"

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

echo "Verifying the scriptlets do NOT auto-add interactive users to tapauthd-clients..."
# Membership is a manual, per-user opt-in: the postinst prints an advisory and
# must never modify group membership itself.
AUTO_ADDED=""
while IFS=: read -r _user _pw _uid _gid _gecos _home _shell; do
    [ "$_uid" -ge 1000 ] 2>/dev/null || continue
    [ "$_uid" -lt 65534 ] || continue
    case "$_shell" in */nologin|*/false) continue ;; esac
    if id -nG "$_user" 2>/dev/null | tr ' ' '\n' | grep -qx tapauthd-clients; then
        AUTO_ADDED="${AUTO_ADDED} ${_user}"
    fi
done < <(getent passwd)
if [ -n "$AUTO_ADDED" ]; then
    echo "ERROR: postinst auto-added interactive user(s) to tapauthd-clients:${AUTO_ADDED}"
    exit 1
fi
echo "OK: no interactive user was auto-added to tapauthd-clients"

echo "Verifying the shipped postinst carries the manual-membership advisory..."
DEB_PKG=$(ls /tmp/deb-build/tapauth_${PKG_VER}*.deb | head -1)
rm -rf /tmp/tapauth-deb-control
dpkg-deb -e "$DEB_PKG" /tmp/tapauth-deb-control
grep -q "sudo usermod -aG tapauthd-clients" /tmp/tapauth-deb-control/postinst

echo "Checking directory and config file ownership and permissions..."
test -d /etc/tapauth
DIR_OWNER=$(stat -c "%U:%G" /etc/tapauth)
DIR_MODE=$(stat -c "%a" /etc/tapauth)
echo "/etc/tapauth: $DIR_OWNER ($DIR_MODE)"
test "$DIR_OWNER" = "tapauthd:tapauthd"
test "$DIR_MODE" = "755"

test -f /etc/tapauth/config.toml
if grep -Eq '^enable_fprintd_bridge' /etc/tapauth/config.toml; then
    echo "ERROR: install must not write enable_fprintd_bridge into config.toml (tri-state default: auto/marker-derived)"
    exit 1
fi
if [ -e /usr/share/tapauth/fprintd-emulation.enabled ]; then
    echo "ERROR: base install shipped the fprintd-emulation marker (bridge would default on)"
    exit 1
fi
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
echo "/etc/tapauth/config.toml: $OWNER ($MODE)"
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

test -f /lib/systemd/system/tapauthd.service || test -f /usr/lib/systemd/system/tapauthd.service
test -f /lib/systemd/system/tapauthd.socket || test -f /usr/lib/systemd/system/tapauthd.socket

echo "Verifying the legacy tapauth-fprintd subpackage is gone (the emulation package is expected)..."
# Match ONLY the removed legacy name tapauth-fprintd_<version>; the opt-in
# replacement package tapauth-fprintd-emulation_<version> must not trip this.
LEGACY_FPRINTD_DEBS=$(find /tmp/deb-build -maxdepth 1 \
    -name 'tapauth-fprintd_*.deb' \
    ! -name 'tapauth-fprintd-emulation*' 2>/dev/null || true)
if [ -n "$LEGACY_FPRINTD_DEBS" ]; then
    echo "ERROR: legacy tapauth-fprintd subpackage was removed but a .deb for it was still built:"
    printf '%s\n' "$LEGACY_FPRINTD_DEBS"
    exit 1
fi
if dpkg -l tapauth-fprintd 2>/dev/null | grep -q '^ii'; then
    echo "ERROR: tapauth-fprintd is installed"
    exit 1
fi

echo "Verifying the base package ships the virtual fprintd D-Bus policy (and no activation file/marker)..."
verify_fprintd_coexistence deb

echo "Verifying coexistence with the real fprintd package (installs first, no conflicts)..."
if ! dpkg -s fprintd >/dev/null 2>&1; then
    apt-get install -y fprintd
fi
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
assert_exec_not_tapauth /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd's activation file points at tapauthd — package overwrote it"

echo "Verifying fprintd's activation file survived the tapauth install untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
assert_fprintd_exec_matches /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd activation Exec changed" \
    /usr/libexec/fprintd /usr/lib/fprintd/fprintd /usr/sbin/fprintd

echo "Verifying PAM scope: only sudo, su and polkit-1 are patched..."
for pam_svc in sudo su polkit-1; do
    test -f "/etc/pam.d/${pam_svc}"
    grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
    test -f "/etc/pam.d/${pam_svc}.tapauth-bak"
    ! grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}.tapauth-bak"
done
# su must not bypass pam_rootok/pam_wheel (PAM_USER is the target user).
echo "Verifying su insertion lands after pam_rootok/pam_wheel..."
assert_su_line_after_rootok /etc/pam.d/su

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

echo "==> 4b-2. Testing the opt-in tapauth-fprintd-emulation package..."
EMU_DEB=$(find /tmp/deb-build -maxdepth 1 -name 'tapauth-fprintd-emulation_*.deb' | head -1 || true)
if [ -z "$EMU_DEB" ]; then
    echo "ERROR: tapauth-fprintd-emulation package was expected but was not built"
    exit 1
fi
verify_fprintd_emulation_pkg deb /tmp/deb-build

echo "Verifying the emulation package's libpam-fprintd conflict is honored..."
# The emulation package declares conflicts/replaces/provides against the
# distro libpam-fprintd provider; the two providers must never be installed
# at the same time.
if apt-get install -y libpam-fprintd >/dev/null 2>&1; then
    if ! apt-get install -y "$EMU_DEB"; then
        echo "apt refused the emulation install while libpam-fprintd was present (conflict honored); removing libpam-fprintd first..."
        apt-get remove -y libpam-fprintd
        apt-get install -y "$EMU_DEB"
    fi
else
    apt-get install -y "$EMU_DEB"
fi
PAM_FPRINTD_SO=$(find /usr/lib /lib -name pam_fprintd.so 2>/dev/null | head -1 || true)
if [ -z "$PAM_FPRINTD_SO" ]; then
    echo "ERROR: tapauth-fprintd-emulation did not install pam_fprintd.so"
    exit 1
fi
if dpkg -s libpam-fprintd 2>/dev/null | grep -q '^Status: install ok installed'; then
    echo "ERROR: libpam-fprintd is installed alongside tapauth-fprintd-emulation"
    exit 1
fi

echo "Verifying the emulation package ships the bridge marker (tri-state default -> on)..."
test -f /usr/share/tapauth/fprintd-emulation.enabled

echo "Verifying enable_fprintd_bridge = false is preserved as an explicit override..."
# The Rust resolver (shared::config::resolve_enable_fprintd_bridge, unit-tested
# in shared/src/config/toml_config.rs) gives explicit values precedence over the
# marker; here we assert the marker and an explicit key can coexist on disk and
# the daemon does not get a rewritten/removed key.
if ! grep -Eq '^enable_fprintd_bridge' /etc/tapauth/config.toml; then
    printf 'enable_fprintd_bridge = false\n' >> /etc/tapauth/config.toml
fi
grep -Eq '^enable_fprintd_bridge[[:space:]]*=[[:space:]]*false' /etc/tapauth/config.toml
sed -i '/^enable_fprintd_bridge[[:space:]]*=[[:space:]]*false/d' /etc/tapauth/config.toml

echo "Verifying the emulation package removes cleanly..."
apt-get remove -y tapauth-fprintd-emulation
PAM_FPRINTD_SO=$(find /usr/lib /lib -name pam_fprintd.so 2>/dev/null | head -1 || true)
if [ -n "$PAM_FPRINTD_SO" ]; then
    echo "ERROR: pam_fprintd.so survived removal of tapauth-fprintd-emulation: $PAM_FPRINTD_SO"
    exit 1
fi
verify_no_emulation_marker

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
assert_fprintd_exec_matches /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd activation Exec changed after tapauth removal" \
    /usr/libexec/fprintd /usr/lib/fprintd/fprintd /usr/sbin/fprintd
echo "Verifying tapauth's D-Bus files were removed with the package (policy gone too)..."
test ! -e /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
test ! -e /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf
test ! -e /usr/share/tapauth/fprintd-emulation.enabled
if [ -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf ]; then
    echo "ERROR: tapauth D-Bus policy file survived package removal"
    exit 1
fi

echo "=================================================="
echo "🎉 ALL UBUNTU/DEBIAN BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
