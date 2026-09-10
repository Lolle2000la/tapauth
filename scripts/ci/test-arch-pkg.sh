#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
cd "$WORKSPACE_DIR"

SKIP_BUILD=false
PKG_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=true
            if [[ $# -ge 2 && "$2" != --* ]]; then
                PKG_DIR="$2"
                shift 2
            else
                shift
            fi
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)
echo "==> Testing Arch Linux packaging for TapAuth version: ${PKG_VER}..."

# Shared virtual-fprintd D-Bus coexistence verification helpers
source "${WORKSPACE_DIR}/scripts/ci/verify-fprintd-coexistence.sh"

BUILD_DIR="/home/builder/pkg"

if [ "$SKIP_BUILD" = false ]; then
    echo "==> 1. Updating pacman databases and installing build dependencies..."
    pacman -Syu --noconfirm --needed sudo cargo rust protobuf clang pam dbus systemd git tar binutils findutils sed grep wayland

    echo "==> 2. Setting up unprivileged builder user..."
    if ! id -u builder >/dev/null 2>&1; then
        useradd -m -s /bin/bash builder
        echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
    fi

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    echo "==> 3. Packaging local source tarball for offline/local makepkg..."
    mkdir -p "/tmp/src/tapauth-${PKG_VER}"
    tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "/tmp/src/tapauth-${PKG_VER}" -xf -
    tar -C /tmp/src -czf "${BUILD_DIR}/tapauth-${PKG_VER}.tar.gz" "tapauth-${PKG_VER}"

    cp "${WORKSPACE_DIR}/packaging/arch/PKGBUILD" "${BUILD_DIR}/PKGBUILD"
    cp "${WORKSPACE_DIR}/packaging/arch/tapauth.install" "${BUILD_DIR}/tapauth.install"
    cp "${WORKSPACE_DIR}/config.toml.example" "${BUILD_DIR}/config.toml.example"

    # Adjust PKGBUILD for local tarball build
    sed -i "s/^pkgver=.*/pkgver=${PKG_VER}/" "${BUILD_DIR}/PKGBUILD"
    sed -i "s|^source=.*|source=(\"tapauth-\${pkgver}.tar.gz\")|" "${BUILD_DIR}/PKGBUILD"
    sed -i "s|^sha256sums=.*|sha256sums=('SKIP')|" "${BUILD_DIR}/PKGBUILD"

    chown -R builder:builder "$BUILD_DIR" "/home/builder"

    echo "==> 4. Building Arch packages with makepkg..."
    su builder -c "cd '$BUILD_DIR' && makepkg -s --noconfirm"

    echo "==> 5. Generated Arch packages:"
    ls -la "${BUILD_DIR}"/*.pkg.tar.zst
    PKG_DIR="${BUILD_DIR}"
else
    echo "==> Updating pacman databases..."
    pacman -Sy --noconfirm
    PKG_DIR="${PKG_DIR:-${WORKSPACE_DIR}/pkg-arch}"
fi

echo "Verifying the tapauth-fprintd subpackage is gone (only the base package is built)..."
if ls "${PKG_DIR}"/tapauth-fprintd-*.pkg.tar.zst >/dev/null 2>&1; then
    echo "ERROR: tapauth-fprintd subpackage was removed but a package for it was still built"
    exit 1
fi

# tapauth-git must ship the same install scriptlet as tapauth: the two
# scriptlets are kept in lockstep so both packages behave identically. Only
# the tapauth-fprintd notice lines may differ (package names differ).
echo "Verifying tapauth-git install scriptlet parity with tapauth..."
if ! diff "${WORKSPACE_DIR}/packaging/arch/tapauth.install" "${WORKSPACE_DIR}/packaging/arch-git/tapauth-git.install" > /tmp/scriptlet-parity.diff; then
    # Every changed line must be one of the fprintd-notice lines.
    if grep -E '^[<>]' /tmp/scriptlet-parity.diff | grep -qv "tapauth-fprintd"; then
        echo "ERROR: tapauth-git.install diverges from tapauth.install beyond the fprintd notice:"
        cat /tmp/scriptlet-parity.diff
        exit 1
    fi
    echo "tapauth-git scriptlet parity OK (only the fprintd notice differs)."
else
    echo "tapauth-git scriptlet parity OK (identical)."
fi

echo "Creating dummy kde-fingerprint PAM stack to verify it stays STOCK..."
mkdir -p /etc/pam.d
cat << 'PAMEof' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
account include       system-login
PAMEof

echo "==> 7. Testing installation of base package (tapauth)..."
echo "Installing the REAL fprintd package first (coexistence P0 test: tapauth"
echo "must install without file conflicts over fprintd's D-Bus activation file)..."
pacman -S --noconfirm --needed fprintd
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
assert_exec_not_tapauth /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd's activation file points at tapauthd"
pacman -U --noconfirm "${PKG_DIR}"/tapauth-${PKG_VER}-*.pkg.tar.zst

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

test -f /usr/lib/systemd/system/tapauthd.service
test -f /usr/lib/systemd/system/tapauthd.socket
test -f /usr/lib/security/pam_tapauth.so

echo "Verifying the virtual fprintd D-Bus policy + renamed activation file ship in the base package..."
verify_fprintd_coexistence arch
test ! -e /usr/share/libalpm/hooks/tapauth-fprintd-pam.hook
# polkit vendor-drift hook must ship.
test -f /usr/share/libalpm/hooks/tapauth-polkit-pam.hook
test -f /usr/share/libalpm/scripts/tapauth-polkit-pam
# No live config.toml may be shipped (only the example; post_install seeds
# /etc/tapauth/config.toml from it). Shipping a live config causes .pacnew churn.
if pacman -Ql tapauth | grep -qE "etc/tapauth/config.toml$"; then
    echo "ERROR: package ships a live /etc/tapauth/config.toml (should only ship config.toml.example)"
    exit 1
fi
if [ ! -f /etc/tapauth/config.toml ]; then
    echo "ERROR: post_install did not seed /etc/tapauth/config.toml from the example"
    exit 1
fi
if pacman -Qq tapauth-fprintd >/dev/null 2>&1 || pacman -Qq tapauth-fprintd-git >/dev/null 2>&1; then
    echo "ERROR: tapauth-fprintd(-git) subpackage is installed"
    exit 1
fi

echo "Verifying PAM scope: only sudo, su and polkit-1 are patched..."
for pam_svc in sudo su polkit-1; do
    test -f "/etc/pam.d/${pam_svc}"
    grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
    test -f "/etc/pam.d/${pam_svc}.tapauth-bak"
    ! grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}.tapauth-bak"
done

echo "Verifying fprintd's activation file survived the tapauth install untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
assert_fprintd_exec_matches /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd activation Exec changed after tapauth install" \
    /usr/libexec/fprintd /usr/lib/fprintd

# Verify the polkit vendor-drift hook script works: simulate a polkit
# upgrade by rewriting the vendor file, run the hook script, and assert the
# override was re-seeded with the tapauth line re-applied.
echo "Verifying the polkit vendor-drift hook script..."
if [ -f /usr/lib/pam.d/polkit-1 ]; then
    cp /usr/lib/pam.d/polkit-1 /tmp/polkit-1.vendor
    cp /etc/pam.d/polkit-1 /tmp/polkit-1.before-hook || true
    sed -i '1i # SIMULATED POLKIT UPGRADE' /usr/lib/pam.d/polkit-1
    /usr/share/libalpm/scripts/tapauth-polkit-pam
    if ! grep -q "pam_tapauth\.so" /etc/pam.d/polkit-1; then
        echo "ERROR: drift hook did not re-apply the tapauth line after simulated polkit upgrade"
        cp /tmp/polkit-1.vendor /usr/lib/pam.d/polkit-1
        exit 1
    fi
    if ! grep -q "SIMULATED POLKIT UPGRADE" /etc/pam.d/polkit-1; then
        echo "ERROR: drift hook did not re-seed the override from the new vendor file"
        cp /tmp/polkit-1.vendor /usr/lib/pam.d/polkit-1
        exit 1
    fi
    if ! grep -q "pam_tapauth\.so" /etc/pam.d/polkit-1; then
        echo "ERROR: re-seeded override lost the tapauth line"
        cp /tmp/polkit-1.vendor /usr/lib/pam.d/polkit-1
        exit 1
    fi
    cp /tmp/polkit-1.vendor /usr/lib/pam.d/polkit-1
    echo "polkit drift hook works."
fi

echo "Verifying that kde-fingerprint was NOT modified (stays stock)..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
test ! -e /etc/pam.d/kde-fingerprint.tapauth-bak

echo "==> 8. Testing package upgrade (exercises post_upgrade)..."
pacman -U --noconfirm "${PKG_DIR}"/tapauth-${PKG_VER}-*.pkg.tar.zst

echo "Verifying permissions, config, and PAM wiring survived upgrade..."
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

echo "Verifying that kde-fingerprint still has pam_fprintd.so (stock) after upgrade..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint

echo "==> 9. Testing removal of the base package (tapauth)..."
pacman -R --noconfirm tapauth

echo "Verifying the three PAM services were restored upon removal..."
for pam_svc in sudo su polkit-1; do
    if [ -f "/etc/pam.d/${pam_svc}" ]; then
        ! grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
    fi
    test ! -e "/etc/pam.d/${pam_svc}.tapauth-bak"
done

echo "Verifying that kde-fingerprint still has pam_fprintd.so (stock) after removal..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
test ! -e /etc/pam.d/kde-fingerprint.tapauth-bak

echo "Verifying the real fprintd package survived the full tapauth lifecycle untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
assert_fprintd_exec_matches /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd activation Exec changed after tapauth removal" \
    /usr/libexec/fprintd /usr/lib/fprintd
echo "Verifying tapauth's renamed D-Bus files were removed with the package..."
test ! -e /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
test ! -e /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "=================================================="
echo "🎉 ALL ARCH LINUX BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
