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
    cp "${WORKSPACE_DIR}/packaging/arch/tapauth-fprintd.install" "${BUILD_DIR}/tapauth-fprintd.install"
    cp "${WORKSPACE_DIR}/packaging/arch/"*.hook "${BUILD_DIR}/" 2>/dev/null || true
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
    PKG_DIR="${PKG_DIR:-${WORKSPACE_DIR}/pkg-arch}"
fi

echo "==> 6. Testing installation of base package (tapauth)..."
pacman -U --noconfirm "${PKG_DIR}"/tapauth-${PKG_VER}-*.pkg.tar.zst

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

test -f /usr/lib/systemd/system/tapauthd.service
test -f /usr/lib/systemd/system/tapauthd.socket
test -f /usr/lib/security/pam_tapauth.so

echo "==> 7. Setting up simulated pam_fprintd in kde-fingerprint to verify auto-repair..."
mkdir -p /etc/pam.d
cat << 'PAMEof' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
account include       system-login
PAMEof

echo "==> 8. Testing installation of subpackage (tapauth-fprintd)..."
pacman -U --noconfirm "${PKG_DIR}"/tapauth-fprintd-${PKG_VER}-*.pkg.tar.zst

echo "Checking config file and bridge enablement after subpackage install..."
grep "enable_fprintd_bridge = true" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
test -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf
test -f /usr/share/libalpm/hooks/tapauth-fprintd-pam.hook

echo "Verifying that kde-fingerprint was updated to pam_tapauth.so..."
grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
! grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint

echo "==> 9. Testing removal of subpackage (tapauth-fprintd)..."
pacman -R --noconfirm tapauth-fprintd
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

echo "Verifying that kde-fingerprint reverted pam_fprintd.so..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint

echo "==> 10. Testing simultaneous removal of both packages..."
pacman -U --noconfirm "${PKG_DIR}"/tapauth-fprintd-${PKG_VER}-*.pkg.tar.zst
grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
pacman -R --noconfirm tapauth-fprintd tapauth
echo "Verifying that kde-fingerprint has pam_fprintd.so restored and not wiped after simultaneous removal..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint

echo "=================================================="
echo "🎉 ALL ARCH LINUX BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
