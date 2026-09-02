#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
cd "$WORKSPACE_DIR"

PKG_VER=$(grep '^version = ' "${WORKSPACE_DIR}/Cargo.toml" | head -1 | cut -d '"' -f2 || echo "0.1.0")
echo "==> Testing Arch Linux packaging for TapAuth version: ${PKG_VER}..."

echo "==> 1. Updating pacman databases and installing build dependencies..."
pacman -Syu --noconfirm --needed sudo rust protobuf clang pam dbus systemd git tar binutils findutils sed grep

echo "==> 2. Setting up unprivileged builder user..."
if ! id -u builder >/dev/null 2>&1; then
    useradd -m -s /bin/bash builder
    echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
fi

BUILD_DIR="/home/builder/pkg"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> 3. Packaging local source tarball for offline/local makepkg..."
mkdir -p "/tmp/src/tapauth-${PKG_VER}"
tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "/tmp/src/tapauth-${PKG_VER}" -xf -
tar -C /tmp/src -czf "${BUILD_DIR}/tapauth-${PKG_VER}.tar.gz" "tapauth-${PKG_VER}"

cp "${WORKSPACE_DIR}/packaging/arch/PKGBUILD" "${BUILD_DIR}/PKGBUILD"
cp "${WORKSPACE_DIR}/packaging/arch/tapauth.install" "${BUILD_DIR}/tapauth.install"
cp "${WORKSPACE_DIR}/packaging/arch/tapauth-fprintd.install" "${BUILD_DIR}/tapauth-fprintd.install"
cp "${WORKSPACE_DIR}/config.toml.example" "${BUILD_DIR}/config.toml.example"

# Adjust PKGBUILD for local tarball build
sed -i "s/^pkgver=.*/pkgver=${PKG_VER}/" "${BUILD_DIR}/PKGBUILD"
sed -i "s|^source=.*|source=(\"tapauth-\${pkgver}.tar.gz\")|" "${BUILD_DIR}/PKGBUILD"
sed -i "s|^sha256sums=.*|sha256sums=('SKIP')|" "${BUILD_DIR}/PKGBUILD"

chown -R builder:builder "$BUILD_DIR" "/home/builder"

echo "==> 4. Building Arch packages with makepkg..."
su builder -c "cd '$BUILD_DIR' && makepkg --noconfirm"

echo "==> 5. Generated Arch packages:"
ls -la "${BUILD_DIR}"/*.pkg.tar.zst

echo "==> 6. Testing installation of base package (tapauth)..."
pacman -U --noconfirm "${BUILD_DIR}"/tapauth-${PKG_VER}-*.pkg.tar.zst

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
pacman -U --noconfirm "${BUILD_DIR}"/tapauth-fprintd-${PKG_VER}-*.pkg.tar.zst

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

echo "==> 9. Testing removal of subpackage (tapauth-fprintd)..."
pacman -R --noconfirm tapauth-fprintd
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

echo "Verifying that kde-fingerprint reverted pam_fprintd.so..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint

echo "==> 10. Adding simulated pam_tapauth.so line to system-auth to test pre_remove cleanup..."
echo "auth sufficient pam_tapauth.so" >> /etc/pam.d/system-auth

echo "==> 11. Testing complete removal of base package (tapauth)..."
pacman -R --noconfirm tapauth

echo "Verifying pam_tapauth.so was stripped from system-auth on uninstall..."
! grep "pam_tapauth.so" /etc/pam.d/system-auth

echo "=================================================="
echo "🎉 ALL ARCH LINUX BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
