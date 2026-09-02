#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
cd "$WORKSPACE_DIR"

PKG_VER=$(grep '^version = ' "${WORKSPACE_DIR}/Cargo.toml" | head -1 | cut -d '"' -f2 || echo "0.1.0")
echo "==> Testing Fedora RPM packaging for TapAuth version: ${PKG_VER}..."

echo "==> 1. Installing Fedora build dependencies and rpmlint..."
dnf install -y --setopt=install_weak_deps=False \
    rpm-build rpmlint rust cargo protobuf-compiler clang pam-devel dbus-devel systemd-rpm-macros authselect sed tar git findutils

echo "==> 2. Setting up RPM build directory..."
mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "${WORKSPACE_DIR}/packaging/tapauth.spec" /root/rpmbuild/SPECS/tapauth.spec

# Update spec version if needed
sed -i "s/%{?pkgversion}%{!?pkgversion:0.1.0}/${PKG_VER}/g" /root/rpmbuild/SPECS/tapauth.spec

echo "==> 3. Running rpmlint on spec file..."
rpmlint /root/rpmbuild/SPECS/tapauth.spec

echo "==> 4. Packaging source tarball..."
mkdir -p "/tmp/src/tapauth-${PKG_VER}"
tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "/tmp/src/tapauth-${PKG_VER}" -xf -
tar -C /tmp/src -czf "/root/rpmbuild/SOURCES/tapauth-${PKG_VER}.tar.gz" "tapauth-${PKG_VER}"

echo "==> 5. Building SRPM and Binary RPMs with rpmbuild..."
rpmbuild -ba /root/rpmbuild/SPECS/tapauth.spec --define "_topdir /root/rpmbuild"

echo "==> 6. Generated RPMs:"
ls -la /root/rpmbuild/RPMS/*/*.rpm

echo "==> 7. Running rpmlint on generated RPM packages..."
rpmlint /root/rpmbuild/RPMS/*/*.rpm

echo "==> 8. Testing installation of base package (tapauth)..."
dnf install -y /root/rpmbuild/RPMS/*/tapauth-${PKG_VER}-*.rpm

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

echo "Verifying rpm integrity (rpm -V tapauth)..."
rpm -V tapauth

echo "Testing authselect vendor profile activation and rollback..."
if command -v authselect >/dev/null 2>&1; then
    authselect select vendor/tapauth --force
    authselect check
    authselect select local --force
fi

echo "==> 9. Testing installation of subpackage (tapauth-fprintd)..."
dnf install -y /root/rpmbuild/RPMS/*/tapauth-fprintd-${PKG_VER}-*.rpm

echo "Checking config file and bridge enablement after subpackage install..."
grep "enable_fprintd_bridge = true" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
test -f /etc/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "==> 10. Testing removal of subpackage (tapauth-fprintd)..."
dnf remove -y tapauth-fprintd
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

echo "==> 11. Testing complete removal of base package..."
rpm -e tapauth

echo "=================================================="
echo "🎉 ALL FEDORA RPM BUILD, LINT AND INSTALL TESTS PASSED!"
echo "=================================================="
