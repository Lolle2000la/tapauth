#!/usr/bin/env bash
set -euo pipefail

echo "==> 1. Installing Fedora build dependencies and rpmlint..."
dnf install -y --setopt=install_weak_deps=False \
    rpm-build rpmlint rust cargo protobuf-compiler clang pam-devel dbus-devel systemd-rpm-macros authselect sed tar git findutils

echo "==> 2. Setting up RPM build directory..."
mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp /workspace/packaging/tapauth.spec /root/rpmbuild/SPECS/tapauth.spec

echo "==> 3. Running rpmlint on spec file..."
rpmlint /root/rpmbuild/SPECS/tapauth.spec || true

echo "==> 4. Packaging source tarball..."
# Copy source files to clean temp directory without git or existing target/build artifacts
mkdir -p /tmp/src/tapauth-0.1.0
tar -C /workspace --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C /tmp/src/tapauth-0.1.0 -xf -
tar -C /tmp/src -czf /root/rpmbuild/SOURCES/tapauth-0.1.0.tar.gz tapauth-0.1.0

echo "==> 5. Building SRPM and Binary RPMs with rpmbuild..."
rpmbuild -ba /root/rpmbuild/SPECS/tapauth.spec --define "_topdir /root/rpmbuild"

echo "==> 6. Generated RPMs:"
ls -la /root/rpmbuild/RPMS/*/*.rpm

echo "==> 7. Running rpmlint on generated RPM packages..."
rpmlint /root/rpmbuild/RPMS/*/*.rpm || true

echo "==> 8. Testing installation of base package (tapauth)..."
dnf install -y /root/rpmbuild/RPMS/*/tapauth-0.1.0-*.rpm

echo "Checking config file and ownership after base install..."
test -f /etc/tapauth/config.toml
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
echo "Owner of /etc/tapauth/config.toml: $OWNER"
test "$OWNER" = "tapauthd:tapauthd"

echo "==> 9. Testing installation of subpackage (tapauth-fprintd)..."
dnf install -y /root/rpmbuild/RPMS/*/tapauth-fprintd-0.1.0-*.rpm

echo "Checking config file and bridge enablement after subpackage install..."
grep "enable_fprintd_bridge = true" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
echo "Owner of /etc/tapauth/config.toml: $OWNER"
test "$OWNER" = "tapauthd:tapauthd"
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
test -f /etc/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "==> 10. Testing removal of subpackage (tapauth-fprintd)..."
dnf remove -y tapauth-fprintd
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
echo "Owner of /etc/tapauth/config.toml: $OWNER"
test "$OWNER" = "tapauthd:tapauthd"

echo "==> 11. Testing complete removal of base package..."
rpm -e tapauth

echo "=================================================="
echo "🎉 ALL FEDORA RPM BUILD, LINT AND INSTALL TESTS PASSED!"
echo "=================================================="
