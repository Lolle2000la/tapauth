#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
cd "$WORKSPACE_DIR"

PKG_VER=$(grep '^version = ' "${WORKSPACE_DIR}/Cargo.toml" | head -1 | cut -d '"' -f2 || echo "0.1.0")
echo "==> Testing Ubuntu/Debian packaging for TapAuth version: ${PKG_VER}..."

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

BUILD_DIR="/tmp/deb-build/tapauth-${PKG_VER}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> 2. Copying workspace to clean build directory..."
tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "$BUILD_DIR" -xf -
cd "$BUILD_DIR"

echo "==> 3. Generating debian packaging files..."
mkdir -p debian/source
echo "3.0 (native)" > debian/source/format

cat > debian/changelog <<EOF
tapauth (${PKG_VER}-1) noble; urgency=medium

  * Automated packaging test build.

 -- Luca Auer <lolle2000.la+tapauth@gmail.com>  $(date -R)
EOF

cat > debian/control <<'EOF'
Source: tapauth
Section: admin
Priority: optional
Maintainer: Luca Auer <lolle2000.la+tapauth@gmail.com>
Build-Depends: debhelper-compat (= 13), cargo, rustc, protobuf-compiler, libdbus-1-dev, libsystemd-dev, libpam0g-dev, clang, libclang-dev, pkg-config
Standards-Version: 4.7.0

Package: tapauth
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}, polkitd, libdbus-1-3, bluez
Suggests: firewalld, iptables, tapauth-fprintd
Description: Local smartphone-based authentication framework
 A modern, privacy-preserving local-first authentication system.

Package: tapauth-fprintd
Architecture: all
Depends: ${misc:Depends}, tapauth (>= ${source:Version}), dbus
Conflicts: fprintd
Provides: fprintd
Replaces: fprintd
Description: Virtual fprintd D-Bus bridge for TapAuth lock screen integration
 Virtual net.reactivated.Fprint D-Bus service.
EOF

cat > debian/rules <<'RULESEOF'
#!/usr/bin/make -f

export PATH := $(HOME)/.cargo/bin:$(PATH)
DEB_HOST_MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH)

%:
	dh $@

override_dh_auto_build:
	cargo build --workspace --release --locked

override_dh_auto_install:
	mkdir -p debian/tapauth/usr/bin
	mkdir -p debian/tapauth/lib/$(DEB_HOST_MULTIARCH)/security
	mkdir -p debian/tapauth/lib/systemd/system
	mkdir -p debian/tapauth/usr/lib/sysusers.d
	mkdir -p debian/tapauth/usr/lib/tmpfiles.d
	mkdir -p debian/tapauth/usr/share/pam-configs
	mkdir -p debian/tapauth/usr/share/applications
	mkdir -p debian/tapauth/usr/share/icons/hicolor/scalable/apps
	mkdir -p debian/tapauth/usr/share/polkit-1/actions
	mkdir -p debian/tapauth/usr/share/polkit-1/rules.d
	mkdir -p debian/tapauth/etc/tapauth
	mkdir -p debian/tapauth/lib/systemd/system/polkit-agent-helper@.service.d
	cp systemd/polkit-agent-helper@.service.d/tapauth.conf debian/tapauth/lib/systemd/system/polkit-agent-helper@.service.d/
	cp target/release/tapauthd debian/tapauth/usr/bin/
	cp target/release/tapauth-config debian/tapauth/usr/bin/
	cp target/release/libclient_pam.so debian/tapauth/lib/$(DEB_HOST_MULTIARCH)/security/pam_tapauth.so
	cp systemd/tapauthd.service debian/tapauth/lib/systemd/system/
	cp systemd/tapauthd.socket debian/tapauth/lib/systemd/system/
	cp packaging/sysusers.conf debian/tapauth/usr/lib/sysusers.d/tapauth.conf
	cp packaging/tmpfiles.conf debian/tapauth/usr/lib/tmpfiles.d/tapauth.conf
	cp packaging/debian.pam-config debian/tapauth/usr/share/pam-configs/tapauth
	cp client-config-gui/tapauth-config.desktop debian/tapauth/usr/share/applications/
	cp client-config-gui/assets/tapauth-config.svg debian/tapauth/usr/share/icons/hicolor/scalable/apps/
	cp tapauthd/dev.rourunisen.tapauth.config.admin.policy debian/tapauth/usr/share/polkit-1/actions/
	cp packaging/50-tapauthd.rules debian/tapauth/usr/share/polkit-1/rules.d/
	
	mkdir -p debian/tapauth-fprintd/usr/share/dbus-1/system-services
	mkdir -p debian/tapauth-fprintd/usr/share/dbus-1/system.d
	cp packaging/net.reactivated.Fprint.service debian/tapauth-fprintd/usr/share/dbus-1/system-services/
	cp packaging/net.reactivated.Fprint.tapauth.conf debian/tapauth-fprintd/usr/share/dbus-1/system.d/
RULESEOF
chmod +x debian/rules

cat > debian/postinst <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
	systemd-sysusers /usr/lib/sysusers.d/tapauth.conf
	systemd-tmpfiles --create /usr/lib/tmpfiles.d/tapauth.conf
	mkdir -p /etc/tapauth
	if [ ! -f /etc/tapauth/config.toml ]; then
		printf "# TapAuth Configuration\nenable_fprintd_bridge = false\n" > /etc/tapauth/config.toml
		chmod 644 /etc/tapauth/config.toml
		chown tapauthd:tapauthd /etc/tapauth/config.toml 2>/dev/null || true
	fi
	if command -v pam-auth-update >/dev/null 2>&1; then
		pam-auth-update --package
	fi
fi
#DEBHELPER#
exit 0
EOF

cat > debian/postrm <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
	if command -v pam-auth-update >/dev/null 2>&1; then
		pam-auth-update --package
	fi
fi
if [ "$1" = "purge" ]; then
	rm -rf /etc/tapauth /var/lib/tapauth /run/tapauthd || true
	systemd-tmpfiles --remove /usr/lib/tmpfiles.d/tapauth.conf 2>/dev/null || true
fi
#DEBHELPER#
exit 0
EOF

cat > debian/tapauth-fprintd.postinst <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
	if [ -z "$2" ]; then
		mkdir -p /etc/tapauth
		if [ ! -f /etc/tapauth/config.toml ]; then
			printf "# TapAuth Configuration\nenable_fprintd_bridge = true\n" > /etc/tapauth/config.toml
		elif grep -Eq '^[[:space:]]*#?[[:space:]]*enable_fprintd_bridge' /etc/tapauth/config.toml; then
			sed -i -E 's/^[[:space:]]*#?[[:space:]]*enable_fprintd_bridge[[:space:]]*=.*/enable_fprintd_bridge = true/' /etc/tapauth/config.toml
		else
			echo "enable_fprintd_bridge = true" >> /etc/tapauth/config.toml
		fi
		chmod 644 /etc/tapauth/config.toml
		chown tapauthd:tapauthd /etc/tapauth/config.toml 2>/dev/null || true
	fi
	if command -v deb-systemd-invoke >/dev/null 2>&1; then
		deb-systemd-invoke reload dbus || true
		deb-systemd-invoke try-restart tapauthd.service || true
	elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dbus 2>/dev/null; then
		systemctl reload dbus 2>/dev/null || true
		systemctl try-restart tapauthd.service 2>/dev/null || true
	fi
fi
#DEBHELPER#
exit 0
EOF

cat > debian/tapauth-fprintd.postrm <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
	if [ -f /etc/tapauth/config.toml ]; then
		sed -i -E 's/^[[:space:]]*#?[[:space:]]*enable_fprintd_bridge[[:space:]]*=.*/enable_fprintd_bridge = false/' /etc/tapauth/config.toml 2>/dev/null || true
		chmod 644 /etc/tapauth/config.toml
		chown tapauthd:tapauthd /etc/tapauth/config.toml 2>/dev/null || true
	fi
	if command -v deb-systemd-invoke >/dev/null 2>&1; then
		deb-systemd-invoke reload dbus || true
		deb-systemd-invoke try-restart tapauthd.service || true
	elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet dbus 2>/dev/null; then
		systemctl reload dbus 2>/dev/null || true
		systemctl try-restart tapauthd.service 2>/dev/null || true
	fi
fi
#DEBHELPER#
exit 0
EOF

echo "==> 4. Building Debian packages with dpkg-buildpackage..."
dpkg-buildpackage -us -uc -b -d

echo "==> 5. Generated Debian packages:"
ls -la /tmp/deb-build/*.deb

echo "==> 6. Testing installation of base package (tapauth)..."
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

echo "==> 7. Testing installation of subpackage (tapauth-fprintd)..."
apt-get install -y /tmp/deb-build/tapauth-fprintd_${PKG_VER}*.deb

echo "Checking config file and bridge enablement after subpackage install..."
grep "enable_fprintd_bridge = true" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
test -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "==> 8. Testing removal of subpackage (tapauth-fprintd)..."
apt-get remove -y tapauth-fprintd
grep "enable_fprintd_bridge = false" /etc/tapauth/config.toml
OWNER=$(stat -c "%U:%G" /etc/tapauth/config.toml)
MODE=$(stat -c "%a" /etc/tapauth/config.toml)
test "$OWNER" = "tapauthd:tapauthd"
test "$MODE" = "644"

echo "==> 9. Testing purge of base package (tapauth)..."
apt-get purge -y tapauth
test ! -d /etc/tapauth

echo "=================================================="
echo "🎉 ALL UBUNTU/DEBIAN BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
