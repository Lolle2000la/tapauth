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
echo "==> Testing Fedora RPM packaging for TapAuth version: ${PKG_VER}..."

if [ "$SKIP_BUILD" = false ]; then
    echo "==> 1. Installing Fedora build dependencies and rpmlint..."
    dnf install -y --setopt=install_weak_deps=False \
        rpm-build rpmlint rust cargo protobuf-compiler clang pam-devel systemd-devel dbus-devel systemd-rpm-macros sed tar git findutils selinux-policy policycoreutils

    echo "==> 2. Setting up RPM build directory..."
    mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp "${WORKSPACE_DIR}/packaging/tapauth.spec" /root/rpmbuild/SPECS/tapauth.spec

    # Update spec version if needed
    sed -i "s/%{?pkgversion}%{!?pkgversion:0.1.0}/${PKG_VER}/g" /root/rpmbuild/SPECS/tapauth.spec

    echo "==> 3. Running rpmlint on spec file (with the shipped rpmlintrc)..."
    rpmlint --ignore-unused-rpmlintrc -r "${WORKSPACE_DIR}/packaging/tapauth.rpmlintrc" /root/rpmbuild/SPECS/tapauth.spec

    echo "==> 3b. Compile-checking the SELinux policy module against the real policy store..."
    # NOTE: bare `secilc` cannot compile CIL fragments that reference distro
    # types (xdm_t, init_t, ...); semodule against the installed selinux-policy
    # store is the correct validation (resolves all distro type declarations).
    semodule -n -i "${WORKSPACE_DIR}/packaging/selinux/tapauth.cil" \
        && echo "SELinux policy compiles cleanly" \
        || { echo "ERROR: SELinux policy failed to compile"; exit 1; }
    semodule -n -X 400 -r tapauth 2>/dev/null || true

    echo "==> 4. Packaging source tarball..."
    mkdir -p "/tmp/src/tapauth-${PKG_VER}"
    tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "/tmp/src/tapauth-${PKG_VER}" -xf -
    tar -C /tmp/src -czf "/root/rpmbuild/SOURCES/tapauth-${PKG_VER}.tar.gz" "tapauth-${PKG_VER}"
    cp "${WORKSPACE_DIR}/packaging/sysusers.conf" "/root/rpmbuild/SOURCES/tapauth-sysusers.conf"
    cp "${WORKSPACE_DIR}/packaging/tmpfiles.conf" "/root/rpmbuild/SOURCES/tapauth-tmpfiles.conf"

    echo "==> 5. Building SRPM and Binary RPMs with rpmbuild..."
    rpmbuild -ba /root/rpmbuild/SPECS/tapauth.spec --define "_topdir /root/rpmbuild"

    echo "==> 6. Generated RPMs:"
    ls -la /root/rpmbuild/RPMS/*/*.rpm

    echo "==> 7. Running rpmlint on generated RPM packages (with the shipped rpmlintrc; errors are fatal)..."
    rpmlint --ignore-unused-rpmlintrc -r "${WORKSPACE_DIR}/packaging/tapauth.rpmlintrc" /root/rpmbuild/RPMS/*/*.rpm
    # NOTE: must be a literal directory (not a glob) — several call sites
    # quote "${PKG_DIR}" and a quoted glob would never expand.
    PKG_DIR="$(dirname "$(find /root/rpmbuild/RPMS -name "tapauth-${PKG_VER}-*.rpm" | head -1)")"
else
    dnf install -y --setopt=install_weak_deps=False sed grep rpmlint || true
    PKG_DIR="${PKG_DIR:-${WORKSPACE_DIR}/pkg-fedora}"
fi

echo "==> 8. Testing installation of base package (tapauth)..."
echo "Installing the REAL fprintd package first (coexistence P0 test: tapauth"
echo "must install without file conflicts over fprintd's D-Bus activation file)..."
if ! rpm -q fprintd >/dev/null 2>&1; then
    dnf install -y fprintd
fi
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
echo "Real fprintd activation Exec: $FPRINT_BIN"
case "$FPRINT_BIN" in
    /usr/libexec/fprintd|/usr/lib/fprintd/fprintd|/usr/sbin/fprintd) : ;;
    *) echo "ERROR: fprintd activation Exec unexpected: $FPRINT_BIN"; exit 1 ;;
esac
dnf install -y "${PKG_DIR}"/tapauth-${PKG_VER}-*.rpm

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

echo "Verifying rpm integrity (rpm -V tapauth)..."
rpm -V tapauth

echo "Verifying the tapauth-fprintd subpackage is gone..."
if ls "${PKG_DIR}"/tapauth-fprintd-*.rpm >/dev/null 2>&1; then
    echo "ERROR: tapauth-fprintd subpackage was removed but an .rpm for it was still built"
    exit 1
fi
if rpm -q tapauth-fprintd >/dev/null 2>&1; then
    echo "ERROR: tapauth-fprintd is installed"
    exit 1
fi

echo "Verifying no authselect vendor profile is shipped anymore..."
test ! -e /usr/share/authselect/vendor/tapauth
test ! -e /usr/share/authselect/vendor/tapauth-sssd

echo "Verifying the virtual fprintd D-Bus policy + renamed activation file ship in the base package..."
test -f /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf
# The activation file is RENAMED (net.reactivated.Fprint.tapauth.service) so
# it can never collide with real fprintd's own
# net.reactivated.Fprint.service. Container-verified semantics: BOTH
# dbus-daemon (1.12.20 & 1.14.10) and dbus-broker (36 — Fedora's default
# broker) require the service file's filename to match the bus name, so the
# renamed file is an inert, collision-free placeholder — neither broker
# uses it for activation; real fprintd keeps full control of on-demand
# activation. The file still ships (never zero activation files) for
# forward compatibility.
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
grep -q '^Name=net.reactivated.Fprint$' /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
grep -q '^Exec=/usr/bin/tapauthd$' /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
grep -q '^User=tapauthd$' /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
grep -q '^SystemdService=tapauthd.service$' /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
# tapauth must never own (or overwrite) fprintd's exact activation filename.
# The un-renamed file may legitimately exist on disk because the
# coexistence test installs the real fprintd package.
if rpm -ql tapauth | grep -q "system-services/net.reactivated.Fprint.service$"; then
    echo "ERROR: tapauth ships the un-renamed net.reactivated.Fprint.service (collision with fprintd)"
    exit 1
fi
if [ -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service ]; then
    FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
    case "$FPRINT_BIN" in
        *tapauthd*) echo "ERROR: net.reactivated.Fprint.service points at tapauthd (tapauth must never own that file)"; exit 1 ;;
    esac
fi

echo "Verifying coexistence with the real fprintd package (installs first, no conflicts)..."
if ! rpm -q fprintd >/dev/null 2>&1; then
    dnf install -y fprintd
fi
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
echo "Real fprintd activation Exec: $FPRINT_BIN"
case "$FPRINT_BIN" in
    /usr/libexec/fprintd|/usr/lib/fprintd/fprintd|/usr/sbin/fprintd) : ;;
    *) echo "ERROR: fprintd activation Exec unexpected: $FPRINT_BIN"; exit 1 ;;
esac

echo "Verifying fprintd's activation file survived the tapauth install untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
FPRINT_BIN=$(grep -m1 '^Exec=' /usr/share/dbus-1/system-services/net.reactivated.Fprint.service | sed 's/^Exec=//;s/ .*//')
case "$FPRINT_BIN" in
    /usr/libexec/fprintd|/usr/lib/fprintd/fprintd|/usr/sbin/fprintd) : ;;
    *) echo "ERROR: fprintd activation Exec changed after tapauth install: $FPRINT_BIN"; exit 1 ;;
esac

echo "Verifying PAM scope: only sudo, su and polkit-1 are patched..."
for pam_svc in sudo su polkit-1; do
    if [ -f "/etc/pam.d/${pam_svc}" ]; then
        grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}"
        test -f "/etc/pam.d/${pam_svc}.tapauth-bak"
        ! grep "pam_tapauth.so" "/etc/pam.d/${pam_svc}.tapauth-bak"
    else
        echo "ERROR: /etc/pam.d/${pam_svc} missing after install (no /usr/lib/pam.d vendor file either?)"
        exit 1
    fi
done

echo "Creating dummy kde-fingerprint PAM stack to verify it stays STOCK..."
mkdir -p /etc/pam.d
cat << 'PAMEof' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
account include       system-auth
PAMEof

echo "==> 9b. Testing package upgrade (rpm -Uvh --replacepkgs)..."
rpm -Uvh --replacepkgs "${PKG_DIR}"/tapauth-${PKG_VER}-*.rpm

echo "Verifying %config(noreplace) preserved config.toml and PAM wiring survived upgrade..."
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

echo "==> 9c. Upgrade-path test from a published v0.10.0-style package (authselect era)..."
# v0.10.0 shipped authselect vendor profiles (vendor/tapauth, vendor/
# tapauth-sssd) that users selected with `authselect select`. This package
# ships no profiles; removal must roll the selection back to the stock
# profile and leave no tapauth line in the generated stacks, or
# system-auth/password-auth would keep referencing the removed module.
if command -v authselect >/dev/null 2>&1; then
    rm -rf /etc/authselect/custom/tapauth
    mkdir -p /etc/authselect/custom/tapauth
    cp -a /usr/share/authselect/default/local/. /etc/authselect/custom/tapauth/
    sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' /etc/authselect/custom/tapauth/system-auth
    authselect select custom/tapauth --force
    grep "pam_tapauth.so" /etc/pam.d/system-auth
    echo "Simulated v0.10.0 authselect state in place; removing the package now (step 10) must roll back."
fi

echo "==> 10. Testing complete removal of the base package..."
rpm -e tapauth

if command -v authselect >/dev/null 2>&1 && [ -d /etc/authselect ]; then
    CURRENT_PROFILE=$(LC_ALL=C authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs || true)
    echo "authselect profile after removal: ${CURRENT_PROFILE:-<none>}"
    if [ "$CURRENT_PROFILE" = "custom/tapauth" ] || [ "$CURRENT_PROFILE" = "vendor/tapauth" ]; then
        echo "ERROR: removal did not roll back the TapAuth authselect profile"
        exit 1
    fi
    if [ -d /etc/authselect/custom/tapauth ]; then
        echo "ERROR: leftover /etc/authselect/custom/tapauth after removal"
        exit 1
    fi
    if [ -f /etc/pam.d/system-auth ] && grep -q "pam_tapauth.so" /etc/pam.d/system-auth; then
        echo "ERROR: generated system-auth still references pam_tapauth.so after removal (missing-module lockout)"
        exit 1
    fi
fi

echo "Verifying the three PAM services were restored upon removal..."
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
echo "Verifying tapauth's renamed D-Bus files were removed with the package..."
test ! -e /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
test ! -e /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

echo "=================================================="
echo "🎉 ALL FEDORA RPM BUILD, LINT AND INSTALL TESTS PASSED!"
echo "=================================================="
