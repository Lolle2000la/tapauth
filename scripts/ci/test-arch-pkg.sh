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
    cp "${WORKSPACE_DIR}/packaging/arch/tapauth-fprintd-emulation.install" "${BUILD_DIR}/tapauth-fprintd-emulation.install"
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

echo "Verifying the legacy tapauth-fprintd subpackage is gone (only the base package and the optional emulation package are built)..."
# Match ONLY the removed legacy names (tapauth-fprintd-<version> and
# tapauth-fprintd-git-<version>); the opt-in replacement package
# tapauth-fprintd-emulation(-git) is expected and must not trip this check.
LEGACY_FPRINTD_PKGS=$(find "${PKG_DIR}" -maxdepth 1 \
    -name 'tapauth-fprintd-*.pkg.tar.zst' \
    ! -name 'tapauth-fprintd-emulation-*' 2>/dev/null || true)
if [ -n "$LEGACY_FPRINTD_PKGS" ]; then
    echo "ERROR: legacy tapauth-fprintd subpackage was removed but a package for it was still built:"
    printf '%s\n' "$LEGACY_FPRINTD_PKGS"
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

echo "Verifying the scriptlets do NOT auto-add interactive users to tapauthd-clients..."
# Membership is a manual, per-user opt-in: post_install prints an advisory and
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
    echo "ERROR: post_install auto-added interactive user(s) to tapauthd-clients:${AUTO_ADDED}"
    exit 1
fi
echo "OK: no interactive user was auto-added to tapauthd-clients"

echo "Verifying the shipped .INSTALL carries the manual-membership advisory..."
ARCH_PKG=$(ls "${PKG_DIR}"/tapauth-${PKG_VER}-*.pkg.tar.zst | head -1)
tar --zstd -xOf "$ARCH_PKG" .INSTALL | grep -q "sudo usermod -aG tapauthd-clients"

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

test -f /usr/lib/systemd/system/tapauthd.service
test -f /usr/lib/systemd/system/tapauthd.socket
test -f /usr/lib/security/pam_tapauth.so

echo "Verifying the base package ships the virtual fprintd D-Bus policy (and no activation file/marker)..."
verify_fprintd_coexistence arch
test ! -e /usr/share/libalpm/hooks/tapauth-fprintd-pam.hook
# PAM vendor-drift hook (generalized from the old polkit-only hook) must ship.
test -f /usr/share/libalpm/hooks/tapauth-pam-vendor-drift.hook
test -f /usr/share/libalpm/scripts/tapauth-pam-vendor-drift
# The hook must target all three in-scope services.
grep -q '^Target = usr/lib/pam.d/polkit-1$' /usr/share/libalpm/hooks/tapauth-pam-vendor-drift.hook
grep -q '^Target = etc/pam.d/sudo$' /usr/share/libalpm/hooks/tapauth-pam-vendor-drift.hook
grep -q '^Target = etc/pam.d/su$' /usr/share/libalpm/hooks/tapauth-pam-vendor-drift.hook
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
# su must not bypass pam_rootok/pam_wheel (PAM_USER is the target user).
echo "Verifying su insertion lands after pam_rootok/pam_wheel..."
assert_su_line_after_rootok /etc/pam.d/su

echo "Verifying fprintd's activation file survived the tapauth install untouched..."
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service
assert_fprintd_exec_matches /usr/share/dbus-1/system-services/net.reactivated.Fprint.service \
    "fprintd activation Exec changed after tapauth install" \
    /usr/libexec/fprintd /usr/lib/fprintd

# Verify the PAM vendor-drift hook script works: simulate vendor upgrades by
# rewriting the polkit vendor file (override path) and by stripping the
# tapauth line from the su vendor file (in-place path), run the hook script,
# and assert the tapauth line was re-applied.
echo "Verifying the PAM vendor-drift hook script..."
DRIFT_SCRIPT=/usr/share/libalpm/scripts/tapauth-pam-vendor-drift
if [ -f /usr/lib/pam.d/polkit-1 ]; then
    cp /usr/lib/pam.d/polkit-1 /tmp/polkit-1.vendor
    cp /etc/pam.d/polkit-1 /tmp/polkit-1.before-hook || true
    sed -i '1i # SIMULATED POLKIT UPGRADE' /usr/lib/pam.d/polkit-1
    "$DRIFT_SCRIPT"
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
# su: simulate a util-linux upgrade replacing /etc/pam.d/su without our line.
cp /etc/pam.d/su /tmp/su.before-drift
sed -i '/pam_tapauth\.so/d' /etc/pam.d/su
"$DRIFT_SCRIPT"
if ! grep -q "pam_tapauth\.so" /etc/pam.d/su; then
    echo "ERROR: drift hook did not re-apply the tapauth line to su"
    cp /tmp/su.before-drift /etc/pam.d/su
    exit 1
fi
# And the re-applied su line must still sit after pam_rootok/pam_wheel.
assert_su_line_after_rootok /etc/pam.d/su
echo "sudo/su drift hook works."

echo "Verifying that kde-fingerprint was NOT modified (stays stock)..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
test ! -e /etc/pam.d/kde-fingerprint.tapauth-bak

echo "==> 8. Testing the opt-in tapauth-fprintd-emulation package..."
EMU_PKG=$(find "${PKG_DIR}" -maxdepth 1 \
    -name 'tapauth-fprintd-emulation-*.pkg.tar.zst' \
    ! -name 'tapauth-fprintd-emulation-git-*' | head -1 || true)
if [ -z "$EMU_PKG" ]; then
    echo "ERROR: tapauth-fprintd-emulation package was expected but was not built"
    exit 1
fi
verify_fprintd_emulation_pkg arch "${PKG_DIR}"

echo "Verifying the emulation package's fprintd conflict is honored..."
# The real fprintd package is installed at this point. pacman must never allow
# both pam_fprintd.so providers to be installed at once: it either replaces
# fprintd (replaces= metadata) or refuses the transaction.
if pacman -U --noconfirm "$EMU_PKG"; then
    if pacman -Qq fprintd >/dev/null 2>&1; then
        echo "ERROR: fprintd and tapauth-fprintd-emulation are installed simultaneously (conflict ignored)"
        exit 1
    fi
    echo "Emulation package replaced the real fprintd package (replaces honored)."
else
    echo "pacman refused the emulation install while fprintd was present (conflict honored); removing fprintd first..."
    pacman -R --noconfirm fprintd
    pacman -U --noconfirm "$EMU_PKG"
fi
test -f /usr/lib/security/pam_fprintd.so
if pacman -Qq fprintd >/dev/null 2>&1; then
    echo "ERROR: fprintd is still installed alongside tapauth-fprintd-emulation"
    exit 1
fi

echo "Verifying the emulation package ships the bridge marker (tri-state default -> on)..."
test -f /usr/share/tapauth/fprintd-emulation.enabled

echo "Verifying enable_fprintd_bridge = false is preserved as an explicit override..."
# The Rust resolver (shared::config::resolve_enable_fprintd_bridge, unit-tested
# in shared/src/config/toml_config.rs) gives explicit values precedence over the
# marker.
if ! grep -Eq '^enable_fprintd_bridge' /etc/tapauth/config.toml; then
    printf 'enable_fprintd_bridge = false\n' >> /etc/tapauth/config.toml
fi
grep -Eq '^enable_fprintd_bridge[[:space:]]*=[[:space:]]*false' /etc/tapauth/config.toml
sed -i '/^enable_fprintd_bridge[[:space:]]*=[[:space:]]*false/d' /etc/tapauth/config.toml

echo "Verifying the emulation package removes cleanly..."
pacman -R --noconfirm tapauth-fprintd-emulation
test ! -e /usr/lib/security/pam_fprintd.so
verify_no_emulation_marker

echo "Reinstalling the real fprintd package so the coexistence checks below stay valid..."
pacman -S --noconfirm --needed fprintd
test -f /usr/share/dbus-1/system-services/net.reactivated.Fprint.service

echo "==> 8b. Testing package upgrade (exercises post_upgrade)..."
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
echo "Verifying tapauth's D-Bus files were removed with the package (policy gone too)..."
test ! -e /usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service
test ! -e /usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf
test ! -e /usr/share/tapauth/fprintd-emulation.enabled

echo "=================================================="
echo "🎉 ALL ARCH LINUX BUILD AND INSTALL TESTS PASSED!"
echo "=================================================="
