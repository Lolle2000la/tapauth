#!/bin/bash
# Runs TapAuth E2E tests inside a container (Fedora or Arch) against host Android emulator
set -euo pipefail

DISTRO="${1:-}"
PACKAGE_DIR="${2:-}"

if [[ -z "$DISTRO" || -z "$PACKAGE_DIR" ]]; then
    echo "Usage: $0 <fedora|arch> <package-dir>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=================================================="
echo " Starting TapAuth E2E Test on Distro: $DISTRO"
echo " Package directory: $PACKAGE_DIR"
echo "=================================================="

# Set up a dummy kde-fingerprint to verify it stays STOCK (fingerprint stacks
# are no longer patched; they resolve pam_fprintd.so to the daemon's built-in
# virtual fprintd D-Bus service).
mkdir -p /etc/pam.d
cat << 'EOF' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
auth    sufficient    pam_fprintd.so
EOF

case "$DISTRO" in
    fedora)
        echo "==> Installing Fedora runtime requirements..."
        dnf install -y pamtester python3 python3-cryptography python3-protobuf qrencode dbus dbus-tools procps-ng iproute android-tools systemd bluez bluez-deprecated util-linux

        echo "==> Installing pre-built Fedora RPM packages..."
        dnf install -y "$PACKAGE_DIR"/tapauth-[0-9]*.rpm
        ;;

    arch)
        echo "==> Installing Arch Linux runtime requirements..."
        pacman -Sy --noconfirm python python-cryptography python-protobuf qrencode dbus procps-ng iproute2 gcc pam android-tools bluez bluez-utils util-linux

        echo "==> Building standalone pamtester..."
        gcc -o /usr/bin/pamtester "$WORKSPACE_DIR/scripts/ci/pamtester.c" -lpam -lpam_misc

        echo "==> Installing pre-built Arch Linux packages..."
        pacman -U --noconfirm "$PACKAGE_DIR"/tapauth-[0-9]*.pkg.tar.zst
        ;;

    *)
        echo "Unknown distro: $DISTRO"
        exit 1
        ;;
esac

echo "==> Verifying the fingerprint stack stayed STOCK on $DISTRO (virtual fprintd is built in)..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
test ! -e /etc/pam.d/kde-fingerprint.tapauth-bak

echo "==> Verifying system users, permissions, and directories..."
id tapauthd
getent group tapauthd-clients
mkdir -p /run/tapauthd /etc/tapauth /var/lib/tapauth
chown -R tapauthd:tapauthd /etc/tapauth /run/tapauthd /var/lib/tapauth 2>/dev/null || true
chmod 0755 /etc/tapauth /run/tapauthd 2>/dev/null || true
chmod 0700 /var/lib/tapauth 2>/dev/null || true

# Verify shipped systemd unit files syntax using distro's systemd
if command -v systemd-analyze >/dev/null 2>&1; then
    echo "==> Verifying shipped systemd unit files syntax via systemd-analyze..."
    systemd-analyze verify /usr/lib/systemd/system/tapauthd.service /usr/lib/systemd/system/tapauthd.socket || true
fi

# ── Optional fprintd-emulation package (enables E2E Phase 2j) ─────────────────
# This installs a second client-pam build as pam_fprintd.so and conflicts with
# the distro fprintd PAM provider. It must happen AFTER the stock-fingerprint
# assertions above (which prove the base package never rewrites vendor stacks).
# The enabled phase exercises the real phone-auth path over the production Unix
# socket, including the socket-permission gate for non-root callers.
EMU_INSTALLED=false
FPRINTD_PROVIDER_RESTORE=""
echo "==> Installing optional tapauth-fprintd-emulation package..."
case "$DISTRO" in
    fedora)
        EMU_RPM=$(find "$PACKAGE_DIR" -maxdepth 1 -name 'tapauth-fprintd-emulation-*.rpm' | head -1 || true)
        if [ -n "$EMU_RPM" ]; then
            if rpm -q fprintd-pam >/dev/null 2>&1; then
                # The two providers of pam_fprintd.so can never coexist; drop the
                # distro one and remember to restore it during cleanup.
                dnf remove -y fprintd-pam
                FPRINTD_PROVIDER_RESTORE="fprintd-pam"
            fi
            dnf install -y "$EMU_RPM"
            test -f /usr/lib64/security/pam_fprintd.so
            test -f /usr/share/tapauth/fprintd-emulation.enabled
            EMU_INSTALLED=true
        else
            echo "⚠️  tapauth-fprintd-emulation RPM not found in $PACKAGE_DIR; Phase 2j will be skipped."
        fi
        ;;
    arch)
        EMU_PKG=$(find "$PACKAGE_DIR" -maxdepth 1 \
            -name 'tapauth-fprintd-emulation-*.pkg.tar.zst' \
            ! -name 'tapauth-fprintd-emulation-git-*' | head -1 || true)
        if [ -n "$EMU_PKG" ]; then
            if pacman -Qq fprintd >/dev/null 2>&1; then
                # The Arch fprintd package is monolithic (daemon + PAM module),
                # so it is replaced wholesale; restore it during cleanup.
                pacman -R --noconfirm fprintd
                FPRINTD_PROVIDER_RESTORE="fprintd"
            fi
            pacman -U --noconfirm "$EMU_PKG"
            test -f /usr/lib/security/pam_fprintd.so
            test -f /usr/share/tapauth/fprintd-emulation.enabled
            EMU_INSTALLED=true
        else
            echo "⚠️  tapauth-fprintd-emulation package not found in $PACKAGE_DIR; Phase 2j will be skipped."
        fi
        ;;
esac
if [ "$EMU_INSTALLED" = true ]; then
    export TAPAUTH_E2E_FPRINTD_EMULATION=1
    echo "    tapauth-fprintd-emulation installed; E2E Phase 2j enabled."
fi

# Check ADB connectivity to host emulator
if command -v adb >/dev/null 2>&1; then
    echo "==> Checking ADB connectivity to host emulator..."
    adb devices
    adb shell pm clear dev.rourunisen.tapauth.e2e || true
fi

echo "==> Running TapAuth E2E suite against installed $DISTRO package..."
cd "$WORKSPACE_DIR"
export TAPAUTH_DEV_MODE=1
export TAPAUTH_E2E_USE_INSTALLED_PACKAGE=1
export TAPAUTH_E2E_DAEMON_MODE=dev
./scripts/test-e2e.sh

# The emulation package depends on tapauth, so remove it (and release its
# conflict with the distro fprintd PAM provider) before removing the base
# package. Restoring the distro provider keeps the environment as we found it.
if [ "$EMU_INSTALLED" = true ]; then
    echo "==> Removing optional tapauth-fprintd-emulation package..."
    case "$DISTRO" in
        fedora) rpm -e tapauth-fprintd-emulation 2>/dev/null || dnf remove -y tapauth-fprintd-emulation || true ;;
        arch)   pacman -R --noconfirm tapauth-fprintd-emulation ;;
    esac
    # Removing the package removes its bridge marker, so the daemon's
    # tri-state default flips back to "off". Only assert once the package is
    # actually gone (the Fedora removal above tolerates a failure).
    _emu_still_installed=false
    case "$DISTRO" in
        fedora) rpm -q tapauth-fprintd-emulation >/dev/null 2>&1 && _emu_still_installed=true || true ;;
        arch)   pacman -Qq tapauth-fprintd-emulation >/dev/null 2>&1 && _emu_still_installed=true || true ;;
    esac
    if [ "$_emu_still_installed" = false ]; then
        test ! -e /usr/share/tapauth/fprintd-emulation.enabled
    fi
    if [ -n "$FPRINTD_PROVIDER_RESTORE" ]; then
        echo "==> Restoring distro fprintd PAM provider '$FPRINTD_PROVIDER_RESTORE'..."
        case "$DISTRO" in
            fedora) dnf install -y "$FPRINTD_PROVIDER_RESTORE" || true ;;
            arch)   pacman -S --noconfirm --needed "$FPRINTD_PROVIDER_RESTORE" || true ;;
        esac
    fi
fi

echo "==> Verifying clean package uninstallation on $DISTRO..."
case "$DISTRO" in
    fedora)
        rpm -e tapauth
        ;;
    arch)
        pacman -R --noconfirm tapauth
        ;;
esac

echo "==> Verifying the fingerprint stack is still untouched after removal on $DISTRO..."
grep "pam_fprintd.so" /etc/pam.d/kde-fingerprint
! grep "pam_tapauth.so" /etc/pam.d/kde-fingerprint
test ! -e /etc/pam.d/kde-fingerprint.tapauth-bak

echo "=================================================="
echo "🎉 ALL E2E TESTS PASSED ON DISTRO: $DISTRO"
echo "=================================================="
