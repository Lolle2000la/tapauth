#!/bin/bash
# Scans built distribution package binaries (.deb, .rpm, .pkg.tar.zst)
# to guarantee no dev/test environment overrides are compiled into shipped artifacts.
set -euo pipefail

PKG_TYPE="${1:-}"
PKG_DIR="${2:-}"

if [[ -z "$PKG_TYPE" || -z "$PKG_DIR" ]]; then
    echo "Usage: $0 <deb|rpm|arch> <package-dir>"
    exit 1
fi

STRINGS_BIN="${STRINGS_BIN:-strings}"
if ! command -v "$STRINGS_BIN" >/dev/null 2>&1; then
    echo "❌ ERROR: '$STRINGS_BIN' command not found."
    exit 1
fi

DEV_VARS=("TAPAUTHD_SOCK" "TAPAUTH_STATE_DIR" "TAPAUTH_DEV_UDP_TARGET" "TAPAUTH_DEV_MODE")

WORK_DIR=$(mktemp -d -t scan-pkg.XXXXXX)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Extracting $PKG_TYPE packages from $PKG_DIR for strings security scan..."

case "$PKG_TYPE" in
    deb)
        for deb in "$PKG_DIR"/tapauth_*.deb "$PKG_DIR"/tapauth-*.deb; do
            [ -f "$deb" ] || continue
            dpkg-deb -x "$deb" "$WORK_DIR" || {
                echo "❌ ERROR: failed to extract $deb (production-build invariant must fail closed)"
                exit 1
            }
        done
        ;;
    rpm)
        for rpm in "$PKG_DIR"/tapauth-[0-9]*.rpm "$PKG_DIR"/tapauth-*.rpm; do
            [ -f "$rpm" ] || continue
            if ! (cd "$WORK_DIR" && rpm2cpio "$rpm" | cpio -idm >/dev/null 2>&1); then
                echo "❌ ERROR: failed to extract $rpm (production-build invariant must fail closed)"
                exit 1
            fi
        done
        ;;
    arch)
        for pkg in "$PKG_DIR"/tapauth-[0-9]*.pkg.tar.zst "$PKG_DIR"/tapauth-*.pkg.tar.zst; do
            [ -f "$pkg" ] || continue
            tar --zstd -xf "$pkg" -C "$WORK_DIR" || {
                echo "❌ ERROR: failed to extract $pkg (production-build invariant must fail closed)"
                exit 1
            }
        done
        ;;
    *)
        echo "Unknown package type: $PKG_TYPE"
        exit 1
        ;;
esac

BINARIES=(
    "usr/bin/tapauthd"
    "usr/bin/tapauth-config"
    "usr/bin/tapauth-ipc-cli"
)

# Find pam_tapauth.so across multiarch or standard security dirs
PAM_SO=$(find "$WORK_DIR" -name "pam_tapauth.so" 2>/dev/null | head -1 || true)
if [ -n "$PAM_SO" ]; then
    BINARIES+=("${PAM_SO#$WORK_DIR/}")
fi

# Fail closed: a production package MUST contain the shipped binaries. A
# package payload with none of them means extraction silently produced an
# empty tree (which used to print success).
found_any=0
for rel_bin in "${BINARIES[@]}"; do
    [ -f "$WORK_DIR/$rel_bin" ] && found_any=1 && break
done
if [ "$found_any" -ne 1 ]; then
    echo "❌ ERROR: no shipped binaries found in $PKG_TYPE package payload from $PKG_DIR — refusing to report success (production-build invariant must fail closed)."
    exit 1
fi

fail=0
for rel_bin in "${BINARIES[@]}"; do
    bin_path="$WORK_DIR/$rel_bin"
    if [ ! -f "$bin_path" ]; then
        echo "⚠️  Note: $rel_bin not found in $PKG_TYPE package payload (might belong to a subpackage)."
        continue
    fi

    echo "==> Scanning shipped binary: $rel_bin"
    for var in "${DEV_VARS[@]}"; do
        hits=$("$STRINGS_BIN" "$bin_path" | grep -c "$var" || true)
        if [ "$hits" != "0" ]; then
            echo "❌ ERROR: Shipped binary $rel_bin contains dev override '$var' ($hits matches)!"
            fail=1
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    echo "❌ SECURITY FAILURE: Production $PKG_TYPE packages contain forbidden dev/test overrides!"
    exit 1
fi

# Positive control: verify the scan itself can detect a planted dev
# override. If this ever fails, the scan is broken (e.g. strings/grep
# unavailable) and "clean" results cannot be trusted.
if [[ "${SCAN_SELF_TEST:-0}" == "1" ]]; then
    plant_dir=$(mktemp -d -t scan-pkg-selftest.XXXXXX)
    mkdir -p "$plant_dir/usr/bin"
    printf 'placeholder with TAPAUTHD_SOCK dev override\n' > "$plant_dir/usr/bin/tapauthd"
    if bash "$0" deb "$plant_dir" >/dev/null 2>&1; then
        echo "❌ ERROR: scan self-test FAILED — a planted dev override was NOT detected; scan is unreliable!"
        rm -rf "$plant_dir"
        exit 1
    fi
    rm -rf "$plant_dir"
    echo "✅ Scan self-test passed: planted dev override was correctly detected."
fi

echo "✅ All shipped $PKG_TYPE binaries are 100% clean of dev/test overrides."
