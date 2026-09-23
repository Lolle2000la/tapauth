#!/bin/bash
# Scans built distribution package binaries (.deb, .rpm, .pkg.tar.zst) to
# guarantee no dev/test environment overrides are compiled into shipped
# artifacts. Also accepts an already-extracted payload ("dir") for the
# positive control below.
set -euo pipefail

PKG_TYPE="${1:-}"
PKG_DIR="${2:-}"

if [[ -z "$PKG_TYPE" || -z "$PKG_DIR" ]]; then
    echo "Usage: $0 <deb|rpm|arch|dir> <package-dir>"
    exit 1
fi

STRINGS_BIN="${STRINGS_BIN:-strings}"
if ! command -v "$STRINGS_BIN" >/dev/null 2>&1; then
    echo "❌ ERROR: '$STRINGS_BIN' command not found."
    exit 1
fi

DEV_VARS=("TAPAUTHD_SOCK" "TAPAUTH_STATE_DIR" "TAPAUTH_DEV_UDP_TARGET" "TAPAUTH_DEV_MODE" "dev-firewall-bypass")

# Only ever delete an extraction dir we created ourselves; never the caller's
# input directory (the "dir" mode scans it in place).
WORK_DIR=""
CLEAN_WORK=0
cleanup_work() {
    if [ "$CLEAN_WORK" = 1 ] && [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup_work EXIT

case "$PKG_TYPE" in
    deb)
        WORK_DIR=$(mktemp -d -t scan-pkg.XXXXXX)
        CLEAN_WORK=1
        echo "==> Extracting $PKG_TYPE packages from $PKG_DIR for strings security scan..."
        for deb in "$PKG_DIR"/tapauth_*.deb "$PKG_DIR"/tapauth-*.deb; do
            [ -f "$deb" ] || continue
            dpkg-deb -x "$deb" "$WORK_DIR" || {
                echo "❌ ERROR: failed to extract $deb (production-build invariant must fail closed)"
                exit 1
            }
        done
        ;;
    rpm)
        WORK_DIR=$(mktemp -d -t scan-pkg.XXXXXX)
        CLEAN_WORK=1
        echo "==> Extracting $PKG_TYPE packages from $PKG_DIR for strings security scan..."
        # A single glob: `tapauth-*.rpm` already covers the versioned main
        # package, so the former `tapauth-[0-9]*.rpm` companion only caused the
        # main package to be extracted twice.
        for rpm in "$PKG_DIR"/tapauth-*.rpm; do
            [ -f "$rpm" ] || continue
            if ! (cd "$WORK_DIR" && rpm2cpio "$rpm" | cpio -idm >/dev/null 2>&1); then
                echo "❌ ERROR: failed to extract $rpm (production-build invariant must fail closed)"
                exit 1
            fi
        done
        ;;
    arch)
        WORK_DIR=$(mktemp -d -t scan-pkg.XXXXXX)
        CLEAN_WORK=1
        echo "==> Extracting $PKG_TYPE packages from $PKG_DIR for strings security scan..."
        # Single glob; see the rpm branch comment (`tapauth-[0-9]*.pkg.tar.zst`
        # was a redundant subset).
        for pkg in "$PKG_DIR"/tapauth-*.pkg.tar.zst; do
            [ -f "$pkg" ] || continue
            tar --zstd -xf "$pkg" -C "$WORK_DIR" || {
                echo "❌ ERROR: failed to extract $pkg (production-build invariant must fail closed)"
                exit 1
            }
        done
        ;;
    dir)
        # Already-extracted payload (used by the self-test positive control so
        # it does not depend on dpkg/rpm/tar being present).
        WORK_DIR="$PKG_DIR"
        echo "==> Scanning already-extracted payload in $PKG_DIR..."
        ;;
    *)
        echo "Unknown package type: $PKG_TYPE"
        exit 1
        ;;
esac

# Shipped binaries only: tapauth-ipc-cli is a testing-only admin tool and is
# deliberately not shipped by any distro package, so it is not scanned here.
BINARIES=(
    "usr/bin/tapauthd"
    "usr/bin/tapauth-config"
)

# Find pam_tapauth.so across multiarch or standard security dirs
PAM_SO=$(find "$WORK_DIR" -name "pam_tapauth.so" 2>/dev/null | head -1 || true)
if [ -n "$PAM_SO" ]; then
    BINARIES+=("${PAM_SO#"$WORK_DIR"/}")
fi

# The PAM module is the security-critical shipped artifact; require it in every
# mode (including an extracted `dir` payload) so a rename/relocation cannot make
# its scan silently vacuous. The self-test below plants a stub module so it
# still exercises the rest of the scanner.
if [ -z "$PAM_SO" ]; then
    echo "❌ ERROR: pam_tapauth.so not found in the $PKG_TYPE payload from $PKG_DIR — refusing to report success (production-build invariant must fail closed)."
    exit 1
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

# tapauthd is the only carrier of the daemon-only dev-firewall-bypass signature
# (its warning literal). If a packaging change moved or renamed the daemon
# binary, the generic "might belong to a subpackage" skip below would let the
# scan report clean without ever checking that tag. The daemon binary is always
# in the main package, so require it explicitly.
if [ ! -f "$WORK_DIR/usr/bin/tapauthd" ]; then
    echo "❌ ERROR: usr/bin/tapauthd is missing from the $PKG_TYPE package payload from $PKG_DIR — the daemon-only dev-override scan would be vacuous (production-build invariant must fail closed)."
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

# Positive control: prove the scan can actually detect a planted dev override
# AND still accepts a clean payload. If this ever fails, the scan is broken
# (e.g. strings/grep unavailable or accidentally failing closed on everything)
# and "clean" results cannot be trusted. The child runs in "dir" mode with
# SCAN_SELF_TEST disabled, so it neither needs a package manager nor recurses.
if [[ "${SCAN_SELF_TEST:-0}" == "1" ]]; then
    # Every forbidden tag must be individually detectable: plant one marker per
    # variable so a renamed/removed literal (e.g. the dev-firewall-bypass tag,
    # which is this feature's only detectable signature) cannot silently make
    # the guard vacuous. The child runs in "dir" mode with SCAN_SELF_TEST
    # disabled, so it neither needs a package manager nor recurses.
    for var in "${DEV_VARS[@]}"; do
        plant_dir=$(mktemp -d -t scan-pkg-selftest.XXXXXX)
        mkdir -p "$plant_dir/usr/bin" "$plant_dir/usr/lib/security"
        printf 'placeholder for %s dev override\n' "$var" > "$plant_dir/usr/bin/tapauthd"
        printf 'clean pam stub\n' > "$plant_dir/usr/lib/security/pam_tapauth.so"
        if SCAN_SELF_TEST=0 bash "$0" dir "$plant_dir" >/dev/null 2>&1; then
            echo "❌ ERROR: scan self-test FAILED — planted '$var' was NOT detected; scan is unreliable!"
            rm -rf "$plant_dir"
            exit 1
        fi
        rm -rf "$plant_dir"
    done

    clean_dir=$(mktemp -d -t scan-pkg-selftest.XXXXXX)
    mkdir -p "$clean_dir/usr/bin" "$clean_dir/usr/lib/security"
    printf 'clean placeholder binary with no dev overrides\n' > "$clean_dir/usr/bin/tapauthd"
    printf 'clean pam stub\n' > "$clean_dir/usr/lib/security/pam_tapauth.so"
    if ! SCAN_SELF_TEST=0 bash "$0" dir "$clean_dir" >/dev/null 2>&1; then
        echo "❌ ERROR: scan self-test FAILED — a clean payload was incorrectly rejected!"
        rm -rf "$clean_dir"
        exit 1
    fi
    rm -rf "$clean_dir"

    # The module requirement must fire: a payload with the daemon but no
    # pam_tapauth.so has to be rejected rather than scanned as "clean".
    no_pam_dir=$(mktemp -d -t scan-pkg-selftest.XXXXXX)
    mkdir -p "$no_pam_dir/usr/bin"
    printf 'clean daemon without a pam module\n' > "$no_pam_dir/usr/bin/tapauthd"
    if SCAN_SELF_TEST=0 bash "$0" dir "$no_pam_dir" >/dev/null 2>&1; then
        echo "❌ ERROR: scan self-test FAILED — a payload missing pam_tapauth.so was accepted!"
        rm -rf "$no_pam_dir"
        exit 1
    fi
    rm -rf "$no_pam_dir"

    echo "✅ Scan self-test passed: every forbidden tag (${DEV_VARS[*]}) was detected, clean payload accepted, missing pam_tapauth.so rejected."
fi

echo "✅ All shipped $PKG_TYPE binaries are 100% clean of dev/test overrides."
