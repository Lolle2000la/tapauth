#!/bin/bash
# Builds TapAuth Fedora RPM packages (.rpm) into /tmp/rpm-build/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)
CARGO_FEATURES="${CARGO_FEATURES:-}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/rpm-build}"
NO_CHECK=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --features)
            CARGO_FEATURES="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --nocheck)
            NO_CHECK=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    mkdir -p "$CARGO_TARGET_DIR"
    export CARGO_TARGET_DIR
fi

if ! command -v rpmbuild >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
    echo "==> Installing build dependencies for Fedora..."
    dnf install -y rpm-build cargo rust protobuf-compiler clang pam-devel systemd-devel dbus-devel
fi

echo "==> Preparing RPM build directory structure..."
RPM_ROOT="/root/rpmbuild"
mkdir -p "$RPM_ROOT"/{SOURCES,SPECS,BUILD,RPMS,SRPMS} "$OUTPUT_DIR"

# Copy spec file and update version
cp "${WORKSPACE_DIR}/packaging/tapauth.spec" "$RPM_ROOT/SPECS/"
sed -i "s/^Version:.*/Version:        ${PKG_VER}/" "$RPM_ROOT/SPECS/tapauth.spec"

# Create source tarball
echo "==> Creating source tarball for TapAuth ${PKG_VER}..."
tar -czf "$RPM_ROOT/SOURCES/tapauth-${PKG_VER}.tar.gz" \
    --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle \
    --transform "s,^./,tapauth-${PKG_VER}/," \
    -C "${WORKSPACE_DIR}" .

# Define cargo_features macro if features were passed
RPMBUILD_ARGS=("-ba" "$RPM_ROOT/SPECS/tapauth.spec")
if [ "$NO_CHECK" = true ]; then
    RPMBUILD_ARGS+=("--nocheck")
fi
if [ -n "$CARGO_FEATURES" ]; then
    RPMBUILD_ARGS+=("--define" "cargo_features --features ${CARGO_FEATURES}")
fi

echo "==> Running rpmbuild..."
rpmbuild "${RPMBUILD_ARGS[@]}"

echo "==> Copying built RPMs to $OUTPUT_DIR..."
cp "$RPM_ROOT"/RPMS/*/*.rpm "$OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.rpm
