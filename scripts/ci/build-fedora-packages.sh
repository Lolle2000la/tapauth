#!/bin/bash
# Builds TapAuth Fedora RPM packages (.rpm) into /tmp/rpm-build/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)
CARGO_FEATURES="${CARGO_FEATURES:-}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/rpm-build}"
NO_CHECK=false
ALLOW_TEST_FEATURES=false

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
        --allow-test-features)
            ALLOW_TEST_FEATURES=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Guard: reject dev/test features in production package builds unless explicitly allowed
DEV_FEATURE_PATTERNS=("dev-" "fallback-socket")
if [ "$ALLOW_TEST_FEATURES" = false ] && [ -n "$CARGO_FEATURES" ]; then
    for pattern in "${DEV_FEATURE_PATTERNS[@]}"; do
        if echo "$CARGO_FEATURES" | grep -q "$pattern"; then
            echo "❌ ERROR: Cannot build production Fedora package with test feature: '$CARGO_FEATURES'"
            echo "   Production packages must never contain dev overrides."
            echo "   Pass --allow-test-features if this is an explicit test build."
            exit 1
        fi
    done
fi

if ! command -v rpmbuild >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
    echo "==> Installing build dependencies for Fedora..."
    dnf install -y --setopt=keepcache=1 rpm-build cargo rust protobuf-compiler clang pam-devel systemd-devel dbus-devel sccache
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
cp "${WORKSPACE_DIR}/packaging/sysusers.conf" "$RPM_ROOT/SOURCES/tapauth-sysusers.conf"
cp "${WORKSPACE_DIR}/packaging/tmpfiles.conf" "$RPM_ROOT/SOURCES/tapauth-tmpfiles.conf"

# Define cargo_features macro if features were passed
RPMBUILD_ARGS=("-ba" "$RPM_ROOT/SPECS/tapauth.spec")
if [ "$NO_CHECK" = true ]; then
    RPMBUILD_ARGS+=("--nocheck")
fi
if [ -n "$CARGO_FEATURES" ]; then
    RPMBUILD_ARGS+=("--define" "cargo_features --features ${CARGO_FEATURES}")
fi

if [ -d /root/.cargo ]; then
    RPMBUILD_ARGS+=("--define" "_cargo_home /root/.cargo")
fi
if [ -d /root/.cache/sccache ]; then
    RPMBUILD_ARGS+=("--define" "_sccache_dir /root/.cache/sccache")
fi

echo "==> Running rpmbuild..."
rpmbuild "${RPMBUILD_ARGS[@]}"

echo "==> Copying built RPMs to $OUTPUT_DIR..."
cp "$RPM_ROOT"/RPMS/*/*.rpm "$OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.rpm
