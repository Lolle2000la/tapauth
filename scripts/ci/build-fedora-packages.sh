#!/bin/bash
# Builds TapAuth Fedora RPM packages (.rpm) into /tmp/rpm-build/
set -euo pipefail

# Shared workspace detection, argument parsing and dev-feature guard
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pkg-common.sh"

NO_CHECK=false
pkg_extra_option() {
    case "$1" in
        --nocheck) NO_CHECK=true ;;
        *) return 1 ;;
    esac
}

pkg_common_parse_args "$@"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/rpm-build}"
enforce_prod_feature_guard "Fedora"

if ! command -v rpmbuild >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
    echo "==> Installing build dependencies for Fedora..."
    dnf install -y --setopt=keepcache=1 rpm-build cargo rust protobuf-compiler clang pam-devel systemd-devel dbus-devel sccache
fi

echo "==> Preparing RPM build directory structure..."
RPM_ROOT="/root/rpmbuild"
mkdir -p "$RPM_ROOT"/{SOURCES,SPECS,BUILD,RPMS,SRPMS} "$OUTPUT_DIR"

# Copy spec file and hardcode the version. The spec keeps a conditional
# pkgversion macro for the release workflow, so replace the whole macro
# expression (not just a literal Version: line).
cp "${WORKSPACE_DIR}/packaging/tapauth.spec" "$RPM_ROOT/SPECS/"
sed -i "s/%{?pkgversion}%{!?pkgversion:0.1.0}/${PKG_VER}/g" "$RPM_ROOT/SPECS/tapauth.spec"

# Create source tarball
echo "==> Creating source tarball for TapAuth ${PKG_VER}..."
tar -czf "$RPM_ROOT/SOURCES/tapauth-${PKG_VER}.tar.gz" \
    --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle \
    --transform "s,^./,tapauth-${PKG_VER}/," \
    -C "${WORKSPACE_DIR}" .

# NOTE: sysusers.conf/tmpfiles.conf are read by the spec from the unpacked
# source tree (%install), not from SOURCES — no copies are needed here.

# Define cargo_features macro if features were passed
RPMBUILD_ARGS=("-ba" "$RPM_ROOT/SPECS/tapauth.spec")
if [ "$NO_CHECK" = true ]; then
    RPMBUILD_ARGS+=("--nocheck")
fi
if [ -n "$CARGO_FEATURES" ]; then
    RPMBUILD_ARGS+=("--define" "cargo_features --features ${CARGO_FEATURES}")
fi
if [ "$ALLOW_TEST_FEATURES" = true ]; then
    # Let the spec's dev-feature guard accept the test-only feature set. Without
    # this the spec refuses dev-*/fallback-socket outright, which is exactly the
    # invariant we want for anything that is not an explicit test build.
    RPMBUILD_ARGS+=("--define" "allow_test_features 1")
fi

if [ -d /root/.cargo ]; then
    RPMBUILD_ARGS+=("--define" "_cargo_home /root/.cargo")
fi
if [ -d /root/.cache/sccache ]; then
    RPMBUILD_ARGS+=("--define" "_sccache_dir /root/.cache/sccache")
fi
if [ -d /root/.cache/cargo-target ]; then
    RPMBUILD_ARGS+=("--define" "_cargo_target_dir /root/.cache/cargo-target")
fi

echo "==> Running rpmbuild..."
rpmbuild "${RPMBUILD_ARGS[@]}"

echo "==> Copying built RPMs to $OUTPUT_DIR..."
cp "$RPM_ROOT"/RPMS/*/*.rpm "$OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.rpm
