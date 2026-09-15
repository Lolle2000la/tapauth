#!/bin/bash
# Builds TapAuth Arch Linux packages (.pkg.tar.zst) into /tmp/arch-build/
set -euo pipefail

# Shared workspace detection, argument parsing and dev-feature guard
PKG_COMMON_DISTRO="Arch"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pkg-common.sh"

pkg_common_parse_args "$@"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/arch-build}"
enforce_prod_feature_guard "Arch"

if ! command -v cargo >/dev/null 2>&1; then
    echo "==> Installing build dependencies (cargo, protobuf, clang, pam, sccache)..."
    pacman -Sy --noconfirm --needed cargo protobuf clang pam sccache
fi

BUILD_DIR="/tmp/arch-build-src"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# Create source tarball
echo "==> Creating source tarball for TapAuth ${PKG_VER}..."
tar -czf "$BUILD_DIR/tapauth-${PKG_VER}.tar.gz" \
    --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle \
    --transform "s,^./,tapauth-${PKG_VER}/," \
    -C "${WORKSPACE_DIR}" .

# Copy PKGBUILD, install files, and hooks
cp "${WORKSPACE_DIR}/packaging/arch/PKGBUILD" "$BUILD_DIR/"
cp "${WORKSPACE_DIR}/packaging/arch/"*.install "$BUILD_DIR/" 2>/dev/null || true
cp "${WORKSPACE_DIR}/packaging/arch/"*.hook "$BUILD_DIR/" 2>/dev/null || true
cp "${WORKSPACE_DIR}/config.toml.example" "$BUILD_DIR/" 2>/dev/null || true

cd "$BUILD_DIR"
sed -i "s/^pkgver=.*/pkgver=${PKG_VER}/" PKGBUILD
sed -i "s|^source=.*|source=(\"tapauth-\${pkgver}.tar.gz\")|" PKGBUILD
# Replace sha256sums with SKIP for local source tarball
sed -i "s/^sha256sums=.*/sha256sums=('SKIP')/" PKGBUILD

if [ -n "$CARGO_FEATURES" ]; then
    sed -i "s|cargo build --frozen --workspace --release --locked|cargo build --frozen --workspace --release --locked --features \"$CARGO_FEATURES\"|" PKGBUILD
fi

# Ensure builder user exists
if ! id builder >/dev/null 2>&1; then
    useradd -m builder
fi
if [ -d /cache ]; then
    mkdir -p /cache/cargo /cache/sccache /cache/target
    chown -R builder:builder /cache
    sed -i 's|export CARGO_HOME=.*|export CARGO_HOME="/cache/cargo"|' PKGBUILD
    sed -i '/export CARGO_PROFILE_RELEASE_STRIP=/a \  export RUSTC_WRAPPER=sccache\n  export SCCACHE_DIR="/cache/sccache"\n  export CARGO_TARGET_DIR="/cache/target"' PKGBUILD
    sed -i 's|target/release/|/cache/target/release/|g' PKGBUILD
fi
chown -R builder:builder "$BUILD_DIR" "$OUTPUT_DIR"

echo "==> Building Arch packages with makepkg..."
su builder -c "makepkg -s --noconfirm --nodeps"

echo "==> Copying built Arch packages to $OUTPUT_DIR..."
cp "$BUILD_DIR"/*.pkg.tar.zst "$OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.pkg.tar.zst

# Visibility for CI: report sccache hit rate (server may still be running)
if [ -d /cache/sccache ] && command -v sccache >/dev/null 2>&1; then
    echo "==> sccache statistics:"
    su builder -c "SCCACHE_DIR=/cache/sccache sccache --show-stats" 2>/dev/null | sed -n '1,10p' || true
fi
