#!/bin/bash
# Builds TapAuth Arch Linux packages (.pkg.tar.zst) into /tmp/arch-build/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)
CARGO_FEATURES="${CARGO_FEATURES:-}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/arch-build}"

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
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if ! command -v cargo >/dev/null 2>&1; then
    echo "==> Installing build dependencies (cargo, protobuf, clang, pam)..."
    pacman -Sy --noconfirm cargo protobuf clang pam
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
    mkdir -p /cache/cargo
    chown -R builder:builder /cache
    sed -i 's|export CARGO_HOME=.*|export CARGO_HOME="/cache/cargo"|' PKGBUILD
fi
chown -R builder:builder "$BUILD_DIR" "$OUTPUT_DIR"

echo "==> Building Arch packages with makepkg..."
su builder -c "makepkg -s --noconfirm --nodeps"

echo "==> Copying built Arch packages to $OUTPUT_DIR..."
cp "$BUILD_DIR"/*.pkg.tar.zst "$OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.pkg.tar.zst
