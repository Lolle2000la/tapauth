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

# Copy PKGBUILD and install files
cp "${WORKSPACE_DIR}/packaging/arch/PKGBUILD" "$BUILD_DIR/"
cp "${WORKSPACE_DIR}/packaging/arch/"*.install "$BUILD_DIR/" 2>/dev/null || true
cp "${WORKSPACE_DIR}/config.toml.example" "$BUILD_DIR/" 2>/dev/null || true

cd "$BUILD_DIR"
sed -i "s/^pkgver=.*/pkgver=${PKG_VER}/" PKGBUILD
# Replace sha256sums with SKIP for local source tarball
sed -i "s/^sha256sums=.*/sha256sums=('SKIP')/" PKGBUILD

# Ensure builder user exists
if ! id builder >/dev/null 2>&1; then
    useradd -m builder
fi
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    mkdir -p "$CARGO_TARGET_DIR"
    chown -R builder:builder "$CARGO_TARGET_DIR"
fi
chown -R builder:builder "$BUILD_DIR" "$OUTPUT_DIR"

echo "==> Building Arch packages with makepkg..."
su builder -c "CARGO_FEATURES='${CARGO_FEATURES}' CARGO_TARGET_DIR='${CARGO_TARGET_DIR:-}' makepkg -s --noconfirm --nodeps"

echo "==> Copying built Arch packages to $OUTPUT_DIR..."
cp "$BUILD_DIR"/*.pkg.tar.zst "$OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.pkg.tar.zst
