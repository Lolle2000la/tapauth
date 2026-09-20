#!/bin/bash
# Builds TapAuth Debian packages (.deb) into /tmp/deb-build/
set -euo pipefail

# Shared workspace detection, argument parsing and dev-feature guard
PKG_COMMON_DISTRO="Debian"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pkg-common.sh"

pkg_common_parse_args "$@"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/deb-build}"
enforce_prod_feature_guard "Debian"

export CARGO_FEATURES

BUILD_DIR="/tmp/deb-build/tapauth-${PKG_VER}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Packaging TapAuth version ${PKG_VER}..."
tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "$BUILD_DIR" -xf -
cd "$BUILD_DIR"

# Symlink workspace target directory so cargo writes directly into the cached location
mkdir -p "${WORKSPACE_DIR}/target"
ln -sfn "${WORKSPACE_DIR}/target" "$BUILD_DIR/target"

# Copy debian packaging files
rm -rf debian
cp -r "${WORKSPACE_DIR}/packaging/debian" debian

# Create changelog
cat > debian/changelog <<EOF
tapauth (${PKG_VER}-1) noble; urgency=medium

  * Package build.

 -- Luca Auer <lolle2000.la+tapauth@gmail.com>  $(date -R)
EOF

echo "==> Building Debian packages with dpkg-buildpackage..."
DEB_BUILD_OPTIONS="${DEB_BUILD_OPTIONS:-nocheck}" dpkg-buildpackage -us -uc -b -d

echo "==> Built Debian packages in /tmp/deb-build/:"
ls -la /tmp/deb-build/*.deb

if [ "$OUTPUT_DIR" != "/tmp/deb-build" ]; then
    mkdir -p "$OUTPUT_DIR"
    cp /tmp/deb-build/*.deb "$OUTPUT_DIR/"
    echo "==> Copied packages to $OUTPUT_DIR:"
    ls -la "$OUTPUT_DIR"/*.deb
fi
