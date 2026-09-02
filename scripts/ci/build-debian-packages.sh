#!/bin/bash
# Builds TapAuth Debian packages (.deb) into /tmp/deb-build/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)
CARGO_FEATURES="${CARGO_FEATURES:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --features)
            CARGO_FEATURES="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

export CARGO_FEATURES

BUILD_DIR="/tmp/deb-build/tapauth-${PKG_VER}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Packaging TapAuth version ${PKG_VER}..."
tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "$BUILD_DIR" -xf -
cd "$BUILD_DIR"

# Reuse cached workspace target directory if present
if [ -d "${WORKSPACE_DIR}/target" ]; then
    echo "==> Reusing cached workspace target directory in Debian build..."
    cp -al "${WORKSPACE_DIR}/target" "$BUILD_DIR/target" 2>/dev/null || cp -r "${WORKSPACE_DIR}/target" "$BUILD_DIR/target" || true
fi

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

# Sync back compiled target artifacts to workspace target for caching
if [ -d "$BUILD_DIR/target" ]; then
    mkdir -p "${WORKSPACE_DIR}/target"
    cp -al "$BUILD_DIR/target"/* "${WORKSPACE_DIR}/target/" 2>/dev/null || cp -r "$BUILD_DIR/target"/* "${WORKSPACE_DIR}/target/" || true
fi

echo "==> Built Debian packages in /tmp/deb-build/:"
ls -la /tmp/deb-build/*.deb
