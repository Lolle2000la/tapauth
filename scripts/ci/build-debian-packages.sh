#!/bin/bash
# Builds TapAuth Debian packages (.deb) into /tmp/deb-build/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" | cut -d '"' -f2)
CARGO_FEATURES="${CARGO_FEATURES:-}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/deb-build}"
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
            echo "❌ ERROR: Cannot build production Debian package with test feature: '$CARGO_FEATURES'"
            echo "   Production packages must never contain dev overrides."
            echo "   Pass --allow-test-features if this is an explicit test build."
            exit 1
        fi
    done
fi

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
