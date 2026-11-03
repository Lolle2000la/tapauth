#!/bin/bash
# Builds TapAuth Debian packages (.deb) into the output directory (default
# /tmp/deb-build). The build happens inside $OUTPUT_DIR so a test build with a
# different --output-dir can never overwrite the production packages.
set -euo pipefail

# Shared workspace detection, argument parsing and dev-feature guard
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_pkg-common.sh"

pkg_common_parse_args "$@"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/deb-build}"
enforce_prod_feature_guard "Debian"

export CARGO_FEATURES
# Signal the in-tree rules guard that this is an explicit test build. Only the
# literal "1" disables it (mirroring the RPM spec's allow_test_features opt-in);
# a plain production invocation leaves it unset and the guard stays armed.
if [ "$ALLOW_TEST_FEATURES" = true ]; then
    export ALLOW_TEST_FEATURES=1
else
    unset ALLOW_TEST_FEATURES
fi

mkdir -p "$OUTPUT_DIR"
BUILD_DIR="${OUTPUT_DIR}/tapauth-${PKG_VER}"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Packaging TapAuth version ${PKG_VER}..."
tar -C "${WORKSPACE_DIR}" --exclude=./target --exclude=./.git --exclude=./server-android/app/build --exclude=./server-android/.gradle -cf - . | tar -C "$BUILD_DIR" -xf -
cd "$BUILD_DIR"

# Symlink workspace target directory so cargo writes directly into the cached
# location. NOTE: the workspace target/ is shared with the production build in
# the same job, so a test build (different CARGO_FEATURES) reuses and rebuilds
# those artifacts with the test feature set — the cached target dir and the
# already-produced production .deb therefore diverge. The .deb itself is not
# overwritten (OUTPUT_DIR differs), which is what matters.
mkdir -p "${WORKSPACE_DIR}/target"
ln -sfn "${WORKSPACE_DIR}/target" "$BUILD_DIR/target"

# Copy debian packaging files
rm -rf debian
cp -r "${WORKSPACE_DIR}/packaging/debian" debian

# Create changelog. The distribution is informational for a `-b` build, but use
# the host codename so a jammy/bookworm build is not mislabelled as noble
# (debian/rules branches on it for the jammy-only pkla). Overridable via
# DEB_CODENAME.
DEB_CODENAME="${DEB_CODENAME:-}"
if [ -z "$DEB_CODENAME" ] && [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    DEB_CODENAME="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
fi
DEB_CODENAME="${DEB_CODENAME:-noble}"
cat > debian/changelog <<EOF
tapauth (${PKG_VER}-1) ${DEB_CODENAME}; urgency=medium

  * Package build.

 -- Luca Auer <lolle2000.la+tapauth@gmail.com>  $(date -R)
EOF

echo "==> Building Debian packages with dpkg-buildpackage..."
DEB_BUILD_OPTIONS="${DEB_BUILD_OPTIONS:-nocheck}" dpkg-buildpackage -us -uc -b -d

echo "==> Built Debian packages in ${OUTPUT_DIR}:"
ls -la "$OUTPUT_DIR"/*.deb
