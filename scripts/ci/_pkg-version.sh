# shellcheck shell=bash
# Shared TapAuth version resolution for build scripts and lifecycle tests.
#
# Sourced (not executed) by scripts/ci/_pkg-common.sh and the distro package
# tests so the logic cannot drift between them.
#
# The version lives in tapauthd/Cargo.toml. The parse is section-scoped: only
# the `[package]` section is considered, so a reordered manifest or a `version`
# key in another section cannot be picked up. If the crate switches to
# `version.workspace = true` there is no `version =` line in `[package]`, so we
# fall back to `[workspace.package]` in the root Cargo.toml.
#
# Usage: resolve_tapauth_version <workspace_dir>
resolve_tapauth_version() {
    local workspace="${1:-.}"
    local ver=""

    ver=$(awk '
        /^\[/ { inpkg = ($0 == "[package]") }
        inpkg && /^[[:space:]]*version[[:space:]]*=/ {
            sub(/[^"]*"/, ""); sub(/".*/, ""); print; exit
        }
    ' "${workspace}/tapauthd/Cargo.toml" 2>/dev/null || true)

    if [ -z "$ver" ]; then
        ver=$(awk '
            /^\[workspace\.package\]/ { inpkg=1; next }
            /^\[/ { inpkg=0 }
            inpkg && /^[[:space:]]*version[[:space:]]*=/ {
                sub(/[^"]*"/, ""); sub(/".*/, ""); print; exit
            }
        ' "${workspace}/Cargo.toml" 2>/dev/null || true)
    fi

    printf '%s' "$ver"
}
