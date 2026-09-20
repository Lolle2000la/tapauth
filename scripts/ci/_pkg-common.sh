# shellcheck shell=bash disable=SC2034
# Shared scaffolding for scripts/ci/build-{arch,debian,fedora}-packages.sh:
# workspace detection, argument parsing, and the production dev-feature guard.
# Sourcing this file must be the first statement after the shebang/copyright
# comment; everything the caller needs (WORKSPACE_DIR, PKG_VER, CARGO_FEATURES,
# OUTPUT_DIR, ALLOW_TEST_FEATURES) is set up here.
#
# Contract with the caller:
# - may define pkg_extra_option() for distro-specific flags (receives the
#   unknown option token; returns 0 when it consumed that single token — it
#   cannot consume a following value, so only valueless extra options are
#   supported here);
# - must call pkg_common_parse_args "$@" after sourcing;
# - must apply its own OUTPUT_DIR default afterwards (the default path differs
#   per distro), e.g. OUTPUT_DIR="${OUTPUT_DIR:-/tmp/arch-build}";
# - must call enforce_prod_feature_guard <distro> after the args are parsed.
#
# No set -e here: callers already run under set -euo pipefail.

_PKG_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$_PKG_COMMON_DIR/../.." && pwd)"

# Version comes from the crate manifest; fall back to a `[workspace.package]`
# version for the `version.workspace = true` layout.
PKG_VER=$(grep -m1 '^version' "${WORKSPACE_DIR}/tapauthd/Cargo.toml" 2>/dev/null | cut -d '"' -f2 || true)
if [ -z "$PKG_VER" ]; then
    PKG_VER=$(awk '
        /^\[workspace\.package\]/ { inpkg=1; next }
        /^\[/ { inpkg=0 }
        inpkg && /^[[:space:]]*version[[:space:]]*=/ {
            sub(/[^"]*"/, ""); sub(/".*/, ""); print; exit
        }
    ' "${WORKSPACE_DIR}/Cargo.toml" 2>/dev/null || true)
fi
if [ -z "$PKG_VER" ]; then
    echo "❌ ERROR: could not determine the TapAuth version from tapauthd/Cargo.toml or [workspace.package] in Cargo.toml"
    exit 1
fi

CARGO_FEATURES="${CARGO_FEATURES:-}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
ALLOW_TEST_FEATURES=false

pkg_common_parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --features)
                if [ $# -lt 2 ]; then
                    echo "❌ ERROR: --features requires a value"
                    exit 1
                fi
                CARGO_FEATURES="$2"
                shift 2
                ;;
            --output-dir)
                if [ $# -lt 2 ]; then
                    echo "❌ ERROR: --output-dir requires a value"
                    exit 1
                fi
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --allow-test-features)
                ALLOW_TEST_FEATURES=true
                shift
                ;;
            *)
                if declare -F pkg_extra_option >/dev/null && pkg_extra_option "$1"; then
                    shift
                else
                    echo "Unknown option: $1"
                    exit 1
                fi
                ;;
        esac
    done
}

# Guard: reject dev/test features in production package builds unless
# explicitly allowed. $1 = distro name for the error message.
enforce_prod_feature_guard() {
    local distro="$1"
    local pattern
    local dev_feature_patterns=("dev-" "fallback-socket")
    if [ "$ALLOW_TEST_FEATURES" = false ] && [ -n "$CARGO_FEATURES" ]; then
        for pattern in "${dev_feature_patterns[@]}"; do
            if echo "$CARGO_FEATURES" | grep -q "$pattern"; then
                echo "❌ ERROR: Cannot build production $distro package with test feature: '$CARGO_FEATURES'"
                echo "   Production packages must never contain dev overrides."
                echo "   Pass --allow-test-features if this is an explicit test build."
                exit 1
            fi
        done
    fi
}
