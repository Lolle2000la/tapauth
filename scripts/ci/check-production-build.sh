#!/bin/bash
# Guard: production artifacts must not contain any dev/test environment override.
#
# Every knob the E2E suite relies on is compiled behind a Cargo feature
# (dev-state-override, dev-udp-loopback, dev-polkit-bypass, dev-socket-override,
# fallback-socket) AND requires TAPAUTH_DEV_MODE at runtime. The first layer is
# the one that is easy to lose: Cargo unifies features per package across a
# workspace build, so `cargo build --workspace --features tapauthd/fallback-socket`
# compiles shared/dev-state-override into the GUI and PAM module as well, even
# though neither crate asks for it. `packaging/tapauth.spec` builds
# `cargo build --workspace --release`, so a stray --features there would ship
# environment-controlled state/socket redirection in pam_tapauth.so.
#
# This script builds the shipped artifacts the way the installers do, then fails
# if a dev-only variable name survives into them. It also verifies the check
# itself can fire (positive control), so a broken `strings` cannot make it pass
# vacuously.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

export CARGO_TARGET_DIR="${PROJECT_ROOT}/target"

STRINGS_BIN="${STRINGS_BIN:-strings}"
if ! command -v "$STRINGS_BIN" >/dev/null 2>&1; then
    echo "❌ ERROR: '$STRINGS_BIN' not found. Install binutils (provides strings)."
    exit 1
fi

# Variable names that must never appear in a shipped binary.
# TAPAUTHD_SOCK is deliberately excluded for tapauthd itself: main.rs reads it
# unconditionally at shutdown to unlink the socket it created (pre-existing
# behaviour, only reachable when the socket was not systemd-activated).
DEV_VARS_CLIENT=("TAPAUTHD_SOCK" "TAPAUTH_STATE_DIR" "TAPAUTH_DEV_UDP_TARGET")
DEV_VARS_DAEMON=("TAPAUTH_STATE_DIR" "TAPAUTH_DEV_UDP_TARGET")

echo "==> Building production artifacts (per crate, default features)"
# Mirrors install.sh: each crate is built on its own so no dev feature can be
# pulled in through workspace feature unification.
cargo build --quiet -p tapauthd
cargo build --quiet -p client-pam
cargo build --quiet -p client-config-gui

fail=0

check_artifact() {
    local artifact=$1
    shift
    local vars=("$@")
    if [ ! -f "$artifact" ]; then
        echo "❌ ERROR: expected artifact '$artifact' was not built"
        fail=1
        return
    fi
    local hits=0
    local var
    for var in "${vars[@]}"; do
        local n
        n=$("$STRINGS_BIN" "$artifact" | grep -c "$var" || true)
        if [ "$n" != "0" ]; then
            echo "❌ ERROR: $artifact contains dev override '$var' ($n match(es))"
            hits=1
        fi
    done
    if [ "$hits" = "0" ]; then
        echo "✅ $artifact: no dev environment overrides compiled in"
    else
        fail=1
    fi
}

echo "==> Checking shipped artifacts"
check_artifact "${CARGO_TARGET_DIR}/debug/tapauthd" "${DEV_VARS_DAEMON[@]}"
check_artifact "${CARGO_TARGET_DIR}/debug/libclient_pam.so" "${DEV_VARS_CLIENT[@]}"
check_artifact "${CARGO_TARGET_DIR}/debug/tapauth-config" "${DEV_VARS_CLIENT[@]}"

# Positive control: prove the scan above is capable of detecting a dev build.
# Without this, a missing/garbled strings binary would report "clean" for every
# artifact and the guard would pass vacuously.
# (Note: count matches with `grep -c` rather than `grep -q` — under `pipefail` an
# early-exit `grep -q` closes the pipe and makes `strings` fail with SIGPIPE,
# which turns a successful match into a false negative.)
echo "==> Positive control: rebuilding tapauthd with fallback-socket (dev build)"
cargo build --quiet -p tapauthd --features fallback-socket
control_hits=$("$STRINGS_BIN" "${CARGO_TARGET_DIR}/debug/tapauthd" | grep -c "TAPAUTH_STATE_DIR" || true)
if [ "${control_hits:-0}" != "0" ]; then
    echo "✅ dev build does contain TAPAUTH_STATE_DIR ($control_hits match(es)) — the scan can detect overrides"
else
    echo "❌ ERROR: the dev reference build does NOT contain TAPAUTH_STATE_DIR."
    echo "   The string scan is not working (check \$STRINGS_BIN); the checks above"
    echo "   are meaningless until this positive control passes."
    fail=1
fi

# Restore the production artifact so a later step cannot pick up the dev build.
cargo build --quiet -p tapauthd

if [ "$fail" != "0" ]; then
    echo ""
    echo "❌ Production-build check FAILED."
    echo "   Production builds must not enable dev-state-override / dev-udp-loopback /"
    echo "   dev-polkit-bypass / fallback-socket / dev-socket-override (see AGENTS.md)."
    exit 1
fi

echo ""
echo "🎉 Production-build check passed."
