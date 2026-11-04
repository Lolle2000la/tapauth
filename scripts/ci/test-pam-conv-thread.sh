#!/bin/bash
# E2E: the threaded PAM conversation path of the PAM module, across the stack
# shapes the module is installed on.
#
# `client-pam` chooses at runtime between driving the host's PAM conversation
# from a worker thread (safe for hosts whose conversation stays answerable while
# the calling thread is blocked) and leaving the conversation alone.  The choice
# is an allowlist keyed on the calling process (`conversation_mode` in
# client-pam/src/pam_logic.rs), so neither branch is reachable from a Rust unit
# test: it needs a real libpam stack, a dynamically loaded `pam_tapauth.so`, and
# a process whose `/proc/self/exe` basename is on the allowlist.
#
# The thread strategy and the return-code policy have to hold *together*, so the
# conversation half is exercised against three real stacks:
#
#   sufficient   auth sufficient <module>
#                auth required <token-check> expected=<pw> marker=<tmp>/token-seen
#                account required pam_permit.so
#                The worker collects the password, so the module returns
#                PAM_AUTHINFO_UNAVAIL; on a `sufficient` line (which expands to
#                [success=done new_authtok_reqd=done default=ignore]) that is
#                `ignore`, the token-check runs, reads the token that
#                `pam_get_authtok` cached in the handle and succeeds, so the
#                whole stack grants.  This is password fallback.
#
#   required     auth required <module>
#                auth required <token-check> expected=<pw> marker=<tmp>/token-seen
#                On a `required` line every code except PAM_IGNORE is
#                `_PAM_ACTION_BAD`, so the same PAM_AUTHINFO_UNAVAIL fails the
#                stack even though the token-check would have accepted the
#                password.  Fail-closed by design: TapAuth is only supported on
#                `sufficient` lines (client-pam/pam_install.sh).
#
#   bypass       auth required <module>
#                auth optional pam_permit.so
#                The shape that made PAM_IGNORE an authentication bypass: with
#                PAM_IGNORE the required line would record no failure and the
#                optional pam_permit success vote would grant the stack.  The
#                module must not grant here.
#
# This script therefore:
#   1. builds `libclient_pam.so` release with `dev-socket-override` so the
#      module talks to a socket under our control instead of /run/tapauthd;
#   2. compiles scripts/ci/conv_thread_harness.c (the driver) and
#      scripts/ci/conv_thread_token_check.c (the token-check module) into $TMP;
#   3. for each shape, writes a private confdir service file that loads the
#      module and the token check by absolute path, copies the harness (not a
#      symlink — the kernel resolves /proc/self/exe) to `kscreenlocker_worker`,
#      the allowlisted name, runs it, and asserts `RESULT: PASS`, the stack
#      verdict, the conversation having run on a worker thread, and — where the
#      stack has one — that the token check saw the cached password;
#   4. runs the same binary under a name that is NOT allowlisted and asserts it
#      does not pass, so step 3 cannot succeed vacuously.
#
# The threaded runs must finish in well under `pam_gui_timeout_secs` (default
# 30 s).  A regression to the sequential path would either be killed by
# `timeout` or fail on `conv_entered`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

export CARGO_TARGET_DIR="${PROJECT_ROOT}/target"

HARNESS_SRC="$SCRIPT_DIR/conv_thread_harness.c"
TOKEN_CHECK_SRC="$SCRIPT_DIR/conv_thread_token_check.c"
MODULE_PATH="$CARGO_TARGET_DIR/release/libclient_pam.so"
PAM_APPL_HEADER="/usr/include/security/pam_appl.h"

# The password the harness conversation hands to the worker. Must match
# PASSWORD in conv_thread_harness.c.
PASSWORD="conv-thread-harness-pw"

# `pam_start_confdir` (Linux-PAM >= 1.5) is what lets an unprivileged test use a
# private service file instead of writing /etc/pam.d.
if ! grep -q 'pam_start_confdir' "$PAM_APPL_HEADER" 2>/dev/null; then
    echo "❌ ERROR: $PAM_APPL_HEADER does not declare pam_start_confdir."
    echo "   This E2E needs Linux-PAM >= 1.5. Run it in the dev container"
    echo "   (docker-compose.dev.yml) rather than faking the result."
    exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tapauth-conv-thread.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> Building libclient_pam.so (release, --features dev-socket-override)"
cargo build --quiet --release -p client-pam --features dev-socket-override

if [ ! -f "$MODULE_PATH" ]; then
    echo "❌ ERROR: $MODULE_PATH was not produced"
    exit 1
fi

echo "==> Building the PAM conversation harness"
HARNESS_BIN="$TMP_DIR/conv_thread_harness"
gcc -O1 -Wall -Wextra -o "$HARNESS_BIN" "$HARNESS_SRC" -lpam -lpthread

echo "==> Building the PAM token-check module"
TOKEN_CHECK_SO="$TMP_DIR/conv_thread_token_check.so"
gcc -O1 -Wall -Wextra -shared -fPIC -o "$TOKEN_CHECK_SO" "$TOKEN_CHECK_SRC" -lpam

echo "==> Creating a private PAM confdir"
CONFDIR="$TMP_DIR/pam.d"
mkdir -p "$CONFDIR"

SOCK_PATH="$TMP_DIR/tapauthd.sock"
export TAPAUTHD_SOCK="$SOCK_PATH"
export CONV_TEST_CONFDIR="$CONFDIR"

# /proc/self/exe resolves symlinks, so the copy has to be a real file.
THREADED_BIN="$TMP_DIR/kscreenlocker_worker"
cp "$HARNESS_BIN" "$THREADED_BIN"
chmod +x "$THREADED_BIN"

# run_shape <label> <service> <expect> <marker-path-or-empty>
#
# Runs the allowlisted copy against an already written service file and asserts
# the harness reported PASS, and — when the stack contains the token check —
# that the token check ran *and* saw the cached password.
run_shape() {
    local label="$1" service="$2" expect="$3" marker="$4"

    echo "==> ${label}: running the harness as 'kscreenlocker_worker'"
    set +e
    local out rc
    out="$(CONV_TEST_SERVICE="$service" CONV_TEST_EXPECT="$expect" \
        timeout 15 "$THREADED_BIN" 2>&1)"
    rc=$?
    set -e
    echo "$out"

    if [ "$rc" -eq 124 ]; then
        echo "❌ ERROR: ${label}: the run hit the 15 s harness timeout."
        exit 1
    fi
    if [ "$rc" -ne 0 ]; then
        echo "❌ ERROR: ${label}: harness exited $rc"
        exit 1
    fi
    if ! grep -q '^RESULT: PASS$' <<<"$out"; then
        echo "❌ ERROR: ${label}: harness did not report RESULT: PASS"
        exit 1
    fi

    if [ -n "$marker" ]; then
        if [ ! -f "$marker" ]; then
            echo "❌ ERROR: ${label}: the token-check module never ran (no $marker)."
            echo "   The password collected by the worker never reached the next"
            echo "   module in the stack."
            exit 1
        fi
        if ! grep -qx 'match' "$marker"; then
            echo "❌ ERROR: ${label}: the token-check module saw '$(cat "$marker")'"
            echo "   instead of the collected password: the cached PAM_AUTHTOK was"
            echo "   not handed to the next module."
            exit 1
        fi
    fi
}

# ---------------------------------------------------------------- sufficient --
SUFFICIENT_SERVICE="tapauth-conv-sufficient"
SUFFICIENT_MARKER="$TMP_DIR/token-seen-sufficient"
cat > "$CONFDIR/$SUFFICIENT_SERVICE" <<EOF
auth sufficient $MODULE_PATH
auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$SUFFICIENT_MARKER
account required pam_permit.so
EOF
run_shape "sufficient (password fallback)" "$SUFFICIENT_SERVICE" success "$SUFFICIENT_MARKER"

# ------------------------------------------------------------------ required --
REQUIRED_SERVICE="tapauth-conv-required"
REQUIRED_MARKER="$TMP_DIR/token-seen-required"
cat > "$CONFDIR/$REQUIRED_SERVICE" <<EOF
auth required $MODULE_PATH
auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$REQUIRED_MARKER
account required pam_permit.so
EOF
# Fail-closed: the stack must not grant, but the token still reaches the next
# module (which is why the marker is asserted inside run_shape).
run_shape "required (fail closed)" "$REQUIRED_SERVICE" non-success "$REQUIRED_MARKER"

# -------------------------------------------------------------------- bypass --
BYPASS_SERVICE="tapauth-conv-bypass"
cat > "$CONFDIR/$BYPASS_SERVICE" <<EOF
auth required $MODULE_PATH
auth optional pam_permit.so
account required pam_permit.so
EOF
# No token check in this stack, so no marker: the assertions are the verdict and
# the conversation having run.
run_shape "bypass (no grant)" "$BYPASS_SERVICE" non-success ""

# Positive control: an unknown process name must NOT reach the threaded path.
# The module then waits out the GUI timeout, so a short timeout is enough.
CONTROL_BIN="$TMP_DIR/not_allowlisted_host"
cp "$HARNESS_BIN" "$CONTROL_BIN"
chmod +x "$CONTROL_BIN"

echo "==> Control: the same harness as 'not_allowlisted_host' must not pass"
set +e
CONTROL_OUT="$(CONV_TEST_SERVICE="$SUFFICIENT_SERVICE" CONV_TEST_EXPECT=success \
    timeout 3 "$CONTROL_BIN" 2>&1)"
CONTROL_RC=$?
set -e
echo "$CONTROL_OUT"

if [ "$CONTROL_RC" -eq 0 ] || grep -q '^RESULT: PASS$' <<<"$CONTROL_OUT"; then
    echo "❌ ERROR: a non-allowlisted process reached the threaded conversation path"
    exit 1
fi

echo "✅ PAM conversation threading E2E passed (sufficient, required, bypass, control)"
