#!/bin/bash
# E2E: the PAM conversation strategies of the PAM module, across the stack
# shapes the module is installed on.
#
# `client-pam` chooses at runtime between driving the host's PAM conversation
# from a worker thread (safe for hosts whose conversation stays answerable while
# the calling thread is blocked), collecting a password the host already holds
# without contacting the daemon (pre-collected hosts), and leaving the
# conversation alone.  The choice is an allowlist keyed on the calling process
# (`conversation_mode` in client-pam/src/pam_logic.rs), so none of the branches
# is reachable from a Rust unit test: it needs a real libpam stack, a
# dynamically loaded `pam_tapauth.so`, and a process whose `/proc/self/exe`
# basename is on the allowlist.
#
# The thread strategy and the return-code policy have to hold *together*, so the
# conversation half is exercised against these real stacks:
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
#   pre-collect  auth sufficient <module>       (harness run as `swaylock`)
#                auth required <token-check> expected=<pw> marker=…
#                CONV_TEST_PRECOLLECT=1 makes the conversation replay the
#                password immediately, like swaylock/gtklock/i3lock.  The module
#                must read it on the calling thread and hand it on *without
#                contacting the daemon*: daemon accept count must stay 0.
#
#   grant        auth sufficient <module>       (harness run as
#                account required pam_permit.so   `kscreenlocker_worker`)
#                CONV_TEST_BLOCK=cancel parks the conversation in
#                `pthread_cond_wait` — a POSIX cancellation point — and never
#                signals it, while the fake daemon waits for the conversation to
#                be entered and then writes a granted IpcEnvelope.  The phone
#                therefore wins while the host is still blocked, and the module
#                must abandon the worker (`pthread_cancel`) instead of waiting
#                for a password that never comes.  A pass cannot be explained by
#                password fallback: the conversation never returns, and the
#                harness asserts `conv_returned == 0` even though the stack
#                granted.  Together with the `duplicate` shape below, this
#                exercises the cancel path.
#
#   duplicate    auth sufficient <module>       (harness run as
#                account required pam_permit.so   `kscreenlocker_worker`)
#                Four transactions in one process (pam_start/pam_authenticate
#                pairs, all handles kept open): user at T0, user immediately
#                (the modelled 0.37 ms duplicate), user at T0+300 ms and user
#                at T0+600 ms.  All four must grant and the fake daemon must
#                have accepted exactly TWO connections: T0 and T0+600 ms.  The
#                T0+300 ms call is a hit under a fixed *and* a sliding window,
#                so only the T0+600 ms call can tell them apart — under the
#                fixed 500 ms window it has been 600 ms since T0 and must start
#                a real transaction, while a window that re-records on each hit
#                would answer it and leave the count at one.  `pam_end` unloads
#                the module and its window, hence the open handles — see
#                run_duplicate_sequence in conv_thread_harness.c.
#
#   duplicate-unavailable
#                auth required <module>          (harness run as
#                account required pam_permit.so   `kscreenlocker_worker`)
#                The same immediate duplicate, but the fake daemon hangs up on
#                the first connection, so both conclude PAM_AUTHINFO_UNAVAIL
#                within milliseconds (no full timeout) with exactly one
#                connection: a concluded failure is reused just like a success,
#                because the duplicate was queued while the first transaction
#                was still running and re-asking would only cost another ring
#                and another wait.
#
#   duplicate-cross-user
#                auth sufficient <module>       (harness run as
#                account required pam_permit.so   `kscreenlocker_worker`)
#                A negative test: the immediate duplicate for a *different*
#                user (this user, then `nobody`) must not be answered from the
#                window, so both must grant and the daemon must have accepted
#                exactly TWO connections.  It fails if the window ever drops the
#                username from its key.
#
#   duplicate-cross-service
#                auth sufficient <module>       (harness run as
#                account required pam_permit.so   `kscreenlocker_worker`)
#                The other negative test: the immediate duplicate for the same
#                user against a *different* PAM service file must not be
#                answered from the window, so both must grant and the daemon
#                must have accepted exactly TWO connections.  It fails if the
#                window ever drops the service from its key — which would let a
#                lock-screen unlock answer a `sudo`/polkit prompt silently.
#
#   gdm reauth   the service file is `gdm-password` and the harness runs as
#                `gdm-session-worker` with GDM_SESSION_FOR_REAUTH=1: a GDM
#                unlock must be offered the phone (threaded, daemon >= 1).
#
#   gdm login    the same service and binary without the reauth variable: the
#                display-manager bypass must still skip it (conversation not
#                entered, daemon 0, and the next module sees no token).
#
# This script therefore:
#   1. builds `libclient_pam.so` release with `dev-socket-override` so the
#      module talks to a socket under our control instead of /run/tapauthd;
#   2. compiles scripts/ci/conv_thread_harness.c (the driver) and
#      scripts/ci/conv_thread_token_check.c (the token-check module) into $TMP;
#   3. for each shape, writes a private confdir service file that loads the
#      module and the token check by absolute path, copies the harness (not a
#      symlink — the kernel resolves /proc/self/exe) to the allowlisted name
#      under test, runs it with the matching CONV_TEST_MODE assertion set, and
#      asserts `RESULT: PASS`, the stack verdict, the strategy actually taken,
#      and — where the stack has one — that the token check saw the cached
#      password;
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

# Every shape that actually passed, as "<short name>=pass".  The final summary
# is derived from this array so a shape that is no longer run (or that stopped
# being reached) cannot stay listed in a hand-maintained trailer.
SHAPES=()

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

# run_shape <label> <binary> <service> <expect> <marker-path-or-empty> <assert-mode> [VAR=VAL...]
#
# Runs the harness copy named <binary> against an already written service file
# and asserts it reported PASS, that the strategy under test actually ran (the
# harness enforces the per-mode conversation assertions), and — when the stack
# contains the token check — that the token check saw the expected password.
run_shape() {
    local label="$1" bin="$2" service="$3" expect="$4" marker="$5" assert_mode="$6"
    shift 6
    local -a extra_env=()
    local kv
    for kv in "$@"; do
        extra_env+=("$kv")
    done

    echo "==> ${label}: running the harness as '$(basename "$bin")' [${assert_mode}]"
    # The caller's own environment must not decide the GDM shape: clear the
    # reauth variable here so the login run really is a login.  `env` applies
    # -u before the assignments, so the reauth shape's GDM_SESSION_FOR_REAUTH=1
    # (from extra_env) still wins.
    set +e
    local out rc
    out="$(env -u GDM_SESSION_FOR_REAUTH CONV_TEST_MODE="$assert_mode" \
        ${extra_env[@]+"${extra_env[@]}"} \
        CONV_TEST_SERVICE="$service" CONV_TEST_EXPECT="$expect" \
        timeout 15 "$bin" 2>&1)"
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

    # Past every assertion: this shape is a genuine pass.  The short name is the
    # label up to the parenthesised detail, e.g. "sufficient (password
    # fallback)" -> "sufficient".
    SHAPES+=("${label%% (*}=pass")
}

# assert_marker <label> <marker> <expected-verdict>
#
# For stacks where the token check must NOT see a token (a bypassed service):
# its marker still proves the module ran, and its verdict proves the previous
# module neither collected nor cached anything.
assert_marker() {
    local label="$1" marker="$2" expected="$3"
    if [ ! -f "$marker" ]; then
        echo "❌ ERROR: ${label}: the token-check module never ran (no $marker)."
        exit 1
    fi
    if ! grep -qx "$expected" "$marker"; then
        echo "❌ ERROR: ${label}: the token-check module reported '$(cat "$marker")',"
        echo "   expected '$expected'."
        exit 1
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
run_shape "sufficient (password fallback)" "$THREADED_BIN" "$SUFFICIENT_SERVICE" \
    success "$SUFFICIENT_MARKER" threaded

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
run_shape "required (fail closed)" "$THREADED_BIN" "$REQUIRED_SERVICE" \
    non-success "$REQUIRED_MARKER" threaded

# -------------------------------------------------------------------- bypass --
BYPASS_SERVICE="tapauth-conv-bypass"
cat > "$CONFDIR/$BYPASS_SERVICE" <<EOF
auth required $MODULE_PATH
auth optional pam_permit.so
account required pam_permit.so
EOF
# No token check in this stack, so no marker: the assertions are the verdict and
# the conversation having run.
run_shape "bypass (no grant)" "$THREADED_BIN" "$BYPASS_SERVICE" non-success "" threaded

# --------------------------------------------------------------- pre-collect --
# swaylock/gtklock/i3lock read the password *before* pam_authenticate and their
# conversation replays it.  The module must collect that token on the calling
# thread and hand it to the next module without ever contacting the daemon: the
# user already chose the password, so ringing the phone could only time out.
# The assertion that discriminates this from a threaded regression is the
# daemon-accept count being zero (the harness's `precollect` set).
PRECOLLECT_BIN="$TMP_DIR/swaylock"
cp "$HARNESS_BIN" "$PRECOLLECT_BIN"
chmod +x "$PRECOLLECT_BIN"

PRECOLLECT_SERVICE="tapauth-conv-precollect"
PRECOLLECT_MARKER="$TMP_DIR/token-seen-precollect"
cat > "$CONFDIR/$PRECOLLECT_SERVICE" <<EOF
auth sufficient $MODULE_PATH
auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$PRECOLLECT_MARKER
account required pam_permit.so
EOF
run_shape "pre-collect (no phone, token handed on)" "$PRECOLLECT_BIN" \
    "$PRECOLLECT_SERVICE" success "$PRECOLLECT_MARKER" precollect \
    CONV_TEST_PRECOLLECT=1

# --------------------------------------------------------------------- grant --
# The phone grants while the host's conversation is still parked in a
# cancellation point.  This is the one shape where the module must abandon the
# worker: the conversation is never signalled, so if `pthread_cancel` in
# `cancel_and_join` stops happening the harness never returns and `timeout 15`
# below turns the regression into rc 124 instead of a hung CI job.
#
# A pass cannot come from password fallback: nothing ever writes a password, the
# conversation never returns (`conv_returned == 0`), yet the stack must grant —
# so the grant can only be the daemon's response, and the module can only have
# reported it after reaping a *cancelled* worker.
GRANT_SERVICE="tapauth-conv-grant"
cat > "$CONFDIR/$GRANT_SERVICE" <<EOF
auth sufficient $MODULE_PATH
account required pam_permit.so
EOF
run_shape "grant (phone wins while the conversation is parked)" \
    "$THREADED_BIN" "$GRANT_SERVICE" success "" grant CONV_TEST_BLOCK=cancel

# ----------------------------------------------------------------- duplicate --
# A lock screen that re-enters `pam_authenticate` right after a transaction
# concludes (kscreenlocker >= 6.8 does so 0.37 ms later) must not produce a
# second transaction: no new request id, no new daemon challenge, no second ring
# of the phone.  The harness runs four transactions in one process (T0, an
# immediate duplicate, T0+300 ms, T0+600 ms; every handle stays open) and
# requires all four to grant.
#
# The discriminator is the fake daemon's accept count: exactly TWO connections,
# one at T0 and one at T0+600 ms.  The immediate duplicate and the T0+300 ms
# call are answered from the module's verdict-reuse window under any model; the
# T0+600 ms call is 600 ms after the *original* verdict, so a fixed 500 ms
# window misses and a new transaction starts, while a window that re-records on
# each hit would still answer it and leave the count at one.  `nanosleep` never
# sleeps less than requested, so overshoot cannot turn the T0+600 ms miss into a
# hit.  The conversation is parked in a cancellation point (`sem_wait`, which
# the mode sets up itself) so a grant cannot come from password fallback.
DUPLICATE_SERVICE="tapauth-conv-duplicate"
cat > "$CONFDIR/$DUPLICATE_SERVICE" <<EOF
auth sufficient $MODULE_PATH
account required pam_permit.so
EOF
run_shape "duplicate (previous success reused, two phone requests)" \
    "$THREADED_BIN" "$DUPLICATE_SERVICE" success "" duplicate

# The duplicate is dispatched whatever the first transaction concluded, so a
# concluded *failure* has to be reused too: the fake daemon hangs up on the
# first connection and both transactions must return PAM_AUTHINFO_UNAVAIL with
# exactly one accepted connection.  Without the reuse window the second call
# starts a fresh transaction, which the daemon grants — so the regression fails
# on the verdict as well as on the count, and the phone would have been rung and
# waited on a second time.  A `required` line makes the nine fail the stack, so
# the verdict is unambiguous.
DUPLICATE_FAIL_SERVICE="tapauth-conv-duplicate-unavailable"
cat > "$CONFDIR/$DUPLICATE_FAIL_SERVICE" <<EOF
auth required $MODULE_PATH
account required pam_permit.so
EOF
run_shape "duplicate-unavailable (concluded failure reused, one phone request)" \
    "$THREADED_BIN" "$DUPLICATE_FAIL_SERVICE" non-success "" duplicate-unavailable

# Negative test for the per-user key: the same immediate duplicate for a
# *different* user must not be answered from the window, so the daemon is asked
# twice and both grant.  A window that ignored the username would answer the
# second call from the first user's verdict and accept only one connection.
DUPLICATE_CROSS_SERVICE="tapauth-conv-duplicate-cross-user"
cat > "$CONFDIR/$DUPLICATE_CROSS_SERVICE" <<EOF
auth sufficient $MODULE_PATH
account required pam_permit.so
EOF
run_shape "duplicate-cross-user (window is per user, daemon asked twice)" \
    "$THREADED_BIN" "$DUPLICATE_CROSS_SERVICE" success "" duplicate-cross-user

# The same negative test for the service half of the key: the same user, but a
# second service file (so a second stack) must not inherit the first one's
# verdict — a window keyed only on the user would let a lock-screen unlock
# answer a `sudo`/polkit prompt without ringing the phone.
DUPLICATE_CROSS_SERVICE_1="tapauth-conv-duplicate-cross-service-1"
DUPLICATE_CROSS_SERVICE_2="tapauth-conv-duplicate-cross-service-2"
for svc in "$DUPLICATE_CROSS_SERVICE_1" "$DUPLICATE_CROSS_SERVICE_2"; do
    cat > "$CONFDIR/$svc" <<EOF
auth sufficient $MODULE_PATH
account required pam_permit.so
EOF
done
run_shape "duplicate-cross-service (window is per service, daemon asked twice)" \
    "$THREADED_BIN" "$DUPLICATE_CROSS_SERVICE_1" success "" duplicate-cross-service \
    CONV_TEST_SERVICE_2="$DUPLICATE_CROSS_SERVICE_2"

# ------------------------------------------------------------------ gdm reauth --
# A GDM reauthentication (unlock / admin prompt of a running session) must NOT
# take the display-manager bypass, and its conversation is answerable from a
# worker thread: the unlock prompt is where the phone has to be offered.
GDM_BIN="$TMP_DIR/gdm-session-worker"
cp "$HARNESS_BIN" "$GDM_BIN"
chmod +x "$GDM_BIN"

GDM_SERVICE="gdm-password"
GDM_REAUTH_MARKER="$TMP_DIR/token-seen-gdm-reauth"
cat > "$CONFDIR/$GDM_SERVICE" <<EOF
auth sufficient $MODULE_PATH
auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$GDM_REAUTH_MARKER
account required pam_permit.so
EOF
run_shape "gdm-password reauth (phone offered)" "$GDM_BIN" "$GDM_SERVICE" \
    success "$GDM_REAUTH_MARKER" threaded GDM_SESSION_FOR_REAUTH=1

# ------------------------------------------------------------- gdm login ------
# The same service without the reauth variable is a *login*: the module must
# keep skipping it so the session can populate PAM_AUTHTOK and unlock the
# keyring.  A regression that widened the reauth exemption would connect here.
GDM_LOGIN_MARKER="$TMP_DIR/token-seen-gdm-login"
cat > "$CONFDIR/$GDM_SERVICE" <<EOF
auth sufficient $MODULE_PATH
auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$GDM_LOGIN_MARKER
account required pam_permit.so
EOF
run_shape "gdm-password login (guard bypass)" "$GDM_BIN" "$GDM_SERVICE" \
    non-success "" bypass
assert_marker "gdm-password login (guard bypass)" "$GDM_LOGIN_MARKER" no-token

# Positive control: an unknown process name must NOT reach the threaded path.
# The module then waits out the GUI timeout, so a short timeout is enough.
CONTROL_BIN="$TMP_DIR/not_allowlisted_host"
cp "$HARNESS_BIN" "$CONTROL_BIN"
chmod +x "$CONTROL_BIN"

echo "==> Control: the same harness as 'not_allowlisted_host' must not pass"
set +e
CONTROL_OUT="$(CONV_TEST_MODE=threaded CONV_TEST_SERVICE="$SUFFICIENT_SERVICE" \
    CONV_TEST_EXPECT=success timeout 3 "$CONTROL_BIN" 2>&1)"
CONTROL_RC=$?
set -e
echo "$CONTROL_OUT"

if [ "$CONTROL_RC" -eq 0 ] || grep -q '^RESULT: PASS$' <<<"$CONTROL_OUT"; then
    echo "❌ ERROR: a non-allowlisted process reached the threaded conversation path"
    exit 1
fi
echo "✅ control (not_allowlisted_host): did not reach the threaded conversation path"
SHAPES+=("control=pass")

SHAPE_LIST=""
for shape in "${SHAPES[@]}"; do
    if [ -n "$SHAPE_LIST" ]; then
        SHAPE_LIST+=", "
    fi
    SHAPE_LIST+="$shape"
done
echo "✅ PAM conversation E2E passed (${#SHAPES[@]} shapes: $SHAPE_LIST)"
