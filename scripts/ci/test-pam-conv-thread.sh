#!/bin/bash
# E2E: the PAM conversation strategies of the PAM module, across the stack
# shapes the module is installed on.
#
# `client-pam` chooses at runtime between driving the host's PAM conversation
# from a worker thread (safe for hosts whose conversation stays answerable while
# the calling thread is blocked), collecting a password the host already holds
# without contacting the daemon (pre-collected hosts), and leaving the
# conversation alone.  The choice is a rule table keyed on the caller — the
# calling process, the PAM service name and the GDM reauth flag
# (`classify` in client-pam/src/policy.rs), so none of the branches is reachable
# from a Rust unit test: it needs a real libpam stack, a dynamically loaded
# `pam_tapauth.so`, and a process whose `/proc/self/exe` basename is on the
# allowlist.
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
#   duplicate-after-slow-module
#                auth required <module>          (harness run as
#                auth required pam_exec.so /bin/sleep 0.8
#                auth required pam_permit.so      `kscreenlocker_worker`)
#                account required pam_permit.so
#                The window's *end*, pinned.  The harness issues its two
#                transactions immediately one after the other, but the first
#                `pam_authenticate` only returns after the module *after*
#                `pam_tapauth.so` has blocked for 800 ms — and the window is
#                anchored at the module's return, not at the end of the stack.
#                The duplicate therefore starts >= 800 ms after the module
#                returned, outside the 500 ms the window covers, so the phone
#                must be rung a second time: both calls grant, the conversation
#                is entered, and the daemon accepts exactly TWO connections.
#                This is the documented limitation, and it fails if the window
#                is widened past 800 ms.
#
#   gdm reauth   the service file is `gdm-password` and the harness runs as
#                `gdm-session-worker` with GDM_SESSION_FOR_REAUTH=1: a GDM
#                unlock must be offered the phone (threaded, daemon >= 1).
#
#   gdm login    the same service and binary without the reauth variable: the
#                display-manager bypass must still skip it (conversation not
#                entered, daemon 0, and the next module sees no token).
#
#   sshd         the service file is `sshd` (and `sshd-session` for the second
#                shape) with the `bypass` stack: R1 refuses a remote stack on
#                the service name alone, before any config read, username
#                lookup, conversation construction or message load.  Asserted:
#                the conversation is not entered, the daemon is not contacted,
#                and the module shows no message at all — the last one is what
#                proves the refusal happened before anything could announce.
#
# This script therefore:
#   1. builds `libclient_pam.so` release with `dev-socket-override` so the
#      module talks to a socket under our control instead of /run/tapauthd;
#   2. compiles scripts/ci/conv_thread_harness.c (the driver) and
#      scripts/ci/conv_thread_token_check.c (the token-check module) into $TMP;
#   3. for each `e2e=1` row of the shared caller corpus
#      (client-pam/tests/fixtures/callers.csv), writes a private confdir service
#      file named after the row's `service`, copies the harness (not a symlink —
#      the kernel resolves /proc/self/exe) to the row's `exe` name, applies the
#      row's `env` column to GDM_SESSION_FOR_REAUTH, runs it with the matching
#      CONV_TEST_MODE assertion set, and asserts `RESULT: PASS`, the stack
#      verdict, the strategy actually taken, and — where the stack has one —
#      that the token check saw the cached password.  The row's `case` arm adds
#      what a CSV cannot express: which stack runs, the markers, the accept
#      counts, the thread the conversation ran on and how many messages the
#      module showed;
#   4. runs a row whose process is deliberately NOT allowlisted and asserts it
#      does not pass, so step 3 cannot succeed vacuously;
#   5. asserts that the executed shapes are exactly the corpus's `e2e=1` rows,
#      so a dropped row fails the run instead of quietly shrinking it.
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

# ------------------------------------------------------- the caller fixture --
# Which hosts and services run is decided by the shared caller corpus, not by a
# list in this script: a row with `e2e=1` is executed as one shape, a row with
# no `case` arm below fails the run, and the executed count is asserted against
# the corpus, so a dropped row cannot silently drop its coverage.  What a row
# proves about the daemon — which stack runs, the token marker, the accept
# counts, the thread the conversation ran on, how many messages the user saw —
# cannot be expressed in the CSV and stays in that row's arm.
FIXTURE="$PROJECT_ROOT/client-pam/tests/fixtures/callers.csv"
if [ ! -f "$FIXTURE" ]; then
    echo "❌ ERROR: the shared caller fixture is missing: $FIXTURE"
    exit 1
fi

# The fixture is 10 comma-separated columns and a `why` containing a comma is a
# parse error rather than a quoted field — the same rule the Rust reader in
# client-pam/src/policy.rs (`parse_row`) enforces on the same file.
read_fixture_row() {
    # shellcheck disable=SC2034  # every column is consumed by the caller
    IFS=, read -r F_ID F_SERVICE F_EXE F_COMM F_ENV F_TTY F_RULE F_POLICY F_WHY \
        F_E2E F_REST
}

# The number of rows that must run, counted in its own pass so the loop below can
# assert that it executed every one of them.
E2E_ROWS=0
while read_fixture_row; do
    if [ -n "$F_REST" ]; then
        echo "❌ ERROR: $FIXTURE row '$F_ID' has more than 10 fields."
        echo "   A comma in the justification is a parse error, not a quoted field."
        exit 1
    fi
    if [ "$F_ID" = "id" ] || [ -z "$F_ID" ]; then
        continue
    fi
    if [ "$F_E2E" = "1" ]; then
        E2E_ROWS=$((E2E_ROWS + 1))
    fi
done <"$FIXTURE"

# The floor is the 13 shapes this layer has always run plus the two R1 service
# names: losing one of them removes the only end-to-end proof of a rule or a
# mechanism, so the number is asserted rather than reported.
MIN_SHAPES=15
if [ "$E2E_ROWS" -lt "$MIN_SHAPES" ]; then
    echo "❌ ERROR: $FIXTURE has only $E2E_ROWS rows with e2e=1, fewer than the"
    echo "   $MIN_SHAPES shapes this layer must keep."
    exit 1
fi

# ------------------------------------------------------------- the runners --

# fail_row <label> <message>
fail_row() {
    echo "❌ ERROR: $1: $2"
    exit 1
}

# write_stack <service-file> <pam.d line>...
#
# The stack is the arm's business: the fixture says which host and service run,
# not which modules follow `pam_tapauth.so`.
write_stack() {
    local file="$1"
    shift
    printf '%s\n' "$@" >"$file"
}

# row_env_args
#
# Applies the row's `env` column: `-` is an *unset* variable, `0` and `1` are
# values it holds.  The module's read (`GdmReauth::from_env`) is presence-only,
# so a set-but-`0` variable must be exported rather than dropped as false.
row_env_args() {
    case "$ROW_ENV" in
    -) ROW_ENV_ARGS=(-u GDM_SESSION_FOR_REAUTH) ;;
    0 | 1) ROW_ENV_ARGS=("GDM_SESSION_FOR_REAUTH=$ROW_ENV") ;;
    *) fail_row "$ROW_ID" "env column is '$ROW_ENV', expected '-', '0' or '1'" ;;
    esac
}

# assert_marker <label> <marker> <expected-verdict>
#
# For stacks where the token check must NOT see a token (a bypassed service):
# its marker still proves the module ran, and its verdict proves the previous
# module neither collected nor cached anything.
assert_marker() {
    local label="$1" marker="$2" expected="$3"
    if [ ! -f "$marker" ]; then
        fail_row "$label" "the token-check module never ran (no $marker)"
    fi
    if ! grep -qx "$expected" "$marker"; then
        fail_row "$label" "the token-check module reported '$(cat "$marker")', expected '$expected'"
    fi
}

# run_harness <label> <assert-mode> <expect> [VAR=VAL...]
#
# Runs the row's harness copy against the row's private service file, with the
# row's `env` column applied, and asserts what every successful shape asserts:
# `RESULT: PASS` and — when the arm set ROW_MARKER — that the token check saw the
# collected password.  The harness's counters are left in OUT_*, so each arm can
# assert what *its* shape proves about the daemon and the user's terminal.
run_harness() {
    local label="$1" assert_mode="$2" expect="$3"
    shift 3
    local -a extra_env=("$@")

    row_env_args

    echo "==> ${label}: running the harness as '$(basename "$ROW_BIN")' [${assert_mode}]"
    set +e
    local out rc
    out="$(env "${ROW_ENV_ARGS[@]}" CONV_TEST_MODE="$assert_mode" \
        ${extra_env[@]+"${extra_env[@]}"} \
        CONV_TEST_SERVICE="$ROW_SERVICE" CONV_TEST_EXPECT="$expect" \
        timeout 15 "$ROW_BIN" 2>&1)"
    rc=$?
    set -e
    echo "$out"

    if [ "$rc" -eq 124 ]; then
        fail_row "$label" "the run hit the 15 s harness timeout"
    fi
    if [ "$rc" -ne 0 ]; then
        fail_row "$label" "the harness exited $rc"
    fi
    if ! grep -q '^RESULT: PASS$' <<<"$out"; then
        fail_row "$label" "the harness did not report RESULT: PASS"
    fi

    if [ -n "$ROW_MARKER" ]; then
        if [ ! -f "$ROW_MARKER" ]; then
            fail_row "$label" "the token-check module never ran (no $ROW_MARKER): the password collected by the worker never reached the next module in the stack"
        fi
        if ! grep -qx 'match' "$ROW_MARKER"; then
            fail_row "$label" "the token-check module saw '$(cat "$ROW_MARKER")' instead of the collected password: the cached PAM_AUTHTOK was not handed to the next module"
        fi
    fi

    OUT_ENTERED="$(sed -n 's/^conv_entered: //p' <<<"$out")"
    OUT_RETURNED="$(sed -n 's/^conv_returned: //p' <<<"$out")"
    OUT_ON_MAIN="$(sed -n 's/^conv_ran_on_main_thread: //p' <<<"$out")"
    OUT_ACCEPTED="$(sed -n 's/^daemon_accepted: //p' <<<"$out")"
    OUT_TEXT_INFO="$(sed -n 's/^conv_text_info: //p' <<<"$out")"

    SHAPES+=("${label%% (*}=pass")
}

# assert_threaded <label>
#
# The four facts a threaded shape must show, whatever its stack: the
# conversation was entered, it ran off the calling thread, the phone was asked,
# and the user was shown the wait announcement.  The last one is also the
# positive control for `conv_text_info`: the skip and handoff arms assert the
# same counter is 0, which would be vacuous if the counter never moved.
assert_threaded() {
    local label="$1"
    if [ "$OUT_ENTERED" -ne 1 ]; then
        fail_row "$label" "the conversation was never entered (threaded mode not selected?)"
    fi
    if [ "$OUT_RETURNED" -ne 1 ]; then
        fail_row "$label" "the conversation had not returned when pam_authenticate returned"
    fi
    if [ "$OUT_ON_MAIN" -ne 0 ]; then
        fail_row "$label" "the conversation ran on the pam_authenticate thread, not the worker"
    fi
    if [ "$OUT_ACCEPTED" -lt 1 ]; then
        fail_row "$label" "the fake daemon accepted no connection"
    fi
    if [ "$OUT_TEXT_INFO" -lt 1 ]; then
        fail_row "$label" "the module showed the user no wait announcement (conv_text_info $OUT_TEXT_INFO)"
    fi
}

# assert_silent <label>
#
# The three facts a shape that must not take part shows: no conversation (so no
# prompt and no password), no daemon contact (so no ring), and no message (so
# nothing was announced before the decision).  Silent is a *property* here, not
# an omission: the module shows its announcement only once it participates.
assert_silent() {
    local label="$1"
    if [ "$OUT_ENTERED" -ne 0 ]; then
        fail_row "$label" "the conversation was entered (conv_entered $OUT_ENTERED)"
    fi
    if [ "$OUT_ACCEPTED" -ne 0 ]; then
        fail_row "$label" "the module contacted the daemon (daemon_accepted $OUT_ACCEPTED): this call must not ring the phone"
    fi
    if [ "$OUT_TEXT_INFO" -ne 0 ]; then
        fail_row "$label" "the module showed the user $OUT_TEXT_INFO message(s): this call must be answered silently"
    fi
}

# assert_accepts <label> <expected>
assert_accepts() {
    local label="$1" expected="$2"
    if [ "$OUT_ACCEPTED" -ne "$expected" ]; then
        fail_row "$label" "the fake daemon accepted $OUT_ACCEPTED connection(s), expected exactly $expected"
    fi
}

# ------------------------------------------------------------ the rows ------
#
# One arm per executed row, keyed by the row's `id`.  The arm writes the stack
# (the CSV has no column for it), runs the row's harness copy, and asserts what
# that shape proves.  A row whose id has no arm is a hard failure: the count
# alone cannot catch a row added without assertions.
EXECUTED=0
while read_fixture_row; do
    if [ -n "$F_REST" ]; then
        echo "❌ ERROR: $FIXTURE row '$F_ID' has more than 10 fields."
        echo "   A comma in the justification is a parse error, not a quoted field."
        exit 1
    fi
    if [ "$F_ID" = "id" ] || [ -z "$F_ID" ]; then
        continue
    fi
    if [ "$F_E2E" != "1" ]; then
        continue
    fi

    ROW_ID="$F_ID"
    ROW_SERVICE="$F_SERVICE"
    ROW_ENV="$F_ENV"
    ROW_EXE="$F_EXE"
    ROW_MARKER=""
    OUT_ENTERED=""
    OUT_RETURNED=""
    OUT_ON_MAIN=""
    OUT_ACCEPTED=""
    OUT_TEXT_INFO=""

    case "$ROW_EXE" in
    "" | - | "~")
        fail_row "$ROW_ID" "an e2e row must name the binary to copy (exe column is '$ROW_EXE')"
        ;;
    esac
    case "$ROW_SERVICE" in
    "" | - | "~")
        fail_row "$ROW_ID" "an e2e row must name its PAM service (service column is '$ROW_SERVICE')"
        ;;
    *[A-Z]*)
        # libpam resolves a mixed-case service name to the *lowercase* service
        # file (`pam_start_confdir` aborts with PAM_ABORT when only the
        # mixed-case file exists), so two rows whose services differ only in case
        # would silently share one stack.  The case-insensitive comparisons stay
        # covered by the corpus rows the Rust reader feeds.
        fail_row "$ROW_ID" "service '$ROW_SERVICE' has upper-case letters; a private confdir cannot name it (libpam lower-cases it)"
        ;;
    esac

    # /proc/self/exe resolves symlinks, so the copy has to be a real file.
    ROW_BIN="$TMP_DIR/$ROW_EXE"
    cp "$HARNESS_BIN" "$ROW_BIN"
    chmod +x "$ROW_BIN"

    EXECUTED=$((EXECUTED + 1))

    case "$ROW_ID" in
    # ---- sufficient: the worker collects the password, the next module sees it
    threaded_no_tty)
        ROW_MARKER="$TMP_DIR/token-seen-$ROW_ID"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$ROW_MARKER" \
            "account required pam_permit.so"
        run_harness "sufficient (password fallback)" threaded success
        assert_threaded "sufficient (password fallback)"
        ;;

    # ---- required: the same collection, but the stack must fail closed
    exe_beats_comm)
        ROW_MARKER="$TMP_DIR/token-seen-$ROW_ID"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth required $MODULE_PATH" \
            "auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$ROW_MARKER" \
            "account required pam_permit.so"
        run_harness "required (fail closed)" threaded non-success
        assert_threaded "required (fail closed)"
        ;;

    # ---- bypass: `required` + `optional pam_permit` must not become a grant
    # No token check in this stack, so no marker: the assertions are the verdict
    # and the conversation having run on the worker.
    kscreenlocker_truncated)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth required $MODULE_PATH" \
            "auth optional pam_permit.so" \
            "account required pam_permit.so"
        run_harness "bypass (no grant)" threaded non-success
        assert_threaded "bypass (no grant)"
        ;;

    # ---- pre-collect: the password predates pam_authenticate, no ring at all
    precollected_swaylock)
        ROW_MARKER="$TMP_DIR/token-seen-$ROW_ID"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$ROW_MARKER" \
            "account required pam_permit.so"
        run_harness "pre-collect (no phone, token handed on)" precollect success \
            CONV_TEST_PRECOLLECT=1
        if [ "$OUT_ON_MAIN" -ne 1 ]; then
            fail_row "$ROW_ID" "the pre-collected replay ran off the pam_authenticate thread; a pre-collected host must be served synchronously on it"
        fi
        if [ "$OUT_ACCEPTED" -ne 0 ]; then
            fail_row "$ROW_ID" "a pre-collected host contacted the daemon: the password was already typed, so the phone must not be consulted"
        fi
        if [ "$OUT_TEXT_INFO" -ne 0 ]; then
            fail_row "$ROW_ID" "a pre-collected host showed the user a message; the handoff returns before anything is announced"
        fi
        ;;

    # ---- grant: the phone wins while the host's conversation is parked
    # A pass cannot come from password fallback: nothing ever writes a password,
    # nothing ever signals the conversation, yet the stack must grant — so the
    # grant can only be the daemon's response, reported after reaping a
    # *cancelled* worker.  If `pthread_cancel` stops happening the run does not
    # hang: `timeout 15` turns it into rc 124.
    threaded_with_tty_unreachable)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "account required pam_permit.so"
        run_harness "grant (phone wins while the conversation is parked)" grant success \
            CONV_TEST_BLOCK=cancel
        if [ "$OUT_ENTERED" -ne 1 ]; then
            fail_row "$ROW_ID" "the conversation was never entered (threaded mode not selected?)"
        fi
        if [ "$OUT_ON_MAIN" -ne 0 ]; then
            fail_row "$ROW_ID" "the conversation ran on the pam_authenticate thread, not the worker"
        fi
        if [ "$OUT_RETURNED" -ne 0 ]; then
            fail_row "$ROW_ID" "the conversation returned a password: a grant here cannot be distinguished from password fallback (worker not cancelled?)"
        fi
        if [ "$OUT_ACCEPTED" -lt 1 ]; then
            fail_row "$ROW_ID" "the fake daemon accepted no connection"
        fi
        ;;

    # ---- duplicate: the previous success is reused, two phone requests
    # The row sets `env=0`: the module's reauth read is presence-only, so a
    # set-but-`0` variable must take the gdm-password reauth path (threaded) and
    # not the display-manager login bypass.  Four transactions in one process
    # (T0, an immediate duplicate, T0+300 ms, T0+600 ms; every handle stays
    # open) must all grant, with exactly TWO daemon connections: T0 and
    # T0+600 ms.  The T0+300 ms call is a hit under a fixed *and* a sliding
    # window, so only the T0+600 ms call can tell them apart.
    reauth_zero_value)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "account required pam_permit.so"
        run_harness "duplicate (previous success reused, two phone requests)" duplicate success
        assert_accepts "$ROW_ID" 2
        if [ "$OUT_ENTERED" -ne 1 ]; then
            fail_row "$ROW_ID" "the conversation was never entered (threaded mode not selected?)"
        fi
        ;;

    # ---- duplicate-unavailable: a concluded failure is reused too
    # The fake daemon hangs up on the first connection, so both transactions
    # conclude PAM_AUTHINFO_UNAVAIL within milliseconds (no full timeout) with
    # exactly one connection.  Without the reuse window the second call starts a
    # fresh transaction, which the daemon grants — so the regression fails on the
    # verdict as well as on the count.
    threaded_polkit_agent)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth required $MODULE_PATH" \
            "account required pam_permit.so"
        run_harness "duplicate-unavailable (concluded failure reused, one phone request)" \
            duplicate-unavailable non-success
        assert_accepts "$ROW_ID" 1
        ;;

    # ---- duplicate-cross-user: the window is per user (negative test)
    threaded_hyprlock)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "account required pam_permit.so"
        run_harness "duplicate-cross-user (window is per user, daemon asked twice)" \
            duplicate-cross-user success
        assert_accepts "$ROW_ID" 2
        ;;

    # ---- duplicate-cross-service: the window is per service (negative test)
    # A second service file means a second stack: a window keyed only on the user
    # would let a lock-screen unlock answer a `sudo`/polkit prompt silently.
    threaded_xsecurelock)
        SECOND_SERVICE="$ROW_SERVICE-e2e-second"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "account required pam_permit.so"
        write_stack "$CONFDIR/$SECOND_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "account required pam_permit.so"
        run_harness "duplicate-cross-service (window is per service, daemon asked twice)" \
            duplicate-cross-service success "CONV_TEST_SERVICE_2=$SECOND_SERVICE"
        assert_accepts "$ROW_ID" 2
        ;;

    # ---- duplicate-after-slow-module: the window's end, pinned
    # The stack puts `pam_exec.so /bin/sleep 0.8` after `pam_tapauth.so`, so the
    # first `pam_authenticate` only returns ~800 ms after the module did, and the
    # immediate duplicate is already outside the 500 ms window: the phone must be
    # rung a second time (two accepts).  A window widened past 800 ms turns this
    # into one accept.
    threaded_polkit_agent_truncated)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth required $MODULE_PATH" \
            "auth required pam_exec.so /bin/sleep 0.8" \
            "auth required pam_permit.so" \
            "account required pam_permit.so"
        run_harness "duplicate-after-slow-module (later module blocks past the window, two phone requests)" \
            duplicate-after-slow-module success
        assert_accepts "$ROW_ID" 2
        ;;

    # ---- gdm reauth: an unlock is offered the phone
    # The row is R3's other spelling: `/proc/self/comm` truncates the worker's
    # name to `gdm-session-wor` (TASK_COMM_LEN - 1), while the login row above
    # uses the full `gdm-session-worker`.
    threaded_gdm_worker_truncated)
        ROW_MARKER="$TMP_DIR/token-seen-$ROW_ID"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$ROW_MARKER" \
            "account required pam_permit.so"
        run_harness "gdm-password reauth (phone offered)" threaded success
        assert_threaded "gdm-password reauth (phone offered)"
        ;;

    # ---- gdm login: the display-manager bypass still skips it
    # A regression that widened the reauth exemption would connect here; the
    # marker proves the token check ran and saw no token, so nothing was
    # collected and PAM_AUTHTOK stays available to the session's keyring module.
    gdm_login_bypass)
        LOGIN_MARKER="$TMP_DIR/token-seen-$ROW_ID"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$LOGIN_MARKER" \
            "account required pam_permit.so"
        run_harness "gdm-password login (guard bypass)" bypass non-success
        assert_marker "$ROW_ID" "$LOGIN_MARKER" no-token
        assert_silent "gdm-password login (guard bypass)"
        ;;

    # ---- control: a real host outside the allowlist must not reach the worker
    # `kscreenlocker_greet` is deliberately absent from the table, so the module
    # takes the sequential path and the threaded assertion set cannot hold.  With
    # no terminal it waits out the GUI timeout, so a short timeout is enough.
    kscreenlocker_greet)
        CONTROL_MARKER="$TMP_DIR/token-seen-$ROW_ID"
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth sufficient $MODULE_PATH" \
            "auth required $TOKEN_CHECK_SO expected=$PASSWORD marker=$CONTROL_MARKER" \
            "account required pam_permit.so"
        row_env_args
        echo "==> control: the same harness as '$(basename "$ROW_BIN")' must not reach the threaded path"
        set +e
        CONTROL_OUT="$(env "${ROW_ENV_ARGS[@]}" CONV_TEST_MODE=threaded \
            CONV_TEST_SERVICE="$ROW_SERVICE" CONV_TEST_EXPECT=success \
            timeout 3 "$ROW_BIN" 2>&1)"
        CONTROL_RC=$?
        set -e
        echo "$CONTROL_OUT"
        if [ "$CONTROL_RC" -eq 0 ] || grep -q '^RESULT: PASS$' <<<"$CONTROL_OUT"; then
            fail_row "$ROW_ID" "a process outside the allowlist reached the threaded conversation path"
        fi
        echo "✅ control (${ROW_EXE}): did not reach the threaded conversation path"
        SHAPES+=("control=pass")
        ;;

    # ---- R1: the service name alone refuses a remote stack
    # The module must not take part in a remote authentication, and the refusal
    # happens before the config read, the username lookup, the conversation and
    # the message load.  The stack is `required` + `optional pam_permit`: if the
    # module answered PAM_IGNORE (the code it must never return) the required
    # line would record no failure and the optional line would grant, so the
    # non-success verdict is part of the shape.  `conv_text_info == 0` is the
    # ordering-independent half: any participation would have announced its wait.
    svc_sshd | svc_sshd_session)
        write_stack "$CONFDIR/$ROW_SERVICE" \
            "auth required $MODULE_PATH" \
            "auth optional pam_permit.so" \
            "account required pam_permit.so"
        run_harness "${ROW_ID} (service name refused, no message)" bypass non-success
        assert_silent "$ROW_ID"
        ;;

    *)
        echo "❌ ERROR: fixture row '$ROW_ID' has e2e=1 but no case arm in this script."
        echo "   The row would run unasserted: its stack, markers, accept counts"
        echo "   and message counts are not in the CSV, so add an arm for it."
        exit 1
        ;;
    esac
done <"$FIXTURE"

if [ "$EXECUTED" -ne "$E2E_ROWS" ]; then
    echo "❌ ERROR: executed $EXECUTED shapes, but $FIXTURE has $E2E_ROWS rows with e2e=1."
    exit 1
fi
if [ "${#SHAPES[@]}" -ne "$EXECUTED" ]; then
    echo "❌ ERROR: $EXECUTED rows ran but only ${#SHAPES[@]} shapes were recorded:"
    echo "   an arm that runs without recording its pass would vanish from the summary."
    exit 1
fi
if [ "$EXECUTED" -lt "$MIN_SHAPES" ]; then
    echo "❌ ERROR: only $EXECUTED shapes ran; this layer must keep at least $MIN_SHAPES."
    exit 1
fi

SHAPE_LIST=""
for shape in "${SHAPES[@]}"; do
    if [ -n "$SHAPE_LIST" ]; then
        SHAPE_LIST+=", "
    fi
    SHAPE_LIST+="$shape"
done
echo "✅ PAM conversation E2E passed (${#SHAPES[@]} shapes, $EXECUTED/$E2E_ROWS e2e fixture rows: $SHAPE_LIST)"
