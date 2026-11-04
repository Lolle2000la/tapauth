#!/usr/bin/env bash
#
# test-pam-host-cases.sh — host-facing PAM module verdicts (TTY-less hosts, DM
# bypass, sufficient-stack fallthrough).
#
# WHAT IT PROVES
#   The client-pam fixes "never return PAM_IGNORE" (0868f81) and "announce the
#   wait exactly once, right before blocking" (c40543f) are only observable
#   through a real PAM stack on a host the module cannot drive interactively.
#   This runner builds those stacks under /etc/pam.d, points the *production*
#   socket path at a silent stub daemon (scripts/ci/pam-stub-daemon.py) and
#   drives the module through scripts/ci/pamtester.c with no controlling
#   terminal, asserting the numeric PAM result (not just the exit status).
#
#   Cases (one PASS/FAIL/SKIP line each):
#     1 ttyless_wait_announced_before_blocking  (exactly one pre-wait TEXT_INFO
#                                              whose wording names the
#                                              password route; the *position*
#                                              relative to the dispatch is
#                                              case 7's job)
#     2 conv_error_still_verdicts
#     3 null_conv_is_survivable               (expected SKIP: libpam rejects a
#                                              NULL conversation in pam_start,
#                                              so this state is unreachable
#                                              through the public libpam API)
#     4 required_arch_gdm_stack_not_success   (4a synthetic DM service
#                                              gdm-tapauth-host, 4b the same
#                                              stack under a non-DM service)
#     5 sufficient_stack_falls_through        (guard against a PAM_SUCCESS
#                                              regression only: it also passes
#                                              on the pre-fix tree)
#     6 double_invocation_never_ignore
#     7 fast_path_does_not_announce_the_wait  (only TEXT_INFO is forbidden; the
#                                              fast path does emit a
#                                              PAM_ERROR_MSG)
#
# REQUIREMENTS
#   - root: it writes /etc/pam.d/tapauth-host-* and /etc/pam.d/gdm-tapauth-host,
#     backs up+replaces /etc/tapauth/config.toml and binds the production socket
#     /run/tapauthd/tapauthd.sock. Only files this run actually wrote are
#     removed again, and only a file it actually backed up is restored. A
#     pre-existing socket is refused (the script aborts; it never shadows or
#     deletes a real daemon's socket). As non-root it prints one SKIP line per
#     case and exits 0.
#   - cc (builds pamtester), python3 (stub daemon), setsid (util-linux),
#     libpam headers.
#   - The module is built from the tree unless SKIP_BUILD=1.
#
# USAGE
#   sudo ./scripts/ci/test-pam-host-cases.sh
#   PAM_MODULE_PATH=/tmp/opencode/pam-base/target/debug/libclient_pam.so \
#     SKIP_BUILD=1 sudo -E ./scripts/ci/test-pam-host-cases.sh
#
# ENVIRONMENT
#   PAM_MODULE_PATH   module under test (default: target/debug/libclient_pam.so)
#   SKIP_BUILD=1      do not run cargo build
#   PAMTESTER_BIN     use an existing pamtester binary instead of compiling
#   PAM_CASE_FILTER   space-separated case numbers/names to run (default: all)
#
# LC_ALL/LANG are forced to `C` below, so the module's own (localized) message
# text is locale-independent even under `sudo -E` with a non-English user
# locale; the script never relies on the text alone anyway (case 1 asserts the
# announcement's count and timing, and treats the wording as an extra check).
#
# The config is written to the production path with a 2 s GUI timeout and a 4 s
# operation timeout, so every blocking case settles in about 2 s.
set -u -o pipefail

# A correct run must not FAIL just because the caller has a German (or any
# non-English) locale: the module localizes its messages, and `sudo -E` (the
# documented invocation) forwards LANG/LC_ALL to root. Pin C for this script and
# every pamtester child.
export LC_ALL=C
export LANG=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PAM_MODULE_PATH="${PAM_MODULE_PATH:-${REPO_ROOT}/target/debug/libclient_pam.so}"
SKIP_BUILD="${SKIP_BUILD:-0}"
PAMTESTER_BIN="${PAMTESTER_BIN:-}"
PAM_CASE_FILTER="${PAM_CASE_FILTER:-}"

PAM_CONFIG_PATH="/etc/tapauth/config.toml"
PAM_SOCKET_PATH="/run/tapauthd/tapauthd.sock"
GUI_TIMEOUT_SECS=2
OP_TIMEOUT_SECS=4

SERVICE_SEQUENTIAL="tapauth-host-sequential"
SERVICE_ARCH_GDM="tapauth-host-arch-gdm"
# Synthetic display-manager service for case 4a. The module matches on the
# service-name prefix (`gdm-…`), so this exercises the DM bypass without
# overwriting a real desktop's /etc/pam.d/gdm-password — an aborted run must not
# be able to break the developer's own login.
SERVICE_DM="gdm-tapauth-host"
SERVICE_SUFFICIENT_PERMIT="tapauth-host-sufficient-permit"
SERVICE_SUFFICIENT_DENY="tapauth-host-sufficient-deny"
SERVICE_DOUBLE="tapauth-host-double"

CASE_NAMES=(
    "ttyless_wait_announced_before_blocking"
    "conv_error_still_verdicts"
    "null_conv_is_survivable"
    "required_arch_gdm_stack_not_success"
    "sufficient_stack_falls_through"
    "double_invocation_never_ignore"
    "fast_path_does_not_announce_the_wait"
)

PASSED=0
FAILED=0
SKIPPED=0
RAN=0

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

now_ms() {
    # GNU date: nanoseconds truncated to milliseconds.
    date +%s%N | cut -b1-13
}

die() {
    echo "ERROR: $*" >&2
    exit 2
}

case_selected() { # $1 = case number (1-based)
    local n="$1"
    local name="${CASE_NAMES[$((n - 1))]}"
    local tok
    [ -z "$PAM_CASE_FILTER" ] && return 0
    for tok in $PAM_CASE_FILTER; do
        [ "$tok" = "$n" ] && return 0
        [ "$tok" = "$name" ] && return 0
    done
    return 1
}

begin_case() {
    CASE_NAME="$1"
    CASE_ERRORS=()
    CASE_SKIPPED=0
    CASE_SKIP_REASON=""
    CASE_DIR="${TMP_ROOT}/case-$(printf '%02d' "$2")"
    mkdir -p "$CASE_DIR"
    stop_stub
}

add_error() {
    CASE_ERRORS+=("$*")
}

skip_case() {
    CASE_SKIPPED=1
    CASE_SKIP_REASON="$*"
}

end_case() {
    RAN=$((RAN + 1))
    if [ "$CASE_SKIPPED" -eq 1 ]; then
        printf 'SKIP %s: %s\n' "$CASE_NAME" "$CASE_SKIP_REASON"
        SKIPPED=$((SKIPPED + 1))
        return
    fi
    if [ "${#CASE_ERRORS[@]}" -eq 0 ]; then
        printf 'PASS %s\n' "$CASE_NAME"
        PASSED=$((PASSED + 1))
    else
        printf 'FAIL %s\n' "$CASE_NAME"
        local e
        for e in "${CASE_ERRORS[@]}"; do
            printf '     - %s\n' "$e"
        done
        printf '     PAM_RESULT=%s exit=%s elapsed=%sms\n' \
            "${RUN_RESULT:-<none>}" "${RUN_EXIT:-?}" "${RUN_MS:-?}"
        FAILED=$((FAILED + 1))
    fi
}

# assert_eq NAME EXPECTED ACTUAL
assert_eq() {
    if [ "$2" != "$3" ]; then
        add_error "$1: expected '$2', got '$3'"
    fi
}

# assert_ok NAME CONDITION(0=ok) DESCRIPTION
assert_ok() {
    if [ "$2" -ne 0 ]; then
        add_error "$1: $3"
    fi
}

# ---------------------------------------------------------------------------
# pamtester invocation
# ---------------------------------------------------------------------------

# run_pamtester [pamtester args...]
#
# Runs pamtester in its own session (setsid) so the PAM module cannot open
# /dev/tty and therefore takes its TTY-less path, with stdin from /dev/null.
# Sets RUN_RESULT (numeric PAM code, if printed), RUN_EXIT (exit status,
# 128+N when the process died from signal N) and RUN_MS (wall time).
run_pamtester() {
    local out="${CASE_DIR}/stdout" err="${CASE_DIR}/stderr"
    local code_file="${CASE_DIR}/code"
    : >"$out"
    : >"$err"
    : >"$code_file"

    RUN_RESULT=""
    RUN_MS=""

    local start end
    start=$(now_ms)
    OUT="$out" ERR="$err" CODE="$code_file" RUN_TIMEOUT=15 \
        setsid -w sh -c 'timeout "$RUN_TIMEOUT" "$@" </dev/null >"$OUT" 2>"$ERR"; echo $? >"$CODE"' \
        sh "$@" >/dev/null 2>&1
    end=$(now_ms)

    RUN_MS=$((end - start))
    RUN_EXIT="$(cat "$code_file" 2>/dev/null || echo 1)"
    [ -n "$RUN_EXIT" ] || RUN_EXIT=1
    RUN_RESULT="$(sed -n 's/^PAM_RESULT=\([-0-9]*\)$/\1/p' "$out" | tail -n 1)"
}

stub_pid=""
stub_log=""
# 1 once *this* run created the socket at $PAM_SOCKET_PATH. Only then may
# stop_stub() unlink it; a socket this script did not create is never removed.
STUB_CREATED=0

# A dangling symlink at the socket path is still "something is there": `-e`
# alone is false for it, and the stub must not bind over (or replace) it.
socket_path_present() {
    [ -e "$PAM_SOCKET_PATH" ] || [ -L "$PAM_SOCKET_PATH" ]
}

start_stub() {
    mkdir -p "$(dirname "$PAM_SOCKET_PATH")" || die "cannot create ${PAM_SOCKET_PATH%/*}"
    # Defense in depth: start-up already refuses a pre-existing socket, so one
    # appearing here belongs to somebody else (a daemon started mid-run). The
    # stub binds without unlinking, so it must not even be started.
    if socket_path_present; then
        add_error "${PAM_SOCKET_PATH} exists but was not created by this run; refusing to shadow it"
        return 1
    fi
    stub_log="${CASE_DIR}/stub.log"
    python3 "$REPO_ROOT/scripts/ci/pam-stub-daemon.py" "$PAM_SOCKET_PATH" \
        >"$stub_log" 2>&1 &
    stub_pid=$!
    for _ in $(seq 1 100); do
        if [ -S "$PAM_SOCKET_PATH" ]; then
            STUB_CREATED=1
            return 0
        fi
        if ! kill -0 "$stub_pid" 2>/dev/null; then
            add_error "stub daemon exited before binding ${PAM_SOCKET_PATH}: $(cat "$stub_log" 2>/dev/null)"
            stub_pid=""
            return 1
        fi
        sleep 0.05
    done
    add_error "stub daemon did not bind ${PAM_SOCKET_PATH} within 5s"
    return 1
}

stop_stub() {
    if [ -n "$stub_pid" ]; then
        kill -TERM "$stub_pid" 2>/dev/null || true
        wait "$stub_pid" 2>/dev/null || true
        stub_pid=""
    fi
    # The stub unlinks its own socket on SIGTERM; this is only a safety net and
    # never touches a socket another process owns.
    if [ "$STUB_CREATED" -eq 1 ]; then
        rm -f "$PAM_SOCKET_PATH"
        STUB_CREATED=0
    fi
}

# write_service NAME  (stack on stdin)
write_service() {
    local name="$1"
    local path="/etc/pam.d/${name}"
    # Registered *before* the redirection: `cat >` truncates the target first,
    # so a half-written file must still be cleanup()'s responsibility. The name
    # is a synthetic, script-owned one, so owning it from the first byte is
    # correct.
    WRITTEN_PAM_SERVICES+=("$name")
    cat >"$path" || die "cannot write $path"
    chmod 0644 "$path" || die "cannot chmod $path"
}

# ---------------------------------------------------------------------------
# environment / cleanup
# ---------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    reason="requires root (writes /etc/pam.d, ${PAM_CONFIG_PATH}, ${PAM_SOCKET_PATH})"
    for name in "${CASE_NAMES[@]}"; do
        echo "SKIP ${name}: $reason"
        SKIPPED=$((SKIPPED + 1))
    done
    echo ""
    echo "Summary: 0 passed, 0 failed, ${SKIPPED} skipped (not root)"
    exit 0
fi

# The stub occupies the *production* socket path. If something is already there
# — including a dangling symlink — it belongs to a real tapauthd (or to another
# run), and this script must neither shadow it nor delete it, so refuse instead
# of cleaning up behind us.
if socket_path_present; then
    die "refusing to run: ${PAM_SOCKET_PATH} already exists (a running tapauthd?). Stop it first; this script will not delete it."
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/tapauth-pam-cases.XXXXXX")" || die "mktemp failed"

CONFIG_BACKUP=""
# 1 only once this run wrote $PAM_CONFIG_PATH (and only then may cleanup()
# restore or delete it).
CONFIG_WRITTEN=0
# PAM service files this run actually wrote (registered by write_service()).
WRITTEN_PAM_SERVICES=()
CLEANED_UP=0

cleanup() {
    # Idempotent: an INT/TERM trap runs this and the later EXIT trap runs it
    # again; the second call must not undo the restore the first one did.
    if [ "$CLEANED_UP" -eq 1 ]; then
        return 0
    fi
    CLEANED_UP=1
    set +e
    stop_stub
    local svc
    for svc in ${WRITTEN_PAM_SERVICES[@]+"${WRITTEN_PAM_SERVICES[@]}"}; do
        rm -f "/etc/pam.d/${svc}"
    done
    # Only touch $PAM_CONFIG_PATH when this run actually wrote it, and only
    # restore from a backup that was really taken. A run that aborts before the
    # backup/write section must leave the host's files byte-for-byte alone.
    if [ "$CONFIG_WRITTEN" -eq 1 ]; then
        if [ -n "$CONFIG_BACKUP" ] && [ -f "$CONFIG_BACKUP" ]; then
            cp -p "$CONFIG_BACKUP" "$PAM_CONFIG_PATH"
        else
            rm -f "$PAM_CONFIG_PATH"
        fi
    fi
    rm -rf "$TMP_ROOT"
}
# A signal handler that only runs cleanup() lets bash resume the interrupted
# case, which would then rewrite files the cleanup already removed — so the
# INT/TERM handlers clean up and exit, and the EXIT trap's cleanup() is a no-op
# thanks to the guard above.
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# --- module under test -------------------------------------------------------
if [ "$SKIP_BUILD" != "1" ]; then
    echo "==> Building client-pam module..."
    ( cd "$REPO_ROOT" && cargo build --manifest-path client-pam/Cargo.toml ) \
        || die "cargo build failed"
fi
[ -f "$PAM_MODULE_PATH" ] || die "PAM module not found at ${PAM_MODULE_PATH}"

# --- pamtester ---------------------------------------------------------------
if [ -z "$PAMTESTER_BIN" ]; then
    command -v cc >/dev/null 2>&1 || die "cc is required to build scripts/ci/pamtester.c"
    PAMTESTER_BIN="${TMP_ROOT}/pamtester"
    cc -O2 -o "$PAMTESTER_BIN" "$REPO_ROOT/scripts/ci/pamtester.c" -lpam \
        || die "failed to compile scripts/ci/pamtester.c"
fi
[ -x "$PAMTESTER_BIN" ] || die "pamtester binary not executable: ${PAMTESTER_BIN}"

command -v setsid >/dev/null 2>&1 || die "setsid (util-linux) is required to detach from the terminal"
command -v python3 >/dev/null 2>&1 || die "python3 is required to run scripts/ci/pam-stub-daemon.py"

# --- config backup -----------------------------------------------------------
mkdir -p "$(dirname "$PAM_CONFIG_PATH")"
if [ -f "$PAM_CONFIG_PATH" ]; then
    CONFIG_BACKUP="${TMP_ROOT}/config.toml.orig"
    cp -p "$PAM_CONFIG_PATH" "$CONFIG_BACKUP" || die "cannot back up $PAM_CONFIG_PATH"
fi
# Flagged before the redirection: `cat >` truncates the host's file first, so a
# failed write must still make the trap restore it (and abort the run rather than
# continue against a half-written config).
CONFIG_WRITTEN=1
cat >"$PAM_CONFIG_PATH" <<EOF || die "cannot write $PAM_CONFIG_PATH"
# Written by scripts/ci/test-pam-host-cases.sh (restored on exit).
pam_gui_timeout_secs = ${GUI_TIMEOUT_SECS}
pam_operation_timeout_secs = ${OP_TIMEOUT_SECS}
EOF
chmod 0600 "$PAM_CONFIG_PATH" || die "cannot chmod $PAM_CONFIG_PATH"

CONV_LOG="${TMP_ROOT}/conv.log"
export PAMTESTER_CONV_LOG="$CONV_LOG"

echo "==> Module: ${PAM_MODULE_PATH}"
echo "==> pamtester: ${PAMTESTER_BIN}"
echo "==> Config: ${PAM_CONFIG_PATH} (gui=${GUI_TIMEOUT_SECS}s op=${OP_TIMEOUT_SECS}s)"
echo ""

# ===========================================================================
# Case 1: the TTY-less wait is announced exactly once, before the wait ends.
#
# Pins three things, all structural:
#   - exactly one TEXT_INFO is delivered before the wait completes (T < 1.0 s
#     while the call itself blocks for > 1.5 s), so the module does not stay
#     silent and does not announce after giving up;
#   - that message names the password route (LC_ALL=C makes the wording the
#     English string), i.e. it is the announcement and not some other notice;
#   - the pre-wait announcement replaces the old wording: the pre-fix tree
#     announced "Waiting for phone tap..." *at module entry* instead.
# It deliberately does NOT pin the position relative to the daemon request:
# the announcement is written after `send_authenticate_start` and the stub only
# stamps connections, so the two are unordered. "Does not announce before it
# can possibly wait" is what case 7 pins, via the no-daemon fast path.
# ===========================================================================
case_1() {
    write_service "$SERVICE_SEQUENTIAL" <<EOF
auth    required        ${PAM_MODULE_PATH}
EOF
    rm -f "$CONV_LOG"
    start_stub || return
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_SEQUENTIAL" root authenticate
    assert_eq "PAM result" "9" "$RUN_RESULT"
    assert_ok "wall time" \
        "$([ "${RUN_MS:-0}" -gt 1500 ] && echo 0 || echo 1)" \
        "expected the module to block for the ${GUI_TIMEOUT_SECS}s GUI timeout (>1500 ms), took ${RUN_MS:-?} ms"

    if [ ! -f "$CONV_LOG" ]; then
        add_error "no conversation log at ${CONV_LOG}"
        return
    fi
    assert_eq "conv log start" "START T=0.000" "$(head -n 1 "$CONV_LOG")"

    # Structural assertion (locale-independent). The module also emits a
    # TEXT_INFO when it gives up ("Timed out, trying password...") at the end of
    # the wait, so "before the wait ends" is what is asserted: exactly one
    # TEXT_INFO at T < 1.0 s, while the call itself takes > 1.5 s.
    local info_lines=() early=() line
    mapfile -t info_lines < <(grep 'STYLE=TEXT_INFO' "$CONV_LOG")
    if [ "${#info_lines[@]}" -eq 0 ]; then
        add_error "no STYLE=TEXT_INFO on the conversation, so the wait was never announced"
        return
    fi
    for line in "${info_lines[@]}"; do
        if awk -v t="$(printf '%s\n' "$line" | awk '{print $2}' | sed 's/^T=//')" \
            'BEGIN { exit !(t < 1.0) }'; then
            early+=("$line")
        fi
    done
    if [ "${#early[@]}" -ne 1 ]; then
        add_error "expected exactly one STYLE=TEXT_INFO before the wait ends (T<1.0s), got ${#early[@]} of ${#info_lines[@]}"
        return
    fi

    # The early message is the password-route announcement, not some other
    # TEXT_INFO. LC_ALL=C is exported above, so this text is the English string
    # from client-pam/locales/en/main.ftl.
    if ! printf '%s\n' "${early[0]}" | grep -qi 'password'; then
        add_error "the wait announcement does not mention the password route: ${early[0]}"
    fi
}

# ===========================================================================
# Case 2: a host whose conversation refuses every message still gets a verdict.
# ===========================================================================
case_2() {
    write_service "$SERVICE_SEQUENTIAL" <<EOF
auth    required        ${PAM_MODULE_PATH}
EOF
    start_stub || return
    run_pamtester "$PAMTESTER_BIN" --conv-err "$SERVICE_SEQUENTIAL" root authenticate
    assert_eq "PAM result" "9" "$RUN_RESULT"
    assert_ok "termination" \
        "$([ "${RUN_EXIT:-999}" -lt 128 ] && echo 0 || echo 1)" \
        "process exited with ${RUN_EXIT} (>=128 means it died from a signal)"
    assert_ok "wall time" \
        "$([ "${RUN_MS:-0}" -gt 1500 ] && echo 0 || echo 1)" \
        "expected the module to block for the ${GUI_TIMEOUT_SECS}s GUI timeout (>1500 ms), took ${RUN_MS:-?} ms"
}

# ===========================================================================
# Case 3: a NULL conversation must not crash the module.
#
# Expected to SKIP: libpam refuses a NULL conversation in pam_start() itself, so
# this state is unreachable through the public libpam API. The `7` assertion
# below is what the module *would* return (conversation lookup failure) and is
# therefore NOT covered behaviour — the SKIP is honest, not pending.
# ===========================================================================
case_3() {
    write_service "$SERVICE_SEQUENTIAL" <<EOF
auth    required        ${PAM_MODULE_PATH}
EOF
    # No daemon: the module must fail before it could talk to one.
    run_pamtester "$PAMTESTER_BIN" --null-conv "$SERVICE_SEQUENTIAL" root authenticate
    if [ "${RUN_EXIT:-999}" -eq 3 ]; then
        skip_case "libpam rejected a NULL conversation: $(grep -h 'pam_start failed' "${CASE_DIR}/stderr" 2>/dev/null | head -n 1)"
        return
    fi
    assert_eq "PAM result" "7" "$RUN_RESULT"
    assert_ok "termination" \
        "$([ "${RUN_EXIT:-999}" -lt 128 ] && echo 0 || echo 1)" \
        "process exited with ${RUN_EXIT} (>=128 means it died from a signal)"
}

# ===========================================================================
# Case 4: a `required` Arch/GDM-style stack must never be granted.
#
# Discriminates 0868f81: on the pre-fix tree the module returned PAM_IGNORE,
# which Linux-PAM does not record, so `optional pam_permit` granted the stack
# (PAM_RESULT=0).
# ===========================================================================
gdm_stack() {
    cat <<EOF
auth    required        ${PAM_MODULE_PATH}
auth    optional        pam_permit.so
auth    required        pam_env.so
EOF
}

case_4() {
    # 4a: display-manager bypass path. The service name only has to carry the
    # `gdm-` prefix for the bypass to match, so a synthetic service is used:
    # overwriting a real desktop's /etc/pam.d/gdm-password would break the
    # developer's own login if the run were killed before cleanup.
    # (Command substitution, not a pipeline: write_service must run in this
    # shell so it can register the file for cleanup.)
    write_service "$SERVICE_DM" <<EOF
$(gdm_stack)
EOF
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_DM" root authenticate
    assert_eq "4a ${SERVICE_DM} PAM result" "9" "${RUN_RESULT:-<none>}"

    # 4b: identical stack under a non-DM service with a silent daemon, i.e. the
    # sequential wait path instead of the bypass.
    write_service "$SERVICE_ARCH_GDM" <<EOF
$(gdm_stack)
EOF
    start_stub || return
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_ARCH_GDM" root authenticate
    assert_eq "4b ${SERVICE_ARCH_GDM} PAM result" "9" "${RUN_RESULT:-<none>}"
}

# ===========================================================================
# Case 5: on a `sufficient` line the skip verdict expands to default=ignore.
#
# This case does NOT discriminate the fix: it produces the same two results on
# the pre-fix (PAM_IGNORE) tree, because PAM_IGNORE and PAM_AUTHINFO_UNAVAIL both
# expand to `ignore` via `default=ignore` and the next module decides either
# way. It is a guard against a PAM_SUCCESS regression only (a module that
# granted the `sufficient` line would skip pam_deny in the second stack).
# ===========================================================================
case_5() {
    write_service "$SERVICE_SUFFICIENT_PERMIT" <<EOF
auth    sufficient      ${PAM_MODULE_PATH}
auth    required        pam_permit.so
EOF
    write_service "$SERVICE_SUFFICIENT_DENY" <<EOF
auth    sufficient      ${PAM_MODULE_PATH}
auth    required        pam_deny.so
EOF
    start_stub || return
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_SUFFICIENT_PERMIT" root authenticate
    assert_eq "sufficient+pam_permit result" "0" "$RUN_RESULT"
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_SUFFICIENT_DENY" root authenticate
    assert_ok "sufficient+pam_deny result" \
        "$([ -n "$RUN_RESULT" ] && [ "$RUN_RESULT" != "0" ] && echo 0 || echo 1)" \
        "expected non-zero (pam_deny must decide), got '${RUN_RESULT:-<none>}'"
}

# ===========================================================================
# Case 6: a second invocation in the same transaction also gets a real code.
# (Main has no dedupe branch; this pins that the second call is not PAM_IGNORE.)
# ===========================================================================
case_6() {
    write_service "$SERVICE_DOUBLE" <<EOF
auth    required        ${PAM_MODULE_PATH}
auth    required        ${PAM_MODULE_PATH}
EOF
    start_stub || return
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_DOUBLE" root authenticate
    assert_eq "PAM result" "9" "$RUN_RESULT"
    assert_ok "wall time" \
        "$([ "${RUN_MS:-0}" -gt 3000 ] && echo 0 || echo 1)" \
        "expected two sequential ${GUI_TIMEOUT_SECS}s waits (>3000 ms), took ${RUN_MS:-?} ms"
}

# ===========================================================================
# Case 7: the fast path (no daemon) does not announce the wait.
#
# Only PAM_TEXT_INFO is forbidden here: the fast path does emit a
# PAM_ERROR_MSG ("Cannot connect to daemon, trying password..."), which is a
# verdict message, not a "waiting for your phone" announcement.
# ===========================================================================
case_7() {
    write_service "$SERVICE_SEQUENTIAL" <<EOF
auth    required        ${PAM_MODULE_PATH}
EOF
    stop_stub   # socket absent: connect() fails immediately
    rm -f "$CONV_LOG"
    run_pamtester "$PAMTESTER_BIN" "$SERVICE_SEQUENTIAL" root authenticate
    assert_eq "PAM result" "9" "$RUN_RESULT"
    assert_ok "wall time" \
        "$([ "${RUN_MS:-9999}" -lt 1500 ] && echo 0 || echo 1)" \
        "the daemon-unreachable path took ${RUN_MS:-?} ms (expected <1500 ms, i.e. no wait)"
    if [ -f "$CONV_LOG" ] && grep -q 'STYLE=TEXT_INFO' "$CONV_LOG"; then
        add_error "the fast path announced a wait: $(grep 'STYLE=TEXT_INFO' "$CONV_LOG" | head -n 1)"
    fi
}

run_case() {
    local n="$1"
    case_selected "$n" || return 0
    begin_case "${CASE_NAMES[$((n - 1))]}" "$n"
    "case_${n}"
    stop_stub
    end_case
}

run_case 1
run_case 2
run_case 3
run_case 4
run_case 5
run_case 6
run_case 7

echo ""
printf 'Summary: %d passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
if [ "$RAN" -eq 0 ]; then
    echo "ERROR: no cases were selected" >&2
    exit 2
fi
[ "$FAILED" -eq 0 ] || exit 1
exit 0
