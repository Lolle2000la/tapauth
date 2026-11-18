#!/bin/bash
# Master End-to-End (E2E) Test Suite for TapAuth (Pairing + UDP + BLE)
# Runs the real production Android app against the real Linux daemon.
#
# Daemon modes (select via TAPAUTH_E2E_DAEMON_MODE=systemd|dev|auto):
#
#   systemd (default when running as root under systemd, e.g. CI):
#     Installs the real systemd/tapauthd.socket + tapauthd.service units and the
#     production PolKit policy. The daemon runs as the unprivileged `tapauthd`
#     user, is socket-activated on the real /run/tapauthd/tapauthd.sock, keeps
#     state in /var/lib/tapauth and writes /etc/tapauth/config.toml. The PAM
#     module and CLI are built WITHOUT dev socket overrides and talk through
#     the production socket. File/socket permission properties are asserted.
#
#   dev (fallback for unprivileged local development):
#     Builds the feature-gated daemon (fallback-socket) and redirects state via
#     TAPAUTH_STATE_DIR / TAPAUTHD_SOCK into a temporary sandbox directory.
#
# NOTE on the systemd-mode build: it enables ONLY `dev-udp-loopback` (the
# emulator UDP delivery shim, TAPAUTH_DEV_UDP_TARGET) and `dev-polkit-bypass`
# (so headless runners need no authentication agent). A hosted CI runner has no
# LAN multicast path into the Android emulator, hence the shim. `dev-state-override`
# stays OFF in this mode, so no TAPAUTH_STATE_DIR/TAPAUTHD_SOCK redirection is
# compiled in at all: every state and config path is the real production path.
# PolKit is still evaluated for every non-root caller (Phase 7 asserts this).

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║      TapAuth Full Real-Android End-to-End Test Suite          ║"
echo "║      (v2 UDP/BLE Pairing + UDP Network + BLE GATT Auth)       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# ── Phase registry ────────────────────────────────────────────────────────────
#
# The summary at the end of this suite is GENERATED from what each phase records
# here while it runs; there is no second, hand-written copy of the phase list to
# fall out of date. A phase that is added to the suite but not given a record
# shows up as NOT RUN, and a phase that skipped shows SKIPPED with the reason it
# skipped — neither can claim PASSED merely because the script reached the
# summary.
#
# PHASE_ORDER    the ids the matrix prints, in PRINT order. That is deliberately
#                not the run order: 7 and 6b run last but print at positions
#                10-11, which reproduces the matrix this suite has always
#                printed. It must name exactly the ids in PHASE_NAME, once each
#                (checked at startup by registry_selfcheck).
# PHASE_NAME     id -> phase label. These strings are part of the log surface CI
#                and the per-distro E2E wrappers key off; do not renumber or
#                reword them.
# PHASE_OUTCOME  id -> pass | fail | skip, written only by phase_pass/phase_fail/
#                phase_skip.
# PHASE_ASSERTED id -> what that outcome actually asserted, or why it skipped.
#
# An id with no recorded outcome prints NOT RUN. Only a `pass` record can ever
# produce PASSED.
#
# The two lists are kept in step by registry_selfcheck, which runs on every
# invocation: an id that is in PHASE_NAME but not PHASE_ORDER would otherwise
# record into a key the matrix never prints (no row, no counter, exit 0), and an
# id in PHASE_ORDER with no label would print a nameless row.
PHASE_ORDER=(
    "1a" "1b" "1c" "2" "2-mcast" "2b" "2e" "2c" "2d" "7" "6b" "3" "4" "5" "5b" "6"
)
declare -A PHASE_NAME=(
    ["1a"]="Phase 1a: Pairing negatives (SAS + pk pin)"
    ["1b"]="Phase 1b: v2 UDP pairing (QEMU SLIRP)"
    ["1c"]="Phase 1c: v2 BLE-only pairing (vhci)"
    ["2"]="Phase 2: Local Network (UDP) Authentication"
    ["2-mcast"]="Phase 2: Custom multicast groups (v4 + v6)"
    ["2b"]="Phase 2b: Real PAM Module (pamtester)"
    ["2e"]="Phase 2e: Mixed-stack PAM (grant path)"
    ["2c"]="Phase 2c: Adversarial Replay + PamCancel"
    ["2d"]="Phase 2d: Adversarial Tampered Ciphertext"
    ["7"]="Phase 7: Admin IPC Authorization (PolKit)"
    ["6b"]="Phase 6b: Mixed-stack PAM password fallback"
    ["3"]="Phase 3: Bluetooth Low Energy (BLE)"
    ["4"]="Phase 4: Parallel Race (UDP + BLE)"
    ["5"]="Phase 5: Explicit Denial & Rejection"
    ["5b"]="Phase 5b: Authentication Timeout"
    ["6"]="Phase 6: Device Removal & Ignore Outcome"
)
declare -A PHASE_OUTCOME=()
declare -A PHASE_ASSERTED=()

# The number of phases the matrix publishes. Adding or removing a phase is a
# deliberate change to a log surface other CI logs are read against, so it is
# also a deliberate change here; registry_selfcheck fails until it is.
EXPECTED_PHASE_COUNT=16

# Summary counters, filled in by print_phase_summary.
SUMMARY_PASSED=0
SUMMARY_SKIPPED=0
SUMMARY_FAILED=0
SUMMARY_NOT_RUN=0

# phase_id_registered <id>: 0 when <id> is one of the published phases.
phase_id_registered() {
    local want=$1 known
    for known in "${PHASE_ORDER[@]}"; do
        if [ "$known" = "$want" ]; then
            return 0
        fi
    done
    return 1
}

# phase_record <id> <pass|fail|skip> <what it asserted / why it skipped>
#
# Pure bookkeeping: it returns 0 unconditionally, so it can never defuse `set -e`
# and can never turn a phase's own failure into a pass. A phase still signals
# failure the way it always has — by exiting non-zero itself — and this only
# remembers what happened on the way there.
#
# An id that is not published by BOTH lists is a bug in this file, not in a
# phase: recording it would be stored in a key the matrix never prints, so it
# aborts rather than pass silently.
phase_record() {
    local id=$1 outcome=$2 note=${3:-}
    if ! phase_id_registered "$id" || [ -z "${PHASE_NAME[$id]:-}" ]; then
        echo "❌ ERROR (phase registry): '${id}' is not a published phase (it is missing from PHASE_ORDER or PHASE_NAME)." >&2
        exit 1
    fi
    case "$outcome" in
        pass|fail|skip) ;;
        *)
            echo "❌ ERROR (phase registry): invalid outcome '${outcome}' for phase '${id}'." >&2
            exit 1
            ;;
    esac
    PHASE_OUTCOME["$id"]="$outcome"
    PHASE_ASSERTED["$id"]="$note"
    return 0
}

phase_pass() { phase_record "$1" pass "${2:-assertion not recorded}"; }
phase_fail() { phase_record "$1" fail "${2:-failure reason not recorded}"; }
phase_skip() { phase_record "$1" skip "${2:-reason not recorded}"; }

# outcome_label <pass|fail|skip|anything else>: the word the matrix prints for a
# raw registry outcome. This is the ONE place an outcome becomes a word, so the
# startup self-check and the rendered rows cannot disagree about it.
outcome_label() {
    case "$1" in
        pass) printf 'PASSED' ;;
        skip) printf 'SKIPPED' ;;
        fail) printf 'FAILED' ;;
        *)    printf 'NOT RUN' ;;
    esac
}

# phase_outcome_label <id>: the word printed for a registry id. A recorded pass
# is the only thing that can become PASSED.
phase_outcome_label() {
    outcome_label "${PHASE_OUTCOME[$1]:-}"
}

# count_phase_outcomes: fill the SUMMARY_* counters from the registry. Called by
# print_phase_summary so the counts and the rows can never disagree.
count_phase_outcomes() {
    local id
    SUMMARY_PASSED=0
    SUMMARY_SKIPPED=0
    SUMMARY_FAILED=0
    SUMMARY_NOT_RUN=0
    for id in "${PHASE_ORDER[@]}"; do
        case "$(phase_outcome_label "$id")" in
            PASSED)  SUMMARY_PASSED=$((SUMMARY_PASSED + 1)) ;;
            SKIPPED) SUMMARY_SKIPPED=$((SUMMARY_SKIPPED + 1)) ;;
            FAILED)  SUMMARY_FAILED=$((SUMMARY_FAILED + 1)) ;;
            *)       SUMMARY_NOT_RUN=$((SUMMARY_NOT_RUN + 1)) ;;
        esac
    done
    return 0
}

# phase_summary_verdict: 0 when the matrix may be accepted (every phase passed
# or skipped with a recorded reason), 1 when any phase failed or never reported.
# This is the gate the suite's own exit status rests on.
phase_summary_verdict() {
    if [ "$SUMMARY_FAILED" -ne 0 ] || [ "$SUMMARY_NOT_RUN" -ne 0 ]; then
        return 1
    fi
    return 0
}

# registry_selfcheck: run on EVERY invocation, before any phase or device
# interaction, so the registry's own coherence is checked by real runs instead of
# only by the env-gated stub below (which is manual-only). Cheap and device-free:
# it reads the two lists and the outcome mapping, never the host.
#
# It exists because the two lists are hand-kept. An id added to PHASE_NAME with a
# record call but missing from PHASE_ORDER would record into a key nothing
# renders — no row, no counter change, exit 0 — which is exactly the silent gap
# the registry is meant to remove.
registry_selfcheck() {
    local id problems=""
    # 1. Both lists must hold the published number of ids...
    if [ "${#PHASE_ORDER[@]}" -ne "$EXPECTED_PHASE_COUNT" ] \
        || [ "${#PHASE_NAME[@]}" -ne "$EXPECTED_PHASE_COUNT" ]; then
        problems="${problems}expected ${EXPECTED_PHASE_COUNT} phases but PHASE_ORDER has ${#PHASE_ORDER[@]} and PHASE_NAME has ${#PHASE_NAME[@]}; "
    fi
    # ...the same ones, each once, each labelled.
    for id in "${PHASE_ORDER[@]}"; do
        if [ -z "${PHASE_NAME[$id]:-}" ]; then
            problems="${problems}'${id}' is in PHASE_ORDER but has no PHASE_NAME; "
        fi
        if [ "$(printf '%s\n' "${PHASE_ORDER[@]}" | grep -c -x -F -- "$id")" -ne 1 ]; then
            problems="${problems}'${id}' appears more than once in PHASE_ORDER; "
        fi
    done
    for id in "${!PHASE_NAME[@]}"; do
        if ! phase_id_registered "$id"; then
            problems="${problems}'${id}' is in PHASE_NAME but not in PHASE_ORDER, so nothing would print it; "
        fi
    done
    # 2. The outcome -> word mapping, probed through the very function the matrix
    #    renders with (outcome_label), so it cannot drift from the rows.
    if [ "$(outcome_label pass)" != "PASSED" ] \
        || [ "$(outcome_label skip)" != "SKIPPED" ] \
        || [ "$(outcome_label fail)" != "FAILED" ] \
        || [ "$(outcome_label "")" != "NOT RUN" ]; then
        problems="${problems}the pass/skip/fail/unset -> PASSED/SKIPPED/FAILED/NOT RUN mapping is broken; "
    fi
    for id in skip fail ""; do
        if [ "$(outcome_label "$id")" = "PASSED" ]; then
            problems="${problems}outcome '${id}' maps to PASSED, and only a recorded pass may; "
        fi
    done
    if [ -n "$problems" ]; then
        echo "❌ ERROR (phase registry): ${problems%; }" >&2
        echo "   PHASE_ORDER and PHASE_NAME must name the same ${EXPECTED_PHASE_COUNT} phases, once each;" >&2
        echo "   the matrix at the end of this suite is generated from them." >&2
        exit 1
    fi
    echo "✅ Phase registry self-check: ${EXPECTED_PHASE_COUNT} phases, ids and outcome labels consistent."
    return 0
}

registry_selfcheck

# print_phase_summary: render the matrix and the assertion notes from the
# registry. Sets the SUMMARY_* counters and returns 0 either way; the end of the
# suite decides what a non-clean matrix means for the exit status.
print_phase_summary() {
    local id label note
    count_phase_outcomes
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  E2E TEST MATRIX SUMMARY                                      ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    for id in "${PHASE_ORDER[@]}"; do
        label="${PHASE_NAME[$id]}"
        printf '║  %-46s %-9s     ║\n' "${label}:" "$(phase_outcome_label "$id")"
    done
    if [ "${E2E_DAEMON_MODE:-}" = "systemd" ]; then
        # The ✔ marks the mode this run used, as the pre-registry matrix did. It
        # is appended after the padded column because printf pads %s by BYTES and
        # the glyph is 3 of them; the fixed 12-space tail keeps the row at the
        # box's 63 content columns (2 + 48 + 1 + 12) and at the same column
        # offsets the old hand-written row used.
        printf '║  %-48s✔%12s║\n' "Daemon mode: systemd socket activation (prod)   " ""
    else
        # Same row shape as the systemd branch above: the glyph is appended after
        # the padded column (printf pads %s by bytes, the glyph is 3 of them) and
        # the fixed 12-space tail holds the row at 63 content columns, matching
        # the offsets the old hand-written matrix used.
        printf '║  %-48s✔%12s║\n' "Daemon mode: dev sandbox (fallback-socket)      " ""
    fi
    echo "╠═══════════════════════════════════════════════════════════════╣"
    printf '║  %-61s║\n' \
        "${SUMMARY_PASSED} passed, ${SUMMARY_SKIPPED} skipped, ${SUMMARY_FAILED} failed, ${SUMMARY_NOT_RUN} not run (of ${#PHASE_ORDER[@]} phases)"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Recorded assertions (what each recorded outcome actually checked):"
    for id in "${PHASE_ORDER[@]}"; do
        label="${PHASE_NAME[$id]}"
        note="${PHASE_ASSERTED[$id]:-the phase never recorded an outcome}"
        printf '  %s\n    %s: %s\n' "$label" "$(phase_outcome_label "$id")" "$note"
    done
    return 0
}

# finish_suite: print the generated summary and turn it into the suite's exit
# status. Exits 1 when any phase failed or never reported, so a phase that never
# recorded an outcome cannot ride the 🎉 line into a green run.
finish_suite() {
    echo ""
    print_phase_summary
    echo ""
    if ! phase_summary_verdict; then
        echo "❌ E2E SUITE INCOMPLETE: ${SUMMARY_FAILED} phase(s) FAILED and ${SUMMARY_NOT_RUN} phase(s) never reported an outcome."
        echo "   A phase with no recorded outcome is a registry/phase mismatch in this script, not a pass."
        exit 1
    fi
    if [ "$SUMMARY_SKIPPED" -ne 0 ]; then
        echo "✅ Every phase that ran PASSED; ${SUMMARY_SKIPPED} phase(s) SKIPPED (reasons in the matrix above)."
    else
        echo "🎉 ALL MANDATORY END-TO-END TESTS PASSED SUCCESSFULLY!"
    fi
}

# ── Registry self-test (dry run; needs no device, daemon or emulator) ────────
#
# Only entered when TAPAUTH_E2E_SELFTEST is set; the normal path ignores it
# entirely. It exists so the two things this registry can get wrong are provable
# without running a phase:
#
#   TAPAUTH_E2E_SELFTEST=summary
#     Register a hand-made pass / skip / fail mix plus one phase deliberately
#     left unrecorded, print the summary, and assert what it rendered. Exits 0
#     only when every assertion below holds.
#
#   TAPAUTH_E2E_SELFTEST=fail-after-record
#     Run a stub phase body that records a `pass` and then fails. The script must
#     abort with the failing command's status: recording an outcome must not
#     swallow a failure through a helper's return value.
#
# Placed before cleanup() is trapped and before any environment is touched, so a
# dry run cannot alter the host.
case "${TAPAUTH_E2E_SELFTEST:-}" in
    "")
        ;;
    summary)
        phase_pass "1a" "stub: recorded pass for the dry run"
        phase_skip "2c" "stub: no captured grant packet available (not running as root)"
        phase_fail "2d" "stub: the tampered packet was accepted"
        # "4" is deliberately left without an outcome.
        SELFTEST_OUT="$(print_phase_summary)"
        printf '%s\n' "$SELFTEST_OUT"
        # The render above ran in a subshell; recompute the counters in this
        # shell from the same registry the rows came from.
        count_phase_outcomes

        selftest_fail() {
            echo "❌ REGISTRY SELF-TEST FAILED: $1"
            exit 1
        }

        # 1. A skip prints SKIPPED with its reason and never PASSED.
        printf '%s\n' "$SELFTEST_OUT" \
            | grep -Eq '^║  Phase 2c: Adversarial Replay \+ PamCancel: +SKIPPED +║$' \
            || selftest_fail "the skipped phase did not render SKIPPED"
        if printf '%s\n' "$SELFTEST_OUT" | grep -Eq '^║  Phase 2c: .*PASSED'; then
            selftest_fail "the skipped phase also rendered PASSED"
        fi
        printf '%s\n' "$SELFTEST_OUT" \
            | grep -qF 'SKIPPED: stub: no captured grant packet available (not running as root)' \
            || selftest_fail "the skip reason is missing from the recorded assertions"
        # 2. A fail prints FAILED and never PASSED.
        printf '%s\n' "$SELFTEST_OUT" \
            | grep -Eq '^║  Phase 2d: Adversarial Tampered Ciphertext: +FAILED +║$' \
            || selftest_fail "the failed phase did not render FAILED"
        if printf '%s\n' "$SELFTEST_OUT" | grep -Eq '^║  Phase 2d: .*PASSED'; then
            selftest_fail "the failed phase also rendered PASSED"
        fi
        # 3. A phase with no recorded outcome prints NOT RUN and never PASSED.
        printf '%s\n' "$SELFTEST_OUT" \
            | grep -Eq '^║  Phase 4: Parallel Race \(UDP \+ BLE\): +NOT RUN +║$' \
            || selftest_fail "the unrecorded phase did not render NOT RUN"
        if printf '%s\n' "$SELFTEST_OUT" | grep -Eq '^║  Phase 4: .*PASSED'; then
            selftest_fail "the unrecorded phase also rendered PASSED"
        fi
        # 4. A recorded pass still renders PASSED (the matrix can say yes).
        printf '%s\n' "$SELFTEST_OUT" \
            | grep -Eq '^║  Phase 1a: Pairing negatives \(SAS \+ pk pin\): +PASSED +║$' \
            || selftest_fail "a recorded pass did not render PASSED"
        # 5. Exactly one row per registered phase.
        SELFTEST_ROWS="$(printf '%s\n' "$SELFTEST_OUT" | grep -c '^║  Phase ' || true)"
        [ "$SELFTEST_ROWS" = "16" ] \
            || selftest_fail "expected 16 phase rows, got ${SELFTEST_ROWS}"
        # 6. The counters agree with the rows.
        if [ "$SUMMARY_PASSED" != "1" ] || [ "$SUMMARY_SKIPPED" != "1" ] \
            || [ "$SUMMARY_FAILED" != "1" ] || [ "$SUMMARY_NOT_RUN" != "13" ]; then
            selftest_fail "counters are passed=$SUMMARY_PASSED skipped=$SUMMARY_SKIPPED failed=$SUMMARY_FAILED not_run=$SUMMARY_NOT_RUN"
        fi
        # 7. The gate the suite's exit status rests on rejects a matrix that
        # holds a FAILED or an unreported phase — and the whole summary tail says
        # so instead of claiming a pass.
        if phase_summary_verdict; then
            selftest_fail "the suite verdict accepted a FAILED phase and 13 unreported ones"
        fi
        set +e
        SELFTEST_TAIL="$(finish_suite 2>&1)"
        SELFTEST_RC=$?
        set -e
        [ "$SELFTEST_RC" = "1" ] \
            || selftest_fail "the suite tail exited ${SELFTEST_RC} with a FAILED phase, expected 1"
        printf '%s\n' "$SELFTEST_TAIL" \
            | grep -qF "E2E SUITE INCOMPLETE: 1 phase(s) FAILED and 13 phase(s) never reported an outcome" \
            || selftest_fail "the suite tail did not report the incomplete matrix"
        # 8. ...and accepts one where every phase passed or skipped explicitly.
        PHASE_OUTCOME=()
        PHASE_ASSERTED=()
        for selftest_id in "${PHASE_ORDER[@]}"; do
            if [ "$selftest_id" = "2c" ]; then
                phase_skip "2c" "stub: explicit skip"
            else
                phase_pass "$selftest_id" "stub: pass"
            fi
        done
        count_phase_outcomes
        if ! phase_summary_verdict; then
            selftest_fail "the suite verdict rejected 15 passes and 1 explicit skip"
        fi
        set +e
        SELFTEST_TAIL="$(finish_suite 2>&1)"
        SELFTEST_RC=$?
        set -e
        [ "$SELFTEST_RC" = "0" ] \
            || selftest_fail "the suite tail exited ${SELFTEST_RC} for 15 passes and 1 explicit skip, expected 0"
        printf '%s\n' "$SELFTEST_TAIL" \
            | grep -qF "Every phase that ran PASSED; 1 phase(s) SKIPPED (reasons in the matrix above)." \
            || selftest_fail "the suite tail did not report the explicit skip"
        echo "✅ REGISTRY SELF-TEST PASSED: 1 PASSED, 1 SKIPPED (with reason), 1 FAILED, 13 NOT RUN."
        exit 0
        ;;
    fail-after-record)
        selftest_phase_body() {
            phase_pass "1b" "stub: recorded before the failure"
            # Stands in for any assertion in a phase body that fails after the
            # outcome was recorded.
            false
        }
        selftest_phase_body
        echo "❌ REGISTRY SELF-TEST FAILED: a phase body that failed did not abort the script."
        exit 99
        ;;
    *)
        echo "❌ ERROR: unknown TAPAUTH_E2E_SELFTEST value '$TAPAUTH_E2E_SELFTEST' (expected summary|fail-after-record)" >&2
        exit 2
        ;;
esac

PYTHON_BIN="${PYTHON_BIN:-python3}"

# IPv6 host changes this run may make, reverted in cleanup() below so a root run
# on a developer machine does not leave networking modified.
IPV6_SYSCTL_RESTORE=()
IPV6_ADDRS_ADDED=()

# ── Ports ─────────────────────────────────────────────────────────────────────
# UDP_PORT      the daemon's port (written to the config file, used for packet
#               capture and for injecting adversarial packets).
# DEV_HOST_PORT host-side port of the emulator UDP redirection
#               (adb emu redir add udp:$DEV_HOST_PORT:$UDP_PORT); the daemon
#               unicasts to it when the dev-udp-loopback feature is compiled in.
UDP_PORT="${TAPAUTH_E2E_UDP_PORT:-36692}"
DEV_HOST_PORT="${TAPAUTH_E2E_DEV_HOST_PORT:-36695}"
# Exported so the bridge helpers stay in sync with this suite's port choices.
export TAPAUTH_E2E_UDP_PORT="$UDP_PORT"
export TAPAUTH_E2E_DEV_HOST_PORT="$DEV_HOST_PORT"

# Discovery multicast groups. MUST stay in sync with shared/src/network.rs
# (IPV4_MULTICAST_ADDR / IPV6_MULTICAST_ADDR) and the Android
# AuthenticationService: Phase 2 asserts tapauthd really emits packets to both.
IPV4_MCAST="239.255.26.44"
IPV6_MCAST="ff12::fdec:fc27"

# Ensure adb is in PATH
if ! command -v adb &> /dev/null; then
    for p in "/usr/local/lib/android/sdk/platform-tools" "$ANDROID_HOME/platform-tools" "$ANDROID_SDK_ROOT/platform-tools" "$HOME/Android/Sdk/platform-tools"; do
        if [ -x "$p/adb" ]; then
            export PATH="$PATH:$p"
            break
        fi
    done
fi

# Check for running Android emulator
if ! adb devices | grep -q 'emulator-[0-9]*'; then
    echo "❌ ERROR: No active Android emulator detected."
    echo "   Please start an emulator (e.g. via Android Studio or 'emulator @<avd_name>') before running this test."
    exit 1
fi

echo "✅ Android emulator detected."

# ── Daemon mode detection ─────────────────────────────────────────────────────
E2E_DAEMON_MODE="${TAPAUTH_E2E_DAEMON_MODE:-auto}"
if [ "$E2E_DAEMON_MODE" = "auto" ]; then
    if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && [ "$(ps -p 1 -o comm=)" = "systemd" ] && [ -d /run/systemd/system ]; then
        E2E_DAEMON_MODE="systemd"
    else
        E2E_DAEMON_MODE="dev"
    fi
fi
if [ "$E2E_DAEMON_MODE" != "systemd" ] && [ "$E2E_DAEMON_MODE" != "dev" ]; then
    echo "❌ ERROR: invalid TAPAUTH_E2E_DAEMON_MODE '$E2E_DAEMON_MODE' (expected systemd|dev|auto)"
    exit 1
fi

# Sandbox directory for logs, captures and (dev mode) state redirection
TEST_DIR=$(mktemp -d -t tapauth-e2e.XXXXXX)
DAEMON_LOG="${TEST_DIR}/tapauthd.log"

# Per-target trace directives added to the daemon's log filter for the E2E run.
#
# Three facts the suite asserts are logged below the level the daemon runs at
# (INFO in journald, `debug` on stdout), and each is the *only* daemon-side
# evidence of the thing asserted — none of them may be inferred from timing:
#   * `BLE advertising started (attempt N)` (tapauthd/src/transport/ble.rs:671)
#     — the advertisement for the session was registered with BlueZ. Phase 4
#     asserts it while UDP is also live, so a daemon that quietly serves the
#     race over UDP alone cannot pass.
#   * `Sent IPv4 multicast on <N> interface(s)` (shared/src/network/udp.rs:461)
#     — the UDP egress for the request. Phase 4 asserts it so "both transports
#     participated" does not rest on the winner's name, and Phase 2d's sibling
#     assertions need no addition (its transport attribution is an INFO line).
#   * `Dropped a datagram from <addr> (<N> bytes): <reason>; still waiting for a
#     response` (shared/src/network/udp.rs:78) — the per-frame decode drop.
#     Phase 2d asserts it for its non-protobuf injection: the aggregate `warn`
#     beside it is rate limited to one per 60 s, so only the per-frame line is
#     deterministic.
# The directives are per target, so every other module keeps the level it had
# and no other phase's log volume or assertions change.
E2E_TRACE_TARGETS="tapauthd::transport::ble=trace,shared::network::udp=trace"

PAM_SERVICE_NAME="tapauth-test-e2e"
PAM_MIXED_SERVICE_NAME="tapauth-mixed-stack"
PAM_CONFIG_PATH="/etc/pam.d/${PAM_SERVICE_NAME}"
PAM_MIXED_CONFIG_PATH="/etc/pam.d/${PAM_MIXED_SERVICE_NAME}"
PAM_FALLBACK_USER="tapauth-e2e-pam"
PAM_FALLBACK_PASS="TapAuth-E2E-Fallback-$(date +%s)!"
ADMIN_DENY_USER="tapauth-e2e-deny"
USE_INSTALLED_PACKAGE="${TAPAUTH_E2E_USE_INSTALLED_PACKAGE:-0}"

if [ "$E2E_DAEMON_MODE" = "dev" ] && [ "$USE_INSTALLED_PACKAGE" = "1" ]; then
    # The packaged daemon is built WITHOUT fallback-socket, so it cannot bind
    # the socket itself: without systemd socket activation it exits with
    # "Systemd socket activation required". The old dev+installed path launched
    # it manually and always died at Step 4, so reject the combination up front.
    echo "❌ ERROR: TAPAUTH_E2E_USE_INSTALLED_PACKAGE=1 requires systemd daemon mode."
    echo "   The packaged tapauthd has no fallback-socket feature, so it cannot bind"
    echo "   the socket without systemd socket activation (FD #3)."
    echo "   Set TAPAUTH_E2E_DAEMON_MODE=systemd, or drop TAPAUTH_E2E_USE_INSTALLED_PACKAGE."
    exit 1
fi

if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    # Dev-mode sandbox: feature-gated daemon + env redirection.
    export TAPAUTHD_SOCK="${TEST_DIR}/tapauthd.sock"
    export TAPAUTH_STATE_DIR="${TEST_DIR}/state"
    export TAPAUTH_DEV_MODE=1
    mkdir -p "$TAPAUTH_STATE_DIR"
    chmod 700 "$TAPAUTH_STATE_DIR"
    CONFIG_ASSERT_FILE="${TAPAUTH_STATE_DIR}/config.toml"
    chown -R tapauthd:tapauthd "$TEST_DIR" 2>/dev/null || true
else
    CONFIG_ASSERT_FILE="/etc/tapauth/config.toml"
fi

# Detect test username (matches caller UID for daemon IPC authorization)
TEST_USER="$(whoami)"

echo "ℹ️  Daemon mode:    $E2E_DAEMON_MODE"
echo "ℹ️  Test User:      $TEST_USER"
echo "ℹ️  UDP port:       $UDP_PORT (emulator shim: 127.0.0.1:$DEV_HOST_PORT)"
if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    # dev + installed-package mode is rejected above, so TAPAUTH_STATE_DIR is
    # always set here (a sandbox path).
    echo "ℹ️  Isolated Socket: $TAPAUTHD_SOCK"
    echo "ℹ️  State Directory: $TAPAUTH_STATE_DIR"
fi
echo "ℹ️  Sandbox Dir:    $TEST_DIR"
echo ""

# ── IPv6 availability for multicast verification ──────────────────────────────
# GitHub-hosted runners disable IPv6 by default, which makes tapauthd skip the
# IPv6 multicast branch entirely (is_ipv6_available() -> false). Enable IPv6 so
# Phase 2 can verify that both discovery groups actually egress.
if [ "$(id -u)" -eq 0 ]; then
    if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)" = "1" ] \
        || ! ip -6 addr show 2>/dev/null | grep -q 'inet6 fe80'; then
        echo "ℹ️  Enabling IPv6 for multicast verification..."
        # Record the current values so cleanup() can restore them.
        for _scope in all default; do
            _orig="$(cat "/proc/sys/net/ipv6/conf/${_scope}/disable_ipv6" 2>/dev/null || true)"
            [ -n "$_orig" ] && IPV6_SYSCTL_RESTORE+=("${_scope}=${_orig}")
        done
        for _if in /sys/class/net/*; do
            _name="$(basename "$_if")"
            _orig="$(cat "/proc/sys/net/ipv6/conf/${_name}/disable_ipv6" 2>/dev/null || true)"
            [ -n "$_orig" ] && IPV6_SYSCTL_RESTORE+=("${_name}=${_orig}")
        done
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
        for _if in /sys/class/net/*; do
            sysctl -w "net.ipv6.conf.$(basename "$_if").disable_ipv6=0" >/dev/null 2>&1 || true
        done
        # Some images also disable automatic link-local generation. Ensure the
        # default-route interface owns an IPv6 address so tapauthd has somewhere
        # to send the IPv6 group (DAD is skipped to avoid a tentative window).
        # Only touch that one interface to keep the host change minimal; if the
        # host has no default route, fall back to every interface.
        _primary_if="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
        for _if in /sys/class/net/*; do
            _name="$(basename "$_if")"
            [ "$_name" = "lo" ] && continue
            if [ -n "$_primary_if" ] && [ "$_name" != "$_primary_if" ]; then
                continue
            fi
            if ! ip -6 addr show dev "$_name" 2>/dev/null | grep -q 'inet6'; then
                if ip -6 addr add "fe80::a17:1/64" dev "$_name" nodad 2>/dev/null; then
                    IPV6_ADDRS_ADDED+=("$_name")
                fi
            fi
        done
        sleep 1
    fi
    if ip -6 addr show 2>/dev/null | grep -q 'inet6 fe80'; then
        echo "✅ IPv6 link-local address present for multicast verification."
    else
        echo "⚠️  No IPv6 link-local address after enable attempt; IPv6 multicast will not be observable."
    fi
fi

# Background processes this suite owns directly; the BLE/biometric helpers track
# their own PIDs in /tmp and are torn down through their own subcommands.
DAEMON_PID=""
JOURNAL_PID=""
CAPTURE_PID=""
GROUPS_PID=""

# systemd-mode teardown bookkeeping: only undo what this run actually installed.
# (Set for real in the systemd setup block below; defaults keep cleanup() safe if
# the suite aborts earlier.)
E2E_OWNED_STATE=false
CREATED_CONFIG=false
UNITS_PREEXISTED=false
BINARY_PREEXISTED=false
# Set when this run stages the test-only tapauth-ipc-cli at /usr/local/bin so the
# unprivileged Phase 7 cases (runuser -u ...) can execute it.
INSTALLED_TEST_CLI=false
CLI_BIN_PREEXISTED=false
# Original /etc/shadow mode, restored in cleanup() if this run relaxes it for
# passwd(1) (Debian/Ubuntu conventionally ship 0640 root:shadow).
SHADOW_MODE_PRE=""

# Env prefix for pamtester invocations: dev mode points the PAM module (and the
# CLI, whose TAPAUTHD_SOCK override is compiled in via fallback-socket ->
# dev-socket-override) at the sandbox socket; systemd mode must NOT set the
# variable so the production socket path is used.
# TAPAUTH_LOG_LEVEL=debug makes the module's tracing visible in the CI log so
# PAM-phase failures are diagnosable.
if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    PAM_ENV=(env "TAPAUTHD_SOCK=${TAPAUTHD_SOCK}" TAPAUTH_LOG_LEVEL=debug)
else
    PAM_ENV=(env -u TAPAUTHD_SOCK TAPAUTH_LOG_LEVEL=debug)
fi

cleanup() {
    EXIT_CODE=$?
    echo ""
    echo "==> Cleaning up test environment (exit code: $EXIT_CODE)..."
    if [ "$EXIT_CODE" -ne 0 ] && [ -n "$DAEMON_LOG" ] && [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/bumble-bridge.log ]; then
        echo "=== BUMBLE LOG DUMP ==="
        cat /tmp/bumble-bridge.log
        echo "======================="
    fi
    if [ "$EXIT_CODE" -ne 0 ] && [ -f /tmp/bluetoothd.log ]; then
        echo "=== BLUETOOTH DAEMON LOG DUMP ==="
        cat /tmp/bluetoothd.log
        echo "=================================="
    fi
    if [ "$EXIT_CODE" -ne 0 ]; then
        echo "=== ANDROID LOGCAT DUMP ==="
        adb logcat -d -v time -s AuthenticationService:* BleGattService:* AuthRequestManager:* TapAuthApplication:* PairingClient:* BiometricPromptActivity:* AuthActionReceiver:* TemporalIdCache:* 2>/dev/null || true
        echo "==========================="
    fi
    if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
        systemctl stop tapauthd.service 2>/dev/null || true
        systemctl stop tapauthd.socket 2>/dev/null || true
        systemctl disable tapauthd.socket 2>/dev/null || true
    fi
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [ -n "$JOURNAL_PID" ]; then
        kill "$JOURNAL_PID" 2>/dev/null || true
        wait "$JOURNAL_PID" 2>/dev/null || true
    fi
    if [ -n "$CAPTURE_PID" ]; then
        kill "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi
    if [ -n "$GROUPS_PID" ]; then
        kill "$GROUPS_PID" 2>/dev/null || true
        wait "$GROUPS_PID" 2>/dev/null || true
    fi
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant 2>/dev/null || true
    if [ "${E2E_KEEP_BLE_BRIDGE:-0}" != "1" ]; then
        if [ -f /tmp/bumble-bridge.pid ]; then
            kill "$(cat /tmp/bumble-bridge.pid)" 2>/dev/null || true
            rm -f /tmp/bumble-bridge.pid
        fi
    fi
    if [ "$INSTALLED_POLKIT" = true ]; then
        sudo rm -f "$POLKIT_POLICY_DEST" 2>/dev/null || true
    fi
    # systemd mode installed a real daemon on this host; put the machine back the
    # way we found it. Without this, `sudo ./scripts/test-e2e.sh` would leave a
    # debug binary plus an E2E drop-in (TAPAUTH_DEV_MODE=1 + UDP shim) enabled on
    # the developer's machine. Files that already existed are never deleted.
    if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
        rm -f /etc/systemd/system/tapauthd.service.d/e2e.conf 2>/dev/null || true
        rmdir /etc/systemd/system/tapauthd.service.d 2>/dev/null || true
        if [ "$UNITS_PREEXISTED" != true ]; then
            rm -f /etc/systemd/system/tapauthd.service /etc/systemd/system/tapauthd.socket 2>/dev/null || true
        fi
        if [ "$BINARY_PREEXISTED" != true ]; then
            rm -f /usr/bin/tapauthd /usr/local/bin/tapauth-ipc-cli 2>/dev/null || true
        fi
        systemctl daemon-reload 2>/dev/null || true
        if [ "$CREATED_CONFIG" = true ]; then
            rm -f "$CONFIG_ASSERT_FILE" 2>/dev/null || true
        fi
        if [ "$E2E_OWNED_STATE" = true ]; then
            find /var/lib/tapauth -mindepth 1 -delete 2>/dev/null || true
        fi
        if [ "$USE_INSTALLED_PACKAGE" != "1" ] && { [ "$UNITS_PREEXISTED" = true ] || [ "$BINARY_PREEXISTED" = true ]; }; then
            echo "⚠️  WARNING: this run replaced pre-existing TapAuth units/binaries with"
            echo "   the E2E debug build and left them in place. Reinstall (e.g."
            echo "   ./install.sh or your distro package) before using TapAuth again."
        fi
    fi
    # Remove the test-only CLI this run staged for the unprivileged cases.
    if [ "$INSTALLED_TEST_CLI" = true ] && [ "$CLI_BIN_PREEXISTED" != true ]; then
        rm -f /usr/local/bin/tapauth-ipc-cli 2>/dev/null || true
    fi
    if [ -w "$PAM_CONFIG_PATH" ]; then
        rm -f "$PAM_CONFIG_PATH" 2>/dev/null || true
    fi
    if [ -w "$PAM_MIXED_CONFIG_PATH" ]; then
        rm -f "$PAM_MIXED_CONFIG_PATH" 2>/dev/null || true
    fi
    if id "$PAM_FALLBACK_USER" >/dev/null 2>&1; then
        passwd -l "$PAM_FALLBACK_USER" >/dev/null 2>&1 || true
        userdel -r "$PAM_FALLBACK_USER" >/dev/null 2>&1 || true
    fi
    if id "$ADMIN_DENY_USER" >/dev/null 2>&1; then
        userdel -r "$ADMIN_DENY_USER" >/dev/null 2>&1 || true
    fi
    # Undo any IPv6 host changes this run made (see the enablement block above),
    # so a root run on a developer machine leaves networking as it found it.
    for _name in "${IPV6_ADDRS_ADDED[@]}"; do
        ip -6 addr del fe80::a17:1/64 dev "$_name" 2>/dev/null || true
    done
    for _entry in "${IPV6_SYSCTL_RESTORE[@]}"; do
        sysctl -w "net.ipv6.conf.${_entry%%=*}.disable_ipv6=${_entry##*=}" >/dev/null 2>&1 || true
    done
    # Restore /etc/shadow's mode if this run loosened it for passwd(1).
    if [ -n "$SHADOW_MODE_PRE" ]; then
        chmod "$SHADOW_MODE_PRE" /etc/shadow 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR" 2>/dev/null || true
    echo "✅ Teardown complete."
}
trap cleanup EXIT INT TERM

# Helper: assert a path's mode/owner/group via stat(1)
assert_stat() {
    local path=$1 expected=$2 label=$3
    local actual
    actual="$(stat -c '%a %U %G' "$path" 2>/dev/null || echo "missing")"
    if [ "$actual" = "$expected" ]; then
        echo "✅ ${label}: $(basename "$path") -> $actual"
    else
        echo "❌ ERROR (${label}): expected '$path' to be '$expected' but got '$actual'"
        exit 1
    fi
}

# Helper: wait for a background process to exit, with a timeout (seconds).
# Returns the process' exit status, or 99 on timeout (after SIGKILL).
wait_pid_with_timeout() {
    local pid=$1 timeout_secs=$2
    for _ in $(seq 1 $((timeout_secs * 10))); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            return $?
        fi
        sleep 0.1
    done
    echo "❌ ERROR: process $pid did not exit within ${timeout_secs}s" >&2
    kill -9 "$pid" 2>/dev/null || true
    return 99
}

# PolKit policy bookkeeping: the policy itself is only ever installed by the
# systemd-mode setup block below (the dev sandbox's dev-polkit-bypass makes an
# installed policy unnecessary, and Phase 7 runs in systemd mode only). These
# defaults keep cleanup() safe if the suite aborts before that block runs.
POLKIT_POLICY_DEST="/usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy"
INSTALLED_POLKIT=false

# Ensure Android app is in a clean state (wiping any previous pairing keys)
if command -v adb >/dev/null 2>&1; then
    adb shell pm clear dev.rourunisen.tapauth.e2e >/dev/null 2>&1 || true
fi

# Step 1: Build necessary Linux binaries or resolve installed packages
if [ "$USE_INSTALLED_PACKAGE" = "1" ]; then
    echo "==> Step 1: Using pre-installed distro packages for E2E tests..."
    TAPAUTHD_BIN="/usr/bin/tapauthd"

    # tapauth-ipc-cli is a testing-only admin harness and is deliberately NOT
    # shipped by the distro packages, so it is resolved from the workspace
    # instead of the installed payload. In installed-package mode the daemon
    # always listens on the production socket path, which the CLI's default
    # (non-dev) build already targets, so no dev feature is required. The CI
    # E2E containers have no Rust toolchain and reuse the binary the host built
    # through the bind-mounted workspace target dir (see run-all-e2e.sh).
    export CARGO_TARGET_DIR="${PROJECT_ROOT}/target"
    CLI_BIN_SRC="${CARGO_TARGET_DIR}/debug/tapauth-ipc-cli"
    if [ ! -x "$CLI_BIN_SRC" ] && command -v cargo >/dev/null 2>&1; then
        cargo build -p tapauthd --bin tapauth-ipc-cli
    fi

    PAM_LIB=""
    for candidate in \
        "/lib/x86_64-linux-gnu/security/pam_tapauth.so" \
        "/usr/lib/security/pam_tapauth.so" \
        "/lib/security/pam_tapauth.so" \
        "/usr/lib64/security/pam_tapauth.so"; do
        if [ -f "$candidate" ]; then
            PAM_LIB="$candidate"
            break
        fi
    done
    if [ -z "$PAM_LIB" ]; then
        # The multiarch security dir differs across distros; fall back to a
        # bounded search before giving up.
        PAM_LIB="$(find /usr/lib /lib -maxdepth 4 -name pam_tapauth.so 2>/dev/null | head -1 || true)"
    fi
    if [ -z "$PAM_LIB" ]; then
        echo "❌ ERROR: installed-package mode could not locate pam_tapauth.so."
        echo "   The PAM phases (2b/2e/6b) would otherwise be skipped silently;"
        echo "   the installed package is broken or ships the module elsewhere."
        exit 1
    fi

    if [ ! -x "$TAPAUTHD_BIN" ]; then
        echo "❌ ERROR: tapauthd binary not found at $TAPAUTHD_BIN"
        exit 1
    fi
    if [ ! -x "$CLI_BIN_SRC" ]; then
        echo "❌ ERROR: tapauth-ipc-cli not found at $CLI_BIN_SRC"
        echo "   It is a testing-only tool and is not shipped by the distro packages."
        echo "   Build it from the workspace with:"
        echo "   cargo build -p tapauthd --bin tapauth-ipc-cli"
        exit 1
    fi
    # Phase 7 runs the CLI as unprivileged users (runuser -u ...), which cannot
    # traverse the workspace target dir, so stage the test-only binary at a
    # world-executable path for the duration of the run. cleanup() removes it
    # again unless it was already there.
    if [ -e /usr/local/bin/tapauth-ipc-cli ]; then
        CLI_BIN_PREEXISTED=true
    fi
    install -Dm0755 "$CLI_BIN_SRC" /usr/local/bin/tapauth-ipc-cli
    CLI_BIN="/usr/local/bin/tapauth-ipc-cli"
    INSTALLED_TEST_CLI=true
    echo "    Found installed tapauthd:       $TAPAUTHD_BIN"
    echo "    Using workspace-built CLI:      $CLI_BIN (from $CLI_BIN_SRC)"
    echo "    Found installed pam_tapauth.so:  $PAM_LIB"

    # Capability probe: detect whether the installed daemon contains dev-mode shims
    if command -v strings >/dev/null 2>&1; then
        if strings "$TAPAUTHD_BIN" | grep -q 'TAPAUTH_DEV_UDP_TARGET' 2>/dev/null; then
            echo "    Daemon Capabilities:            dev shims enabled (UDP loopback, PolKit bypass)"
        else
            echo "    Daemon Capabilities:            production release build (no dev shims, systemd activation required)"
        fi
    else
        echo "    Daemon Capabilities:            unknown (binutils/strings not installed)"
    fi
else
    echo "==> Step 1: Building Linux components (tapauthd, tapauth-ipc-cli, client-pam)..."
    # Pin the cargo target directory so the artifact paths below are deterministic
    # regardless of any user-level CARGO_TARGET_DIR override (~/.cargo/config.toml).
    export CARGO_TARGET_DIR="${PROJECT_ROOT}/target"
    if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
        # Production-style build: systemd socket activation (fallback-socket OFF) and
        # no dev-state-override, so state/config/socket paths are production. Only the
        # emulator UDP shim and the headless PolKit bypass are compiled in, both still
        # requiring TAPAUTH_DEV_MODE at runtime.
        cargo build -p tapauthd --no-default-features --features ble,dev-udp-loopback,dev-polkit-bypass --bin tapauthd --bin tapauth-ipc-cli
        cargo build -p client-pam
    else
        cargo build -p tapauthd --features fallback-socket,ble --bin tapauthd --bin tapauth-ipc-cli
        cargo build -p client-pam --features dev-socket-override
    fi

    TAPAUTHD_BIN="${PROJECT_ROOT}/target/debug/tapauthd"
    CLI_BIN="${PROJECT_ROOT}/target/debug/tapauth-ipc-cli"
    PAM_LIB="${PROJECT_ROOT}/target/debug/libclient_pam.so"
fi

# ── systemd-mode environment setup ────────────────────────────────────────────
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    echo ""
    echo "==> Step 1b: Setting up production systemd environment (units, users, config)..."

    if [ "$USE_INSTALLED_PACKAGE" = "1" ]; then
        echo "    Verifying pre-installed package systemd environment..."
        UNITS_PREEXISTED=true
        BINARY_PREEXISTED=true
        E2E_OWNED_STATE=false
        CREATED_CONFIG=false

        id tapauthd >/dev/null 2>&1 || "$PROJECT_ROOT/create-dev-users.sh"
        # Run the shipped tmpfiles config exactly as the package postinst does:
        # it creates /etc/tapauth (root:root 0755) and config.toml owned by the
        # daemon. Do NOT chown the directory -- production keeps it root-owned,
        # and the E2E must exercise the real SaveConfig permission path.
        systemd-tmpfiles --create "$PROJECT_ROOT/packaging/tmpfiles.conf" 2>/dev/null || true
        if [ ! -f "$CONFIG_ASSERT_FILE" ]; then
            CREATED_CONFIG=true
            cat > "$CONFIG_ASSERT_FILE" <<EOF
# TapAuth Configuration (created by the E2E suite)
pam_operation_timeout_secs = 120
udp_port = ${UDP_PORT}
use_tpm = false
EOF
            chown tapauthd:tapauthd "$CONFIG_ASSERT_FILE" 2>/dev/null || true
            chmod 644 "$CONFIG_ASSERT_FILE" 2>/dev/null || true
        fi
    else
        # This mode installs over a REAL system installation (/usr/bin/tapauthd, the
        # systemd units, /etc/tapauth, /var/lib/tapauth). On CI the runner is
        # disposable; on a developer workstation that is someone's live pairing state,
        # so refuse unless the caller opts in explicitly.
        PREEXISTING=""
        if [ -x /usr/bin/tapauthd ]; then
            PREEXISTING="/usr/bin/tapauthd"
        fi
        if [ -n "$(find /var/lib/tapauth -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then
            PREEXISTING="${PREEXISTING:+$PREEXISTING, }/var/lib/tapauth (non-empty)"
        fi
        if [ -n "$PREEXISTING" ] && [ "${TAPAUTH_E2E_ALLOW_DESTRUCTIVE:-0}" != "1" ]; then
            echo "❌ ERROR: systemd mode would overwrite an existing TapAuth installation: $PREEXISTING"
            echo "   Run as root inside a disposable VM/container, or set"
            echo "   TAPAUTH_E2E_ALLOW_DESTRUCTIVE=1 to accept that pairing state and"
            echo "   binaries under /var/lib/tapauth, /etc/tapauth and /usr/bin are replaced."
            exit 1
        fi
        # We only remove state/config files that we know were absent before this run.
        E2E_OWNED_STATE=false
        if [ ! -d /var/lib/tapauth ] || [ -z "$(find /var/lib/tapauth -maxdepth 1 -type f 2>/dev/null | head -1)" ]; then
            E2E_OWNED_STATE=true
        fi
        CREATED_CONFIG=false
        # Same for the units and binaries: with TAPAUTH_E2E_ALLOW_DESTRUCTIVE=1 on a
        # host that already has TapAuth installed, overwrite them for the duration of
        # the run but never delete the pre-existing files afterwards.
        UNITS_PREEXISTED=false
        if [ -e /etc/systemd/system/tapauthd.service ] || [ -e /etc/systemd/system/tapauthd.socket ]; then
            UNITS_PREEXISTED=true
        fi
        BINARY_PREEXISTED=false
        if [ -e /usr/bin/tapauthd ] || [ -e /usr/local/bin/tapauth-ipc-cli ]; then
            BINARY_PREEXISTED=true
        fi

        # 1. System users/groups exactly as install.sh creates them
        "$PROJECT_ROOT/create-dev-users.sh"

        # 2. Install binaries + units + PolKit policy as the packages would
        install -Dm0755 "$TAPAUTHD_BIN" /usr/bin/tapauthd
        # Track the test-only CLI independently of the daemon binary: if only
        # /usr/bin/tapauthd pre-existed, cleanup() must still remove the CLI
        # this run staged (it never belonged on the host).
        if [ -e /usr/local/bin/tapauth-ipc-cli ]; then
            CLI_BIN_PREEXISTED=true
        fi
        install -Dm0755 "$CLI_BIN" /usr/local/bin/tapauth-ipc-cli
        INSTALLED_TEST_CLI=true
        # Use the world-executable copy everywhere so the unprivileged Phase 7
        # cases (runuser -u ...) can execute it.
        CLI_BIN="/usr/local/bin/tapauth-ipc-cli"
        install -Dm0644 "$PROJECT_ROOT/systemd/tapauthd.service" /etc/systemd/system/tapauthd.service
        install -Dm0644 "$PROJECT_ROOT/systemd/tapauthd.socket" /etc/systemd/system/tapauthd.socket
        # Only register the policy if it is not already installed: cleanup() deletes
        # what it registered, and removing a pre-existing production policy would
        # break the host's real installation.
        if [ ! -f "$POLKIT_POLICY_DEST" ]; then
            install -Dm0644 "${PROJECT_ROOT}/tapauthd/dev.rourunisen.tapauth.config.admin.policy" "$POLKIT_POLICY_DEST"
            INSTALLED_POLKIT=true
        fi

        # 3. Runtime/state/config directories exactly as packaging does. tmpfiles
        #    creates /etc/tapauth root:root 0755 and config.toml owned by the
        #    daemon (it carries no secrets; keys/state live under /var/lib/tapauth
        #    at 0700). Track a config.toml that did not pre-exist so cleanup only
        #    removes the one we introduced.
        if [ ! -f "$CONFIG_ASSERT_FILE" ]; then
            CREATED_CONFIG=true
        fi
        systemd-tmpfiles --create "$PROJECT_ROOT/packaging/tmpfiles.conf"
        if [ ! -f "$CONFIG_ASSERT_FILE" ]; then
            cat > "$CONFIG_ASSERT_FILE" <<EOF
# TapAuth Configuration (created by the E2E suite, mirrors install.sh)
pam_operation_timeout_secs = 120
udp_port = ${UDP_PORT}
use_tpm = false
EOF
            chown tapauthd:tapauthd "$CONFIG_ASSERT_FILE"
            chmod 644 "$CONFIG_ASSERT_FILE"
        fi
    fi

    # The daemon reads udp_port from config.toml. When the package's tmpfiles
    # created an empty file, the built-in default (36692) applies. Assert the
    # effective port matches the one this harness drives the emulator
    # redirection and packet capture with, so overriding TAPAUTH_E2E_UDP_PORT
    # cannot silently desync the daemon from the test.
    CONFIGURED_UDP_PORT="$(grep -E '^[[:space:]]*udp_port[[:space:]]*=' "$CONFIG_ASSERT_FILE" 2>/dev/null | tail -n1 | sed -E 's/.*=[[:space:]]*//; s/[^0-9].*//')"
    CONFIGURED_UDP_PORT="${CONFIGURED_UDP_PORT:-36692}"
    if [ "$CONFIGURED_UDP_PORT" != "$UDP_PORT" ]; then
        echo "❌ ERROR: $CONFIG_ASSERT_FILE sets udp_port=$CONFIGURED_UDP_PORT but this run uses $UDP_PORT."
        echo "   Set TAPAUTH_E2E_UDP_PORT=$CONFIGURED_UDP_PORT to match the installed config."
        exit 1
    fi

    # 4. E2E-only unit override. These are the ONLY non-production knobs: the
    #    emulator UDP delivery shim (a CI runner cannot deliver LAN multicast
    #    into the Android emulator), the headless PolKit bypass, and debug logs.
    #    State/config paths and socket activation stay production; the binary is
    #    built WITHOUT dev-state-override, so TAPAUTH_STATE_DIR cannot redirect
    #    anything even if it were set in the environment.
    #
    #    Note that under systemd the journal filter comes from
    #    TAPAUTH_JOURNALD_LOG_LEVEL, NOT from TAPAUTH_LOG_LEVEL/RUST_LOG
    #    (tapauthd/src/logging.rs:40-51 keys the stdout layer off the latter but
    #    skips it when JOURNAL_STREAM is set). Assertions therefore read
    #    TAPAUTH_JOURNALD_LOG_LEVEL, which is why the per-target trace directives
    #    are added there as well as to the dev-mode run below.
    mkdir -p /etc/systemd/system/tapauthd.service.d
    cat > /etc/systemd/system/tapauthd.service.d/e2e.conf <<EOF
# E2E-only override (not shipped in production packages)
[Service]
Environment=TAPAUTH_DEV_MODE=1
Environment=TAPAUTH_DEV_UDP_TARGET=127.0.0.1:${DEV_HOST_PORT}
Environment=TAPAUTH_LOG_LEVEL=debug,${E2E_TRACE_TARGETS}
Environment=RUST_LOG=debug,${E2E_TRACE_TARGETS}
Environment=TAPAUTH_JOURNALD_LOG_LEVEL=info,${E2E_TRACE_TARGETS}
EOF

    # 5. Enable the real socket unit; the service is activated on first IPC
    systemctl daemon-reload
    systemctl stop tapauthd.service 2>/dev/null || true
    systemctl enable --now tapauthd.socket

    if ! systemctl is-active --quiet tapauthd.socket; then
        echo "❌ ERROR: tapauthd.socket failed to start:"
        systemctl status tapauthd.socket --no-pager || true
        exit 1
    fi
    echo "✅ tapauthd.socket enabled (socket-activated service)."

    # 6. Real socket activation: this CLI call starts the daemon via FD#3
    if ! "$CLI_BIN" get-config > "${TEST_DIR}/activation.log" 2>&1; then
        echo "❌ ERROR: socket-activated daemon did not answer. Log:"
        cat "${TEST_DIR}/activation.log"
        systemctl status tapauthd.service --no-pager || true
        exit 1
    fi
    if ! systemctl is-active --quiet tapauthd.service; then
        echo "❌ ERROR: tapauthd.service was not activated by IPC connect:"
        systemctl status tapauthd.service --no-pager || true
        exit 1
    fi
    cat "${TEST_DIR}/activation.log"
    echo "✅ tapauthd.service socket-activated and answering IPC."

    # 7. Follow the daemon's journald output into DAEMON_LOG for assertions
    stdbuf -oL journalctl -u tapauthd.service -f -n 0 --no-pager > "$DAEMON_LOG" 2>&1 &
    JOURNAL_PID=$!
fi

# Step 2: Install Android App and Test Runner on Emulator
echo "==> Step 2: Ensuring Android App and Instrumentation Tests are installed..."
APP_PKG="dev.rourunisen.tapauth.e2e"
TEST_PKG="dev.rourunisen.tapauth.e2e.test"

if [ -f "server-android/app/build/outputs/apk/e2e/app-e2e.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/e2e/app-e2e.apk || true
elif [ -f "server-android/app/build/outputs/apk/debug/app-debug.apk" ]; then
    # `debug` instead of `e2e`: the debug variant logs command_preview's length
    # instead of its content (BuildConfig.E2E_TESTING is false for `debug`), so
    # assert_caller_context_delivered skips its preview assertion for this run.
    # Nothing else changes — every later phase still runs against this package.
    APP_PKG="dev.rourunisen.tapauth.debug"
    adb install -r -t server-android/app/build/outputs/apk/debug/app-debug.apk || true
fi

if [ -f "server-android/app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk" ]; then
    adb install -r -t server-android/app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk || true
elif [ -f "server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" ]; then
    TEST_PKG="dev.rourunisen.tapauth.debug.test"
    adb install -r -t server-android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk || true
fi

echo "==> Granting runtime permissions to Android app ($APP_PKG)..."
adb shell pm grant "$APP_PKG" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.ACCESS_FINE_LOCATION 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.BLUETOOTH_CONNECT 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.BLUETOOTH_ADVERTISE 2>/dev/null || true
adb shell pm grant "$APP_PKG" android.permission.BLUETOOTH_SCAN 2>/dev/null || true
# The grants above are all `|| true`, so a renamed package or a permission model
# change would silently degrade into a 30 s BLE pairing mystery. Read them back.
# A *denied* permission still lists its name, so match the granted state.
PERM_DUMP=$(timeout 20 adb shell dumpsys package "$APP_PKG" 2>/dev/null || true)
if ! printf '%s\n' "$PERM_DUMP" | grep -q 'android.permission.BLUETOOTH_SCAN: granted=true'; then
    echo "⚠️  BLUETOOTH_SCAN is NOT granted to $APP_PKG — Phase 1c cannot work; check the pm grant calls above"
fi

# Step 3: Setup Bridges and Virtual Transport Layers
echo "==> Step 3: Setting up Transport Bridges (BLE + UDP)..."
"$SCRIPT_DIR/ci/setup-emulator-ble-bridge.sh"
"$SCRIPT_DIR/ci/setup-emulator-udp-bridge.sh"
# Setup biometrics: the helper performs real enrollment where the image
# supports it (`cmd fingerprint enroll`) and otherwise falls back — loudly — to
# the e2e build's auto-approve behavior (no biometrics enrolled, grant ~1s after
# the prompt). Passing the package lets it verify that fallback prerequisite.
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" setup "$APP_PKG"

# Step 4: Launch tapauthd daemon
echo "==> Step 4: Launching tapauthd daemon..."
if [ "$E2E_DAEMON_MODE" = "dev" ]; then
    env TAPAUTH_DEV_MODE="1" TAPAUTH_DEV_UDP_TARGET="127.0.0.1:${DEV_HOST_PORT}" TAPAUTH_LOG_LEVEL="debug,${E2E_TRACE_TARGETS}" RUST_LOG="debug" TAPAUTHD_SOCK="$TAPAUTHD_SOCK" ${TAPAUTH_STATE_DIR:+TAPAUTH_STATE_DIR="$TAPAUTH_STATE_DIR"} "$TAPAUTHD_BIN" > "$DAEMON_LOG" 2>&1 &
    DAEMON_PID=$!

    echo -n "    Waiting for daemon socket"
    for _ in {1..50}; do
        if [ -S "$TAPAUTHD_SOCK" ]; then break; fi
        echo -n "."; sleep 0.1
    done
    echo ""

    if [ ! -S "$TAPAUTHD_SOCK" ]; then
        echo "❌ ERROR: tapauthd socket failed to initialize. Daemon log:"
        cat "$DAEMON_LOG"
        exit 1
    fi
    echo "✅ tapauthd daemon is active (dev sandbox)."
else
    echo "✅ tapauthd daemon is active (systemd socket activation)."
fi

# ── Phase 1 helpers: protocol-v2 pairing URL ──────────────────────────────────
#
# `start-pairing` prints the QR on a single `URL=` line, in the v2 form
#
#   tapauth://pair?v=2&sid=<32 hex>&pk=<64 hex>[&p=<udp port>][&ip4=…][&ip6=…]
#
# so every field has to be read as a query parameter. Splitting that line on `=`
# (`cut -d'=' -f2`, what this phase used to do) truncates it at the first `=`
# inside the URL and hands the phone a malformed QR, which the instrumentation
# run then reports as an assertion failure the old harness ignored.

# pair_url_param <url> <key>: first value of `key` in the query, empty if absent.
pair_url_param() {
    local url=$1 key=$2 query part
    query="${url#*\?}"
    if [ "$query" = "$url" ]; then
        return 0
    fi
    local IFS='&'
    for part in $query; do
        if [ "${part%%=*}" = "$key" ]; then
            printf '%s' "${part#*=}"
            return 0
        fi
    done
}

# pair_url_set <url> <key> <value>: replace the first `key=…`, else append it.
pair_url_set() {
    local url=$1 key=$2 value=$3
    local prefix query part out="" replaced=0
    case "$url" in
        *\?*) prefix="${url%%\?*}?"; query="${url#*\?}" ;;
        *)    prefix="${url}?";      query="" ;;
    esac
    local IFS='&'
    for part in $query; do
        if [ "$replaced" = "0" ] && [ "${part%%=*}" = "$key" ]; then
            out="${out:+$out&}${key}=${value}"
            replaced=1
        else
            out="${out:+$out&}${part}"
        fi
    done
    if [ "$replaced" = "0" ]; then
        out="${out:+$out&}${key}=${value}"
    fi
    printf '%s' "${prefix}${out}"
}

# pair_url_del <url> <key>: the URL without `key=…` (used to strip the network
# endpoints, which is what turns a QR into a BLE-only one).
pair_url_del() {
    local url=$1 key=$2 prefix query part out=""
    case "$url" in
        *\?*) prefix="${url%%\?*}?"; query="${url#*\?}" ;;
        *)    printf '%s' "$url"; return 0 ;;
    esac
    local IFS='&'
    for part in $query; do
        if [ "${part%%=*}" = "$key" ]; then
            continue
        fi
        out="${out:+$out&}${part}"
    done
    printf '%s' "${prefix}${out}"
}

# require_pair_url_v2 <url> <label> [require_udp_endpoint]
#
# Fails loudly (exit 1) unless the QR is a usable v2 pairing URL: `v=2`, a
# 32-hex `sid`, a 64-hex non-zero `pk`. With `require_udp_endpoint=1` the QR must
# also carry a UDP endpoint (`p` and `ip4`), which is what makes a run a *UDP*
# pairing rather than a BLE one. Always echoes the reconstructed keys, so the
# log shows exactly which URL the phone was given.
require_pair_url_v2() {
    local url=$1 label=$2 require_udp=${3:-0}
    local v sid pk p ip4 ip6 err=""
    v=$(pair_url_param "$url" v)
    sid=$(pair_url_param "$url" sid)
    pk=$(pair_url_param "$url" pk)
    p=$(pair_url_param "$url" p)
    ip4=$(pair_url_param "$url" ip4)
    ip6=$(pair_url_param "$url" ip6)
    if [ "$v" != "2" ]; then
        err="v='$v' (expected '2')"
    elif ! printf '%s' "$sid" | grep -Eq '^[0-9a-fA-F]{32}$'; then
        err="sid='$sid' (expected 32 hex characters)"
    elif printf '%s' "$pk" | grep -Eq '^0+$'; then
        err="pk='$pk' is the all-zero key"
    elif ! printf '%s' "$pk" | grep -Eq '^[0-9a-fA-F]{64}$'; then
        err="pk='$pk' (expected 64 hex characters)"
    elif [ "$require_udp" = "1" ] && [ -z "$p" ]; then
        err="p is empty (the QR carries no ephemeral UDP pairing port)"
    elif [ "$require_udp" = "1" ] && [ -z "$ip4" ]; then
        err="ip4 is empty (the QR carries no IPv4 endpoint)"
    fi
    if [ -n "$err" ]; then
        echo "❌ ERROR (${label}): not a usable v2 pairing URL: $err"
        echo "   QR keys: v='$v' sid='$sid' pk='$pk' p='$p' ip4='$ip4' ip6='$ip6'"
        exit 1
    fi
    echo "✅ ${label}: v2 QR keys v='$v' sid='$sid' pk='$pk' p='$p' ip4='$ip4' ip6='$ip6'"
}

# pair_url_for_emulator <url>: rewrite the QR's `ip4` to 10.0.2.2, the QEMU SLIRP
# alias for the host, because the QR's LAN address is not routable from inside
# the guest. This does not weaken the handshake: the endpoints are NOT part of
# the pairing transcript, and the identity pin (`pk`) travels in the same URL and
# is still verified by the phone. `p`/`sid`/`pk`/`ip6` are left untouched, and a
# BLE-only QR (no `ip4`) is returned unchanged instead of gaining a bogus one.
pair_url_for_emulator() {
    local url=$1
    if [ -n "$(pair_url_param "$url" ip4)" ]; then
        pair_url_set "$url" ip4 "10.0.2.2"
    else
        printf '%s' "$url"
    fi
}

# instrument_ok <am-log>: true only when the runner itself reported success.
# `am instrument`'s exit status is not trustworthy, so the verdict is read from
# its output — the same distrust scripts/ci/run-all-e2e.sh applies.
instrument_ok() {
    local log=$1
    if [ ! -f "$log" ]; then
        return 1
    fi
    if grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed' "$log"; then
        return 1
    fi
    grep -q 'OK (' "$log"
}

# assert_instrument_ok <am-log> <label>: fail, dumping the log, unless the run
# actually passed. Never replace this with `wait "$AM_PID"`: a crashed or
# assertion-failing run must not be able to look like a pass.
assert_instrument_ok() {
    local log=$1 label=$2
    if instrument_ok "$log"; then
        echo "✅ ${label}: instrumentation reported OK"
        return 0
    fi
    echo "❌ ERROR (${label}): instrumentation did not report a passing run."
    echo "---- ${log} ----"
    cat "$log" || true
    exit 1
}

# phase_marker <am-log> <marker>: true when <marker> appears in the phase's
# instrumentation output OR in logcat. Several observables (the rejected-SAS
# outcome, "SAS reached the phone over BLE", "Pairing completed and persisted")
# are reported with Log.i, and `am instrument`'s stream carries the test's stdout,
# not logcat — so a run that only greps the instrumentation log would look like a
# failure forever. Every phase clears the buffer with `adb logcat -c` before it
# runs, so the logcat half cannot match a line from an earlier phase or run.
phase_marker() {
    local am_log=$1 marker=$2
    if [ -f "$am_log" ] && grep -qF "$marker" "$am_log"; then
        return 0
    fi
    adb logcat -d 2>/dev/null | grep -qF "$marker"
}

# servers_count <label>: the daemon's paired-device count as a validated integer.
#
# A bare `$(get-servers | grep 'COUNT=' | cut -f2)` is empty whenever the CLI or
# the daemon fails, and `[ "" -ne 0 ]` / `[ "" -lt 1 ]` are errors (status 2) that
# an `if` reads as false — so an empty count silently satisfied both the "must be
# 0" and the "must be at least 1" assertions. This exits instead.
servers_count() {
    local label=$1 raw count
    if ! raw=$("$CLI_BIN" get-servers 2>&1); then
        echo "❌ ERROR (${label}): get-servers failed:" >&2
        printf '%s\n' "$raw" >&2
        exit 1
    fi
    count=$(printf '%s\n' "$raw" | sed -n 's/^COUNT=\([0-9][0-9]*\)$/\1/p' | head -n1)
    if [ -z "$count" ]; then
        echo "❌ ERROR (${label}): get-servers produced no COUNT= line:" >&2
        printf '%s\n' "$raw" >&2
        exit 1
    fi
    printf '%s' "$count"
}

# clear_logcat <label>: empty the logcat ring buffer, or fail.
#
# Every Phase 1 staleness claim rests on this having happened, so a rejected
# `logcat -c` (adb hiccup, locked device) must not be swallowed the way
# `2>/dev/null || true` swallows it — that would let a line from an earlier phase
# or an earlier run satisfy a marker this phase is supposed to prove.
clear_logcat() {
    local label=$1 out
    if ! out=$(adb logcat -c 2>&1); then
        echo "❌ ERROR (${label}): 'adb logcat -c' failed:" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
    if printf '%s' "$out" | grep -qi 'failed'; then
        echo "❌ ERROR (${label}): 'adb logcat -c' reported a failure:" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
}

# phone_sas <am-log> <label>: the SAS the phone derived, as one value.
#
# The daemon's own `SAS=` (from `wait-for-pairing`) is authoritative — that is
# the code the user is asked to compare. The phone's value is corroboration, and
# it has to come from something THIS run produced: the instrumentation's stdout
# (`ANDROID_DERIVED_SAS=` via println) or the logcat buffer, which every sub-phase
# clears before it starts. The file the test writes to filesDir is deliberately
# not consulted: it survives across runs, so a stale value would satisfy the
# comparison on a run where the phone derived nothing at all.
phone_sas() {
    local am_log=$1 label=$2 sas
    sas=$(grep -o 'ANDROID_DERIVED_SAS=[0-9-]*' "$am_log" 2>/dev/null | head -n1 | cut -d'=' -f2 || true)
    if [ -z "$sas" ]; then
        sas=$(adb logcat -d 2>/dev/null | grep -o 'Derived SAS: [0-9-]*' | tail -n1 | cut -d':' -f2 | tr -d ' \r\n' || true)
    fi
    if [ -z "$sas" ]; then
        echo "❌ ERROR (${label}): the phone never reported a derived SAS." >&2
        echo "   (looked for ANDROID_DERIVED_SAS= in ${am_log} and 'Derived SAS:' in logcat)" >&2
        tail -n 40 "$am_log" 2>/dev/null >&2 || true
        exit 1
    fi
    printf '%s' "$sas"
}

# log_since_present <base-line-count> <fixed-string> [tries]
#
# The probe behind `wait_log_since`: poll until the line shows up, return 1
# instead of exiting when it does not. Callers that want to fold "the daemon
# never logged this" into their own evidence dump use it directly.
log_since_present() {
    local base=$1 needle=$2 tries=${3:-40} _i
    for _i in $(seq 1 "$tries"); do
        if tail -n +"$((base + 1))" "$DAEMON_LOG" 2>/dev/null | grep -qF "$needle"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# wait_log_since <base-line-count> <fixed-string> <label> [tries]
#
# Poll the daemon log for a line emitted after `base`, 0.5 s apart (40 tries by
# default, i.e. 20 s), then fail with the log tail. DAEMON_LOG is followed
# asynchronously — a redirect in dev mode, `journalctl -f` in systemd mode — so a
# line the daemon just emitted may not be on disk yet when the assertion runs.
# That is why the window is anchored to a line count and why this polls.
#
# This is the Phase 1 poll-based variant. `assert_log_since` further down stays
# single-shot and is untouched for the later phases, whose sequences are settled
# by the time it runs; Phase 1 asserts while a session and a journald follower
# are still moving, which is the only reason the two differ. The divergence is
# intentional and scoped to Phase 1.
wait_log_since() {
    local base=$1 needle=$2 label=$3 tries=${4:-40}
    if log_since_present "$base" "$needle" "$tries"; then
        echo "✅ ${label}"
        return 0
    fi
    echo "❌ ERROR (${label}): '${needle}' never appeared in the daemon log for this phase."
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
}

# pairing_sas_match <desktop-sas> <am-log> <label>: bilateral SAS comparison.
# The daemon's value is authoritative (see phone_sas); the phone's is read from
# this run's stdout or the logcat buffer that the phase cleared on entry.
pairing_sas_match() {
    local desktop=$1 am_log=$2 label=$3 android_sas
    android_sas=$(phone_sas "$am_log" "$label")
    echo "    Android Derived SAS: $android_sas"
    # Both sides must be present: an empty desktop value and an empty phone value
    # would otherwise compare equal and "pass" a comparison nobody made.
    if [ -n "$desktop" ] && [ -n "$android_sas" ] && [ "$android_sas" = "$desktop" ]; then
        echo "✅ ${label}: SAS Anti-MITM verification PASSED, both sides derived $desktop"
    else
        echo "❌ ERROR (${label}): SAS Anti-MITM verification mismatch! Desktop='$desktop', Android='$android_sas'"
        cat "$am_log" || true
        exit 1
    fi
}

# Step 5: Phase 1 - Protocol v2 unified pairing (UDP + BLE)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 1: Protocol v2 Pairing (UDP + BLE) & SAS Anti-MITM     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Phase outcomes are recorded in the registry at the top of this file
# (phase_pass / phase_skip / phase_fail); the summary at the end is generated
# from it. Phase 1a is one registry entry covering the three sub-cases below, so
# it is recorded once, after the last of them has asserted.

# The daemon's own SAS display form, e.g. 123-456.
SAS_PATTERN='^[0-9][0-9][0-9]-[0-9][0-9][0-9]$'

# ── 1a-i: the phone rejects the SAS ──────────────────────────────────────────
#
# The phone derives its SAS from the desktop's PairingResponse, so getting as far
# as the rejection proves the phone reached this daemon and verified its packet.
# The daemon's side of the evidence is two log lines: the accepted PairingInit
# (the SAS was derived) and the abort with the phone's reason.
echo "==> Step 1a-i: the phone rejects the SAS..."
clear_logcat "Phase 1a-i"
LOG_BASE=$(wc -l < "$DAEMON_LOG")

if ! START_NEG_OUTPUT=$("$CLI_BIN" start-pairing); then
    echo "❌ ERROR (Phase 1a-i): start-pairing failed (a previous session may still be active):"
    printf '%s\n' "$START_NEG_OUTPUT"
    exit 1
fi
PORT_NEG=$(echo "$START_NEG_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL_NEG=$(echo "$START_NEG_OUTPUT" | grep 'URL=' | cut -d'=' -f2-)
SESSION_ID_NEG=$(echo "$START_NEG_OUTPUT" | grep 'SESSION_ID=' | cut -d'=' -f2)
echo "    Pairing port: $PORT_NEG  session: $SESSION_ID_NEG"
# No UDP endpoint is demanded here: a rejection is equally valid over BLE, so
# this sub-case only requires a well-formed v2 QR.
require_pair_url_v2 "$PAIR_URL_NEG" "Phase 1a-i QR"
PAIR_URL_NEG=$(pair_url_for_emulator "$PAIR_URL_NEG")
echo "    Pairing URL (emulator view): $PAIR_URL_NEG"

WAIT_NEG_LOG="${TEST_DIR}/wait_neg_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT_NEG" > "$WAIT_NEG_LOG" 2>&1 &
WAIT_NEG_PID=$!

# The whole device command is ONE quoted string: `adb shell` re-parses its command
# line on the device, and the QR contains `&` — unquoted, the device shell would
# split the URL there and background half the command. The host-side double quotes
# let `$PAIR_URL_NEG` expand here; the device sees it single-quoted.
AM_NEG_LOG="${TEST_DIR}/am_neg_pairing.log"
adb shell "am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_url '$PAIR_URL_NEG' \
    -e reject_sas true \
    '$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner'" > "$AM_NEG_LOG" 2>&1 || true

# The phone has rejected the SAS by now, so the session is over. Before the
# desktop attempts its own approval, require the daemon to have logged the abort:
# if that datagram were lost or late, `complete-pairing` would enter provisioning
# and block for its full 120 s deadline, then fail with the misleading "before
# the phone confirmed the CSK" instead of the abort reason. An approval must only
# be attempted against a session the daemon already knows the phone abandoned.
set +e
wait "$WAIT_NEG_PID"
WAIT_NEG_EXIT=$?
set -e

DAEMON_SAW=1
if ! log_since_present "$LOG_BASE" 'PairingInit accepted over'; then
    echo "❌ ERROR (Phase 1a-i): the daemon never logged an accepted PairingInit (the phone never reached it)."
    DAEMON_SAW=0
fi
if [ "$DAEMON_SAW" = "1" ] \
    && ! log_since_present "$LOG_BASE" 'Pairing aborted by the phone (USER_REJECTED_SAS)'; then
    echo "❌ ERROR (Phase 1a-i): the daemon never logged the phone's USER_REJECTED_SAS abort, so no approval is attempted."
    DAEMON_SAW=0
fi
if [ "$DAEMON_SAW" != "1" ]; then
    echo "---- ${AM_NEG_LOG} ----"
    cat "$AM_NEG_LOG" || true
    echo "---- ${WAIT_NEG_LOG} ----"
    cat "$WAIT_NEG_LOG" || true
    echo "---- logcat (PairingSession / PairingE2eTest) ----"
    adb logcat -d -v time -s 'PairingSession:*' 'PairingE2eTest:*' 2>/dev/null | tail -n 40 || true
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
fi
echo "✅ Phase 1a-i: the daemon logged the accepted PairingInit and the phone's USER_REJECTED_SAS abort."

set +e
"$CLI_BIN" complete-pairing "$PORT_NEG" > "${TEST_DIR}/complete_neg_pairing.log" 2>&1
COMPLETE_NEG_EXIT=$?
set -e

NEG_SAS=$(grep 'SAS=' "$WAIT_NEG_LOG" | head -n1 | cut -d'=' -f2 || true)
NEG_SERVERS_COUNT=$(servers_count "Phase 1a-i")

NEG_OK=1
if ! instrument_ok "$AM_NEG_LOG"; then
    echo "❌ ERROR (Phase 1a-i): the SAS-rejection instrumentation run did not report OK."
    NEG_OK=0
fi
if ! phase_marker "$AM_NEG_LOG" 'Negative pairing test passed: SAS rejected, no device stored.'; then
    echo "❌ ERROR (Phase 1a-i): the phone never reported the rejected-SAS outcome."
    NEG_OK=0
fi
if [ "$WAIT_NEG_EXIT" -ne 0 ]; then
    echo "❌ ERROR (Phase 1a-i): wait-for-pairing exited $WAIT_NEG_EXIT instead of reporting the SAS."
    NEG_OK=0
fi
if ! printf '%s' "$NEG_SAS" | grep -Eq "$SAS_PATTERN"; then
    echo "❌ ERROR (Phase 1a-i): the daemon never displayed a SAS (got '$NEG_SAS')."
    NEG_OK=0
fi
if [ "$COMPLETE_NEG_EXIT" -ne 1 ]; then
    echo "❌ ERROR (Phase 1a-i): complete-pairing exited $COMPLETE_NEG_EXIT, expected a refusal (1)."
    NEG_OK=0
fi
if ! grep -qF 'ERROR: Pairing session failed: the phone aborted the pairing (USER_REJECTED_SAS)' \
    "${TEST_DIR}/complete_neg_pairing.log"; then
    echo "❌ ERROR (Phase 1a-i): the desktop refused for the wrong reason — expected the phone's USER_REJECTED_SAS."
    NEG_OK=0
fi
if [ "$NEG_SERVERS_COUNT" -ne 0 ]; then
    echo "❌ ERROR (Phase 1a-i): $NEG_SERVERS_COUNT device(s) stored despite a rejected SAS."
    NEG_OK=0
fi
if [ "$NEG_OK" != "1" ]; then
    echo "---- ${AM_NEG_LOG} ----"
    cat "$AM_NEG_LOG" || true
    echo "---- ${WAIT_NEG_LOG} ----"
    cat "$WAIT_NEG_LOG" || true
    echo "---- ${TEST_DIR}/complete_neg_pairing.log ----"
    cat "${TEST_DIR}/complete_neg_pairing.log" || true
    echo "---- logcat (PairingSession / PairingE2eTest) ----"
    adb logcat -d -v time -s 'PairingSession:*' 'PairingE2eTest:*' 2>/dev/null | tail -n 40 || true
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
fi
# Both sides must have shown the same code before the phone rejected it.
pairing_sas_match "$NEG_SAS" "$AM_NEG_LOG" "Phase 1a-i"
echo "✅ Phase 1a-i PASSED: both sides derived SAS $NEG_SAS, the phone rejected it, the desktop refused with USER_REJECTED_SAS and 0 devices were stored."

# ── 1a-ii: the phone pins the QR `pk` ────────────────────────────────────────
#
# The protocol declares `PairingAbortReason::KEY_MISMATCH`, but NO implementation
# emits it. On a mismatched `pk` the phone's Rust pin check simply rejects the
# packet (constant-time comparison via shared/src/ffi/ops.rs), logs
# "PairingResponse rejected: challenge does not match the session" and waits out
# its own response deadline without sending any abort — so the daemon cannot
# observe that reason and this phase cannot assert it. What is assertable is the
# phone-side pin rejection, the phone's resulting failure, and a session that
# this harness then tears down from the desktop with `cancel-pairing`.
echo "==> Step 1a-ii: the phone rejects a PairingResponse that does not match the QR pk..."
clear_logcat "Phase 1a-ii"
LOG_BASE=$(wc -l < "$DAEMON_LOG")

if ! START_MISMATCH_OUTPUT=$("$CLI_BIN" start-pairing); then
    echo "❌ ERROR (Phase 1a-ii): start-pairing failed (a previous session may still be active):"
    printf '%s\n' "$START_MISMATCH_OUTPUT"
    exit 1
fi
PORT_MISMATCH=$(echo "$START_MISMATCH_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL_MISMATCH=$(echo "$START_MISMATCH_OUTPUT" | grep 'URL=' | cut -d'=' -f2-)
SESSION_ID_MISMATCH=$(echo "$START_MISMATCH_OUTPUT" | grep 'SESSION_ID=' | cut -d'=' -f2)
echo "    Pairing port: $PORT_MISMATCH  session: $SESSION_ID_MISMATCH"
# require_udp_endpoint=1: the pin must be exercised on a path the phone can
# actually reach, otherwise the run fails for "no endpoint" and would look like
# a correct rejection for the wrong reason.
require_pair_url_v2 "$PAIR_URL_MISMATCH" "Phase 1a-ii QR" 1
# A different but well-formed, non-zero 64-hex X25519 public key.
PAIR_URL_MISMATCH=$(pair_url_set "$PAIR_URL_MISMATCH" pk "$(printf '%064d' 1)")
PAIR_URL_MISMATCH=$(pair_url_for_emulator "$PAIR_URL_MISMATCH")
echo "    Mismatched URL pk: $(pair_url_param "$PAIR_URL_MISMATCH" pk)"
echo "    Pairing URL (emulator view): $PAIR_URL_MISMATCH"

WAIT_MISMATCH_LOG="${TEST_DIR}/wait_mismatch_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT_MISMATCH" > "$WAIT_MISMATCH_LOG" 2>&1 &
WAIT_MISMATCH_PID=$!

# Synchronous: the phone rejects the mismatched `PairingResponse` and then waits out its own 30 s
# response deadline, which is the terminal state `PairingE2eTest` observes (`Pairing failed while
# waiting for the derived SAS: …`). The test's own await is 45 s — deliberately above that
# deadline so it can never win the race — so this returns (failing) within about 45 s.
AM_MISMATCH_LOG="${TEST_DIR}/am_mismatch_pairing.log"
adb shell "am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_url '$PAIR_URL_MISMATCH' \
    '$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner'" > "$AM_MISMATCH_LOG" 2>&1 || true

set +e
wait "$WAIT_MISMATCH_PID"
WAIT_MISMATCH_EXIT=$?
set -e

LOGCAT_MISMATCH=$(adb logcat -d 2>/dev/null || true)
MISMATCH_SAS=$(grep 'SAS=' "$WAIT_MISMATCH_LOG" | head -n1 | cut -d'=' -f2 || true)
MISMATCH_SERVERS_COUNT=$(servers_count "Phase 1a-ii")

MISMATCH_OK=1
if ! printf '%s\n' "$LOGCAT_MISMATCH" | grep -qF 'PairingResponse rejected: challenge does not match the session'; then
    echo "❌ ERROR (Phase 1a-ii): the phone did not reject the mismatched PairingResponse."
    MISMATCH_OK=0
fi
# `Starting E2E pairing:` is a Log.i, so it is a logcat line; `phase_marker` also
# accepts it from the instrumentation stream, which carries the test's stdout.
if ! phase_marker "$AM_MISMATCH_LOG" 'Starting E2E pairing:'; then
    echo "❌ ERROR (Phase 1a-ii): the instrumentation run never started the pairing flow."
    MISMATCH_OK=0
fi
if ! phase_marker "$AM_MISMATCH_LOG" 'Pairing failed while waiting for the derived SAS'; then
    echo "❌ ERROR (Phase 1a-ii): the phone did not fail waiting for the (never accepted) response."
    MISMATCH_OK=0
fi
if [ "$WAIT_MISMATCH_EXIT" -ne 0 ]; then
    echo "❌ ERROR (Phase 1a-ii): wait-for-pairing exited $WAIT_MISMATCH_EXIT instead of reporting the SAS."
    MISMATCH_OK=0
fi
if ! printf '%s' "$MISMATCH_SAS" | grep -Eq "$SAS_PATTERN"; then
    echo "❌ ERROR (Phase 1a-ii): the daemon never displayed a SAS (got '$MISMATCH_SAS')."
    MISMATCH_OK=0
fi
if [ "$MISMATCH_SERVERS_COUNT" -ne 0 ]; then
    echo "❌ ERROR (Phase 1a-ii): $MISMATCH_SERVERS_COUNT device(s) stored despite a pk mismatch."
    MISMATCH_OK=0
fi
if [ "$MISMATCH_OK" != "1" ]; then
    echo "---- ${AM_MISMATCH_LOG} ----"
    cat "$AM_MISMATCH_LOG" || true
    echo "---- ${WAIT_MISMATCH_LOG} ----"
    cat "$WAIT_MISMATCH_LOG" || true
    echo "---- logcat (PairingSession / PairingE2eTest) ----"
    adb logcat -d -v time -s 'PairingSession:*' 'PairingE2eTest:*' 2>/dev/null | tail -n 40 || true
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
fi
echo "✅ Phase 1a-ii: the phone pinned the QR pk and dropped the daemon's PairingResponse; the desktop had derived SAS $MISMATCH_SAS and 0 devices were stored."

# Teardown. `complete-pairing` would block for the daemon's `SESSION_REPLY_TIMEOUT`
# (135 s, tapauthd/src/pairing.rs) here — the phone is gone and will never send
# PairingConfirmServer — so the session is cancelled from the desktop instead, and
# only then is the completion refusal checked. The CLI's own 150 s deadline outlives
# that daemon bound, so it would report the daemon's timeout rather than its own.
if ! "$CLI_BIN" cancel-pairing --port "$PORT_MISMATCH" --session-id "$SESSION_ID_MISMATCH" \
    > "${TEST_DIR}/cancel_mismatch_pairing.log" 2>&1; then
    echo "❌ ERROR (Phase 1a-ii): cancel-pairing failed:"
    cat "${TEST_DIR}/cancel_mismatch_pairing.log" || true
    exit 1
fi
if ! grep -qF 'CANCELLED=true' "${TEST_DIR}/cancel_mismatch_pairing.log"; then
    echo "❌ ERROR (Phase 1a-ii): cancel-pairing did not confirm the cancellation:"
    cat "${TEST_DIR}/cancel_mismatch_pairing.log" || true
    exit 1
fi
set +e
"$CLI_BIN" complete-pairing "$PORT_MISMATCH" > "${TEST_DIR}/complete_mismatch_pairing.log" 2>&1
COMPLETE_MISMATCH_EXIT=$?
set -e
if [ "$COMPLETE_MISMATCH_EXIT" -ne 1 ] \
    || ! grep -qF 'ERROR: Pairing session failed: the pairing was cancelled' \
        "${TEST_DIR}/complete_mismatch_pairing.log"; then
    echo "❌ ERROR (Phase 1a-ii): a cancelled session did not refuse completion as cancelled (exit $COMPLETE_MISMATCH_EXIT):"
    cat "${TEST_DIR}/complete_mismatch_pairing.log" || true
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
fi
echo "✅ Phase 1a-ii PASSED: pin mismatch rejected phone-side, session cancelled from the desktop, completion refused (the pairing was cancelled)."

# ── 1a-iii: the desktop cancels a live session ───────────────────────────────
#
# `hold_sas_ms` keeps the phone in `awaitApproval` after it has displayed the
# SAS, so the cancel lands on a session that is genuinely still deciding rather
# than on one the phone already abandoned.
echo "==> Step 1a-iii: the desktop cancels a live session..."
clear_logcat "Phase 1a-iii"
LOG_BASE=$(wc -l < "$DAEMON_LOG")

if ! START_CANCEL_OUTPUT=$("$CLI_BIN" start-pairing); then
    echo "❌ ERROR (Phase 1a-iii): start-pairing failed (a previous session may still be active):"
    printf '%s\n' "$START_CANCEL_OUTPUT"
    exit 1
fi
PORT_CANCEL=$(echo "$START_CANCEL_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL_CANCEL=$(echo "$START_CANCEL_OUTPUT" | grep 'URL=' | cut -d'=' -f2-)
SESSION_ID_CANCEL=$(echo "$START_CANCEL_OUTPUT" | grep 'SESSION_ID=' | cut -d'=' -f2)
echo "    Pairing port: $PORT_CANCEL  session: $SESSION_ID_CANCEL"
require_pair_url_v2 "$PAIR_URL_CANCEL" "Phase 1a-iii QR" 1
PAIR_URL_CANCEL=$(pair_url_for_emulator "$PAIR_URL_CANCEL")
echo "    Pairing URL (emulator view): $PAIR_URL_CANCEL"

AM_CANCEL_LOG="${TEST_DIR}/am_cancel_pairing.log"
adb shell "am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_url '$PAIR_URL_CANCEL' \
    -e hold_sas_ms 8000 \
    '$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner'" > "$AM_CANCEL_LOG" 2>&1 &
AM_CANCEL_PID=$!

# Cancel once the phone actually shows its SAS (its `hold_sas_ms` window), so the
# abort arrives while `awaitApproval` is still waiting for a decision.
#
# 100 polls at 0.5 s ≈ 50 s, which outlives the phone's own 30 s response race
# (`PairingSession.RESPONSE_DEADLINE_MS`) plus app start. A window that expired
# first would report "the phone never displayed a SAS" for a phone that was
# simply still racing for the response.
CANCEL_SAS_SEEN=0
for _ in $(seq 1 100); do
    if adb logcat -d 2>/dev/null | grep -q 'ANDROID_DERIVED_SAS='; then
        CANCEL_SAS_SEEN=1
        break
    fi
    sleep 0.5
done
if [ "$CANCEL_SAS_SEEN" != "1" ]; then
    echo "❌ ERROR (Phase 1a-iii): the phone never displayed a SAS, so there was nothing to cancel."
    adb logcat -d -v time -s 'PairingSession:*' 'PairingE2eTest:*' 2>/dev/null | tail -n 40 || true
    cat "$AM_CANCEL_LOG" || true
    exit 1
fi
echo "    Phone displayed its SAS; cancelling from the desktop..."

if ! "$CLI_BIN" cancel-pairing --port "$PORT_CANCEL" --session-id "$SESSION_ID_CANCEL" \
    > "${TEST_DIR}/cancel_pairing.log" 2>&1; then
    echo "❌ ERROR (Phase 1a-iii): cancel-pairing failed:"
    cat "${TEST_DIR}/cancel_pairing.log" || true
    exit 1
fi
if ! grep -qF 'CANCELLED=true' "${TEST_DIR}/cancel_pairing.log"; then
    echo "❌ ERROR (Phase 1a-iii): cancel-pairing did not confirm the cancellation:"
    cat "${TEST_DIR}/cancel_pairing.log" || true
    exit 1
fi
echo "✅ The desktop cancelled the session (CANCELLED=true)."

wait "$AM_CANCEL_PID" || true

CANCEL_OK=1
if instrument_ok "$AM_CANCEL_LOG"; then
    echo "❌ ERROR (Phase 1a-iii): the instrumentation reported success — a cancelled pairing must never pass."
    CANCEL_OK=0
fi
if ! phase_marker "$AM_CANCEL_LOG" 'The desktop aborted the pairing'; then
    echo "❌ ERROR (Phase 1a-iii): the phone never reported the desktop's abort."
    CANCEL_OK=0
fi
# Negated via `phase_marker` (which also reads logcat) rather than a plain grep of
# the instrumentation log: "Pairing completed and persisted" is a Log.i line, so
# an AM-log-only grep would pass without looking at anything.
if phase_marker "$AM_CANCEL_LOG" 'Pairing completed and persisted'; then
    echo "❌ ERROR (Phase 1a-iii): the phone completed the pairing even though the desktop cancelled."
    CANCEL_OK=0
fi
set +e
"$CLI_BIN" complete-pairing "$PORT_CANCEL" > "${TEST_DIR}/complete_cancel_pairing.log" 2>&1
COMPLETE_CANCEL_EXIT=$?
set -e
if [ "$COMPLETE_CANCEL_EXIT" -ne 1 ] \
    || ! grep -qF 'ERROR: Pairing session failed: the pairing was cancelled' \
        "${TEST_DIR}/complete_cancel_pairing.log"; then
    echo "❌ ERROR (Phase 1a-iii): a cancelled session did not refuse completion as cancelled (exit $COMPLETE_CANCEL_EXIT):"
    CANCEL_OK=0
fi
CANCEL_SERVERS_COUNT=$(servers_count "Phase 1a-iii")
if [ "$CANCEL_SERVERS_COUNT" -ne 0 ]; then
    echo "❌ ERROR (Phase 1a-iii): $CANCEL_SERVERS_COUNT device(s) stored despite a cancelled pairing."
    CANCEL_OK=0
fi
if [ "$CANCEL_OK" != "1" ]; then
    echo "---- ${AM_CANCEL_LOG} ----"
    cat "$AM_CANCEL_LOG" || true
    echo "---- ${TEST_DIR}/cancel_pairing.log ----"
    cat "${TEST_DIR}/cancel_pairing.log" || true
    echo "---- ${TEST_DIR}/complete_cancel_pairing.log ----"
    cat "${TEST_DIR}/complete_cancel_pairing.log" || true
    echo "---- logcat (PairingSession / PairingE2eTest) ----"
    adb logcat -d -v time -s 'PairingSession:*' 'PairingE2eTest:*' 2>/dev/null | tail -n 40 || true
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
fi
wait_log_since "$LOG_BASE" 'Cancelling the pairing session' \
    "Phase 1a-iii: the daemon logged the desktop-initiated cancellation"
echo "✅ Phase 1a-iii PASSED: the desktop cancelled a live session, the phone reported the abort, nothing was stored."
# One registry entry for the three sub-cases above: the rejected SAS (1a-i), the
# pinned pk (1a-ii) and the desktop-initiated cancel (1a-iii).
phase_pass "1a" "the phone rejected SAS ${NEG_SAS} and 0 devices were stored (1a-i), the phone dropped a PairingResponse whose pk did not match the QR and the cancelled completion was refused (1a-ii), and a desktop cancel of a live session was reported by the phone and stored nothing (1a-iii)"

# ── 1b: legitimate UDP pairing over QEMU SLIRP ───────────────────────────────
echo "==> Step 1b: Legitimate UDP pairing over QEMU SLIRP (10.0.2.2)..."
clear_logcat "Phase 1b"
LOG_BASE=$(wc -l < "$DAEMON_LOG")

if ! START_OUTPUT=$("$CLI_BIN" start-pairing); then
    echo "❌ ERROR (Phase 1b): start-pairing failed (a previous session may still be active):"
    printf '%s\n' "$START_OUTPUT"
    exit 1
fi
PORT=$(echo "$START_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL=$(echo "$START_OUTPUT" | grep 'URL=' | cut -d'=' -f2-)
SESSION_ID=$(echo "$START_OUTPUT" | grep 'SESSION_ID=' | cut -d'=' -f2)
echo "    Pairing port: $PORT  session: $SESSION_ID"
# require_udp_endpoint=1: this phase is the UDP one, so a QR without `p`/`ip4`
# would prove nothing about UDP delivery.
require_pair_url_v2 "$PAIR_URL" "Phase 1b QR" 1
PAIR_URL=$(pair_url_for_emulator "$PAIR_URL")
echo "    Pairing URL:  $PAIR_URL"
echo "    QR keys (emulator view): v='$(pair_url_param "$PAIR_URL" v)' sid='$(pair_url_param "$PAIR_URL" sid)' pk='$(pair_url_param "$PAIR_URL" pk)' p='$(pair_url_param "$PAIR_URL" p)' ip4='$(pair_url_param "$PAIR_URL" ip4)' ip6='$(pair_url_param "$PAIR_URL" ip6)'"

wait_log_since "$LOG_BASE" "Started pairing session on UDP port ${PORT} (session ${SESSION_ID})" \
    "Phase 1b: the daemon opened the ephemeral UDP pairing socket (port ${PORT}, session ${SESSION_ID})"

WAIT_LOG="${TEST_DIR}/wait_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT" > "$WAIT_LOG" 2>&1 &
WAIT_PID=$!

echo "==> Triggering PairingClient inside Android Emulator..."
AM_LOG="${TEST_DIR}/am_pairing.log"
adb shell "am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_url '$PAIR_URL' \
    -e pairing_username '${TAPAUTH_E2E_PAIRING_USERNAME:-$TEST_USER}' \
    '$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner'" > "$AM_LOG" 2>&1 &
AM_PID=$!

wait "$WAIT_PID" || {
    echo "❌ wait-for-pairing failed. Log:"
    cat "$WAIT_LOG"
    exit 1
}
SAS_CODE=$(grep 'SAS=' "$WAIT_LOG" | cut -d'=' -f2)
if ! printf '%s' "$SAS_CODE" | grep -Eq "$SAS_PATTERN"; then
    echo "❌ ERROR (Phase 1b): the daemon did not display a SAS (got '$SAS_CODE')."
    cat "$WAIT_LOG" || true
    exit 1
fi
echo "    Desktop Derived SAS: $SAS_CODE"

# The approval is held back so the phone's keepalive path is actually exercised:
# after `PairingE2eTest` displays the SAS it approves its own side immediately and
# parks in `awaitProvision`, which rewrites an idle UDP mapping every 1000 ms. The
# harness's hold is exactly that window: QEMU SLIRP drops a UDP mapping after ~4 s
# of silence, so only a hold longer than that proves the keepalives (rather than
# the mapping's freshness) carry the session across to the approval.
#
# `wait-for-pairing` answers as soon as the *daemon* has derived the SAS, not when
# the phone has received and shown it, so the hold must start from the phone's own
# announcement — otherwise the exercised window is `hold − Δ`, not the hold. The
# logcat buffer was cleared at the start of 1b, so this cannot match an older run.
# 100 polls at 0.5 s ≈ 50 s, above the phone's own 30 s response race plus app
# start (see the Phase 1a-iii poll for the same bound).
PHONE_SAS_SEEN=0
for _ in $(seq 1 100); do
    if adb logcat -d 2>/dev/null | grep -q 'ANDROID_DERIVED_SAS='; then
        PHONE_SAS_SEEN=1
        break
    fi
    sleep 0.5
done
if [ "$PHONE_SAS_SEEN" != "1" ]; then
    echo "❌ ERROR (Phase 1b): the phone never announced its derived SAS, so the keepalive window cannot be measured."
    adb logcat -d -v time -s 'PairingSession:*' 'PairingE2eTest:*' 2>/dev/null | tail -n 40 || true
    cat "$AM_LOG" || true
    exit 1
fi
echo "    Phone displayed its derived SAS."
PAIRING_SAS_PAUSE_SECS="${TAPAUTH_E2E_SAS_PAUSE_SECS:-6}"
echo "    Holding the handshake at SAS confirmation for ${PAIRING_SAS_PAUSE_SECS}s (SLIRP UDP mapping keepalive)..."
sleep "$PAIRING_SAS_PAUSE_SECS"

if ! COMPLETE_OUTPUT=$("$CLI_BIN" complete-pairing "$PORT" 2>&1); then
    echo "❌ ERROR (Phase 1b): complete-pairing failed:"
    printf '%s\n' "$COMPLETE_OUTPUT"
    echo "---- ${AM_LOG} ----"
    cat "$AM_LOG" || true
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    exit 1
fi
SERVER_HEX=$(printf '%s\n' "$COMPLETE_OUTPUT" | grep 'SERVER_HEX=' | cut -d'=' -f2)
if ! printf '%s' "$SERVER_HEX" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "❌ ERROR (Phase 1b): complete-pairing did not print a 64-hex SERVER_HEX (got '$SERVER_HEX'):"
    printf '%s\n' "$COMPLETE_OUTPUT"
    exit 1
fi
echo "✅ The desktop approved the SAS and provisioned the CSK (server key $SERVER_HEX)."

wait "$AM_PID" || true
assert_instrument_ok "$AM_LOG" "Phase 1b"
if ! phase_marker "$AM_LOG" 'Pairing completed and persisted'; then
    echo "❌ ERROR (Phase 1b): the phone never logged 'Pairing completed and persisted'."
    cat "$AM_LOG" || true
    exit 1
fi
pairing_sas_match "$SAS_CODE" "$AM_LOG" "Phase 1b"

wait_log_since "$LOG_BASE" 'PairingInit accepted over Udp' \
    "Phase 1b: the daemon accepted the phone's PairingInit over UDP"
wait_log_since "$LOG_BASE" 'SAS confirmed: provisioning the CSK to the phone over Udp' \
    "Phase 1b: the daemon provisioned the CSK over UDP"
wait_log_since "$LOG_BASE" "Pairing complete: phone key ${SERVER_HEX}" \
    "Phase 1b: the daemon proved the CSK to the paired phone key"
wait_log_since "$LOG_BASE" "Paired server ${SERVER_HEX} saved for user" \
    "Phase 1b: the daemon persisted the paired phone"

SERVERS_COUNT=$(servers_count "Phase 1b")
if [ "$SERVERS_COUNT" -lt 1 ]; then
    echo "❌ ERROR: No paired servers recorded in daemon state."
    exit 1
fi
if ! "$CLI_BIN" get-servers | grep -qF "key=${SERVER_HEX}"; then
    echo "❌ ERROR (Phase 1b): get-servers does not list the paired key ${SERVER_HEX}:"
    "$CLI_BIN" get-servers || true
    exit 1
fi
echo "✅ Verified ${SERVERS_COUNT} paired Android device(s), including ${SERVER_HEX}."

# Verify on-disk security properties of the real state directory (systemd mode)
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    echo "==> Verifying state directory security properties..."
    assert_stat /var/lib/tapauth "700 tapauthd tapauthd" "state dir mode/owner"
    assert_stat /run/tapauthd/tapauthd.sock "660 root tapauthd-clients" "IPC socket mode/owner"
    SECURE_FILES=$(find /var/lib/tapauth -maxdepth 1 -type f -perm 600 | wc -l)
    if [ "$SECURE_FILES" -ge 1 ]; then
        echo "✅ Keystore files present with owner-only (600) permissions: $SECURE_FILES file(s)"
    else
        echo "❌ ERROR: expected at least one 600-permission key file under /var/lib/tapauth"
        ls -la /var/lib/tapauth || true
        exit 1
    fi
    LOOSE_FILES=$(find /var/lib/tapauth -type f -perm /go+w 2>/dev/null | wc -l)
    if [ "$LOOSE_FILES" -eq 0 ]; then
        echo "✅ No group/world-writable files in state directory."
    else
        echo "❌ ERROR: found $LOOSE_FILES group/world-writable file(s) in /var/lib/tapauth:"
        find /var/lib/tapauth -type f -perm /go+w
        exit 1
    fi
    phase_pass "1b" "the phone paired over UDP (both sides derived SAS ${SAS_CODE}), the daemon logged PairingInit/SAS-confirm/persist for ${SERVER_HEX}, get-servers lists it, ${SERVERS_COUNT} device(s) were stored, and the state dir/socket modes+owners and 600 file modes held"
else
    phase_pass "1b" "the phone paired over UDP (both sides derived SAS ${SAS_CODE}), the daemon logged PairingInit/SAS-confirm/persist for ${SERVER_HEX}, get-servers lists it, and ${SERVERS_COUNT} device(s) were stored"
fi

# ── 1c: BLE-only pairing over the Bumble /dev/vhci bridge ────────────────────
#
# A v2 QR carrying no `ip4`/`ip6` describes a BLE-only pairing: the phone
# has no address to send PairingInit to, so it scans for the GATT service and
# writes the init to the characteristic instead. `p` is still present — the format
# allows a portless QR, but the daemon always emits its configured UDP port — so
# the strip below removes only the addresses. The Bumble bridge and its
# /dev/vhci adapter were brought up in Step 3, and the daemon advertises on that
# adapter — but only when BLE is enabled in the config it reads at session start.
echo "==> Step 1c: BLE-only pairing over the Bumble /dev/vhci bridge..."
"$CLI_BIN" set-transports --ble true --network true
clear_logcat "Phase 1c"
LOG_BASE=$(wc -l < "$DAEMON_LOG")

if ! START_BLE_OUTPUT=$("$CLI_BIN" start-pairing); then
    echo "❌ ERROR (Phase 1c): start-pairing failed (a previous session may still be active):"
    printf '%s\n' "$START_BLE_OUTPUT"
    exit 1
fi
PORT_BLE=$(echo "$START_BLE_OUTPUT" | grep 'PORT=' | cut -d'=' -f2)
PAIR_URL_BLE=$(echo "$START_BLE_OUTPUT" | grep 'URL=' | cut -d'=' -f2-)
SESSION_ID_BLE=$(echo "$START_BLE_OUTPUT" | grep 'SESSION_ID=' | cut -d'=' -f2)
echo "    Pairing port: $PORT_BLE  session: $SESSION_ID_BLE"
# require_udp_endpoint=0: a BLE-only QR legitimately carries no endpoint.
require_pair_url_v2 "$PAIR_URL_BLE" "Phase 1c QR"
# Strip the endpoints from the QR the phone is given: with no address to reach,
# the phone's UDP candidate is not even started and BLE is the only transport.
PAIR_URL_BLE=$(pair_url_del "$PAIR_URL_BLE" ip4)
PAIR_URL_BLE=$(pair_url_del "$PAIR_URL_BLE" ip6)
if [ -n "$(pair_url_param "$PAIR_URL_BLE" ip4)" ] || [ -n "$(pair_url_param "$PAIR_URL_BLE" ip6)" ]; then
    echo "❌ ERROR (Phase 1c): failed to strip the network endpoints from the QR: $PAIR_URL_BLE"
    exit 1
fi
if [ -z "$(pair_url_param "$PAIR_URL_BLE" p)" ]; then
    echo "❌ ERROR (Phase 1c): the BLE-only QR lost its 'p' parameter: $PAIR_URL_BLE"
    exit 1
fi
echo "    Pairing URL (no endpoints): $PAIR_URL_BLE"
echo "    QR keys: v='$(pair_url_param "$PAIR_URL_BLE" v)' sid='$(pair_url_param "$PAIR_URL_BLE" sid)' pk='$(pair_url_param "$PAIR_URL_BLE" pk)' p='$(pair_url_param "$PAIR_URL_BLE" p)' ip4='$(pair_url_param "$PAIR_URL_BLE" ip4)' ip6='$(pair_url_param "$PAIR_URL_BLE" ip6)'"

wait_log_since "$LOG_BASE" 'Pairing BLE advertisement started (adv_id ' \
    "Phase 1c: the daemon is advertising the pairing over BLE"

WAIT_BLE_LOG="${TEST_DIR}/wait_ble_pairing.log"
"$CLI_BIN" wait-for-pairing "$PORT_BLE" > "$WAIT_BLE_LOG" 2>&1 &
WAIT_BLE_PID=$!

AM_BLE_LOG="${TEST_DIR}/am_ble_pairing.log"
adb shell "am instrument -w \
    -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \
    -e pairing_url '$PAIR_URL_BLE' \
    -e pairing_username '${TAPAUTH_E2E_PAIRING_USERNAME:-$TEST_USER}' \
    '$TEST_PKG/dev.rourunisen.tapauth.crypto.TapAuthTestRunner'" > "$AM_BLE_LOG" 2>&1 &
AM_BLE_PID=$!

wait "$WAIT_BLE_PID" || {
    echo "❌ wait-for-pairing failed (BLE). Log:"
    cat "$WAIT_BLE_LOG"
    # The phone-side evidence matters here: the daemon only knows it never saw a
    # PairingInit, while the phone knows whether it scanned, connected or failed
    # for an adapter/permission reason. Without this dump a BLE regression looks
    # like a daemon hang.
    echo "---- ${AM_BLE_LOG} ----"
    cat "$AM_BLE_LOG" || true
    echo "---- logcat (PairingSession / BlePairingClient / PairingE2eTest) ----"
    adb logcat -d -v time -s 'PairingSession:*' 'BlePairingClient:*' 'PairingE2eTest:*' \
        2>/dev/null | tail -n 200 || true
    echo "---- tail -n 80 ${DAEMON_LOG} ----"
    tail -n 80 "$DAEMON_LOG" || true
    # Three BLE failure modes look identical from the daemon side: the phone never
    # registered a scan, the scan ran and returned nothing, or results arrived and
    # the filter dropped them. The guest's own BLE state separates them.
    echo "--- guest BLE state (dumpsys bluetooth_manager) ---"
    # `dumpsys bluetooth_manager` blocks on the adapter service; `|| true` guards
    # the exit code, not the wall clock (see scripts/ci/setup-emulator-ble-bridge.sh).
    DUMP=$(timeout 20 adb shell dumpsys bluetooth_manager 2>/dev/null || true)
    printf '%s\n' "$DUMP" | head -n 12
    printf '%s\n' "$DUMP" | grep -A 12 'GATT Scanner Map' || true
    adb shell settings get global bluetooth_on 2>/dev/null || true
    adb shell settings get secure location_mode 2>/dev/null || true
    timeout 20 adb shell dumpsys package "$APP_PKG" 2>/dev/null | grep -i 'BLUETOOTH_\|FINE_LOCATION' || true
    exit 1
}
SAS_BLE=$(grep 'SAS=' "$WAIT_BLE_LOG" | cut -d'=' -f2)
if ! printf '%s' "$SAS_BLE" | grep -Eq "$SAS_PATTERN"; then
    echo "❌ ERROR (Phase 1c): the daemon did not display a SAS (got '$SAS_BLE')."
    cat "$WAIT_BLE_LOG" || true
    exit 1
fi
echo "    Desktop Derived SAS: $SAS_BLE"

if ! COMPLETE_BLE_OUTPUT=$("$CLI_BIN" complete-pairing "$PORT_BLE" 2>&1); then
    echo "❌ ERROR (Phase 1c): complete-pairing failed:"
    printf '%s\n' "$COMPLETE_BLE_OUTPUT"
    echo "---- ${AM_BLE_LOG} ----"
    cat "$AM_BLE_LOG" || true
    exit 1
fi
SERVER_HEX_BLE=$(printf '%s\n' "$COMPLETE_BLE_OUTPUT" | grep 'SERVER_HEX=' | cut -d'=' -f2)
if ! printf '%s' "$SERVER_HEX_BLE" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "❌ ERROR (Phase 1c): complete-pairing did not print a 64-hex SERVER_HEX (got '$SERVER_HEX_BLE'):"
    printf '%s\n' "$COMPLETE_BLE_OUTPUT"
    exit 1
fi
echo "✅ The desktop approved over BLE and provisioned the CSK (server key $SERVER_HEX_BLE)."

wait "$AM_BLE_PID" || true
assert_instrument_ok "$AM_BLE_LOG" "Phase 1c"
if ! phase_marker "$AM_BLE_LOG" 'SAS reached the phone over BLE'; then
    echo "❌ ERROR (Phase 1c): the phone did not report the SAS over BLE — this phase must not pass over UDP."
    cat "$AM_BLE_LOG" || true
    exit 1
fi
if ! phase_marker "$AM_BLE_LOG" 'Pairing completed and persisted'; then
    echo "❌ ERROR (Phase 1c): the phone never logged 'Pairing completed and persisted'."
    cat "$AM_BLE_LOG" || true
    exit 1
fi
pairing_sas_match "$SAS_BLE" "$AM_BLE_LOG" "Phase 1c"

wait_log_since "$LOG_BASE" 'PairingInit accepted over Ble' \
    "Phase 1c: the daemon accepted the phone's PairingInit over BLE"
wait_log_since "$LOG_BASE" 'SAS confirmed: provisioning the CSK to the phone over Ble' \
    "Phase 1c: the daemon provisioned the CSK over BLE"
wait_log_since "$LOG_BASE" "Paired server ${SERVER_HEX_BLE}" \
    "Phase 1c: the daemon persisted the paired phone"

# Re-pairing the same emulator reuses its persistent identity key, so the daemon
# overwrites the entry instead of adding one: only "at least one" is meaningful.
# The real BLE proof is the phone's `SAS reached the phone over BLE` marker above.
SERVERS_COUNT=$(servers_count "Phase 1c")
if [ "$SERVERS_COUNT" -lt 1 ]; then
    echo "❌ ERROR (Phase 1c): no paired device recorded after the BLE-only pairing, daemon reports $SERVERS_COUNT."
    exit 1
fi
if ! "$CLI_BIN" get-servers | grep -qF "key=${SERVER_HEX_BLE}"; then
    echo "❌ ERROR (Phase 1c): get-servers does not list the BLE-paired key ${SERVER_HEX_BLE}:"
    "$CLI_BIN" get-servers || true
    exit 1
fi
echo "✅ Verified the BLE-paired device is present (${SERVERS_COUNT}) after the BLE-only pairing."
phase_pass "1c" "with no endpoint in the QR the phone paired over BLE only (both sides derived SAS ${SAS_BLE}), it logged 'SAS reached the phone over BLE', the daemon logged PairingInit/SAS-confirm/persist for ${SERVER_HEX_BLE}, and get-servers lists it"

# Step 5b: Ensure runtime permissions and start Android app/background services
echo "==> Starting Android foreground services for authentication..."
adb shell am force-stop "$APP_PKG" 2>/dev/null || true
# Clear the log buffer so the group-configuration line the next phase asserts on
# is guaranteed to still be present even on a noisy runner (the logcat ring buffer
# can rotate between app start and Phase 2). A rejected clear must fail the run
# rather than be swallowed: the caller-context tokens below carry no per-run
# entropy, so a stale line from an earlier run would satisfy Phase 2/2b/3.
clear_logcat "Phase 2"
adb shell am start -n "$APP_PKG/dev.rourunisen.tapauth.MainActivity"
sleep 2

# Start background biometric auto-grant listener for auth tests
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
sleep 1

# ── Caller-context (protocol v2) helpers ─────────────────────────────────────
#
# Protocol v2 carries the Client's caller context — `pam_service`,
# `process_name`, `command_preview` — so the phone can show what is being
# approved. A daemon-side line only proves a request was *sent*, so every
# assertion below reads the phone's own line instead:
#
#   Auth request caller context: pamService=…, processName=…, commandPreview=…
#
# emitted by AuthRequestManager.submitRequest, the single funnel both transports
# pass through (AuthenticationService for UDP, BleGattService for BLE), so one
# line proves delivery over either transport. Each field is asserted on its own
# so a failure names the field that did not arrive.

# assert_phone_logged <fixed-string> <label>
#
# Fails unless the phone's logcat dump contains <fixed-string>. The whole dump is
# grepped, deliberately not a window anchored to a line count: the logcat ring
# buffer can rotate between taking a mark and checking it, which slides a counted
# window forward and drops a line the phase did emit — a spurious failure. What
# keeps an earlier phase's line from satisfying this assertion is the per-phase
# token in every fixed string below, together with the `clear_logcat` issued
# before the app is started for Phase 2 (see Step 5b), so a stale line cannot
# match and this can only ever fail for a line that is genuinely missing.
#
# The dump is captured into a variable and grepped through a here-string instead
# of being piped straight into `grep -q`: `grep -q` exits at the first match and
# SIGPIPEs the producer, which this script only survives because it does not set
# `pipefail` — under `set -o pipefail` that SIGPIPE would turn a match into a
# failed pipeline. Capturing first keeps the pattern pipefail-safe, and it also
# means one assertion greps one snapshot instead of re-reading logcat mid-write.
assert_phone_logged() {
    local needle=$1 label=$2 dump
    dump=$(adb logcat -d 2>/dev/null || true)
    if grep -qF "$needle" <<< "$dump"; then
        echo "✅ ${label}"
        return 0
    fi
    echo "❌ ERROR (${label}): the phone never logged '${needle}'."
    echo "---- caller-context lines in the phone log ----"
    grep -F 'caller context' <<< "$dump" || true
    exit 1
}

# caller_context_tokens <label>: per-phase context values in CTX_SERVICE,
# CTX_PROCESS, CTX_REQUEST_ID and CTX_CLI.
#
# The tokens are phase-unique ASCII with no control characters, so neither
# sanitiser (Rust on the Client, ContextSanitizer on the phone) can rewrite them
# and a logcat line from an earlier phase cannot satisfy this phase's assertion.
#
# `process_name` needs the copy. The daemon asks the kernel first, in this order:
# `/proc/<pid>/exe` basename, then the `cmdline` `argv[0]` basename, then
# `/proc/<pid>/comm` (tapauthd/src/caller_context.rs:190-194), and falls back to
# the Client's self-report only when none of those three answers (:371-374). The
# first entry is the one `ptrace_may_access` gates, so it is EACCES for another
# UID and `argv[0]` answers in the shipped unit, while `exe` answers in dev mode,
# where the daemon runs as the caller. Invoking a copy of the CLI named after the
# token makes both of those yield the token, and the same token travels as
# `--process-name`. (`comm` would be the kernel's 15-byte truncation of the
# token, but it is never reached while `argv[0]` answers.)
caller_context_tokens() {
    local label=$1
    CTX_SERVICE="e2e-ctx-${label}"
    CTX_PROCESS="e2e-ctx-proc-${label}"
    CTX_REQUEST_ID="e2e-ctx-${label}-$$"
    CTX_CLI="${TEST_DIR}/${CTX_PROCESS}"
    cp -f "$CLI_BIN" "$CTX_CLI"
    chmod +x "$CTX_CLI"
}

# assert_caller_context_preview_readable: fail unless the daemon can read a
# caller's `/proc/<pid>/cmdline` on this host.
#
# `command_preview` is the kernel's `cmdline` split on NUL
# (tapauthd/src/caller_context.rs:304-310) and joined by single spaces
# (:175; the IPC request has no command field), so the assertion below only
# means something if the daemon can read that file. Only
# `readlink(/proc/<pid>/exe)` is gated by `ptrace_may_access`:
# `cmdline` is 0444 and `comm` 0644, world-readable across UIDs. The shipped unit
# runs as `tapauthd` with `CAP_SYS_PTRACE` deliberately absent
# (systemd/tapauthd.service) and still fills the preview in from a root caller,
# which is why comparing the daemon's uid against ours — as this helper used to —
# switched the assertion off in every `systemd` run, i.e. in every run CI makes.
#
# What can still empty the preview for real is a `hidepid=1`/`hidepid=2` procfs
# mount, which hides other users' entries. So probe by *opening* the file as the
# daemon user instead of assuming, and treat a failure as fatal rather than a
# skip: an assertion that turns itself off reports the same green as one that held
# while checking nothing.
#
# The probe pid is this shell's. Every phase invokes the CLI copy (`$CTX_CLI`) or
# `pamtester` from here, so the caller the daemon resolves runs as this same uid
# and a procfs that answers for `$$` answers for it too.
assert_caller_context_preview_readable() {
    local daemon_user probe="/proc/$$/cmdline" readable=0
    if [ "$E2E_DAEMON_MODE" = "dev" ]; then
        # Dev mode starts the daemon from this script, so it runs as this uid.
        daemon_user=$(id -un)
        if cat "$probe" >/dev/null 2>&1; then
            readable=1
        fi
    else
        daemon_user=$(systemctl show -p User --value tapauthd.service 2>/dev/null || true)
        # Older systemctl ignores --value and prints `User=<name>`.
        daemon_user=${daemon_user#User=}
        if [ -z "$daemon_user" ] || ! id -u "$daemon_user" >/dev/null 2>&1; then
            echo "❌ ERROR: cannot resolve the daemon's user from tapauthd.service (got '${daemon_user}')."
            echo "   The unit this suite installs runs as User=tapauthd. Without it the"
            echo "   command_preview assertion cannot be armed, and skipping it would"
            echo "   report a passing run that never checked the preview."
            systemctl cat tapauthd.service --no-pager 2>&1 | head -n 20 || true
            exit 1
        fi
        if runuser -u "$daemon_user" -- cat "$probe" >/dev/null 2>&1; then
            readable=1
        fi
    fi
    if [ "$readable" -ne 1 ]; then
        echo "❌ ERROR: the daemon user '${daemon_user}' cannot read ${probe}."
        echo "   /proc/<pid>/cmdline is mode 0444 and needs no CAP_SYS_PTRACE, so a"
        echo "   cross-uid failure here means procfs hides other users' entries: look"
        echo "   for hidepid=1 / hidepid=2 on the /proc mount (mount | grep ' /proc ')."
        echo "   Fix the mount; this security assertion is not skipped."
        exit 1
    fi
    echo "✅ ${daemon_user} can read ${probe} — command_preview is asserted."
}

# assert_caller_context_delivered <label> <pam_service> <process_name> <preview_argv>
#
# One assertion per field, so a failure names the field that did not arrive.
# <preview_argv> is the argv prefix the phone must show as `command_preview`; the
# daemon truncates that field to 128 bytes, so it is matched as a prefix.
#
# The `commandPreview=` assertion only works against the e2e build variant: the
# app logs the preview's content when BuildConfig.E2E_TESTING is true, which
# app/build.gradle.kts sets for the `e2e` build type alone (false for `release`
# and `debug`), because the desktop's argv can carry credentials such as
# `-p <password>` and Log.d is not stripped from release builds. Shipped builds
# log `commandPreview=<N chars, E2E build only>` instead.
assert_caller_context_delivered() {
    local label=$1 service=$2 process=$3 preview=$4
    assert_phone_logged "pamService=${service}," \
        "${label}: the phone received pam_service='${service}'"
    assert_phone_logged "processName=${process}," \
        "${label}: the phone received process_name='${process}'"
    # Step 2 installs the debug APK when the e2e one is absent, and the debug
    # variant logs the preview's length rather than its content (see above). Only
    # this assertion is skipped: the phases still to come (2b, 3) run against the
    # same package and must not be aborted by a preview the variant cannot print.
    if [ "$APP_PKG" != "dev.rourunisen.tapauth.e2e" ]; then
        echo "ℹ️  ${label}: command_preview content is NOT asserted with package ${APP_PKG}."
        echo "    BuildConfig.E2E_TESTING is true only for the 'e2e' build type; the installed"
        echo "    package logs the preview's length instead of its content."
        echo "    Install the e2e variant to assert it: (cd server-android && ./gradlew assembleE2e)"
        return 0
    fi
    # Only the branch that really asserts may arm the probe: on a `hidepid` host
    # the probe is fatal, and it must not be fatal for an assertion this run does
    # not make.
    assert_caller_context_preview_readable
    assert_phone_logged "commandPreview=${preview}" \
        "${label}: the phone received command_preview beginning '${preview}'"
}

# Step 6: Phase 2 - Local Network (UDP) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2: Local Network (UDP) End-to-End Authentication       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Assert the Android app is configured for the same discovery groups as the
# daemon. The service logs the group pair unconditionally when it starts
# listening (see AuthenticationService.startListening), which makes this a
# config-level check that does not depend on any interface being joinable.
echo "==> Verifying Android app discovery multicast groups..."
ANDROID_GROUPS_OK=0
for _ in $(seq 1 20); do
    if adb logcat -d 2>/dev/null \
        | grep -q "Multicast groups: IPv4=${IPV4_MCAST}, IPv6=${IPV6_MCAST}"; then
        ANDROID_GROUPS_OK=1
        break
    fi
    sleep 0.5
done
if [ "$ANDROID_GROUPS_OK" = "1" ]; then
    echo "✅ Android AuthenticationService uses IPv4=${IPV4_MCAST}, IPv6=${IPV6_MCAST}."
else
    echo "❌ ERROR: Android app did not log the expected discovery multicast groups."
    adb logcat -d -v time -s AuthenticationService:* 2>/dev/null | tail -n 40 || true
    exit 1
fi

echo "==> Setting transport config: UDP enabled, BLE disabled..."
"$CLI_BIN" set-transports --ble false --network true

# Verify the daemon persisted the toggle to the REAL config file and that the
# file has the production mode/ownership (systemd mode).
echo "==> Verifying persisted config file..."
if grep -q 'enable_network = true' "$CONFIG_ASSERT_FILE" && grep -q 'enable_ble = false' "$CONFIG_ASSERT_FILE"; then
    echo "✅ Transport toggles persisted to ${CONFIG_ASSERT_FILE}."
else
    echo "❌ ERROR: transport toggles not found in ${CONFIG_ASSERT_FILE}:"
    cat "$CONFIG_ASSERT_FILE" || true
    exit 1
fi
if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    assert_stat "$CONFIG_ASSERT_FILE" "644 tapauthd tapauthd" "config file mode/owner"
fi

# Capture UDP traffic while the legitimate grant is exchanged; the adversarial
# phases (2c/2d) replay/tamper this captured grant against a fresh session.
# The capture is a passive AF_PACKET sniffer (root-only) — see udp_attack.py
# sniff for why this replaces tcpdump.
CAPTURE_MANDATORY=0
if [ "$(id -u)" -eq 0 ]; then
    CAPTURE_MANDATORY=1
    echo "==> Starting UDP packet capture (AF_PACKET sniffer)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" sniff --port "$UDP_PORT" --duration 30 \
        > "$TEST_DIR/grants.hex" 2> "$TEST_DIR/sniff.err" &
    CAPTURE_PID=$!

    # Independently observe the daemon's discovery traffic on the wire so we can
    # prove it targets the custom multicast groups (rather than 255.255.255.255
    # / ff02::1). This works even though the emulator delivery goes through the
    # dev-udp-loopback shim rather than real LAN multicast.
    echo "==> Starting multicast-group egress watcher (IPv4 ${IPV4_MCAST}, IPv6 ${IPV6_MCAST})..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" watch-groups \
        --ipv4 "$IPV4_MCAST" --ipv6 "$IPV6_MCAST" --port "$UDP_PORT" --duration 30 \
        > "$TEST_DIR/groups.txt" 2> "$TEST_DIR/groups.err" &
    GROUPS_PID=$!

    # Wait until the watcher has opened its capture sockets so the first
    # transmission cannot race past it (retransmissions would usually cover it,
    # but a single-shot send should not depend on that).
    for _ in $(seq 1 50); do
        grep -q '^READY$' "$TEST_DIR/groups.txt" 2>/dev/null && break
        sleep 0.1
    done
fi

echo "==> Requesting authentication for user '$TEST_USER'..."
# The request carries a protocol-v2 caller context so the phone-side assertions
# below have something to check (see the caller-context helpers above). The
# request id is passed explicitly because it also appears in the expected
# command preview.
# The log offset is taken before the request so the transport attribution below
# is scoped to this phase's session (the same window idiom Phase 2d uses).
LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
caller_context_tokens "udp"
UDP_AUTH_OUTPUT=$("$CTX_CLI" pam-auth "$TEST_USER" 20 "$CTX_REQUEST_ID" \
    --pam-service "$CTX_SERVICE" --process-name "$CTX_PROCESS" || true)
echo "$UDP_AUTH_OUTPUT"

if echo "$UDP_AUTH_OUTPUT" | grep -q 'OUTCOME=SUCCESS'; then
    echo "✅ Local Network (UDP) Authentication PASSED!"
else
    echo "❌ Local Network (UDP) Authentication FAILED."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# The grant above proves *something* answered; it does not prove the phone ever
# received the caller context, which is what protocol v2 added. Assert the three
# fields on the phone itself, over this (UDP-only) transport.
assert_caller_context_delivered "Phase 2 (UDP)" \
    "$CTX_SERVICE" "$CTX_PROCESS" \
    "${CTX_CLI} pam-auth ${TEST_USER} 20 ${CTX_REQUEST_ID}"

# ...and assert the grant came over the transport this phase left enabled.
# `enable_ble = false` above is only a line in config.toml until a grant arrives
# on the transport the daemon actually used: a daemon that ignores the toggle and
# rings the phone over BLE passes every assertion above, because OUTCOME=SUCCESS
# says nothing about which transport delivered it. This is the same assertion
# Phase 2d makes (grant_transport_since + a required transport name), with the
# expected winner kept as Udp.
sleep 1
PHASE2_TRANSPORT=$(grant_transport_since "$LOG_BASE")
if [ "$PHASE2_TRANSPORT" != "Udp" ]; then
    echo "❌ ERROR: expected the grant to be attributed to Udp, got '${PHASE2_TRANSPORT}'."
    tail -n +"$((LOG_BASE + 1))" "$DAEMON_LOG" 2>/dev/null | tail -n 20
    exit 1
fi
echo "✅ Phase 2 grant attributed to Udp (BLE is disabled for this phase)."
phase_pass "2" "pam-auth returned OUTCOME=SUCCESS, the daemon attributed the grant to Udp (so the enable_ble=false toggle is verified behaviourally), and the phone logged the v2 caller context for this request (pam_service='${CTX_SERVICE}', process_name='${CTX_PROCESS}', and command_preview when the e2e build variant is installed)"

# Stop capture and take the first captured server grant packet
CAPTURE_OK=0
GRANT_HEX=""
if [ -n "$CAPTURE_PID" ]; then
    kill "$CAPTURE_PID" 2>/dev/null || true
    wait "$CAPTURE_PID" 2>/dev/null || true
    CAPTURE_PID=""
    GRANT_HEX=$(head -n1 "$TEST_DIR/grants.hex" 2>/dev/null || true)
    [ -n "$GRANT_HEX" ] && CAPTURE_OK=1
fi

if [ "$CAPTURE_OK" = "1" ]; then
    echo "✅ Captured a server grant packet (${#GRANT_HEX} hex chars) for adversarial phases."
elif [ "$CAPTURE_MANDATORY" = "1" ]; then
    echo "❌ ERROR: packet capture produced no server grant packet — cannot run adversarial phases."
    echo "   (This is mandatory when running as root, e.g. CI.)"
    echo "--- sniffer stderr:"; cat "$TEST_DIR/sniff.err" 2>/dev/null || true
    echo "--- captured lines: $(wc -l < "$TEST_DIR/grants.hex" 2>/dev/null || echo 0)"
    exit 1
else
    echo "ℹ️  Adversarial UDP phases will be skipped (not running as root)."
fi

# Verify the daemon actually emitted discovery packets to the configured
# multicast groups. The watcher only records a family when it observes an
# EncryptedPacket addressed to that group on the wire.
if [ -n "$GROUPS_PID" ]; then
    kill "$GROUPS_PID" 2>/dev/null || true
    wait "$GROUPS_PID" 2>/dev/null || true
    GROUPS_PID=""
    echo "==> Multicast-group egress observations:"
    cat "$TEST_DIR/groups.txt" 2>/dev/null || true
    if grep -q "^SEEN_IPV4 ${IPV4_MCAST}$" "$TEST_DIR/groups.txt" 2>/dev/null; then
        echo "✅ Daemon emitted an EncryptedPacket to the IPv4 discovery group ${IPV4_MCAST}."
    else
        echo "❌ ERROR: no EncryptedPacket observed for IPv4 group ${IPV4_MCAST}."
        echo "--- watcher stderr:"; cat "$TEST_DIR/groups.err" 2>/dev/null || true
        exit 1
    fi
    if grep -q "^SEEN_IPV6 ${IPV6_MCAST}$" "$TEST_DIR/groups.txt" 2>/dev/null; then
        echo "✅ Daemon emitted an EncryptedPacket to the IPv6 discovery group ${IPV6_MCAST}."
    else
        echo "❌ ERROR: no EncryptedPacket observed for IPv6 group ${IPV6_MCAST}."
        echo "--- watcher stderr:"; cat "$TEST_DIR/groups.err" 2>/dev/null || true
        echo "--- host IPv6 addresses:"; ip -6 addr show 2>/dev/null || true
        exit 1
    fi
    phase_pass "2-mcast" "the daemon emitted an EncryptedPacket to IPv4 ${IPV4_MCAST} and to IPv6 ${IPV6_MCAST} (observed on the wire, not just configured)"
else
    echo "ℹ️  Multicast-group egress verification skipped (not running as root)."
    phase_skip "2-mcast" "not running as root, so the AF_PACKET egress watcher that observes the discovery groups cannot be started"
fi

# Step 6b: Phase 2b - Real PAM Module Authentication (pamtester)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2b: Real PAM Module Authentication (pamtester)         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

sleep 3
# NOTE: same-user PAM auths that start within 1s of each other are
# deduplicated (the second is answered with Ignore, single-broadcast rule).
# All sleeps below that separate sequential same-user auth phases exist to
# keep them safely outside that dedup window.

# Wait out the 1s same-user dedup window left by the previous auth phase
# ($1 = previous phase label, logged for context; $2 = sleep seconds, default 3).
settle_for_dedup() {
    if [ -n "${1:-}" ]; then
        echo "    (settling after $1 to clear the 1s same-user dedup window)"
    fi
    sleep "${2:-3}"
}

PAM_TESTABLE="false"
if command -v pamtester >/dev/null 2>&1 && [ -w /etc/pam.d ] && [ -f "$PAM_LIB" ]; then
    PAM_TESTABLE="true"
fi

if [ "$PAM_TESTABLE" = "true" ]; then
    echo "==> Configuring temporary PAM service at ${PAM_CONFIG_PATH}..."
    printf 'auth required %s\naccount required pam_permit.so\n' "$PAM_LIB" > "$PAM_CONFIG_PATH"

    echo "==> Executing pamtester for user '$TEST_USER'..."
    set +e
    # stdin = an open pipe that never delivers data: the module's credential
    # dialog must stay ALIVE for the phone-grant path to run. An EOF (e.g.
    # /dev/null) dismisses the dialog and cancels the transaction by design.
    "${PAM_ENV[@]}" pamtester "$PAM_SERVICE_NAME" "$TEST_USER" authenticate < <(sleep 30)
    PAM_EXIT=$?
    set -e

    rm -f "$PAM_CONFIG_PATH"

    if [ "$PAM_EXIT" -eq 0 ]; then
        echo "✅ Real PAM Module Authentication PASSED (exit code: $PAM_EXIT)!"
    else
        echo "❌ Real PAM Module Authentication FAILED (exit code: $PAM_EXIT)."
        exit 1
    fi

    # The exit code only says the module returned success. This is the one phase
    # that exercises the *shipped* caller: libpam loaded into `pamtester`, so it
    # also has to prove the module projected the caller context onto the wire and
    # that the phone received it — `pam_service` as libpam spelled it, and
    # `process_name` as this process's own image (the daemon's kernel view and the
    # module's self-report agree on that name, so the assertion holds either way).
    assert_caller_context_delivered "Phase 2b (PAM module)" \
        "$PAM_SERVICE_NAME" "pamtester" \
        "pamtester ${PAM_SERVICE_NAME} ${TEST_USER} authenticate"
    phase_pass "2b" "pamtester exited ${PAM_EXIT} with the real pam_tapauth.so in the stack, and the phone received the shipped module's caller context (pam_service='${PAM_SERVICE_NAME}', process_name='pamtester')"

    # Phase 2e: mixed-stack semantics — a REAL PAM stack where TapAuth's
    # PAM_AUTHINFO_UNAVAIL is expanded to `ignore` by the [success=1
    # default=ignore] flag below, so it falls through to pam_unix, and a grant
    # must skip it.
    #
    # NOTE 1: the module deliberately yields as soon as an authtok is available
    # ("password submission takes absolute precedence over any concurrent
    # daemon response"), so the grant path below holds stdin open WITHOUT data.
    # NOTE 2: the [success=1] jump MUST land on the trailing pam_permit line —
    # a jump that overshoots the end of the stack makes Linux-PAM return
    # PAM_PERM_DENIED even though the module succeeded.
    echo ""
    echo "==> Phase 2e: Mixed-stack PAM semantics (grant skips password, skip verdict falls back)..."
    # Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 2b).
    settle_for_dedup "Phase 2b"
    printf 'auth [success=1 default=ignore] %s\nauth required pam_unix.so nullok\nauth required pam_permit.so\naccount required pam_permit.so\n' "$PAM_LIB" > "$PAM_MIXED_CONFIG_PATH"

    set +e
    "${PAM_ENV[@]}" pamtester "$PAM_MIXED_SERVICE_NAME" "$TEST_USER" authenticate < <(sleep 30)
    MIXED_GRANT_EXIT=$?
    set -e

    if [ "$MIXED_GRANT_EXIT" -eq 0 ]; then
        echo "✅ Grant path: TapAuth SUCCESS bypassed the password module in a mixed stack."
        phase_pass "2e" "a TapAuth grant in a [success=1 default=ignore] mixed stack bypassed pam_unix and the stack returned ${MIXED_GRANT_EXIT}"
    else
        echo "❌ ERROR: mixed-stack grant path failed (exit $MIXED_GRANT_EXIT)."
        exit 1
    fi
else
    echo "ℹ️  Real PAM module testing skipped (/etc/pam.d not writable or pamtester missing)."
    phase_skip "2b" "pamtester missing, pam_tapauth.so absent, or /etc/pam.d not writable"
    phase_skip "2e" "pamtester missing, pam_tapauth.so absent, or /etc/pam.d not writable"
fi

# Helper: assert a pattern is present in the daemon log AFTER a given line
# offset (window-scoped, so stale matches from earlier phases don't count).
assert_log_since() {
    local base=$1 pattern=$2 label=$3
    if tail -n +"$((base + 1))" "$DAEMON_LOG" 2>/dev/null | grep -q "$pattern"; then
        echo "✅ ${label}"
    else
        echo "❌ ERROR (${label}): pattern '$pattern' not found in the daemon log for this phase."
        exit 1
    fi
}

# Print the transport named by the newest "Authentication granted over …" line
# after a given line offset, or nothing when that window holds none.
grant_transport_since() {
    local base=$1
    tail -n +"$((base + 1))" "$DAEMON_LOG" 2>/dev/null \
        | grep -o "Authentication granted over [A-Za-z]*" \
        | tail -n 1 \
        | awk '{print $NF}'
}

# ── BLE scan resiliency helpers ───────────────────────────────────────────────
#
# Phases 3 and 4 depend on the Android app's hardware-offloaded (PendingIntent)
# BLE scan, which the foreground service registers once at startup. On the
# emulator that registration can silently stop delivering results after the
# preceding UDP / PAM / adversarial churn: the daemon advertises over HCI (the
# Bumble bridge logs the advertisement commands), but the app never receives a
# scan result and the phase times out. Force-stopping and relaunching the app
# re-registers the scan; a bounded retry keeps this environmental flake from
# failing the whole suite. Product regressions still fail, because every phase
# must ultimately succeed.
BLE_MAX_ATTEMPTS="${BLE_MAX_ATTEMPTS:-3}"

restart_android_app_for_ble() {
    adb shell am force-stop "$APP_PKG" 2>/dev/null || true

    # Record the log offset so only lines emitted after the restart are matched
    # (a stale "BLE PendingIntent scanning started" must not count).
    local base
    base=$(adb logcat -d 2>/dev/null | wc -l)

    adb shell am start -n "$APP_PKG/dev.rourunisen.tapauth.MainActivity" >/dev/null 2>&1 || true

    local deadline=$((SECONDS + 15))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if adb logcat -d 2>/dev/null | tail -n +"$((base + 1))" \
            | grep -q "BLE PendingIntent scanning started"; then
            echo "    Android BLE scan re-registered."
            sleep 1
            return 0
        fi
        sleep 0.25
    done
    echo "    ⚠️  Did not observe the Android BLE scan re-register within 15s; continuing anyway."
    sleep 1
    return 0
}

# Authenticate over the currently-configured transport(s), retrying with an app
# restart a bounded number of times. Returns 0 on success; returns 1 after the
# final attempt so the caller can dump diagnostics and fail the phase.
#
# Optional: `authenticate_with_ble_retry <label> [cli] [extra pam-auth args…]`,
# so a phase can send a caller context through a copy of the CLI (Phase 3 does;
# see caller_context_tokens). Without them the behaviour is unchanged.
authenticate_with_ble_retry() {
    local label="$1"
    local cli="${2:-$CLI_BIN}"
    local -a extra=("${@:3}")
    local attempt output
    for ((attempt = 1; attempt <= BLE_MAX_ATTEMPTS; attempt++)); do
        echo "==> ${label}: BLE authentication attempt ${attempt}/${BLE_MAX_ATTEMPTS}..."
        output=$("$cli" pam-auth "$TEST_USER" 30 "${extra[@]}" || true)
        echo "$output"
        if echo "$output" | grep -q 'OUTCOME=SUCCESS'; then
            return 0
        fi
        echo "⚠️  ${label}: attempt ${attempt}/${BLE_MAX_ATTEMPTS} did not succeed."
        if [ "$attempt" -lt "$BLE_MAX_ATTEMPTS" ]; then
            echo "    Restarting Android app to re-register the BLE scan, then retrying..."
            restart_android_app_for_ble
        fi
    done
    return 1
}

# Step 6c: Phase 2c - Adversarial UDP: Replay of a captured grant + PamCancel
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2c: Adversarial UDP (Replay) & PamCancel IPC           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$CAPTURE_OK" = "1" ]; then
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
    # Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 2e).
    settle_for_dedup "Phase 2e"

    # Timing note: on images where real enrollment is unavailable (API 36+;
    # emulator-bio-helper.sh setup falls back to leaving no biometrics
    # enrolled), the E2E app build auto-approves a request after
    # AuthRequestManager.DEBUG_AUTO_APPROVE_DELAY_MS (1s) plus prompt
    # overhead. Injections and the cancel below deliberately land inside that
    # window while the session is still pending.
    LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
    REPLAY_REQUEST_ID="e2e-replay-$$"
    echo "==> Starting auth session (request id $REPLAY_REQUEST_ID) with no grant expected..."
    REPLAY_LOG="${TEST_DIR}/replay-cli.log"
    "$CLI_BIN" pam-auth "$TEST_USER" 30 "$REPLAY_REQUEST_ID" > "$REPLAY_LOG" 2>&1 &
    REPLAY_CLI_PID=$!
    sleep 0.3

    echo "==> Injecting captured grant from an OLD session (challenge mismatch expected)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send "$GRANT_HEX" --port "$UDP_PORT"
    sleep 0.2
    echo "==> Re-injecting the SAME grant (same-session nonce cache expected)..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send "$GRANT_HEX" --port "$UDP_PORT"
    sleep 0.1

    echo "==> Cancelling the pending session via IPC before the app's auto-approval fires..."
    "$CLI_BIN" pam-cancel "$REPLAY_REQUEST_ID" "e2e-test" | tee "${TEST_DIR}/cancel.log"
    if ! grep -q "DETAIL=Cancel forwarded" "${TEST_DIR}/cancel.log"; then
        echo "❌ ERROR: daemon did not accept the cancel (no matching pending request)."
        exit 1
    fi
    # Give the journal follower time to deliver the daemon's audit lines.
    sleep 1

    assert_log_since "$LOG_BASE" "Grant challenge verification failed" \
        "Daemon rejected a grant whose challenge belongs to another session"
    assert_log_since "$LOG_BASE" "Replayed packet detected" \
        "Daemon nonce cache detected the duplicate packet"

    CANCEL_START=$SECONDS
    set +e
    wait_pid_with_timeout "$REPLAY_CLI_PID" 15
    REPLAY_EXIT=$?
    set -e
    CANCEL_ELAPSED=$(( SECONDS - CANCEL_START ))

    cat "$REPLAY_LOG"
    if [ "$REPLAY_EXIT" -ne 0 ] && grep -q "OUTCOME=IGNORE" "$REPLAY_LOG"; then
        echo "✅ Pending authentication was cancelled via IPC (OUTCOME=IGNORE, waited ${CANCEL_ELAPSED}s for the process)."
    else
        echo "❌ ERROR: expected cancelled session to exit with OUTCOME=IGNORE (rc=$REPLAY_EXIT)."
        exit 1
    fi

    # Restore auto-grant for the following positive phases
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
    sleep 1
    phase_pass "2c" "the replayed grant failed challenge verification, the nonce cache detected the duplicate replay, and pam-cancel ended the pending session with OUTCOME=IGNORE"
else
    echo "ℹ️  SKIPPED (no captured grant packet available)."
    phase_skip "2c" "no captured server grant packet available (packet capture needs root)"
fi

# Step 6d: Phase 2d - Adversarial UDP: a tampered datagram must not end the
# session, and must never authenticate on its own. The rule under test is the
# one `fix(net)` established: an attempt concludes only on (a) a valid,
# cryptographically verified response from an authorised server, (b) its own
# deadline, or (c) an explicit local cancel or user denial. A tampered frame is
# none of those, so it is dropped and the attempt keeps waiting for the answer
# the phone really sends — which is what makes this phase stronger than the
# fail-closed shape it replaced: passing now requires the injection to be
# dropped *and* the genuine grant to still authenticate.
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 2d: Adversarial UDP (Tampered Ciphertext)              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$CAPTURE_OK" = "1" ]; then
    # Auto-grant stays ON for this whole phase (unlike Phase 2c, which pauses it
    # so nothing answers): the phone's real grant landing after the injection is
    # half of what is asserted. `start-auto-grant` is not idempotent — a second
    # listener would double every touch — and Phase 2c left the one listener
    # running, so restore it only if it is actually gone.
    if [ ! -f /tmp/bio-auto-grant.pid ] \
        || ! kill -0 "$(cat /tmp/bio-auto-grant.pid)" 2>/dev/null; then
        "$SCRIPT_DIR/ci/emulator-bio-helper.sh" start-auto-grant
        sleep 1
    fi
    # Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 2c).
    settle_for_dedup "Phase 2c"

    LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
    TAMPER_REQUEST_ID="e2e-tamper-$$"
    echo "==> Starting auth session (request id $TAMPER_REQUEST_ID); auto-grant will answer it..."
    TAMPER_LOG="${TEST_DIR}/tamper-cli.log"
    "$CLI_BIN" pam-auth "$TEST_USER" 30 "$TAMPER_REQUEST_ID" > "$TAMPER_LOG" 2>&1 &
    TAMPER_CLI_PID=$!
    # Inject inside the pre-grant window (DEBUG_AUTO_APPROVE_DELAY_MS is 1s), so
    # the corrupted frame reaches the daemon before the phone's real grant does.
    sleep 0.4

    echo "==> Injecting grant with a flipped AES-GCM tag byte..."
    "$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send "$GRANT_HEX" --port "$UDP_PORT" --corrupt

    # The injection above is the expensive half of this attack: it needs a
    # captured grant and the CSK to look authentic enough to reach decryption.
    # The cheaper one needs neither — a datagram that is not a protobuf at all.
    # It is dropped a layer lower (shared/src/network/udp.rs:706-717, before any
    # crypto runs) and counted by a different counter from the AEAD drop above,
    # so it gets its own assertion below. Sent in the same pre-grant window, so
    # the session is still pending when it lands.
    echo "==> Injecting a non-protobuf datagram (no key, no captured packet)..."
    GARBAGE_OUT=$("$PYTHON_BIN" "$SCRIPT_DIR/ci/udp_attack.py" send --garbage --port "$UDP_PORT")
    echo "$GARBAGE_OUT"
    GARBAGE_LEN=$(printf '%s\n' "$GARBAGE_OUT" | sed -n 's/^GARBAGE_LEN=\([0-9][0-9]*\)$/\1/p' | head -n1)
    if [ -z "$GARBAGE_LEN" ]; then
        echo "❌ ERROR: udp_attack.py send --garbage did not print GARBAGE_LEN, so the drop cannot be attributed."
        exit 1
    fi

    set +e
    wait_pid_with_timeout "$TAMPER_CLI_PID" 15
    TAMPER_EXIT=$?
    set -e
    # Give the journal follower time to deliver the daemon's audit lines.
    sleep 1
    cat "$TAMPER_LOG"

    # The tampered frame keeps protobuf framing and the temporal identifier and
    # only fails AEAD, so the daemon must reach decryption and drop it there.
    # That warn is the aggregate drop warning: it carries the phrase on its first
    # occurrence and is then rate-limited to one per 60 s (DROP_WARN_INTERVAL in
    # tapauthd/src/auth_handler.rs), with per-drop detail at debug. This phase's
    # injection is the only frame in the run that fails AEAD, so the first
    # occurrence is this one.
    assert_log_since "$LOG_BASE" "Failed to decrypt response packet" \
        "Daemon dropped the tampered datagram instead of treating it as a response (audit trail present)"

    # The non-protobuf frame never reaches AEAD: `receive_udp_packet` fails the
    # decode and calls `record_dropped_datagram` (shared/src/network/udp.rs:77-82),
    # whose per-frame line names the byte length it was handed. That length is
    # this harness's own GARBAGE_PAYLOAD size, printed by the helper above, so the
    # line can only be this injection. The per-frame line is asserted rather than
    # the aggregate warn beside it, which is rate limited to one per 60 s and
    # therefore not deterministic. Note that "unusable UDP datagram" (this
    # counter) and "unauthenticated frame(s)" (the AEAD counter above) are
    # deliberately different strings: one drop must not satisfy both assertions.
    assert_log_since "$LOG_BASE" \
        "Dropped a datagram from .* (${GARBAGE_LEN} bytes)" \
        "Daemon dropped the non-protobuf datagram before any crypto ran (${GARBAGE_LEN}-byte frame)"

    # The dropped frame must not conclude anything: the session is still waiting,
    # so the auto-granted grant that follows still authenticates it.
    if grep -q "OUTCOME=SUCCESS" "$TAMPER_LOG"; then
        echo "✅ Tampered datagram dropped; the phone's real grant still authenticated the session (OUTCOME=SUCCESS)."
    else
        echo "❌ ERROR: expected the dropped injection to leave the session waiting for the real grant (OUTCOME=SUCCESS)."
        exit 1
    fi
    if [ "$TAMPER_EXIT" -eq 0 ]; then
        echo "✅ Exit code 0 — the session concluded on the phone's verified grant."
    else
        echo "❌ ERROR: an arbitrary datagram must not end the attempt; pam-auth exited ${TAMPER_EXIT}."
        exit 1
    fi
    # ...and it concluded over the transport the tampered frame arrived on: BLE
    # is disabled for this phase (`set-transports --ble false --network true`
    # above), so a drop that cost the UDP path its grant could not be papered
    # over by the other transport.
    TAMPER_TRANSPORT=$(grant_transport_since "$LOG_BASE")
    if [ "$TAMPER_TRANSPORT" != "Udp" ]; then
        echo "❌ ERROR: expected the grant to be attributed to Udp, got '${TAMPER_TRANSPORT}'."
        tail -n +"$((LOG_BASE + 1))" "$DAEMON_LOG" 2>/dev/null | tail -n 20
        exit 1
    fi

    phase_pass "2d" "the corrupted grant was dropped rather than answered (the daemon logged the decryption failure and kept waiting), a non-protobuf datagram was dropped one layer lower without needing any key, and the phone's real grant then authenticated the session over Udp (OUTCOME=SUCCESS, exit code ${TAMPER_EXIT})"
else
    echo "ℹ️  SKIPPED (no captured grant packet available)."
    phase_skip "2d" "no captured server grant packet available (packet capture needs root)"
fi


# Step 7: Phase 3 - Bluetooth Low Energy (BLE) Authentication
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 3: Bluetooth Low Energy (BLE) Authentication           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 2d).
settle_for_dedup "Phase 2d"

# The virtual HCI adapter has already been set up by
# setup-emulator-ble-bridge.sh: on the host directly, and inside the systemd
# containers via its external-bridge mode (the host runs the Bumble bridge, the
# container's own bluetoothd owns the adapter). Either way, an unreachable
# BlueZ is a real failure, not something to skip silently.
if ! command -v dbus-send >/dev/null 2>&1; then
    echo "❌ ERROR: 'dbus-send' is not installed, so BlueZ reachability cannot be verified."
    echo "   Install dbus (which provides dbus-send) and re-run: BLE is the only"
    echo "   end-to-end verification of that transport, so it cannot be skipped."
    exit 1
elif ! dbus-send --system --dest=org.bluez / org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1; then
    echo "❌ ERROR: System D-Bus / BlueZ is not reachable."
    echo "   BLE is the only end-to-end verification of that transport; refusing to skip."
    exit 1
fi

# Refresh the Android BLE scan before the BLE phases: the preceding UDP/PAM
# churn can leave the offloaded scan silently dead (#133). Retry a bounded
# number of times.
echo "==> Refreshing Android BLE scan registration before the BLE phases..."
restart_android_app_for_ble

echo "==> Setting transport config: BLE enabled, UDP disabled..."
"$CLI_BIN" set-transports --ble true --network false

LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
echo "==> Requesting authentication for user '$TEST_USER' over virtual BLE..."
# The same protocol-v2 caller context as Phase 2, now carried over BLE (UDP is
# switched off above, so a phone-side line here can only have arrived over BLE).
caller_context_tokens "ble"
if authenticate_with_ble_retry "Bluetooth Low Energy (BLE) Authentication" "$CTX_CLI" \
    "$CTX_REQUEST_ID" --pam-service "$CTX_SERVICE" --process-name "$CTX_PROCESS"; then
    # UDP is switched off above, so `OUTCOME=SUCCESS` alone does not prove BLE did
    # anything — it only proves *something* satisfied the request. The daemon names
    # the transport that carried the grant, and this phase requires it to say Ble:
    # a dead BLE path that falls back to another transport (or to a stale session)
    # must fail here, which is what the earlier blind spot hid.
    sleep 1
    assert_log_since "$LOG_BASE" "Authentication granted over Ble" \
        "Daemon reports the grant was delivered over BLE"
    assert_caller_context_delivered "Phase 3 (BLE)" \
        "$CTX_SERVICE" "$CTX_PROCESS" \
        "${CTX_CLI} pam-auth ${TEST_USER} 30 ${CTX_REQUEST_ID}"
    echo "✅ Bluetooth Low Energy (BLE) Authentication PASSED!"
    phase_pass "3" "with UDP disabled, pam-auth returned OUTCOME=SUCCESS, the daemon attributed the grant to Ble, and the phone logged the v2 caller context for this request"
else
    echo "❌ Bluetooth Low Energy (BLE) Authentication FAILED after ${BLE_MAX_ATTEMPTS} attempts."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Step 8: Phase 4 - Parallel Discovery Race (Both Enabled)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 4: Parallel Discovery Race (UDP + BLE Simultaneous)    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 3).
settle_for_dedup "Phase 3"

echo "==> Setting transport config: Both BLE and UDP enabled..."
"$CLI_BIN" set-transports --ble true --network true

LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
# The phase-3 style caller context is used here for one extra reason: its
# per-phase token is what the prompt count below counts. Both transports funnel
# through AuthRequestManager.submitRequest, which logs that line once per prompt
# it raises (server-android/.../service/AuthRequestManager.kt:168-175), so the
# token counts prompts for this phase's request and no earlier phase's line can
# satisfy it.
caller_context_tokens "race"
if authenticate_with_ble_retry "Parallel Discovery Race Authentication" "$CTX_CLI" \
    "$CTX_REQUEST_ID" --pam-service "$CTX_SERVICE" --process-name "$CTX_PROCESS"; then
    # The race is decided by whichever transport answers first, so requiring a
    # particular winner would encode a scheduling accident. What must hold is that
    # the daemon named one: with both transports live, "passed" is only meaningful
    # if a grant was actually attributed to a transport.
    sleep 1
    GRANT_TRANSPORT=$(grant_transport_since "$LOG_BASE")
    if [ -z "$GRANT_TRANSPORT" ]; then
        echo "❌ ERROR: the daemon logged no 'Authentication granted over …' line for this phase."
        tail -n +"$((LOG_BASE + 1))" "$DAEMON_LOG" 2>/dev/null | tail -n 20
        exit 1
    fi
    echo "ℹ️  Parallel race: the grant arrived over ${GRANT_TRANSPORT} (either winner is a pass by design)."

    # A named winner says nothing about the loser having been *tried*: a daemon
    # that serves this phase over UDP alone, or over BLE alone, names a transport
    # too. Both transports must have participated, and each half is asserted
    # separately so a failure names the one that did not:
    #   * the BLE advertisement for the session was registered with BlueZ
    #     (tracing::trace! in start_advertising, tapauthd/src/transport/ble.rs:671);
    #   * the request went out to the IPv4 discovery group
    #     (tracing::trace!, shared/src/network/udp.rs:461).
    # Both are LOGGED facts, not timing ones, and neither depends on which
    # transport won. The two lines are at TRACE, which the daemon's E2E log filter
    # raises for these two targets only (see E2E_TRACE_TARGETS above).
    assert_log_since "$LOG_BASE" "BLE advertising started" \
        "Daemon registered the BLE advertisement for this session (BLE participated in the race)"
    # The only other IPv4 send this window can hold is the AuthenticationCancel a
    # BLE winner multicasts through the same helper, so this line cannot be
    # produced by a session in which neither transport ran.
    assert_log_since "$LOG_BASE" "Sent IPv4 multicast on" \
        "Daemon sent the request to the IPv4 discovery group over UDP (UDP participated in the race)"

    # ...and the phone must have been asked exactly once for this request: the
    # daemon opening one session per transport (two challenges) would ring it
    # twice, and the phone only collapses *the same challenge* seen on both
    # transports (TransportLockManager.tryClaimTransport,
    # server-android/.../service/TransportLockManager.kt:38-79). The dump is
    # grepped whole rather than through a line-offset window, for the reason the
    # Phase 2 caller-context helpers give: the logcat ring buffer can rotate
    # between taking a mark and checking it.
    RACE_DUMP=$(adb logcat -d 2>/dev/null || true)
    RACE_PROMPTS=$(grep -cF "pamService=${CTX_SERVICE}," <<< "$RACE_DUMP" || true)
    RACE_PROMPTS=${RACE_PROMPTS:-0}
    if [ "$RACE_PROMPTS" -ne 1 ]; then
        echo "❌ ERROR: expected exactly one prompt on the phone for this request, saw ${RACE_PROMPTS}."
        echo "   Two prompts for one request mean the daemon opened a session per transport. A second"
        echo "   prompt carrying the SAME challenge instead means a released-challenge re-prompt"
        echo "   after a BLE disconnect (the BleDisconnectGrace path), not a duplicate request."
        echo "---- prompts carrying this phase's caller-context token ----"
        grep -F "pamService=${CTX_SERVICE}," <<< "$RACE_DUMP" || true
        echo "---- every prompt the phone logged (compare the challenge= prefixes) ----"
        grep -F 'Posting auth notification' <<< "$RACE_DUMP" || true
        exit 1
    fi
    echo "✅ Exactly one prompt was raised on the phone for this request."
    echo "✅ Parallel Discovery Race Authentication PASSED!"
    phase_pass "4" "with both transports live pam-auth returned OUTCOME=SUCCESS, the daemon registered the BLE advertisement and sent the request to the IPv4 multicast group (both transports participated, winner ${GRANT_TRANSPORT}), and the phone raised exactly one prompt for the request"
else
    echo "❌ Parallel Discovery Race Authentication FAILED after ${BLE_MAX_ATTEMPTS} attempts."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Step 9: Phase 5 - Denial Testing
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5: Explicit User Denial & Rejection Verification       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Stop auto-grant watcher
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" stop-auto-grant
# Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 4).
settle_for_dedup "Phase 4"

echo "==> Setting transport config: UDP enabled, BLE disabled..."
"$CLI_BIN" set-transports --ble false --network true

echo "==> Initiating auth and simulating biometric rejection..."
DENIAL_OUT_LOG="${TEST_DIR}/denial-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 10 > "$DENIAL_OUT_LOG" 2>&1 &
DENIAL_CLI_PID=$!

# Trigger denial repeatedly while the request is in flight to ensure it catches
# the active request without racing UDP transit or background scheduling delays.
# The first call is a full denial once the prompt has had a moment to appear
# (finger 2 + package-scoped broadcast + a single global BACK); the retries use
# deny-retry, which repeats only the targeted triggers, so the loop cannot
# dismiss unrelated emulator UI.
sleep 0.5
"$SCRIPT_DIR/ci/emulator-bio-helper.sh" deny "$APP_PKG"
for _ in {1..15}; do
    if ! kill -0 "$DENIAL_CLI_PID" 2>/dev/null; then
        break
    fi
    "$SCRIPT_DIR/ci/emulator-bio-helper.sh" deny-retry "$APP_PKG"
    sleep 0.3
done

set +e
wait "$DENIAL_CLI_PID"
DENIAL_EXIT=$?
set -e

cat "$DENIAL_OUT_LOG"

if [ "$DENIAL_EXIT" -ne 0 ] && grep -q "OUTCOME=DENIED" "$DENIAL_OUT_LOG"; then
    echo "✅ Explicit Denial correctly rejected with OUTCOME=DENIED (exit code: $DENIAL_EXIT)."
    phase_pass "5" "a simulated biometric rejection ended the request with OUTCOME=DENIED and exit code ${DENIAL_EXIT}"
else
    echo "❌ ERROR: Expected explicit denial with OUTCOME=DENIED, but got exit code $DENIAL_EXIT."
    if [ -f "$DAEMON_LOG" ]; then
        echo "=== DAEMON LOG DUMP ==="
        cat "$DAEMON_LOG"
        echo "======================="
    fi
    exit 1
fi

# Step 9b: Phase 5b - Authentication Timeout Verification
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 5b: Authentication Timeout Verification                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

# Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 5).
settle_for_dedup "Phase 5" 2
# Stop the Android app so that no server responds to the multicast, verifying daemon timeout handling
adb shell am force-stop "$APP_PKG" 2>/dev/null || true
sleep 1

echo "==> Requesting authentication with 2s timeout and no response..."
TIMEOUT_OUT_LOG="${TEST_DIR}/timeout-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 2 > "$TIMEOUT_OUT_LOG" 2>&1 || true

cat "$TIMEOUT_OUT_LOG"

if grep -q "OUTCOME=TIMEOUT" "$TIMEOUT_OUT_LOG"; then
    echo "✅ Authentication Timeout correctly detected OUTCOME=TIMEOUT!"
    phase_pass "5b" "with the phone stopped and a 2s deadline, the request ended with OUTCOME=TIMEOUT"
else
    echo "❌ ERROR: Expected OUTCOME=TIMEOUT, but got:"
    cat "$TIMEOUT_OUT_LOG"
    exit 1
fi

# Step 10: Phase 6 - Device Removal / Un-pairing (+ mixed-stack password fallback)
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 6: Device Removal / Un-pairing Lifecycle               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ -z "$SERVER_HEX" ]; then
    echo "❌ ERROR (Phase 6): SERVER_HEX is empty, so there is no paired device to remove."
    echo "   Phase 1b must set it from the pairing completion step; without it this"
    echo "   phase would call 'remove-device \"\"' and prove nothing."
    "$CLI_BIN" get-servers || true
    exit 1
fi
echo "==> Removing paired device $SERVER_HEX..."
"$CLI_BIN" remove-device "$SERVER_HEX"

REMAINING=$("$CLI_BIN" get-servers | grep 'COUNT=' | cut -d'=' -f2)
if [ "$REMAINING" -eq 0 ]; then
    echo "✅ Device successfully removed. Remaining paired devices: 0"
else
    echo "❌ ERROR: Device removal failed, count=$REMAINING."
    exit 1
fi

# Settle: keep the next same-user auth outside the 1s PAM-PAM dedup window (previous auth: Phase 5b).
settle_for_dedup "Phase 5b"
echo "==> Verifying the daemon reports OUTCOME=IGNORE when no devices are configured..."
UNPAIRED_AUTH_LOG="${TEST_DIR}/unpaired-cli.log"
"$CLI_BIN" pam-auth "$TEST_USER" 5 > "$UNPAIRED_AUTH_LOG" 2>&1 || true
cat "$UNPAIRED_AUTH_LOG"

if grep -q "OUTCOME=IGNORE" "$UNPAIRED_AUTH_LOG"; then
    echo "✅ Un-paired authentication correctly returns OUTCOME=IGNORE (password fallback enabled)!"
    phase_pass "6" "remove-device left COUNT=0, and an authentication with no paired device returned OUTCOME=IGNORE"
else
    echo "❌ ERROR: Expected OUTCOME=IGNORE after device removal, but got:"
    cat "$UNPAIRED_AUTH_LOG"
    exit 1
fi

# Mixed-stack password fallback with the real PAM module: with no paired
# devices TapAuth yields PAM_AUTHINFO_UNAVAIL, which the [success=1
# default=ignore] flag below expands to `ignore`, so the stack falls through to
# pam_unix and the LOCAL PASSWORD decides.
if [ "$PAM_TESTABLE" = "true" ] && [ "$(id -u)" -eq 0 ]; then
    echo ""
    echo "==> Phase 6b: Mixed-stack password fallback after un-pairing..."
    if ! id "$PAM_FALLBACK_USER" >/dev/null 2>&1; then
        useradd -m "$PAM_FALLBACK_USER"
    fi
    # Remember /etc/shadow's original mode before loosening it: pam_unix/passwd
    # need to read it during this phase, and cleanup() restores it afterwards.
    # The unlock/hash steps below are load-bearing on the container distros:
    # dropping them leaves the account unusable and pam_unix reports
    # PAM_AUTHINFO_UNAVAIL. `passwd --stdin` only exists on Fedora/RHEL (on
    # Debian/Ubuntu the guard makes it a no-op); chpasswd alone is not enough
    # there, so both are kept.
    if [ -z "$SHADOW_MODE_PRE" ]; then
        SHADOW_MODE_PRE="$(stat -c '%a' /etc/shadow 2>/dev/null || true)"
    fi
    chmod 0600 /etc/shadow 2>/dev/null || true
    passwd -u "$PAM_FALLBACK_USER" 2>/dev/null || true
    echo "${PAM_FALLBACK_USER}:${PAM_FALLBACK_PASS}" | chpasswd
    echo "$PAM_FALLBACK_PASS" | passwd --stdin "$PAM_FALLBACK_USER" 2>/dev/null || true

    # Same stack shape as Phase 2e (trailing pam_permit so the
    # [success=1] jump can never overshoot the stack).
    printf 'auth [success=1 default=ignore] %s\nauth required pam_unix.so nullok\nauth required pam_permit.so\naccount required pam_permit.so\n' "$PAM_LIB" > "$PAM_MIXED_CONFIG_PATH"

    set +e
    echo "$PAM_FALLBACK_PASS" | "${PAM_ENV[@]}" pamtester "$PAM_MIXED_SERVICE_NAME" "$PAM_FALLBACK_USER" authenticate
    FALLBACK_OK_EXIT=$?
    echo "definitely-not-the-password" | "${PAM_ENV[@]}" pamtester "$PAM_MIXED_SERVICE_NAME" "$PAM_FALLBACK_USER" authenticate
    FALLBACK_BAD_EXIT=$?
    set -e

    if [ "$FALLBACK_OK_EXIT" -eq 0 ]; then
        echo "✅ TapAuth's skip verdict fell through to pam_unix; correct password authenticated."
        phase_pass "6b" "with no paired device the module's skip verdict fell through to pam_unix: the correct password authenticated and a wrong password was rejected"
    else
        echo "❌ ERROR: password fallback did not work after the TapAuth skip verdict (rc=$FALLBACK_OK_EXIT)."
        exit 1
    fi
    if [ "$FALLBACK_BAD_EXIT" -ne 0 ]; then
        echo "✅ Wrong password correctly rejected after TapAuth's skip verdict (PAM_AUTHINFO_UNAVAIL)."
    else
        echo "❌ ERROR: wrong password was accepted — password module did not enforce!"
        exit 1
    fi
    passwd -l "$PAM_FALLBACK_USER" >/dev/null 2>&1 || true
else
    phase_skip "6b" "needs a testable PAM stack and root (PAM_TESTABLE=${PAM_TESTABLE}, uid=$(id -u))"
fi

# Step 11: Phase 7 - IPC Authorization (PolKit) Enforcement
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PHASE 7: Admin IPC Authorization Enforcement (PolKit)        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"

if [ "$E2E_DAEMON_MODE" = "systemd" ]; then
    echo "==> Creating unprivileged probe user (member of tapauthd-clients)..."
    if ! id "$ADMIN_DENY_USER" >/dev/null 2>&1; then
        useradd -m "$ADMIN_DENY_USER"
    fi
    usermod -aG tapauthd-clients "$ADMIN_DENY_USER"

    LOG_BASE=$(wc -l < "$DAEMON_LOG" 2>/dev/null || echo 0)
    echo "==> Admin request as unprivileged user (must be denied by the daemon)..."
    set +e
    runuser -u "$ADMIN_DENY_USER" -- "$CLI_BIN" get-servers > "${TEST_DIR}/deny-admin.log" 2>&1
    DENY_EXIT=$?
    set -e
    cat "${TEST_DIR}/deny-admin.log"

    if [ "$DENY_EXIT" -ne 0 ] && grep -q "ERROR" "${TEST_DIR}/deny-admin.log"; then
        echo "✅ Unprivileged admin request denied (exit code: $DENY_EXIT)."
    else
        echo "❌ ERROR: unprivileged admin request was NOT denied (exit code: $DENY_EXIT)!"
        exit 1
    fi
    sleep 1
    assert_log_since "$LOG_BASE" "Unauthorized admin request" \
        "Daemon logged the unauthorized attempt (audit trail present)"

    echo "==> Socket access gate: user outside 'tapauthd-clients' must not connect..."
    set +e
    runuser -u nobody -- "$CLI_BIN" get-servers > "${TEST_DIR}/deny-socket.log" 2>&1
    SOCKET_DENY_EXIT=$?
    set -e
    cat "${TEST_DIR}/deny-socket.log"
    if [ "$SOCKET_DENY_EXIT" -ne 0 ]; then
        echo "✅ Unprivileged non-group member could not reach the IPC socket (exit code: $SOCKET_DENY_EXIT)."
        phase_pass "7" "an unprivileged admin request was denied and audited by the daemon, and a user outside tapauthd-clients could not reach the IPC socket"
    else
        echo "❌ ERROR: 'nobody' unexpectedly reached the IPC socket!"
        exit 1
    fi
else
    echo "ℹ️  SKIPPED (systemd mode only — dev-mode sandbox does not model production authz)."
    phase_skip "7" "systemd mode only — the dev-mode sandbox does not model production PolKit authorization"
fi

# The matrix and its assertion notes are generated from the registry at the top
# of this file; finish_suite turns that matrix into the suite's exit status.
finish_suite
