#!/bin/bash
# Debian/Ubuntu package lifecycle test for TapAuth.
#
# Usage: scripts/ci/test-ubuntu-deb.sh [--skip-build] [PKG_DIR]
#
# Asserts the packaging checked in under packaging/debian/ on current main:
#   install -> payload -> PAM profile/stack -> /etc/tapauth -> sysusers ->
#   no admin CLI -> upgrade -> remove -> purge, then always purges the package
#   so the container stays reusable.
#
# Must run as root (or with sudo) on Ubuntu/Debian. With --skip-build the .deb
# files already present in PKG_DIR are used as-is; otherwise the build
# dependencies are installed and scripts/ci/build-debian-packages.sh is invoked.
#
# NOTE on /etc/tapauth: the package ships the directory (root:root 0755) and
# tmpfiles creates /etc/tapauth/config.toml owned by the daemon -- the single
# writer via SaveConfig -- so a fresh package install can persist config. This
# test asserts that posture (including that tapauthd can actually write the
# file) and the remove-vs-purge split: removal preserves user data, purge drops
# the generated config but not unrelated files.

set -euo pipefail

export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Argument parsing ──────────────────────────────────────────────────────────
SKIP_BUILD=false
PKG_DIR_ARG=""

usage() {
    cat <<EOF
Usage: $0 [--skip-build] [PKG_DIR]

  --skip-build   Test the .deb files already in PKG_DIR (do not build/install deps).
  PKG_DIR        Directory containing tapauth_*.deb
                 (default: \$PKG_DIR env if set, otherwise /tmp/deb-build).

Environment:
  PKG_DIR        Same as the positional argument; the positional wins.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) PKG_DIR_ARG="$1"; shift ;;
    esac
done

PKG_DIR="${PKG_DIR_ARG:-${PKG_DIR:-/tmp/deb-build}}"

# ── Privilege handling ────────────────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
    SUDO=()
elif command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
else
    echo "❌ ERROR: this lifecycle test must run as root (sudo not available)." >&2
    exit 1
fi

# ── Check helpers ─────────────────────────────────────────────────────────────
FAILURES=0
CHECKS_PASSED=0
CHECKS_SKIPPED=0

section() { printf '\n==> %s\n' "$*"; }
pass() { CHECKS_PASSED=$((CHECKS_PASSED + 1)); printf '✅ %s\n' "$*"; }
fail() { FAILURES=$((FAILURES + 1)); printf '❌ %s\n' "$*" >&2; }
skip() { CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1)); printf '⚠️  SKIP: %s\n' "$*"; }
note() { printf 'ℹ️  %s\n' "$*"; }

assert_file() {
    local p="$1" d="${2:-$1}"
    if [ -f "$p" ]; then pass "$d"; else fail "$d — expected file not found: $p"; fi
}

assert_exec() {
    local p="$1" d="${2:-$1}"
    if [ -x "$p" ]; then pass "$d"; else fail "$d — expected executable not found: $p"; fi
}

assert_dir() {
    local p="$1" d="${2:-$1}"
    if [ -d "$p" ]; then pass "$d"; else fail "$d — expected directory not found: $p"; fi
}

assert_absent() {
    local p="$1" d="${2:-$1}"
    if [ -e "$p" ]; then fail "$d — unexpected path present: $p"; else pass "$d"; fi
}

assert_contains() {
    local f="$1" needle="$2"
    local d="${3:-$f contains $needle}"
    if grep -qF -- "$needle" "$f" 2>/dev/null; then
        pass "$d"
    else
        fail "$d — '$needle' not found in $f"
    fi
}

assert_not_contains() {
    local f="$1" needle="$2"
    local d="${3:-$f does not contain $needle}"
    if grep -qF -- "$needle" "$f" 2>/dev/null; then
        fail "$d — '$needle' still present in $f"
    else
        pass "$d"
    fi
}

first_existing() {
    local p
    for p in "$@"; do
        if [ -e "$p" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 0
}

detect_pam_so() {
    # Finds pam_tapauth.so under any multiarch or plain security directory.
    find /usr/lib /lib -maxdepth 4 -type f -name pam_tapauth.so -print -quit 2>/dev/null || true
}

package_known() {
    dpkg-query -W tapauth >/dev/null 2>&1
}

user_exists() {
    getent passwd "$1" >/dev/null 2>&1 || grep -q "^$1:" /etc/passwd
}

group_exists() {
    getent group "$1" >/dev/null 2>&1 || grep -q "^$1:" /etc/group
}

# ── State paths ───────────────────────────────────────────────────────────────
ETC_TAPAUTH="/etc/tapauth"
ETC_SENTINEL="$ETC_TAPAUTH/persist-check"
STATE_DIR="/var/lib/tapauth"
STATE_SENTINEL="$STATE_DIR/lifecycle-sentinel"
PAM_PROFILE="/usr/share/pam-configs/tapauth"
COMMON_AUTH="/etc/pam.d/common-auth"

# ── Cleanup (always) ──────────────────────────────────────────────────────────
cleanup() {
    if package_known; then
        "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive dpkg -P tapauth >/dev/null 2>&1 || true
    fi
    # Remove the sentinels this test created; leave anything a real install owns.
    rm -f "$ETC_SENTINEL" 2>/dev/null || true
    "${SUDO[@]}" rm -f "$STATE_SENTINEL" 2>/dev/null || true
    rmdir "$ETC_TAPAUTH" 2>/dev/null || true
}
trap cleanup EXIT

# ── Build / dependency setup (skipped with --skip-build) ──────────────────────
BUILD_DEPS=(
    build-essential debhelper-compat protobuf-compiler libdbus-1-dev
    libsystemd-dev libpam0g-dev clang libclang-dev pkg-config git tar
    dpkg-dev polkitd dbus sudo curl ca-certificates
)

version_ge() {
    # version_ge <have> <want> -> true when have >= want
    dpkg --compare-versions "$1" ge "$2"
}

ensure_rust() {
    export PATH="${HOME:-/root}/.cargo/bin:$PATH"
    local need_rustup=false have=""

    if command -v cargo >/dev/null 2>&1; then
        have="$(cargo --version | awk '{print $2}')"
        if version_ge "$have" "1.85"; then
            pass "cargo $have (>= 1.85) is available"
        else
            note "cargo $have is older than 1.85; installing a newer toolchain via rustup"
            need_rustup=true
        fi
    else
        note "cargo not found; installing via rustup"
        need_rustup=true
    fi

    if [ "$need_rustup" = true ]; then
        if ! command -v rustup >/dev/null 2>&1; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        fi
        rustup toolchain install stable --profile minimal
        rustup default stable
        export PATH="${HOME:-/root}/.cargo/bin:$PATH"
        hash -r
    fi

    if cargo --version >/dev/null 2>&1; then
        pass "using $(cargo --version)"
    else
        fail "cargo is still unavailable after setup"
    fi
}

if [ "$SKIP_BUILD" = false ]; then
    section "Installing build dependencies"
    export DEBIAN_FRONTEND=noninteractive
    "${SUDO[@]}" apt-get update
    "${SUDO[@]}" apt-get install -y "${BUILD_DEPS[@]}"
    pass "build dependencies installed"

    section "Ensuring Rust >= 1.85"
    ensure_rust

    section "Building .deb packages"
    if [ ! -d "$PKG_DIR" ]; then
        mkdir -p "$PKG_DIR"
    fi
    PKG_DIR="$(cd "$PKG_DIR" && pwd)"
    bash "$WORKSPACE_DIR/scripts/ci/build-debian-packages.sh" --output-dir "$PKG_DIR"
    pass "build-debian-packages.sh completed"
else
    section "Skipping build (--skip-build)"
    note "testing existing packages in $PKG_DIR"
fi

if [ ! -d "$PKG_DIR" ]; then
    fail "PKG_DIR does not exist: $PKG_DIR"
    echo "❌ ERROR: no package directory to test." >&2
    exit 1
fi
PKG_DIR="$(cd "$PKG_DIR" && pwd)"

shopt -s nullglob
DEBS=("$PKG_DIR"/tapauth_*.deb)
shopt -u nullglob

if [ "${#DEBS[@]}" -eq 0 ]; then
    fail "no tapauth_*.deb found in $PKG_DIR"
    echo "❌ ERROR: nothing to install from $PKG_DIR." >&2
    exit 1
fi
note "packages under test: ${DEBS[*]}"

# ── Reusable assertion groups ─────────────────────────────────────────────────
check_payload() {
    section "Payload checks"
    assert_exec /usr/bin/tapauthd "tapauthd daemon installed and executable"
    assert_exec /usr/bin/tapauth-config "tapauth-config GUI installed and executable"

    local pam_so
    pam_so="$(detect_pam_so)"
    if [ -n "$pam_so" ]; then
        pass "pam_tapauth.so installed at $pam_so"
    else
        fail "pam_tapauth.so not found under /usr/lib/*/security, /lib/*/security or /usr/lib/security"
    fi

    local service socket
    service="$(first_existing /lib/systemd/system/tapauthd.service /usr/lib/systemd/system/tapauthd.service)"
    if [ -n "$service" ]; then
        pass "tapauthd.service installed ($service)"
    else
        fail "tapauthd.service not found in /lib/systemd/system or /usr/lib/systemd/system"
    fi
    socket="$(first_existing /lib/systemd/system/tapauthd.socket /usr/lib/systemd/system/tapauthd.socket)"
    if [ -n "$socket" ]; then
        pass "tapauthd.socket installed ($socket)"
    else
        fail "tapauthd.socket not found in /lib/systemd/system or /usr/lib/systemd/system"
    fi

    assert_file /usr/lib/sysusers.d/tapauth.conf "sysusers fragment installed"
    assert_file /usr/lib/tmpfiles.d/tapauth.conf "tmpfiles fragment installed"
    assert_file /usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy "polkit action installed"
    assert_file /usr/share/polkit-1/rules.d/50-tapauthd.rules "polkit rules installed"
    assert_file /usr/share/applications/tapauth-config.desktop "desktop entry installed"
    assert_file /usr/share/icons/hicolor/scalable/apps/tapauth-config.svg "application icon installed"
}

check_pam() {
    section "PAM profile and shared stack"
    if [ -f "$PAM_PROFILE" ]; then
        pass "pam-config profile installed ($PAM_PROFILE)"
        assert_contains "$PAM_PROFILE" "pam_tapauth.so" \
            "pam-config profile references pam_tapauth.so"
    else
        fail "pam-config profile missing: $PAM_PROFILE"
    fi

    if command -v pam-auth-update >/dev/null 2>&1; then
        assert_contains "$COMMON_AUTH" "pam_tapauth.so" \
            "pam-auth-update wired pam_tapauth.so into $COMMON_AUTH"
    else
        skip "pam-auth-update not available; not asserting $COMMON_AUTH wiring"
    fi
}

check_etc_tapauth() {
    section "/etc/tapauth state"
    if [ -d "$ETC_TAPAUTH" ]; then
        pass "$ETC_TAPAUTH exists"
        local owner mode
        owner="$(stat -c '%U:%G' "$ETC_TAPAUTH" 2>/dev/null || true)"
        if [ "$owner" = "root:root" ]; then
            pass "$ETC_TAPAUTH is owned root:root"
        else
            fail "$ETC_TAPAUTH owner is '$owner' (expected root:root)"
        fi
        mode="$(stat -c '%a' "$ETC_TAPAUTH" 2>/dev/null || true)"
        case "$mode" in
            755|0755) pass "$ETC_TAPAUTH mode is 0755" ;;
            *) fail "$ETC_TAPAUTH mode is '$mode' (expected 0755)" ;;
        esac
    else
        fail "$ETC_TAPAUTH does not exist after install"
    fi
    # tmpfiles creates the runtime config owned by the daemon (it is the single
    # writer via SaveConfig). The directory stays root:root so the daemon cannot
    # add or remove arbitrary files there.
    local cfg="$ETC_TAPAUTH/config.toml"
    assert_file "$cfg" "config.toml is created at install time"
    local cfg_owner cfg_mode
    cfg_owner="$(stat -c '%U:%G' "$cfg" 2>/dev/null || true)"
    cfg_mode="$(stat -c '%a' "$cfg" 2>/dev/null || true)"
    if [ "$cfg_owner" = "tapauthd:tapauthd" ]; then
        pass "$cfg is owned tapauthd:tapauthd"
    else
        fail "$cfg owner is '$cfg_owner' (expected tapauthd:tapauthd)"
    fi
    case "$cfg_mode" in
        644|0644) pass "$cfg mode is 0644" ;;
        *) fail "$cfg mode is '$cfg_mode' (expected 0644)" ;;
    esac
    # Functional check for the regression this ownership exists for: on a
    # pristine install tapauthd must be able to persist SaveConfig.
    if "${SUDO[@]}" runuser -u tapauthd -- test -w "$cfg"; then
        pass "tapauthd can write $cfg (SaveConfig works on a fresh install)"
    else
        fail "tapauthd cannot write $cfg (SaveConfig would fail with EACCES)"
    fi
}

check_sysusers() {
    section "sysusers identity"
    if user_exists tapauthd; then
        pass "user 'tapauthd' exists"
    else
        fail "user 'tapauthd' does not exist"
    fi
    if group_exists tapauthd-clients; then
        pass "group 'tapauthd-clients' exists"
    else
        fail "group 'tapauthd-clients' does not exist"
    fi
}

# ── Phase 1: install ──────────────────────────────────────────────────────────
section "Package install (apt-get install local .deb)"
if "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "${DEBS[@]}"; then
    pass "apt-get install of ${DEBS[*]} succeeded"
else
    fail "apt-get install of the local .deb failed"
fi

# ── Phase 2: installed payload ────────────────────────────────────────────────
check_payload
check_pam
check_etc_tapauth
check_sysusers

section "Admin CLI is not shipped"
assert_absent /usr/bin/tapauth-ipc-cli "tapauth-ipc-cli is not installed"

# ── Phase 3: seed user data to assert removal never deletes it ───────────────
section "Seeding user data under /etc/tapauth"
note "$ETC_TAPAUTH is package-owned (root:root); tmpfiles creates the daemon-owned config.toml."
note "dpkg removes package-owned directories only when empty, so seed an unrelated"
note "user file to assert the real guarantee: removal must not delete user data."
if [ -d "$ETC_TAPAUTH" ]; then
    printf 'lifecycle-test sentinel\n' > "$ETC_SENTINEL"
    pass "seeded $ETC_SENTINEL"
else
    fail "cannot seed sentinel: $ETC_TAPAUTH is missing"
fi

# /var/lib/tapauth is tmpfiles-managed. `dpkg -r` must preserve it (only purge
# removes state), so seed a file and assert it survives removal below.
if [ -d "$STATE_DIR" ]; then
    "${SUDO[@]}" bash -c "printf 'lifecycle-test state sentinel\n' > '$STATE_SENTINEL'"
    pass "seeded $STATE_SENTINEL"
else
    note "$STATE_DIR is absent (tmpfiles did not run); skipping state-preservation assertion"
fi

# ── Phase 4: upgrade / reinstall ──────────────────────────────────────────────
section "Upgrade (dpkg -i same packages again)"
if "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive dpkg -i "${DEBS[@]}"; then
    pass "reinstall/upgrade via dpkg -i succeeded"
else
    fail "reinstall/upgrade via dpkg -i failed"
fi

check_payload
check_pam

# ── Phase 5: remove ───────────────────────────────────────────────────────────
section "Package removal (dpkg -r)"
if "${SUDO[@]}" dpkg -r tapauth; then
    pass "dpkg -r tapauth succeeded"
else
    fail "dpkg -r tapauth failed"
fi

if command -v pam-auth-update >/dev/null 2>&1; then
    "${SUDO[@]}" pam-auth-update --package >/dev/null 2>&1 || true
    assert_not_contains "$COMMON_AUTH" "pam_tapauth.so" \
        "pam_tapauth.so removed from $COMMON_AUTH after removal"
else
    skip "pam-auth-update not available; not asserting $COMMON_AUTH de-wiring"
fi

assert_absent "$PAM_PROFILE" "pam-config profile removed by dpkg -r"
assert_dir "$ETC_TAPAUTH" "$ETC_TAPAUTH survives package removal"
assert_file "$ETC_TAPAUTH/config.toml" "generated config survives package removal"
assert_file "$ETC_SENTINEL" "user data under $ETC_TAPAUTH survives package removal"
# State is intentionally preserved by `dpkg -r`; only purge removes it.
if [ -d "$STATE_DIR" ]; then
    assert_file "$STATE_SENTINEL" "user state under $STATE_DIR survives package removal"
else
    skip "$STATE_DIR was absent before removal; not asserting preservation"
fi

# ── Phase 6: purge ────────────────────────────────────────────────────────────
section "Package purge (dpkg -P)"
if "${SUDO[@]}" dpkg -P tapauth; then
    pass "dpkg -P tapauth succeeded"
else
    fail "dpkg -P tapauth failed"
fi

# packaging/debian/postrm removes the tmpfiles-managed state/runtime dirs
# directly on purge (the shipped fragment is already gone by then), so this
# must hold regardless of whether the host runs systemd.
assert_absent /var/lib/tapauth "/var/lib/tapauth removed on purge"
assert_absent /var/log/tapauth "/var/log/tapauth removed on purge"
assert_absent "$STATE_SENTINEL" "state sentinel removed with the purge"
assert_absent "$ETC_TAPAUTH/config.toml" "generated config removed on purge"
assert_dir "$ETC_TAPAUTH" "$ETC_TAPAUTH survives package purge"
assert_file "$ETC_SENTINEL" "unrelated user data under $ETC_TAPAUTH survives package purge"

# ── Summary ───────────────────────────────────────────────────────────────────
section "Summary"
printf 'Passed: %d   Failed: %d   Skipped: %d\n' "$CHECKS_PASSED" "$FAILURES" "$CHECKS_SKIPPED"
if [ "$FAILURES" -ne 0 ]; then
    echo "❌ $FAILURES assertion(s) failed." >&2
    exit 1
fi
echo "✅ All TapAuth Debian package lifecycle assertions passed."
