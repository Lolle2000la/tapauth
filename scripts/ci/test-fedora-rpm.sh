#!/usr/bin/env bash
#
# End-to-end installation test for the Fedora RPM built from the current
# packaging/tapauth.spec.
#
# Run as root inside a Fedora container:
#
#     ./scripts/ci/test-fedora-rpm.sh [--skip-build] [PKG_DIR]
#
#   --skip-build  Install only minimal tooling (grep/sed/findutils) and test
#                 the RPMs already present in PKG_DIR.
#   PKG_DIR       Directory holding the built .rpm files (or where the build
#                 step should place them).
#                 Default: ${WORKSPACE_DIR}/pkg-fedora.
#
# Exits non-zero if any assertion fails. All checks are executed so the log
# shows every failure at once.
set -euo pipefail

# Deterministic tool output (authselect's "Profile ID:" line, rpm/dnf messages).
export LC_ALL=C

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
cd "$WORKSPACE_DIR"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SKIP_BUILD=false
PKG_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -h | --help)
            sed -n '2,16p' "$0"
            exit 0
            ;;
        --*)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
        *)
            if [ -n "$PKG_DIR" ]; then
                echo "Unexpected extra argument: $1" >&2
                exit 2
            fi
            PKG_DIR="$1"
            shift
            ;;
    esac
done
PKG_DIR="${PKG_DIR:-${WORKSPACE_DIR}/pkg-fedora}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Version resolution is shared with the build scripts.
# shellcheck source=scripts/ci/_pkg-version.sh
source "$SCRIPT_DIR/_pkg-version.sh"
PKG_VER="$(resolve_tapauth_version "$WORKSPACE_DIR")"
if [ -z "$PKG_VER" ]; then
    echo "❌ Could not determine PKG_VER from tapauthd/Cargo.toml or [workspace.package] in Cargo.toml" >&2
    exit 1
fi
echo "==> Testing Fedora RPM packaging for TapAuth version: ${PKG_VER}"
echo "    PKG_DIR: ${PKG_DIR}"

# ---------------------------------------------------------------------------
# Check helpers (✅ pass / ❌ fail / ⚠️ skip)
# ---------------------------------------------------------------------------
FAILURES=0
pass() { printf '✅ %s\n' "$*"; }
fail() {
    printf '❌ %s\n' "$*"
    FAILURES=$((FAILURES + 1))
}
skip() { printf '⚠️  SKIP: %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }

check_file() {
    local path="$1" label="${2:-$1}"
    if [ -f "$path" ]; then
        pass "$label"
    else
        fail "$label (missing: $path)"
    fi
}

check_exec() {
    local path="$1" label="${2:-$1}"
    if [ -x "$path" ]; then
        pass "$label"
    else
        fail "$label (missing or not executable: $path)"
    fi
}

check_absent() {
    local path="$1" label="${2:-$1}"
    if [ -e "$path" ]; then
        fail "$label (present but should not be: $path)"
    else
        pass "$label"
    fi
}

# Find pam_tapauth.so under any known multiarch security dir.
find_pam_module() {
    local dir
    for dir in /usr/lib64/security /usr/lib/security; do
        if [ -f "${dir}/pam_tapauth.so" ]; then
            printf '%s\n' "${dir}/pam_tapauth.so"
            return 0
        fi
    done
    return 1
}

AUTHSELECT_VENDOR_DIR="/usr/share/authselect/vendor"

# Select a stock profile again, trying the profiles available across Fedora
# and RHEL releases (sssd, local, minimal).
authselect_restore_base() {
    local profile
    for profile in sssd local minimal; do
        if authselect select "$profile" --force >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

# Select the TapAuth vendor profile. The profile ID exposed by authselect
# differs across versions: recent Fedora reports the bare directory name
# ("tapauth"), older/reworked authselect accepted a "vendor/<name>" prefix.
# Try both and return the ID that actually worked.
authselect_select_vendor() {
    local id
    for id in vendor/tapauth tapauth; do
        if authselect select "$id" --force >/dev/null 2>&1; then
            printf '%s\n' "$id"
            return 0
        fi
    done
    return 1
}

# A profile ID that refers to the TapAuth vendor profiles on any authselect
# version (bare name or vendor/-prefixed).
is_tapauth_profile_id() {
    case "$1" in
        tapauth | tapauth-sssd | vendor/tapauth | vendor/tapauth-sssd | custom/tapauth | custom/tapauth-sssd) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Assertion groups
# ---------------------------------------------------------------------------
assert_payload() {
    step "Payload assertions ($1)"
    check_exec /usr/bin/tapauthd "binary /usr/bin/tapauthd"
    check_exec /usr/bin/tapauth-config "binary /usr/bin/tapauth-config"

    local pam_so
    if pam_so=$(find_pam_module); then
        pass "PAM module $pam_so"
    else
        fail "pam_tapauth.so not under /usr/lib64/security or /usr/lib/security"
    fi

    check_file /usr/lib/systemd/system/tapauthd.service "unit tapauthd.service"
    check_file /usr/lib/systemd/system/tapauthd.socket "unit tapauthd.socket"
    check_file /usr/lib/systemd/system/polkit-agent-helper@.service.d/tapauth.conf \
        "unit drop-in polkit-agent-helper@.service.d/tapauth.conf"

    check_file /usr/lib/sysusers.d/tapauth.conf "sysusers.d/tapauth.conf"
    check_file /usr/lib/tmpfiles.d/tapauth.conf "tmpfiles.d/tapauth.conf"
    check_file /usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy \
        "polkit action dev.rourunisen.tapauth.config.admin.policy"
    check_file /usr/share/polkit-1/rules.d/50-tapauthd.rules "polkit rule 50-tapauthd.rules"
}

assert_etc_tapauth() {
    step "Structure of /etc/tapauth"
    if [ -d /etc/tapauth ]; then
        pass "/etc/tapauth is a directory"
        local mode owner
        mode=$(stat -c '%a' /etc/tapauth)
        owner=$(stat -c '%U:%G' /etc/tapauth)
        if [ "$mode" = "755" ]; then
            pass "/etc/tapauth mode is 0755"
        else
            fail "/etc/tapauth mode is ${mode}, expected 0755"
        fi
        if [ "$owner" = "root:root" ]; then
            pass "/etc/tapauth owner is root:root"
        else
            fail "/etc/tapauth owner is ${owner}, expected root:root"
        fi
    else
        fail "/etc/tapauth is missing"
    fi
    # tmpfiles creates the daemon-owned runtime config; the directory stays
    # root:root so the daemon cannot add/remove arbitrary files there.
    local cfg=/etc/tapauth/config.toml
    check_file "$cfg" "config.toml is created at install time"
    local cfg_owner cfg_mode
    cfg_owner="$(stat -c '%U:%G' "$cfg" 2>/dev/null || true)"
    cfg_mode="$(stat -c '%a' "$cfg" 2>/dev/null || true)"
    if [ "$cfg_owner" = "tapauthd:tapauthd" ]; then
        pass "$cfg is owned tapauthd:tapauthd"
    else
        fail "$cfg owner is '$cfg_owner' (expected tapauthd:tapauthd)"
    fi
    if [ "$cfg_mode" = "644" ]; then
        pass "$cfg mode is 0644"
    else
        fail "$cfg mode is '$cfg_mode' (expected 0644)"
    fi
    # The regression this ownership exists for: on a pristine install tapauthd
    # must be able to persist SaveConfig. chroot --userspec drops to the daemon
    # uid using coreutils only (runuser is not in every container image).
    if chroot --userspec=tapauthd:tapauthd / /usr/bin/test -w "$cfg"; then
        pass "tapauthd can write $cfg (SaveConfig works on a fresh install)"
    else
        fail "tapauthd cannot write $cfg (SaveConfig would fail with EACCES)"
    fi
}

assert_ipc_cli_absent() {
    step "tapauth-ipc-cli is not shipped"
    if command -v tapauth-ipc-cli >/dev/null 2>&1; then
        fail "tapauth-ipc-cli is on PATH ($(command -v tapauth-ipc-cli))"
    else
        pass "tapauth-ipc-cli is not on PATH"
    fi
    if [ -e /usr/bin/tapauth-ipc-cli ] || [ -e /usr/local/bin/tapauth-ipc-cli ]; then
        fail "a tapauth-ipc-cli file exists on disk"
    else
        pass "no tapauth-ipc-cli file in /usr/bin or /usr/local/bin"
    fi
    if rpm -q --list tapauth 2>/dev/null | grep -q 'tapauth-ipc-cli'; then
        fail "tapauth RPM payload contains tapauth-ipc-cli"
    else
        pass "tapauth RPM payload has no tapauth-ipc-cli"
    fi
}

assert_vendor_profiles() {
    step "authselect vendor profiles shipped (must not be auto-selected)"
    check_file "${AUTHSELECT_VENDOR_DIR}/tapauth/system-auth" "vendor/tapauth/system-auth"
    check_file "${AUTHSELECT_VENDOR_DIR}/tapauth/password-auth" "vendor/tapauth/password-auth"
    check_file "${AUTHSELECT_VENDOR_DIR}/tapauth-sssd/system-auth" "vendor/tapauth-sssd/system-auth"
    check_file "${AUTHSELECT_VENDOR_DIR}/tapauth-sssd/password-auth" "vendor/tapauth-sssd/password-auth"

    if [ -f "${AUTHSELECT_VENDOR_DIR}/tapauth/system-auth" ] &&
        grep -q 'pam_tapauth\.so' "${AUTHSELECT_VENDOR_DIR}/tapauth/system-auth"; then
        pass "vendor/tapauth/system-auth contains pam_tapauth.so"
    else
        fail "vendor/tapauth/system-auth does not contain pam_tapauth.so"
    fi
    if [ -f "${AUTHSELECT_VENDOR_DIR}/tapauth/password-auth" ] &&
        grep -q 'pam_tapauth\.so' "${AUTHSELECT_VENDOR_DIR}/tapauth/password-auth"; then
        pass "vendor/tapauth/password-auth contains pam_tapauth.so"
    else
        fail "vendor/tapauth/password-auth does not contain pam_tapauth.so"
    fi
}

# Functional authselect test: select the vendor profile, confirm the generated
# stack picks up pam_tapauth.so, then restore a stock profile. Minimal
# containers usually cannot run authselect, so this is explicitly optional.
AUTHSELECT_TESTED=false
test_authselect_functional() {
    step "authselect functional test (optional)"
    if ! command -v authselect >/dev/null 2>&1; then
        skip "authselect is not installed in this container"
        return 0
    fi
    if ! authselect current >/dev/null 2>&1; then
        if ! authselect_restore_base; then
            skip "authselect present but not usable in this container (no selectable base profile)"
            return 0
        fi
    fi
    local selected_id
    if ! selected_id=$(authselect_select_vendor); then
        skip "authselect could not select the tapauth vendor profile in this container"
        return 0
    fi

    AUTHSELECT_TESTED=true
    pass "authselect select ${selected_id} --force succeeded"
    if grep -rqs 'pam_tapauth\.so' /etc/authselect 2>/dev/null; then
        pass "generated /etc/authselect stack references pam_tapauth.so"
    else
        fail "generated /etc/authselect stack does not reference pam_tapauth.so"
    fi

    if authselect_restore_base; then
        pass "authselect restored to a stock profile"
        if grep -rqs 'pam_tapauth\.so' /etc/authselect 2>/dev/null; then
            fail "restored /etc/authselect stack still references pam_tapauth.so"
        else
            pass "restored /etc/authselect stack has no pam_tapauth.so"
        fi
    else
        fail "could not restore authselect to a stock profile"
    fi

    # Leave the TapAuth vendor profile selected so the later package removal
    # exercises the %preun rollback path (checked in assert_removed). This is
    # what catches a regression where the spec stops recognising the profile ID
    # authselect actually reports.
    if authselect_select_vendor >/dev/null; then
        pass "left vendor profile selected to exercise %preun rollback on removal"
    fi
}

# systemd tools are environment-dependent inside containers: never fail here.
check_systemd_best_effort() {
    step "systemd tooling (best effort, container-safe)"
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled tapauthd.socket >/dev/null 2>&1; then
            pass "tapauthd.socket is enabled"
        else
            fail "tapauthd.socket is not enabled"
        fi
        if systemctl is-active tapauthd.socket >/dev/null 2>&1; then
            pass "tapauthd.socket is active"
        else
            fail "tapauthd.socket is not active"
        fi
    else
        skip "systemd is not running here; skipping systemctl enable/active checks"
    fi

    if command -v systemd-sysusers >/dev/null 2>&1; then
        if systemd-sysusers --dry-run /usr/lib/sysusers.d/tapauth.conf >/dev/null 2>&1; then
            pass "systemd-sysusers accepts sysusers.d/tapauth.conf"
        else
            skip "systemd-sysusers could not validate sysusers.d/tapauth.conf here"
        fi
    else
        skip "systemd-sysusers is not available"
    fi

    if command -v systemd-tmpfiles >/dev/null 2>&1; then
        if systemd-tmpfiles --create --dry-run /usr/lib/tmpfiles.d/tapauth.conf >/dev/null 2>&1; then
            pass "systemd-tmpfiles accepts tmpfiles.d/tapauth.conf"
        else
            skip "systemd-tmpfiles could not validate tmpfiles.d/tapauth.conf here"
        fi
    else
        skip "systemd-tmpfiles is not available"
    fi
}

assert_removed() {
    step "Removal assertions"
    check_absent /usr/bin/tapauthd "tapauthd binary removed"
    check_absent /usr/bin/tapauth-config "tapauth-config binary removed"

    local pam_so
    if pam_so=$(find_pam_module); then
        fail "pam_tapauth.so still present at $pam_so"
    else
        pass "pam_tapauth.so removed"
    fi

    check_absent /usr/lib/systemd/system/tapauthd.service "tapauthd.service unit removed"
    check_absent /usr/lib/systemd/system/tapauthd.socket "tapauthd.socket unit removed"
    check_absent /usr/lib/sysusers.d/tapauth.conf "sysusers.d/tapauth.conf removed"
    check_absent /usr/lib/tmpfiles.d/tapauth.conf "tmpfiles.d/tapauth.conf removed"
    check_absent /usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy \
        "polkit action removed"
    check_absent /usr/share/polkit-1/rules.d/50-tapauthd.rules "polkit rule removed"

    if [ -e "${AUTHSELECT_VENDOR_DIR}/tapauth" ] || [ -e "${AUTHSELECT_VENDOR_DIR}/tapauth-sssd" ]; then
        fail "authselect vendor profiles still present after removal"
    else
        pass "authselect vendor profiles removed"
    fi

    if [ "$AUTHSELECT_TESTED" = true ]; then
        local current
        current=$(authselect current 2>/dev/null | sed -n 's/^Profile ID:[[:space:]]*//p' | xargs || true)
        if is_tapauth_profile_id "$current"; then
            fail "authselect still selects removed profile '${current}' (dangling)"
        else
            pass "authselect no longer selects a tapauth profile (current: ${current:-<none>})"
        fi
        if grep -rqs 'pam_tapauth\.so' /etc/authselect 2>/dev/null; then
            fail "generated authselect stack still references pam_tapauth.so after removal"
        else
            pass "no pam_tapauth.so left in generated authselect stacks"
        fi
        if [ -e /etc/pam.d/system-auth ] && grep -qs 'pam_tapauth\.so' /etc/pam.d/system-auth; then
            fail "/etc/pam.d/system-auth still references pam_tapauth.so after removal"
        else
            pass "no pam_tapauth.so left in /etc/pam.d/system-auth"
        fi
        authselect_restore_base >/dev/null 2>&1 || true
    else
        skip "authselect was not tested; skipping dangling-profile assertions"
    fi

    # The generated config and state are not package-owned, so `rpm -e` leaves
    # them in place (AGENTS.md); only Debian's purge removes the generated config.
    check_file /etc/tapauth/config.toml "daemon-owned config survives rpm -e"
    if [ -d /var/lib/tapauth ]; then
        pass "/var/lib/tapauth survives rpm -e"
    else
        fail "/var/lib/tapauth removed by rpm -e"
    fi
}

# ---------------------------------------------------------------------------
# 0. Tooling / build
# ---------------------------------------------------------------------------
if [ "$SKIP_BUILD" = false ]; then
    step "Installing Fedora build dependencies"
    dnf install -y rpm-build rust cargo protobuf-compiler clang pam-devel \
        systemd-devel dbus-devel sed tar findutils

    step "Building RPMs into ${PKG_DIR}"
    bash "${WORKSPACE_DIR}/scripts/ci/build-fedora-packages.sh" --nocheck --output-dir "${PKG_DIR}"
else
    step "Installing minimal tooling (--skip-build)"
    dnf install -y grep sed findutils
fi

# ---------------------------------------------------------------------------
# Locate the built RPMs (exclude emulation/debuginfo subpackages and SRPMs)
# ---------------------------------------------------------------------------
shopt -s nullglob
ALL_RPMS=("${PKG_DIR}"/tapauth-*.rpm)
INSTALL_RPMS=()
for rpm_path in "${ALL_RPMS[@]}"; do
    base=$(basename "$rpm_path")
    case "$base" in
        *-emulation* | *debuginfo* | *.src.rpm) continue ;;
    esac
    INSTALL_RPMS+=("$rpm_path")
done
if [ "${#INSTALL_RPMS[@]}" -eq 0 ]; then
    echo "❌ No installable tapauth RPM found in ${PKG_DIR}" >&2
    exit 1
fi
step "Installable RPMs"
for rpm_path in "${INSTALL_RPMS[@]}"; do
    note "$(basename "$rpm_path")"
done

# ---------------------------------------------------------------------------
# 1. Install
# ---------------------------------------------------------------------------
step "1. dnf install tapauth"
dnf install -y "${INSTALL_RPMS[@]}"
if rpm -q tapauth >/dev/null 2>&1; then
    pass "rpm -q tapauth reports the package installed"
else
    fail "rpm -q tapauth reports the package not installed"
fi

# ---------------------------------------------------------------------------
# 2-5. Post-install assertions
# ---------------------------------------------------------------------------
assert_payload "after install"
assert_etc_tapauth
assert_ipc_cli_absent
assert_vendor_profiles
check_systemd_best_effort

# ---------------------------------------------------------------------------
# 6. authselect functional test (optional)
# ---------------------------------------------------------------------------
test_authselect_functional

# ---------------------------------------------------------------------------
# 7. Upgrade
# ---------------------------------------------------------------------------
step "7. Upgrade (rpm -Uvh --replacepkgs)"
rpm -Uvh --replacepkgs "${INSTALL_RPMS[@]}"
assert_payload "after upgrade"
assert_etc_tapauth
assert_ipc_cli_absent
assert_vendor_profiles

# ---------------------------------------------------------------------------
# 8. Remove
# ---------------------------------------------------------------------------
step "8. Remove package (rpm -e tapauth)"
# test_authselect_functional leaves the TapAuth vendor profile selected, so this
# removal must run the %preun rollback. The vendor profile files must disappear
# and no generated stack may keep referencing the removed pam_tapauth.so.
rpm -e tapauth
assert_removed

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
step "Summary"
if [ "$FAILURES" -ne 0 ]; then
    echo "❌ ${FAILURES} Fedora RPM check(s) failed."
    exit 1
fi
echo "🎉 ALL FEDORA RPM INSTALL TESTS PASSED!"
