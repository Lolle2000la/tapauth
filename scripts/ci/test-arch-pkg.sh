#!/usr/bin/env bash
#
# End-to-end installation test for the Arch Linux package built from the
# current packaging/arch/PKGBUILD + packaging/arch/tapauth.install.
#
# Run as root inside an Arch container:
#
#     ./scripts/ci/test-arch-pkg.sh [--skip-build] [PKG_DIR]
#
#   --skip-build  Install only minimal tooling (grep/sed/findutils) and test
#                 the packages already present in PKG_DIR.
#   PKG_DIR       Directory holding the built .pkg.tar.zst files (or where the
#                 build step should place them).
#                 Default: ${WORKSPACE_DIR}/pkg-arch.
#
# Exits non-zero if any assertion fails. All checks are executed so the log
# shows every failure at once.
set -euo pipefail

# Deterministic tool output (pacman messages).
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
PKG_DIR="${PKG_DIR:-${WORKSPACE_DIR}/pkg-arch}"

# Version comes from the crate manifest; fall back to a `[workspace.package]`
# version for the `version.workspace = true` layout (same logic as
# _pkg-common.sh) so this test still resolves the version if the manifests move
# to workspace inheritance.
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
    echo "❌ Could not determine PKG_VER from tapauthd/Cargo.toml or [workspace.package] in Cargo.toml" >&2
    exit 1
fi
echo "==> Testing Arch Linux packaging for TapAuth version: ${PKG_VER}"
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

# ---------------------------------------------------------------------------
# pacman wrappers
#
# The packaged tapauth.install scriptlets call systemctl/systemd-sysusers/
# systemd-tmpfiles unconditionally; in a container without systemd those fail.
# pacman reports the scriptlet error, but the package is still installed/
# removed, so tolerate that specific situation instead of failing the test.
# ---------------------------------------------------------------------------
pacman_install() {
    local out rc=0
    if out=$(pacman -U --noconfirm "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    printf '%s\n' "$out" | sed 's/^/   /'
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    if pacman -Qq tapauth >/dev/null 2>&1; then
        printf '⚠️  pacman -U exited %s (likely a systemd scriptlet in this container), but tapauth is installed; continuing.\n' "$rc"
        return 0
    fi
    return "$rc"
}

pacman_remove() {
    local out rc=0
    if out=$(pacman -R --noconfirm "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    printf '%s\n' "$out" | sed 's/^/   /'
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    if ! pacman -Qq tapauth >/dev/null 2>&1; then
        printf '⚠️  pacman -R exited %s (likely a systemd scriptlet in this container), but tapauth is removed; continuing.\n' "$rc"
        return 0
    fi
    return "$rc"
}

# ---------------------------------------------------------------------------
# Assertion groups
# ---------------------------------------------------------------------------
assert_payload() {
    step "Payload assertions ($1)"
    check_exec /usr/bin/tapauthd "binary /usr/bin/tapauthd"
    check_exec /usr/bin/tapauth-config "binary /usr/bin/tapauth-config"
    check_file /usr/lib/security/pam_tapauth.so "PAM module /usr/lib/security/pam_tapauth.so"

    check_file /usr/lib/systemd/system/tapauthd.service "unit tapauthd.service"
    check_file /usr/lib/systemd/system/tapauthd.socket "unit tapauthd.socket"
    check_file /usr/lib/systemd/system/polkit-agent-helper@.service.d/tapauth.conf \
        "unit drop-in polkit-agent-helper@.service.d/tapauth.conf"

    check_file /usr/lib/sysusers.d/tapauth.conf "sysusers.d/tapauth.conf"
    check_file /usr/lib/tmpfiles.d/tapauth.conf "tmpfiles.d/tapauth.conf"
    check_file /usr/share/applications/tapauth-config.desktop "desktop entry tapauth-config.desktop"
    check_file /usr/share/icons/hicolor/scalable/apps/tapauth-config.svg "icon tapauth-config.svg"
    check_file /usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy \
        "polkit action dev.rourunisen.tapauth.config.admin.policy"
    check_file /usr/share/polkit-1/rules.d/50-tapauthd.rules "polkit rule 50-tapauthd.rules"
    check_file /usr/share/licenses/tapauth/LICENSE "license /usr/share/licenses/tapauth/LICENSE"
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
    # The package does not ship config.toml; tapauth.install's post_install runs
    # systemd-tmpfiles, which creates it owned by the daemon (the single writer
    # via SaveConfig). The directory stays root:root.
    local cfg=/etc/tapauth/config.toml
    check_file "$cfg" "config.toml is created at install time (via tmpfiles)"
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
    # must be able to persist SaveConfig.
    if runuser -u tapauthd -- test -w "$cfg"; then
        pass "tapauthd can write $cfg (SaveConfig works on a fresh install)"
    else
        fail "tapauthd cannot write $cfg (SaveConfig would fail with EACCES)"
    fi
    # PKGBUILD declares backup=('etc/tapauth/config.toml'); the file is created
    # by tmpfiles rather than shipped, so pacman backs up/restores whatever is
    # on disk at that path on upgrade.
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
    if pacman -Ql tapauth 2>/dev/null | grep -q 'tapauth-ipc-cli'; then
        fail "tapauth package payload contains tapauth-ipc-cli"
    else
        pass "tapauth package payload has no tapauth-ipc-cli"
    fi
}

assert_pam_untouched() {
    step "Arch packaging must not patch /etc/pam.d"
    if [ -e /etc/pam.d/system-auth ]; then
        if grep -qs 'pam_tapauth\.so' /etc/pam.d/system-auth; then
            fail "/etc/pam.d/system-auth references pam_tapauth.so"
        else
            pass "/etc/pam.d/system-auth present but references no pam_tapauth.so"
        fi
    else
        pass "/etc/pam.d/system-auth is absent (package did not create it)"
    fi
    if grep -rqs 'pam_tapauth\.so' /etc/pam.d 2>/dev/null; then
        fail "some file under /etc/pam.d references pam_tapauth.so"
    else
        pass "no file under /etc/pam.d references pam_tapauth.so"
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
    check_absent /usr/lib/security/pam_tapauth.so "PAM module removed"
    check_absent /usr/lib/systemd/system/tapauthd.service "tapauthd.service unit removed"
    check_absent /usr/lib/systemd/system/tapauthd.socket "tapauthd.socket unit removed"
    check_absent /usr/lib/sysusers.d/tapauth.conf "sysusers.d/tapauth.conf removed"
    check_absent /usr/lib/tmpfiles.d/tapauth.conf "tmpfiles.d/tapauth.conf removed"
    check_absent /usr/share/applications/tapauth-config.desktop "desktop entry removed"
    check_absent /usr/share/icons/hicolor/scalable/apps/tapauth-config.svg "icon removed"
    check_absent /usr/share/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy \
        "polkit action removed"
    check_absent /usr/share/polkit-1/rules.d/50-tapauthd.rules "polkit rule removed"
    check_absent /usr/share/licenses/tapauth/LICENSE "license removed"

    # The package never edited PAM, so removal must not have touched it either.
    if grep -rqs 'pam_tapauth\.so' /etc/pam.d 2>/dev/null; then
        fail "some file under /etc/pam.d references pam_tapauth.so after removal"
    else
        pass "no file under /etc/pam.d references pam_tapauth.so after removal"
    fi
}

# ---------------------------------------------------------------------------
# 0. Tooling / build
# ---------------------------------------------------------------------------
if [ "$SKIP_BUILD" = false ]; then
    step "Installing Arch build dependencies"
    pacman -Sy --noconfirm --needed sudo cargo rust protobuf clang pam dbus \
        systemd git tar binutils findutils sed grep

    step "Building Arch packages into ${PKG_DIR}"
    bash "${WORKSPACE_DIR}/scripts/ci/build-arch-packages.sh" --output-dir "${PKG_DIR}"
else
    step "Installing minimal tooling (--skip-build)"
    # Refresh the databases so a later dependency resolution during pacman -U
    # does not fail on a stale sync database.
    pacman -Sy --noconfirm || skip "pacman -Sy failed; continuing with existing databases"
    pacman -S --noconfirm --needed grep sed findutils
fi

# ---------------------------------------------------------------------------
# Locate the built package (the main tapauth package starts with a digit)
# ---------------------------------------------------------------------------
shopt -s nullglob
PKG_FILES=("${PKG_DIR}"/tapauth-[0-9]*.pkg.tar.zst)
if [ "${#PKG_FILES[@]}" -eq 0 ]; then
    echo "❌ No installable tapauth package found in ${PKG_DIR}" >&2
    exit 1
fi
step "Installable packages"
for pkg_path in "${PKG_FILES[@]}"; do
    note "$(basename "$pkg_path")"
done

# ---------------------------------------------------------------------------
# 1. Install
# ---------------------------------------------------------------------------
step "1. pacman -U tapauth"
if ! pacman_install "${PKG_FILES[@]}"; then
    echo "❌ pacman -U failed to install tapauth (and the package is absent)" >&2
    exit 1
fi
if pacman -Qq tapauth >/dev/null 2>&1; then
    pass "pacman -Qq tapauth reports the package installed"
else
    fail "pacman -Qq tapauth reports the package not installed"
fi

# ---------------------------------------------------------------------------
# 2-5. Post-install assertions
# ---------------------------------------------------------------------------
assert_payload "after install"
assert_etc_tapauth
assert_ipc_cli_absent
assert_pam_untouched
check_systemd_best_effort

# ---------------------------------------------------------------------------
# 6. Upgrade (exercises post_upgrade)
# ---------------------------------------------------------------------------
step "6. Upgrade (pacman -U again)"
if ! pacman_install "${PKG_FILES[@]}"; then
    echo "❌ pacman -U upgrade failed and tapauth is not installed" >&2
    exit 1
fi
assert_payload "after upgrade"
assert_etc_tapauth
assert_ipc_cli_absent
assert_pam_untouched

# ---------------------------------------------------------------------------
# 7. Remove
# ---------------------------------------------------------------------------
step "7. Remove package (pacman -R tapauth)"
if ! pacman_remove tapauth; then
    echo "❌ pacman -R failed to remove tapauth (and the package is still present)" >&2
    exit 1
fi
assert_removed

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
step "Summary"
if [ "$FAILURES" -ne 0 ]; then
    echo "❌ ${FAILURES} Arch package check(s) failed."
    exit 1
fi
echo "🎉 ALL ARCH LINUX PACKAGE INSTALL TESTS PASSED!"
