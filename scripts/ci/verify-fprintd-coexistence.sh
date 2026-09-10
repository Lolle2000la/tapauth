# Shared verification of the virtual-fprintd D-Bus coexistence invariants.
# Sourced by scripts/ci/test-{ubuntu-deb,fedora-rpm,arch-pkg}.sh (the distro
# containers mount the whole workspace, so sourcing from there works).
#
# Every distro container test must assert the same thing: the base package
# ships the RENAMED activation file, never owns fprintd's exact filename, and
# real fprintd's own activation file keeps pointing at fprintd — regardless of
# the package manager used to list/verify ownership.
#
# No set -e here: callers already run with set -euo pipefail, and sourcing
# would otherwise flip their options. All functions exit non-zero on failure.

# Real fprintd activation Exec paths per distro family (pass to
# assert_fprintd_exec_matches; the Arch build ships /usr/lib/fprintd, the
# RPM/DEB families ship /usr/libexec/fprintd, /usr/lib/fprintd/fprintd or
# /usr/sbin/fprintd depending on release).

# assert_fprintd_exec_matches <file> <failure-message> <allowed-exec>...
# Extracts the Exec= binary from a D-Bus activation file and asserts it is
# one of the allowed paths. Prints the resolved Exec on success.
assert_fprintd_exec_matches() {
    local file="$1" msg="$2"
    shift 2
    local exec_bin
    exec_bin=$(grep -m1 '^Exec=' "$file" | sed 's/^Exec=//;s/ .*//')
    echo "Real fprintd activation Exec: $exec_bin"
    local pat
    for pat in "$@"; do
        if [[ "$exec_bin" == "$pat" ]]; then
            return 0
        fi
    done
    echo "ERROR: $msg (got Exec: $exec_bin)"
    exit 1
}

# assert_exec_not_tapauth <file> <failure-message>
# The activation file must NOT reference tapauthd (used for fprintd's own
# un-renamed net.reactivated.Fprint.service, which tapauth must never own
# or overwrite).
assert_exec_not_tapauth() {
    local file="$1" msg="$2"
    if grep -m1 '^Exec=' "$file" | grep -q 'tapauthd'; then
        echo "ERROR: $msg"
        exit 1
    fi
}

# verify_fprintd_coexistence <pkg-manager: deb|rpm|arch>
# Asserts the installed base package ships the virtual-fprintd D-Bus policy
# plus the RENAMED activation file with the expected content, and that the
# package does NOT own the un-renamed activation filename belonging to the
# real fprintd package.
verify_fprintd_coexistence() {
    local pkg_manager="$1"
    local conf="/usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf"
    local renamed="/usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service"
    local unrenamed="/usr/share/dbus-1/system-services/net.reactivated.Fprint.service"
    local pkg_list_cmd
    case "$pkg_manager" in
        deb)  pkg_list_cmd=(dpkg -L tapauth) ;;
        rpm)  pkg_list_cmd=(rpm -ql tapauth) ;;
        arch) pkg_list_cmd=(pacman -Ql tapauth) ;;
        *) echo "ERROR: unknown package manager '$pkg_manager' (expected deb|rpm|arch)"; exit 1 ;;
    esac

    test -f "$conf"
    # The activation file is RENAMED (net.reactivated.Fprint.tapauth.service) so
    # it can never collide with real fprintd's own
    # net.reactivated.Fprint.service. Container-verified semantics: BOTH
    # dbus-daemon (1.12.20 & 1.14.10) and dbus-broker (36) require the service
    # file's filename to match the bus name, so the renamed file is an inert,
    # collision-free placeholder — neither broker uses it for activation; real
    # fprintd keeps full control of on-demand activation. The file still ships
    # (never zero activation files) for forward compatibility.
    test -f "$renamed"
    grep -q '^Name=net.reactivated.Fprint$' "$renamed"
    grep -q '^Exec=/usr/bin/tapauthd$' "$renamed"
    grep -q '^User=tapauthd$' "$renamed"
    grep -q '^SystemdService=tapauthd.service$' "$renamed"
    # tapauth must never own (or overwrite) fprintd's exact activation filename.
    # The un-renamed file may legitimately exist on disk because the
    # coexistence test installs the real fprintd package.
    if "${pkg_list_cmd[@]}" | grep -q "system-services/net.reactivated.Fprint.service$"; then
        echo "ERROR: tapauth ships the un-renamed net.reactivated.Fprint.service (collision with fprintd)"
        exit 1
    fi
    if [ -f "$unrenamed" ]; then
        assert_exec_not_tapauth "$unrenamed" \
            "net.reactivated.Fprint.service points at tapauthd (tapauth must never own that file)"
    fi
}
