# shellcheck shell=bash
# Shared verification of the virtual-fprintd D-Bus and PAM invariants.
# Sourced by scripts/ci/test-{ubuntu-deb,fedora-rpm,arch-pkg}.sh (the distro
# containers mount the whole workspace, so sourcing from there works).
#
# Every distro container test must assert the same things: the base package
# ships the D-Bus policy but NO activation file (and no emulation marker), it
# never owns fprintd's exact filename, real fprintd's own activation file keeps
# pointing at fprintd, the optional emulation package ships the bridge marker,
# and the `su` PAM line is inserted after pam_rootok/pam_wheel.
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
# but NOT the emulation marker and NOT any D-Bus activation file, and that the
# package does NOT own the un-renamed activation filename belonging to the real
# fprintd package.
verify_fprintd_coexistence() {
    local pkg_manager="$1"
    local conf="/usr/share/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf"
    local renamed="/usr/share/dbus-1/system-services/net.reactivated.Fprint.tapauth.service"
    local unrenamed="/usr/share/dbus-1/system-services/net.reactivated.Fprint.service"
    local marker="/usr/share/tapauth/fprintd-emulation.enabled"
    local pkg_list_cmd
    case "$pkg_manager" in
        deb)  pkg_list_cmd=(dpkg -L tapauth) ;;
        rpm)  pkg_list_cmd=(rpm -ql tapauth) ;;
        arch) pkg_list_cmd=(pacman -Ql tapauth) ;;
        *) echo "ERROR: unknown package manager '$pkg_manager' (expected deb|rpm|arch)"; exit 1 ;;
    esac

    test -f "$conf"
    # The bridge is opt-in: the base package ships only the D-Bus policy, no
    # activation file and no emulation marker. tapauthd claims the bus name
    # solely at startup, and only when enable_fprintd_bridge is true or the
    # emulation package's marker exists. No D-Bus activation file is shipped
    # (both dbus-daemon and dbus-broker require the filename to match the bus
    # name, so a renamed file would be inert); real fprintd keeps full control
    # of on-demand activation.
    if [ -e "$renamed" ]; then
        echo "ERROR: base package shipped the (removed) renamed activation file $renamed"
        exit 1
    fi
    if "${pkg_list_cmd[@]}" | grep -q "system-services/net.reactivated.Fprint.tapauth.service$"; then
        echo "ERROR: tapauth still owns the removed renamed activation file"
        exit 1
    fi
    # The emulation marker must never be shipped by the base package.
    if [ -e "$marker" ]; then
        echo "ERROR: base package shipped the emulation marker $marker (bridge would default on)"
        exit 1
    fi
    if "${pkg_list_cmd[@]}" | grep -q "share/tapauth/fprintd-emulation.enabled$"; then
        echo "ERROR: tapauth owns the emulation marker (must belong to tapauth-fprintd-emulation only)"
        exit 1
    fi
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

# verify_no_emulation_marker
# After the optional emulation package is removed, its marker must be gone so
# the daemon's tri-state default flips back to "off".
verify_no_emulation_marker() {
    if [ -e /usr/share/tapauth/fprintd-emulation.enabled ]; then
        echo "ERROR: emulation marker survived removal of tapauth-fprintd-emulation"
        exit 1
    fi
}

# assert_su_line_after_rootok <pam-file>
# The TapAuth line in `su` must not land before pam_rootok.so / pam_wheel.so.
# PAM_USER for su is the target user, so inserting first would let a phone
# grant for root bypass those checks. Tolerates su stacks without rootok.
assert_su_line_after_rootok() {
    local pam_file="$1"
    test -f "$pam_file" || return 0
    local tapauth_ln rootok_ln
    tapauth_ln=$(grep -n 'pam_tapauth\.so' "$pam_file" | head -1 | cut -d: -f1 || true)
    rootok_ln=$(grep -nE '^[[:space:]]*auth[[:space:]].*pam_(rootok|wheel)\.so' "$pam_file" | head -1 | cut -d: -f1 || true)
    if [ -n "$rootok_ln" ] && [ -n "$tapauth_ln" ] && [ "$tapauth_ln" -lt "$rootok_ln" ]; then
        echo "ERROR: pam_tapauth.so appears before pam_rootok/pam_wheel in $pam_file (root bypass)"
        grep -n '' "$pam_file"
        exit 1
    fi
}

# fprintd_distro_provider <deb|rpm|arch>
# Prints the distro package that owns pam_fprintd.so (the provider the
# optional tapauth-fprintd-emulation package must conflict with/replace/provide).
# Maps to deb -> libpam-fprintd, rpm -> fprintd-pam, arch -> fprintd.
fprintd_distro_provider() {
    case "$1" in
        deb)  printf '%s\n' "libpam-fprintd" ;;
        rpm)  printf '%s\n' "fprintd-pam" ;;
        arch) printf '%s\n' "fprintd" ;;
        *) echo "ERROR: unknown package manager '$1' (expected deb|rpm|arch)" >&2; return 1 ;;
    esac
}

# _assert_emulation_files_contain_module <file-list>
# The emulation package must install its PAM module as
# .../security/pam_fprintd.so in every supported layout.
_assert_emulation_files_contain_module() {
    if ! printf '%s\n' "$1" | grep -Eq 'security/pam_fprintd\.so$'; then
        echo "ERROR: tapauth-fprintd-emulation does not ship security/pam_fprintd.so"
        exit 1
    fi
}

# _assert_emulation_files_contain_marker <file-list>
# The emulation package must ship the bridge marker at the exact path the Rust
# config constant uses: /usr/share/tapauth/fprintd-emulation.enabled. It is the
# marker's presence alone that flips the tri-state default to "on".
_assert_emulation_files_contain_marker() {
    if ! printf '%s\n' "$1" | grep -Eq '(^|/)usr/share/tapauth/fprintd-emulation\.enabled$'; then
        echo "ERROR: tapauth-fprintd-emulation does not ship /usr/share/tapauth/fprintd-emulation.enabled"
        exit 1
    fi
}

# _emulation_meta_mentions <metadata-blob> <provider>
# Returns 0 if the given dependency metadata declares the distro provider
# (version constraints and comma separators are tolerated).
_emulation_meta_mentions() {
    printf '%s\n' "$1" | grep -Eq "(^|[ ,])$2([ ,=<>()]|$)"
}

# _assert_emulation_meta_mentions <field-label> <metadata-blob> <provider>
# Fails unless the given dependency metadata declares the distro provider
# (version constraints and comma separators are tolerated).
_assert_emulation_meta_mentions() {
    local field="$1" blob="$2" provider="$3"
    if ! _emulation_meta_mentions "$blob" "$provider"; then
        echo "ERROR: tapauth-fprintd-emulation does not declare ${field} against ${provider} (got: ${blob:-<none>})"
        exit 1
    fi
}

# verify_fprintd_emulation_pkg <deb|rpm|arch> [package-dir]
# Asserts the optional tapauth-fprintd-emulation package:
#   * ships its PAM module as .../security/pam_fprintd.so,
#   * ships the bridge marker /usr/share/tapauth/fprintd-emulation.enabled, and
#   * declares the distro fprintd PAM provider as conflict/replace/provide
#     (deb: libpam-fprintd, rpm: fprintd-pam, arch: fprintd).
# When package-dir is given the built package file is inspected; otherwise the
# installed package metadata is queried.
verify_fprintd_emulation_pkg() {
    local pkg_manager="$1"
    local pkg_dir="${2:-}"
    local provider
    provider=$(fprintd_distro_provider "$pkg_manager") || exit 1
    local emu_pkg="tapauth-fprintd-emulation"
    local files conflict replace provide

    case "$pkg_manager" in
        deb)
            if [ -n "$pkg_dir" ]; then
                local deb
                deb=$(find "$pkg_dir" -maxdepth 1 -name 'tapauth-fprintd-emulation_*.deb' | head -1 || true)
                if [ -z "$deb" ]; then
                    echo "ERROR: tapauth-fprintd-emulation .deb not found in $pkg_dir"
                    exit 1
                fi
                files=$(dpkg-deb -c "$deb")
                conflict=$(dpkg-deb -f "$deb" Conflicts)
                replace=$(dpkg-deb -f "$deb" Replaces)
                provide=$(dpkg-deb -f "$deb" Provides)
            else
                if ! dpkg -s "$emu_pkg" >/dev/null 2>&1; then
                    echo "ERROR: $emu_pkg is not installed and no package-dir was given"
                    exit 1
                fi
                files=$(dpkg -L "$emu_pkg")
                conflict=$(dpkg-query -W -f='${Conflicts}' "$emu_pkg")
                replace=$(dpkg-query -W -f='${Replaces}' "$emu_pkg")
                provide=$(dpkg-query -W -f='${Provides}' "$emu_pkg")
            fi
            ;;
        rpm)
            if [ -n "$pkg_dir" ]; then
                local rpmf
                rpmf=$(find "$pkg_dir" -maxdepth 1 -name 'tapauth-fprintd-emulation-*.rpm' | head -1 || true)
                if [ -z "$rpmf" ]; then
                    echo "ERROR: tapauth-fprintd-emulation .rpm not found in $pkg_dir"
                    exit 1
                fi
                files=$(rpm -qpl "$rpmf")
                conflict=$(rpm -qp --conflicts "$rpmf")
                replace=$(rpm -qp --obsoletes "$rpmf")
                provide=$(rpm -qp --provides "$rpmf")
            else
                if ! rpm -q "$emu_pkg" >/dev/null 2>&1; then
                    echo "ERROR: $emu_pkg is not installed and no package-dir was given"
                    exit 1
                fi
                files=$(rpm -ql "$emu_pkg")
                conflict=$(rpm -q --conflicts "$emu_pkg")
                replace=$(rpm -q --obsoletes "$emu_pkg")
                provide=$(rpm -q --provides "$emu_pkg")
            fi
            ;;
        arch)
            if [ -n "$pkg_dir" ]; then
                local pkgf
                pkgf=$(find "$pkg_dir" -maxdepth 1 \
                    -name 'tapauth-fprintd-emulation-*.pkg.tar.zst' \
                    ! -name 'tapauth-fprintd-emulation-git-*' | head -1 || true)
                if [ -z "$pkgf" ]; then
                    echo "ERROR: tapauth-fprintd-emulation package not found in $pkg_dir"
                    exit 1
                fi
                files=$(tar --zstd -tf "$pkgf")
                local pkginfo
                pkginfo=$(tar --zstd -xOf "$pkgf" .PKGINFO)
                conflict=$(printf '%s\n' "$pkginfo" | sed -n 's/^conflict = //p')
                replace=$(printf '%s\n' "$pkginfo" | sed -n 's/^replaces = //p')
                provide=$(printf '%s\n' "$pkginfo" | sed -n 's/^provides = //p')
            else
                if ! pacman -Qq "$emu_pkg" >/dev/null 2>&1; then
                    echo "ERROR: $emu_pkg is not installed and no package-dir was given"
                    exit 1
                fi
                files=$(pacman -Ql "$emu_pkg")
                local qi
                qi=$(LC_ALL=C pacman -Qi "$emu_pkg")
                conflict=$(printf '%s\n' "$qi" | sed -n 's/^Conflicts With *: *//p')
                replace=$(printf '%s\n' "$qi" | sed -n 's/^Replaces *: *//p')
                provide=$(printf '%s\n' "$qi" | sed -n 's/^Provides *: *//p')
            fi
            ;;
    esac

    _assert_emulation_files_contain_module "$files"
    _assert_emulation_files_contain_marker "$files"
    # Debian and RPM can express exclusivity as Provides + Conflicts: dpkg and
    # rpm both exclude a package's own provides from its conflict check, so the
    # conflict still fires against the installed provider. Arch cannot: a
    # provides=fprintd would satisfy its own conflicts=fprintd, so the
    # emulation PKGBUILD deliberately omits the provide and relies on
    # conflicts/replaces instead.
    case "$pkg_manager" in
        deb|rpm) _assert_emulation_meta_mentions "Provides" "$provide" "$provider" ;;
    esac
    # Exclusivity may be expressed either as Conflicts (alternative provider;
    # the user explicitly confirms the swap) or as Obsoletes/Replaces
    # (automatic replacement). Accept either.
    if ! _emulation_meta_mentions "$conflict" "$provider" \
        && ! _emulation_meta_mentions "$replace" "$provider"; then
        echo "ERROR: tapauth-fprintd-emulation must declare Conflicts or Replaces against ${provider} (conflicts: ${conflict:-<none>}; replaces: ${replace:-<none>})"
        exit 1
    fi
    echo "tapauth-fprintd-emulation: ships pam_fprintd.so and declares exclusivity with ${provider} (conflicts/replaces)."
}
