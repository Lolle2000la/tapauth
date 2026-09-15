# Rust --release produces stripped binaries; disable automatic debuginfo
# subpackage generation to avoid empty debugsourcefiles.list errors on RHEL
%global debug_package %{nil}

Name:           tapauth
Version:        %{?pkgversion}%{!?pkgversion:0.1.0}
Release:        1%{?dist}
Summary:        Local smartphone-based authentication framework

License:        AGPL-3.0-only
URL:            https://github.com/lolle2000la/tapauth
Source0:        https://github.com/lolle2000la/tapauth/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
Source1:        tapauth-sysusers.conf
Source2:        tapauth-tmpfiles.conf

%bcond_with check

ExclusiveArch:  x86_64 aarch64
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  clang
%if 0%{?suse_version}
BuildRequires:  protobuf-devel
%else
BuildRequires:  protobuf-compiler
%endif
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pam-devel
BuildRequires:  systemd-rpm-macros
%{?sysusers_requires_compat}
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires:       pam
Requires:       polkit
Requires:       dbus
# firewalld/iptables are optional integrations. They must be Suggests, not
# Recommends: dnf removes Recommends when the package is removed, which
# would uninstall the system firewall (and can fail the whole transaction).
Suggests:       firewalld iptables

%description
A modern, privacy-preserving local-first authentication system using Rust
PAM modules, systemd system daemons, and low-level communication links.

pam_tapauth.so is wired into sudo, su and polkit-1 only; all other PAM
stacks — including fingerprint stacks (kde-fingerprint, gdm-fingerprint,
fingerprint-auth) — stay stock.

Desktop lock screens and greeters (KDE Plasma, GNOME) can integrate
through the built-in virtual fprintd D-Bus service
(net.reactivated.Fprint): stock fingerprint stacks call pam_fprintd.so,
which resolves to tapauthd. This base package deliberately does NOT
conflict with the real fprintd package and does NOT ship a D-Bus
activation file; tapauthd is a systemd-managed daemon that owns the bus
name while it runs (and restarts on failure), so the virtual bridge
needs no activation support from D-Bus. It ships only the D-Bus policy
file that lets tapauthd own the name.

The virtual bridge is opt-in. With enable_fprintd_bridge unset (the
default), it is enabled only when the optional tapauth-fprintd-emulation
subpackage is installed (it ships the marker file
/usr/share/tapauth/fprintd-emulation.enabled); the base package ships no
marker, so a real local fingerprint reader is never shadowed by a base
install and real fprintd keeps the bus name. Set enable_fprintd_bridge
= true or = false in /etc/tapauth/config.toml to force the bridge on or
off explicitly (applies at the next daemon restart). The optional
tapauth-fprintd-emulation subpackage replaces the fprintd PAM provider
and ships the marker. No local fingerprint reader is required.

%package fprintd-emulation
Summary:        Optional fprintd PAM emulation for TapAuth (pam_fprintd.so)
# The optional emulation subpackage is an alternative provider of
# pam_fprintd.so: it Provides fprintd-pam while Conflicting with the
# distro fprintd-pam, so the two providers can never be installed at once
# and the user must explicitly confirm the swap. There is deliberately no
# Obsoletes: replacing the distro module is an opt-in choice, not an
# automatic upgrade.
Provides:       fprintd-pam = %{version}-%{release}
Conflicts:      fprintd-pam
Requires:       %{name} = %{version}-%{release}
# %post/%postun bounce tapauthd so the marker-derived bridge default is
# re-evaluated at daemon startup.
Requires(post): systemd
Requires(postun): systemd

%description fprintd-emulation
This optional subpackage ships a second build of the TapAuth PAM module,
installed as pam_fprintd.so, taking over the file normally provided by
the fprintd-pam subpackage.

It exists for the opt-in case where stock fingerprint PAM stacks must be
served by TapAuth instead of a real local fingerprint reader. It
Provides and Conflicts fprintd-pam so the two providers of pam_fprintd.so
can never coexist and installing it requires explicitly replacing the
distro module. The fprintd daemon package itself is deliberately NOT
conflicted with, and the base tapauth package stays unchanged (it keeps
shipping pam_tapauth.so and ships no D-Bus activation file).

It also ships the marker file /usr/share/tapauth/fprintd-emulation.enabled
which turns the daemon's tri-state enable_fprintd_bridge default into "on"
(the D-Bus name net.reactivated.Fprint is claimed at tapauthd startup), so
lock screens/greeters can discover the virtual fingerprint device. Its
scriptlets restart tapauthd so the claim/release takes effect immediately.
With enable_fprintd_bridge = false in /etc/tapauth/config.toml the marker
is overridden and the bridge stays off.

%prep
%setup -q -n %{name}-%{version}

%build
export CARGO_HOME="%{?_cargo_home}%{!?_cargo_home:${CARGO_HOME:-%{_builddir}/cargo-home}}"
export CARGO_PROFILE_RELEASE_STRIP=true
export CARGO_TARGET_DIR="%{?_cargo_target_dir}%{!?_cargo_target_dir:${CARGO_TARGET_DIR:-target}}"
if command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER=sccache
    export SCCACHE_DIR="%{?_sccache_dir}%{!?_sccache_dir:${SCCACHE_DIR:-%{_builddir}/sccache}}"
fi
cargo build --workspace --release --locked %{?cargo_features}
# Opt-in second client-pam build backing the fprintd-emulation subpackage.
# Uses a separate target dir (under CARGO_TARGET_DIR) so the base
# libclient_pam.so installed as pam_tapauth.so is never clobbered.
# %{?cargo_features} is deliberately NOT reused: it may contain
# package-qualified workspace features (e.g. tapauthd/dev-udp-loopback)
# that the client-pam package does not define.
cargo build -p client-pam --release --locked --features replace-fprintd-pam \
    --target-dir "${CARGO_TARGET_DIR}/fprintd-emulation"
if command -v sccache >/dev/null 2>&1; then
    sccache --show-stats || true
fi

%if %{with check}
%check
cargo test --workspace %{?cargo_features}
%endif

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/security
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_presetdir}
mkdir -p %{buildroot}%{_sysusersdir}
mkdir -p %{buildroot}%{_tmpfilesdir}
mkdir -p %{buildroot}%{_sharedstatedir}/tapauth
mkdir -p %{buildroot}%{_datadir}/doc/tapauth
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
mkdir -p %{buildroot}%{_datadir}/polkit-1/actions
mkdir -p %{buildroot}%{_datadir}/polkit-1/rules.d
mkdir -p %{buildroot}%{_sysconfdir}/tapauth

# Binaries & Shared Objects
# (the install section runs in the source dir; the cargo target dir mirrors the build one)
# NOTE: tapauth-ipc-cli is a testing-only admin tool and is deliberately NOT
# installed/shipped here. It is built from the workspace by the E2E harness.
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauthd" %{buildroot}%{_bindir}/tapauthd
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauth-config" %{buildroot}%{_bindir}/tapauth-config
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/libclient_pam.so" %{buildroot}%{_libdir}/security/pam_tapauth.so

# fprintd-emulation subpackage: the second (opt-in) client-pam build,
# installed under fprintd's module name. The base %files lists only
# pam_tapauth.so, so the two packages never share a path.
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/fprintd-emulation/release/libclient_pam.so" %{buildroot}%{_libdir}/security/pam_fprintd.so

# Default Configuration
# The virtual fprintd bridge is opt-in: with enable_fprintd_bridge unset the
# daemon follows the marker file shipped by the optional fprintd-emulation
# subpackage (absent for a base install), so a base install does not claim the
# net.reactivated.Fprint bus name. Do not write enable_fprintd_bridge here;
# users can force it with an explicit key in config.toml.
cat << 'EOF' > %{buildroot}%{_sysconfdir}/tapauth/config.toml
# TapAuth System Configuration
EOF
chmod 0644 %{buildroot}%{_sysconfdir}/tapauth/config.toml

# System Services and Presets
install -m 0644 systemd/tapauthd.service %{buildroot}%{_unitdir}/tapauthd.service
install -m 0644 systemd/tapauthd.socket %{buildroot}%{_unitdir}/tapauthd.socket
install -m 0644 packaging/90-tapauthd.preset %{buildroot}%{_presetdir}/90-tapauthd.preset

mkdir -p %{buildroot}%{_unitdir}/polkit-agent-helper@.service.d
install -m 0644 systemd/polkit-agent-helper@.service.d/tapauth.conf %{buildroot}%{_unitdir}/polkit-agent-helper@.service.d/tapauth.conf

# Structural Declarations
install -m 0644 packaging/sysusers.conf %{buildroot}%{_sysusersdir}/tapauth.conf
install -m 0644 packaging/tmpfiles.conf %{buildroot}%{_tmpfilesdir}/tapauth.conf
install -m 0644 config.toml.example %{buildroot}%{_datadir}/doc/tapauth/config.toml.example
install -m 0644 client-config-gui/tapauth-config.desktop %{buildroot}%{_datadir}/applications/tapauth-config.desktop
install -m 0644 client-config-gui/assets/tapauth-config.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/tapauth-config.svg
install -m 0644 tapauthd/dev.rourunisen.tapauth.config.admin.policy %{buildroot}%{_datadir}/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy
install -m 0644 packaging/50-tapauthd.rules %{buildroot}%{_datadir}/polkit-1/rules.d/50-tapauthd.rules

# SELinux Policy Module
mkdir -p %{buildroot}%{_datadir}/selinux/packages
install -m 0644 packaging/selinux/tapauth.cil %{buildroot}%{_datadir}/selinux/packages/tapauth.cil

# Virtual fprintd D-Bus bridge: the base package ships only the D-Bus policy
# file (functionally required so tapauthd may own the net.reactivated.Fprint
# bus name when the bridge is enabled). No D-Bus activation file is shipped:
# dbus-daemon and dbus-broker only activate files named exactly after the bus
# name, so a renamed TapAuth file would be inert, and real fprintd's own
# net.reactivated.Fprint.service keeps full control of on-demand activation.
# tapauthd's availability comes from systemd (started at install,
# Restart=on-failure), not from D-Bus activation.
mkdir -p %{buildroot}%{_datadir}/dbus-1/system.d
install -m 0644 packaging/net.reactivated.Fprint.tapauth.conf %{buildroot}%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

# Optional fprintd-emulation marker: its presence (and only its presence)
# flips the daemon's tri-state enable_fprintd_bridge default to "on". Empty
# file; the %files fprintd-emulation section owns the directory and the file.
mkdir -p %{buildroot}%{_datadir}/tapauth
: > %{buildroot}%{_datadir}/tapauth/fprintd-emulation.enabled
chmod 0644 %{buildroot}%{_datadir}/tapauth/fprintd-emulation.enabled

%pre
%sysusers_create_compat %{SOURCE1}
getent group tapauthd >/dev/null 2>&1 || groupadd -r tapauthd
getent group tapauthd-clients >/dev/null 2>&1 || groupadd -r tapauthd-clients
if ! getent passwd tapauthd >/dev/null 2>&1; then
    useradd -r -g tapauthd -G tapauthd-clients -d /var/lib/tapauth -s /usr/sbin/nologin \
        -c "TapAuth Daemon" tapauthd
else
    usermod -aG tapauthd-clients tapauthd 2>/dev/null || true
fi

%post
%tmpfiles_create %{_tmpfilesdir}/tapauth.conf
chown tapauthd:tapauthd %{_sysconfdir}/tapauth 2>/dev/null || true
chmod 0755 %{_sysconfdir}/tapauth 2>/dev/null || true
chmod 0644 %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
chown tapauthd:tapauthd %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true

# Patch only the three PAM services in scope: sudo, su, polkit-1. All other
# stacks — including fingerprint stacks (kde-fingerprint, gdm-fingerprint,
# fingerprint-auth) — stay stock: they call pam_fprintd.so, which resolves to
# tapauthd's virtual fprintd D-Bus service when the bridge is enabled (opt-in;
# see the fprintd-emulation subpackage). Vendor PAM files live in
# /usr/lib/pam.d on Fedora; /etc/pam.d overrides them. When no /etc override
# exists yet, seed one from the vendor file so the inserted line does not
# replace the vendor stack.
pam_line="auth        sufficient    pam_tapauth.so"
for pam_svc in sudo su polkit-1; do
    pam_file="/etc/pam.d/${pam_svc}"
    if [ ! -e "$pam_file" ] && [ ! -e "/usr/lib/pam.d/${pam_svc}" ]; then
        continue
    fi
    if [ ! -e "$pam_file" ]; then
        install -m 0644 "/usr/lib/pam.d/${pam_svc}" "$pam_file" 2>/dev/null || continue
    fi
    if [ ! -f "$pam_file" ] || [ -L "$pam_file" ]; then
        continue
    fi
    if grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
        continue
    fi
    # Keep a pristine copy for restore on removal (only created once so it
    # stays the unmodified upstream file).
    if [ ! -f "${pam_file}.tapauth-bak" ]; then
        cp -p "$pam_file" "${pam_file}.tapauth-bak" 2>/dev/null || true
    fi
    if [ "$pam_svc" = "su" ]; then
        # PAM_USER for su is the TARGET user, so inserting at the top would
        # let a phone grant for root bypass pam_rootok.so / pam_wheel.so (and
        # would prompt for root's own `su`). Fedora's su has no pam_env.so, so
        # insert after the pam_rootok/pam_wheel block and before the first
        # auth include (system-auth / common-auth / @include).
        pam_anchor=$(awk '
            /^[[:space:]]*#/ { next }
            /(common-auth|system-auth)/ || ($1 == "auth" && /(include|substack)/) { print NR; exit }
        ' "$pam_file")
        if [ -n "$pam_anchor" ]; then
            sed -i "${pam_anchor}i $pam_line" "$pam_file" 2>/dev/null || true
        elif head -n1 "$pam_file" | grep -q '^#%PAM-1.0'; then
            sed -i "1a $pam_line" "$pam_file" 2>/dev/null || true
        else
            sed -i "1i $pam_line" "$pam_file" 2>/dev/null || true
        fi
    elif head -n1 "$pam_file" | grep -q '^#%PAM-1.0'; then
        sed -i "1a $pam_line" "$pam_file" 2>/dev/null || true
    else
        sed -i "1i $pam_line" "$pam_file" 2>/dev/null || true
    fi
done

%systemd_post tapauthd.socket
if [ $1 -eq 1 ]; then
    # Start the socket immediately on initial install so auth requests don't hit a dead socket
    systemctl start tapauthd.socket 2>/dev/null || true
fi
# Start (or bounce) the daemon so the IPC socket answers right away and the
# (opt-in) virtual fprintd bridge is evaluated at startup (the D-Bus name is
# claimed only then). `start` is a no-op when already running.
systemctl start tapauthd.service 2>/dev/null || \
    systemctl try-restart tapauthd.service 2>/dev/null || true
if command -v systemctl &>/dev/null && systemctl is-active --quiet dbus 2>/dev/null; then
    systemctl reload dbus 2>/dev/null || true
fi

echo "TapAuth: pam_tapauth.so was wired into sudo, su and polkit-1"
echo "         (originals kept as <file>.tapauth-bak; in su it is inserted"
echo "         after pam_rootok/pam_wheel so it cannot bypass them)."
echo "         Fingerprint stacks stay stock; the virtual fprintd bridge is"
echo "         opt-in (install tapauth-fprintd-emulation, or set"
echo "         enable_fprintd_bridge = true, then restart tapauthd)."
# Membership is a manual, per-user opt-in: the scriptlet never modifies group
# membership. Needed for the configuration GUI and for user-session lock-screen
# unlock (e.g. KDE's kscreenlocker_worker, which runs as the logged-in user,
# reaches /run/tapauthd/tapauthd.sock as root:tapauthd-clients 0660). Root-run
# greeters/auth helpers (GDM/SDDM/LightDM) are unaffected. Memberships are
# deliberately left in place on removal/purge (only the sysusers group itself
# is removed on %preun/erase).
echo "TapAuth: To use the configuration GUI and to unlock user-session"
echo "         lock screens, add your user to the tapauthd-clients group:"
echo "         sudo usermod -aG tapauthd-clients \$USER"
echo "         Then log out and log back in for the change to take effect."
echo "         Membership is not granted automatically. Root-run greeters and"
echo "         auth helpers (GDM/SDDM/LightDM) are unaffected."
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    echo "TapAuth: SELinux is Enforcing. If GDM/KDM lock screen authentication fails due to AVC denial,"
    echo "         allow GDM to connect to the daemon socket via:"
    echo "         sudo ausearch -m avc -ts recent | audit2allow -M tapauth_gdm && sudo semodule -i tapauth_gdm.pp"
fi
if command -v semodule >/dev/null 2>&1 && [ -x /usr/sbin/selinuxenabled ] && /usr/sbin/selinuxenabled 2>/dev/null; then
    semodule -i %{_datadir}/selinux/packages/tapauth.cil 2>/dev/null || true
fi
restorecon -R /run/tapauthd %{_sharedstatedir}/tapauth %{_sysconfdir}/tapauth 2>/dev/null || true

# The optional fprintd-emulation subpackage ships the marker file that flips
# the daemon's tri-state enable_fprintd_bridge default to "on". The daemon
# claims/releases the net.reactivated.Fprint bus name only at startup, so a
# running daemon must be bounced after the file is added/removed. Guarded and
# non-fatal (no systemd, or daemon not running, must not fail the transaction).
%post fprintd-emulation
if command -v systemctl >/dev/null 2>&1; then
    systemctl try-restart tapauthd.service 2>/dev/null || true
fi

%preun
%systemd_preun tapauthd.service tapauthd.socket
%if 0%{?fedora} || 0%{?rhel}
if { [ "$1" -eq 0 ] || [ "$1" -eq 1 ]; } && command -v authselect >/dev/null 2>&1; then
    # Upgrade migration from TapAuth <= 0.10.x: those releases shipped
    # authselect vendor profiles (vendor/tapauth, vendor/tapauth-sssd) and
    # could leave the system selected into one of them. This package no
    # longer ships authselect profiles, so the selection would dangle (and
    # the authselect-generated /etc/pam.d/system-auth and password-auth
    # would keep referencing the now-removed pam_tapauth.so module).
    # Restore the stock profile the vendor profile was derived from on BOTH
    # erase ($1 -eq 0) and upgrade ($1 -eq 1: the new package's %post runs
    # after this %preun and re-patches the three in-scope PAM services, so
    # the rollback must happen first — mirroring the Debian maintainer
    # scripts, which regenerate the pam-auth-update stacks on upgrade too).
    # The profile checks below keep this a no-op for systems that were
    # never selected into a TapAuth profile. rpm then drops the leftover
    # profile directory.
    current_profile=$(LC_ALL=C authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs || true)
    case "$current_profile" in
        vendor/tapauth|custom/tapauth|tapauth)
            target_profile="local"
            ;;
        vendor/tapauth-sssd|custom/tapauth-sssd|tapauth-sssd)
            target_profile="sssd"
            ;;
        *)
            target_profile=""
            ;;
    esac
    if [ -n "$target_profile" ]; then
        features=$(LC_ALL=C authselect current 2>/dev/null | grep '^- ' | cut -c3- | tr '\n' ' ' || true)
        authselect select "$target_profile" $features --force 2>/dev/null || \
            authselect select "$target_profile" --force 2>/dev/null || true
        # Remove the leftover custom/vendor profile directory if the old
        # package left it behind (e.g. unclean upgrades).
        rm -rf /etc/authselect/custom/tapauth /etc/authselect/custom/tapauth-sssd 2>/dev/null || true
    elif [ -d /etc/authselect/custom/tapauth ] || [ -d /etc/authselect/custom/tapauth-sssd ]; then
        # Dangling custom profile directory without an active TapAuth
        # selection: just clean it up.
        rm -rf /etc/authselect/custom/tapauth /etc/authselect/custom/tapauth-sssd 2>/dev/null || true
    fi
fi
%endif
if [ $1 -eq 0 ]; then
    # Strip the TapAuth-inserted line(s) from the three PAM services in
    # scope (sudo, su, polkit-1) and drop the one-time snapshot. The
    # .tapauth-bak copy is deliberately NOT restored over the file: it was
    # taken once at install time, so copying it back would silently revert
    # every admin edit and vendor/distro update made since. (An admin who
    # really wants the install-time snapshot back can restore it manually
    # from the .tapauth-bak copy — or via the standalone uninstall.sh
    # --restore-pam-backups path.) Removing only our line cannot lock
    # anyone out, and stays best-effort so removal never fails.
    for pam_svc in sudo su polkit-1; do
        pam_file="/etc/pam.d/${pam_svc}"
        if [ ! -f "$pam_file" ] || [ -L "$pam_file" ]; then
            continue
        fi
        sed -i '/pam_tapauth\.so/d' "$pam_file" 2>/dev/null || true
        rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
    done
    # If TapAuth seeded the /etc/pam.d/polkit-1 override from a vendor file
    # in /usr/lib/pam.d, stripping the line can leave the override
    # byte-identical to that vendor stack. In that case delete the override
    # so the vendor file applies again. cmp -s is what makes this safe (any
    # admin edit anywhere in the file keeps the override); skip entirely
    # when cmp is unavailable. Never remove a symlink.
    if [ -f /etc/pam.d/polkit-1 ] && [ ! -L /etc/pam.d/polkit-1 ] \
        && [ -f /usr/lib/pam.d/polkit-1 ] && command -v cmp >/dev/null 2>&1; then
        if cmp -s /etc/pam.d/polkit-1 /usr/lib/pam.d/polkit-1; then
            rm -f /etc/pam.d/polkit-1 2>/dev/null || true
        fi
    fi
    # Best-effort cleanup for upgrades from older versions, which patched
    # fingerprint stacks (kde-fingerprint, gdm-fingerprint,
    # gdm3-fingerprint, fingerprint-auth) directly. Synthetic
    # "# Managed by TapAuth" files are deleted; real vendor stacks have only
    # the TapAuth lines stripped (the snapshot is dropped, never copied
    # back — see above).
    for pam_file in /etc/pam.d/kde-fingerprint /etc/pam.d/gdm-fingerprint /etc/pam.d/gdm3-fingerprint /etc/pam.d/fingerprint-auth; do
        if [ ! -f "$pam_file" ] || [ -L "$pam_file" ]; then
            continue
        fi
        if ! grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null \
            && ! grep -q "# Managed by TapAuth" "$pam_file" 2>/dev/null; then
            rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
            continue
        fi
        if grep -q "# Managed by TapAuth" "$pam_file" 2>/dev/null; then
            rm -f "$pam_file" "${pam_file}.tapauth-bak" 2>/dev/null || true
        else
            sed -i '/pam_tapauth\.so/d' "$pam_file" 2>/dev/null || true
            rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
        fi
    done
    # Remove the GDM dconf override written by older versions.
    if [ -f /etc/dconf/db/gdm.d/10-tapauth-fingerprint ]; then
        rm -f /etc/dconf/db/gdm.d/10-tapauth-fingerprint
        if command -v dconf &>/dev/null; then
            dconf update 2>/dev/null || true
        fi
    fi
fi

%postun
%systemd_postun_with_restart tapauthd.service tapauthd.socket
if [ $1 -eq 0 ] && command -v semodule >/dev/null 2>&1 && [ -x /usr/sbin/selinuxenabled ] && /usr/sbin/selinuxenabled 2>/dev/null; then
    semodule -r tapauth 2>/dev/null || true
fi

# Removal (or upgrade) of the optional emulation subpackage adds/removes the
# bridge marker; bounce a running daemon so the tri-state default is
# re-evaluated at startup. Guarded and non-fatal.
%postun fprintd-emulation
if command -v systemctl >/dev/null 2>&1; then
    systemctl try-restart tapauthd.service 2>/dev/null || true
fi

# PAM vendor-drift protection: when the package owning one of the PAM
# service files TapAuth patched is installed or upgraded (polkit -> polkit-1,
# sudo -> sudo, util-linux/coreutils -> su), its vendor stack changes.
# Depending on the distro release the vendor file is /usr/lib/pam.d/<svc>
# (with our /etc/pam.d override shadowing it forever) or /etc/pam.d/<svc>
# itself (replaced on upgrade, dropping our line). Re-seed the override from
# the new vendor file (when present) and re-apply the TapAuth line — but only
# when TapAuth has patched that file before (the .tapauth-bak marker created
# by the post-install scriptlet), and only when the line is missing
# (idempotent). For `su` the same insertion rule as the post-install
# scriptlet applies (after pam_rootok/pam_wheel, before the first auth
# include). The snapshot is refreshed from the current unpatched file, which
# also keeps the explicit rollback path current. Idempotent; a no-op when
# TapAuth never touched the file.
%triggerin -- polkit sudo util-linux coreutils
pam_line="auth        sufficient    pam_tapauth.so"
for pam_svc in sudo su polkit-1; do
    pam_file="/etc/pam.d/${pam_svc}"
    if [ ! -f "$pam_file" ] || [ -L "$pam_file" ]; then
        continue
    fi
    if [ ! -f "${pam_file}.tapauth-bak" ]; then
        continue
    fi
    if [ -f "/usr/lib/pam.d/${pam_svc}" ]; then
        cp -p "/usr/lib/pam.d/${pam_svc}" "${pam_file}.tapauth-bak" 2>/dev/null || true
        cp -p "/usr/lib/pam.d/${pam_svc}" "$pam_file" 2>/dev/null || true
    fi
    if grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
        continue
    fi
    # Refresh the snapshot from the current (unpatched) stack so a later
    # explicit rollback / removal keeps a current copy, then insert the line.
    cp -p "$pam_file" "${pam_file}.tapauth-bak" 2>/dev/null || true
    if [ "$pam_svc" = "su" ]; then
        # PAM_USER for su is the TARGET user: insert after the
        # pam_rootok/pam_wheel block and before the first auth include
        # (system-auth / common-auth / @include), never at the top.
        pam_anchor=$(awk '
            /^[[:space:]]*#/ { next }
            /(common-auth|system-auth)/ || ($1 == "auth" && /(include|substack)/) { print NR; exit }
        ' "$pam_file")
        if [ -n "$pam_anchor" ]; then
            sed -i "${pam_anchor}i $pam_line" "$pam_file" 2>/dev/null || true
        elif head -n1 "$pam_file" | grep -q '^#%PAM-1.0'; then
            sed -i "1a $pam_line" "$pam_file" 2>/dev/null || true
        else
            sed -i "1i $pam_line" "$pam_file" 2>/dev/null || true
        fi
    elif head -n1 "$pam_file" | grep -q '^#%PAM-1.0'; then
        sed -i "1a $pam_line" "$pam_file" 2>/dev/null || true
    else
        sed -i "1i $pam_line" "$pam_file" 2>/dev/null || true
    fi
done

%files
%license LICENSE
%dir %attr(0755, tapauthd, tapauthd) %{_sysconfdir}/tapauth
%config(noreplace) %attr(0644, tapauthd, tapauthd) %{_sysconfdir}/tapauth/config.toml
%dir %attr(0700, tapauthd, tapauthd) %{_sharedstatedir}/tapauth
# /run/tapauthd and /var/log/tapauth are created at runtime by the systemd
# units (RuntimeDirectory= / LogsDirectory=), not packaged.
%{_bindir}/tapauthd
%{_bindir}/tapauth-config
%{_libdir}/security/pam_tapauth.so
%{_unitdir}/tapauthd.service
%{_unitdir}/tapauthd.socket
%{_presetdir}/90-tapauthd.preset
%dir %{_unitdir}/polkit-agent-helper@.service.d
%{_unitdir}/polkit-agent-helper@.service.d/tapauth.conf
%{_sysusersdir}/tapauth.conf
%{_tmpfilesdir}/tapauth.conf
%doc %{_datadir}/doc/tapauth/config.toml.example
%{_datadir}/applications/tapauth-config.desktop
%{_datadir}/icons/hicolor/scalable/apps/tapauth-config.svg
%{_datadir}/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy
%{_datadir}/polkit-1/rules.d/50-tapauthd.rules
%{_datadir}/selinux/packages/tapauth.cil
%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

%files fprintd-emulation
# The base tapauth package already ships the shared %license LICENSE;
# listing it here too would make the two subpackages co-own the same path.
%{_libdir}/security/pam_fprintd.so
# Marker that flips the daemon's tri-state enable_fprintd_bridge default to
# "on". Owned by this subpackage only; the base package ships no
# %{_datadir}/tapauth directory.
%dir %{_datadir}/tapauth
%{_datadir}/tapauth/fprintd-emulation.enabled

%changelog
* Wed Sep 02 2026 Luca Auer <lolle2000.la+tapauth@gmail.com> - 0.1.0-1
- Release 0.1.0
