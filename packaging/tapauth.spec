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

Desktop lock screens and greeters (KDE Plasma, GNOME) integrate
automatically through the built-in virtual fprintd D-Bus service
(net.reactivated.Fprint): stock fingerprint stacks call pam_fprintd.so,
which resolves to tapauthd. The package deliberately does NOT conflict
with the real fprintd package — the real daemon simply stays dormant
while tapauthd claims the bus name. No local fingerprint reader is
required.

To keep using a real local fingerprint reader instead, set
enable_fprintd_bridge = false in /etc/tapauth/config.toml.

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
# (%install runs in the source dir; CARGO_TARGET_DIR mirrors %build)
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauthd" %{buildroot}%{_bindir}/tapauthd
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauth-config" %{buildroot}%{_bindir}/tapauth-config
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauth-ipc-cli" %{buildroot}%{_bindir}/tapauth-ipc-cli
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/libclient_pam.so" %{buildroot}%{_libdir}/security/pam_tapauth.so

# Default Configuration
# The virtual fprintd bridge is enabled by default in the daemon; do not
# write enable_fprintd_bridge here. Users who want a real local fingerprint
# reader opt out via this key in config.toml.
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
install -m 0644 packaging/pam-config.example %{buildroot}%{_datadir}/doc/tapauth/pam-config.example
install -m 0644 client-config-gui/tapauth-config.desktop %{buildroot}%{_datadir}/applications/tapauth-config.desktop
install -m 0644 client-config-gui/assets/tapauth-config.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/tapauth-config.svg
install -m 0644 tapauthd/dev.rourunisen.tapauth.config.admin.policy %{buildroot}%{_datadir}/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy
install -m 0644 packaging/50-tapauthd.rules %{buildroot}%{_datadir}/polkit-1/rules.d/50-tapauthd.rules

# SELinux Policy Module
mkdir -p %{buildroot}%{_datadir}/selinux/packages
install -m 0644 packaging/selinux/tapauth.cil %{buildroot}%{_datadir}/selinux/packages/tapauth.cil

# Virtual fprintd D-Bus bridge files (the bridge is enabled by default, so
# lock screens and greeters work out of the box). The activation file name
# differs from fprintd's own, so the real fprintd package can stay
# installed side by side (its daemon stays dormant while tapauthd owns the
# net.reactivated.Fprint bus name).
mkdir -p %{buildroot}%{_datadir}/dbus-1/system-services
mkdir -p %{buildroot}%{_datadir}/dbus-1/system.d
install -m 0644 packaging/net.reactivated.Fprint.service %{buildroot}%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
install -m 0644 packaging/net.reactivated.Fprint.tapauth.conf %{buildroot}%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

%pre
%sysusers_create_compat %{SOURCE1}
getent group tapauthd >/dev/null 2>&1 || groupadd -r tapauthd
getent group tapauthd-clients >/dev/null 2>&1 || groupadd -r tapauthd-clients
if ! getent passwd tapauthd >/dev/null 2>&1; then
    useradd -r -g tapauthd -G tapauthd-clients -d /var/lib/tapauth -s /sbin/nologin \
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
# fingerprint-auth) — stay stock: they call pam_fprintd.so, which resolves
# to tapauthd's virtual fprintd D-Bus service (bridge enabled by default).
# Vendor PAM files live in /usr/lib/pam.d on Fedora; /etc/pam.d overrides
# them. When no /etc override exists yet, seed one from the vendor file so
# the inserted line does not replace the vendor stack.
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
    sed -i "1i $pam_line" "$pam_file" 2>/dev/null || true
done

%systemd_post tapauthd.socket
if [ $1 -eq 1 ]; then
    # Start the socket immediately on initial install so auth requests don't hit a dead socket
    systemctl start tapauthd.socket 2>/dev/null || true
fi
if command -v systemctl &>/dev/null && systemctl is-active --quiet dbus 2>/dev/null; then
    systemctl reload dbus 2>/dev/null || true
fi
systemctl try-restart tapauthd.service 2>/dev/null || true

echo "TapAuth: pam_tapauth.so was wired into sudo, su and polkit-1"
echo "         (originals kept as <file>.tapauth-bak). Fingerprint stacks"
echo "         stay stock: lock screens and greeters integrate through the"
echo "         built-in virtual fprintd service (no real reader required)."
echo "TapAuth: To use the configuration GUI, add your user to the"
echo "         tapauthd-clients group:"
echo "         sudo usermod -aG tapauthd-clients \$USER"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    echo "TapAuth: SELinux is Enforcing. If GDM/KDM lock screen authentication fails due to AVC denial,"
    echo "         allow GDM to connect to the daemon socket via:"
    echo "         sudo ausearch -m avc -ts recent | audit2allow -M tapauth_gdm && sudo semodule -i tapauth_gdm.pp"
fi
if command -v semodule >/dev/null 2>&1 && [ -x /usr/sbin/selinuxenabled ] && /usr/sbin/selinuxenabled 2>/dev/null; then
    semodule -i %{_datadir}/selinux/packages/tapauth.cil 2>/dev/null || true
fi
restorecon -R /run/tapauthd %{_sharedstatedir}/tapauth %{_sysconfdir}/tapauth 2>/dev/null || true

%preun
%systemd_preun tapauthd.service tapauthd.socket
if [ $1 -eq 0 ]; then
    # Restore the three PAM services in scope from their pristine backups.
    for pam_svc in sudo su polkit-1; do
        pam_file="/etc/pam.d/${pam_svc}"
        if [ ! -f "$pam_file" ] || [ -L "$pam_file" ]; then
            continue
        fi
        if ! grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
            # Stack no longer references TapAuth; drop a stale backup
            # without clobbering the file.
            rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
            continue
        fi
        if [ -s "${pam_file}.tapauth-bak" ]; then
            if cp -p "${pam_file}.tapauth-bak" "$pam_file" 2>/dev/null; then
                rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
            fi
        else
            sed -i '/pam_tapauth\.so/d' "$pam_file" 2>/dev/null || true
        fi
    done
    # Best-effort cleanup for upgrades from older versions, which patched
    # fingerprint stacks (kde-fingerprint, gdm-fingerprint,
    # gdm3-fingerprint, fingerprint-auth) directly. Restore the original
    # stack when a backup exists; otherwise drop the TapAuth lines (and
    # synthetic files).
    for pam_file in /etc/pam.d/kde-fingerprint /etc/pam.d/gdm-fingerprint /etc/pam.d/gdm3-fingerprint /etc/pam.d/fingerprint-auth; do
        if [ ! -f "$pam_file" ] || [ -L "$pam_file" ]; then
            continue
        fi
        if ! grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
            rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
            continue
        fi
        if grep -q "# Managed by TapAuth" "$pam_file" 2>/dev/null; then
            rm -f "$pam_file" "${pam_file}.tapauth-bak" 2>/dev/null || true
        elif [ -s "${pam_file}.tapauth-bak" ]; then
            if cp -p "${pam_file}.tapauth-bak" "$pam_file" 2>/dev/null; then
                rm -f "${pam_file}.tapauth-bak" 2>/dev/null || true
            fi
        else
            sed -i '/pam_tapauth\.so/d' "$pam_file" 2>/dev/null || true
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

%files
%license LICENSE
%dir %attr(0755, tapauthd, tapauthd) %{_sysconfdir}/tapauth
%config(noreplace) %attr(0644, tapauthd, tapauthd) %{_sysconfdir}/tapauth/config.toml
%dir %attr(0700, tapauthd, tapauthd) %{_sharedstatedir}/tapauth
# /run/tapauthd and /var/log/tapauth are created at runtime by the systemd
# units (RuntimeDirectory= / LogsDirectory=), not packaged.
%{_bindir}/tapauthd
%{_bindir}/tapauth-config
%{_bindir}/tapauth-ipc-cli
%{_libdir}/security/pam_tapauth.so
%{_unitdir}/tapauthd.service
%{_unitdir}/tapauthd.socket
%{_presetdir}/90-tapauthd.preset
%dir %{_unitdir}/polkit-agent-helper@.service.d
%{_unitdir}/polkit-agent-helper@.service.d/tapauth.conf
%{_sysusersdir}/tapauth.conf
%{_tmpfilesdir}/tapauth.conf
%doc %{_datadir}/doc/tapauth/pam-config.example
%{_datadir}/applications/tapauth-config.desktop
%{_datadir}/icons/hicolor/scalable/apps/tapauth-config.svg
%{_datadir}/polkit-1/actions/dev.rourunisen.tapauth.config.admin.policy
%{_datadir}/polkit-1/rules.d/50-tapauthd.rules
%{_datadir}/selinux/packages/tapauth.cil
%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

%changelog
* Wed Sep 02 2026 Luca Auer <lolle2000.la+tapauth@gmail.com> - 0.1.0-1
- Release 0.1.0
