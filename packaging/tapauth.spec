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
%if 0%{?fedora} || 0%{?rhel}
BuildRequires:  authselect
Requires:       authselect
%endif
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
Recommends:     firewalld
Suggests:       iptables

%description
A modern, privacy-preserving local-first authentication system using Rust
PAM modules, systemd system daemons, and low-level communication links.

%package fprintd
Summary:        Virtual fprintd D-Bus bridge for TapAuth lock screen integration
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       dbus
Conflicts:      fprintd
Provides:       fprintd = 1.94.5

%description fprintd
Provides a virtual net.reactivated.Fprint D-Bus service enabling TapAuth
authentication on desktop lock screens (GNOME, KDE Plasma) via fingerprint UI.

WARNING: Installing this package replaces and conflicts with hardware fprintd.
Do not install if you rely on a physical fingerprint reader.

%prep
%setup -q -n %{name}-%{version}

%build
export CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
export CARGO_PROFILE_RELEASE_STRIP=true
if command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER=sccache
    export SCCACHE_DIR="${SCCACHE_DIR:-/root/.cache/sccache}"
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
mkdir -p %{buildroot}%{_localstatedir}/log/tapauth
mkdir -p %{buildroot}/run/tapauthd
mkdir -p %{buildroot}%{_datadir}/doc/tapauth
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
mkdir -p %{buildroot}%{_datadir}/polkit-1/actions
mkdir -p %{buildroot}%{_datadir}/polkit-1/rules.d
mkdir -p %{buildroot}%{_sysconfdir}/tapauth

# Binaries & Shared Objects
install -m 0755 target/release/tapauthd %{buildroot}%{_bindir}/tapauthd
install -m 0755 target/release/tapauth-config %{buildroot}%{_bindir}/tapauth-config
install -m 0755 target/release/tapauth-ipc-cli %{buildroot}%{_bindir}/tapauth-ipc-cli
install -m 0755 target/release/libclient_pam.so %{buildroot}%{_libdir}/security/pam_tapauth.so

# Default Configuration
cat << 'EOF' > %{buildroot}%{_sysconfdir}/tapauth/config.toml
# TapAuth System Configuration
enable_fprintd_bridge = false
EOF
chmod 0644 %{buildroot}%{_sysconfdir}/tapauth/config.toml

%if 0%{?fedora} || 0%{?rhel}
# Authselect Vendor Profile Generation
mkdir -p %{buildroot}%{_datadir}/authselect/vendor/tapauth
for f in %{_datadir}/authselect/default/local/*; do
    [ -e "$f" ] || continue
    filename=$(basename "$f")
    case "$filename" in
        system-auth|password-auth|fingerprint-auth|README) continue ;;
    esac
    ln -sf "%{_datadir}/authselect/default/local/$filename" %{buildroot}%{_datadir}/authselect/vendor/tapauth/$filename
done
install -m 0644 %{_datadir}/authselect/default/local/system-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
install -m 0644 %{_datadir}/authselect/default/local/password-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth
install -m 0644 %{_datadir}/authselect/default/local/fingerprint-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/fingerprint-auth
if grep -q '^[[:space:]]*auth.*pam_localuser.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth; then
    sed -i '/^[[:space:]]*auth.*pam_localuser.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
else
    sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
fi
sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth
sed -i 's/pam_fprintd\.so/pam_tapauth.so/g' %{buildroot}%{_datadir}/authselect/vendor/tapauth/fingerprint-auth
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/fingerprint-auth || exit 1
printf "TapAuth Local Authentication\n\nThis profile extends the default local profile with smartphone-based TapAuth authentication.\n" > %{buildroot}%{_datadir}/authselect/vendor/tapauth/README

mkdir -p %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd
for f in %{_datadir}/authselect/default/sssd/*; do
    [ -e "$f" ] || continue
    filename=$(basename "$f")
    case "$filename" in
        system-auth|password-auth|fingerprint-auth|README) continue ;;
    esac
    ln -sf "%{_datadir}/authselect/default/sssd/$filename" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/$filename
done
install -m 0644 %{_datadir}/authselect/default/sssd/system-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth
install -m 0644 %{_datadir}/authselect/default/sssd/password-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/password-auth
install -m 0644 %{_datadir}/authselect/default/sssd/fingerprint-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/fingerprint-auth
if grep -q '^[[:space:]]*auth.*pam_localuser.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth; then
    sed -i '/^[[:space:]]*auth.*pam_localuser.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth
else
    sed -i '/^[[:space:]]*auth.*pam_sss.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth
fi
sed -i '/^[[:space:]]*auth.*pam_sss.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/password-auth
sed -i 's/pam_fprintd\.so/pam_tapauth.so/g' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/fingerprint-auth
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/password-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/fingerprint-auth || exit 1
printf "TapAuth SSSD Authentication\n\nThis profile extends the default sssd profile with smartphone-based TapAuth authentication.\n" > %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/README
%endif

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

# Virtual fprintd D-Bus Bridge files (subpackage)
mkdir -p %{buildroot}%{_datadir}/dbus-1/system-services
mkdir -p %{buildroot}%{_datadir}/dbus-1/system.d
install -m 0644 packaging/net.reactivated.Fprint.service %{buildroot}%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
install -m 0644 packaging/net.reactivated.Fprint.tapauth.conf %{buildroot}%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

%pre
%{?sysusers_create_compat:%sysusers_create_compat %{SOURCE1}}
getent group tapauthd >/dev/null 2>&1 || groupadd -r tapauthd 2>/dev/null || :
getent group tapauthd-clients >/dev/null 2>&1 || groupadd -r tapauthd-clients 2>/dev/null || :
if ! getent passwd tapauthd >/dev/null 2>&1; then
    useradd -r -g tapauthd -G tapauthd-clients -d /var/lib/tapauth -s /sbin/nologin \
        -c "TapAuth Daemon" tapauthd 2>/dev/null || :
else
    usermod -aG tapauthd-clients tapauthd 2>/dev/null || :
fi

%post
%tmpfiles_create %{_tmpfilesdir}/tapauth.conf
chown -R tapauthd:tapauthd %{_sysconfdir}/tapauth 2>/dev/null || true
chmod 0755 %{_sysconfdir}/tapauth 2>/dev/null || true
chmod 0644 %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
# If authselect is active with a TapAuth profile, refresh authselect files on upgrade
if command -v authselect &>/dev/null; then
    current_profile=$(LC_ALL=C authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs)
    if [ "$current_profile" = "tapauth" ] || [ "$current_profile" = "tapauth-sssd" ]; then
        authselect apply-changes || true
    fi
fi
%systemd_post tapauthd.socket
if [ $1 -eq 1 ]; then
    # Start the socket immediately on initial install so auth requests don't hit a dead socket
    systemctl start tapauthd.socket 2>/dev/null || true
fi

echo "TapAuth: To use the configuration GUI or enable lock-screen unlock,"
echo "         add your user to the tapauthd-clients group:"
echo "         sudo usermod -aG tapauthd-clients \$USER"
echo "TapAuth: To enable system-wide authentication with authselect:"
echo "         sudo authselect select tapauth with-silent-lastlog with-mkhomedir --backup=pre-tapauth --force"
echo "TapAuth: On SELinux enforcing systems, if greeter access to the socket is denied,"
echo "         inspect audit logs: ausearch -m avc -ts recent | audit2allow -M tapauth_selinux"

%preun
%systemd_preun tapauthd.service tapauthd.socket
%if 0%{?fedora} || 0%{?rhel}
if [ $1 -eq 0 ] && command -v authselect &>/dev/null; then
    current_profile=$(LC_ALL=C authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs)
    if [ "$current_profile" = "tapauth" ] || [ "$current_profile" = "tapauth-sssd" ]; then
        target_profile="local"
        [ "$current_profile" = "tapauth-sssd" ] && target_profile="sssd"
        features=$(LC_ALL=C authselect current 2>/dev/null | grep '^- ' | cut -c3- | tr '\n' ' ')
        if ! authselect select "$target_profile" $features --backup=tapauth-uninstall --force 2>/dev/null; then
            echo "WARNING: Failed to automatically revert authselect profile to $target_profile." >&2
            echo "         Please run 'sudo authselect select $target_profile' manually to avoid PAM issues." >&2
        fi
    fi
fi
%endif

%postun
%systemd_postun_with_restart tapauthd.service tapauthd.socket

%post fprintd
if [ -f %{_sysconfdir}/tapauth/config.toml ]; then
    if grep -Eq "^[[:space:]]*#?[[:space:]]*enable_fprintd_bridge" %{_sysconfdir}/tapauth/config.toml; then
        sed -i -E 's/^[[:space:]]*#?[[:space:]]*enable_fprintd_bridge[[:space:]]*=.*/enable_fprintd_bridge = true/' %{_sysconfdir}/tapauth/config.toml
    else
        echo "enable_fprintd_bridge = true" >> %{_sysconfdir}/tapauth/config.toml
    fi
    chown tapauthd:tapauthd %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
    chmod 0644 %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
fi

# Wire up PAM stacks for desktop lock screen integration (non-authselect files)
pam_decisive="auth    [success=done default=bad]    pam_tapauth.so"
for pam_file in /etc/pam.d/gdm-fingerprint /etc/pam.d/kde-fingerprint; do
    [ -f "$pam_file" ] || continue
    [ -L "$pam_file" ] && continue
    if grep -q "pam_fprintd\.so" "$pam_file" 2>/dev/null && ! grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
        [ -f "${pam_file}.tapauth-bak" ] || cp -p "$pam_file" "${pam_file}.tapauth-bak" 2>/dev/null || true
        sed -i "s|.*pam_fprintd\.so.*|$pam_decisive|" "$pam_file" 2>/dev/null || true
    fi
done

# If authselect is active with a TapAuth profile, refresh authselect files
if command -v authselect &>/dev/null; then
    current_profile=$(LC_ALL=C authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs)
    if [ "$current_profile" = "tapauth" ] || [ "$current_profile" = "tapauth-sssd" ]; then
        authselect apply-changes || true
    fi
fi

# Create gdm-fingerprint if GDM exists but service file does not
if [ ! -f /etc/pam.d/gdm-fingerprint ] && { [ -f /etc/pam.d/gdm-password ] || [ -d /etc/gdm ]; }; then
    cat << 'EOF' > /etc/pam.d/gdm-fingerprint
#%PAM-1.0
# Managed by TapAuth
auth    [success=done default=bad]    pam_tapauth.so
auth    include                       system-auth
account include                       system-auth
session include                       system-auth
EOF
    chmod 0644 /etc/pam.d/gdm-fingerprint
fi

# Create kde-fingerprint if KDE lock screen exists but service file does not
if [ ! -f /etc/pam.d/kde-fingerprint ] && { [ -f /etc/pam.d/kscreenlocker ] || [ -f /etc/pam.d/kde ] || [ -d /usr/share/plasma ]; }; then
    cat << 'EOF' > /etc/pam.d/kde-fingerprint
#%PAM-1.0
# Managed by TapAuth
auth    [success=done default=bad]    pam_tapauth.so
auth    include                       system-auth
account include                       system-auth
session include                       system-auth
EOF
    chmod 0644 /etc/pam.d/kde-fingerprint
fi

# Enable fingerprint authentication in GDM dconf settings
if [ -d /etc/dconf/db/gdm.d ]; then
    mkdir -p /etc/dconf/profile
    if [ ! -f /etc/dconf/profile/gdm ]; then
        cat << 'EOF' > /etc/dconf/profile/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF
    fi
    cat << 'EOF' > /etc/dconf/db/gdm.d/10-tapauth-fingerprint
[org/gnome/login-screen]
enable-fingerprint-authentication=true
EOF
    if command -v dconf &>/dev/null; then
        dconf update 2>/dev/null || true
    fi
fi

if command -v systemctl &>/dev/null && systemctl is-active --quiet dbus 2>/dev/null; then
    systemctl reload dbus 2>/dev/null || true
elif command -v dbus-send &>/dev/null; then
    dbus-send --system --type=method_call --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>/dev/null || true
fi
systemctl try-restart tapauthd.service 2>/dev/null || true

%preun fprintd
if [ $1 -eq 0 ]; then
    # Restore PAM stacks (non-authselect files)
    for pam_file in /etc/pam.d/gdm-fingerprint /etc/pam.d/kde-fingerprint; do
        [ -L "$pam_file" ] && continue
        [ -f "$pam_file" ] || continue
        if ! grep -q "pam_tapauth\.so" "$pam_file" 2>/dev/null; then
            # Active PAM stack was modified to remove TapAuth; drop stale backup without clobbering
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
    if [ -f /etc/dconf/db/gdm.d/10-tapauth-fingerprint ]; then
        rm -f /etc/dconf/db/gdm.d/10-tapauth-fingerprint
        if command -v dconf &>/dev/null; then
            dconf update 2>/dev/null || true
        fi
    fi
fi

%postun fprintd
if [ $1 -eq 0 ]; then
    if [ -f %{_sysconfdir}/tapauth/config.toml ]; then
        sed -i -E 's/^[[:space:]]*#?[[:space:]]*enable_fprintd_bridge[[:space:]]*=.*/enable_fprintd_bridge = false/' %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
        chown tapauthd:tapauthd %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
        chmod 0644 %{_sysconfdir}/tapauth/config.toml 2>/dev/null || true
    fi
    if command -v systemctl &>/dev/null && systemctl is-active --quiet dbus 2>/dev/null; then
        systemctl reload dbus 2>/dev/null || true
    fi
    systemctl try-restart tapauthd.service 2>/dev/null || true
fi

%files
%license LICENSE
%dir %attr(0755, tapauthd, tapauthd) %{_sysconfdir}/tapauth
%config(noreplace) %attr(0644, tapauthd, tapauthd) %{_sysconfdir}/tapauth/config.toml
%dir %attr(0700, tapauthd, tapauthd) %{_sharedstatedir}/tapauth
%dir %attr(0755, tapauthd, tapauthd) %{_localstatedir}/log/tapauth
%ghost %dir %attr(0750, tapauthd, tapauthd-clients) /run/tapauthd
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
%if 0%{?fedora} || 0%{?rhel}
%{_datadir}/authselect/vendor/tapauth
%{_datadir}/authselect/vendor/tapauth-sssd
%endif

%files fprintd
%license LICENSE
%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.tapauth.conf

%changelog
* Wed Sep 02 2026 Luca Auer <lolle2000.la+tapauth@gmail.com> - 0.1.0-1
- Release 0.1.0