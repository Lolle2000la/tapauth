# Rust --release produces stripped binaries; disable automatic debuginfo
# subpackage generation to avoid empty debugsourcefiles.list errors on RHEL
%global debug_package %{nil}

Name:           tapauth
Version:        %{?pkgversion}%{!?pkgversion:0.1.0}
Release:        1%{?dist}
Summary:        Local smartphone-based authentication framework

License:        AGPL-3.0
URL:            https://github.com/lolle2000la/tapauth
Source0:        %{name}-%{version}.tar.gz

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
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires:       pam
Requires:       dbus-libs
Requires:       systemd-libs
Requires:       polkit
Recommends:     firewalld
Suggests:       iptables

%description
A modern, privacy-preserving local-first authentication system using Rust PAM modules,
systemd system daemons, and low-level communication links.

%prep
%setup -q -n %{name}-%{version}

%build
cargo build --workspace --release

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/security
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysusersdir}
mkdir -p %{buildroot}%{_tmpfilesdir}
mkdir -p %{buildroot}%{_datadir}/doc/tapauth
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
mkdir -p %{buildroot}%{_datadir}/polkit-1/actions
mkdir -p %{buildroot}%{_datadir}/polkit-1/rules.d
mkdir -p %{buildroot}%{_sysconfdir}/tapauth

# Binaries & Shared Objects
install -m 0755 target/release/tapauthd %{buildroot}%{_bindir}/tapauthd
install -m 0755 target/release/tapauth-config %{buildroot}%{_bindir}/tapauth-config
install -m 0755 target/release/libclient_pam.so %{buildroot}%{_libdir}/security/pam_tapauth.so

%if 0%{?fedora} || 0%{?rhel}
# Authselect Vendor Profile Generation
mkdir -p %{buildroot}%{_datadir}/authselect/vendor/tapauth
for f in %{_datadir}/authselect/default/local/*; do
    [ -e "$f" ] || continue
    filename=$(basename "$f")
    case "$filename" in
        system-auth|password-auth|README) continue ;;
    esac
    ln -sf "../../default/local/$filename" %{buildroot}%{_datadir}/authselect/vendor/tapauth/$filename
done
install -m 0644 %{_datadir}/authselect/default/local/system-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
install -m 0644 %{_datadir}/authselect/default/local/password-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth
if grep -q '^[[:space:]]*auth.*pam_localuser.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth; then
    sed -i '/^[[:space:]]*auth.*pam_localuser.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
else
    sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
fi
sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth || exit 1
printf "TapAuth Local Authentication\n\nThis profile extends the default local profile with smartphone-based TapAuth authentication.\n" > %{buildroot}%{_datadir}/authselect/vendor/tapauth/README

mkdir -p %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd
for f in %{_datadir}/authselect/default/sssd/*; do
    [ -e "$f" ] || continue
    filename=$(basename "$f")
    case "$filename" in
        system-auth|password-auth|README) continue ;;
    esac
    ln -sf "../../default/sssd/$filename" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/$filename
done
install -m 0644 %{_datadir}/authselect/default/sssd/system-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth
install -m 0644 %{_datadir}/authselect/default/sssd/password-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/password-auth
if grep -q '^[[:space:]]*auth.*pam_localuser.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth; then
    sed -i '/^[[:space:]]*auth.*pam_localuser.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth
else
    sed -i '/^[[:space:]]*auth.*pam_sss.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth
fi
sed -i '/^[[:space:]]*auth.*pam_sss.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/password-auth
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/system-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/password-auth || exit 1
printf "TapAuth SSSD Authentication\n\nThis profile extends the default sssd profile with smartphone-based TapAuth authentication.\n" > %{buildroot}%{_datadir}/authselect/vendor/tapauth-sssd/README
%endif

# System Services
install -m 0644 systemd/tapauthd.service %{buildroot}%{_unitdir}/tapauthd.service
install -m 0644 systemd/tapauthd.socket %{buildroot}%{_unitdir}/tapauthd.socket

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

%post
%sysusers_create_compat %{_sysusersdir}/tapauth.conf
%tmpfiles_create %{_tmpfilesdir}/tapauth.conf
%systemd_post tapauthd.service tapauthd.socket

%preun
%systemd_preun tapauthd.service tapauthd.socket
%if 0%{?fedora} || 0%{?rhel}
if [ $1 -eq 0 ] && command -v authselect &>/dev/null; then
    current_profile=$(authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs)
    if [ "$current_profile" = "vendor/tapauth" ] || [ "$current_profile" = "vendor/tapauth-sssd" ]; then
        target_profile="local"
        [ "$current_profile" = "vendor/tapauth-sssd" ] && target_profile="sssd"
        features=$(authselect current 2>/dev/null | grep '^- ' | cut -c3- | tr '\n' ' ')
        authselect select "$target_profile" $features --force || true
    fi
fi
%endif

%postun
%systemd_postun_with_restart tapauthd.service tapauthd.socket

%files
%license LICENSE
%dir %{_sysconfdir}/tapauth
%{_bindir}/tapauthd
%{_bindir}/tapauth-config
%{_libdir}/security/pam_tapauth.so
%{_unitdir}/tapauthd.service
%{_unitdir}/tapauthd.socket
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