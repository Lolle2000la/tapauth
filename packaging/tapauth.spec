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
# Base profile the TapAuth vendor profiles are derived from: RHEL 10 / Fedora 40+
# ship "local", RHEL 9 and older ship "minimal". Resolved at build time (the
# COPR/build host is the target distro) so %preun can roll back to the profile
# that actually exists instead of hardcoding "local" (which fails on RHEL 9).
%global authselect_local %(if [ -e %{_datadir}/authselect/default/local/system-auth ]; then echo local; else echo minimal; fi)
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
# Refuse to let the cargo_features define pull dev overrides into a production
# RPM. scripts/ci/build-fedora-packages.sh sets allow_test_features=1 only for
# the explicitly test-only E2E packages, which are never scanned or published.
if [ -n "%{?cargo_features}" ] && [ -z "%{?allow_test_features}" ]; then
    case "%{cargo_features}" in
        *dev-*|*fallback-socket*)
            echo "ERROR: refusing to build a production RPM with test features: %{cargo_features}" >&2
            exit 1
            ;;
    esac
fi

# Allow CI to point cargo at a persistent cache (scripts/ci/build-fedora-packages.sh
# passes these as rpm defines when the mounted cache dirs exist).
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
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauthd" %{buildroot}%{_bindir}/tapauthd
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/tapauth-config" %{buildroot}%{_bindir}/tapauth-config
install -m 0755 "%{?_cargo_target_dir}%{!?_cargo_target_dir:target}/release/libclient_pam.so" %{buildroot}%{_libdir}/security/pam_tapauth.so

%if 0%{?fedora} || 0%{?rhel}
# Authselect Vendor Profile Generation
#
# The base profile ("local" or "minimal") is resolved at build time into
# %{authselect_local} so both the generated vendor profile and the %preun
# rollback target agree on every supported release.
AUTHSELECT_LOCAL="%{?authselect_local}"

mkdir -p %{buildroot}%{_datadir}/authselect/vendor/tapauth
for f in %{_datadir}/authselect/default/$AUTHSELECT_LOCAL/*; do
    [ -e "$f" ] || continue
    filename=$(basename "$f")
    case "$filename" in
        system-auth|password-auth|README) continue ;;
    esac
    ln -sf "../../default/$AUTHSELECT_LOCAL/$filename" %{buildroot}%{_datadir}/authselect/vendor/tapauth/$filename
done
install -m 0644 %{_datadir}/authselect/default/$AUTHSELECT_LOCAL/system-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
install -m 0644 %{_datadir}/authselect/default/$AUTHSELECT_LOCAL/password-auth %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth
if grep -q '^[[:space:]]*auth.*pam_localuser.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth; then
    sed -i '/^[[:space:]]*auth.*pam_localuser.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
else
    sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth
fi
sed -i '/^[[:space:]]*auth.*pam_unix.so/i auth        sufficient    pam_tapauth.so' %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/system-auth || exit 1
grep -q "pam_tapauth.so" %{buildroot}%{_datadir}/authselect/vendor/tapauth/password-auth || exit 1
printf "TapAuth Local Authentication\n\nThis profile extends the default %s profile with smartphone-based TapAuth authentication.\n" "$AUTHSELECT_LOCAL" > %{buildroot}%{_datadir}/authselect/vendor/tapauth/README

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
    current_profile=$(LC_ALL=C authselect current 2>/dev/null | grep 'Profile ID:' | cut -d: -f2 | xargs)
    # authselect reports the bare profile ID on some versions (e.g. "tapauth")
    # and a vendor/-prefixed ID on others, so accept both spellings.
    case "$current_profile" in
        vendor/tapauth|custom/tapauth|tapauth)
            # Roll back to the base profile the vendor profile was built from
            # ("local" on Fedora 40+/RHEL 10, "minimal" on RHEL 9 and older).
            target_profile="%{?authselect_local}"
            ;;
        vendor/tapauth-sssd|custom/tapauth-sssd|tapauth-sssd)
            target_profile="sssd"
            ;;
        *)
            target_profile=""
            ;;
    esac
    if [ -n "$target_profile" ]; then
        features=$(LC_ALL=C authselect current 2>/dev/null | grep '^- ' | cut -c3- | tr '\n' ' ')
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