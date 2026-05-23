Name:           tapauth
Version:        %{?pkgversion}%{!?pkgversion:0.1.0}
Release:        1%{?dist}
Summary:        Local smartphone-based authentication framework

License:        Apache-2.0
URL:            https://github.com/lolle2000la/tapauth
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  protobuf-compiler
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(gtk4)
BuildRequires:  pam-devel
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

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

# Binaries & Shared Objects
install -m 0755 target/release/tapauthd %{buildroot}%{_bindir}/tapauthd
install -m 0755 target/release/tapauth-config %{buildroot}%{_bindir}/tapauth-config
install -m 0755 target/release/libclient_pam.so %{buildroot}%{_libdir}/security/pam_tapauth.so

# System Services
install -m 0644 systemd/tapauthd.service %{buildroot}%{_unitdir}/tapauthd.service
install -m 0644 systemd/tapauthd.socket %{buildroot}%{_unitdir}/tapauthd.socket

# Structural Declarations
install -m 0644 packaging/sysusers.conf %{buildroot}%{_sysusersdir}/tapauth.conf
install -m 0644 packaging/tmpfiles.conf %{buildroot}%{_tmpfilesdir}/tapauth.conf

%post
%systemd_post tapauthd.service tapauthd.socket

%preun
%systemd_preun tapauthd.service tapauthd.socket

%postun
%systemd_postun_with_restart tapauthd.service tapauthd.socket

%files
%license LICENSE
%{_bindir}/tapauthd
%{_bindir}/tapauth-config
%{_libdir}/security/pam_tapauth.so
%{_unitdir}/tapauthd.service
%{_unitdir}/tapauthd.socket
%{_sysusersdir}/tapauth.conf
%{_tmpfilesdir}/tapauth.conf