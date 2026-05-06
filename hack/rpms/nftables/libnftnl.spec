# Calico build of libnftnl. The custom Release tag (.tigera) and the
# Obsoletes/Provides below let this RPM cleanly supersede the BaseOS
# libnftnl in the consuming image without leaving the BaseOS package
# half-installed.

Name:           libnftnl
Version:        1.2.8
Release:        1.tigera%{?dist}
Summary:        Library for low-level interaction with nftables Netlink's API
License:        LGPL-2.1-or-later
URL:            https://netfilter.org/projects/libnftnl/
Source0:        https://netfilter.org/projects/libnftnl/files/libnftnl-%{version}.tar.xz

BuildRequires:  gcc make autoconf automake libtool pkgconfig
BuildRequires:  libmnl-devel

Provides:       libnftnl = %{version}-%{release}
Obsoletes:      libnftnl < %{version}-%{release}

%description
libnftnl is a userspace library providing a low-level netlink programming
interface to the in-kernel nf_tables subsystem. This is the Calico build,
shipped alongside the patched nftables RPM so the consuming image has a
matching libnftnl with consistent rpm-db ownership.

%package devel
Summary:        Development headers for libnftnl
Requires:       libnftnl%{?_isa} = %{version}-%{release}
Provides:       libnftnl-devel = %{version}-%{release}
Obsoletes:      libnftnl-devel < %{version}-%{release}

%description devel
Headers and pkg-config files for building against the Calico libnftnl.

%prep
%autosetup -p1

%build
%configure --libdir=%{_libdir}
%make_build

%install
%make_install
rm -f %{buildroot}%{_libdir}/*.la

%files
%license COPYING
%{_libdir}/libnftnl.so.*

%files devel
%{_includedir}/libnftnl/
%{_libdir}/libnftnl.so
%{_libdir}/pkgconfig/libnftnl.pc

%changelog
* Sun May 03 2026 Tigera <maintainers@tigera.io> - 1.2.8-1.tigera
- Calico build of libnftnl 1.2.8.
