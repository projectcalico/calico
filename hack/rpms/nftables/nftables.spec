# Calico build of nftables 1.1.1 with a backport of upstream commit be737a1
# ("src: netlink: fix crash when ops doesn't support udata", first released in
# 1.1.4). 1.1.1 is the last release whose set-creation udata is parseable by
# the older nft binaries that ship in BaseOS images and on host operating
# systems, so a patched 1.1.1 is the only build that is safe in both
# directions: reads of newer rulesets do not crash, and writes do not poison
# the kernel for older nft elsewhere on the host. See projectcalico/calico#11750.
#
# Do not bump Version past 1.1.1.

Name:           nftables
Version:        1.1.1
Release:        1.tigera%{?dist}
Summary:        Netfilter Tables userspace utilities (Calico patched build)
License:        GPL-2.0-only
URL:            https://netfilter.org/projects/nftables/
Source0:        https://netfilter.org/projects/nftables/files/nftables-%{version}.tar.xz
Patch0:         nftables-set_make_key-tolerate-unknown-typeof-udata.patch

BuildRequires:  gcc make autoconf automake libtool pkgconfig
BuildRequires:  bison flex
BuildRequires:  libmnl-devel libnftnl-devel >= 1.2.8
BuildRequires:  jansson-devel gmp-devel

Requires:       libnftnl >= 1.2.8

# Supersede the BaseOS nftables and the (separately packaged) nftables-libs.
Provides:       nftables = %{version}-%{release}
Obsoletes:      nftables < %{version}-%{release}
Provides:       nftables-libs = %{version}-%{release}
Obsoletes:      nftables-libs < %{version}-%{release}

%description
nftables replaces the existing {ip,ip6,arp,eb}tables framework. This Calico
build of 1.1.1 includes a backport of upstream commit be737a1
(set_make_key: tolerate unknown typeof udata) for projectcalico/calico#11750.

%prep
%autosetup -p1

%build
# --with-json: knftables (used by Felix) parses nft JSON output.
# --without-cli: we never invoke the interactive shell (`nft -i`); dropping
#                it removes the editline build dep.
%configure --disable-man-doc --with-json --without-cli --libdir=%{_libdir}
%make_build

%install
%make_install
# Drop dev artifacts and runtime data we don't use; we only ship the binary
# and shared library. /etc/nftables/osf is OS-fingerprinting data for the
# `osf` match expression — Felix doesn't use it.
rm -rf %{buildroot}%{_includedir}
rm -rf %{buildroot}%{_libdir}/pkgconfig
rm -f  %{buildroot}%{_libdir}/*.la
rm -f  %{buildroot}%{_libdir}/*.a
rm -rf %{buildroot}%{_datadir}
rm -rf %{buildroot}%{_sysconfdir}/nftables

%files
%license COPYING
%{_sbindir}/nft
%{_libdir}/libnftables.so*

%changelog
* Sun May 03 2026 Tigera <maintainers@tigera.io> - 1.1.1-1.tigera
- Build patched nftables 1.1.1 with backport of upstream be737a1
  (src: netlink: fix crash when ops doesn't support udata) for
  projectcalico/calico#11750. Do not bump past 1.1.1.
