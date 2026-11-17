# Calico build of BIRD 1.6.8, the last release of the BIRD 1.6 line, with the
# patches in patches/. Each patch file says what it is for.
#
# calico_release counts changes to the patch set. Raise it whenever a patch is
# added, removed or changed. BIRD reports it in its version string, so a
# running daemon names the package it came from.

%global calico_release 1

# BIRD 1.6 predates link-time optimization and is not tested with it.
%global _lto_cflags %{nil}
%global debug_package %{nil}

Name:           bird
Version:        1.6.8
Release:        %{calico_release}.tigera%{?dist}
Summary:        BIRD Internet Routing Daemon (Calico patched build)
License:        GPL-2.0-or-later
URL:            https://bird.nic.cz/
Source0:        https://bird.nic.cz/download/bird-%{version}.tar.gz
Patch1:         0001-netlink-treat-route-gateways-as-onlink.patch
Patch2:         0002-netlink-ignore-addresses-on-down-interfaces.patch
Patch3:         0003-krt-add-krt_tunnel-attribute.patch
Patch4:         0004-ip-treat-240.0.0.0-4-as-host-addresses.patch
Patch5:         0005-iface-remove-deleted-interfaces.patch
Patch6:         0006-unix-restrict-control-socket-mode.patch
Patch7:         0007-unix-make-signal-flags-atomic.patch

BuildRequires:  autoconf bison flex gcc m4 make

%description
BIRD is a dynamic IP routing daemon. This Calico build of BIRD 1.6.8 carries
the Calico patches, and ships an IPv4 daemon (bird) and an IPv6 daemon (bird6)
with a lightweight control client for each (birdcl, birdcl6).

%prep
%autosetup -p1
sed -i 's/^#define BIRD_VERSION .*/#define BIRD_VERSION "%{version}-%{calico_release}.tigera"/' sysdep/config.h
grep -q '"%{version}-%{calico_release}.tigera"' sysdep/config.h
# The shipped configure script is too old to know --runstatedir.
autoreconf

%build
# BIRD 1.6 defines some globals in headers, which GCC 10 and later reject
# without -fcommon.
export CFLAGS="%{optflags} -fcommon"

# BIRD 1.6 builds either an IPv4 or an IPv6 daemon, so configure and build it
# twice, out of tree.
%global bird_configure ../configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --runstatedir=/var/run/calico --with-protocols="bfd bgp pipe static" --enable-client=no --enable-pthreads=yes

mkdir build4 build6
( cd build4 && %{bird_configure} --with-sysconfig=linux && make %{?_smp_mflags} bird birdcl )
( cd build6 && %{bird_configure} --with-sysconfig=linux-v6 --enable-ipv6=yes && make %{?_smp_mflags} bird birdcl )

%install
install -D -m 0755 build4/bird   %{buildroot}%{_bindir}/bird
install -D -m 0755 build4/birdcl %{buildroot}%{_bindir}/birdcl
install -D -m 0755 build6/bird   %{buildroot}%{_bindir}/bird6
install -D -m 0755 build6/birdcl %{buildroot}%{_bindir}/birdcl6

%files
# BIRD 1.6 has no separate license file. Its README carries the license notice.
%license README
%{_bindir}/bird
%{_bindir}/bird6
%{_bindir}/birdcl
%{_bindir}/birdcl6

%changelog
* Tue Nov 17 2026 Tigera <maintainers@tigera.io> - 1.6.8-1.tigera
- Build BIRD 1.6.8 with the patches that the projectcalico/bird fork carried.
