# Producer image for the patched nftables + libnftnl RPMs that calico/node and
# the istio CNI install image consume. Output is /rpms/*.rpm; consumers
# COPY --from this image into their runtime stage and dnf install.
#
# Versions and tarball checksums come in as build args from
# hack/rpms/nftables/Makefile (which sources them from metadata.mk). Bumping
# either version requires updating both the Makefile pin and the matching
# Version: in the spec file; rpmbuild fails loudly if they drift.

FROM almalinux:9

ARG LIBNFTNL_VER
ARG LIBNFTNL_SHA256
ARG NFTABLES_VER
ARG NFTABLES_SHA256

RUN dnf upgrade -y && dnf install -y epel-release

RUN dnf --enablerepo=crb install -y \
    autoconf \
    automake \
    bison \
    flex \
    gcc \
    gmp-devel \
    jansson-devel \
    libmnl-devel \
    libtool \
    make \
    pkgconfig \
    rpm-build \
    xz

COPY libnftnl.spec /root/rpmbuild/SPECS/libnftnl.spec
COPY nftables.spec /root/rpmbuild/SPECS/nftables.spec
COPY patches/ /root/rpmbuild/SOURCES/

RUN curl -sSfL --retry 5 -o /root/rpmbuild/SOURCES/libnftnl-${LIBNFTNL_VER}.tar.xz \
        https://netfilter.org/projects/libnftnl/files/libnftnl-${LIBNFTNL_VER}.tar.xz && \
    echo "${LIBNFTNL_SHA256}  /root/rpmbuild/SOURCES/libnftnl-${LIBNFTNL_VER}.tar.xz" | sha256sum -c - && \
    curl -sSfL --retry 5 -o /root/rpmbuild/SOURCES/nftables-${NFTABLES_VER}.tar.xz \
        https://netfilter.org/projects/nftables/files/nftables-${NFTABLES_VER}.tar.xz && \
    echo "${NFTABLES_SHA256}  /root/rpmbuild/SOURCES/nftables-${NFTABLES_VER}.tar.xz" | sha256sum -c -

# Build libnftnl first and install the runtime + devel RPMs into this stage so
# nftables can BuildRequires: libnftnl-devel against the patched build, then
# build nftables. Stage runtime RPMs we want to ship under /rpms/.
RUN rpmbuild -ba /root/rpmbuild/SPECS/libnftnl.spec && \
    rpm -Uvh --force \
        /root/rpmbuild/RPMS/$(rpm --eval '%{_arch}')/libnftnl-${LIBNFTNL_VER}-*.rpm \
        /root/rpmbuild/RPMS/$(rpm --eval '%{_arch}')/libnftnl-devel-${LIBNFTNL_VER}-*.rpm && \
    rpmbuild -ba /root/rpmbuild/SPECS/nftables.spec && \
    mkdir -p /rpms && \
    cp /root/rpmbuild/RPMS/$(rpm --eval '%{_arch}')/libnftnl-${LIBNFTNL_VER}-*.rpm /rpms/ && \
    cp /root/rpmbuild/RPMS/$(rpm --eval '%{_arch}')/nftables-${NFTABLES_VER}-*.rpm /rpms/

# Stash the corresponding source (the pinned, checksum-verified upstream
# tarballs plus our patches) under /src. nftables and libnftnl are both GPL-2.0,
# so consuming images COPY --from=nft-rpms /src into their /included-source to
# ship the complete corresponding source alongside the binaries.
RUN mkdir -p /src && \
    cp /root/rpmbuild/SOURCES/libnftnl-${LIBNFTNL_VER}.tar.xz \
       /root/rpmbuild/SOURCES/nftables-${NFTABLES_VER}.tar.xz \
       /root/rpmbuild/SOURCES/*.patch \
       /src/

RUN dnf clean all
