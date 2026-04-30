# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG BIRD_IMAGE=calico/bird:latest
ARG BPFTOOL_IMAGE
ARG UBI_IMAGE

ARG RUNIT_VER=2.1.2

# nftables 1.0.x in UBI 9 / AlmaLinux 9 BaseOS segfaults when listing or
# validating rulesets that contain "udata"-bearing sets created by newer nft
# (1.1.2+) in the same network namespace (see projectcalico/calico#11750).
#
# We build nftables 1.1.1 from source and apply upstream commit be737a1
# ("src: netlink: fix crash when ops doesn't support udata"). 1.1.1 is the
# last nft release whose set-creation udata is parseable by the older nft
# binaries that ship in BaseOS images and on host operating systems, so a
# patched 1.1.1 is the only build that is safe in both directions:
#
#   - reads of newer rulesets do not crash, thanks to the upstream patch;
#   - writes do not poison the kernel for older nft elsewhere on the host.
#
# Do not bump past 1.1.1 — see issue #11750 for context.
ARG LIBNFTNL_VER=1.2.6
ARG LIBNFTNL_SHA256=ceeaea2cd92147da19f13a35a7f1a4bc2767ff897e838e4b479cf54b59c777f4
ARG NFTABLES_VER=1.1.1
ARG NFTABLES_SHA256=6358830f3a64f31e39b0ad421d7dadcd240b72343ded48d8ef13b8faf204865a

FROM ${BPFTOOL_IMAGE} AS bpftool

FROM ${BIRD_IMAGE} AS bird

# Use this build stage to install iptables-legacy, build runit binaries, and
# build a patched nftables (with libnftnl) from source.
FROM almalinux:9 AS almalinux

ARG RUNIT_VER
ARG LIBNFTNL_VER
ARG LIBNFTNL_SHA256
ARG NFTABLES_VER
ARG NFTABLES_SHA256

RUN dnf upgrade -y && dnf install -y epel-release

RUN dnf --enablerepo=crb install -y \
    iptables-legacy \
    # Needed for building runit and nftables
    gcc \
    glibc-static \
    make \
    patch \
    # Build deps for nftables / libnftnl source builds
    autoconf \
    automake \
    bison \
    flex \
    gmp-devel \
    jansson-devel \
    libmnl-devel \
    libtool \
    pkgconfig \
    xz

# Copy the patch that adjusts svlogd log file permissions from 0744 to 0644.
# This file is used in the next step to apply the patch during the build process.
COPY patches/svlogd_use_0644_permission_instead_of_0744.patch /svlogd_use_0644_permission_instead_of_0744.patch

# Backport of upstream nftables commit be737a1 ("src: netlink: fix crash when
# ops doesn't support udata"), used in the nftables build below.
COPY patches/nftables-set_make_key-tolerate-unknown-typeof-udata.patch \
     /nftables-set_make_key-tolerate-unknown-typeof-udata.patch

# runit is not available in ubi or AlmaLinux repos so build it.
# get it from the debian repos as the official website doesn't support https
RUN curl -sSfL --retry 5 -o /tmp/runit.tar.gz https://ftp.debian.org/debian/pool/main/r/runit/runit_${RUNIT_VER}.orig.tar.gz && \
    tar xz -C /root -f /tmp/runit.tar.gz && rm -f /tmp/runit.tar.gz && \
    cd /root/admin/runit-${RUNIT_VER} && \
    patch -p1 < /svlogd_use_0644_permission_instead_of_0744.patch && \
    package/compile

# Build libnftnl from source so the nftables build below can link against it.
RUN curl -sSfL --retry 5 -o /tmp/libnftnl.tar.xz \
        https://netfilter.org/projects/libnftnl/files/libnftnl-${LIBNFTNL_VER}.tar.xz && \
    echo "${LIBNFTNL_SHA256}  /tmp/libnftnl.tar.xz" | sha256sum -c - && \
    tar xJ -C /root -f /tmp/libnftnl.tar.xz && rm -f /tmp/libnftnl.tar.xz && \
    cd /root/libnftnl-${LIBNFTNL_VER} && \
    ./configure --prefix=/usr --libdir=/usr/lib64 && \
    make -j"$(nproc)" && \
    make install

# Build patched nftables from source. Install into a clean DESTDIR so the
# runtime image only picks up the bits we actually want to overlay onto the
# BaseOS install (the BaseOS nftables package is still installed in the
# runtime stage so its transitive runtime deps stay satisfied).
RUN curl -sSfL --retry 5 -o /tmp/nftables.tar.xz \
        https://netfilter.org/projects/nftables/files/nftables-${NFTABLES_VER}.tar.xz && \
    echo "${NFTABLES_SHA256}  /tmp/nftables.tar.xz" | sha256sum -c - && \
    tar xJ -C /root -f /tmp/nftables.tar.xz && rm -f /tmp/nftables.tar.xz && \
    cd /root/nftables-${NFTABLES_VER} && \
    patch -p1 < /nftables-set_make_key-tolerate-unknown-typeof-udata.patch && \
    # --with-json: knftables (used by Felix) parses nft JSON output;
    # --without-cli: we never invoke the interactive shell (`nft -i`) and
    #                 dropping it removes the editline build dep.
    ./configure --prefix=/usr --libdir=/usr/lib64 --sbindir=/usr/sbin \
                --disable-man-doc --with-json --without-cli && \
    make -j"$(nproc)" && \
    make install DESTDIR=/nft-install && \
    # Strip headers, pkg-config, static archives, and libtool .la files; we
    # only want the runtime binary and shared libraries in the final image.
    rm -rf /nft-install/usr/include \
           /nft-install/usr/lib64/pkgconfig \
           /nft-install/usr/lib64/*.la \
           /nft-install/usr/lib64/*.a \
           /nft-install/usr/share && \
    # Stage libnftnl runtime libs alongside the nftables artifacts so a single
    # COPY in the runtime image overlays both.
    cp -a /usr/lib64/libnftnl.so* /nft-install/usr/lib64/

RUN dnf clean all

FROM ${UBI_IMAGE} AS ubi

ARG RUNIT_VER

# Update base packages to pick up security updates - must do this before adding the AlmaLinux repo,
# and install the necessary packages from ubi repos.
RUN microdnf upgrade -y
RUN microdnf install -y \
    # Don't install copious docs.
    --setopt=tsflags=nodocs \
    gzip \
    cryptsetup-libs \
    # Needed for iptables
    libpcap libmnl libnfnetlink libnetfilter_conntrack \
    ipset \
    iputils \
    nftables \
    # Need arp
    net-tools \
    # Need kmod to ensure ip6tables-save works correctly
    kmod \
    # Also needed (provides utilities for browsing procfs like ps)
    iproute \
    procps \
    # Needed for runit startup script
    which \
    # Needed for the cleanup script
    findutils

# Since the ubi repos do not contain all the packages we need (e.g. they're missing conntrack-tools),
# we're using AlmaLinux repos for missing packages.
COPY --from=almalinux  /etc/yum.repos.d/almalinux-appstream.repo /etc/yum.repos.d/almalinux-appstream.repo
COPY --from=almalinux  /etc/yum.repos.d/almalinux-baseos.repo /etc/yum.repos.d/almalinux-baseos.repo
COPY --from=almalinux  /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9 /etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9

RUN microdnf --enablerepo=appstream --enablerepo=baseos install -y \
    # From appstream - needed for conntrack
    libnetfilter_cthelper libnetfilter_cttimeout libnetfilter_queue \
    conntrack-tools \
    # From baseos
    iproute-tc iptables-nft

RUN microdnf clean all

# Copy in runit binaries
COPY --from=almalinux /root/admin/runit-${RUNIT_VER}/command/* /usr/local/bin/

# Copy in xtables-legacy binary and libs
COPY --from=almalinux /usr/sbin/xtables-legacy-multi /usr/sbin/xtables-legacy-multi
COPY --from=almalinux /lib64/libip4tc.so.2 /lib64/libip4tc.so.2
COPY --from=almalinux /lib64/libip6tc.so.2 /lib64/libip6tc.so.2

# Overlay our patched nftables (and matching libnftnl) on top of the BaseOS
# nftables package. The BaseOS package is left installed so its transitive
# runtime deps (jansson, gmp, libmnl, ...) stay satisfied; we only replace
# the nft binary and the libnftables / libnftnl shared libraries. See the
# almalinux build stage above for the rationale.
COPY --from=almalinux /nft-install/ /

# Set symbolic links for iptables-legacy binaries
RUN set -eux; \
    for link in \
        ip6tables-legacy \
        ip6tables-legacy-restore \
        ip6tables-legacy-save \
        iptables-legacy \
        iptables-legacy-restore \
        iptables-legacy-save; \
    do \
        ln -sf xtables-legacy-multi /usr/sbin/${link} || true; \
    done

# Copy our bird binaries in
COPY --from=bird /bird /bin/bird
COPY --from=bird /bird6 /bin/bird6
COPY --from=bird /birdcl /bin/birdcl
COPY --from=bird /birdcl6 /bin/birdcl6

# Copy in the filesystem - this contains licenses, etc...
COPY filesystem/etc/ /etc
COPY filesystem/included-source/ /included-source
COPY filesystem/sbin/ /usr/sbin/
COPY filesystem/usr/ /usr

COPY --from=bpftool /bpftool /bin/bpftool

ARG BIN_DIR
ARG TARGETARCH

# Copy in the combined calico binary (built with CGO for BPF support).
COPY ${BIN_DIR}/calico-${TARGETARCH} /usr/bin/calico

# Copy in the mountns binary
COPY ${BIN_DIR}/mountns-${TARGETARCH} /bin/mountns

# Clean out as many files as we can from the filesystem.  We no longer need dnf or the platform python install
# or any of its dependencies.
COPY clean-up-filesystem.sh /clean-up-filesystem.sh
RUN touch /in-the-container && /clean-up-filesystem.sh

# Add in top-level license file
COPY dist/LICENSE /licenses/LICENSE

# Copy everything into a fresh scratch image so that naive CVE scanners don't pick up binaries and libraries
# that have been removed in our later layers.
FROM scratch

ARG GIT_VERSION=unknown

# Tell sv where to find the services.
ENV SVDIR=/etc/service/enabled

# Required labels for certification
LABEL org.opencontainers.image.description="Calico node handles networking and policy for Calico"
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico node"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Calico node handles networking and policy for Calico"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico node"
LABEL release=1
LABEL summary="The primary networking and policy engine for Calico"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

COPY --from=ubi / /

CMD ["start_runit"]
