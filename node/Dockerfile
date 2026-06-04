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

FROM ${BPFTOOL_IMAGE} AS bpftool

FROM ${BIRD_IMAGE} AS bird

# nft-rpms is supplied as a named build context
# (--build-context nft-rpms=docker-image://<NFT_RPMS_IMAGE>) by node/Makefile.
# Using a build context rather than FROM ${NFT_RPMS_IMAGE} avoids buildkit's
# `--pull=always` trying to fetch our locally-built/loaded producer image
# from a registry. The image is built by hack/rpms/nftables/ and carries the
# patched nftables + libnftnl RPMs (referenced via COPY --from=nft-rpms
# below). The tag is content-addressed; see hack/rpms/nftables/Makefile.

# Use this build stage to install iptables-legacy and build runit binaries.
# We need to build runit because there aren't any rpms for it in AlmaLinux or ubi repositories.
FROM almalinux:9 AS almalinux

ARG RUNIT_VER

RUN dnf upgrade -y && dnf install -y epel-release

RUN dnf --enablerepo=crb install -y \
    iptables-legacy \
    # Needed for building runit
    gcc \
    glibc-static \
    patch

RUN dnf clean all

# Copy the patch that adjusts svlogd log file permissions from 0744 to 0644.
# This file is used in the next step to apply the patch during the build process.
COPY patches/svlogd_use_0644_permission_instead_of_0744.patch /svlogd_use_0644_permission_instead_of_0744.patch

# runit is not available in ubi or AlmaLinux repos so build it.
# get it from the debian repos as the official website doesn't support https
RUN curl -sSfL --retry 5 -o /tmp/runit.tar.gz https://ftp.debian.org/debian/pool/main/r/runit/runit_${RUNIT_VER}.orig.tar.gz && \
    tar xz -C /root -f /tmp/runit.tar.gz && rm -f /tmp/runit.tar.gz && \
    cd /root/admin/runit-${RUNIT_VER} && \
    patch -p1 < /svlogd_use_0644_permission_instead_of_0744.patch && \
    package/compile

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
    # nftables is installed below from our patched RPMs (calico/nftables-rpms).
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
    iproute-tc iptables-nft \
    # Runtime deps of our patched nftables RPM (libnftnl is pulled in
    # transitively by iptables-nft).
    gmp jansson

# Install our patched libnftnl and nftables RPMs. Their Provides/Obsoletes
# clauses cleanly upgrade the BaseOS libnftnl that iptables-nft pulled in
# above and add nftables, leaving the runtime image's rpm db as the owner of
# /usr/sbin/nft, /usr/lib64/libnftables.so.*, and /usr/lib64/libnftnl.so.*.
# `rpm -Uvh` is used here because UBI's microdnf does not accept local rpm
# files as install arguments.
COPY --from=nft-rpms /rpms/ /tmp/rpms/
RUN rpm -Uvh /tmp/rpms/libnftnl-*.rpm /tmp/rpms/nftables-*.rpm && \
    rm -rf /tmp/rpms

RUN microdnf clean all

# Copy in runit binaries
COPY --from=almalinux /root/admin/runit-${RUNIT_VER}/command/* /usr/local/bin/

# Copy in xtables-legacy binary and libs
COPY --from=almalinux /usr/sbin/xtables-legacy-multi /usr/sbin/xtables-legacy-multi
COPY --from=almalinux /lib64/libip4tc.so.2 /lib64/libip4tc.so.2
COPY --from=almalinux /lib64/libip6tc.so.2 /lib64/libip6tc.so.2

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
