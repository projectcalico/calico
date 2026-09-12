# The EL 8 build container: it builds our RPMs, and it builds the calico-felix
# binary that both the RPMs and the .debs ship.
#
# Those are two jobs in one image on purpose.  calico/go-build links against a
# newer glibc than EL 8 has (2.34 versus 2.28), so a binary built there will not
# run on EL 8 - or on Ubuntu 20.04, whose glibc is 2.31.  Building it here, in
# the oldest distribution we package for, gives one binary that runs on all of
# them.  The same trick, for the same reason, is used for calico-node's RHEL 8
# RPM in calico-private (third_party/host-native/Dockerfile.rhel8).

ARG ARCH="amd64"

FROM --platform=linux/${ARCH} almalinux:8

ARG ARCH
ARG GO_VERSION
ARG UID
ARG GID

LABEL org.opencontainers.image.authors="Daniel Fox <dan.fox@tigera.io>"
ENV STREAM=el8

# powertools is EL 8's CodeReady Builder: libpcap-devel and libidn-devel live
# there.  The first group is what rpmbuild needs for our specs, the second what
# the felix cgo build needs.  Nothing we build here uses pbr, so EPEL - which the
# CentOS 7 image needed for python2-pbr - is not enabled.
RUN dnf upgrade -y && dnf --enablerepo=powertools install -y \
        dbus-devel \
        gcc \
        gcc-c++ \
        git \
        libidn-devel \
        make \
        python3-devel \
        python3-setuptools \
        rpm-build \
        elfutils-libelf-devel \
        libpcap-devel \
        zlib-devel \
    && dnf clean all

# Go from upstream, pinned to the repo's GO_VERSION, because EL 8 has no Go new
# enough to build Calico.  GOPATH is world-writable so that the build can run as
# any uid.
RUN GOARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/ppc64le/ppc64le/')" && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" | tar -xz -C /usr/local && \
    mkdir -p /go && chmod 0777 /go

ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# rpmbuild requires the current user to exist inside the container, so the
# invoking uid/gid are baked in.
# use `--force` and `-o` since builds can run as root, where these would
# otherwise fail as duplicates.
RUN groupadd --force --gid=$GID user && useradd -o --home=/ --gid=$GID --uid=$UID user

WORKDIR /code
