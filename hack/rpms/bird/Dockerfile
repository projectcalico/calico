# The calico/bird image: the patched BIRD RPM, and a BGP router for tests.
#
#   /rpms/*.rpm  The RPM. calico/node COPYs it --from this image and installs it.
#   /src/        The corresponding source, for images that ship the binaries.
#   The RPM is also installed here, with a base config and an entrypoint that
#   starts bird and bird6. A test runs the image, drops its peer config into
#   /etc/bird/ or /etc/bird6/, and runs `birdcl configure`.
#
# The version and tarball checksum come in as build args from
# hack/rpms/bird/Makefile (which sources them from metadata.mk). Bumping the
# version requires updating both the metadata.mk pin and the matching Version:
# in the spec file; rpmbuild fails loudly if they drift.

FROM almalinux:9 AS build

ARG BIRD_VER
ARG BIRD_SHA256

RUN dnf upgrade -y && dnf install -y \
    autoconf \
    bison \
    flex \
    gcc \
    m4 \
    make \
    rpm-build

COPY bird.spec /root/rpmbuild/SPECS/bird.spec
COPY patches/ /root/rpmbuild/SOURCES/

RUN curl -sSfL --retry 5 -o /root/rpmbuild/SOURCES/bird-${BIRD_VER}.tar.gz \
        https://bird.nic.cz/download/bird-${BIRD_VER}.tar.gz && \
    echo "${BIRD_SHA256}  /root/rpmbuild/SOURCES/bird-${BIRD_VER}.tar.gz" | sha256sum -c -

RUN rpmbuild -ba /root/rpmbuild/SPECS/bird.spec && \
    mkdir -p /rpms && \
    cp /root/rpmbuild/RPMS/$(rpm --eval '%{_arch}')/bird-${BIRD_VER}-*.rpm /rpms/

# Stash the corresponding source under /src: the pinned, checksum-verified
# upstream tarball, our patches, and the spec file that drives the build (the
# spec file is part of the complete corresponding source). BIRD is
# GPL-2.0-or-later, so consuming images COPY --from this image's /src into
# their /included-source to ship the source alongside the binaries.
RUN mkdir -p /src && \
    cp /root/rpmbuild/SOURCES/bird-${BIRD_VER}.tar.gz \
       /root/rpmbuild/SOURCES/*.patch \
       /root/rpmbuild/SPECS/bird.spec \
       /src/

FROM almalinux:9

# iproute for the entrypoint and for tests that program routes; procps-ng for
# tests that signal the daemons.
RUN dnf upgrade -y && dnf install -y \
    iproute \
    procps-ng && \
    dnf clean all

COPY --from=build /rpms/ /rpms/
COPY --from=build /src/ /src/
RUN rpm -Uvh /rpms/bird-*.rpm

COPY router/bird.conf /etc/bird.conf
COPY router/bird6.conf /etc/bird6.conf
COPY router/bird-wrapper.sh /opt/bird-wrapper.sh
RUN mkdir -p /etc/bird /etc/bird6

ENTRYPOINT ["/opt/bird-wrapper.sh"]
