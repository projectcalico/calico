# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

# Producer image for the upstream BIRD Internet Routing Daemon, built from the
# official release tarball. This replaces the old calico/bird fork image.
#
# Built on a glibc base (debian) WITHOUT libssh, so the `bird` and `birdcl`
# binaries depend only on glibc. That is required because calico/node copies
# these two binaries into its glibc UBI runtime (FROM ${BIRD_IMAGE} +
# COPY --from=bird ...); a musl- or libssh-linked binary would not run there.
# Dropping libssh only disables the RPKI SSH transport, which Calico does not
# use (it programs only bgp/kernel/device/direct/static protocols).
#
# The resulting image also serves as a runnable BGP test peer for the e2e /
# k8st / kubevirt suites, shipping a default /etc/bird/bird.conf (single unified
# daemon, both families) that includes /etc/bird/peers.conf and
# /etc/bird/static-route.conf, which the tests populate at runtime.

ARG BIRD_VERSION
ARG BIRD_SHA256

FROM debian:bookworm-slim AS builder
ARG BIRD_VERSION
ARG BIRD_SHA256
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates wget build-essential autoconf flex bison m4 \
        libreadline-dev libncurses-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN wget -q -O bird.tar.gz "https://bird.nic.cz/download/bird-${BIRD_VERSION}.tar.gz" && \
    echo "${BIRD_SHA256}  bird.tar.gz" | sha256sum -c - && \
    tar xzf bird.tar.gz && \
    cd "bird-${BIRD_VERSION}" && \
    autoreconf -fi && \
    # No libssh-dev installed, so configure builds without the RPKI SSH
    # transport; the bird/birdcl binaries then link only against glibc.
    ./configure --prefix=/usr --sysconfdir=/etc/bird --runstatedir=/run/bird && \
    make -j"$(nproc)" && \
    make install DESTDIR=/install

FROM debian:bookworm-slim
# libreadline is only needed by the interactive birdc client; bird and birdcl
# link only glibc.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libreadline8 libncurses6 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /install/usr/sbin/bird /usr/sbin/bird
COPY --from=builder /install/usr/sbin/birdc /usr/sbin/birdc
COPY --from=builder /install/usr/sbin/birdcl /usr/sbin/birdcl
# Default runnable config so the image can serve as an external BGP peer in
# e2e/k8st tests. Validation use (`bird -p -c <file>`) overrides the CMD.
RUN mkdir -p /etc/bird /run/bird
COPY bird-base.conf /etc/bird/bird.conf
RUN touch /etc/bird/peers.conf /etc/bird/static-route.conf
RUN bird --version && bird -p -c /etc/bird/bird.conf
ENTRYPOINT ["bird"]
CMD ["-f", "-c", "/etc/bird/bird.conf"]
