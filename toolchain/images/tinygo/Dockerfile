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

# calico/tinygo: TinyGo and the Go it drives, for building WebAssembly.
#
# The image is the builder's whole filesystem copied into one layer, so a
# file deleted in a later step does not ship.

FROM almalinux:9 AS builder

ARG TARGETARCH

# TinyGo upstream publishes Linux tarballs for amd64 and arm64 only. Wasm
# output does not depend on the host arch; arm64 is here so arm64 hosts
# build without emulation.
RUN if [ "${TARGETARCH}" != "amd64" ] && [ "${TARGETARCH}" != "arm64" ]; then \
        echo >&2 "error: calico/tinygo: TinyGo upstream does not publish a Linux ${TARGETARCH} tarball"; \
        exit 1; \
    fi

# Docs are never read in a build container.
RUN set -eux; \
    dnf upgrade -y --setopt=tsflags=nodocs; \
    dnf install -y --setopt=tsflags=nodocs epel-release; \
    dnf install -y --setopt=tsflags=nodocs \
        bsdtar \
        file \
        git \
        make \
        wget \
        yq; \
    dnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf* /var/log/hawkey.log /tmp/*

COPY versions.yaml /etc/versions.yaml

# TinyGo runs the host `go` to load and type-check packages before lowering
# them to wasm, so the image needs a Go that TinyGo accepts. Go's own test
# suite is never used.
RUN set -eux; \
    golang_version=$(yq -r .golang.version /etc/versions.yaml); \
    golang_sha256=$(yq -r ".golang.checksum.sha256.${TARGETARCH}" /etc/versions.yaml); \
    wget -q -O /tmp/go.tar.gz "https://dl.google.com/go/go${golang_version}.linux-${TARGETARCH}.tar.gz"; \
    echo "${golang_sha256}  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm -rf /tmp/go.tar.gz /usr/local/go/test

# The TinyGo tarball is statically linked, so it needs nothing from the base
# image's libc or libstdc++.
RUN set -eux; \
    tinygo_version=$(yq -r .tinygo.version /etc/versions.yaml); \
    tinygo_sha256=$(yq -r ".tinygo.checksum.sha256.${TARGETARCH}" /etc/versions.yaml); \
    wget -q -O /tmp/tinygo.tar.gz \
        "https://github.com/tinygo-org/tinygo/releases/download/v${tinygo_version}/tinygo${tinygo_version}.linux-${TARGETARCH}.tar.gz"; \
    echo "${tinygo_sha256}  /tmp/tinygo.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/tinygo.tar.gz; \
    rm /tmp/tinygo.tar.gz

ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:/usr/local/tinygo/bin:$PATH

# World-writable, since callers run the image as their own UID.
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 1777 "$GOPATH"

RUN go version && tinygo version

FROM scratch

ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:/usr/local/tinygo/bin:/go/bin:$PATH

COPY --from=builder / /

WORKDIR /go
