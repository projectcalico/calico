# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

# calico/rust-build: the Rust toolchain Calico builds Rust components with.
#
# The image is the builder's whole filesystem copied into one layer, so a
# file deleted in a later step does not ship. Caches are cleaned once, at the
# end.

FROM almalinux:9 AS builder

ARG TARGETARCH
ARG RUST_VERSION
ARG RUSTUP_VERSION=1.29.0
ARG PROTOC_VERSION=35.1

ENV CC=clang
ENV CXX=clang++
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

# Docs are never read in a build container. EPEL carries the aarch64 binutils
# that amd64 cross-compiles with.
RUN set -eux; \
    dnf upgrade -y --setopt=tsflags=nodocs; \
    dnf install -y --setopt=tsflags=nodocs epel-release; \
    dnf install -y --setopt=tsflags=nodocs \
        bsdtar \
        clang \
        cmake \
        cpio \
        lld \
        make \
        wget; \
    if [ "${TARGETARCH}" = "amd64" ]; then \
        dnf install -y --setopt=tsflags=nodocs binutils-aarch64-linux-gnu; \
    fi

RUN set -eux; \
    test -n "${RUST_VERSION}"; \
    case "${TARGETARCH}" in \
    'amd64') \
        rustup_arch='x86_64-unknown-linux-gnu'; \
        rustup_sha256='4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10'; \
        ;; \
    'arm64') \
        rustup_arch='aarch64-unknown-linux-gnu'; \
        rustup_sha256='9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792'; \
        ;; \
    'ppc64le') \
        rustup_arch='powerpc64le-unknown-linux-gnu'; \
        rustup_sha256='4bfff85bd3967d988e14567aa9cc6ab0ea386f0ffeff0f9f14d23f0103bf1f97'; \
        ;; \
    's390x') \
        rustup_arch='s390x-unknown-linux-gnu'; \
        rustup_sha256='66c2c132428b6b77803facb02cbdf33b89d20c00bd20da142be8cb651f2e7cd8'; \
        ;; \
    *) echo >&2 "error: unsupported architecture '${TARGETARCH}'"; exit 1 ;; \
    esac; \
    url="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustup_arch}/rustup-init"; \
    wget --progress=dot:giga "$url"; \
    echo "${rustup_sha256} *rustup-init" | sha256sum -c -; \
    chmod +x rustup-init; \
    ./rustup-init -y \
        --no-modify-path \
        --profile minimal \
        --component clippy --component llvm-tools --component rustfmt \
        --default-toolchain "${RUST_VERSION}" --default-host ${rustup_arch}; \
    rm rustup-init; \
    # Builds run as the caller's UID, and cargo writes its registry here.
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME; \
    rustup --version; \
    cargo --version; \
    rustc --version

# An arm64 sysroot, so amd64 cross-compiles with clang --target/--sysroot
# instead of building under QEMU. The target-arch RPMs are unpacked rather
# than installed.
RUN set -eux; \
    if [ "${TARGETARCH}" != "amd64" ]; then exit 0; fi; \
    arch=aarch64; \
    triple=aarch64-linux-gnu; \
    sysroot="/usr/${triple}/sys-root"; \
    mkdir -p "${sysroot}"; \
    tmpdir=$(mktemp -d); \
    dnf download --destdir="${tmpdir}" \
        --repofrompath="alma-${arch}-baseos,https://repo.almalinux.org/almalinux/9/BaseOS/${arch}/os/" \
        --repofrompath="alma-${arch}-appstream,https://repo.almalinux.org/almalinux/9/AppStream/${arch}/os/" \
        --repo="alma-${arch}-baseos" \
        --repo="alma-${arch}-appstream" \
        --setopt="alma-${arch}-baseos.gpgcheck=1" \
        --setopt="alma-${arch}-baseos.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9" \
        --setopt="alma-${arch}-appstream.gpgcheck=1" \
        --setopt="alma-${arch}-appstream.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9" \
        --forcearch="${arch}" \
        gcc libgcc \
        glibc glibc-devel \
        kernel-headers; \
    for rpm in "${tmpdir}"/*.rpm; do \
        rpm2cpio "${rpm}" | cpio -idm -D "${sysroot}"; \
    done; \
    rm -rf "${tmpdir}"; \
    # AlmaLinux's usrmerge layout (/lib64 -> usr/lib64), so absolute paths in
    # glibc's linker scripts resolve under --sysroot.
    for dir in lib lib64; do \
        if [ -d "${sysroot}/${dir}" ] && [ ! -L "${sysroot}/${dir}" ]; then \
            mkdir -p "${sysroot}/usr/${dir}"; \
            cp -a "${sysroot}/${dir}/." "${sysroot}/usr/${dir}/"; \
            rm -rf "${sysroot}/${dir}"; \
        fi; \
        if [ ! -e "${sysroot}/${dir}" ]; then \
            ln -s "usr/${dir}" "${sysroot}/${dir}"; \
        fi; \
    done; \
    rustup target add aarch64-unknown-linux-gnu

RUN set -eux; \
    case "${TARGETARCH}" in \
    'amd64')   protoc_arch=x86_64 ;; \
    'arm64')   protoc_arch=aarch_64 ;; \
    'ppc64le') protoc_arch=ppcle_64 ;; \
    's390x')   protoc_arch=s390_64 ;; \
    *) echo >&2 "error: unsupported architecture '${TARGETARCH}'"; exit 1 ;; \
    esac; \
    curl -sfL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${protoc_arch}.zip" \
        | bsdtar -xf - -C /usr; \
    chmod +x /usr/bin/protoc; \
    protoc --version

# The sysroot download leaves its own repo metadata behind, which dnf clean
# all does not know about.
RUN set -eux; \
    dnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf* /var/log/hawkey.log /tmp/* /root/.cache

FROM scratch

ENV CC=clang
ENV CXX=clang++
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

COPY --from=builder / /
