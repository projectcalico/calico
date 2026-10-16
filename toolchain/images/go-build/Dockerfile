# Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

# calico/go-build: the Go, Clang and tooling image every Calico build runs in.
#
# Layers go from least to most likely to change, so a bump re-pulls only the
# layers above what it touched. Each layer holds only its final files: a
# component is built in its own stage and arrives through one COPY, and the dnf
# layers clean up in the same RUN. A file written in one layer and deleted or
# rewritten in a later one would still ship in the earlier layer.
#
#   1. OS packages        (squashed, so dnf upgrade does not duplicate the base)
#   2. LLVM
#   3. Cross sysroots     (amd64 only)
#   4. Small static tools (su-exec, protoc, docker-credential-gcr)
#   5. Go
#   6. Go tools built with that Go
#   7. Prebuilt tools     (golangci-lint, mockery, crane, ocb)
#   8. CI scripts and the entrypoint

ARG CI_SCRIPTS_VERSION=v2
FROM calico/ci-scripts:${CI_SCRIPTS_VERSION} AS ci-scripts

################################################################################
# 1. OS packages
################################################################################
FROM almalinux:9 AS os-build

ARG TARGETARCH

# Docs are never read in a build container.
RUN set -eux; \
    dnf upgrade -y --setopt=tsflags=nodocs; \
    dnf install -y --setopt=tsflags=nodocs epel-release; \
    dnf --enablerepo=crb install -y --setopt=tsflags=nodocs \
        autoconf \
        automake \
        bpftool \
        bsdtar \
        ccache \
        cpio \
        elfutils-libelf-devel \
        git \
        iproute-devel \
        iproute-tc \
        iputils \
        jq \
        libbpf-devel \
        libcurl-devel \
        libpcap-devel \
        libtool \
        make \
        openssh-clients \
        patch \
        pcre-devel \
        pigz \
        pkg-config \
        sudo \
        wget \
        xz \
        yq \
        zip; \
    if [ "${TARGETARCH}" = "amd64" ]; then \
        dnf --enablerepo=crb install -y --setopt=tsflags=nodocs mingw64-gcc; \
    fi; \
    dnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf* /var/log/hawkey.log /tmp/*; \
    # The entrypoint's useradd must not create a mail spool.
    sed -i 's/^CREATE_MAIL_SPOOL=yes/CREATE_MAIL_SPOOL=no/' /etc/default/useradd

FROM scratch AS os
COPY --from=os-build / /

################################################################################
# 2. LLVM
################################################################################
FROM os AS llvm

ARG LLVM_VERSION

RUN set -eux; \
    test -n "${LLVM_VERSION}"; \
    dnf --enablerepo=crb install -y --setopt=tsflags=nodocs \
        clang-${LLVM_VERSION} \
        lld-${LLVM_VERSION} \
        llvm-${LLVM_VERSION}; \
    dnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum /var/log/dnf* /var/log/hawkey.log /tmp/*

################################################################################
# 3. Cross-compilation sysroots
################################################################################
# Sysroots for arm64, ppc64le and s390x let amd64 cross-compile Go+CGO at native
# speed with clang instead of building under QEMU (2-3 min instead of 30+ for
# calico-node). The target-arch RPMs are unpacked rather than installed.
FROM os AS sysroots

ARG TARGETARCH

RUN set -eux; \
    mkdir -p /out; \
    if [ "${TARGETARCH}" != "amd64" ]; then exit 0; fi; \
    for arch in aarch64 ppc64le s390x; do \
        case "${arch}" in \
            aarch64) triple=aarch64-linux-gnu ;; \
            ppc64le) triple=powerpc64le-linux-gnu ;; \
            s390x)   triple=s390x-linux-gnu ;; \
        esac; \
        sysroot="/out/usr/${triple}/sys-root"; \
        mkdir -p "${sysroot}"; \
        tmpdir=$(mktemp -d); \
        packages="gcc libgcc glibc glibc-devel kernel-headers elfutils-libelf elfutils-libelf-devel libpcap libpcap-devel zlib zlib-devel"; \
        if [ "${arch}" = "s390x" ]; then \
            packages="${packages} glibc-headers"; \
        fi; \
        dnf download --destdir="${tmpdir}" \
            --repofrompath="alma-${arch}-baseos,https://repo.almalinux.org/almalinux/9/BaseOS/${arch}/os/" \
            --repofrompath="alma-${arch}-appstream,https://repo.almalinux.org/almalinux/9/AppStream/${arch}/os/" \
            --repofrompath="alma-${arch}-crb,https://repo.almalinux.org/almalinux/9/CRB/${arch}/os/" \
            --repo="alma-${arch}-baseos" \
            --repo="alma-${arch}-appstream" \
            --repo="alma-${arch}-crb" \
            --setopt="alma-${arch}-baseos.mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/baseos" \
            --setopt="alma-${arch}-baseos.gpgcheck=1" \
            --setopt="alma-${arch}-baseos.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9" \
            --setopt="alma-${arch}-appstream.mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/appstream" \
            --setopt="alma-${arch}-appstream.gpgcheck=1" \
            --setopt="alma-${arch}-appstream.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9" \
            --setopt="alma-${arch}-crb.mirrorlist=https://mirrors.almalinux.org/mirrorlist/9/crb" \
            --setopt="alma-${arch}-crb.gpgcheck=1" \
            --setopt="alma-${arch}-crb.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9" \
            --forcearch="${arch}" \
            ${packages}; \
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
        # s390x's libgcc_s.so is an absolute symlink to /lib64/libgcc_s.so.1,
        # which ld.lld follows to the host fs because --sysroot is not applied to
        # symlinks. A linker script, as aarch64 and ppc64le ship, is resolved
        # under --sysroot.
        if [ "${arch}" = "s390x" ]; then \
            for libgcc_s in "${sysroot}"/usr/lib/gcc/s390x-redhat-linux/*/libgcc_s.so; do \
                [ -L "${libgcc_s}" ] || continue; \
                rm "${libgcc_s}"; \
                printf 'OUTPUT_FORMAT(elf64-s390)\nGROUP ( /lib64/libgcc_s.so.1 libgcc.a )\n' > "${libgcc_s}"; \
            done; \
        fi; \
    done

################################################################################
# 4. Small static tools
################################################################################
FROM llvm AS static-tools

ARG TARGETARCH
ARG PROTOC_VERSION=36.0
ARG DOCKER_CREDENTIAL_GCR_VERSION=2.2.1
ARG SU_EXEC_COMMIT=89c016e6e08749d583efdeda04b9f73e1218e253

RUN set -eux; \
    mkdir -p /out/usr/bin /out/usr/local/bin; \
    # The entrypoint drops to the caller's UID with su-exec.
    curl -sfL "https://raw.githubusercontent.com/ncopa/su-exec/${SU_EXEC_COMMIT}/su-exec.c" -o /tmp/su-exec.c; \
    clang -Wall -O2 /tmp/su-exec.c -o /out/usr/bin/su-exec; \
    case "${TARGETARCH}" in \
        amd64)   protoc_arch=x86_64 ;; \
        arm64)   protoc_arch=aarch_64 ;; \
        ppc64le) protoc_arch=ppcle_64 ;; \
        s390x)   protoc_arch=s390_64 ;; \
    esac; \
    curl -sfL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${protoc_arch}.zip" \
        | bsdtar -xf - -C /out/usr bin/protoc include; \
    chmod +x /out/usr/bin/protoc; \
    # A standalone GCR credential helper, so the image needs no gcloud SDK.
    # Upstream ships no ppc64le build.
    if [ "${TARGETARCH}" != "ppc64le" ]; then \
        curl -sfL "https://github.com/GoogleCloudPlatform/docker-credential-gcr/releases/download/v${DOCKER_CREDENTIAL_GCR_VERSION}/docker-credential-gcr_linux_${TARGETARCH}-${DOCKER_CREDENTIAL_GCR_VERSION}.tar.gz" \
            | tar -xz -C /out/usr/local/bin docker-credential-gcr; \
    fi

################################################################################
# 5. Go
################################################################################
FROM os AS go

ARG TARGETARCH
ARG GO_VERSION

COPY go.sha256 /tmp/go.sha256

RUN set -eux; \
    test -n "${GO_VERSION}"; \
    tarball="go${GO_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    url="https://dl.google.com/go/${tarball}"; \
    cd /tmp; \
    grep -F "  ${tarball}" go.sha256 > want.sha256 || { echo "no checksum for ${tarball} in go.sha256" >&2; exit 1; }; \
    wget -q -O "${tarball}.asc" "${url}.asc"; \
    wget -q -O "${tarball}" "${url}"; \
    sha256sum -c want.sha256; \
    # https://github.com/golang/go/issues/14739#issuecomment-324767697
    GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; \
    # https://www.google.com/linuxrepositories/
    gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 'EB4C 1BFD 4F04 2F6D DDCC  EC91 7721 F63B D38B 4796'; \
    # The subkey go.tgz.asc is expected to be signed by.
    gpg --batch --keyserver keyserver.ubuntu.com --recv-keys '2F52 8D36 D67B 69ED F998  D857 78BD 6547 3CB3 BD13'; \
    gpg --batch --verify "${tarball}.asc" "${tarball}"; \
    gpgconf --kill all; \
    mkdir -p /out/usr/local; \
    tar -C /out/usr/local -xzf "${tarball}"; \
    # Go's own test suite; nothing builds or tests against it.
    rm -rf /out/usr/local/go/test; \
    rm -rf "${GNUPGHOME}" /tmp/*; \
    /out/usr/local/go/bin/go version

################################################################################
# 6. Go tools
################################################################################
FROM os AS go-tools

ARG GINKGO_VERSION=v2.32.1
ARG GOTESTSUM_VERSION

COPY --from=go /out/usr/local/go /usr/local/go

ENV PATH=/usr/local/go/bin:$PATH
ENV GOTOOLCHAIN=local
ENV GOPATH=/tmp/gopath
ENV GOBIN=/out/go/bin
ENV CGO_ENABLED=0

# Stripped, since nobody debugs these. /go is world-writable so any UID the
# entrypoint drops to can populate the module and build caches under it.
RUN set -eux; \
    test -n "${GOTESTSUM_VERSION}"; \
    mkdir -p /out/go/src /out/go/bin /out/go/pkg; \
    flags="-trimpath -ldflags=-s -ldflags=-w"; \
    go install ${flags} github.com/jstemmer/go-junit-report@v1.0.0; \
    go install ${flags} github.com/onsi/ginkgo/v2/ginkgo@${GINKGO_VERSION}; \
    go install ${flags} github.com/wadey/gocovmerge@v0.0.0-20160331181800-b5bfa59ec0ad; \
    go install ${flags} golang.org/x/tools/cmd/goimports@v0.50.0; \
    go install ${flags} golang.org/x/tools/cmd/stringer@v0.50.0; \
    go install ${flags} google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2; \
    go install ${flags} google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12; \
    go install ${flags} gotest.tools/gotestsum@${GOTESTSUM_VERSION}; \
    go install ${flags} mvdan.cc/gofumpt@v0.11.0; \
    chmod -R 1777 /out/go; \
    chmod 755 /out/go/bin/*; \
    rm -rf /tmp/gopath /root/.cache

################################################################################
# 7. Prebuilt tools
################################################################################
FROM os AS prebuilt-tools

ARG TARGETARCH
ARG CONTAINERREGISTRY_VERSION
ARG GO_LINT_VERSION=v2.14.0
ARG MOCKERY_VERSION=3.8.1
ARG OCB_VERSION=0.157.0

RUN set -eux; \
    test -n "${CONTAINERREGISTRY_VERSION}"; \
    mkdir -p /out/usr/local/bin; \
    cd /out/usr/local/bin; \
    curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b /out/usr/local/bin ${GO_LINT_VERSION}; \
    case "${TARGETARCH}" in \
        amd64) mockery_arch=x86_64 ;; \
        arm64) mockery_arch=arm64 ;; \
        *)     mockery_arch= ;; \
    esac; \
    if [ -n "${mockery_arch}" ]; then \
        curl -sfL "https://github.com/vektra/mockery/releases/download/v${MOCKERY_VERSION}/mockery_${MOCKERY_VERSION}_Linux_${mockery_arch}.tar.gz" | tar -xz mockery; \
    fi; \
    # Release targets copy images between registries with crane.
    if [ "${TARGETARCH}" = "amd64" ]; then \
        curl -sfL "https://github.com/google/go-containerregistry/releases/download/${CONTAINERREGISTRY_VERSION}/go-containerregistry_Linux_x86_64.tar.gz" | tar -xz crane; \
    fi; \
    # The OpenTelemetry Collector Builder, for otel-collector.
    if [ "${TARGETARCH}" = "amd64" ] || [ "${TARGETARCH}" = "arm64" ]; then \
        curl -sfL "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/cmd%2Fbuilder%2Fv${OCB_VERSION}/ocb_${OCB_VERSION}_linux_${TARGETARCH}" -o ocb; \
        chmod +x ocb; \
    fi

################################################################################
# 8. CI scripts
################################################################################
FROM scratch AS ci

ARG TARGETARCH

# Argo workflows have no pre-checkout step, so these helpers make this image a
# usable step image on its own. Semaphore runners do their own checkout and
# ignore them.
COPY --from=ci-scripts /changesIn /checkout /createLocalSecret /logSection /setupGithubSSH /usr/local/bin/
# A gsutil-free artifact, so the image needs no gcloud SDK or its bundled Python.
COPY bin/artifact-${TARGETARCH} /usr/local/bin/artifact
# Some callers use the kebab-case spellings.
COPY --from=ci-scripts /setupGithubSSH /usr/local/bin/setup-github-ssh
COPY --from=ci-scripts /createLocalSecret /usr/local/bin/create-local-secret
COPY ssh_known_hosts /etc/ssh/ssh_known_hosts
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

################################################################################
# Final image
################################################################################
FROM llvm

COPY --from=sysroots /out/ /
COPY --from=static-tools /out/ /
COPY --from=go /out/usr/local/go /usr/local/go
# The parent, so /go keeps its mode: copying a directory's contents to a new
# path creates that path as 755.
COPY --from=go-tools /out/ /
COPY --from=prebuilt-tools /out/usr/local/bin/ /usr/local/bin/
COPY --from=ci / /

ENV GOPATH=/go
ENV GOTOOLCHAIN=local
ENV CC=clang
ENV CXX=clang++
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
