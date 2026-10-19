# Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.
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

# check=skip=InvalidDefaultArgInFrom
# calico/base: the glibc runtime that Calico's dynamically linked binaries run
# on. It exists to carry UBI's package updates, so it is rebuilt from the
# current ubi-minimal and upgraded, then cut down to what the binaries load.

# Set by the Makefile. The digest pins the exact ubi-minimal it resolved, so
# the image's label names what it was built from.
ARG UBI_VERSION
ARG UBI_DIGEST

FROM registry.access.redhat.com/${UBI_VERSION}/ubi-minimal@${UBI_DIGEST} AS ubi

ARG TARGETARCH

# Only the files listed here ship; symbolic links are preserved where cp -a
# is used. The NSS config is our own, since the base image's only enables the
# dns and files plugins.
RUN set -eux; \
    microdnf upgrade -y; \
    case "${TARGETARCH}" in \
        amd64)   ldsoname=ld-linux-x86-64.so.2 ;; \
        arm64)   ldsoname=ld-linux-aarch64.so.1 ;; \
        ppc64le) ldsoname=ld64.so.2 ;; \
        s390x)   ldsoname=ld64.so.1 ;; \
        *) echo >&2 "error: unsupported architecture '${TARGETARCH}'"; exit 1 ;; \
    esac; \
    mkdir -p /rootfs/lib64 /rootfs/etc; \
    if [ -f "/lib64/${ldsoname}" ]; then \
        cp -a "/lib64/${ldsoname}" "/rootfs/lib64/${ldsoname}"; \
    fi; \
    if [ -f "/lib/${ldsoname}" ]; then \
        mkdir -p /rootfs/lib && cp -a "/lib/${ldsoname}" "/rootfs/lib/${ldsoname}"; \
    fi; \
    # CGO's libc dependencies, then the rest of the standard C and C++ runtime.
    for lib in \
        libc.so.6 libpthread.so.0 libresolv.so.2 \
        libdl.so.2 libgcc_s.so.1 libm.so.6 librt.so.1 libstdc++.so.6 \
        libnss_dns.so.2 libnss_files.so.2; do \
        cp "/lib64/${lib}" "/rootfs/lib64/${lib}"; \
    done; \
    for f in host.conf hosts networks os-release; do \
        cp "/etc/${f}" "/rootfs/etc/${f}"; \
    done; \
    mkdir -m 1777 /rootfs/tmp

COPY nsswitch.conf /rootfs/etc/nsswitch.conf

FROM scratch AS source

COPY --from=ubi /rootfs /

# Fails the build if the dynamic loader or its links were not copied.
RUN ["/lib64/libc.so.6"]

COPY licenses /licenses/

FROM scratch

COPY --from=source / /
