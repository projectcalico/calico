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

# calico/signing-tools: pinned cosign and syft for release signing, on scratch.
# No entrypoint: callers run `cosign ...` or `syft ...` directly. The versions
# and checksums come from versions.env.
ARG UBI_VERSION=ubi9

FROM registry.access.redhat.com/${UBI_VERSION}/ubi-minimal:latest AS rootfs

ARG TARGETARCH
ARG COSIGN_VERSION
ARG COSIGN_SHA256
ARG SYFT_VERSION
ARG SYFT_SHA256

RUN microdnf install -y tar gzip && microdnf clean all

RUN set -eux; \
    mkdir -p /rootfs/etc/ssl/certs /rootfs/tmp /rootfs/usr/local/bin; \
    cp /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /rootfs/etc/ssl/certs/ca-certificates.crt; \
    chmod 1777 /rootfs/tmp; \
    curl -sfL -o /rootfs/usr/local/bin/cosign \
        https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${TARGETARCH}; \
    echo "${COSIGN_SHA256} */rootfs/usr/local/bin/cosign" | sha256sum -c -; \
    chmod +x /rootfs/usr/local/bin/cosign; \
    curl -sfL -o /tmp/syft.tar.gz \
        https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz; \
    echo "${SYFT_SHA256} */tmp/syft.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/syft.tar.gz -C /rootfs/usr/local/bin syft

FROM scratch

COPY --from=rootfs /rootfs /

# cosign keeps its sigstore trust root under $HOME, which must be writable by a
# uid with no /etc/passwd entry.
ENV HOME=/tmp
ENV PATH=/usr/local/bin

USER 65532
