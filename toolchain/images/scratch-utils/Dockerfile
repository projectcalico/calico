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

# calico/scratch-utils: the static scratch-utils binary on scratch. Beyond itself
# it needs two things, prepared from UBI the same way calico/base builds its
# rootfs: a TLS trust store (every GCP API call fails without one) and a writable
# /tmp (the compute SA key is written there). There is no shell and no package
# manager, so workflow steps run `scratch-utils <subcommand>` directly. The
# Makefile builds the binary into bin/ before the image.

ARG UBI_VERSION=ubi9

FROM registry.access.redhat.com/${UBI_VERSION}/ubi-minimal:latest AS rootfs
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/tmp \
    && cp /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
          /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chmod 1777 /rootfs/tmp

FROM scratch

ARG TARGETARCH

COPY --from=rootfs /rootfs /
COPY bin/scratch-utils-${TARGETARCH} /usr/local/bin/scratch-utils

# Numeric so no /etc/passwd is needed; same uid distroless nonroot uses.
USER 65532

ENTRYPOINT ["/usr/local/bin/scratch-utils"]
