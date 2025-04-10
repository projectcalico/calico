# Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.
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

ARG CALICO_BASE

FROM scratch AS source

ARG BIN_DIR
ARG TARGETARCH

COPY ${BIN_DIR}/node-driver-registrar-${TARGETARCH} /usr/bin/node-driver-registrar

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown
ARG UPSTREAM_VER=unknown

LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.title="CSI Node driver registrar"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.description="CSI Node driver registrar handles registration of CSI drivers with the kubelet. This is the upstream version repackaged for Calico."
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${UPSTREAM_VER}+calico-${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"


COPY --from=source / /

ENTRYPOINT ["/usr/bin/node-driver-registrar"]
