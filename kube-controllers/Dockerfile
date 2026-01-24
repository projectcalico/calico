# Copyright 2015-2025 Tigera, Inc
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
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

# Make sure the status and pprof files are owned by our user.
RUN mkdir /status /profiles
RUN touch /status/status.json && chown 999 /status/status.json
RUN touch /profiles/mem.pprof && chown 999 /profiles/mem.pprof
RUN touch /profiles/cpu.pprof && chown 999 /profiles/cpu.pprof

FROM scratch AS source

ARG BIN_DIR
ARG TARGETARCH

COPY --from=builder /profiles /profiles/
COPY --from=builder /status /status/

COPY ${BIN_DIR}/LICENSE /licenses/LICENSE

COPY ${BIN_DIR}/kube-controllers-linux-${TARGETARCH} /usr/bin/kube-controllers
COPY ${BIN_DIR}/check-status-linux-${TARGETARCH} /usr/bin/check-status
COPY ${BIN_DIR}/wrapper-${TARGETARCH} /usr/bin/wrapper

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

LABEL org.opencontainers.image.description="Calico Kubernetes controllers monitor the Kubernetes API and perform actions based on cluster state"
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico Kubernetes controllers"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Calico Kubernetes controllers monitor the Kubernetes API and perform actions based on cluster state"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico Kubernetes controllers"
LABEL release=1
LABEL summary="Calico Kubernetes controllers monitor the Kubernetes API and perform actions based on cluster state"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

COPY --from=source / /

USER 999

ENTRYPOINT ["/usr/bin/wrapper", "/usr/bin/kube-controllers"]
