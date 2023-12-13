# Copyright 2019 Tigera, Inc
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

ARG QEMU_IMAGE

FROM ${QEMU_IMAGE} as qemu

FROM alpine:3 as builder

COPY --from=qemu /usr/bin/qemu-*-static /usr/bin/

# Make sure the status file is owned by our user.
RUN mkdir /status
RUN touch /status/status.json && chown 999 /status/status.json

FROM scratch as source

ARG BIN_DIR
ARG TARGETARCH

COPY --from=builder /status /status/

COPY LICENSE /licenses/LICENSE

COPY ${BIN_DIR}/kubectl-${TARGETARCH} /usr/bin/kubectl
COPY ${BIN_DIR}/kube-controllers-linux-${TARGETARCH} /usr/bin/kube-controllers
COPY ${BIN_DIR}/check-status-linux-${TARGETARCH} /usr/bin/check-status

FROM calico/base

ARG GIT_VERSION=unknown

LABEL description="Calico Flannel migration controller updates a flannel cluster to Calico"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico Flannel migration controller"
LABEL release="1"
LABEL summary="Calico Flannel migration controller updates a flannel cluster to Calico"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 999

ENTRYPOINT ["/usr/bin/kube-controllers"]
