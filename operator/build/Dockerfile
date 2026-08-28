# Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS ubi

FROM scratch AS source

ARG TARGETARCH
# BINARY_NAME is "operator" for enterprise/OSS and "operator-cloud" for the Calico Cloud variant.
ARG BINARY_NAME=operator

COPY --from=ubi /etc/pki /etc/pki/
COPY --from=ubi /usr/share/pki /usr/share/pki/

COPY LICENSE /licenses/LICENSE

COPY build/_output/bin/${BINARY_NAME}-${TARGETARCH} /usr/bin/operator

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

LABEL description="Tigera Operator manages the lifecycle of a Calico or Calico Enterprise installation on Kubernetes or OpenShift"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Tigera Operator"
LABEL release="1"
LABEL summary="Tigera Operator manages the lifecycle of a Calico or Calico Enterprise installation on Kubernetes or OpenShift"
LABEL vendor="Tigera"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 10001:10001

ENTRYPOINT ["/usr/bin/operator"]
