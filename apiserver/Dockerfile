# Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
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

COPY LICENSE /licenses/LICENSE

COPY ${BIN_DIR}/apiserver-${TARGETARCH} /code/apiserver

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

LABEL description="Aggregated API server which enables calico resources to be managed via kubectl"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico API server"
LABEL release="1"
LABEL summary="Calico API server"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 10001:10001

WORKDIR /code

ENTRYPOINT ["/code/apiserver"]
