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

# Alpine rather than the Calico base: a scale test execs into these pods through a shell, sets
# POLICYSCALE_* with env, and a sink pod configures its routes with ip.
FROM alpine:3.21

ARG TARGETARCH

RUN apk add --no-cache iproute2

ARG GIT_VERSION=unknown

# Required labels for certification
LABEL org.opencontainers.image.description="Calico policy-set generator and load generator for scale testing"
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico policyscale"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Calico policy-set generator and load generator for scale testing"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico policyscale"
LABEL release=1
LABEL summary="Calico policy-set generator and load generator for scale testing"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

COPY bin/test-tools/policyscale-${TARGETARCH} /usr/bin/policyscale
COPY bin/test-tools/flowgen-${TARGETARCH} /usr/bin/flowgen

ENTRYPOINT ["/usr/bin/flowgen"]
