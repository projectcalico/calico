# Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

FROM scratch AS source

ARG TARGETARCH

# And the mock-node itself...
COPY bin/test-tools/mocknode-${TARGETARCH} /usr/bin/mocknode

FROM calico/base

ARG GIT_VERSION=unknown

# Required labels for certification
LABEL description="Calico mock node for scale testing"
LABEL maintainer="shaun@tigera.io"
LABEL name="Calico mock node"
LABEL release="1"
LABEL summary="Calico mock node for scale testing"
LABEL vendor="Tigera"
LABEL version=${GIT_VERSION}

COPY --from=source / /

ENTRYPOINT ["/usr/bin/mocknode"]
