# Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

FROM scratch as source

ARG TARGETARCH

COPY LICENSE /licenses/LICENSE
COPY bin/calicoctl-linux-${TARGETARCH} /calicoctl

FROM calico/base

ARG GIT_VERSION=unknown

LABEL description="calicoctl(1) is a command line tool used to interface with the Calico datastore"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico CLI tool"
LABEL release="1"
LABEL summary="Calico CLI tool"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

ENV CALICO_CTL_CONTAINER=TRUE

COPY --from=source / /

ENTRYPOINT ["/calicoctl"]
