# Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

COPY bin/calico-typha-${TARGETARCH} /usr/bin/calico-typha
COPY typha.cfg /etc/calico/typha.cfg

FROM calico/base

ARG GIT_VERSION=unknown

LABEL description="Calico Typha is a fan-out datastore proxy"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico Typha"
LABEL release="1"
LABEL summary="Calico Typha is a fan-out datastore proxy"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 999

CMD ["/usr/bin/calico-typha"]
