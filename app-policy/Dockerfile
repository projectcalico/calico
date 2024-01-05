# Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
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

RUN mkdir -p /var/run/dikastes

FROM scratch as source

ARG BIN_DIR
ARG TARGETARCH

COPY LICENSE /licenses/LICENSE

# Typical Linux systems start numbering human users at 1000, reserving 1-999
# for services, so we pick 999 to be least likely to overlap.
#
# Precreate the /var/run/dikastes directory so that we don't need any elevated
# permission to create the directory at runtime.
COPY --chown=999 --from=builder /var/run/dikastes /var/run/dikastes/

COPY ${BIN_DIR}/dikastes-${TARGETARCH} /dikastes
COPY ${BIN_DIR}/healthz-${TARGETARCH} /healthz

FROM calico/base

ARG GIT_VERSION=unknown

LABEL description="Calico Dikastes enables Application Layer Policy"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico Dikastes"
LABEL release="1"
LABEL summary="Calico Dikastes enables Application Layer Policy"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 999

ENTRYPOINT ["/dikastes"]
CMD ["server"]
