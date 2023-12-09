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

ARG UBI_IMAGE

FROM ${UBI_IMAGE} as ubi

FROM scratch as source

ARG TARGETARCH
ARG BIN_DIR

COPY --from=ubi /bin/bash /bin/bash
COPY --from=ubi /usr/bin/chmod /usr/bin/chmod
COPY --from=ubi /usr/bin/coreutils /usr/bin/coreutils
COPY --from=ubi /usr/bin/cp /usr/bin/cp
COPY --from=ubi /usr/bin/echo /usr/bin/echo
COPY --from=ubi /usr/bin/ls /usr/bin/ls
COPY --from=ubi /usr/bin/mv /usr/bin/mv
COPY --from=ubi /usr/bin/rm /usr/bin/rm

COPY --from=ubi /lib64/libacl.so.1 /lib64/libacl.so.1
COPY --from=ubi /lib64/libattr.so.1 /lib64/libattr.so.1
COPY --from=ubi /lib64/libcap.so.2 /lib64/libcap.so.2
COPY --from=ubi /lib64/libdl.so.2 /lib64/libdl.so.2
COPY --from=ubi /lib64/libpcre2-8.so.0 /lib64/libpcre2-8.so.0
COPY --from=ubi /lib64/librt.so.1 /lib64/librt.so.1
COPY --from=ubi /lib64/libselinux.so.1 /lib64/libselinux.so.1
COPY --from=ubi /lib64/libtinfo.so.6 /lib64/libtinfo.so.6

COPY LICENSE /licenses/LICENSE

COPY ${BIN_DIR}/flexvol-${TARGETARCH} /usr/local/bin/flexvol
COPY flexvol/docker-image/flexvol.sh /usr/local/bin/flexvol.sh

FROM calico/base

ARG GIT_VERSION=unknown

LABEL description="Calico FlexVolume driver installer to setup secure connections from Kubernetes pods to local daemons"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico FlexVolume driver installer"
LABEL release="1"
LABEL summary="Calico FlexVolume driver installer to setup secure connections from Kubernetes pods to local daemons"
LABEL vendor="Project Calico"
LABEL version=$GIT_VERSION

COPY --from=source / /

ENTRYPOINT ["/usr/local/bin/flexvol.sh"]
