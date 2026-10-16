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

# calico/binfmt: registers QEMU user-mode emulators with the kernel, so an
# amd64 host can build and run arm64, ppc64le and s390x images.

FROM fedora:44 AS qemu

ARG QEMU_VERSION

RUN set -eux; \
    test -n "${QEMU_VERSION}"; \
    dnf install -y qemu-user-static-${QEMU_VERSION}

# binfmt registers the emulators by these names, without the -static suffix.
FROM scratch AS source

ARG TARGETARCH

COPY --from=qemu /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64
COPY --from=qemu /usr/bin/qemu-ppc64le-static /usr/bin/qemu-ppc64le
COPY --from=qemu /usr/bin/qemu-s390x-static /usr/bin/qemu-s390x
COPY --from=qemu /usr/bin/qemu-x86_64-static /usr/bin/qemu-x86_64
COPY bin/binfmt-${TARGETARCH} /usr/bin/binfmt

FROM scratch

COPY --from=source / /

ENTRYPOINT ["/usr/bin/binfmt"]
