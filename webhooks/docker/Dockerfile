# Copyright 2015-2025 Tigera, Inc
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

FROM scratch

ARG TARGETARCH
ARG GIT_VERSION
COPY ./bin/webhook-${TARGETARCH} /webhook

COPY ./bin/LICENSE /licenses/LICENSE

LABEL org.opencontainers.image.description="Webhook is a validating admission webhook for Calico APIs."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Webhook"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Webhook is a validating admission webhook for Calico APIs."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Webhook"
LABEL release=1
LABEL summary="Webhook is a validating admission webhook for Calico APIs."
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

USER 10001:10001

ENTRYPOINT ["/webhook"]
