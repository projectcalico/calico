# Copyright (c) 2023 Tigera, Inc. All rights reserved.

FROM scratch as source

ARG TARGETARCH

# Copy in the flow-log-generator and example flows
COPY bin/flow-log-generator-${TARGETARCH} /usr/bin/flow-log-generator
COPY example-flows/flows.log /home/log-gen/flows.log

FROM calico/base

ARG GIT_VERSION=unknown

# Required labels for certification
LABEL description="Calico flow log generator for scale testing"
LABEL maintainer="lance@tigera.io"
LABEL name="Calico flow log generator"
LABEL release="1"
LABEL summary="Calico flow log generator for scale testing"
LABEL vendor="Tigera"
LABEL version=${GIT_VERSION}

COPY --from=source / /

WORKDIR /home/log-gen

ENTRYPOINT ["/usr/bin/flow-log-generator"]
