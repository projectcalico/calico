# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

# This is a copy of
# https://github.com/envoyproxy/gateway/blob/v1.1.2/tools/docker/envoy-gateway/Dockerfile
# but:
# - using calico/base instead of distroless
# - using TARGETARCH instead of TARGETPLATFORM.

ARG CALICO_BASE

FROM busybox AS source

# Create the data directory for the gateway
RUN mkdir -p /var/lib/eg

FROM ${CALICO_BASE}

ARG TARGETARCH
ARG GIT_VERSION=unknown

COPY bin/envoy-gateway-${TARGETARCH} /usr/local/bin/envoy-gateway
COPY --from=source --chown=65532:65532 /var/lib /var/lib

USER 65532:65532

# These labels are required for OCP Certification
LABEL description="This image contains a build of the Envoy project's gateway component from github.com/envoyproxy/gateway, which manages the envoy-proxy component as a kubernetes gateway service."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Envoy Gateway"
LABEL release="1"
LABEL summary="envoy-gateway is the proxy management component of Calico's implementation of the Kubernetes Gateway API"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

LABEL org.opencontainers.image.description="This image contains a build of the Envoy project's gateway component from github.com/envoyproxy/gateway, which manages the envoy-proxy component as a kubernetes gateway service."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="envoy-gateway is the proxy management component of Calico's implementation of the Kubernetes Gateway API"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/usr/local/bin/envoy-gateway"]
ENV PATH="$PATH:/usr/local/bin"
