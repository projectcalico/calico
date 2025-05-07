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

COPY bin/envoy-gateway-${TARGETARCH} /usr/local/bin/envoy-gateway
COPY --from=source --chown=65532:65532 /var/lib /var/lib

USER 65532:65532

# These labels are required for OCP Certification
LABEL description="Envoy Gateway is an implementation of the Kubernetes Gateway API using the envoy-gateway project"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Envoy Gateway"
LABEL release="1"
LABEL summary="Envoy Gateway is an implementation of the Kubernetes Gateway API using the envoy-gateway project"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

ENTRYPOINT ["/usr/local/bin/envoy-gateway"]
ENV PATH="$PATH:/usr/local/bin"
