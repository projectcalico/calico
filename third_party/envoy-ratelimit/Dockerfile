# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM ${CALICO_BASE}

ARG TARGETARCH
ARG GIT_VERSION=unknown

COPY bin/envoy-ratelimit-${TARGETARCH} /bin/ratelimit

# These labels are required for OCP Certification
LABEL description="This image contains a build of the Envoy project's ratelimit component from github.com/envoyproxy/ratelimit, which is a service to enable generic rate limiting scenarios for applications."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Envoy Ratelimit"
LABEL release="1"
LABEL summary="envoy-ratelimit is the rate-limiting component of Calico's implementation of the Kubernetes Gateway API"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

LABEL org.opencontainers.image.description="This image contains a build of the Envoy project's ratelimit component from github.com/envoyproxy/ratelimit, which is a service to enable generic rate limiting scenarios for applications."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="envoy-ratelimit is the rate-limiting component of Calico's implementation of the Kubernetes Gateway API"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
