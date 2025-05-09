# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM ${CALICO_BASE}

ARG TARGETARCH

COPY bin/envoy-ratelimit-${TARGETARCH} /bin/ratelimit

# These labels are required for OCP Certification
LABEL description="This image contains a build of the Envoy project's ratelimit component from github.com/envoyproxy/ratelimit, which is a service to enable generic rate limiting scenarios for applications."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Envoy Ratelimit"
LABEL release="1"
LABEL summary="envoy-ratelimit is the rate-limiting component of Calico's implementation of the Kubernetes Gateway API"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"
