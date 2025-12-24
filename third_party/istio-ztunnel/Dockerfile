# Copyright (c) 2025 Tigera, Inc. All rights reserved.
#
# This Dockerfile packages the ztunnel binary built from source into a minimal container.
# The binary is built separately using the Makefile, which compiles ztunnel with Calico patches applied.

ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS ubi

FROM scratch AS source

ARG TARGETARCH

# Copy required runtime libraries (ztunnel needs libgcc_s and libm)
COPY --from=ubi /lib64/libgcc_s.so.1 /lib64/libgcc_s.so.1
COPY --from=ubi /lib64/libm.so.6 /lib64/libm.so.6

# Copy the ztunnel binary built from patched source
COPY bin/ztunnel-${TARGETARCH} /usr/bin/ztunnel
# Copy license from source
COPY ztunnel/LICENSE /LICENSE

FROM ${CALICO_BASE}

ARG GIT_VERSION=unknown

# These labels are required for OCP Certification
LABEL description="This image contains a build of Istio's ztunnel component from github.com/istio/ztunnel with Calico patches applied"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico Istio ztunnel"
LABEL release="1"
LABEL summary="ztunnel is the zero-trust tunnel component of Calico's integration with Istio ambient mesh"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

LABEL org.opencontainers.image.description="This image contains a build of Istio's ztunnel component from github.com/istio/ztunnel with Calico patches applied"
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="ztunnel is the zero-trust tunnel component of Calico's integration with Istio ambient mesh"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=source / /

# Run as non-root user
USER 10001:10001

# Ztunnel default ports
# 15001: Outbound traffic interception
# 15006: Inbound traffic interception
# 15008: HBONE (HTTP-Based Overlay Network Environment) mTLS tunnel port
# 15020: Metrics and health checks
EXPOSE 15001 15006 15008 15020

ENTRYPOINT ["/usr/bin/ztunnel"]
