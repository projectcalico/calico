# Copyright (c) 2026 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM ${CALICO_BASE}

ARG TARGETARCH
ARG GIT_VERSION=unknown

# Upstream CNI plugins built from projectcalico/containernetworking-plugins
# and projectcalico/flannel-cni-plugin. See ../../metadata.mk for the pinned
# versions.
COPY bin/${TARGETARCH}/host-local /plugins/host-local
COPY bin/${TARGETARCH}/portmap    /plugins/portmap
COPY bin/${TARGETARCH}/loopback   /plugins/loopback
COPY bin/${TARGETARCH}/tuning     /plugins/tuning
COPY bin/${TARGETARCH}/flannel    /plugins/flannel

# Entrypoint: copies /plugins/ into the shared stage dir read by install-cni.
COPY bin/${TARGETARCH}/install-cni-plugins /usr/local/bin/install-cni-plugins

# These labels are required for OCP Certification.
LABEL description="Upstream CNI plugins (host-local, portmap, loopback, tuning, flannel) shipped by Calico for staging onto cluster nodes."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico CNI plugins"
LABEL release="1"
LABEL summary="Upstream CNI plugins installed by Calico onto each node."
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

LABEL org.opencontainers.image.description="Upstream CNI plugins (host-local, portmap, loopback, tuning, flannel) shipped by Calico for staging onto cluster nodes."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico CNI plugins"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/usr/local/bin/install-cni-plugins"]
