# Copyright (c) 2026 Tigera, Inc. All rights reserved.

# Init image used to stage upstream CNI plugin binaries into a shared volume
# read by the calico-node install-cni init container. Uses busybox (rather
# than calico/base, which is distroless) because the entrypoint is a small
# shell script that needs cp and sh.
FROM busybox:1.37.0

ARG TARGETARCH
ARG GIT_VERSION=unknown

# Upstream CNI plugins built from projectcalico/containernetworking-plugins
# and projectcalico/flannel-cni-plugin. See ../../metadata.mk for the pinned
# versions.
COPY bin/${TARGETARCH}/host-local /plugins/host-local
COPY bin/${TARGETARCH}/portmap   /plugins/portmap
COPY bin/${TARGETARCH}/loopback  /plugins/loopback
COPY bin/${TARGETARCH}/tuning    /plugins/tuning
COPY bin/${TARGETARCH}/flannel   /plugins/flannel

COPY install-cni-plugins.sh /usr/local/bin/install-cni-plugins

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
