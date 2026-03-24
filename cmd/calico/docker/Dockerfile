ARG CALICO_BASE

FROM ${CALICO_BASE}

ARG TARGETARCH
ARG GIT_VERSION
ARG BIN_DIR

COPY ${BIN_DIR}/calico-${TARGETARCH} /usr/bin/calico
COPY pod2daemon/bin/node-driver-registrar-${TARGETARCH} /usr/bin/csi-node-driver-registrar

# CNI plugin install expects binaries at /opt/cni/bin/
RUN mkdir -p /opt/cni/bin && \
    ln -s /usr/bin/calico /opt/cni/bin/calico && \
    ln -s /usr/bin/calico /opt/cni/bin/calico-ipam

COPY ${BIN_DIR}/LICENSE /licenses/LICENSE

LABEL org.opencontainers.image.description="Calico uber binary containing all Calico components."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Calico uber binary containing all Calico components."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico"
LABEL release=1
LABEL summary="Calico uber binary containing all Calico components."
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

ENTRYPOINT ["/usr/bin/calico"]
