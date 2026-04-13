ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

# pprof profile dumps for kube-controllers.
RUN mkdir /profiles
RUN touch /profiles/mem.pprof && chown 999 /profiles/mem.pprof
RUN touch /profiles/cpu.pprof && chown 999 /profiles/cpu.pprof

# Stage all build-context files into a scratch layer so the final image gets
# them in a single COPY. This keeps the CALICO_BASE layer hash stable across
# (hash)releases — only the staged layer above it changes from one build to
# the next, so the base layer is reused from the registry cache.
FROM scratch AS source

ARG TARGETARCH
ARG BIN_DIR

COPY ${BIN_DIR}/calico-${TARGETARCH} /usr/bin/calico
# Provide calicoctl for backward compatibility with scripts that exec into the container.
COPY ${BIN_DIR}/calico-${TARGETARCH} /usr/bin/calicoctl
COPY pod2daemon/bin/node-driver-registrar-${TARGETARCH} /usr/bin/csi-node-driver-registrar
COPY ${BIN_DIR}/LICENSE /licenses/LICENSE

FROM ${CALICO_BASE}

ARG GIT_VERSION

COPY --from=builder /profiles /profiles/
COPY --from=source / /

LABEL org.opencontainers.image.description="Calico combined binary containing all Calico components."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Calico"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Calico combined binary containing all Calico components."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico"
LABEL release=1
LABEL summary="Calico combined binary containing all Calico components."
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

ENTRYPOINT ["/usr/bin/calico"]
