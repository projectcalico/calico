ARG CALICO_BASE
ARG UBI_IMAGE

FROM ${UBI_IMAGE} AS builder

ARG TARGETARCH
ARG BIN_DIR

# Stage the calico binary alongside a calicoctl symlink. The binary detects
# argv[0]=="calicoctl" and dispatches to the `ctl` subcommand, so calicoctl
# can be a symlink rather than a duplicate copy of the binary.
# The symlink has to be created in a stage that has a shell (scratch does
# not) and the target has to resolve when BuildKit computes the COPY
# checksum, so we stage both files together here under /shim.
RUN mkdir -p /shim/usr/bin
COPY ${BIN_DIR}/calico-${TARGETARCH} /shim/usr/bin/calico
RUN ln -s calico /shim/usr/bin/calicoctl && \
    ln -s calico /shim/usr/bin/calico-ipam

# Stage all build-context files into a scratch layer so the final image gets
# them in a single COPY. This keeps the CALICO_BASE layer hash stable across
# (hash)releases — only the staged layer above it changes from one build to
# the next, so the base layer is reused from the registry cache.
FROM scratch AS source

ARG TARGETARCH
ARG BIN_DIR

COPY --from=builder /shim/ /
COPY pod2daemon/bin/node-driver-registrar-${TARGETARCH} /usr/bin/csi-node-driver-registrar
COPY ${BIN_DIR}/LICENSE /licenses/LICENSE

FROM ${CALICO_BASE}

ARG GIT_VERSION

COPY --from=source / /

USER 10001:10001

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
