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

# Pre-create a writable runtime directory for Calico's unix domain sockets
# (e.g. Typha's diagnostics socket at /var/run/calico/typha.sock). The image
# runs as uid 10001 (see USER in the final stage) with all capabilities
# dropped, so it cannot create this directory itself under the root-owned
# filesystem.
#
# Create the real directory under /run (chowned to the runtime uid) and ship
# /var/run as a symlink to /run, so /var/run/calico resolves to /run/calico on
# every supported base. This has to work for two very different bases:
#   - calico/base is extremely minimal: no /var, /run or /var/run at all, so we
#     add the whole tree (the /var/run symlink included) from scratch.
#   - ubi-minimal already ships /var/run as a symlink to /run. Staging a *real*
#     /var/run/calico directory collides with that symlink in the final COPY
#     ("cannot copy to non-directory: .../var/run"); shipping the real dir under
#     /run and /var/run as the same symlink avoids the clash.
# Only the calico subdirectory is chowned to the runtime uid; nothing above it
# is writable by Typha.
RUN mkdir -p /shim/run/calico && chown 10001:10001 /shim/run/calico && \
    mkdir -p /shim/var && ln -s ../run /shim/var/run

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

# Ship typha's default config so typha's subcommand doesn't try to mkdir
# /var/log/calico at startup (it runs as non-root and has no write access
# to /var). Matches the behavior of the standalone typha image.
COPY docker/calico/typha.cfg /etc/calico/typha.cfg

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
