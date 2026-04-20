# syntax=docker/dockerfile:1.7

ARG CALICO_BASE
ARG UBI_IMAGE
ARG GO_BUILD_IMAGE=calico/go-build
ARG GO_BUILD_VER

# Build the calico binary inside the Dockerfile so BuildKit cache mounts
# (/go/pkg/mod, /root/.cache/go-build) persist across invocations, and so
# registry-level layer caching works across CI runs.
#
# --platform=$BUILDPLATFORM runs the builder natively on the host's arch and
# cross-compiles via GOARCH. Pure Go (CGO=0) cross-compile avoids QEMU; FIPS
# builds are CGO=1 + boringcrypto, amd64 only in practice.
FROM --platform=$BUILDPLATFORM ${GO_BUILD_IMAGE}:${GO_BUILD_VER} AS builder

ARG TARGETARCH
ARG FIPS=false
ARG GIT_DESCRIPTION=<unknown>
ARG GIT_COMMIT=<unknown>
ARG BUILD_DATE=<unknown>
ARG BUILD_ID=0

WORKDIR /go/src/github.com/projectcalico/calico
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,id=gobuild-${TARGETARCH}-fips${FIPS} \
    set -e; \
    mkdir -p /out; \
    LDFLAGS="-X github.com/projectcalico/calico/pkg/buildinfo.Version=${GIT_DESCRIPTION} \
             -X github.com/projectcalico/calico/pkg/buildinfo.BuildDate=${BUILD_DATE} \
             -X github.com/projectcalico/calico/pkg/buildinfo.GitRevision=${GIT_COMMIT} \
             -B 0x${BUILD_ID} -s -w"; \
    if [ "$FIPS" = "true" ]; then \
        CGO_ENABLED=1 GOEXPERIMENT=boringcrypto GOARCH=${TARGETARCH} \
            go build -o /out/calico -tags fipsstrict -v -buildvcs=false -ldflags "$LDFLAGS" ./cmd/calico; \
        go tool nm /out/calico | grep '_Cfunc__goboringcrypto_' >/dev/null; \
    else \
        CGO_ENABLED=0 GOARCH=${TARGETARCH} \
            go build -o /out/calico -v -buildvcs=false -ldflags "$LDFLAGS" ./cmd/calico; \
    fi

# Stage the calico binary alongside a calicoctl symlink. The binary detects
# argv[0]=="calicoctl" and dispatches to the `ctl` subcommand, so calicoctl
# can be a symlink rather than a duplicate copy of the binary.
# The symlink has to be created in a stage that has a shell (scratch does
# not) and the target has to resolve when BuildKit computes the COPY
# checksum, so we stage both files together here under /shim.
FROM ${UBI_IMAGE} AS shim

ARG TARGETARCH

RUN mkdir -p /shim/usr/bin
COPY --from=builder /out/calico /shim/usr/bin/calico
RUN ln -s calico /shim/usr/bin/calicoctl && \
    ln -s calico /shim/usr/bin/calico-ipam

# Stage all build-context files into a scratch layer so the final image gets
# them in a single COPY. This keeps the CALICO_BASE layer hash stable across
# (hash)releases — only the staged layer above it changes from one build to
# the next, so the base layer is reused from the registry cache.
FROM scratch AS source

ARG TARGETARCH

COPY --from=shim /shim/ /
COPY pod2daemon/bin/node-driver-registrar-${TARGETARCH} /usr/bin/csi-node-driver-registrar
COPY LICENSE.md /licenses/LICENSE

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
